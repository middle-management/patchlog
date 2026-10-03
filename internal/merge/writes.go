package merge

import (
	"errors"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
)

// errHistoryPruned marks a needed patch set that is absent (pruned, §8.6).
var errHistoryPruned = errors.New("merge: history pruned")

// docState is a resource's document while folding entries: the document,
// whether it exists at all, whether it is tombstoned, and the last live
// document (what a restore applies to, §8.2).
type docState struct {
	doc     any
	exists  bool // false: absent (before genesis)
	deleted bool // the latest entry is a tombstone; doc is the last live document
}

// sideChange summarises one side's entries since a common ancestor.
type sideChange struct {
	writes  []pointer.Pointer // under the array rule
	revs    bool              // it appends or restores at least one patch set
	deletes bool              // it appends at least one tombstone
	final   docState
}

// foldWrites folds entries (log entries or steps) onto start and computes
// the writes of §6.4.1 under the merge array rule of §F.3: a write whose
// last segment addresses an array element (an index, or "-") counts as a
// write to the whole array.
func foldWrites(start docState, steps []client.Step) (*sideChange, error) {
	sc := &sideChange{final: start}
	st := &sc.final
	for i, s := range steps {
		if s.Delete {
			if !st.exists || st.deleted {
				return nil, fmt.Errorf("merge: step %d deletes a resource that is not live", i)
			}
			st.deleted = true
			sc.deletes = true
			continue
		}
		if s.Patches == nil {
			return nil, errHistoryPruned
		}
		v, err := client.ToValue(s.Patches)
		if err != nil {
			return nil, err
		}
		ops, err := patch.Parse(v)
		if err != nil {
			return nil, err
		}
		// A patch set after a tombstone restores: it applies to the last
		// live document (§8.2).
		st.deleted = false
		sc.revs = true
		for j, op := range ops {
			pre := st.doc
			nd, ws, err := patch.Apply(st.doc, st.exists, []patch.Op{op}, patch.Options{ResourceEnvelope: true})
			if err != nil {
				return nil, fmt.Errorf("merge: step %d op %d: %w", i, j, err)
			}
			st.doc, st.exists = nd, true
			switch op.Op {
			case "remove":
				for _, w := range ws {
					sc.writes = append(sc.writes, arrayRule(pre, w))
				}
			case "move":
				if len(ws) == 2 {
					sc.writes = append(sc.writes, arrayRule(pre, ws[0]), arrayRule(nd, ws[1]))
				}
			default:
				for _, w := range ws {
					sc.writes = append(sc.writes, arrayRule(nd, w))
				}
			}
		}
	}
	sc.writes = dedupe(sc.writes)
	return sc, nil
}

// arrayRule widens a write whose parent is an array to the whole array.
func arrayRule(doc any, w pointer.Pointer) pointer.Pointer {
	if len(w) == 0 {
		return w
	}
	parent := w[:len(w)-1]
	if w[len(w)-1] == "-" {
		return append(pointer.Pointer{}, parent...)
	}
	if v, ok := pointer.Get(doc, parent); ok {
		if _, isArr := v.([]any); isArr {
			return append(pointer.Pointer{}, parent...)
		}
	}
	return w
}

func dedupe(ws []pointer.Pointer) []pointer.Pointer {
	seen := map[string]bool{}
	out := ws[:0:0]
	for _, w := range ws {
		k := w.String()
		if len(w) == 0 {
			k = "\x00root"
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Overlaps returns the writes of a and b that overlap (are at, above or
// below each other, compared segment by segment), as pointer strings, sorted
// and without duplicates.
func Overlaps(a, b []pointer.Pointer) []string {
	set := map[string]bool{}
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				set[x.String()] = true
				set[y.String()] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Writes computes the writes of applying patch sets (and "delete" steps)
// to doc, under the array rule of §F.3. doc nil with exists false means an
// absent resource (a genesis must come first).
func Writes(doc any, exists bool, steps []client.Step) ([]string, error) {
	sc, err := foldWrites(docState{doc: doc, exists: exists}, steps)
	if err != nil {
		return nil, err
	}
	return patch.WritesStrings(sc.writes), nil
}

// ApplySteps folds steps onto a document client-side, as the server would
// (a patch set after a tombstone restores). It returns the resulting
// document and whether it is deleted.
func ApplySteps(doc any, exists, deleted bool, steps []client.Step) (any, bool, error) {
	sc, err := foldWrites(docState{doc: jsonv.Clone(doc), exists: exists, deleted: deleted}, steps)
	if err != nil {
		return nil, false, err
	}
	return sc.final.doc, sc.final.deleted, nil
}

// stepsOf turns log entries into batch steps. A revision without its patch
// set (pruned or purged) becomes a step with nil Patches, which callers
// treat as pruned history.
//
// Each step carries its entry's gesture and undoes (§F.3 Attribution), so
// fast-forwarded and replayed revisions keep their grouping for history
// views and undo (§11.2); squashing replaces the steps, and loses them.
func stepsOf(entries []client.LogEntry) []client.Step {
	out := make([]client.Step, 0, len(entries))
	for _, e := range entries {
		var s client.Step
		switch {
		case e.Kind == "tombstone":
			s = client.DeleteStep()
		case e.HasPatches:
			s = client.PatchStep(e.Patches)
		}
		out = append(out, s.WithGesture(e.Gesture, e.Undoes))
	}
	return out
}

func hasPruned(steps []client.Step) bool {
	for _, s := range steps {
		if !s.Delete && s.Patches == nil {
			return true
		}
	}
	return false
}

// expectedIDs chains the ids that steps produce on parent ("" = genesis).
func expectedIDs(parent string, steps []client.Step) ([]string, error) {
	out := make([]string, 0, len(steps))
	prev := parent
	for _, s := range steps {
		var id string
		var err error
		if s.Delete {
			id, err = client.ExpectedTombstone(prev)
		} else {
			id, err = client.ExpectedRevision(prev, s.Patches)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, id)
		prev = id
	}
	return out, nil
}

func stringsOf(ws []pointer.Pointer) []string {
	if len(ws) == 0 {
		return nil
	}
	return patch.WritesStrings(ws)
}
