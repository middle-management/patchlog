package core

import (
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
)

// EXPERIMENTAL, not in the spec (docs/SPEC-FEEDBACK.md, v0.82 Open 91): an
// append the server may rebase. Off unless Options.ExperimentalRebase.
//
// A single write that carries Item.Rebase and whose If-Match names a
// revision that is no longer the head is applied to the current head
// instead of refused with 412, when all of these hold:
//
//   - the item is one patch set (no delete) without an author signature,
//     which binds its parent (§C.3.1);
//   - If-Match names an ancestor of the live head, at most
//     maxRebaseDistance revisions back, with no tombstone and no pruned
//     patch set in between, and every patch set in between is readable
//     by the server (so never at E3);
//   - the paths the patch set touches (every op's path, a copy's or
//     move's from, and its tests) don't overlap the writes of the
//     revisions in between, a path through an array counting as the
//     outermost array (§F.3), except that two sides which only append to
//     the same array (add at "/…/-", the array itself not nested in
//     another) don't conflict.
//
// The write then goes through every later step as an append on the head
// (§6.2 steps 3–6): its tests, the limits, the schema and the rules apply
// to the result. Its id is the id of the patch set on that head, not the
// one the client could predict. Anything else stays a 412.
const maxRebaseDistance = 64

// touch is what a patch set touches, as rebasing compares it.
type touch struct {
	paths   []pointer.Pointer
	appends map[string]bool // arrays (by pointer text) only appended to
}

// outermostArray cuts p at the first array on its way through any of
// docs: a write inside an array counts as one to the whole array (§F.3).
// inArray reports whether it was cut.
func outermostArray(p pointer.Pointer, docs ...any) (cut pointer.Pointer, inArray bool) {
	best := len(p)
	for _, doc := range docs {
		cur := doc
		for i := 0; i < len(p); i++ {
			if _, ok := cur.([]any); ok {
				if i < best {
					best = i
				}
				break
			}
			m, ok := cur.(map[string]any)
			if !ok {
				break
			}
			if cur, ok = m[p[i]]; !ok {
				break
			}
		}
	}
	return p[:best], best < len(p)
}

// touched collects what ops touch, judged against the documents before
// and after them.
func touched(ops []patch.Op, writes []pointer.Pointer, withReads bool, docs ...any) touch {
	t := touch{appends: map[string]bool{}}
	notAppend := map[string]bool{}
	add := func(p pointer.Pointer, appendOp bool) {
		if len(p) > 0 && p[len(p)-1] == "$nonce" && len(p) == 1 {
			return // a fresh $nonce is no write (§6.4.1)
		}
		cut, in := outermostArray(p, docs...)
		t.paths = append(t.paths, cut)
		k := cut.String()
		if appendOp && in && len(p) == len(cut)+1 {
			if !notAppend[k] {
				t.appends[k] = true
			}
		} else if in || len(cut) == len(p) {
			if _, isArr := arrayAt(cut, docs...); isArr || in {
				notAppend[k] = true
				delete(t.appends, k)
			}
		}
	}
	for _, op := range ops {
		isAppend := op.Op == "add" && len(op.Path) > 0 && op.Path[len(op.Path)-1] == "-"
		if op.Op != "test" || withReads {
			add(op.Path, isAppend)
		}
		if withReads && (op.Op == "copy" || op.Op == "move") {
			add(op.From, false)
		} else if op.Op == "move" {
			add(op.From, false)
		}
	}
	for _, w := range writes {
		// What applying resolved ("-" to an index): already covered by the
		// op's own path, cut at the array.
		cut, _ := outermostArray(w, docs...)
		t.paths = append(t.paths, cut)
	}
	return t
}

func arrayAt(p pointer.Pointer, docs ...any) (any, bool) {
	for _, d := range docs {
		if v, ok := pointer.Get(d, p); ok {
			if _, isArr := v.([]any); isArr {
				return v, true
			}
		}
	}
	return nil, false
}

// conflicts reports whether what the incoming patch set touches overlaps
// what the revisions since its base wrote.
func conflicts(mine, theirs touch) bool {
	for _, p := range mine.paths {
		for _, q := range theirs.paths {
			if !p.Overlaps(q) {
				continue
			}
			if len(p) == len(q) && mine.appends[p.String()] && theirs.appends[q.String()] {
				continue // both sides only appended to this array
			}
			return true
		}
	}
	return false
}

// rebasable reports whether s, whose If-Match names want and not the live
// head, may be applied to the head instead (see above).
func (t *tx) rebasable(v *view, want ids.ID, s *itemState) bool {
	if !t.e.opt.ExperimentalRebase || !s.Rebase || len(s.Steps) != 1 {
		return false
	}
	step := s.Steps[0]
	if step.Delete || step.Signature != "" {
		return false
	}
	ops, err := patch.Parse(step.Patches)
	if err != nil {
		return false
	}
	// The chain from the head back to the base, newest first.
	var between []*revRow
	cur := v.head
	for cur.id != want {
		if cur.kind != kindRev || !cur.patches.Valid || !cur.parentSeq.Valid || len(between) >= maxRebaseDistance {
			return false
		}
		between = append(between, cur)
		if cur = t.rev(cur.parentSeq.Int64); cur == nil || cur.res != v.head.res {
			return false // read through from a base, or gone: not here
		}
	}
	if cur.kind != kindRev {
		return false
	}
	doc, err := t.docAt(cur)
	if err != nil {
		return false
	}
	baseDoc := jsonv.MustParse(jsonv.Canonical(doc))
	theirs := touch{appends: map[string]bool{}}
	closed := map[string]bool{}
	for i := len(between) - 1; i >= 0; i-- {
		raw, perr := jsonv.Parse(t.patchesOf(between[i]))
		if perr != nil {
			return false
		}
		rops, perr := patch.Parse(raw)
		if perr != nil {
			return false
		}
		next, writes, aerr := patch.Apply(doc, true, rops, patch.Options{ResourceEnvelope: true})
		if aerr != nil {
			return false
		}
		one := touched(rops, writes, false, doc, next)
		theirs.paths = append(theirs.paths, one.paths...)
		for _, p := range one.paths {
			k := p.String()
			if one.appends[k] && !closed[k] {
				theirs.appends[k] = true
			} else {
				closed[k] = true
				delete(theirs.appends, k)
			}
		}
		doc = next
	}
	mine := touched(ops, nil, true, baseDoc, doc)
	return !conflicts(mine, theirs)
}
