package merge

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/schema"
)

// RebaseReleaseOptions configure RebaseRelease.
type RebaseReleaseOptions struct {
	// Release is the release document's link.
	Release string
	// Suffix names each successor: the branch's name plus Suffix (e.g.
	// "-b": matches-r7 -> matches-r7-b). Names maps a branch to an explicit
	// successor name instead.
	Suffix string
	Names  map[string]string
	// At is the new release document's combined checkpoint (§B.5), if
	// known; otherwise it is left out: the successors start at their
	// bases' current heads, not at one combined checkpoint.
	At string
	// Plan options for the replays (Squash is ignored).
	Plan Options
}

// RebaseReleaseResult reports what RebaseRelease did.
type RebaseReleaseResult struct {
	// Order is the order the branches were rebased in: schema branches
	// first.
	Order []string `json:"order"`
	// Rebases are the per-branch results, by release key.
	Rebases map[string]*RebaseResult `json:"rebases"`
	// Drafts maps each draft schema revision that was replayed (and got a
	// new id) to the revision it moved to.
	Drafts map[string]string `json:"drafts,omitempty"`
	// Squashed lists, per key, resources squashed because their entries
	// reference a replayed draft.
	Squashed map[string][]string `json:"squashed,omitempty"`
	// Revision is the release document's new revision.
	Revision string `json:"revision,omitempty"`
}

// RebaseRelease rebases every branch of a release (§F.9 Rebasing): it
// creates a successor of each (§F.5), the schema branches' first, each
// with drafts.for naming the other successors in its creation patches, so
// the others' documents resolve as they are replayed. A draft that has to
// be replayed gets a new id, and older entries naming the old one can't be
// replayed into the successors, so a resource whose entries reference such
// a draft is squashed: one resolution set against its new base, reaching
// the branch's document with $schema moved to the draft's new revision.
// Each old branch is switched (frozen with successor) once its successor
// holds its work. Finally the release document gets a new revision
// listing the successors.
//
// On conflicts it stops with ErrConflicts and the plan that needs a person
// (in the result); resolve with `patchlog merge apply -base SUCCESSOR
// -branch OLD -resolve …`, then run it again: it resumes.
func RebaseRelease(ctx context.Context, c *client.Client, opt RebaseReleaseOptions) (*RebaseReleaseResult, error) {
	rel, err := release.Load(ctx, c, opt.Release)
	if err != nil {
		return nil, err
	}
	if rel.Ref.Rev != rel.Head {
		return nil, errors.New("merge: rebase a release from its current revision (give its live link)")
	}
	if opt.Suffix == "" && len(opt.Names) == 0 {
		return nil, errors.New("merge: a release rebase needs successor names (a suffix)")
	}
	succ := map[string]string{} // key -> successor
	for _, k := range rel.Doc.Keys() {
		br := rel.Doc.Branches[k].NS
		n := opt.Names[br]
		if n == "" {
			n = br + opt.Suffix
		}
		if !client.ValidNSName(n) {
			return nil, fmt.Errorf("merge: successor name %q of %s is not a namespace name", n, br)
		}
		succ[k] = n
	}
	// Schema branches first: those that wrote schema documents.
	var schemaKeys, otherKeys []string
	for _, k := range rel.Doc.Keys() {
		holds, err := writesSchemas(ctx, c, rel.Doc.Branches[k].NS)
		if err != nil {
			return nil, err
		}
		if holds {
			schemaKeys = append(schemaKeys, k)
		} else {
			otherKeys = append(otherKeys, k)
		}
	}
	out := &RebaseReleaseResult{Rebases: map[string]*RebaseResult{}, Drafts: map[string]string{}, Squashed: map[string][]string{}}
	popt := opt.Plan
	popt.Squash = false
	for _, k := range schemaKeys {
		var others []any
		for _, k2 := range rel.Doc.Keys() {
			if k2 != k {
				others = append(others, succ[k2])
			}
		}
		sort.Slice(others, func(i, j int) bool { return others[i].(string) < others[j].(string) })
		br := rel.Doc.Branches[k].NS
		out.Order = append(out.Order, br)
		res, err := Rebase(ctx, c, RebaseOptions{Branch: br, New: succ[k], Switch: true, Plan: popt,
			Patches: []any{map[string]any{"op": "add", "path": "/drafts", "value": map[string]any{"for": others}}},
			Prepare: func(ctx context.Context, p *Plan) error { return squashDrafts(ctx, c, p, out.Drafts, out.Squashed, k) },
		})
		out.Rebases[k] = res
		if err != nil {
			return out, fmt.Errorf("merge: rebasing %s into %s: %w", br, succ[k], err)
		}
		if err := ensureDrafts(ctx, c, succ[k], others); err != nil {
			return out, err
		}
		if err := mapDrafts(ctx, c, k, br, succ[k], res, out.Drafts); err != nil {
			return out, err
		}
	}
	for _, k := range otherKeys {
		br := rel.Doc.Branches[k].NS
		out.Order = append(out.Order, br)
		res, err := Rebase(ctx, c, RebaseOptions{Branch: br, New: succ[k], Switch: true, Plan: popt,
			Prepare: func(ctx context.Context, p *Plan) error { return squashDrafts(ctx, c, p, out.Drafts, out.Squashed, k) },
		})
		out.Rebases[k] = res
		if err != nil {
			return out, fmt.Errorf("merge: rebasing %s into %s: %w", br, succ[k], err)
		}
	}
	// The release document lists the successors.
	nd := *rel.Doc
	nd.Branches = map[string]release.Branch{}
	for _, k := range rel.Doc.Keys() {
		h, err := c.NSHead(ctx, succ[k])
		if err != nil {
			return out, err
		}
		d, err := c.NSDoc(ctx, succ[k], h.ID)
		if err != nil {
			return out, err
		}
		bref, _ := d.Value["base"].(map[string]any)
		at, _ := bref["at"].(string)
		nd.Branches[k] = release.Branch{NS: succ[k], At: at}
	}
	nd.At = opt.At
	rev, err := release.Write(ctx, c, rel.Ref, rel.Head, &nd)
	if err != nil {
		return out, err
	}
	out.Revision = rev
	return out, nil
}

// writesSchemas reports whether a branch wrote a schema document.
func writesSchemas(ctx context.Context, c *client.Client, ns string) (bool, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return false, err
	}
	log, err := c.NSLog(ctx, ns, h.ID, "")
	if err != nil {
		return false, err
	}
	for _, ch := range Collect(log) {
		if ch.Kind != "head" || ch.Purged {
			continue
		}
		d, err := c.Doc(ctx, ns, ch.Resource, ch.Target)
		if err != nil {
			return false, err
		}
		if isSchemaDoc(d.Value) {
			return true, nil
		}
	}
	return false, nil
}

// ensureDrafts makes a resumed schema successor's drafts.for name the
// other successors (its creation patches did on a first run).
func ensureDrafts(ctx context.Context, c *client.Client, ns string, others []any) error {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return err
	}
	d, err := c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return err
	}
	dr, _ := d.Value["drafts"].(map[string]any)
	have := map[string]bool{}
	for _, x := range strList(dr["for"]) {
		have[x] = true
	}
	missing := false
	for _, o := range others {
		if !have[o.(string)] {
			missing = true
		}
	}
	if !missing {
		return nil
	}
	_, err = configWrite(ctx, c, ns, []any{map[string]any{"op": "add", "path": "/drafts", "value": map[string]any{"for": others}}})
	return err
}

func strList(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// mapDrafts records, for each schema resource of key that the rebase
// replayed (new ids), every revision the old branch wrote for it ->
// the successor's head of it.
func mapDrafts(ctx context.Context, c *client.Client, key, old, succ string, res *RebaseResult, m map[string]string) error {
	for _, p := range []*Plan{res.First, res.CatchUp} {
		if p == nil {
			continue
		}
		for _, r := range p.Resources {
			if r.Class != Replay && !(r.Class == FastForward && (r.Resolved || r.Squashed)) {
				continue
			}
			h, err := c.Head(ctx, succ, r.Name)
			if err != nil {
				return err
			}
			if h.State != client.Live {
				continue
			}
			es, err := c.Log(ctx, old, r.Name, r.Branch, "")
			if err != nil {
				return err
			}
			start := 0
			if r.Ancestor != "" {
				if i := indexOf(es, r.Ancestor); i >= 0 {
					start = i + 1
				}
			}
			for _, e := range es[start:] {
				if e.ID != h.ID {
					m["/r/"+key+"/"+r.Name+"/rev/"+e.ID] = "/r/" + key + "/" + r.Name + "/rev/" + h.ID
				}
			}
		}
	}
	return nil
}

// squashDrafts resolves every resource of p whose branch entries reference
// a replayed draft (drafts: old path -> new path) by one patch set against
// its new base reaching the branch's document, with $schema moved to the
// new revision (§F.9 Rebasing).
func squashDrafts(ctx context.Context, c *client.Client, p *Plan, drafts map[string]string, squashed map[string][]string, key string) error {
	if len(drafts) == 0 {
		return nil
	}
	for _, r := range p.Resources {
		if r.Class != FastForward && r.Class != Replay {
			continue
		}
		es, err := c.Log(ctx, p.Branch, r.Name, r.Branch, "")
		if err != nil {
			if client.IsPruned(err) {
				continue
			}
			return err
		}
		refs := false
		for _, e := range es {
			if e.Kind == "tombstone" {
				continue
			}
			d, err := c.Doc(ctx, p.Branch, r.Name, e.ID)
			if err != nil {
				if client.IsGone(err) || client.IsPruned(err) {
					continue
				}
				return err
			}
			if s := schemaOf(d.Value); s != "" && drafts[s] != "" {
				refs = true
				break
			}
		}
		if !refs {
			continue
		}
		var step client.Step
		if r.BranchDeleted {
			if r.BaseState != client.Live.String() {
				continue
			}
			step = client.DeleteStep()
		} else {
			hd, err := c.Doc(ctx, p.Branch, r.Name, r.Branch)
			if err != nil {
				return err
			}
			doc := jsonv.Clone(hd.Value)
			if m, ok := doc.(map[string]any); ok {
				if s, _ := m["$schema"].(string); drafts[s] != "" {
					m["$schema"] = drafts[s]
				}
			}
			switch {
			case r.Base == "" || r.BaseState == client.NotFound.String():
				step = client.PatchStep(client.GenesisPatches(doc))
			case r.BaseState == client.Tombstoned.String():
				step = client.PatchStep([]any{map[string]any{"op": "replace", "path": "", "value": doc}})
			default:
				bd, err := c.Doc(ctx, p.Target, r.Name, r.Base)
				if err != nil {
					return err
				}
				diff := Diff(bd.Value, doc)
				if diff == nil {
					diff = []any{}
				}
				step = client.PatchStep(diff)
			}
		}
		if err := p.Resolve(r.Name, step); err != nil {
			return err
		}
		squashed[key] = append(squashed[key], r.Name)
	}
	return nil
}

func schemaOf(d any) string {
	m, _ := d.(map[string]any)
	s, _ := m["$schema"].(string)
	if _, ok := schema.ParseRef(s); !ok {
		return ""
	}
	return s
}
