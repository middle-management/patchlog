package catalog

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/tree"
)

// Merging a catalog branch goes through the catalog service (§F.8): it
// checks every move and placement in the batch as in §B.11.4, including
// no widening, and issues one grant covering exactly that batch.
//
//	POST /merge-grants
//	Authorization: Bearer <the merging person's grant for the catalog>
//	{ "batch": { "items": [ … ], "source": { "ns": "cat-season-r7", "at": "1n…" } } }
//
// batch is the body the merger will POST to /ns/{catalog}/batch. Each
// item's precondition names the catalog revision its steps apply to, so the
// service folds them onto that revision and judges the resulting document
// against the graph it follows. The graph must have reached those
// revisions (otherwise 503 "behind", retry).
//
// The checks, per item, for the caller's subjects:
//
//   - a change of $access (including creating or restoring a node with
//     one) needs the admin group (§B.11.3);
//   - a new placement (create or restore): the caller is in the content
//     namespace's catalogs.{catalog}.place list and has a role with place
//     on every folder in its parents (§B.11.4 place);
//   - a new folder: a role with place on every folder in its parents (the
//     spec has no request for creating folders; placing into a folder is
//     the closest consent, see the README);
//   - a deleted node: a role with move on every current parent (§B.11.4
//     unplace);
//   - changed parents (a move): a role with move on every parent left and
//     on every parent added, and unless the caller is an admin, no
//     widening for any node that existed before in the moved subtrees
//     (§B.11.4 move);
//   - any other edit (titles, order): a role with move on every current
//     parent.
//
// Powers on folders the same batch creates are read from the batch's
// result; on other folders from the graph as it is.
//
// The grant's root names the caller (sub, permitted groups) and the
// catalog's key, so the batch is recorded as the caller's under the
// service's kid: list that pair in the catalog's merge.authors (§F.3,
// §F.9). Its rules allow, per resource of the batch, exactly the actions
// the batch's steps take, and nothing else.

// MergeGrantRequest is the body of POST /merge-grants.
type MergeGrantRequest struct {
	Batch map[string]any `json:"batch"`
}

// MergeGrant is an issued merge grant.
type MergeGrant struct {
	Issued
	// Checks reports, per resource, what was checked.
	Checks []MergeCheck `json:"checks"`
}

// MergeCheck is the decision for one item.
type MergeCheck struct {
	Resource string   `json:"resource"`
	Change   string   `json:"change"` // place, create-folder, delete, move, edit, access
	Actions  []string `json:"actions"`
}

func (s *Service) serveMergeGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, err := s.Authenticate(r.Context(), r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, badInput("cannot read the body"))
		return
	}
	body, err := jsonv.Parse(b)
	if err != nil {
		writeErr(w, badInput("malformed body: %v", err))
		return
	}
	m, _ := body.(map[string]any)
	batch, _ := m["batch"].(map[string]any)
	if batch == nil {
		writeErr(w, badInput("batch is required"))
		return
	}
	res, err := s.IssueMerge(r.Context(), v, batch)
	if err != nil {
		writeErr(w, err)
		return
	}
	tree.WriteJSON(w, http.StatusOK, res)
}

type mergeItem struct {
	name          string
	before, after any // nil: absent or deleted
	beforeLive    bool
	head          string // the precondition's revision ("" for ifNoneMatch)
	actions       []string
}

// IssueMerge checks a catalog merge batch for the verified caller v and
// signs one grant covering it (§F.8).
func (s *Service) IssueMerge(ctx context.Context, v *grant.Verified, batch map[string]any) (*MergeGrant, error) {
	cat := s.t.Catalog()
	src, _ := batch["source"].(map[string]any)
	if sns, _ := src["ns"].(string); sns == "" || sns == cat {
		return nil, badInput("batch.source.ns must name the catalog branch being merged")
	}
	if _, ok := batch["config"]; ok {
		return nil, badInput("a merge grant covers items only; configuration is never merged implicitly (§F.3)")
	}
	rawItems, _ := batch["items"].([]any)
	if len(rawItems) == 0 {
		return nil, badInput("batch.items must list at least one item")
	}
	c := s.t.Client()
	var items []*mergeItem
	seen := map[string]bool{}
	for i, x := range rawItems {
		it, _ := x.(map[string]any)
		name, _ := it["resource"].(string)
		if !client.ValidResourceName(name) || seen[name] {
			return nil, badInput("item %d: a resource name is required, once per batch", i)
		}
		seen[name] = true
		mi := &mergeItem{name: name}
		ifMatch, _ := it["ifMatch"].(string)
		inm, _ := it["ifNoneMatch"].(string)
		h, err := c.Head(ctx, cat, name)
		if err != nil {
			return nil, upstream(err)
		}
		switch {
		case inm == "*":
			if h.State == client.Live || h.State == client.Tombstoned {
				return nil, conflict("%s exists in %s; the batch's precondition is stale", name, cat)
			}
		case ifMatch != "":
			if h.ID != ifMatch {
				return nil, conflict("%s moved in %s since the batch was built (head %s, ifMatch %s)", name, cat, h.ID, ifMatch)
			}
			mi.head = ifMatch
			if h.State == client.Live {
				d, err := c.Doc(ctx, cat, name, h.ID)
				if err != nil {
					return nil, upstream(err)
				}
				mi.before, mi.beforeLive = d.Value, true
			}
		default:
			return nil, badInput("item %s has no precondition", name)
		}
		steps, _ := it["steps"].([]any)
		if len(steps) == 0 {
			return nil, badInput("item %s has no steps", name)
		}
		cur, live := jsonv.Clone(mi.before), mi.beforeLive
		exists := mi.beforeLive || h.State == client.Tombstoned
		if h.State == client.Tombstoned && h.Last != "" {
			// A restore applies to the last live document (§8.2).
			d, err := c.Doc(ctx, cat, name, h.Last)
			if err != nil {
				return nil, upstream(err)
			}
			cur = d.Value
		}
		for j, st := range steps {
			if sv, ok := st.(string); ok {
				if sv != "delete" || !live {
					return nil, badInput("item %s step %d: only \"delete\" of a live document is a step", name, j)
				}
				mi.addAction("delete")
				live = false
				continue
			}
			ops, err := patch.Parse(st)
			if err != nil {
				return nil, badInput("item %s step %d: %v", name, j, err)
			}
			switch {
			case live:
				mi.addAction("append")
			case exists:
				mi.addAction("restore")
			default:
				mi.addAction("create")
			}
			base := cur
			if !live && !exists {
				base = nil
			}
			nd, _, err := patch.Apply(base, live || exists, ops, patch.Options{ResourceEnvelope: true})
			if err != nil {
				return nil, badInput("item %s step %d doesn't apply: %v", name, j, err)
			}
			cur, live, exists = nd, true, true
		}
		if live {
			mi.after = cur
		}
		items = append(items, mi)
	}

	key, err := s.catalogKey(ctx)
	if err != nil {
		return nil, err
	}
	subs := Subjects(v)
	admin := s.isAdmin(v)
	var incs map[string]Includes
	if !admin {
		if incs, err = s.includesOfTrusted(ctx); err != nil {
			return nil, err
		}
	}
	// Place lists of the content namespaces new placements bring in.
	placeOK := map[string]bool{}
	for _, mi := range items {
		ns, _, ok := tree.SplitPlacement(mi.name)
		if !ok || mi.beforeLive || mi.after == nil {
			continue
		}
		if _, done := placeOK[ns]; done {
			continue
		}
		cfg, err := s.t.Checker().Config(ctx, ns)
		if err != nil {
			return nil, upstream(err)
		}
		placeOK[ns] = inPlaceList(cfg.Doc, cat, subs)
	}

	var cp string
	var checks []MergeCheck
	err = nil
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		changes := map[string]any{}
		for _, mi := range items {
			n := g.Node(mi.name)
			explicit := n != nil && g.Explicit(mi.name)
			switch {
			case mi.beforeLive && (!explicit || n.Head != mi.head):
				err = errf(503, "behind", "the catalog service hasn't reached %s/%s at %s yet", cat, mi.name, mi.head)
				return
			case !mi.beforeLive && explicit:
				err = errf(503, "behind", "the catalog service still has %s/%s live", cat, mi.name)
				return
			}
			changes[mi.name] = mi.after
		}
		after := g.With(changes)
		// A folder the same batch creates is entered on the consent that
		// created it: place on every one of its own parents (a release
		// creates such folders without roles that carry place or move,
		// §F.9, so nobody holds powers on them yet).
		var power func(folder, p string, depth int) bool
		power = func(folder, p string, depth int) bool {
			if g.Explicit(folder) {
				if _, changed := changes[folder]; !changed {
					return hasPower(g, folder, subs, p)
				}
				return hasPower(g, folder, subs, p) || hasPower(after, folder, subs, p)
			}
			if doc, created := changes[folder]; created && doc != nil && depth < tree.MaxDepth {
				ps := tree.ParseNode(cat, folder, "", doc).Parents
				if len(ps) == 0 {
					return admin
				}
				for _, pp := range ps {
					if pp.Name == "" || !power(pp.Name, "place", depth+1) {
						return false
					}
				}
				return true
			}
			return false
		}
		names := func(doc any) []string {
			var out []string
			for _, p := range tree.ParseNode(cat, "x", "", doc).Parents {
				if p.Name != "" && !contains(out, p.Name) {
					out = append(out, p.Name)
				}
			}
			sort.Strings(out)
			return out
		}
		var moved []string
		for _, mi := range items {
			chk := MergeCheck{Resource: mi.name, Actions: mi.actions}
			bm, _ := mi.before.(map[string]any)
			am, _ := mi.after.(map[string]any)
			var accessChanged bool
			switch {
			case mi.after == nil:
				accessChanged = false
			case !mi.beforeLive:
				_, accessChanged = am["$access"]
			default:
				accessChanged = !jsonv.Equal(jsonv.FromGo(bm["$access"]), jsonv.FromGo(am["$access"]))
			}
			if accessChanged && !admin {
				err = forbidden("%s: changing $access needs %s (§B.11.3)", mi.name, s.opt.AdminGroup)
				return
			}
			_, _, isPlacement := tree.SplitPlacement(mi.name)
			isPlacement = isPlacement || strings.Contains(mi.name, ".")
			switch {
			case mi.after == nil:
				chk.Change = "delete"
				for _, p := range names(mi.before) {
					if g.Node(p) != nil && g.Node(p).Kind == tree.KindFolder && !power(p, "move", 0) {
						err = forbidden("%s: no role of yours with move is assigned on %s", mi.name, p)
						return
					}
				}
			case !mi.beforeLive:
				chk.Change = "create-folder"
				if isPlacement {
					chk.Change = "place"
					ns, _, ok := tree.SplitPlacement(mi.name)
					if !ok || !placeOK[ns] {
						err = forbidden("%s: namespace %s does not let you place its items in %s (catalogs.%s.place)", mi.name, ns, cat, cat)
						return
					}
				}
				ps := names(mi.after)
				if len(ps) == 0 && !admin {
					err = forbidden("%s: only %s create roots", mi.name, s.opt.AdminGroup)
					return
				}
				for _, p := range ps {
					if !power(p, "place", 0) {
						err = forbidden("%s: no role of yours with place is assigned on %s", mi.name, p)
						return
					}
				}
			default:
				bp, ap := names(mi.before), names(mi.after)
				if strings.Join(bp, ",") != strings.Join(ap, ",") {
					chk.Change = "move"
					moved = append(moved, mi.name)
					for _, p := range bp {
						if !contains(ap, p) && g.Node(p) != nil && g.Node(p).Kind == tree.KindFolder && !power(p, "move", 0) {
							err = forbidden("%s: no role of yours with move is assigned on %s, which the node leaves", mi.name, p)
							return
						}
					}
					for _, p := range ap {
						if !contains(bp, p) && !power(p, "move", 0) {
							err = forbidden("%s: no role of yours with move is assigned on %s", mi.name, p)
							return
						}
					}
				} else {
					chk.Change = "edit"
					if accessChanged {
						chk.Change = "access"
					}
					if !accessChanged && len(ap) == 0 && !admin {
						err = forbidden("%s: only %s edit roots", mi.name, s.opt.AdminGroup)
						return
					}
					if !accessChanged {
						for _, p := range ap {
							if !power(p, "move", 0) {
								err = forbidden("%s: no role of yours with move is assigned on %s", mi.name, p)
								return
							}
						}
					}
				}
			}
			checks = append(checks, chk)
		}
		if admin || len(moved) == 0 {
			return
		}
		// No widening in the moved subtrees, for nodes that existed before
		// (new nodes are judged by the place checks above).
		for _, name := range moved {
			for d := range after.Descendants([]string{name}) {
				if g.Node(d) == nil {
					continue
				}
				a := Effective(after, d, nil)
				b := s.eff[d]
				for _, subj := range subjectsOf(a) {
					for _, r := range a[subj] {
						if !present(after, d, r, b[subj], incs) {
							err = forbidden("moving %s would give %s the role %s on %s", name, subj, r, after.Href(d))
							return
						}
					}
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	var can []string
	var alts []any
	for _, mi := range items {
		for _, a := range mi.actions {
			if !contains(can, a) {
				can = append(can, a)
			}
		}
		alts = append(alts, map[string]any{"all": []any{
			resourceRule(mi.name),
			map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": toAny(mi.actions)}},
		}})
	}
	sort.Strings(can)
	for _, a := range can {
		if !key.IsStar() && !contains(key.Can, a) {
			return nil, forbidden("the catalog's key may not %s in %s", a, cat)
		}
	}
	p := &plan{ns: cat, resource: "", can: can, rules: []any{map[string]any{"any": alts}}, cp: cp, key: key}
	is, err := s.mint(ctx, v, p, map[string]bool{})
	if err != nil {
		return nil, err
	}
	return &MergeGrant{Issued: *is, Checks: checks}, nil
}

func (mi *mergeItem) addAction(a string) {
	if !contains(mi.actions, a) {
		mi.actions = append(mi.actions, a)
	}
}
