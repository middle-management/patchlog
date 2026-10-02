package catalog

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

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
//	Authorization: Bearer <the merge service's grant for the catalog>
//	Approver-Authorization: Bearer <the approving person's grant for the catalog>
//	{ "batch": { "items": [ … ], "source": { "ns": "cat-season-r7", "at": "1n…" } } }
//
// batch is the body the merge service will POST to /ns/{catalog}/batch.
// Each item's precondition names the catalog revision its steps apply to,
// so the service folds them onto that revision and judges the resulting
// document against the graph it follows. The graph must have reached those
// revisions (otherwise 503 "behind", retry).
//
// Merge grants are signed with a key used for nothing else (Options.
// MergeKey) and only for the merge service: the caller must be
// Options.MergeService, which submits the batch itself. The checks are the
// approving person's, whose grant comes in Approver-Authorization (the
// caller's own if there is none). The grant's root names the merge service
// (sub) and the merge key (kid), with attrs.approvedBy the approver, so
// the catalog base lists that one pair in merge.authors (§F.3). Its rules
// allow exactly the batch's pairs of /resource and /action, and it expires
// within minutes (Options.MergeTTL). It can't fix the documents or the
// batch's source, since a fast-forward passes through intermediate states
// and source isn't in the envelope (§6.4.1).
//
// The checks, per item, for the approver's subjects:
//
//   - a change of $access (including creating or restoring a node with
//     one) needs the admin group (§B.11.3), which the catalog's keys may
//     never assert: such a batch is checked as a dry run and answered with
//     "admin": true and no grant. The merge service then submits it under
//     the grant of a person in the admin group, narrowed with its own via
//     (§C.1, §F.8); the catalog base lists each such admin in merge.authors;
//   - a new placement (create or restore): the approver is in the content
//     namespace's catalogs.{catalog}.place list and has a role with place
//     on every folder in its parents (§B.11.4 place);
//   - a new folder: a role with move on every folder in its parents
//     (§B.11.4 create a folder);
//   - a deleted node: a role with move on every current parent (§B.11.4
//     unplace);
//   - changed parents (a move): a role with move on every parent left and
//     on every parent added, and unless the approver is an admin, no
//     widening for any node that existed before in the moved subtrees
//     (§B.11.4 move);
//   - any other edit (titles, order): a role with move on every current
//     parent.
//
// Tree powers on a folder the same batch creates come only from its own
// $access in the batch's result (and an admin may enter one nobody holds
// them on yet); on other folders from the graph as it is.

// MergeGrantRequest is the body of POST /merge-grants.
type MergeGrantRequest struct {
	Batch map[string]any `json:"batch"`
}

// MergeGrant is the answer of POST /merge-grants: an issued merge grant,
// or, for a batch that changes $access, Admin with no grant (checked; to
// be submitted under a catalog admin's grant).
type MergeGrant struct {
	*Issued
	Admin bool `json:"admin,omitempty"`
	// ApprovedBy is the approver whose powers were checked.
	ApprovedBy string `json:"approvedBy"`
	// Checks reports, per resource, what was checked.
	Checks []MergeCheck `json:"checks"`
}

// MergeCheck is the decision for one item.
type MergeCheck struct {
	Resource string   `json:"resource"`
	Change   string   `json:"change"` // place, create-folder, delete, move, edit, access
	Actions  []string `json:"actions"`
}

// ApproverHeader carries the approving person's grant to POST
// /merge-grants.
const ApproverHeader = "Approver-Authorization"

func (s *Service) serveMergeGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, err := s.Authenticate(r.Context(), r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	av := v
	if h := r.Header.Get(ApproverHeader); h != "" {
		tok := ""
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
		if av, err = s.t.Checker().Verify(r.Context(), s.t.Catalog(), tok); err != nil {
			tree.WriteAuthError(w, err, logf(s))
			return
		}
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
	res, err := s.IssueMerge(r.Context(), v, av, batch)
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

// IssueMerge checks a catalog merge batch, for the merge service v and the
// approver av, and signs one grant covering it with the merge key, or for
// a batch changing $access answers Admin (§F.8).
func (s *Service) IssueMerge(ctx context.Context, v, av *grant.Verified, batch map[string]any) (*MergeGrant, error) {
	cat := s.t.Catalog()
	if s.opt.MergeKey == nil {
		return nil, forbidden("this catalog service issues no merge grants: it has no merge key (§F.8)")
	}
	if v.Principal.ID != s.opt.MergeService {
		return nil, forbidden("merge grants are issued only to the merge service (%s), which submits them itself (§F.8)", s.opt.MergeService)
	}
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

	key, err := s.mergeKey(ctx)
	if err != nil {
		return nil, err
	}
	subs := Subjects(av)
	admin := s.isAdmin(av)
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
	needsAdmin := false
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
		// Tree powers on a folder the same batch creates come only from
		// its own $access (§B.11.4 create a folder); until it gives some,
		// only admins can move or place anything into it.
		power := func(folder, p string, _ int) bool {
			if g.Explicit(folder) {
				if _, changed := changes[folder]; !changed {
					return powerOn(g, folder, subs, p, admin)
				}
				return powerOn(g, folder, subs, p, admin) || hasPower(after, folder, subs, p)
			}
			if doc, created := changes[folder]; created && doc != nil {
				return powerOn(after, folder, subs, p, admin)
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
			if accessChanged {
				if !admin {
					err = forbidden("%s: changing $access needs %s (§B.11.3)", mi.name, s.opt.AdminGroup)
					return
				}
				needsAdmin = true
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
				// Placing needs place on every folder (§B.11.4 place);
				// creating a folder, move (§B.11.4 create a folder).
				want := "move"
				if isPlacement {
					want = "place"
				}
				for _, p := range ps {
					if !power(p, want, 0) {
						err = forbidden("%s: no role of yours with %s is assigned on %s", mi.name, want, p)
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
	out := &MergeGrant{ApprovedBy: av.Principal.ID, Checks: checks}
	if needsAdmin {
		// $access needs the admin group, which the merge key may never
		// assert: checked here as a dry run, submitted under an admin's
		// grant narrowed by the merge service (§F.8).
		out.Admin = true
		return out, nil
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
			return nil, forbidden("the merge key may not %s in %s", a, cat)
		}
	}
	p := &plan{ns: cat, resource: "", can: can, rules: []any{map[string]any{"any": alts}}, cp: cp, key: key}
	is, err := s.mintMerge(ctx, v, av, p)
	if err != nil {
		return nil, err
	}
	out.Issued = is
	return out, nil
}

// mergeKey is the merge key's entry in the catalog namespace (§F.8).
func (s *Service) mergeKey(ctx context.Context) (*grant.Key, error) {
	cfg, err := s.t.Checker().Config(ctx, s.t.Catalog())
	if err != nil {
		return nil, upstream(err)
	}
	key := findKey(cfg.Keys, s.opt.MergeKid)
	if key == nil {
		return nil, forbidden("the catalog namespace does not list the merge key %q", s.opt.MergeKid)
	}
	return key, nil
}

// mintMerge signs a merge grant with the merge key: root sub the merge
// service, attrs.approvedBy the approver, no groups, expiring within
// MergeTTL and never after either caller's grant (§F.8).
func (s *Service) mintMerge(ctx context.Context, v, av *grant.Verified, p *plan) (*Issued, error) {
	if err := s.checkLag(ctx, p.cp, p.key); err != nil {
		return nil, err
	}
	now := s.now()
	ttl := s.opt.MergeTTL
	if p.key.MaxTTL != nil && *p.key.MaxTTL < ttl {
		ttl = *p.key.MaxTTL
	}
	exp := now.Add(ttl).UTC().Truncate(time.Second)
	for _, vv := range []*grant.Verified{v, av} {
		for _, b := range vv.Grant.Blocks {
			if b.Exp != nil && b.Exp.Before(exp) {
				exp = b.Exp.UTC()
			}
		}
	}
	if !exp.After(now) {
		return nil, forbidden("a caller's grant expires too soon")
	}
	at := map[string]any{"ns": s.t.Catalog(), "id": p.cp}
	root := map[string]any{
		"kid": s.opt.MergeKid, "sub": s.opt.MergeService, "ns": []any{p.ns}, "can": toAny(p.can),
		"attrs": map[string]any{"approvedBy": av.Principal.ID},
		"exp":   exp.Format(time.RFC3339Nano), "at": at, "rules": p.rules,
	}
	g, err := grant.Mint(root, s.opt.MergeKey)
	if err != nil {
		return nil, err
	}
	return &Issued{Grant: g.Encode(), NS: p.ns, Can: p.can, Exp: exp.Format(time.RFC3339Nano), At: at}, nil
}

func (mi *mergeItem) addAction(a string) {
	if !contains(mi.actions, a) {
		mi.actions = append(mi.actions, a)
	}
}
