package catalog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/tree"
)

// Merging a catalog branch goes through the catalog service (§F.8): it
// checks every change in the batch as §B.11.4 checks organising requests,
// with no widening whoever approved, and issues one grant covering exactly
// that batch.
//
//	POST /merge-grants
//	Authorization: Bearer <the merge service's grant for the catalog>
//	Approver-Authorization: Bearer <the approving person's grant for the catalog>
//	Admin-Authorization: Bearer <the grant of the catalog admin a batch that needs one goes under>
//	{ "batch": { "items": [ … ], "source": { "ns": "cat-season-r7", "at": "1n…" } } }
//
// batch is the body the merge service will POST to /ns/{catalog}/batch.
// Each item's precondition names the catalog revision its steps apply to,
// so the service folds them onto that revision, as the core applies them
// (a create to the document null, a restore to the last live document,
// §6.2 step 3, §8.2), and judges the resulting document against the graph
// it follows. The graph must have reached those revisions (otherwise 503
// "behind", retry).
//
// An end-to-end catalog, whose writes fail rules on /doc (§6.2), gets no
// merge grants and no batch check (404 not_offered), as for organising
// requests (§B.11.4): after the batch's shape (400), before anything else,
// so a service for one may run without a merge key.
//
// Merge grants are signed with a key used for nothing else (Options.
// MergeKey) and only for the merge service: the caller must be
// Options.MergeService, which submits the batch itself. The checks are the
// approving person's, whose grant comes in Approver-Authorization (the
// caller's own if there is none), resolved as §B.11.4 resolves a caller.
// The grant's root names the merge service (sub) and the merge key (kid),
// with attrs.approvedBy the approver, so the catalog base lists that one
// pair in merge.authors (§F.3). Its rules allow exactly the batch's pairs
// of /resource and /action, and it expires within minutes (Options.
// MergeTTL). It can't fix the documents or the batch's source, since a
// fast-forward passes through intermediate states and source isn't in the
// envelope (§6.4.1).
//
// A batch that needs the admin group (§B.11.3), which the catalog's keys
// may never assert, gets no merge grant, whoever approved (§F.8): one that
// changes $access (creating or restoring a node with one included),
// restores a folder (§B.11.4: folders are restored only by catalog
// admins), or widens (§B.11.4 No widening: some subject's roles at a node
// that exists or existed, after the batch, aren't a subset of those
// before; for a placement the batch places again, against its deleted
// placement's rows, §B.11.7). Its approver must be in the admin group (a
// 403 otherwise, as that person's own organising request would be:
// CONFORMANCE scenario 44), and it is checked as a dry run, with the
// admin whose grant it goes under as the caller too: the holder of the
// grant in Admin-Authorization, or, without one, the approver (F-T4). The
// approver's checks come first, so a grant in Admin-Authorization that
// isn't an admin's is 403 only after them. It is answered with "admin":
// true and no grant; the merge service asks again with the admin's grant
// in Admin-Authorization, then submits the batch under that grant,
// narrowed with its own via (§C.1, §F.8), and the catalog base lists each
// such admin in merge.authors.
//
// The checks, per item, for the approver's subjects and, for an admin dry
// run, the admin's, as organising requests answer them (§B.11.4): 404
// first, then 403, then 409 and 410 (the 409s for stale preconditions,
// which the folds need, are the core's and come before them all):
//
//   - to a caller not in the admin group, an item naming a node hidden
//     from it (§B.11.5), or restoring a tombstoned folder (folders are
//     restored only by catalog admins, §B.11.4), is 404, as a missing
//     one; so is, to any caller, a to entry (a parent of a new node, or
//     any parent of a moved one, those it keeps included) that isn't a
//     live folder of the catalog after the batch, or, to a caller not in
//     the admin group, one hidden from it. A new folder's name and a
//     placement's are exempt (names are not secrets);
//   - a new placement (create or restore): the item's namespace is
//     trusted, the caller is in its catalogs.{catalog}.place list and has
//     a role with place on every folder in its parents (§B.11.4 place);
//   - a new folder: a role with move on every folder in its parents
//     (§B.11.4 create a folder);
//   - a deleted node: a role with move on every current parent (§B.11.4
//     unplace);
//   - changed parents (a move): a role with move on every parent left and
//     on every folder in to, the node's parents after the batch, those it
//     keeps included, none of them the node or below it (§B.11.4 move);
//   - any other edit (titles, order): a role with move on every current
//     parent, as a rename is a move to them;
//   - a caller not in the admin group makes no root (an empty parents),
//     and moves, deletes or edits no node without parents or with a
//     parent hidden from it (organising.leaves);
//   - then, after every caller's 404s and 403s: a new folder's name that a
//     parents entry or accepted $parents names, hidden ones included, is
//     409 (§B.11.4 create a folder: names are not secrets, and the new
//     folder would adopt that node); and, from the core's head, so not
//     decided at the checkpoint, a purged placement is 410, as a Place of
//     one, and a purged folder's name 409, as one that existed.
//
// Tree powers are judged as for organising requests (powers, §B.11.2):
// a caller in the admin group needs none, a broken parent gives none,
// only subjects the catalog's key in the catalog may assert count, and a
// folder without $access has, per subject, the powers held at all its
// parents. On a folder the same batch creates they are judged in the
// batch's result; on other folders from the graph as it is. No refusal
// names a node hidden from the caller.

// MergeGrantRequest is the body of POST /merge-grants.
type MergeGrantRequest struct {
	Batch map[string]any `json:"batch"`
}

// MergeGrant is the answer of POST /merge-grants: an issued merge grant,
// or, for a batch that needs the admin group, Admin with no grant
// (checked as a dry run; to be submitted under a catalog admin's grant).
type MergeGrant struct {
	*Issued
	Admin bool `json:"admin,omitempty"`
	// ApprovedBy is the approver.
	ApprovedBy string `json:"approvedBy"`
	// CheckedAs is the caller the checks were last judged for: the
	// approver, or for an Admin batch the admin whose grant it goes under
	// (F-T4).
	CheckedAs string `json:"checkedAs"`
	// Checks reports, per resource, what was checked.
	Checks []MergeCheck `json:"checks"`
	// Checkpoint is what the batch was checked at, as for POST /grants
	// (§B.11.4, checkpointAt): the catalog's ns_id, those of the
	// namespaces of the items its placements name, and those of the
	// namespaces whose roles or includes the checks read. It shadows
	// Issued's, which is the same.
	Checkpoint map[string]string `json:"checkpoint"`
}

// MergeCheck is the decision for one item.
type MergeCheck struct {
	Resource string   `json:"resource"`
	Change   string   `json:"change"` // place, create-folder, restore-folder, delete, move, edit, access
	Actions  []string `json:"actions"`
}

// ApproverHeader carries the approving person's grant to POST
// /merge-grants.
const ApproverHeader = "Approver-Authorization"

// AdminHeader carries the grant of the catalog admin a batch that needs
// one goes under, whose dry run it is (§F.8, F-T4).
const AdminHeader = "Admin-Authorization"

func (s *Service) serveMergeGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, err := s.Authenticate(r.Context(), r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	av := v
	if h := r.Header.Get(ApproverHeader); h != "" {
		if av, err = s.verifyHeader(r.Context(), h); err != nil {
			tree.WriteAuthError(w, err, logf(s))
			return
		}
	}
	var adm *grant.Verified
	if h := r.Header.Get(AdminHeader); h != "" {
		if adm, err = s.verifyHeader(r.Context(), h); err != nil {
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
	res, err := s.IssueMerge(r.Context(), v, av, adm, batch)
	if err != nil {
		writeErr(w, err)
		return
	}
	tree.WriteJSON(w, http.StatusOK, res)
}

// verifyHeader verifies the bearer grant in an Authorization-style header
// value for the catalog namespace.
func (s *Service) verifyHeader(ctx context.Context, h string) (*grant.Verified, error) {
	tok := ""
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		tok = strings.TrimSpace(h[7:])
	}
	return s.t.Checker().Verify(ctx, s.t.Catalog(), tok)
}

type mergeItem struct {
	name          string
	before, after any // the documents before and after the batch (nil for none, or null)
	beforeLive    bool
	afterLive     bool
	// made is, for an item not live before, the document it creates or
	// restores: after, or for one deleted again within the batch, the
	// last live document its steps produce, which is checked as that
	// create is.
	made       any
	tombstoned bool   // the catalog's head of the name is a tombstone
	purged     bool   // the catalog's head of the name is purged (ifNoneMatch)
	head       string // the precondition's revision ("" for ifNoneMatch)
	actions    []string
}

// doc is the item's document after the batch, for Graph.With: nil if it
// deletes the node, and a live null as {} (a node without members).
func (mi *mergeItem) doc() any {
	switch {
	case !mi.afterLive:
		return nil
	case mi.after == nil:
		return map[string]any{}
	}
	return mi.after
}

// accessChanged reports whether the batch changes the node's $access,
// creating or restoring it with one included (§B.11.3).
func (mi *mergeItem) accessChanged() bool {
	if !mi.beforeLive {
		mm, _ := mi.made.(map[string]any)
		_, ok := mm["$access"]
		return ok
	}
	if !mi.afterLive {
		return false
	}
	bm, _ := mi.before.(map[string]any)
	am, _ := mi.after.(map[string]any)
	return !jsonv.Equal(jsonv.FromGo(bm["$access"]), jsonv.FromGo(am["$access"]))
}

func (mi *mergeItem) placement() bool {
	_, _, ok := tree.SplitPlacement(mi.name)
	return ok || strings.Contains(mi.name, ".")
}

// widened is the first widening a batch makes (mergeWidening): subject
// gets role at node, through the change of item by. replace says node is
// a placement the batch places again, judged against its deleted
// placement's rows.
type widened struct {
	by, node, subject, role string
	replace                 bool
}

// IssueMerge checks a catalog merge batch, for the merge service v, the
// approver av and, for a batch that needs the admin group, the admin adm
// whose grant it goes under too (nil: the approver), and signs one grant
// covering it with the merge key, or for a batch that needs the admin
// group answers Admin (§F.8). The checks are taken at one checkpoint, with
// place lists and includes as of it, which the answer carries as
// checkpoint (checkpointAt: the catalog, the namespaces of the items the
// batch's placements name, and those whose roles or includes the checks
// read), and so do its 403s, 404s and the 409 for a new folder's name a
// parents entry names (decidedAt); the 409s for stale preconditions, and
// the answers for a purged name, are from the core's head, not decisions
// at it.
func (s *Service) IssueMerge(ctx context.Context, v, av, adm *grant.Verified, batch map[string]any) (*MergeGrant, error) {
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
	// The catalog namespace's document at the head: an end-to-end catalog
	// gets no merge grants and no batch check, as of its head, since
	// levels only rise (Addendum E, Levels; §F.8, §B.11.4), whether or not
	// this service has a merge key. Its entry for the catalog's key
	// decides, as of the checkpoint, which of the caller's subjects give
	// tree powers (powers).
	catLatest, err := s.t.Checker().Config(ctx, cat)
	if err != nil {
		return nil, configErr(cat, err)
	}
	if derived.InfoOf(catLatest.Doc).Level == derived.LevelE2E {
		return nil, errf(404, "not_offered", "%s is an end-to-end catalog: the catalog service issues no merge grants and checks no batch for it (§F.8)", cat)
	}
	if s.opt.MergeKey == nil {
		return nil, forbidden("this catalog service issues no merge grants: it has no merge key (§F.8)")
	}
	if v.Principal.ID != s.opt.MergeService {
		return nil, forbidden("merge grants are issued only to the merge service (%s), which submits them itself (§F.8)", s.opt.MergeService)
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
			switch h.State {
			case client.Live, client.Tombstoned:
				return nil, conflict("%s exists in %s; the batch's precondition is stale", name, cat)
			case client.Purged:
				// Answered after the checks, where organising requests put
				// 409 (mergeConflicts).
				mi.purged = true
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
		mi.tombstoned = h.State == client.Tombstoned
		cur, live := jsonv.Clone(mi.before), mi.beforeLive
		exists := mi.beforeLive || mi.tombstoned
		if mi.tombstoned && h.Last != "" {
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
			// A create applies to the document null, not to "no
			// document" (§6.2 step 3), as the core applies it: test ""
			// null and a root replace work on it.
			base := cur
			if !exists {
				base = nil
			}
			nd, writes, err := patch.Apply(base, true, ops, patch.Options{ResourceEnvelope: true})
			if err != nil {
				return nil, badInput("item %s step %d doesn't apply: %v", name, j, err)
			}
			if nd == nil && len(writes) == 0 && !exists {
				return nil, badInput("item %s step %d: a create must write the document; it applies to null (§6.2 step 3)", name, j)
			}
			cur, live, exists = nd, true, true
			if !mi.beforeLive {
				mi.made = nd
			}
		}
		if live {
			mi.after, mi.afterLive = cur, true
		}
		items = append(items, mi)
	}

	key, err := s.mergeKey(ctx)
	if err != nil {
		return nil, err
	}
	// Includes decide no widening, whoever approved (§F.8), so they are
	// read for every batch.
	incs, err := s.includesOfTrusted(ctx)
	if err != nil {
		return nil, err
	}
	// The documents of the content namespaces new placements bring in
	// (creates and restores, those the batch deletes again included, which
	// are checked as those creates are), whose place lists are read as of
	// the checkpoint below (configAt). A failure to read one matters only
	// once the namespace is trusted (placeConfig), as for a Place.
	latest := map[string]*grantcheck.Config{}
	cerrs := map[string]error{}
	for _, mi := range items {
		ns, _, ok := tree.SplitPlacement(mi.name)
		if !ok || mi.beforeLive {
			continue
		}
		if _, done := latest[ns]; done {
			continue
		}
		if _, done := cerrs[ns]; done {
			continue
		}
		cfg, err := s.t.Checker().Config(ctx, ns)
		if err != nil {
			cerrs[ns] = err
			continue
		}
		latest[ns] = cfg
	}

	// The items the batch names are its placements' (checkpointAt).
	var nss []string
	for _, mi := range items {
		if ns, _, ok := tree.SplitPlacement(mi.name); ok && !contains(nss, ns) {
			nss = append(nss, ns)
		}
	}
	var (
		cp, checkedAs string
		checkpoint    map[string]string
		checks        []MergeCheck
		needsAdmin    bool
	)
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
			changes[mi.name] = mi.doc()
		}
		after := g.With(changes)
		// read is the namespaces whose state the decision read beyond the
		// catalog and the items' (§B.11.4 checkpoint): the includes of
		// placements compared for no widening, and, for a caller not in
		// the admin group, the roles that decide visibility (organising).
		read := map[string]bool{}
		var orgs []*organising
		defer func() {
			ns := append([]string(nil), nss...)
			for _, o := range orgs {
				for x := range o.read {
					read[x] = true
				}
			}
			for x := range read {
				ns = append(ns, x)
			}
			checkpoint = checkpointAt(g, cur, ns...)
		}()
		incs = s.includesAt(g, incs)

		// Whether the batch needs the admin group (§F.8), whoever
		// approved: it changes $access or restores a folder, or else, it
		// widens.
		var why error
		for _, mi := range items {
			switch {
			case mi.accessChanged():
				why = forbidden("%s: changing $access needs %s (§B.11.3, §F.8)", mi.name, s.opt.AdminGroup)
			case mi.tombstoned && !mi.placement():
				why = forbidden("%s: folders are restored only by %s (§B.11.4, §F.8)", mi.name, s.opt.AdminGroup)
			}
			if why != nil {
				break
			}
		}
		var wd widened
		if why == nil {
			wd, needsAdmin = s.mergeWidening(g, after, items, incs, read)
		}
		needsAdmin = needsAdmin || why != nil

		// The callers: the approver, whose checks every batch passes and
		// who, for a batch that needs the admin group, must be in it (no
		// widening whoever approved); and for such a batch the admin whose
		// grant it goes under, whose dry run it is (F-T4), if that isn't
		// the approver. The approver's 404s and 403s come first: one who
		// may not see a node is told nothing more, not even that the batch
		// needs the admin group.
		callers := []*grant.Verified{av}
		if needsAdmin && adm != nil {
			callers = append(callers, adm)
		}
		for i, caller := range callers {
			admin := s.isAdmin(caller)
			if i > 0 && !admin {
				err = forbidden("the batch needs %s (§F.8), and the grant in %s isn't one of theirs", s.opt.AdminGroup, AdminHeader)
				return
			}
			o := s.organisingAt(g, caller, admin)
			orgs = append(orgs, o)
			if err = s.mergeNotFound(o, g, after, items); err != nil {
				return
			}
			if i == 0 && needsAdmin && !admin {
				if why == nil {
					why = s.wideningRefusal(o, g, wd)
				}
				err = why
				return
			}
			if checks, err = s.mergeChecks(o, caller, g, after, changes, items, latest, cerrs, catLatest); err != nil {
				return
			}
			checkedAs = caller.Principal.ID
		}
		err = mergeConflicts(g, items)
	})
	var nd notDecided
	if errors.As(err, &nd) {
		// From state the checkpoint doesn't pin: no checkpoint (decidedAt).
		return nil, nd.error
	}
	if err != nil {
		// The checks above are decisions at the checkpoint: their 403s,
		// 404s and 409s carry it (decidedAt).
		return nil, decidedAt(err, checkpoint)
	}
	out := &MergeGrant{ApprovedBy: av.Principal.ID, CheckedAs: checkedAs, Checks: checks, Checkpoint: checkpoint}
	if needsAdmin {
		// The admin group, which the merge key may never assert: checked
		// here as a dry run, submitted under an admin's grant narrowed by
		// the merge service (§F.8).
		out.Admin = true
		return out, nil
	}
	// The batch's pairs of /resource and /action, as one alternative per
	// action naming its resources, so the rule's forms stay within
	// rulesPerGrant (§12.2) however many items the batch has.
	var can []string
	names := map[string][]any{}
	for _, mi := range items {
		for _, a := range mi.actions {
			if !contains(can, a) {
				can = append(can, a)
			}
			names[a] = append(names[a], mi.name)
		}
	}
	sort.Strings(can)
	alts := []any{}
	for _, a := range can {
		alts = append(alts, map[string]any{"all": []any{
			map[string]any{"op": "test", "path": "/action", "value": a},
			map[string]any{"op": "compare", "path": "/resource", "in": map[string]any{"value": names[a]}},
		}})
	}
	for _, a := range can {
		if !key.IsStar() && !contains(key.Can, a) {
			return nil, forbidden("the merge key may not %s in %s", a, cat)
		}
	}
	p := &plan{ns: cat, resource: "", can: can, rules: []any{map[string]any{"any": alts}}, cp: cp, checkpoint: checkpoint, key: key}
	is, err := s.mintMerge(ctx, v, av, p)
	if err != nil {
		return nil, err
	}
	out.Issued = is
	return out, nil
}

// mergeWidening reports the first widening the batch makes (§B.11.4 No
// widening, §F.8), in batch order: at a node the graph has, for every
// subject, its roles after the batch must be a subset of those before,
// both computed as for live items (§B.11.2), so a deleted item's
// placement counts too. Only a node whose existence, parents or $access
// the batch changes, and the nodes below it along every edge of the graph
// before or after, can change: that covers moves, and anything else that
// changes a walk up, such as a new folder a dangling parents entry already
// names (refused 409 after the 403s anyway, mergeConflicts), or a deleted
// node that made others cyclic. New nodes are judged by the place
// checks instead (an implicit placement collects nothing, so an explicit
// one that replaces it is new). A placement the batch places again is
// compared with its deleted placement's rows, none if the service holds
// none (unplacedRows, §B.11.7). It notes in read the namespaces whose
// includes it compared with. Call it under View.
func (s *Service) mergeWidening(g, after *tree.Graph, items []*mergeItem, incs map[string]Includes, read map[string]bool) (widened, bool) {
	done := map[string]bool{}
	compare := func(d string) {
		if ns, _, ok := tree.SplitPlacement(d); ok {
			read[ns] = true
		}
	}
	for _, mi := range items {
		if mi.tombstoned {
			done[mi.name] = true
			if !mi.afterLive || !mi.placement() {
				continue
			}
			kept, _ := s.unplacedRows(mi.name)
			compare(mi.name)
			if subj, r, bad := widening(mi.name, Effective(after, mi.name, nil), kept, incs); bad {
				return widened{by: mi.name, node: mi.name, subject: subj, role: r, replace: true}, true
			}
		}
	}
	for _, mi := range items {
		if mi.beforeLive && mi.afterLive && !mi.accessChanged() && sameParents(parentsOf(g.Catalog, mi.before), parentsOf(g.Catalog, mi.after)) {
			// An edit that keeps the node's parents and $access changes
			// no walk up (§B.11.2).
			continue
		}
		below := g.Descendants([]string{mi.name})
		for d := range after.Descendants([]string{mi.name}) {
			below[d] = true
		}
		nodes := make([]string, 0, len(below))
		for d := range below {
			nodes = append(nodes, d)
		}
		sort.Strings(nodes)
		for _, d := range nodes {
			if done[d] {
				continue
			}
			done[d] = true
			if bn := g.Node(d); bn == nil || bn.Self || after.Node(d) == nil {
				continue
			}
			compare(d)
			if subj, r, bad := widening(d, Effective(after, d, nil), Effective(g, d, nil), incs); bad {
				return widened{by: mi.name, node: d, subject: subj, role: r}, true
			}
		}
	}
	return widened{}, false
}

// wideningRefusal is the 403 for a widening batch, refused to a caller not
// in the admin group. It names the node and the role only where the
// caller sees the node; otherwise only the batch's item whose change
// widens, which the caller sees (mergeNotFound), so nothing about a hidden
// node appears (§B.11, §B.11.5).
func (s *Service) wideningRefusal(o *organising, g *tree.Graph, wd widened) error {
	switch {
	case wd.replace:
		return forbidden("re-placing %s would give %s the role %s, which it didn't have when its placement was deleted; that needs %s (§B.11.4, §F.8)",
			wd.node, wd.subject, wd.role, s.opt.AdminGroup)
	case o.sees(g.Node(wd.node)):
		return forbidden("the batch would give %s the role %s on %s; widening needs %s (§B.11.4, §F.8)", wd.subject, wd.role, g.Href(wd.node), s.opt.AdminGroup)
	}
	return forbidden("the batch's change of %s would widen access below it; widening needs %s (§B.11.4, §F.8)", wd.by, s.opt.AdminGroup)
}

// mergeNotFound answers the batch's 404s as organising requests answer
// them (§B.11.4, §B.11.5): an item naming a node of the catalog that is
// hidden from a caller not in the admin group, as a missing one, or that
// restores a tombstoned folder, which only admins restore, and a
// to entry (a new node's parent, or any parent of a moved node after the
// batch, those it keeps included, as Move's to) that isn't a live folder
// of the catalog after the batch, or that, existing before, is hidden from
// such a caller. A folder the batch creates is the caller's own, whose
// parents are judged in turn. A new folder's name and a placement's are
// exempt. Call it under View.
func (s *Service) mergeNotFound(o *organising, g, after *tree.Graph, items []*mergeItem) error {
	for _, mi := range items {
		switch {
		case mi.beforeLive:
			if _, err := o.node(mi.name); err != nil {
				return err
			}
		case mi.tombstoned && !mi.placement() && !o.admin:
			// Folders are restored only by catalog admins: to anyone else a
			// request naming a tombstoned folder is 404 (§B.11.4 unplace or
			// delete a folder), as node answers it, reading every trusted
			// namespace as for any folder's name.
			o.readTrusted()
			return errf(404, "not_found", "no node %s in %s", mi.name, g.Catalog)
		}
	}
	for _, mi := range items {
		var tos []tree.Parent
		switch {
		case !mi.beforeLive:
			tos = parentsOf(g.Catalog, mi.made)
		case mi.afterLive:
			// A move's to is every parent the node has after it, those it
			// keeps included, as Move's to entries are each checked
			// (targets); an edit that keeps the parents names none.
			if bp, ap := parentsOf(g.Catalog, mi.before), parentsOf(g.Catalog, mi.after); !sameParents(bp, ap) {
				tos = ap
			}
		}
		if len(tos) > 0 && !o.admin {
			o.readTrusted()
		}
		for _, p := range tos {
			n := after.Node(p.Name)
			if p.Name == "" || n == nil || n.Self || n.Kind != tree.KindFolder {
				return errf(404, "not_found", "no folder %s in %s", parentLabel(p), g.Catalog)
			}
			if bn := g.Node(p.Name); g.Explicit(p.Name) && (bn.Cyclic || !o.sees(bn)) {
				return errf(404, "not_found", "no folder %s in %s", p.Name, g.Catalog)
			}
		}
	}
	return nil
}

// mergeChecks is the batch's 403s for caller (§B.11.4, the list in the
// comment above IssueMerge), after its 404s (mergeNotFound), with o its
// organising view; it reports what it checked per item. Call it under
// View.
func (s *Service) mergeChecks(o *organising, caller *grant.Verified, g, after *tree.Graph, changes map[string]any, items []*mergeItem,
	latest map[string]*grantcheck.Config, cerrs map[string]error, catLatest *grantcheck.Config) ([]MergeCheck, error) {
	cat := g.Catalog
	admin := o.admin
	var checks []MergeCheck
	// Tree powers as for organising requests (powers): admins need
	// none; on a folder the same batch creates they are judged in the
	// batch's result, where one without $access has, per subject, the
	// powers held at all its parents (§B.11.2, §B.11.4 create a
	// folder).
	ck := s.keyAt(g, cat, catLatest)
	pwBefore, pwAfter := powersAt(g, ck, callerOf(caller)), powersAt(after, ck, callerOf(caller))
	power := func(folder, p string) bool {
		if admin {
			return true
		}
		if g.Explicit(folder) {
			if _, changed := changes[folder]; !changed {
				return pwBefore.has(folder, p)
			}
			return pwBefore.has(folder, p) || pwAfter.has(folder, p)
		}
		if doc, created := changes[folder]; created && doc != nil {
			return pwAfter.has(folder, p)
		}
		return false
	}
	// Place lists as of the checkpoint (configAt), as for POST /grants,
	// for the caller's subjects.
	subs := Subjects(caller)
	for _, mi := range items {
		chk := MergeCheck{Resource: mi.name, Actions: mi.actions}
		bp, ap := parentsOf(cat, mi.before), parentsOf(cat, mi.after)
		switch {
		case !mi.beforeLive:
			// Creating a folder needs move on every folder it goes
			// into (§B.11.4 create a folder), placing place (§B.11.4
			// place).
			ap = parentsOf(cat, mi.made)
			want := "move"
			chk.Change = "create-folder"
			switch {
			case mi.placement():
				chk.Change, want = "place", "place"
				ns, _, ok := tree.SplitPlacement(mi.name)
				if !ok || !g.Trust[ns] {
					return nil, forbidden("%s: namespace %s is not trusted by catalog %s", mi.name, ns, cat)
				}
				ccur := s.placeConfig(g, ns, latest[ns])
				if ccur == nil {
					// Not decided at the checkpoint (decidedAt), as for a
					// Place.
					cerr := cerrs[ns]
					if cerr == nil {
						cerr = errors.New("namespace " + ns + " has no document the service could read")
					}
					return nil, notDecided{configErr(ns, cerr)}
				}
				if !inPlaceList(ccur.Doc, cat, subs) {
					return nil, forbidden("%s: namespace %s does not let you place its items in %s (catalogs.%s.place)", mi.name, ns, cat, cat)
				}
			case mi.tombstoned:
				// An admin's (IssueMerge: it needs the admin group).
				chk.Change = "restore-folder"
			}
			if len(ap) == 0 && !admin {
				return nil, forbidden("%s: only %s make roots", mi.name, s.opt.AdminGroup)
			}
			for _, p := range ap {
				if !power(p.Name, want) {
					return nil, forbidden("%s: no role of yours with %s is assigned on %s", mi.name, want, parentLabel(p))
				}
			}
		case !mi.afterLive:
			chk.Change = "delete"
			if err := o.leaves(g.Node(mi.name), "delete"); err != nil {
				return nil, err
			}
			for _, p := range bp {
				if !power(p.Name, "move") {
					return nil, forbidden("%s: no role of yours with move is assigned on %s", mi.name, parentLabel(p))
				}
			}
		case !sameParents(bp, ap):
			chk.Change = "move"
			if err := o.leaves(g.Node(mi.name), "move"); err != nil {
				return nil, err
			}
			if len(ap) == 0 && !admin {
				return nil, forbidden("%s: only %s make roots", mi.name, s.opt.AdminGroup)
			}
			// Move on every folder in to, the node's parents after the
			// batch, those it keeps included, and on every parent it
			// leaves (§B.11.4 move), as planMove checks them.
			below := after.Descendants([]string{mi.name})
			for _, p := range ap {
				if below[p.Name] {
					return nil, forbidden("%s can't move under %s, which is itself or below it", mi.name, p.Name)
				}
				if !power(p.Name, "move") {
					return nil, forbidden("%s: no role of yours with move is assigned on %s", mi.name, parentLabel(p))
				}
			}
			for _, p := range added(ap, bp) {
				if !power(p.Name, "move") {
					return nil, forbidden("%s: no role of yours with move is assigned on %s, which the node leaves", mi.name, parentLabel(p))
				}
			}
		default:
			chk.Change = "edit"
			if mi.accessChanged() {
				// An admin's (IssueMerge: it needs the admin group), who
				// needs no power.
				chk.Change = "access"
				break
			}
			if err := o.leaves(g.Node(mi.name), "edit"); err != nil {
				return nil, err
			}
			for _, p := range ap {
				if !power(p.Name, "move") {
					return nil, forbidden("%s: no role of yours with move is assigned on %s", mi.name, parentLabel(p))
				}
			}
		}
		checks = append(checks, chk)
	}
	return checks, nil
}

// placeConfig is a trusted content namespace's document as of the
// checkpoint, whose place list a new placement is checked against: the
// graph's, or latest, the checker's at the head, where the graph has none
// (configAt); nil if neither, when the service couldn't read it, which
// matters only for a trusted namespace (planPlace). Call it under View.
func (s *Service) placeConfig(g *tree.Graph, ns string, latest *grantcheck.Config) *grantcheck.Config {
	if latest != nil {
		return s.configAt(g, ns, latest)
	}
	if c := g.Content[ns]; c != nil {
		return s.parsed(c).cfg
	}
	return nil
}

// notDecided marks a merge answer from state the checkpoint doesn't pin,
// such as the core's head of a name or a namespace document the service
// couldn't read: it carries no checkpoint (decidedAt).
type notDecided struct{ error }

func (e notDecided) Unwrap() error { return e.error }

// mergeConflicts is the batch's answers after every caller's 404s and
// 403s, in batch order, where organising requests put 409 (§B.11.4): a new
// folder's name that a parents entry or accepted $parents names, hidden
// ones included, is 409 (create a folder: names are not secrets, and the
// folder would adopt every node that names it, giving it roles and powers
// a dangling entry gives none, §B.11.2); and, from the core's head, a
// purged placement is 410, as a Place of one, and a purged folder's name
// 409, as one that existed (create a folder), neither decided at the
// checkpoint. Call it under View.
func mergeConflicts(g *tree.Graph, items []*mergeItem) error {
	for _, mi := range items {
		switch {
		case mi.purged && mi.placement():
			return notDecided{errf(410, "gone", "%s was purged in %s", mi.name, g.Catalog)}
		case mi.purged:
			return notDecided{conflict("%s existed in %s; a new folder needs a name no node has or had (§B.11.4)", mi.name, g.Catalog)}
		case !mi.beforeLive && !mi.tombstoned && !mi.placement() && len(g.DeclaredChildren(mi.name)) > 0:
			return conflict("a parents entry in %s names %s; a new folder needs a name no parents entry names, hidden ones included (§B.11.4)", g.Catalog, mi.name)
		}
	}
	return nil
}

// parentsOf is a node document's parents entries, once per node name (an
// entry that isn't a live link to a node of the catalog once per href),
// sorted.
func parentsOf(cat string, doc any) []tree.Parent {
	var out []tree.Parent
	seen := map[string]bool{}
	for _, p := range tree.ParseNode(cat, "x", "", doc).Parents {
		k := p.Name
		if k == "" {
			k = "\x00" + p.Href
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return parentKey(out[i]) < parentKey(out[j]) })
	return out
}

func parentKey(p tree.Parent) string {
	if p.Name == "" {
		return "\x00" + p.Href
	}
	return p.Name
}

// added is the entries of b that a doesn't have.
func added(a, b []tree.Parent) []tree.Parent {
	have := map[string]bool{}
	for _, p := range a {
		have[parentKey(p)] = true
	}
	var out []tree.Parent
	for _, p := range b {
		if !have[parentKey(p)] {
			out = append(out, p)
		}
	}
	return out
}

func sameParents(a, b []tree.Parent) bool {
	return len(added(a, b)) == 0 && len(added(b, a)) == 0
}

// mergeKey is the merge key's entry in the catalog namespace (§F.8).
func (s *Service) mergeKey(ctx context.Context) (*grant.Key, error) {
	cfg, err := s.t.Checker().Config(ctx, s.t.Catalog())
	if err != nil {
		return nil, configErr(s.t.Catalog(), err)
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
	return &Issued{Grant: g.Encode(), NS: p.ns, Can: p.can, Exp: exp.Format(time.RFC3339Nano), At: at, Checkpoint: p.checkpoint}, nil
}

func (mi *mergeItem) addAction(a string) {
	if !contains(mi.actions, a) {
		mi.actions = append(mi.actions, a)
	}
}
