package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/tree"
)

// Request is the body of POST /grants (§B.11.4):
//
//	{ "item": "/r/matches/derby", "want": ["read", "append"] }        content verbs, from effective roles
//	{ "item": "/r/matches/final", "want": ["create"] }                 genesis of a placed, never-existing item
//	{ "item": "/r/matches/derby", "want": ["place"], "to": [folders] } create the placement
//	{ "node": "matches.derby",    "want": ["move"],  "to": [folders] } replace the node's parents
//	{ "node": "matches.derby",    "want": ["delete"] }                  unplace
//
// Folders and nodes may be given as /r/{catalog}/{name} or bare names.
type Request struct {
	Item string   `json:"item,omitempty"`
	Node string   `json:"node,omitempty"`
	Want []string `json:"want"`
	To   []string `json:"to,omitempty"`
}

// Issued is an issued grant.
type Issued struct {
	Grant    string         `json:"grant"`
	NS       string         `json:"ns"`
	Resource string         `json:"resource"`
	Can      []string       `json:"can"`
	Roles    []string       `json:"roles,omitempty"`
	Exp      string         `json:"exp"`
	At       map[string]any `json:"at"`
}

// Error is a refusal with an HTTP status.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Msg) }

func errf(status int, code, format string, a ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

func badInput(format string, a ...any) error  { return errf(400, "bad_input", format, a...) }
func forbidden(format string, a ...any) error { return errf(403, "forbidden", format, a...) }
func conflict(format string, a ...any) error  { return errf(409, "conflict", format, a...) }

func upstream(err error) error {
	return &Error{Status: 502, Code: "upstream", Msg: err.Error()}
}

// plan is a decision, made under the graph lock at a checkpoint.
type plan struct {
	ns, resource string
	can, roles   []string
	rules        []any
	cp           string
	key          *grant.Key
}

// Authenticate verifies a caller's grant for the catalog namespace.
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (*grant.Verified, error) {
	return s.t.Checker().Verify(ctx, s.t.Catalog(), tree.Bearer(r))
}

func (s *Service) serveGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, err := s.Authenticate(r.Context(), r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	var req Request
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.Issue(r.Context(), v, req)
	if err != nil {
		writeErr(w, err)
		return
	}
	tree.WriteJSON(w, http.StatusOK, res)
}

// ReadGrantsRequest is the body of POST /read-grants (§B.11.5).
type ReadGrantsRequest struct {
	Items []string `json:"items"`
}

const maxReadGrants = 100

// serveReadGrants issues one read grant per item, fixed to that resource
// (§B.11.5). Items of public namespaces need none; refusals are reported
// per item.
func (s *Service) serveReadGrants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	v, err := s.Authenticate(ctx, r)
	if err != nil {
		tree.WriteAuthError(w, err, logf(s))
		return
	}
	var req ReadGrantsRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if len(req.Items) == 0 || len(req.Items) > maxReadGrants {
		writeErr(w, badInput("items must list 1 to %d items", maxReadGrants))
		return
	}
	lagOK := map[string]bool{}
	out := []any{}
	for _, item := range req.Items {
		e := map[string]any{"item": item}
		if ns, _, ok := tree.ParseHref(item); ok && ns != s.t.Catalog() {
			if cfg, err := s.t.Checker().Config(ctx, ns); err == nil && cfg.Read == "public" {
				e["public"] = true
				out = append(out, e)
				continue
			}
		}
		p, err := s.planContent(ctx, v, item, []string{"read"})
		var is *Issued
		if err == nil {
			is, err = s.mint(ctx, v, p, lagOK)
		}
		if err != nil {
			var ce *Error
			if !errors.As(err, &ce) {
				ce = &Error{Status: 500, Code: "internal", Msg: err.Error()}
			}
			e["error"] = map[string]any{"status": ce.Status, "code": ce.Code, "message": ce.Msg}
		} else {
			e["grant"], e["exp"] = is.Grant, is.Exp
		}
		out = append(out, e)
	}
	tree.WriteJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func logf(s *Service) func(string, ...any) {
	if s.opt.Tree.Logf != nil {
		return s.opt.Tree.Logf
	}
	return func(string, ...any) {}
}

func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return badInput("cannot read the body")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return badInput("malformed body: %v", err)
	}
	return nil
}

func writeErr(w http.ResponseWriter, err error) {
	var ce *Error
	if errors.As(err, &ce) {
		if ce.Status == 503 {
			w.Header().Set("Retry-After", "1")
		}
		tree.WriteError(w, ce.Status, ce.Code, ce.Msg)
		return
	}
	tree.WriteError(w, 500, "internal", err.Error())
}

// Issue decides a grant request for the verified caller v and signs the
// grant (§B.11.4).
func (s *Service) Issue(ctx context.Context, v *grant.Verified, req Request) (*Issued, error) {
	want := dedupe(req.Want)
	var p *plan
	var err error
	switch {
	case len(want) == 0:
		return nil, badInput("want is required")
	case contains(want, "place"):
		if len(want) != 1 || req.Item == "" {
			return nil, badInput(`place takes an item and want ["place"]`)
		}
		p, err = s.planPlace(ctx, v, req.Item, req.To)
	case contains(want, "move"):
		if len(want) != 1 || req.Node == "" {
			return nil, badInput(`move takes a node and want ["move"]`)
		}
		p, err = s.planMove(ctx, v, req.Node, req.To)
	case req.Node != "":
		if len(want) != 1 || want[0] != "delete" {
			return nil, badInput(`a node request wants ["move"] or ["delete"]`)
		}
		p, err = s.planUnplace(ctx, v, req.Node)
	case req.Item != "":
		p, err = s.planContent(ctx, v, req.Item, want)
	default:
		return nil, badInput("item or node is required")
	}
	if err != nil {
		return nil, err
	}
	return s.mint(ctx, v, p, map[string]bool{})
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func resourceRule(name string) any {
	return map[string]any{"op": "test", "path": "/resource", "value": name}
}

// parentsRule fixes /doc/parents to exactly the given folders (any order,
// any order keys).
func parentsRule(catalog string, folders []string) any {
	hrefs := make([]any, len(folders))
	var all []any
	for i, f := range folders {
		hrefs[i] = "/r/" + catalog + "/" + f
		all = append(all, map[string]any{"contains": map[string]any{
			"type": "object", "required": []any{"href"},
			"properties": map[string]any{"href": map[string]any{"const": hrefs[i]}}}})
	}
	sch := map[string]any{
		"type": "array", "minItems": len(folders), "maxItems": len(folders),
		"items": map[string]any{"type": "object", "required": []any{"href"},
			"properties": map[string]any{"href": map[string]any{"enum": hrefs}}},
	}
	if len(all) > 0 {
		sch["allOf"] = all
	}
	return map[string]any{"op": "test", "path": "/doc/parents", "schema": sch}
}

// planContent decides content verbs (read, append, create, …) on an item
// from the caller's effective roles at its placement (§B.11.4).
func (s *Service) planContent(ctx context.Context, v *grant.Verified, item string, want []string) (*plan, error) {
	for _, w := range want {
		if !grant.IsVerb(w) {
			return nil, badInput("unknown verb %q", w)
		}
	}
	cat := s.t.Catalog()
	ns, name, ok := tree.ParseHref(item)
	if !ok {
		return nil, badInput("item must be /r/{ns}/{name}")
	}
	if ns == cat {
		return nil, badInput("catalog documents are organised with place, move and delete")
	}
	create := contains(want, "create")
	if create && len(want) != 1 {
		return nil, badInput("create can't be combined with other verbs")
	}
	cfg, err := s.t.Checker().Config(ctx, ns)
	if err != nil {
		return nil, upstream(err)
	}
	key := findKey(cfg.Keys, s.opt.Kid)
	if key == nil {
		return nil, forbidden("namespace %s does not list the catalog's key %q", ns, s.opt.Kid)
	}
	subs := Subjects(v)
	pl := ns + "." + name
	var (
		trusted, placed bool
		state, itemSt   int
		roles           map[string]bool
		cp              string
	)
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		trusted = g.Trust[ns]
		if n := g.Node(pl); n != nil && !n.Self {
			placed, state, itemSt = true, n.State, n.ItemState
		}
		roles = s.rolesFor(pl, subs)
		cp = cur[cat]
	})
	switch {
	case !trusted:
		return nil, forbidden("namespace %s is not trusted by catalog %s", ns, cat)
	case !placed:
		return nil, forbidden("%s is not placed in catalog %s", item, cat)
	case create:
		// A create grant can only ever produce the genesis: refuse names that
		// exist or existed (§B.11.4).
		if itemSt != tree.ItemUnknown {
			return nil, conflict("%s exists or existed", item)
		}
		h, err := s.t.Client().Head(ctx, ns, name)
		if err != nil {
			return nil, upstream(err)
		}
		if h.State != client.NotFound {
			return nil, conflict("%s exists or existed", item)
		}
	case state != tree.StateLive:
		// A dangling placement grants nothing (§B.11.2).
		return nil, forbidden("the placement of %s is dangling", item)
	}
	var kept, can []string
	for r := range roles {
		def, ok := cfg.Roles[r]
		if !ok || !roleAllowed(key, r) {
			continue
		}
		for _, c := range def.Can {
			if contains(want, c) {
				kept = append(kept, r)
				break
			}
		}
	}
	for _, w := range want {
		if !key.IsStar() && !contains(key.Can, w) {
			continue
		}
		for _, r := range kept {
			if contains(cfg.Roles[r].Can, w) {
				can = append(can, w)
				break
			}
		}
	}
	if len(can) == 0 {
		return nil, forbidden("no role of yours allows %s on %s", strings.Join(want, ", "), item)
	}
	var final []string
	for _, r := range kept {
		for _, c := range can {
			if contains(cfg.Roles[r].Can, c) {
				final = append(final, r)
				break
			}
		}
	}
	sort.Strings(final)
	return &plan{ns: ns, resource: name, can: can, roles: final, rules: []any{resourceRule(name)}, cp: cp, key: key}, nil
}

// folders resolves a to list to distinct folder names.
func (s *Service) folders(to []string) ([]string, error) {
	var out []string
	for _, f := range to {
		name, ok := tree.Resolve(s.t.Catalog(), f)
		if !ok {
			return nil, badInput("malformed folder %q", f)
		}
		if !contains(out, name) {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, badInput("to must name at least one folder")
	}
	return out, nil
}

func liveFolder(g *tree.Graph, name string) bool {
	n := g.Node(name)
	return n != nil && n.Kind == tree.KindFolder && !n.Cyclic
}

// hasPower reports whether a subject of subs is assigned, directly on
// folder, a catalog role with the tree power (move or place, §B.11.1).
func hasPower(g *tree.Graph, folder string, subs map[string]bool, power string) bool {
	n := g.Node(folder)
	if n == nil {
		return false
	}
	roles, _ := g.Config["roles"].(map[string]any)
	for subj, rs := range n.Access {
		if !subs[subj] {
			continue
		}
		for _, r := range rs {
			if def, _ := roles[r].(map[string]any); def[power] == true {
				return true
			}
		}
	}
	return false
}

func (s *Service) isAdmin(v *grant.Verified) bool {
	for _, g := range v.Principal.Groups {
		if g == s.opt.AdminGroup || g == "group:"+s.opt.AdminGroup {
			return true
		}
	}
	return false
}

func (s *Service) catalogKey(ctx context.Context) (*grant.Key, error) {
	cfg, err := s.t.Checker().Config(ctx, s.t.Catalog())
	if err != nil {
		return nil, upstream(err)
	}
	key := findKey(cfg.Keys, s.opt.Kid)
	if key == nil {
		return nil, forbidden("the catalog namespace does not list the catalog's key %q", s.opt.Kid)
	}
	return key, nil
}

// planPlace decides a placement (§B.11.4): the caller is in the content
// namespace's catalogs.{catalog}.place list, and has a role with place
// assigned on every target folder.
//
// The catalog only issues the grant; the client writes the placement
// document. Clients should give every placement (create or restore) a
// fresh random $nonce (§C.7, §B.11.4), so its revision ids can't be used to
// confirm guesses of its content; the grant's rules fix only /resource and
// /doc/parents, so a $nonce is always allowed.
func (s *Service) planPlace(ctx context.Context, v *grant.Verified, item string, to []string) (*plan, error) {
	cat := s.t.Catalog()
	ns, name, ok := tree.ParseHref(item)
	if !ok || ns == cat {
		return nil, badInput("item must be /r/{ns}/{name} of a content namespace")
	}
	pl := ns + "." + name
	if !client.ValidResourceName(pl) {
		return nil, badInput("the placement name %s is not a valid resource name", pl)
	}
	tos, err := s.folders(to)
	if err != nil {
		return nil, err
	}
	ccfg, err := s.t.Checker().Config(ctx, ns)
	if err != nil {
		return nil, upstream(err)
	}
	subs := Subjects(v)
	if !inPlaceList(ccfg.Doc, cat, subs) {
		return nil, forbidden("namespace %s does not let you place its items in %s (catalogs.%s.place)", ns, cat, cat)
	}
	key, err := s.catalogKey(ctx)
	if err != nil {
		return nil, err
	}
	var cp string
	err = nil
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		if !g.Trust[ns] {
			err = errf(422, "untrusted", "namespace %s is not trusted by catalog %s", ns, cat)
			return
		}
		for _, f := range tos {
			if !liveFolder(g, f) {
				err = errf(422, "not_folder", "%s is not a live folder of %s", f, cat)
				return
			}
			if !hasPower(g, f, subs, "place") {
				err = forbidden("no role of yours with place is assigned on %s", f)
				return
			}
		}
		if n := g.Node(pl); n != nil && !n.Self {
			err = conflict("%s is already placed in %s; move it instead", item, cat)
		}
	})
	if err != nil {
		return nil, err
	}
	verb := "create"
	h, herr := s.t.Client().Head(ctx, cat, pl)
	switch {
	case herr != nil:
		return nil, upstream(herr)
	case h.State == client.Live:
		return nil, conflict("%s is already placed in %s; move it instead", item, cat)
	case h.State == client.Purged:
		return nil, conflict("the placement %s was purged", pl)
	case h.State == client.Tombstoned:
		// Re-placing restores the old placement (§B.11.4): the grant carries
		// only restore, never create or append, and the client restores
		// with a root replace. What stops a restore-only grant from acting
		// as a move is the core's gate (§6.2 v0.21 candidate verbs): if the
		// placement is live again by the time the grant is used, the PATCH
		// settles as an append, which isn't a candidate verb, and is refused
		// at step 2 before the If-Match comparison, so nothing about the
		// live document is checked or revealed. On a still-deleted
		// placement the restore sees the last live document at step 3, as
		// any restore does.
		if !key.IsStar() && !contains(key.Can, "restore") {
			return nil, conflict("the placement %s was deleted and the catalog's key may not restore it", pl)
		}
		verb = "restore"
	}
	return &plan{ns: cat, resource: pl, can: []string{verb}, rules: []any{resourceRule(pl), parentsRule(cat, tos)}, cp: cp, key: key}, nil
}

func inPlaceList(doc map[string]any, cat string, subs map[string]bool) bool {
	cs, _ := doc["catalogs"].(map[string]any)
	c, _ := cs[cat].(map[string]any)
	list, _ := c["place"].([]any)
	for _, x := range list {
		if s, ok := x.(string); ok && subs[s] {
			return true
		}
	}
	return false
}

// planMove decides a move (§B.11.4): a role with move on every current
// parent the node leaves and on every target folder, and no widening of
// anyone's effective roles in the moved subtree unless the caller is a
// catalog admin.
func (s *Service) planMove(ctx context.Context, v *grant.Verified, node string, to []string) (*plan, error) {
	cat := s.t.Catalog()
	name, ok := tree.Resolve(cat, node)
	if !ok {
		return nil, badInput("malformed node")
	}
	tos, err := s.folders(to)
	if err != nil {
		return nil, err
	}
	key, err := s.catalogKey(ctx)
	if err != nil {
		return nil, err
	}
	subs := Subjects(v)
	admin := s.isAdmin(v)
	var incs map[string]includes
	if !admin {
		if incs, err = s.includesOfTrusted(ctx); err != nil {
			return nil, err
		}
	}
	var cp string
	err = nil
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		n := g.Node(name)
		if n == nil || n.Self {
			err = errf(404, "not_found", "no node %s in %s", name, cat)
			return
		}
		below := g.Descendants([]string{name})
		for _, f := range tos {
			if !liveFolder(g, f) {
				err = errf(422, "not_folder", "%s is not a live folder of %s", f, cat)
				return
			}
			if below[f] {
				err = conflict("moving %s under %s would make a cycle", name, f)
				return
			}
			if !hasPower(g, f, subs, "move") {
				err = forbidden("no role of yours with move is assigned on %s", f)
				return
			}
		}
		for _, p := range n.Parents {
			if p.Name == "" || contains(tos, p.Name) {
				continue
			}
			if pn := g.Node(p.Name); pn != nil && pn.Kind == tree.KindFolder && !hasPower(g, p.Name, subs, "move") {
				err = forbidden("no role of yours with move is assigned on %s, which the node leaves", p.Name)
				return
			}
		}
		if !admin {
			if subj, at, role, bad := s.widens(g, name, tos, incs); bad {
				err = forbidden("the move would give %s the role %s on %s", subj, role, g.Href(at))
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return &plan{ns: cat, resource: name, can: []string{"append"}, cp: cp, key: key, rules: []any{
		resourceRule(name), parentsRule(cat, tos),
		map[string]any{"op": "writes", "within": []any{"/parents"}}}}, nil
}

// includes is one content namespace's declared role inclusions (§B.11.4):
// role -> the roles it names in "includes".
type includes map[string][]string

// parseIncludes reads "includes" from a namespace document's roles. Other
// role fields are the core's business; a malformed includes counts as none.
func parseIncludes(doc map[string]any) includes {
	out := includes{}
	roles, _ := doc["roles"].(map[string]any)
	for r, def := range roles {
		d, _ := def.(map[string]any)
		list, _ := d["includes"].([]any)
		for _, x := range list {
			if name, ok := x.(string); ok {
				out[r] = append(out[r], name)
			}
		}
	}
	return out
}

// closure is every role present given roles: the roles themselves and,
// transitively, every role they include. Cycles in includes are harmless:
// each role is visited once.
func (inc includes) closure(roles []string) map[string]bool {
	out := map[string]bool{}
	stack := append([]string(nil), roles...)
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[r] {
			continue
		}
		out[r] = true
		stack = append(stack, inc[r]...)
	}
	return out
}

// includesOfTrusted reads the includes of every trusted content namespace.
// The declarations are trusted as written: changing /roles needs a * key
// in that namespace (§B.11.4, §C.1.1).
func (s *Service) includesOfTrusted(ctx context.Context) (map[string]includes, error) {
	var trust []string
	s.t.View(func(g *tree.Graph, _ map[string]string) {
		for ns := range g.Trust {
			trust = append(trust, ns)
		}
	})
	out := map[string]includes{}
	for _, ns := range trust {
		cfg, err := s.t.Checker().Config(ctx, ns)
		if err != nil {
			return nil, upstream(err)
		}
		out[ns] = parseIncludes(cfg.Doc)
	}
	return out, nil
}

// present reports whether role r counts as present before the move at
// node d, given the roles before (§B.11.4: it, or a role including it,
// was present). For a placement, includes are read from its item's own
// content namespace. A folder's roles reach whatever is, or will be,
// placed below it, so for a folder r must be implied in every trusted
// content namespace (a namespace declaring nothing implies nothing).
func present(g *tree.Graph, d, r string, before []string, incs map[string]includes) bool {
	if contains(before, r) {
		return true
	}
	if n := g.Node(d); n != nil && n.ItemNS != "" {
		return incs[n.ItemNS].closure(before)[r]
	}
	if len(incs) == 0 {
		return false
	}
	for _, inc := range incs {
		if !inc.closure(before)[r] {
			return false
		}
	}
	return true
}

// widens reports a subject, node and role that a move of name to tos
// would add to the effective roles of the moved subtree (§B.11.4). Roles
// are compared by name, with the content namespace's declared includes.
func (s *Service) widens(g *tree.Graph, name string, tos []string, incs map[string]includes) (subject, node, role string, bad bool) {
	override := map[string][]string{name: tos}
	below := g.Descendants([]string{name})
	nodes := make([]string, 0, len(below))
	for d := range below {
		nodes = append(nodes, d)
	}
	sort.Strings(nodes)
	for _, d := range nodes {
		after := Effective(g, d, override)
		before := s.eff[d]
		subjects := make([]string, 0, len(after))
		for subj := range after {
			subjects = append(subjects, subj)
		}
		sort.Strings(subjects)
		for _, subj := range subjects {
			for _, r := range after[subj] {
				if !present(g, d, r, before[subj], incs) {
					return subj, d, r, true
				}
			}
		}
	}
	return "", "", "", false
}

// planUnplace decides deleting a placement: a role with move on every
// current parent (§B.11.4).
func (s *Service) planUnplace(ctx context.Context, v *grant.Verified, node string) (*plan, error) {
	cat := s.t.Catalog()
	name, ok := tree.Resolve(cat, node)
	if !ok {
		return nil, badInput("malformed node")
	}
	if !strings.Contains(name, ".") {
		return nil, errf(422, "not_placement", "only placements can be unplaced; %s is a folder", name)
	}
	key, err := s.catalogKey(ctx)
	if err != nil {
		return nil, err
	}
	subs := Subjects(v)
	var cp string
	err = nil
	s.t.View(func(g *tree.Graph, cur map[string]string) {
		cp = cur[cat]
		n := g.Node(name)
		if n == nil || n.Self {
			err = errf(404, "not_found", "no placement %s in %s", name, cat)
			return
		}
		for _, p := range n.Parents {
			if pn := g.Node(p.Name); p.Name != "" && pn != nil && pn.Kind == tree.KindFolder && !hasPower(g, p.Name, subs, "move") {
				err = forbidden("no role of yours with move is assigned on %s", p.Name)
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return &plan{ns: cat, resource: name, can: []string{"delete"}, rules: []any{resourceRule(name)}, cp: cp, key: key}, nil
}

// checkLag refuses to issue from a checkpoint older than the catalog's
// maxLag (or the key's), since the core would reject the grant's at
// anyway (§B.11.8, §C.4 requireAt).
func (s *Service) checkLag(ctx context.Context, cp string, key *grant.Key) error {
	cat := s.t.Catalog()
	if cp == "" {
		return errf(503, "behind", "the catalog service has not reached the catalog yet")
	}
	if key.RequireAt == nil {
		return nil // the core doesn't check at for this key
	}
	h, err := s.t.Client().NSHead(ctx, cat)
	if err != nil {
		return upstream(err)
	}
	if h.ID == cp {
		return nil
	}
	var nsLag *time.Duration
	if cfg, err := s.t.Checker().Config(ctx, cat); err == nil {
		nsLag = cfg.MaxLag
	}
	limit := grant.EffectiveMaxLag(nsLag, key.MaxLag) // default 60 s (§C.4)
	entries, err := s.t.Client().NSLog(ctx, cat, h.ID, cp)
	if err != nil || len(entries) == 0 {
		return errf(503, "behind", "the catalog service's checkpoint is not in the catalog's chain")
	}
	t, err := time.Parse(time.RFC3339Nano, entries[0].Created)
	if err == nil && s.now().Sub(t) > limit {
		return errf(503, "behind", "the catalog service lags the catalog by more than maxLag")
	}
	return nil
}

// mint signs a plan as a root grant for the caller (§B.11.4).
func (s *Service) mint(ctx context.Context, v *grant.Verified, p *plan, lagOK map[string]bool) (*Issued, error) {
	if !lagOK[p.cp] {
		if err := s.checkLag(ctx, p.cp, p.key); err != nil {
			return nil, err
		}
		lagOK[p.cp] = true
	}
	now := s.now()
	ttl := s.opt.TTL
	if p.key.MaxTTL != nil && *p.key.MaxTTL < ttl {
		ttl = *p.key.MaxTTL
	}
	exp := now.Add(ttl).UTC().Truncate(time.Second)
	// Never outlive the caller's own grant.
	for _, b := range v.Grant.Blocks {
		if b.Exp != nil && b.Exp.Before(exp) {
			exp = b.Exp.UTC()
		}
	}
	if !exp.After(now) {
		return nil, forbidden("the caller's grant expires too soon")
	}
	var groups []any
	for _, g := range v.Principal.Groups {
		if ok, _ := p.key.Groups.Permits([]string{g}); ok {
			groups = append(groups, g)
		}
	}
	at := map[string]any{"ns": s.t.Catalog(), "id": p.cp}
	root := map[string]any{
		"kid": s.opt.Kid, "sub": v.Principal.ID, "ns": []any{p.ns}, "can": toAny(p.can),
		"exp": exp.Format(time.RFC3339Nano), "at": at, "rules": p.rules,
	}
	if len(groups) > 0 {
		root["groups"] = groups
	}
	if len(p.roles) > 0 {
		root["roles"] = toAny(p.roles)
	}
	g, err := grant.Mint(root, s.opt.Key)
	if err != nil {
		return nil, err
	}
	return &Issued{Grant: g.Encode(), NS: p.ns, Resource: p.resource, Can: p.can, Roles: p.roles,
		Exp: exp.Format(time.RFC3339Nano), At: at}, nil
}

func toAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
