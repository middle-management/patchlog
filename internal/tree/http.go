package tree

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Cache-Control values (§9). Listings at a checkpoint are cached by the CDN
// for as long as it is current (a catalog write moves every listing to a
// new URL). A change in a content namespace (an item's head, or an item
// appearing or going away) changes listings without changing the catalog
// checkpoint, so browsers keep them only briefly and the CDN is purged by
// tag: node:{catalog}/{node} for every node a response depends on, and
// all:{catalog} for whole-catalog reports.
const (
	ccHeadPointer = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccListing     = "public, max-age=5, s-maxage=31536000"
	ccPrivatePtr  = "private, no-cache"
	ccPrivateList = "private, max-age=5"
	cdnListing    = "max-age=31536000"
)

// Limits of listings.
const (
	defaultLimit    = 100
	maxLimit        = 1000
	maxPaths        = 1000
	maxSubtreeNodes = 5000
	maxManifest     = 10000
	maxTags         = 200
)

// RoleView lets readers see nodes through roles (§B.11.5); the catalog
// implements it.
type RoleView interface {
	// Resolve is called once per request with the reader's grant, verified
	// for the catalog namespace. It returns the subjects that key the
	// reader's listings (§B.11.5) and the reader's visibility. Resolve runs
	// outside the graph lock; the Visibility's methods run under it.
	Resolve(ctx context.Context, v *grant.Verified) (subjects []string, vis Visibility, err error)
}

// Visibility decides, under the graph lock, what a reader may see.
type Visibility interface {
	// Node reports whether the reader may list the node.
	Node(g *Graph, n *Node) bool
	// Item reports whether the reader may see a placement's item (its
	// head and URL).
	Item(g *Graph, n *Node) bool
}

// viewer is the outcome of the read check for one request.
type viewer struct {
	anon       bool // no grant: the public URL space
	gs         string
	catAll     bool
	catRead    func(name string) bool
	contentAll map[string]bool
	vis        Visibility
}

func (v *viewer) node(g *Graph, n *Node) bool {
	return v.catAll || (v.catRead != nil && v.catRead(n.Name)) || (v.vis != nil && v.vis.Node(g, n))
}

func (v *viewer) item(g *Graph, n *Node) bool {
	if n.ItemNS == "" || n.State != StateLive {
		return false
	}
	return v.contentAll[n.ItemNS] || (v.vis != nil && v.vis.Item(g, n))
}

// Bearer returns the request's bearer token.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// viewer resolves the reader (§B.10: services that list content enforce
// read permissions for every node and item they list):
//
//   - catalog structure: everyone if the catalog is public, otherwise a
//     grant for the catalog namespace that reads the whole namespace, or
//     (filtered per node) one whose rules restrict /resource;
//   - items' heads: public content namespaces, or content namespaces the
//     same grant reads as a whole;
//   - with a RoleView (the catalog), additionally what the reader's roles
//     reach (§B.11.5).
//
// Anonymous readers of a public catalog use the public URL space; a reader
// with a grant is routed under /g/{gs}/, where gs keys everything its
// listings depend on: its subjects (from the RoleView, or its groups) and
// markers for how much of the catalog and which content namespaces it
// reads as a whole.
func (s *Service) viewer(ctx context.Context, r *http.Request) (*viewer, error) {
	cat := s.opt.Catalog
	cfg, err := s.checker.Config(ctx, cat)
	if err != nil {
		return nil, err
	}
	catPublic := cfg.Read == "public"
	var trust []string
	s.View(func(g *Graph, _ map[string]string) {
		for ns := range g.Trust {
			trust = append(trust, ns)
		}
	})
	sort.Strings(trust)
	token := Bearer(r)
	v := &viewer{contentAll: map[string]bool{}}
	if token == "" {
		if !catPublic {
			return nil, &grant.AuthError{Status: 401, Msg: "missing grant"}
		}
		v.anon, v.catAll = true, true
		for _, ns := range trust {
			if c, err := s.checker.Config(ctx, ns); err == nil && c.Read == "public" {
				v.contentAll[ns] = true
			}
		}
		return v, nil
	}
	vg, err := s.checker.Verify(ctx, cat, token)
	if err != nil {
		return nil, err
	}
	var markers []string
	readsCat, _ := vg.Allows("read")
	switch {
	case catPublic:
		v.catAll = true
	case readsCat && s.checker.ReadsAll(vg) && s.checker.AllowsRead(vg, ""):
		v.catAll = true
		markers = append(markers, "catalog:all")
	case readsCat:
		v.catRead = func(name string) bool { return s.checker.AllowsRead(vg, name) }
		markers = append(markers, "catalog:scope:"+ScopeDigest(vg))
	}
	for _, ns := range trust {
		c, err := s.checker.Config(ctx, ns)
		if err != nil {
			continue
		}
		if c.Read == "public" {
			v.contentAll[ns] = true
			continue
		}
		cv, err := s.checker.Verify(ctx, ns, token)
		if err != nil {
			continue
		}
		if ok, _ := cv.Allows("read"); ok && s.checker.ReadsAll(cv) && s.checker.AllowsRead(cv, "") {
			v.contentAll[ns] = true
			markers = append(markers, "reads:"+ns)
		}
	}
	var subjects []string
	if s.opt.RoleView != nil {
		subjects, v.vis, err = s.opt.RoleView.Resolve(ctx, vg)
		if err != nil {
			return nil, err
		}
	} else {
		if !v.catAll && v.catRead == nil {
			return nil, &grant.AuthError{Status: 403, Msg: "the grant does not allow reading the catalog"}
		}
		subjects = grantcheck.SubjectSet(vg, false)
	}
	v.gs = grantcheck.SubjectSetID(append(subjects, markers...))
	return v, nil
}

// ScopeDigest digests everything a resource-restricted read decision of a
// grant depends on, so readers share listings only with identical scopes.
func ScopeDigest(v *grant.Verified) string {
	roles := map[string]any{}
	for _, role := range v.EffectiveRoles {
		roles[role] = v.RoleRules(role)
	}
	x := map[string]any{
		"principal": v.Principal.Envelope(), "key": v.Key.Kid, "readScope": v.Key.ReadScopeResource,
		"keyRules": v.KeyRules, "blockRules": v.BlockRules, "roles": roles,
	}
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(x)))
	return ids.FromBytes(sum[:ids.Size]).String()
}

var ops = map[string]bool{
	"children": true, "ancestors": true, "subtree": true, "roots": true,
	"orphans": true, "problems": true, "where": true, "manifest": true,
}

// Handler returns the query API (§B.5):
//
//	GET /{catalog}/{op}?…                      302 → /{catalog}/at/{checkpoint}[/g/{gs}]/{op}?…  (head pointer)
//	GET /{catalog}/at/{ns_id}/{op}?…            200, public readers                            (cached while current)
//	GET /{catalog}/at/{ns_id}/g/{gs}/{op}?…     200, readers with a grant, keyed by subject set (§B.11.5)
//
// op is one of children?of=&after=&limit=, ancestors?of=, subtree?of=&depth=,
// roots, orphans, problems, where?item=, manifest?of=. An at URL that isn't
// the current checkpoint redirects to it; ?min={ns_id} (of the catalog or
// of a trusted namespace) waits until the service has applied it.
func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		WriteError(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
		return
	}
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	cat := s.opt.Catalog
	var at, gs, op string
	isAt := false
	switch {
	case len(segs) == 2 && segs[0] == cat:
		op = segs[1]
	case len(segs) == 4 && segs[0] == cat && segs[1] == "at":
		at, op, isAt = segs[2], segs[3], true
	case len(segs) == 6 && segs[0] == cat && segs[1] == "at" && segs[3] == "g":
		at, gs, op, isAt = segs[2], segs[4], segs[5], true
	default:
		WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !ops[op] {
		WriteError(w, http.StatusNotFound, "not_found", "unknown listing")
		return
	}
	if isAt {
		if _, err := ids.Parse(at); err != nil {
			WriteError(w, http.StatusBadRequest, "bad_input", "malformed ns_id")
			return
		}
	}
	if gs != "" {
		if _, err := ids.Parse(gs); err != nil {
			WriteError(w, http.StatusNotFound, "not_found", "malformed subject set")
			return
		}
	}
	s.serve(w, r, op, at, gs, isAt)
}

// WriteAuthError writes a grant failure (401/403) or an upstream error.
func WriteAuthError(w http.ResponseWriter, err error, logf func(string, ...any)) {
	var ae *grant.AuthError
	if errors.As(err, &ae) {
		code := "forbidden"
		if ae.Status == 401 {
			code = "unauthenticated"
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		w.Header().Set("Cache-Control", "no-store")
		WriteError(w, ae.Status, code, ae.Msg)
		return
	}
	logf("tree: access check: %v", err)
	WriteError(w, http.StatusBadGateway, "upstream", "cannot read a namespace configuration")
}

func (s *Service) serve(w http.ResponseWriter, r *http.Request, op, at, gs string, isAt bool) {
	ctx := r.Context()
	cat := s.opt.Catalog
	if _, purged, _ := s.state(); purged {
		WriteError(w, http.StatusGone, "gone", "catalog purged")
		return
	}
	v, err := s.viewer(ctx, r)
	if err != nil {
		WriteAuthError(w, err, s.opt.Logf)
		return
	}
	vals := r.URL.Query()
	base := "/" + cat + "/at/"
	target := func(cp string) string {
		if v.anon {
			return base + cp + "/" + op
		}
		return base + cp + "/g/" + v.gs + "/" + op
	}
	setPtr := func() {
		if v.anon {
			w.Header().Set("Cache-Control", ccHeadPointer)
			w.Header().Set("Cache-Tag", "ns:"+cat)
		} else {
			w.Header().Set("Cache-Control", ccPrivatePtr)
			w.Header().Set("CDN-Cache-Control", "no-store")
			w.Header().Set("Vary", "Authorization")
		}
	}
	if min := vals.Get("min"); min != "" && !s.waitMin(ctx, min) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		WriteError(w, http.StatusServiceUnavailable, "behind", "the tree service has not reached min yet")
		return
	}
	cur, _, _ := s.state()
	if cur == "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		WriteError(w, http.StatusServiceUnavailable, "behind", "the tree service has not reached the catalog yet")
		return
	}
	if !isAt || at != cur || gs != v.gs || (v.anon && gs != "") {
		setPtr()
		redirect(w, target(cur)+encodeQuery(vals, "min"))
		return
	}

	var (
		status = http.StatusOK
		body   any
		tags   tagSet
		errMsg string
		got    string
	)
	s.View(func(g *Graph, curMap map[string]string) {
		got = curMap[cat]
		if got != at {
			return
		}
		q := &query{s: s, g: g, v: v, vals: vals, tags: tagSet{}, at: at}
		body, status, errMsg = q.run(op)
		tags = q.tags
	})
	if got != at {
		setPtr()
		redirect(w, target(got)+encodeQuery(vals, "min"))
		return
	}
	if status != http.StatusOK {
		WriteError(w, status, codeFor(status), errMsg)
		return
	}
	if v.anon {
		w.Header().Set("Cache-Control", ccListing)
	} else {
		w.Header().Set("Cache-Control", ccPrivateList)
		w.Header().Set("CDN-Cache-Control", cdnListing)
	}
	w.Header().Set("Cache-Tag", tags.header(cat))
	w.Header().Set("X-Namespace-Revision", at)
	WriteJSON(w, http.StatusOK, body)
}

func codeFor(status int) string {
	switch status {
	case http.StatusNotFound:
		return "not_found"
	case http.StatusBadRequest:
		return "bad_input"
	case http.StatusUnprocessableEntity:
		return "too_large"
	}
	return "error"
}

type tagSet map[string]bool

func (t tagSet) node(cat, name string) { t["node:"+cat+"/"+name] = true }

func (t tagSet) header(cat string) string {
	out := []string{"ns:" + cat}
	if len(t) > maxTags {
		return strings.Join(append(out, "all:"+cat), ",")
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(append(out, keys...), ",")
}

// waitMin waits up to MinWait until min is the catalog checkpoint or an
// ns_id the service has applied (§A.5).
func (s *Service) waitMin(ctx context.Context, min string) bool {
	timer := time.NewTimer(s.opt.MinWait)
	defer timer.Stop()
	for {
		cur, _, changed := s.state()
		if cur == min || s.Seen(ctx, min) {
			return true
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		}
	}
}

// encodeQuery encodes the query canonically (sorted keys) without drop.
func encodeQuery(v url.Values, drop ...string) string {
	c := url.Values{}
	for k, vals := range v {
		c[k] = vals
	}
	for _, d := range drop {
		delete(c, d)
	}
	if s := c.Encode(); s != "" {
		return "?" + s
	}
	return ""
}

func redirect(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

// WriteError writes an error body.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	if w.Header().Get("Cache-Control") == "" {
		if status == http.StatusNotFound {
			w.Header().Set("Cache-Control", "public, max-age=5")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
	}
	WriteJSON(w, status, map[string]any{"code": code, "message": msg})
}

// WriteJSON writes v as JSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// --- queries -------------------------------------------------------------------

type query struct {
	s    *Service
	g    *Graph
	v    *viewer
	vals url.Values
	tags tagSet
	at   string
}

func (q *query) run(op string) (any, int, string) {
	switch op {
	case "children":
		return q.children()
	case "ancestors":
		return q.ancestors()
	case "subtree":
		return q.subtree()
	case "roots":
		return q.roots()
	case "orphans":
		return q.orphans()
	case "problems":
		return q.problems()
	case "where":
		return q.where()
	case "manifest":
		return q.manifest()
	}
	return nil, http.StatusNotFound, "unknown listing"
}

// Resolve maps a node reference to a node name: /r/{catalog}/{name}, an
// item /r/{ns}/{name} (its placement {ns}.{name}), or a bare node name.
func Resolve(catalog, ref string) (string, bool) {
	if ns, name, ok := ParseHref(ref); ok {
		if ns == catalog {
			return name, true
		}
		return ns + "." + name, true
	}
	if client.ValidResourceName(ref) {
		return ref, true
	}
	return "", false
}

// node resolves the of parameter to a node the viewer may see.
func (q *query) node(param string) (*Node, int, string) {
	ref := q.vals.Get(param)
	if ref == "" {
		return nil, http.StatusBadRequest, param + " is required"
	}
	name, ok := Resolve(q.g.Catalog, ref)
	if !ok {
		return nil, http.StatusBadRequest, "malformed " + param
	}
	q.tags.node(q.g.Catalog, name)
	n := q.g.Node(name)
	if n == nil || !q.v.node(q.g, n) {
		return nil, http.StatusNotFound, "no such node"
	}
	return n, http.StatusOK, ""
}

func (q *query) entry(n *Node) map[string]any {
	m := map[string]any{"href": q.g.Href(n.Name), "name": n.Name, "kind": "folder"}
	if n.Title != "" {
		m["title"] = n.Title
	}
	if n.Kind == KindPlacement {
		m["kind"] = "item"
		if it := n.Item(); it != "" {
			m["item"] = it
		}
		if n.Self {
			m["self"] = true
		}
		if q.v.item(q.g, n) && n.ItemHead != "" {
			m["head"] = n.ItemHead
			m["url"] = q.s.origin + n.Item() + "/rev/" + n.ItemHead
		}
		if n.State == StateDangling {
			m["dangling"] = n.Dangling
		}
	}
	return m
}

func (q *query) visibleChildren(parent string) []Child {
	var out []Child
	for _, c := range q.g.Children(parent) {
		q.tags.node(q.g.Catalog, c.Node.Name)
		if c.Node.Live() && q.v.node(q.g, c.Node) {
			out = append(out, c)
		}
	}
	return out
}

func limitParam(vals url.Values) (int, bool) {
	l := defaultLimit
	if s := vals.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return 0, false
		}
		l = min(n, maxLimit)
	}
	return l, true
}

// children lists a folder's direct children, ordered (§B.2), paginated
// with ?after={order}; next links add &name= (and &unordered=1 past the
// ordered siblings) to break ties exactly.
func (q *query) children() (any, int, string) {
	n, st, msg := q.node("of")
	if n == nil {
		return nil, st, msg
	}
	if n.Kind != KindFolder {
		return nil, http.StatusBadRequest, "of must be a folder"
	}
	limit, ok := limitParam(q.vals)
	if !ok {
		return nil, http.StatusBadRequest, "malformed limit"
	}
	kids := q.visibleChildren(n.Name)
	after, hasAfter := q.vals["after"]
	cur := Child{Node: &Node{Name: q.vals.Get("name")}}
	hasName := q.vals.Has("name")
	if hasAfter {
		cur.Order, cur.HasOrder = after[0], true
	}
	if q.vals.Get("unordered") == "1" {
		cur.HasOrder, hasAfter = false, true
	}
	var page []any
	var last *Child
	more := false
	for i := range kids {
		c := kids[i]
		if hasAfter || hasName {
			if !cursorBefore(cur, hasName, c) {
				continue
			}
		}
		if len(page) == limit {
			more = true
			break
		}
		e := q.entry(c.Node)
		if c.HasOrder {
			e["order"] = c.Order
		}
		page = append(page, e)
		last = &kids[i]
	}
	body := map[string]any{"at": q.at, "of": q.g.Href(n.Name), "children": nonNil(page)}
	if more && last != nil {
		nv := url.Values{}
		for k, v := range q.vals {
			nv[k] = v
		}
		nv.Del("after")
		nv.Del("unordered")
		nv.Del("min")
		if last.HasOrder {
			nv.Set("after", last.Order)
		} else {
			nv.Set("unordered", "1")
		}
		nv.Set("name", last.Node.Name)
		body["next"] = "?" + nv.Encode()
	}
	return body, http.StatusOK, ""
}

// cursorBefore reports whether the cursor sorts before c.
func cursorBefore(cur Child, hasName bool, c Child) bool {
	if cur.HasOrder != c.HasOrder {
		return cur.HasOrder // ordered siblings come first
	}
	if cur.HasOrder && cur.Order != c.Order {
		return lessUTF16(cur.Order, c.Order)
	}
	if !hasName {
		return false
	}
	return cur.Node.Name < c.Node.Name
}

func nonNil(a []any) []any {
	if a == nil {
		return []any{}
	}
	return a
}

// paths returns every walkable path from n up to a root, root first,
// without n itself, bounded at MaxDepth and maxPaths. incomplete counts
// paths that end below a root (at a node whose parents are all gone,
// dangling or cyclic), deep those cut at MaxDepth.
func (q *query) paths(n *Node) (paths [][]*Node, incomplete, deep int, truncated bool) {
	var stack []*Node
	var walk func(x *Node, depth int)
	walk = func(x *Node, depth int) {
		if len(paths) >= maxPaths {
			truncated = true
			return
		}
		if len(x.Parents) == 0 && !x.Cyclic {
			p := make([]*Node, len(stack))
			for i := range stack {
				p[i] = stack[len(stack)-1-i]
			}
			paths = append(paths, p)
			return
		}
		ps := q.g.WalkableParents(x)
		if len(ps) == 0 {
			incomplete++
			return
		}
		if depth >= MaxDepth {
			deep++
			return
		}
		for _, pn := range ps {
			parent := q.g.Node(pn)
			onPath := false
			for _, s := range stack {
				if s == parent {
					onPath = true
				}
			}
			if onPath {
				continue
			}
			stack = append(stack, parent)
			walk(parent, depth+1)
			stack = stack[:len(stack)-1]
		}
	}
	walk(n, 0)
	return
}

func (q *query) pathJSON(ps [][]*Node) (out []any, hidden int) {
	out = []any{}
	for _, p := range ps {
		ok := true
		arr := make([]any, 0, len(p))
		for _, x := range p {
			q.tags.node(q.g.Catalog, x.Name)
			if !q.v.node(q.g, x) {
				ok = false
				break
			}
			e := map[string]any{"href": q.g.Href(x.Name), "name": x.Name}
			if x.Title != "" {
				e["title"] = x.Title
			}
			arr = append(arr, e)
		}
		if !ok {
			hidden++
			continue
		}
		out = append(out, arr)
	}
	return out, hidden
}

// ancestors lists every path from the node to a root, root first, for
// breadcrumbs. Paths through nodes the reader may not see are left out.
func (q *query) ancestors() (any, int, string) {
	n, st, msg := q.node("of")
	if n == nil {
		return nil, st, msg
	}
	ps, incomplete, deep, trunc := q.paths(n)
	js, hidden := q.pathJSON(ps)
	body := map[string]any{"at": q.at, "of": q.g.Href(n.Name), "node": q.entry(n), "paths": js}
	if incomplete > 0 {
		body["incomplete"] = incomplete
	}
	if deep > 0 {
		body["tooDeep"] = deep
	}
	if hidden > 0 {
		body["hidden"] = hidden
	}
	if trunc {
		body["truncated"] = true
	}
	return body, http.StatusOK, ""
}

// subtree lists a folder's descendants as a nested listing, depth levels
// deep (default 3, at most 64).
func (q *query) subtree() (any, int, string) {
	n, st, msg := q.node("of")
	if n == nil {
		return nil, st, msg
	}
	depth := 3
	if s := q.vals.Get("depth"); s != "" {
		d, err := strconv.Atoi(s)
		if err != nil || d < 0 {
			return nil, http.StatusBadRequest, "malformed depth"
		}
		depth = min(d, MaxDepth)
	}
	count := 0
	truncated := false
	var build func(x *Node, d int, onPath map[string]bool) map[string]any
	build = func(x *Node, d int, onPath map[string]bool) map[string]any {
		e := q.entry(x)
		if x.Kind != KindFolder {
			return e
		}
		if d >= depth {
			if len(q.visibleChildren(x.Name)) > 0 {
				e["more"] = true
			}
			return e
		}
		kids := []any{}
		onPath[x.Name] = true
		for _, c := range q.visibleChildren(x.Name) {
			if onPath[c.Node.Name] {
				continue
			}
			if count >= maxSubtreeNodes {
				truncated = true
				break
			}
			count++
			ce := build(c.Node, d+1, onPath)
			if c.HasOrder {
				ce["order"] = c.Order
			}
			kids = append(kids, ce)
		}
		delete(onPath, x.Name)
		e["children"] = kids
		return e
	}
	body := map[string]any{"at": q.at, "of": q.g.Href(n.Name), "depth": depth, "tree": build(n, 0, map[string]bool{})}
	if truncated {
		body["truncated"] = true
	}
	return body, http.StatusOK, ""
}

// roots lists nodes without parents.
func (q *query) roots() (any, int, string) {
	q.tags["all:"+q.g.Catalog] = true
	out := []any{}
	for _, name := range q.g.Names() {
		n := q.g.Node(name)
		if len(n.Parents) == 0 && n.Live() && q.v.node(q.g, n) {
			out = append(out, q.entry(n))
		}
	}
	return map[string]any{"at": q.at, "roots": out}, http.StatusOK, ""
}

func (q *query) parentsJSON(n *Node) []any {
	out := []any{}
	for i, p := range n.Parents {
		e := map[string]any{"state": EdgeStateName(n.EdgeStates[i])}
		if p.Href != "" {
			e["href"] = p.Href
		}
		if p.Invalid != "" {
			e["reason"] = p.Invalid
		}
		out = append(out, e)
	}
	return out
}

// orphans lists nodes whose every parent is gone, dangling, not a folder
// or in a cycle (§B.5, §B.7: children of a deleted folder).
func (q *query) orphans() (any, int, string) {
	q.tags["all:"+q.g.Catalog] = true
	out := []any{}
	for _, name := range q.g.Names() {
		n := q.g.Node(name)
		if len(n.Parents) == 0 || len(q.g.WalkableParents(n)) > 0 || !q.v.node(q.g, n) {
			continue
		}
		e := q.entry(n)
		e["parents"] = q.parentsJSON(n)
		out = append(out, e)
	}
	return map[string]any{"at": q.at, "orphans": out}, http.StatusOK, ""
}

// problems reports cycles, dangling items, dangling parents and nodes
// deeper than MaxDepth (§B.3, §B.5).
func (q *query) problems() (any, int, string) {
	g := q.g
	q.tags["all:"+g.Catalog] = true
	cycles := []any{}
	for _, scc := range g.Cycles() {
		arr := []any{}
		for _, name := range scc {
			if n := g.Node(name); n != nil && q.v.node(g, n) {
				arr = append(arr, g.Href(name))
			}
		}
		if len(arr) > 0 {
			cycles = append(cycles, arr)
		}
	}
	items, parents, deep := []any{}, []any{}, []any{}
	for _, name := range g.Names() {
		n := g.Node(name)
		if !q.v.node(g, n) {
			continue
		}
		if n.State == StateDangling {
			e := map[string]any{"href": g.Href(name), "reason": n.Dangling}
			if it := n.Item(); it != "" {
				e["item"] = it
			}
			items = append(items, e)
		}
		for i, p := range n.Parents {
			st := n.EdgeStates[i]
			if st == EdgeValid || st == EdgeCycle {
				continue
			}
			e := map[string]any{"href": g.Href(name), "state": EdgeStateName(st)}
			if p.Href != "" {
				e["parent"] = p.Href
			}
			if p.Invalid != "" {
				e["reason"] = p.Invalid
			}
			parents = append(parents, e)
		}
		if n.Deep {
			deep = append(deep, map[string]any{"href": g.Href(name), "depth": n.Depth})
		}
	}
	return map[string]any{"at": q.at, "cycles": cycles, "danglingItems": items, "danglingParents": parents, "tooDeep": deep}, http.StatusOK, ""
}

// where answers "is this item in the catalog, and where?" with its
// placement and every path to a root.
func (q *query) where() (any, int, string) {
	ref := q.vals.Get("item")
	ns, name, ok := ParseHref(ref)
	if !ok || ns == q.g.Catalog {
		return nil, http.StatusBadRequest, "item must be /r/{ns}/{name} of a content namespace"
	}
	pl := ns + "." + name
	q.tags.node(q.g.Catalog, pl)
	body := map[string]any{"at": q.at, "item": ref, "placement": nil}
	n := q.g.Node(pl)
	if n == nil || !q.v.node(q.g, n) {
		return body, http.StatusOK, ""
	}
	body["placement"] = q.entry(n)
	ps, incomplete, deep, trunc := q.paths(n)
	js, hidden := q.pathJSON(ps)
	body["paths"] = js
	if incomplete > 0 {
		body["incomplete"] = incomplete
	}
	if deep > 0 {
		body["tooDeep"] = deep
	}
	if hidden > 0 {
		body["hidden"] = hidden
	}
	if trunc {
		body["truncated"] = true
	}
	return body, http.StatusOK, ""
}

// manifest generates a manifest (§B.4) for a folder's subtree as of the
// checkpoint: the folder's pinned revision and one pinned entry per item
// and path. The client creates it as an ordinary resource.
func (q *query) manifest() (any, int, string) {
	n, st, msg := q.node("of")
	if n == nil {
		return nil, st, msg
	}
	if n.Kind != KindFolder || n.Head == "" {
		return nil, http.StatusBadRequest, "of must be a folder"
	}
	entries := []any{}
	tooLarge := false
	var walk func(x *Node, path []string, depth int)
	walk = func(x *Node, path []string, depth int) {
		if depth > MaxDepth || tooLarge {
			return
		}
		for _, c := range q.visibleChildren(x.Name) {
			if c.Node.Kind == KindFolder {
				if slicesContains(path, c.Node.Name) {
					continue
				}
				walk(c.Node, append(append([]string(nil), path...), c.Node.Name), depth+1)
				continue
			}
			if !q.v.item(q.g, c.Node) || c.Node.ItemHead == "" {
				continue
			}
			if len(entries) >= maxManifest {
				tooLarge = true
				return
			}
			p := make([]any, len(path))
			for i, s := range path {
				p[i] = s
			}
			e := map[string]any{"href": c.Node.Item() + "/rev/" + c.Node.ItemHead, "path": p}
			if c.HasOrder {
				e["order"] = c.Order
			}
			entries = append(entries, e)
		}
	}
	walk(n, []string{n.Name}, 0)
	if tooLarge {
		return nil, http.StatusUnprocessableEntity, "the subtree has too many items for one manifest"
	}
	return map[string]any{
		"catalog": q.g.Catalog,
		"root":    q.g.Href(n.Name) + "/rev/" + n.Head,
		"entries": entries,
	}, http.StatusOK, ""
}

func slicesContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
