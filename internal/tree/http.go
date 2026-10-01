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
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
)

// Cache-Control values (§9). A listing's at is the service's combined
// checkpoint over the catalog and every content namespace it follows
// (§B.5), so any change a listing depends on (a catalog write, an item's
// head, an item appearing or going away) moves listings to a new URL, and a
// listing at a given at never changes: the immutable class. Listings are
// tagged r:{ns}/{name} for every resource they show (catalog nodes and
// their items) and ns:{ns} for every namespace in the checkpoint, and the
// service purges those tags on purge and purge-ns entries (Apply), so a
// purge removes cached listings at every at. A listing showing more than
// maxTags resources carries rs:{catalog} instead of its r: tags, which
// every purge of a resource purges too.
const (
	ccHeadPointer = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccListing     = "public, max-age=86400, s-maxage=31536000, immutable"
	ccPrivatePtr  = "private, no-cache"
	ccPrivateList = "private, max-age=300"
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
//	GET /{catalog}/{op}?…                   302 → /{catalog}/at/{at}[/g/{gs}]/{op}?…  (head pointer)
//	GET /{catalog}/at/{at}/{op}?…            200, public readers                     (immutable)
//	GET /{catalog}/at/{at}/g/{gs}/{op}?…     200, readers with a grant, keyed by subject set (§B.11.5)
//
// at is the combined checkpoint (CombinedAt). op is one of
// children?of=&after=&limit=, ancestors?of=, subtree?of=&depth=, roots,
// orphans, problems, where?item=, manifest?of=.
//
// The service keeps no results: it answers 200 only at the current at,
// and redirects every other at to the current one (§B.5 "only if it is
// current or that exact result was stored").
//
// ?min= waits until the service has applied an ns_id (§A.5): {ns}:{ns_id}
// for the catalog or a followed content namespace, repeatable, or a bare
// {ns_id} of any of them.
//
// A sealed or e2e catalog (§E.2.5, §E.2.6; package derived). Titles are
// the only values a listing takes from documents' content (names, heads,
// hrefs, structure, order and cursors stay in the clear, and content
// namespaces contribute nothing else), so a listing has one sealed source,
// the catalog. A reader of the whole catalog gets the listing sealed as
// one JWE under the catalog's current epoch key, Content-Type
// application/jose, pl { ns, view } where view is the listing's request
// target (/{catalog}/at/{at}[/g/{gs}]/{op}?{query}; an at URL whose query
// isn't in the canonical form the redirects give is redirected to it). A
// reader whose grant restricts catalog resources (or who sees nodes only
// through roles) gets JSON in which every node with a title carries
// "sealed": JWE of { title } under that catalog resource's K_r, pl { ns,
// name, view }, instead of "title". Sealed listings are produced once per
// view (a rotation moves at), stored in the database with their cache
// tags, and served unchanged, across restarts, until a purge with one of
// those tags or a new at retires them (derived.Cache).
//
//	GET /_status    each followed namespace's encryption level and epoch,
//	                whether listings are sealed, and why a namespace is
//	                skipped (or its documents not read); "catalogs" names
//	                the catalog served (several behind Multi)
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
	case len(segs) == 1 && segs[0] == "_status":
		s.serveStatus(w)
		return
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
	if reason := s.keys.Skipped(cat); reason != "" {
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, "skipped", "the service does not consume the catalog: "+reason)
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
	// Behind a verifying edge, private reads must come through it (§9).
	if !s.opt.Edge.Allow(r, v.anon) {
		w.Header().Set("Cache-Control", "no-store")
		WriteError(w, http.StatusForbidden, edge.Code, edge.Message)
		return
	}
	setPtr := func() {
		if v.anon {
			w.Header().Set("Cache-Control", ccHeadPointer)
			w.Header().Set("Cache-Tag", "ns:"+cat)
		} else {
			// A pointer depends on the caller's grant: no shared cache
			// keeps it, behind a verifying edge or not.
			w.Header().Set("Cache-Control", ccPrivatePtr)
			w.Header().Set("CDN-Cache-Control", "no-store")
			w.Header().Set("Surrogate-Control", "no-store")
			w.Header().Add("Vary", "Authorization")
		}
	}
	mins, err := parseMins(vals["min"])
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		WriteError(w, http.StatusBadRequest, "bad_input", err.Error())
		return
	}
	followed := map[string]bool{}
	for _, ns := range s.followed() {
		followed[ns] = true
	}
	for _, m := range mins {
		if m.ns != "" && !followed[m.ns] {
			w.Header().Set("Cache-Control", "no-store")
			WriteError(w, http.StatusBadRequest, "bad_input", "min names a namespace the service does not follow")
			return
		}
	}
	if !s.waitMins(ctx, mins) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		WriteError(w, http.StatusServiceUnavailable, "behind", "the tree service has not reached min yet")
		return
	}
	if c, _, _ := s.state(); c == "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		WriteError(w, http.StatusServiceUnavailable, "behind", "the tree service has not reached the catalog yet")
		return
	}
	var cur string
	s.View(func(g *Graph, curMap map[string]string) { cur, _ = CombinedAt(g, curMap) })
	if !isAt || at != cur || gs != v.gs || (v.anon && gs != "") {
		setPtr()
		redirect(w, target(cur)+encodeQuery(vals, "min"))
		return
	}

	info, key, err := s.keys.Current(ctx, cat)
	if err != nil {
		s.opt.Logf("tree: keys of %s: %v", cat, err)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		WriteError(w, http.StatusServiceUnavailable, "keys", "the service cannot obtain the key that seals listings of the catalog")
		return
	}
	var view derived.View
	perEntry := false
	if info.Protected() {
		// view binds the listing to its URL (§E.2.6): only the canonical
		// form is served.
		view = derived.View{NS: cat, Target: target(at) + encodeQuery(vals, "min")}
		if r.URL.RequestURI() != view.Target {
			setPtr()
			redirect(w, view.Target)
			return
		}
		perEntry = !v.catAll
		if st, ok := s.sealed.Get(ctx, view.Target); ok {
			s.writeListing(w, v, at, st)
			return
		}
	}

	var (
		status = http.StatusOK
		body   any
		tags   tagSet
		errMsg string
		got    string
		nss    []string
		serr   error
	)
	s.View(func(g *Graph, curMap map[string]string) {
		got, nss = CombinedAt(g, curMap)
		if got != at {
			return
		}
		q := &query{s: s, g: g, v: v, vals: vals, tags: tagSet{}, at: at}
		if perEntry {
			q.sealTitle = func(name, title string) string {
				jwe, err := derived.SealItem(key, view, name, map[string]any{"title": title})
				if err != nil && serr == nil {
					serr = err
				}
				return jwe
			}
		}
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
	if info.Protected() {
		var b []byte
		if serr == nil {
			if perEntry {
				b, serr = derived.Marshal(body)
			} else {
				var jwe string
				jwe, serr = derived.SealView(key, view, body)
				b = []byte(jwe)
			}
		}
		if serr != nil {
			s.opt.Logf("tree: sealing a listing: %v", serr)
			WriteError(w, http.StatusInternalServerError, "internal", "sealing failed")
			return
		}
		st, err := s.sealed.Put(ctx, view.Target, cat, at, derived.Stored{Body: b, JSON: perEntry, Tags: tags.header(cat, nss)})
		if err != nil {
			s.opt.Logf("tree: storing a sealed listing: %v", err)
		}
		if cur := s.At(); cur != at {
			// An apply (maybe a purge) committed meanwhile: don't keep a
			// listing it may have retired.
			if err := s.sealed.Retire(ctx, s.db, cat, cur); err != nil {
				s.opt.Logf("tree: retiring sealed listings: %v", err)
			}
		}
		s.writeListing(w, v, at, st)
		return
	}
	s.setListingHeaders(w, v, at, tags.header(cat, nss))
	WriteJSON(w, http.StatusOK, body)
}

func (s *Service) setListingHeaders(w http.ResponseWriter, v *viewer, at, tags string) {
	if v.anon {
		w.Header().Set("Cache-Control", ccListing)
	} else {
		w.Header().Set("Cache-Control", ccPrivateList)
		s.opt.Edge.Private(w.Header(), cdnListing)
	}
	w.Header().Set("Cache-Tag", tags)
	w.Header().Set("X-Namespace-Revision", at)
}

// writeListing writes a stored sealed listing: the JWE (application/jose),
// or the JSON with per-node sealed titles, with the Cache-Tag it was
// stored with.
func (s *Service) writeListing(w http.ResponseWriter, v *viewer, at string, st derived.Stored) {
	s.setListingHeaders(w, v, at, st.Tags)
	if st.JSON {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", seal.ContentType)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(st.Body)
}

// serveStatus answers GET /_status (Addendum E).
func (s *Service) serveStatus(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusOK, map[string]any{"namespaces": s.status(), "catalogs": []string{s.opt.Catalog}})
}

// status is each followed namespace's encryption state (Addendum E).
func (s *Service) status() []derived.Status { return s.keys.Status(s.followed()) }

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

// CombinedAt is the service's combined checkpoint (§B.5):
// text(trunc160(sha256(canonical({ ns: ns_id, … })))) over the catalog and
// every content namespace it follows (catalog.trust) that the service has
// reached, with the namespaces it covers, sorted. Call it under the graph
// lock (View).
func CombinedAt(g *Graph, cur map[string]string) (string, []string) {
	m := map[string]any{}
	nss := []string{}
	add := func(ns string) {
		if id := cur[ns]; id != "" {
			m[ns] = id
			nss = append(nss, ns)
		}
	}
	add(g.Catalog)
	for ns := range g.Trust {
		if ns != g.Catalog {
			add(ns)
		}
	}
	sort.Strings(nss)
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo(m)))
	return ids.FromBytes(sum[:ids.Size]).String(), nss
}

// At returns the current combined checkpoint (§B.5): the at of listings.
func (s *Service) At() string {
	var at string
	s.View(func(g *Graph, cur map[string]string) { at, _ = CombinedAt(g, cur) })
	return at
}

// tagSet collects the r:{ns}/{name} tags of the resources a listing shows.
type tagSet map[string]bool

// node tags a catalog node and, for a placement, its item.
func (t tagSet) node(g *Graph, name string) {
	t["r:"+g.Catalog+"/"+name] = true
	if n := g.Node(name); n != nil && n.ItemNS != "" {
		t["r:"+n.ItemNS+"/"+n.ItemName] = true
	}
}

// header is ns:{ns} for every namespace in the checkpoint, then the r:
// tags, or rs:{catalog} in their place if there are too many.
func (t tagSet) header(cat string, nss []string) string {
	out := make([]string, 0, len(nss)+len(t))
	for _, ns := range nss {
		out = append(out, "ns:"+ns)
	}
	if len(t) > maxTags {
		return strings.Join(append(out, ManyTag(cat)), ",")
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(append(out, keys...), ",")
}

// ManyTag tags listings that show more resources than they name; every
// purge of a resource purges it.
func ManyTag(cat string) string { return "rs:" + cat }

// minRef is one ?min= value: {ns}:{ns_id}, or a bare {ns_id} (ns "").
type minRef struct{ ns, id string }

func parseMins(vals []string) ([]minRef, error) {
	var out []minRef
	for _, v := range vals {
		var m minRef
		if i := strings.LastIndexByte(v, ':'); i >= 0 {
			m.ns, v = v[:i], v[i+1:]
			if !client.ValidNSName(m.ns) {
				return nil, errors.New("min: malformed namespace name")
			}
		}
		if _, err := ids.Parse(v); err != nil {
			return nil, errors.New("min must be {ns}:{ns_id} or an ns_id")
		}
		m.id = v
		out = append(out, m)
	}
	return out, nil
}

// waitMins waits up to MinWait until every min is reached: the namespace's
// checkpoint or an ns_id the service has applied in it (§A.5); a bare
// ns_id may be of any followed namespace.
func (s *Service) waitMins(ctx context.Context, mins []minRef) bool {
	if len(mins) == 0 {
		return true
	}
	timer := time.NewTimer(s.opt.MinWait)
	defer timer.Stop()
	for {
		s.mu.RLock()
		cur, changed := s.cur, s.changed
		ok := true
		for _, m := range mins {
			if m.ns != "" && cur[m.ns] == m.id {
				continue
			}
			if m.ns == "" && cur[s.opt.Catalog] == m.id {
				continue
			}
			ok = false
		}
		s.mu.RUnlock()
		if !ok {
			ok = true
			for _, m := range mins {
				if !s.reached(ctx, m) {
					ok = false
					break
				}
			}
		}
		if ok {
			return true
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-lifecycle.Stopping(ctx):
			// Shutting down: answer now, as if the wait had run out.
			return false
		}
	}
}

func (s *Service) reached(ctx context.Context, m minRef) bool {
	if m.ns == "" {
		return s.Checkpoint(s.opt.Catalog) == m.id || s.Seen(ctx, m.id)
	}
	if s.Checkpoint(m.ns) == m.id {
		return true
	}
	var one int
	return s.db.QueryRowContext(ctx, `SELECT 1 FROM seen WHERE ns = ? AND ns_id = ?`, m.ns, m.id).Scan(&one) == nil
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
	// sealTitle, if set, seals a catalog node's title for per-entry
	// sealing (§E.2.6): the entry carries "sealed" instead of "title".
	sealTitle func(name, title string) string
}

// title sets a node's title on an entry, in the clear or sealed.
func (q *query) title(m map[string]any, n *Node) {
	switch {
	case n.Title == "":
	case q.sealTitle != nil:
		m["sealed"] = q.sealTitle(n.Name, n.Title)
	default:
		m["title"] = n.Title
	}
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
	q.tags.node(q.g, name)
	n := q.g.Node(name)
	if n == nil || !q.v.node(q.g, n) {
		return nil, http.StatusNotFound, "no such node"
	}
	return n, http.StatusOK, ""
}

func (q *query) entry(n *Node) map[string]any {
	q.tags.node(q.g, n.Name)
	m := map[string]any{"href": q.g.Href(n.Name), "name": n.Name, "kind": "folder"}
	q.title(m, n)
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
			if !q.v.node(q.g, x) {
				ok = false
				break
			}
			q.tags.node(q.g, x.Name)
			e := map[string]any{"href": q.g.Href(x.Name), "name": x.Name}
			q.title(e, x)
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
	// In a DAG a folder is listed under each of its parents, and one
	// reached along several paths would be expanded once per path, which
	// grows exponentially with stacked diamonds. So a folder is expanded
	// at its first occurrence only; later ones are marked "repeat" and
	// listed without children (§B.5).
	expanded := map[string]bool{}
	var build func(x *Node, d int, onPath map[string]bool) map[string]any
	build = func(x *Node, d int, onPath map[string]bool) map[string]any {
		e := q.entry(x)
		if x.Kind != KindFolder {
			return e
		}
		if expanded[x.Name] {
			e["repeat"] = true
			return e
		}
		if d >= depth {
			if len(q.visibleChildren(x.Name)) > 0 {
				e["more"] = true
			}
			return e
		}
		kids := []any{}
		expanded[x.Name] = true
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
	cycles := []any{}
	for _, scc := range g.Cycles() {
		arr := []any{}
		for _, name := range scc {
			if n := g.Node(name); n != nil && q.v.node(g, n) {
				q.tags.node(g, name)
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
			q.tags.node(g, name)
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
			q.tags.node(g, name)
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
			q.tags.node(g, name)
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
	q.tags.node(q.g, pl)
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
				q.tags.node(q.g, c.Node.Name)
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
			q.tags.node(q.g, c.Node.Name)
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
