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
	"github.com/middle-management/patchlog/internal/kept"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/telemetry"
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
	// privateListMaxAge is ccPrivateList's max-age.
	privateListMaxAge = 300 * time.Second
	cdnListing        = "max-age=31536000"
)

// Limits of listings.
const (
	defaultLimit    = 100
	maxLimit        = 1000
	maxPaths        = 1000
	maxSubtreeNodes = 5000
	maxManifest     = 10000
	maxTags         = 200
	// keepBytes bounds the listings kept past their at (package kept).
	keepBytes = 64 << 20
)

// RoleView lets readers see nodes through roles (§B.11.5); the catalog
// implements it.
type RoleView interface {
	// Resolve is called once per request with the reader's grant, verified
	// for the catalog namespace. It returns the subjects that key the
	// reader's listings (§B.11.5) and the reader's visibility. Resolve runs
	// outside the graph lock; the Visibility's methods run under it.
	Resolve(ctx context.Context, v *grant.Verified) (subjects []string, vis Visibility, err error)
	// ForSubjects is the visibility of a subject set as Resolve keyed it,
	// for a reader whose edge grant is bound to it (§B.11.5): the cookie
	// carries no grant, only the subject set's prefix.
	ForSubjects(subjects []string) Visibility
}

// Visibility decides, under the graph lock, what a reader may see.
type Visibility interface {
	// Node reports whether the reader may list the node.
	Node(g *Graph, n *Node) bool
	// Item reports whether the reader may see a placement's item (its
	// head and URL).
	Item(g *Graph, n *Node) bool
}

// AllSubjects is the subject set segment of unfiltered listings,
// /{catalog}/g/all/at/{at}/… (§B.11.5).
const AllSubjects = "all"

// viewer is the outcome of the read check for one request.
type viewer struct {
	anon       bool // no grant: the public URL space
	gs         string
	catAll     bool
	catRead    func(name string) bool
	contentAll map[string]bool
	// contentRead, per content namespace the reader's grant reads only in
	// part (rules on /resource), decides which items' heads it may see.
	// Its scope is part of the subject set (no RoleView).
	contentRead map[string]func(name string) bool
	vis         Visibility
	// exp, if set, is the earliest expiry of the grants an unfiltered
	// listing was admitted with: it isn't kept past it (§B.11.5).
	exp time.Time
	// In a subject set's URL space (RoleView), the namespace-wide reads
	// the reader has besides: wideCat for the catalog, wideNS per content
	// namespace (public ones included, §B.11.5), and wideExp the earliest
	// expiry of the grants behind them. problems, orphans and manifests
	// need only those of the namespaces they cover. An answer admitted
	// through such a grant (not public namespaces alone) depends on more
	// than the subject set: priv marks it, and it is kept by no shared
	// cache and no longer than wideExp.
	wideCat   bool
	wideNS    map[string]bool
	wideGrant map[string]bool // namespaces read namespace-wide through a grant, not because they are public ("" the catalog)
	wideExp   time.Time
	priv      bool
	// For an edge grant (edgegrants.go): subjects are what gs is over, as
	// RoleView.Resolve keyed them, and idExp the expiry of the grant
	// verified for the catalog namespace. notBefore, set for a read under
	// a g/all cookie, is the earliest that cookie may have been issued
	// (allNotBefore).
	subjects  []string
	idExp     time.Time
	notBefore time.Time
	// bucket keys the exchangeRate bucket of the grant's principal, as
	// the core keys write buckets: principal and kid (§C.5, §6.6).
	bucket string
	// noEdge keeps a listing out of shared caches whoever reads it
	// (edgeHold).
	noEdge bool
}

// wide reports whether the viewer reads the catalog and every namespace of
// nss namespace-wide (or they are public): what unfiltered listings need
// (§B.11.5).
func (v *viewer) wide(nss []string) bool {
	if !v.catAll {
		return false
	}
	for _, ns := range nss {
		if !v.contentAll[ns] {
			return false
		}
	}
	return true
}

// shape is what a listing at a URL depends on besides the URL: what the
// reader reads whole. A public namespace that turns private moves neither
// the anonymous URL space nor a gs, so a kept listing is served only to
// readers of the shape it was computed for.
func (v *viewer) shape() string {
	nss := make([]string, 0, len(v.contentAll))
	for ns := range v.contentAll {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	return strconv.FormatBool(v.catAll) + " " + strings.Join(nss, ",")
}

func (v *viewer) node(g *Graph, n *Node) bool {
	return v.catAll || (v.catRead != nil && v.catRead(n.Name)) || (v.vis != nil && v.vis.Node(g, n))
}

func (v *viewer) item(g *Graph, n *Node) bool {
	if n.ItemNS == "" || n.State != StateLive {
		return false
	}
	if v.contentAll[n.ItemNS] || (v.vis != nil && v.vis.Item(g, n)) {
		return true
	}
	rd := v.contentRead[n.ItemNS]
	return rd != nil && rd(n.ItemName)
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
//     grant for the catalog namespace that reads the whole namespace
//     (unrestricted, §2.1: one read role without rules on /resource is
//     enough, roles being alternatives), or (filtered per node) one whose
//     rules restrict /resource;
//   - items' heads: public content namespaces, or content namespaces the
//     same grant reads as a whole;
//   - with a RoleView (the catalog), listings are filtered by the reader's
//     subject set alone (§B.11.5): what its roles make visible, under
//     /g/{gs}/ with gs over the subjects. A reader whose grants read the
//     catalog and every trusted content namespace as a whole (or that are
//     public, or purged: trustList) gets unfiltered listings instead,
//     under /g/all/, shared by
//     every such reader, and kept no longer than the earliest of those
//     grants. Namespace-wide reads of only some of them don't count: the
//     listing is then the subject set's.
//
// Anonymous readers of a public catalog use the public URL space; without
// a RoleView, a reader with a grant is routed under /g/{gs}/, where gs
// keys everything its listings depend on: its groups and markers for how
// much of the catalog and which content namespaces it reads as a whole.
//
// A GET or HEAD without Authorization that carries an edge grant the
// service minted, covering its path, is read as that grant's subject set
// (edgeViewer, §B.11.5).
func (s *Service) viewer(ctx context.Context, r *http.Request) (*viewer, error) {
	if cl := s.edgeClaims(r); cl != nil {
		return s.edgeViewer(ctx, cl)
	}
	return s.grantViewer(ctx, Bearer(r))
}

// edgeClaims is the edge grant the service minted that a GET or HEAD
// without Authorization carries, covering its path, if any.
func (s *Service) edgeClaims(r *http.Request) *edge.Claims {
	if s.opt.EdgeGrants == nil || r.Header.Get("Authorization") != "" {
		return nil
	}
	return s.opt.EdgeGrants.FromRequest(r, s.opt.Now())
}

// grantViewer is the viewer of a reader presenting token ("" for none).
func (s *Service) grantViewer(ctx context.Context, token string) (*viewer, error) {
	// In a release preview every check is on the branch read in place of
	// a namespace: a viewer sees only branches it can read (§B.5).
	cat := s.actual(s.opt.Catalog)
	cfg, err := s.checker.Config(ctx, cat)
	if err != nil {
		return nil, err
	}
	catPublic := cfg.Read == "public"
	trust, gone := s.trustList()
	v := &viewer{contentAll: map[string]bool{}, contentRead: map[string]func(string) bool{}}
	if token == "" {
		if !catPublic {
			return nil, &grant.AuthError{Status: 401, Msg: "missing grant"}
		}
		v.anon, v.catAll = true, true
		for _, ns := range trust {
			if gone[ns] {
				v.contentAll[ns] = true
				continue
			}
			if c, err := s.checker.Config(ctx, s.actual(ns)); err == nil && c.Read == "public" {
				v.contentAll[ns] = true
			}
		}
		return v, nil
	}
	vg, err := s.checker.Verify(ctx, cat, token)
	if err != nil {
		return nil, err
	}
	v.bucket = vg.Principal.ID + "\x00" + vg.Key.Kid
	exp := grantExp(vg, time.Time{})
	v.idExp = exp
	var markers []string
	readsCat, _ := vg.Allows("read")
	switch {
	case catPublic:
		v.catAll = true
	case s.checker.ReadsUnrestricted(vg):
		v.catAll = true
		markers = append(markers, "catalog:all")
	case readsCat:
		v.catRead = func(name string) bool { return s.checker.AllowsRead(vg, name) }
		markers = append(markers, "catalog:scope:"+ScopeDigest(vg))
	}
	for _, ns := range trust {
		if gone[ns] {
			v.contentAll[ns] = true
			continue
		}
		real := s.actual(ns)
		c, err := s.checker.Config(ctx, real)
		if err != nil {
			continue
		}
		if c.Read == "public" {
			v.contentAll[ns] = true
			continue
		}
		cv, err := s.checker.Verify(ctx, real, token)
		if err != nil {
			continue
		}
		if ok, _ := cv.Allows("read"); ok && s.checker.ReadsUnrestricted(cv) {
			v.contentAll[ns] = true
			markers = append(markers, "reads:"+real)
			exp = grantExp(cv, exp)
		} else if ok {
			// A grant that reads only some resources (§B.11.5): the items
			// it may read carry their heads, as they would for a reader of
			// the whole namespace. Readers share listings only with
			// identical scopes.
			v.contentRead[ns] = func(name string) bool { return s.checker.AllowsRead(cv, name) }
			markers = append(markers, "reads:"+real+":scope:"+ScopeDigest(cv))
			exp = grantExp(cv, exp)
		}
	}
	if s.opt.RoleView != nil {
		v.contentRead = nil // the subject set alone decides (vis)
		v.wideCat, v.wideNS, v.wideGrant, v.wideExp = v.catAll, map[string]bool{}, map[string]bool{}, exp
		if v.catAll && !catPublic {
			v.wideGrant[""] = true
		}
		for ns := range v.contentAll {
			v.wideNS[ns] = true
		}
		if v.wide(trust) {
			// Unfiltered (§B.11.5): namespace-wide read on the catalog and
			// on every content namespace it trusts.
			v.catRead, v.gs, v.exp = nil, AllSubjects, exp
			return v, nil
		}
		// Filtered by the subject set alone (§B.11.5).
		v.catAll, v.catRead = catPublic, nil
		for ns := range v.contentAll {
			if gone[ns] {
				continue
			}
			if c, err := s.checker.Config(ctx, s.actual(ns)); err != nil || c.Read != "public" {
				delete(v.contentAll, ns)
				v.wideGrant[ns] = true
			}
		}
		v.subjects, v.vis, err = s.opt.RoleView.Resolve(ctx, vg)
		if err != nil {
			return nil, err
		}
		v.gs = grantcheck.SubjectSetID(v.subjects)
		return v, nil
	}
	if !v.catAll && v.catRead == nil {
		return nil, &grant.AuthError{Status: 403, Msg: "the grant does not allow reading the catalog"}
	}
	subjects := grantcheck.SubjectSet(vg, false)
	v.gs = grantcheck.SubjectSetID(append(subjects, markers...))
	return v, nil
}

// trustList is every content namespace the catalog trusts, sorted, and
// gone, those of them the service holds as purged. A purged namespace has
// no live items, so every reader reads it whole, as if it were public,
// sealed or not: a sealed one's documents are 410 once purged (§8.5), and
// no grant can be checked against them, which would otherwise end
// unfiltered listings and g/all edge grants for good (§B.11.5). With edge
// grants, only once an edge's copies of g/all listings from before the
// purge, which show its last items to every g/all cookie, have surely
// expired: cdnAll after the service applied it, should the purge of
// ns:{ns} be lost or late (Apply). Until then each reader's grant is
// checked as before, and a sealed one is read whole by nobody.
func (s *Service) trustList() (trust []string, gone map[string]bool) {
	gone = map[string]bool{}
	var hold time.Duration
	if s.opt.EdgeGrants != nil {
		hold = s.cdnAll()
	}
	now := s.opt.Now()
	s.View(func(g *Graph, _ map[string]string) {
		for ns := range g.Trust {
			trust = append(trust, ns)
			if at, ok := s.purged[ns]; ok && !now.Before(at.Add(hold)) {
				gone[ns] = true
			}
		}
	})
	sort.Strings(trust)
	return trust, gone
}

// grantExp is the earlier of exp (zero: none) and the earliest expiry of
// a verified grant's blocks.
func grantExp(v *grant.Verified, exp time.Time) time.Time {
	for _, b := range v.Grant.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	return exp
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
//	GET /{catalog}/{op}?…                   302 → /{catalog}[/g/{gs}]/at/{at}/{op}?…  (head pointer)
//	GET /{catalog}/at/{at}/{op}?…            200, public readers                     (immutable)
//	GET /{catalog}/g/{gs}/at/{at}/{op}?…     200, readers with a grant, keyed by subject set (§B.11.5)
//
// at is the combined checkpoint (CombinedAt). The subject set comes before
// it, so one edge grant for the prefix /{catalog}/g/{gs} covers every
// checkpoint (§B.11.5); the form before v0.51,
// /{catalog}/at/{at}/g/{gs}/{op}?…, is moved permanently (301) to it. op
// is one of
// children?of=&after=&limit=, ancestors?of=, subtree?of=&depth=, roots,
// orphans, problems, where?item=, manifest?of=.
//
// children, ancestors, subtree, roots and where show the nodes the reader
// may see, and only paths through visible folders, with no trace of hidden
// nodes (no counts); limits, cut markers and pagination count visible
// nodes only (§B.11.5). orphans, problems and manifest aren't filtered:
// they answer 403 unless the reader reads the catalog and the content
// namespaces they cover as a whole. A catalog service's readers with such
// grants on the catalog and every trusted namespace are served unfiltered
// listings under /g/all/ (§B.11.5, viewer).
//
// Every listing computed, including the one a redirect names, is kept for
// a while (package kept), under its URL and what the reader reads whole
// (viewer.shape), and answered 200 at its at however far the checkpoint
// moves meanwhile, so one redirect suffices (§A.4 "Bounded redirects",
// §B.5 "only if it is current or that exact result was stored"); any other
// at is redirected to the current one. A purge drops the kept listings
// that carry a tag it purges. Listings whose answer depends on more than
// the reader's URL space (perReader) aren't kept.
//
// ?min= waits until the service has applied an ns_id (§A.5): {ns}:{ns_id}
// for the catalog or a followed content namespace, repeatable, or a bare
// {ns_id} of any of them. It always redirects (§A.5): an at URL whose
// listing already includes every min (the current at, or a kept one whose
// checkpoints show it does, atIncludes) to itself without min, anything
// else, once every min is reached, to the current at.
//
// Redirects name the query in its canonical form (§A.5,
// derived.CanonicalQuery), and so does a children listing's next; an at
// URL is answered 200 only in that form and without min, and one in
// another form is redirected to it. Every parameter but min is
// single-valued: given more than once, it is 400 bad_input.
//
// File trees (§H.2, §H.3; files.go). A catalog whose catalog.files makes
// it a file tree gives every placement entry with a head "file": { size,
// type, modified } of that head, in the clear for items of a namespace
// that is neither sealed nor e2e. For an item of a sealed (E2) namespace
// it is "file": { "sealed": JWE of { file } } under the item's own K_r,
// kid its namespace's current epoch, pl { ns, name, view } of the item, so
// readers given K_r by /read-grants open it, whatever the catalog's level;
// for an e2e item it is left out. A listing holding any sealed file is
// stored and served unchanged like a sealed catalog's. While a sealed
// namespace's key can't be had for the moment, listings are 503, no-store
// (fileSealing). The "file": { "sealed" } form, and its nesting inside a
// sealed catalog's whole-listing JWE below, are provisional: §E.2.6 has a
// per-entry "sealed" member for values of one source (the catalog's
// titles), and no form yet for values another namespace's resource gives.
//
// A sealed or e2e catalog (§E.2.5, §E.2.6; package derived). Titles are
// the only values a listing takes from the catalog's content (names,
// heads, hrefs, structure, order and cursors stay in the clear, and
// content namespaces contribute nothing else but file metadata, sealed on
// its own), so the catalog is the one source of what a listing seals
// whole. A reader of the whole catalog gets the listing sealed as
// one JWE under the catalog's current epoch key, Content-Type
// application/jose, pl { ns, view } where view is the listing's request
// target (/{catalog}[/g/{gs}]/at/{at}/{op}?{query}, the canonical form). A
// reader whose grant restricts catalog resources (or who sees nodes only
// through roles) gets JSON in which every node with a title carries
// "sealed": JWE of { title } under that catalog resource's K_r, pl { ns,
// name, view }, instead of "title". Sealed listings are produced once per
// view (a rotation moves at), stored in the database with their cache
// tags, and served unchanged, across restarts, until a purge with one of
// those tags or a new at retires them (derived.Cache).
//
//	POST   /edge-grants             the service's own edge grants, with
//	DELETE /edge-grants?prefix=…    Options.EdgeGrants (edgegrants.go)
//
//	GET /_status    each followed namespace's encryption level and epoch,
//	                whether listings are sealed, and why a namespace is
//	                skipped (or its documents not read); "catalogs" names
//	                the catalog served (several behind Multi)
func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/edge-grants" {
		s.serveEdgeGrants(w, r)
		return
	}
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
		telemetry.SetRoute(r, "/_status")
		s.serveStatus(w)
		return
	case len(segs) == 2 && segs[0] == cat:
		op = segs[1]
	case len(segs) == 4 && segs[0] == cat && segs[1] == "at":
		at, op, isAt = segs[2], segs[3], true
	case len(segs) == 6 && segs[0] == cat && segs[1] == "g" && segs[3] == "at":
		gs, at, op, isAt = segs[2], segs[4], segs[5], true
	case len(segs) == 6 && segs[0] == cat && segs[1] == "at" && segs[3] == "g" && oldForm(segs[2], segs[4], segs[5]):
		// Before v0.51 (§B.11.5): the subject set now comes first.
		telemetry.SetRoute(r, "/{catalog}/at/{at}/g/{gs}/{op}")
		moved(w, r, "/"+cat+"/g/"+segs[4]+"/at/"+segs[2]+"/"+segs[5])
		return
	default:
		WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !ops[op] {
		WriteError(w, http.StatusNotFound, "not_found", "unknown listing")
		return
	}
	// The listing is one of a fixed set: it stays in the route.
	switch {
	case gs != "":
		telemetry.SetRoute(r, "/{catalog}/g/{gs}/at/{at}/"+op)
	case isAt:
		telemetry.SetRoute(r, "/{catalog}/at/{at}/"+op)
	default:
		telemetry.SetRoute(r, "/{catalog}/"+op)
	}
	if isAt {
		if _, err := ids.Parse(at); err != nil {
			WriteError(w, http.StatusBadRequest, "bad_input", "malformed ns_id")
			return
		}
	}
	if gs != "" && gs != AllSubjects {
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
	if reason := s.keys.Skipped(cat); reason != "" {
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, "skipped", "the service does not consume the catalog: "+reason)
		return
	}
	v, err := s.viewer(ctx, r)
	if client.IsPurged(err) {
		// A purged sealed catalog's document is 410 too (§8.5): the core
		// makes the read check before answering it, as below. An edge
		// grant that passed the service's checks stands for the grant it
		// was exchanged for, which the core would take as an anonymous
		// read: 410 purged. A g/all one's grant read the catalog, so it
		// gets head; a subject set's may not have (RoleView issues one to
		// any grant verifying for the catalog), and gets none, since the
		// core shows a sealed purged catalog's head only to its readers.
		var head string
		if cl := s.edgeClaims(r); cl != nil {
			if gs, _ := s.edgeGS(cl.Prefix); gs != AllSubjects {
				err = nil
			} else if head = s.purgedHead(err); head != "" {
				err = nil
			}
		} else {
			head, err = s.checker.PurgedRead(ctx, s.actual(cat), Bearer(r))
		}
		if err == nil {
			writePurged(w, head)
			return
		}
	}
	if err != nil {
		WriteAuthError(w, err, s.opt.Logf)
		return
	}
	vals := r.URL.Query()
	// Every parameter but min is single-valued, read as its first value,
	// and the canonical form sorts a repeated one's values (§A.5): a
	// repeat would change what a redirect means, so it is refused.
	for k, vs := range vals {
		if len(vs) > 1 && k != "min" {
			w.Header().Set("Cache-Control", "no-store")
			WriteError(w, http.StatusBadRequest, "bad_input", k+" given more than once")
			return
		}
	}
	target := func(cp string) string {
		if v.anon {
			return "/" + cat + "/at/" + cp + "/" + op
		}
		return "/" + cat + "/g/" + v.gs + "/at/" + cp + "/" + op
	}
	// A purged catalog answers as the core's URLs of it do, after the read
	// check: 410 purged with head, its purge-ns entry (§8.5, §12), the
	// log's last, where the checkpoint stopped; none under a subject
	// set's edge grant, as above.
	if head, purged, _ := s.state(); purged {
		if cl := s.edgeClaims(r); cl != nil && v.gs != AllSubjects {
			head = ""
		}
		writePurged(w, head)
		return
	}
	setPtr := func() {
		// An anonymous reader's redirect out of a subject set's URL space
		// is no shared cache's either: there, the edge serves what it
		// holds to readers with that subject set's edge grant (§B.11.5).
		if v.anon && gs == "" {
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
	if a := s.awaitMins(ctx, vals["min"], Bearer(r)); a.status != 0 {
		a.write(w)
		return
	}
	if ns := s.behind(); ns != "" {
		msg := "the tree service has not reached the catalog yet"
		if ns != cat {
			msg = "the tree service has not reached namespace " + ns + ", which the catalog trusts, yet"
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		WriteError(w, http.StatusServiceUnavailable, "behind", msg)
		return
	}
	// canon is the canonical URL of this listing at an at (§A.5): what
	// redirects name, what listings are kept and stored under (with the
	// reader's shape, keyOf), and in a sealed or e2e catalog the view a
	// listing is bound to (§E.2.6). Only it is answered 200: another form
	// of it, or one with min, is redirected.
	canon := func(at string) string { return target(at) + derived.CanonicalQuery(vals, "min") }
	keyOf := func(at string) string { return canon(at) + "\n" + v.shape() }
	keep := !perReader(op, v)
	var cur string
	s.View(func(g *Graph, curMap map[string]string) { cur, _ = CombinedAt(g, curMap) })
	if ns := s.trustedSince(v, at, cur); ns != "" {
		// A g/all edge grant covers every later at, but not one that
		// includes a namespace it wasn't checked against (§B.11.5).
		w.Header().Set("Cache-Control", "no-store")
		WriteError(w, http.StatusForbidden, "forbidden", "the edge grant for all predates the catalog's trust in "+ns+": exchange the grants again")
		return
	}
	v.noEdge = s.edgeHold(v, at, cur)
	own := isAt && gs == v.gs && !(v.anon && gs != "")
	mins := len(vals["min"]) > 0
	canonical := r.URL.RequestURI() == canon(at)
	if own && mins && at != cur && s.atIncludes(ctx, at, vals["min"], keyOf(at), keep) {
		// min always redirects (§A.5): an older at that already includes
		// every min to itself without it. The current at needs no
		// judging: the redirect to the current at below names the same
		// URL, with the listing computed and kept there first.
		setPtr()
		redirect(w, canon(at))
		return
	}
	if own && keep && !mins {
		// A kept listing answers its at however far the checkpoint has
		// moved since.
		if st, _, ok := s.kept.Get(keyOf(at)); ok {
			if !canonical {
				setPtr()
				redirect(w, canon(at))
				return
			}
			s.writeListing(w, r, v, at, st)
			return
		}
	}
	if !own || at != cur || mins {
		// Head pointer, another URL space, an at whose listing isn't
		// kept, or a min waited for (§A.5): redirect to the current at,
		// with the listing computed there and kept, so the redirect is
		// answered even if the checkpoint moves on before it is followed.
		// If it can't be computed, the at URL says why.
		to := cur
		if _, _, ok := s.kept.Get(keyOf(cur)); keep && !ok {
			if info, key, err := s.keys.Current(ctx, cat); err == nil {
				if l, err := s.listing(ctx, v, op, vals, canon, keyOf, info, key); err == nil && l.status == http.StatusOK {
					to = l.at
				}
			}
		}
		setPtr()
		redirect(w, canon(to))
		return
	}
	if !canonical {
		setPtr()
		redirect(w, canon(at))
		return
	}

	info, key, err := s.keys.Current(ctx, cat)
	if err != nil {
		s.opt.Logf("tree: keys of %s: %v", cat, err)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		// Keys it can't fetch yet are a view it hasn't caught up with
		// (§12.1 behind, §E.2.6).
		WriteError(w, http.StatusServiceUnavailable, "behind", "the service cannot obtain the key that seals listings of the catalog yet")
		return
	}
	l, err := s.listing(ctx, v, op, vals, canon, keyOf, info, key)
	switch {
	case errors.Is(err, errFileKeys):
		s.opt.Logf("tree: %v", err)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		WriteError(w, http.StatusServiceUnavailable, "behind", "the service cannot obtain the key that seals the file metadata of a trusted namespace yet")
	case err != nil:
		s.opt.Logf("tree: sealing a listing: %v", err)
		WriteError(w, http.StatusInternalServerError, "internal", "sealing failed")
	case l.status != http.StatusOK:
		WriteError(w, l.status, codeFor(l.status), l.msg)
	case l.at != at:
		// The checkpoint moved since the check: the listing is kept at
		// the new one.
		setPtr()
		redirect(w, canon(l.at))
	default:
		s.writeListing(w, r, v, at, l.st)
	}
}

// writePurged writes the 410 of a purged catalog, with head its purge-ns
// entry's ns_id (§8.5, §12), or none if head is "".
func writePurged(w http.ResponseWriter, head string) {
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]any{"code": "purged", "message": "catalog purged"}
	if head != "" {
		body["head"] = head
	}
	WriteJSON(w, http.StatusGone, body)
}

// purgedHead is the head of the catalog's purge, its purge-ns entry's
// ns_id (§8.5): the service's checkpoint once it holds the catalog as
// purged, else the head of err, the 410 purged of the catalog's document
// ("" if it has none).
func (s *Service) purgedHead(err error) string {
	if head, purged, _ := s.state(); purged {
		return head
	}
	if ae, ok := client.AsAPIError(err); ok {
		return ae.Head()
	}
	return ""
}

// computed is a listing computed at an at, or why there is none (status,
// msg).
type computed struct {
	st     derived.Stored
	at     string
	status int
	msg    string
}

// listing computes the listing of op for v at the current at, sealed in a
// sealed or e2e catalog, stores a sealed one and keeps it (unless
// perReader), and returns it with the at it is at. canon gives its URL at
// an at, the view it is bound to, and keyOf what it is stored and kept
// under: the URL and the reader's shape, since a namespace that turns
// private moves no URL (viewer.shape).
func (s *Service) listing(ctx context.Context, v *viewer, op string, vals url.Values, canon, keyOf func(string) string, info derived.Info, key derived.Key) (*computed, error) {
	cat := s.opt.Catalog
	keep := !perReader(op, v)
	gen := s.kept.Generation(cat)
	fs, err := s.fileSealing(ctx)
	if err != nil {
		return nil, err
	}
	// A listing that seals values, the catalog's or an item's file
	// metadata, is sealed once and then served unchanged (§E.2.6).
	sealed := info.Protected() || fs.seals()
	if sealed && keep {
		at := s.At()
		if st, ok := s.sealed.Get(ctx, keyOf(at)); ok {
			st, _ = s.kept.Put(keyOf(at), cat, gen, true, st)
			return &computed{st: st, at: at, status: http.StatusOK}, nil
		}
	}
	var (
		l    = &computed{}
		body any
		tags tagSet
		nss  []string
		view derived.View
		serr error
	)
	perEntry := info.Protected() && !v.catAll
	var cps map[string]string
	s.View(func(g *Graph, curMap map[string]string) {
		l.at, nss = CombinedAt(g, curMap)
		cps = checkpointsOf(g, curMap)
		view = derived.View{NS: cat, Target: canon(l.at)}
		q := &query{s: s, g: g, v: v, vals: vals, tags: tagSet{}, at: l.at, files: fs, view: view, serr: &serr}
		if perEntry {
			q.sealTitle = func(name, title string) string {
				jwe, err := derived.SealItem(key, view, name, map[string]any{"title": title})
				if err != nil && serr == nil {
					serr = err
				}
				return jwe
			}
		}
		body, l.status, l.msg = q.run(op)
		tags = q.tags
	})
	if l.status != http.StatusOK {
		return l, nil
	}
	l.st = derived.Stored{JSON: true, Tags: tags.header(cat, nss)}
	if serr == nil && info.Protected() && !perEntry {
		var jwe string
		jwe, serr = derived.SealView(key, view, body)
		l.st.Body, l.st.JSON = []byte(jwe), false
	} else if serr == nil {
		l.st.Body, serr = derived.Marshal(body)
	}
	if serr != nil {
		return nil, serr
	}
	if !keep {
		// Neither stored nor kept: whether it may be served depends on
		// the reader.
		return l, nil
	}
	if sealed {
		var err error
		if l.st, err = s.sealed.Put(ctx, keyOf(l.at), cat, l.at, l.st); err != nil {
			s.opt.Logf("tree: storing a sealed listing: %v", err)
		}
		if cur := s.At(); cur != l.at {
			// An apply (maybe a purge) committed meanwhile: don't keep a
			// listing it may have retired.
			if err := s.sealed.Retire(ctx, s.db, cat, cur); err != nil {
				s.opt.Logf("tree: retiring sealed listings: %v", err)
			}
		}
	}
	l.st, _ = s.kept.Put(keyOf(l.at), cat, gen, sealed, l.st)
	s.recordAt(l.at, cps)
	return l, nil
}

// atRecord is what a combined at is over: each namespace's checkpoint, by
// the name listings and min use (in a release preview, the base's).
type atRecord struct {
	cps map[string]string
	exp time.Time
}

// checkpointsOf is the checkpoints CombinedAt hashes, keyed as cur is.
func checkpointsOf(g *Graph, cur map[string]string) map[string]string {
	cps := map[string]string{}
	if id := cur[g.Catalog]; id != "" {
		cps[g.Catalog] = id
	}
	for ns := range g.Trust {
		if id := cur[ns]; id != "" {
			cps[ns] = id
		}
	}
	return cps
}

// recordAt records the checkpoints behind at, a listing of which was just
// kept, for as long as kept listings are (kept.For), so atIncludes can
// judge a min on an older at.
func (s *Service) recordAt(at string, cps map[string]string) {
	now := s.opt.Now()
	s.amu.Lock()
	defer s.amu.Unlock()
	if s.ats == nil {
		s.ats = map[string]atRecord{}
	}
	if _, ok := s.ats[at]; !ok {
		for a, rec := range s.ats {
			if now.After(rec.exp) {
				delete(s.ats, a)
			}
		}
	}
	s.ats[at] = atRecord{cps: cps, exp: now.Add(kept.For)}
}

// atIncludes reports whether the listing at an older at already includes
// every min of vals (§A.5 "min always redirects"), once AwaitMins has
// waited for them. It is judged only while the listing is kept (key, if
// keep) and its checkpoints are recorded (recordAt): each {ns}:{ns_id}
// must be ns's checkpoint there or one the core's log places before it
// (since=min is accepted only if min is in the chain up to it, §7.1), and
// a bare ns_id, whose namespace isn't named, never counts. An at it can't
// judge redirects to the current one.
func (s *Service) atIncludes(ctx context.Context, at string, vals []string, key string, keep bool) bool {
	if !keep {
		return false
	}
	if _, _, ok := s.kept.Get(key); !ok {
		return false
	}
	s.amu.Lock()
	rec, ok := s.ats[at]
	s.amu.Unlock()
	if !ok {
		return false
	}
	mins, err := parseMins(vals)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, m := range mins {
		if m.ns == "" {
			return false
		}
		ns := s.logical(m.ns)
		id, ok := rec.cps[ns]
		if !ok {
			return false
		}
		if id == m.id {
			continue
		}
		if _, _, err := s.c.NSLogPage(ctx, s.actual(ns), id, m.id); err != nil {
			return false
		}
	}
	return true
}

// perReader reports whether an answer to op may be served depends
// on more than the reader's URL space: problems, orphans and manifests in
// a subject set's URL space, which need namespace-wide reads the subject
// set doesn't imply (query.unfiltered).
func perReader(op string, v *viewer) bool {
	return !v.anon && v.gs != AllSubjects && v.wideNS != nil && (op == "problems" || op == "orphans" || op == "manifest")
}

// setListingHeaders sets a listing's headers: one for readers with a grant
// gets edge lifetimes only for a read the verifying edge verified (§9).
func (s *Service) setListingHeaders(w http.ResponseWriter, r *http.Request, v *viewer, at, tags string) {
	switch {
	case v.priv:
		// Admitted through namespace-wide grants the subject set doesn't
		// imply: no shared cache keeps it, and the browser no longer than
		// those grants (§B.11.5).
		secs := int(privateListMaxAge / time.Second)
		if !v.wideExp.IsZero() {
			secs = min(secs, max(int(v.wideExp.Sub(s.opt.Now())/time.Second), 0))
		}
		w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(secs))
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Surrogate-Control", "no-store")
	case v.anon:
		w.Header().Set("Cache-Control", ccListing)
	case !v.exp.IsZero() && v.exp.Sub(s.opt.Now()) < privateListMaxAge:
		// An unfiltered listing expires with the earliest grant it was
		// admitted with (§B.11.5).
		secs := max(int(v.exp.Sub(s.opt.Now())/time.Second), 0)
		w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(secs))
		s.opt.Edge.Private(w.Header(), r, "max-age="+strconv.Itoa(secs))
	case v.gs == AllSubjects && s.opt.EdgeGrants != nil:
		w.Header().Set("Cache-Control", ccPrivateList)
		s.opt.Edge.Private(w.Header(), r, "max-age="+strconv.Itoa(int(s.cdnAll()/time.Second)))
	default:
		w.Header().Set("Cache-Control", ccPrivateList)
		s.opt.Edge.Private(w.Header(), r, cdnListing)
	}
	if v.noEdge {
		edge.NoStore(w.Header())
	}
	w.Header().Set("Cache-Tag", tags)
	w.Header().Set("X-Namespace-Revision", at)
}

// cdnAll is the longest an edge keeps a g/all listing: as long as a g/all
// cookie lives, and edgeClockSkew. An edge serves the g/all listings it
// holds to every g/all cookie, including one issued after the catalog
// stopped trusting a namespace a listing shows, which the service purges
// (ns:{catalog}, Apply); should that purge be lost, or race a fill, the
// listing outlives the change by no more than a cookie issued before it
// (§B.11.5, §C.5: the cookie's lifetime is the revocation latency). A
// purged namespace counts as read whole that long after the purge
// (trustList), for the same reason. Listings an edge cached from earlier
// releases, with a year, are purged once by the operator (README).
func (s *Service) cdnAll() time.Duration {
	return s.opt.EdgeGrants.MaxTTL() + edgeClockSkew
}

// writeListing writes a stored sealed listing: the JWE (application/jose),
// or the JSON with per-node sealed titles, with the Cache-Tag it was
// stored with.
func (s *Service) writeListing(w http.ResponseWriter, r *http.Request, v *viewer, at string, st derived.Stored) {
	s.setListingHeaders(w, r, v, at, st.Tags)
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
func (s *Service) status() []derived.Status {
	var nss []string
	for _, ns := range s.followed() {
		nss = append(nss, s.actual(ns))
	}
	return s.keys.Status(nss)
}

func codeFor(status int) string {
	switch status {
	case http.StatusNotFound:
		return "not_found"
	case http.StatusBadRequest:
		return "bad_input"
	case http.StatusUnprocessableEntity:
		return "too_large"
	case http.StatusForbidden:
		return "forbidden"
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
	// In a release preview the checkpoint is over the branches (§B.5).
	add := func(ns string) {
		if id := cur[ns]; id != "" {
			m[g.Actual(ns)] = id
			nss = append(nss, g.Actual(ns))
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
	t["r:"+g.Actual(g.Catalog)+"/"+name] = true
	if n := g.Node(name); n != nil && n.ItemNS != "" {
		t["r:"+g.Actual(n.ItemNS)+"/"+n.ItemName] = true
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

// AwaitMins implements ?min={ns}:{ns_id} (§A.5) for the values given: 0 once
// the service has reached every one (waiting up to MinWait), else the
// status and error to answer with: 400 for a malformed min or one naming a
// namespace the service doesn't follow, 503 (with Retry-After) while it is
// behind. A min naming a namespace the service holds as purged counts as
// reached. Services of the addenda use it for the endpoints that take min.
func (s *Service) AwaitMins(ctx context.Context, vals []string) (status int, code, msg string) {
	a := s.awaitMins(ctx, vals, "")
	return a.status, a.code, a.msg
}

// AwaitMinsRefused is AwaitMins with, for a 400, the mins it refuses as
// given, which the body of the 400 lists as min (§A.5).
func (s *Service) AwaitMinsRefused(ctx context.Context, vals []string) (status int, code, msg string, refused []string) {
	a := s.awaitMins(ctx, vals, "")
	return a.status, a.code, a.msg, a.refused
}

// minElsewhere is the 400 for a min naming a namespace that neither the
// service nor, behind Multi, another catalog's follows, or that the
// reader can't see: one message, so it doesn't tell which namespaces
// exist.
const minElsewhere = "min names a namespace the service does not follow or the reader can't see"

// minAnswer is the answer to a request whose mins can't all be waited for
// (§A.5): status 0 once every one is reached; else the status, code and
// message, and, for a 400, refused, every min refused as given, which the
// body lists as min, so a tool drops those.
type minAnswer struct {
	status    int
	code, msg string
	refused   []string
}

// write writes a: no-store, Retry-After on a 503.
func (a minAnswer) write(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	if a.status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	body := map[string]any{"code": a.code, "message": a.msg}
	if len(a.refused) > 0 {
		body["min"] = a.refused
	}
	WriteJSON(w, a.status, body)
}

// awaitMins is AwaitMins for a reader presenting token ("" for none).
// Behind Multi, a min naming a namespace that another catalog's service
// follows, and that the reader may see (public, or its grant reads it),
// is waited for there: this catalog's at doesn't cover it, so the
// listing then redirects to the current at in one hop (§A.5, §B.5). A min
// naming a namespace this service or a sibling holds as purged counts as
// reached, without a read check: a purge is no secret (§A.5, §E.4).
func (s *Service) awaitMins(ctx context.Context, vals []string, token string) minAnswer {
	var own []minRef
	other := map[*Service][]minRef{}
	var refused []string
	malformed := ""
	for _, raw := range vals {
		m, err := parseMin(raw)
		if err != nil {
			refused = append(refused, raw)
			if malformed == "" {
				malformed = err.Error()
			}
			continue
		}
		// A preview's readers write to the branches, so min names them.
		m.ns = s.logical(m.ns)
		if m.ns == "" {
			own = append(own, m)
			continue
		}
		if s.holdsPurged(m.ns) {
			continue
		}
		if s.follows(m.ns) {
			own = append(own, m)
			continue
		}
		if s.siblingPurged(m.ns) {
			continue
		}
		o := s.sibling(m.ns)
		if o == nil {
			refused = append(refused, raw)
			continue
		}
		switch ok, err := o.sees(ctx, m.ns, token); {
		case err != nil:
			s.opt.Logf("tree: access check for %s: %v", m.ns, err)
			return minAnswer{status: http.StatusBadGateway, code: "upstream", msg: "cannot read a namespace configuration"}
		case !ok:
			refused = append(refused, raw)
			continue
		}
		other[o] = append(other[o], m)
	}
	if len(refused) > 0 {
		msg := minElsewhere
		if malformed != "" {
			msg = malformed
		}
		return minAnswer{status: http.StatusBadRequest, code: "bad_input", msg: msg, refused: refused}
	}
	ctx, cancel := context.WithTimeout(ctx, s.opt.MinWait)
	defer cancel()
	behind := minAnswer{status: http.StatusServiceUnavailable, code: "behind", msg: "the tree service has not reached min yet"}
	if !s.waitMins(ctx, own) {
		return behind
	}
	for o, ms := range other {
		if !o.waitMins(ctx, ms) {
			return behind
		}
	}
	return minAnswer{}
}

// holdsPurged reports whether the service holds ns as purged (meta
// "purged:{ns}"), trusted still or not.
func (s *Service) holdsPurged(ns string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.purged[ns]
	return ok
}

// siblingPurged reports whether the service of another catalog behind the
// same Multi holds ns as purged.
func (s *Service) siblingPurged(ns string) bool {
	for _, o := range s.siblings {
		if o.holdsPurged(ns) {
			return true
		}
	}
	return false
}

// sibling is the service of another catalog behind the same Multi that
// follows ns, if any.
func (s *Service) sibling(ns string) *Service {
	for _, o := range s.siblings {
		if o.follows(ns) {
			return o
		}
	}
	return nil
}

// follows reports whether the service follows ns for a min (§A.5): the
// catalog, or a namespace it trusts and can follow. A min naming one it
// can't (unfollowed: refused or absent at the core, skipped for its keys)
// would wait for a checkpoint that doesn't come; it is the 400 for a
// namespace the service doesn't follow.
func (s *Service) follows(ns string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ns == s.opt.Catalog || s.g.Trust[ns] && s.unfollowed[ns] == ""
}

// sees reports whether the bearer of token ("" for none) may see ns:
// it is public, or the grant reads it, in whole or in part. A purged sealed
// namespace's document is 410 (§8.5): the core makes the read check
// instead (PurgedRead). Any other namespace document that can't be read is
// an error.
func (s *Service) sees(ctx context.Context, ns, token string) (bool, error) {
	cfg, err := s.checker.Config(ctx, s.actual(ns))
	if client.IsPurged(err) {
		_, err = s.checker.PurgedRead(ctx, s.actual(ns), token)
		var ae *grant.AuthError
		if errors.As(err, &ae) {
			return false, nil
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	if cfg.Read == "public" {
		return true, nil
	}
	if token == "" {
		return false, nil
	}
	v, err := s.checker.Verify(ctx, s.actual(ns), token)
	var ae *grant.AuthError
	switch {
	case errors.As(err, &ae):
		return false, nil
	case err != nil:
		return false, err
	}
	ok, _ := v.Allows("read")
	return ok, nil
}

func parseMins(vals []string) ([]minRef, error) {
	var out []minRef
	for _, v := range vals {
		m, err := parseMin(v)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// parseMin parses one ?min= value: {ns}:{ns_id} or a bare {ns_id}.
func parseMin(v string) (minRef, error) {
	var m minRef
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		m.ns, v = v[:i], v[i+1:]
		if !client.ValidNSName(m.ns) {
			return minRef{}, errors.New("min: malformed namespace name")
		}
	}
	if _, err := ids.Parse(v); err != nil {
		return minRef{}, errors.New("min must be {ns}:{ns_id} or an ns_id")
	}
	m.id = v
	return m, nil
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

func redirect(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

// oldForm reports whether the segments of a listing URL of a form before
// v0.51 are well formed, so the URL moved names nothing but them.
func oldForm(at, gs, op string) bool {
	_, err := ids.Parse(at)
	if gs != AllSubjects {
		if _, gerr := ids.Parse(gs); gerr != nil {
			err = gerr
		}
	}
	return err == nil && ops[op]
}

// moved answers a URL of a form before v0.51 (§B.11.5) with a permanent
// redirect to path, the same query kept: the redirect depends on the URL
// alone, so it reveals nothing, and the URL it names checks the reader.
func moved(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Location", path)
	w.WriteHeader(http.StatusMovedPermanently)
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
	// files says how placements carry file metadata in a file tree
	// (§H.3), sealed under view; serr records a sealing failure.
	files *fileSealing
	view  derived.View
	serr  *error
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
		return nil, http.StatusNotFound, noSuchNode
	}
	return n, http.StatusOK, ""
}

// noSuchNode is the 404 of a parameter naming a node or item not in the
// catalog, or hidden from the reader: one message, so it doesn't tell
// them apart (§B.5, §B.11.5).
const noSuchNode = "no such node"

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
			if n.Title == "" && n.ItemTitle != "" {
				// The head's title (§B.5), unless the placement has its own.
				q.title(m, &Node{Name: n.Name, Title: n.ItemTitle})
			}
			m["head"] = n.ItemHead
			// In a release preview the head is the branch's: url reads it
			// there (§B.5), while item keeps the name documents use.
			m["url"] = q.s.origin + q.g.ItemHref(n) + "/rev/" + n.ItemHead
			if a := q.g.Actual(n.ItemNS); a != n.ItemNS {
				m["branch"] = a
			}
			if f := q.file(n); f != nil {
				m["file"] = f
			}
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
		body["next"] = derived.CanonicalQuery(nv)
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

// paths returns every walkable path from n up to a root for the viewer
// through nodes it may see, root first, without n itself, bounded at
// MaxDepth and maxPaths. A root for the viewer is a node without parents,
// or a visible one whose parents are all hidden from it, where its paths
// end (§B.11.5). incomplete counts paths that end below a root (at a node
// whose parents are all gone, dangling or cyclic), deep those cut at
// MaxDepth. A path through a node the viewer may not see is left out
// without a trace: listings show only paths through visible folders, and
// nothing about a hidden node, not even a count (§B.11.5), so limits apply
// to visible paths only.
func (q *query) paths(n *Node) (paths [][]*Node, incomplete, deep int, truncated bool) {
	var stack []*Node
	var walk func(x *Node, depth int)
	end := func() {
		p := make([]*Node, len(stack))
		for i := range stack {
			p[i] = stack[len(stack)-1-i]
		}
		paths = append(paths, p)
	}
	walk = func(x *Node, depth int) {
		if len(paths) >= maxPaths {
			truncated = true
			return
		}
		if len(x.Parents) == 0 && !x.Cyclic {
			end()
			return
		}
		ps := q.g.WalkableParents(x)
		if len(ps) == 0 {
			incomplete++
			return
		}
		var visible []*Node
		for _, pn := range ps {
			if parent := q.g.Node(pn); q.v.node(q.g, parent) {
				visible = append(visible, parent)
			}
		}
		if len(visible) == 0 {
			// Every parent is hidden: x is a root for the viewer.
			end()
			return
		}
		if depth >= MaxDepth {
			deep++
			return
		}
		for _, parent := range visible {
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

func (q *query) pathJSON(ps [][]*Node) []any {
	out := []any{}
	for _, p := range ps {
		arr := make([]any, 0, len(p))
		for _, x := range p {
			q.tags.node(q.g, x.Name)
			e := map[string]any{"href": q.g.Href(x.Name), "name": x.Name}
			q.title(e, x)
			arr = append(arr, e)
		}
		out = append(out, arr)
	}
	return out
}

// ancestors lists every path from the node to a root, root first, for
// breadcrumbs. Paths through nodes the reader may not see are left out.
func (q *query) ancestors() (any, int, string) {
	n, st, msg := q.node("of")
	if n == nil {
		return nil, st, msg
	}
	ps, incomplete, deep, trunc := q.paths(n)
	body := map[string]any{"at": q.at, "of": q.g.Href(n.Name), "node": q.entry(n), "paths": q.pathJSON(ps)}
	if incomplete > 0 {
		body["incomplete"] = incomplete
	}
	if deep > 0 {
		body["tooDeep"] = deep
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

// roots lists the roots for the reader's subject set (§B.5, §B.11.5):
// visible nodes without parents, and visible nodes whose parents are all
// hidden from it.
func (q *query) roots() (any, int, string) {
	out := []any{}
	for _, n := range q.rootNodes() {
		out = append(out, q.entry(n))
	}
	return map[string]any{"at": q.at, "roots": out}, http.StatusOK, ""
}

// rootNodes are the live nodes that are roots for the viewer, by name.
func (q *query) rootNodes() []*Node {
	var out []*Node
	for _, name := range q.g.Names() {
		if n := q.g.Node(name); n.Live() && q.v.node(q.g, n) && q.rootFor(n) {
			out = append(out, n)
		}
	}
	return out
}

// rootFor reports whether n, visible to the viewer, is a root for it: it
// has no parents, or every parent a walk may go up to is hidden from it
// (§B.11.5). A node whose parents are all gone, dangling or cyclic is an
// orphan (§B.5), not a root.
func (q *query) rootFor(n *Node) bool {
	if len(n.Parents) == 0 {
		return true
	}
	ps := q.g.WalkableParents(n)
	for _, p := range ps {
		if q.v.node(q.g, q.g.Node(p)) {
			return false
		}
	}
	return len(ps) > 0
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

// trusted is every content namespace the catalog trusts, sorted.
func (q *query) trusted() []string {
	out := make([]string, 0, len(q.g.Trust))
	for ns := range q.g.Trust {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// unfiltered checks that the viewer may see an unfiltered listing covering
// the content namespaces nss: problems, orphans and manifests aren't
// filtered, and need namespace-wide read on the catalog and on the content
// namespaces they cover (§B.11.5).
//
// In a subject set's URL space the reader's namespace-wide grants count
// too, those of the namespaces covered only (a public namespace counts as
// read namespace-wide); an answer that needed such a grant is marked
// private (viewer.priv).
func (q *query) unfiltered(nss []string) (int, string) {
	if q.v.wide(nss) {
		return http.StatusOK, ""
	}
	if q.v.wideCat && q.v.wideNS != nil {
		ok, priv := true, q.v.wideGrant[""]
		for _, ns := range nss {
			ok = ok && q.v.wideNS[ns]
			priv = priv || q.v.wideGrant[ns]
		}
		if ok {
			q.v.priv = q.v.priv || priv
			return http.StatusOK, ""
		}
	}
	return http.StatusForbidden, "this listing isn't filtered: it needs namespace-wide read on the catalog and on " + strings.Join(nss, ", ")
}

// orphans lists nodes whose every parent is gone, dangling, not a folder
// or in a cycle (§B.5, §B.7: children of a deleted folder). Unfiltered.
func (q *query) orphans() (any, int, string) {
	if st, msg := q.unfiltered(q.trusted()); st != http.StatusOK {
		return nil, st, msg
	}
	out := []any{}
	for _, name := range q.g.Names() {
		n := q.g.Node(name)
		if len(n.Parents) == 0 || len(q.g.WalkableParents(n)) > 0 {
			continue
		}
		e := q.entry(n)
		e["parents"] = q.parentsJSON(n)
		out = append(out, e)
	}
	return map[string]any{"at": q.at, "orphans": out}, http.StatusOK, ""
}

// problems reports cycles, dangling items, dangling parents and nodes
// deeper than MaxDepth (§B.3, §B.5). Unfiltered.
func (q *query) problems() (any, int, string) {
	if st, msg := q.unfiltered(q.trusted()); st != http.StatusOK {
		return nil, st, msg
	}
	g := q.g
	cycles := []any{}
	for _, scc := range g.Cycles() {
		arr := []any{}
		for _, name := range scc {
			q.tags.node(g, name)
			arr = append(arr, g.Href(name))
		}
		if len(arr) > 0 {
			cycles = append(cycles, arr)
		}
	}
	items, parents, deep := []any{}, []any{}, []any{}
	for _, name := range g.Names() {
		n := g.Node(name)
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
// placement and every path to a root. An item not in the catalog, or
// whose placement is hidden from the reader, is 404 with one message, as
// a parameter naming a node not in the catalog is (§B.5, §B.11.5).
func (q *query) where() (any, int, string) {
	ref := q.vals.Get("item")
	ns, name, ok := ParseHref(ref)
	if !ok || ns == q.g.Catalog {
		return nil, http.StatusBadRequest, "item must be /r/{ns}/{name} of a content namespace"
	}
	pl := ns + "." + name
	q.tags.node(q.g, pl)
	n := q.g.Node(pl)
	if n == nil || !q.v.node(q.g, n) {
		return nil, http.StatusNotFound, noSuchNode
	}
	body := map[string]any{"at": q.at, "item": ref, "placement": q.entry(n)}
	ps, incomplete, deep, trunc := q.paths(n)
	body["paths"] = q.pathJSON(ps)
	if incomplete > 0 {
		body["incomplete"] = incomplete
	}
	if deep > 0 {
		body["tooDeep"] = deep
	}
	if trunc {
		body["truncated"] = true
	}
	return body, http.StatusOK, ""
}

// manifest generates a manifest (§B.4) for a folder's subtree as of the
// checkpoint: the folder's pinned revision and one pinned entry per item
// and path. The client creates it as an ordinary resource. Unfiltered: it
// needs namespace-wide read on the catalog and on the content namespaces
// of the items it pins.
func (q *query) manifest() (any, int, string) {
	if st, msg := q.unfiltered(nil); st != http.StatusOK {
		return nil, st, msg
	}
	n, st, msg := q.node("of")
	if n == nil {
		return nil, st, msg
	}
	if n.Kind != KindFolder || n.Head == "" {
		return nil, http.StatusBadRequest, "of must be a folder"
	}
	entries := []any{}
	covers := map[string]bool{}
	tooLarge := false
	var walk func(x *Node, path []string, depth int)
	walk = func(x *Node, path []string, depth int) {
		if depth > MaxDepth || tooLarge {
			return
		}
		for _, c := range q.g.Children(x.Name) {
			if !c.Node.Live() {
				continue
			}
			if c.Node.Kind == KindFolder {
				if slicesContains(path, c.Node.Name) {
					continue
				}
				q.tags.node(q.g, c.Node.Name)
				walk(c.Node, append(append([]string(nil), path...), c.Node.Name), depth+1)
				continue
			}
			if c.Node.ItemHead == "" {
				continue
			}
			covers[c.Node.ItemNS] = true
			if len(entries) >= maxManifest {
				tooLarge = true
				return
			}
			q.tags.node(q.g, c.Node.Name)
			p := make([]any, len(path))
			for i, s := range path {
				p[i] = s
			}
			e := map[string]any{"href": q.g.ItemHref(c.Node) + "/rev/" + c.Node.ItemHead, "path": p}
			if c.HasOrder {
				e["order"] = c.Order
			}
			entries = append(entries, e)
		}
	}
	walk(n, []string{n.Name}, 0)
	nss := make([]string, 0, len(covers))
	for ns := range covers {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	if st, msg := q.unfiltered(nss); st != http.StatusOK {
		return nil, st, msg
	}
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
