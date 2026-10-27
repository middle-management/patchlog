package tree

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/kept"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
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
	// keptChildren bounds the children of the pages a children listing
	// computes and keeps after the one asked for (query.children).
	keptChildren = 10 * maxLimit
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
	// anon marks the public URL space, /{catalog}/at/{at}/…: every
	// namespace in the listings' combined checkpoint is public
	// (publicViewer), and any grant is ignored.
	anon bool
	// byGrant marks a viewer of the grant in Authorization: a redirect it
	// decides is kept by no cache (§B.11.5). cookie marks one of the
	// service's own edge grants (edgeViewer).
	byGrant, cookie bool
	gs              string
	// catPublic says the catalog is public: its listings are never sealed
	// whole (sealsWhole, §E.2.6).
	catPublic  bool
	catAll     bool
	contentAll map[string]bool
	vis        Visibility
	// exp, if set, is the earliest expiry of the grants an unfiltered
	// listing was admitted with: it isn't kept past it (§B.11.5).
	exp time.Time
	// In a subject set's URL space (RoleView), the namespace-wide reads
	// the reader has besides: wideCat for the catalog, wideNS per content
	// namespace (public ones included, §B.11.5), and wideExp the earliest
	// expiry of the grants behind them. They are unrestricted reads
	// (§2.1), judged on this request. problems, orphans and manifests
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

// readsCatalog reports whether the reader reads the catalog unrestricted
// (§2.1), as everyone reads a public one: only such a reader learns which
// namespace a service that is behind waits for (§B.5).
func (v *viewer) readsCatalog() bool { return v.catAll || v.wideCat }

// sealsWhole reports whether a listing of a sealed or e2e catalog is sealed
// whole for the viewer, as one JWE under the catalog's epoch key: only
// where the catalog isn't public and every reader its URL admits reads it
// whole, which is g/all (§E.2.6, §B.11.5). Anywhere else, the public URL
// space and a subject set's, each entry is sealed under its own K_r.
func (v *viewer) sealsWhole() bool { return !v.catPublic && v.gs == AllSubjects }

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
	return v.catAll || (v.vis != nil && v.vis.Node(g, n))
}

func (v *viewer) item(g *Graph, n *Node) bool {
	if n.ItemNS == "" || n.State != StateLive {
		return false
	}
	return v.contentAll[n.ItemNS] || (v.vis != nil && v.vis.Item(g, n))
}

// Bearer returns the request's bearer token.
func Bearer(r *http.Request) string { return svcedge.Bearer(r) }

// viewer resolves the reader of a listing at a URL whose subject set is
// want ("" for none) (§B.10: services that list content enforce read
// permissions for every node and item they list; §B.11.5):
//
//   - while the catalog and every namespace in the listings' combined
//     checkpoint are public, everyone reads unfiltered listings in the
//     public URL space, /{catalog}/at/{at}/…, any grant ignored, as on the
//     core's public reads (publicViewer);
//   - otherwise a GET or HEAD without Authorization that carries an edge
//     grant the service minted, covering its path, is read as that
//     grant's subject set (edgeViewer);
//   - and otherwise the grant in Authorization decides (grantViewer),
//     and a request with neither is 401: there is no anonymous filtered
//     mode.
func (s *Service) viewer(ctx context.Context, r *http.Request, want string) (*viewer, error) {
	if v, err := s.publicViewer(ctx); err != nil || v != nil {
		return v, err
	}
	if cl := s.edgeClaims(r); cl != nil {
		return s.edgeViewer(ctx, cl)
	}
	return s.grantViewer(ctx, Bearer(r), want, false)
}

// edgeClaims is the edge grant the service minted that a GET or HEAD
// without Authorization carries, covering its path, if any.
func (s *Service) edgeClaims(r *http.Request) *edge.Claims {
	if s.opt.EdgeGrants == nil || r.Header.Get("Authorization") != "" {
		return nil
	}
	return s.opt.EdgeGrants.FromRequest(r, s.opt.Now())
}

// publicViewer is the viewer of every reader while the catalog and every
// content namespace in the listings' combined checkpoint (§B.5) are
// public: those listings are served unfiltered at /{catalog}/at/{at}/…,
// to everyone, grant or not, while they stay public (§B.11.5). It is nil
// while any isn't, and a namespace whose document can't be read counts as
// not public. A purged namespace counts as public, every reader reading
// it whole (trustList); a trusted one the service holds no checkpoint of,
// since it can't follow it (§B.5), isn't in the checkpoint and shows
// nothing in listings.
func (s *Service) publicViewer(ctx context.Context) (*viewer, error) {
	cfg, err := s.checker.Config(ctx, s.actual(s.opt.Catalog))
	if err != nil || cfg.Read != "public" {
		return nil, err
	}
	trust, gone := s.trustList()
	listed := s.listed()
	v := &viewer{anon: true, catPublic: true, catAll: true, contentAll: map[string]bool{}}
	for _, ns := range trust {
		if gone[ns] {
			v.contentAll[ns] = true
			continue
		}
		if c, err := s.checker.Config(ctx, s.actual(ns)); err == nil && c.Read == "public" {
			v.contentAll[ns] = true
		} else if listed[ns] {
			return nil, nil
		}
	}
	return v, nil
}

// listed reports, for each content namespace the catalog trusts, whether
// the service holds a checkpoint of it, which puts it in the listings'
// combined checkpoint (§B.5, CombinedAt). One it can't follow (refused,
// absent, without keys it can have) has none, and shows nothing in
// listings: its placements dangle.
func (s *Service) listed() map[string]bool {
	listed := map[string]bool{}
	s.View(func(g *Graph, cur map[string]string) {
		for ns := range g.Trust {
			listed[ns] = cur[ns] != ""
		}
	})
	return listed
}

// grantViewer is the viewer of a reader presenting token ("" for none)
// where the listings aren't all public (publicViewer), at a URL whose
// subject set is want ("" for none, as for the exchange):
//
//   - without a grant it is 401: a listing that isn't all public needs
//     /g/{gs}, and a grant or a cookie the service verifies (§B.11.5);
//   - a reader whose grant would be issued a namespace-wide edge grant
//     (§C.5.2, grantcheck.NamespaceWide) on every namespace in the
//     combined checkpoint that isn't public, the catalog included, those
//     purged (trustList) aside, reads unfiltered listings under /g/all/,
//     shared by every such reader and kept no longer than the earliest of
//     those grants (§B.11.5), unless want names another subject set. A
//     public catalog needs no grant: one that doesn't verify for it still
//     qualifies through the content namespaces alone, drawing from the
//     exchangeRate bucket of its principal there. For an edge grant
//     (forCookie), which covers every later at, every namespace the
//     catalog trusts counts, those the service doesn't follow too: a
//     g/all cookie is refused at an at including one trusted since its
//     issue (trustedSince), and the service knows when each became
//     trusted, not when it came into the checkpoint;
//   - with a RoleView (a catalog service), any other reader whose grant
//     verifies for the catalog reads the listings of its subject set
//     under /g/{gs}/, filtered by what its roles make visible (§B.11.5),
//     and so does a reader of g/all at its subject set's URLs. One whose
//     grant doesn't is refused as the catalog refuses it. Unrestricted
//     reads (§2.1) of namespaces add problems, orphans and manifests that
//     cover only those (query.unfiltered);
//   - a tree service without §B.11 (no RoleView) serves only g/all, and
//     any other reader is 403 (§B.11.5).
//
// A request at a want other than the viewer's gs is 403 (serve).
func (s *Service) grantViewer(ctx context.Context, token, want string, forCookie bool) (*viewer, error) {
	// In a release preview every check is on the branch read in place of
	// a namespace: a viewer sees only branches it can read (§B.5).
	cat := s.actual(s.opt.Catalog)
	cfg, err := s.checker.Config(ctx, cat)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, &grant.AuthError{Status: 401, Msg: "missing grant"}
	}
	catPublic := cfg.Read == "public"
	trust, gone := s.trustList()
	listed := s.listed()
	// The grant verified for the catalog, nil where a public catalog
	// refuses it (catErr): g/all needs none there (§B.11.5). A grant over
	// grantSize or rulesPerGrant is 413 wherever it is presented, before
	// any ns check (§C.8).
	vg, catErr := s.checker.Verify(ctx, cat, token)
	var le *grantcheck.LimitError
	var ae *grant.AuthError
	switch {
	case catErr == nil:
	case catPublic && !errors.As(catErr, &le) && errors.As(catErr, &ae):
		vg = nil
	default:
		return nil, catErr
	}
	var exp time.Time
	v := &viewer{byGrant: true, catPublic: catPublic, contentAll: map[string]bool{}}
	if vg != nil {
		exp = grantExp(vg, exp)
		v.bucket, v.idExp = vg.Principal.ID+"\x00"+vg.Key.Kid, exp
	}
	// What the grant reads namespace-wide, "" the catalog, a public or
	// purged namespace counting as read so by everyone: unrestricted
	// (§2.1), as problems, orphans and manifests need, judged on this
	// request; and as a namespace-wide edge grant would be issued
	// (§C.5.2), as g/all needs, since its listings serve every such
	// reader (§B.11.5).
	public := map[string]bool{"": catPublic}
	unres := map[string]bool{"": catPublic || (vg != nil && s.checker.ReadsUnrestricted(vg))}
	wide := map[string]bool{}
	all := catPublic || (vg != nil && s.checker.NamespaceWide(vg))
	for _, ns := range trust {
		if gone[ns] {
			public[ns], unres[ns], wide[ns] = true, true, true
			continue
		}
		real := s.actual(ns)
		c, err := s.checker.Config(ctx, real)
		switch {
		case err != nil:
		case c.Read == "public":
			public[ns], unres[ns], wide[ns] = true, true, true
		default:
			if cv, err := s.checker.Verify(ctx, real, token); err == nil {
				unres[ns], wide[ns] = s.checker.ReadsUnrestricted(cv), s.checker.NamespaceWide(cv)
				exp = grantExp(cv, exp)
				if v.bucket == "" {
					// Its principal and kid there, as the core keys write
					// buckets (§C.5, §6.6).
					v.bucket = cv.Principal.ID + "\x00" + cv.Key.Kid
				}
			}
		}
		if forCookie || listed[ns] {
			all = all && wide[ns]
		}
	}
	if v.bucket == "" {
		// Verified for no namespace at all.
		return nil, catErr
	}
	if all && (want == "" || want == AllSubjects || s.opt.RoleView == nil) {
		// Unfiltered (§B.11.5).
		v.gs, v.catAll, v.exp = AllSubjects, true, exp
		for _, ns := range trust {
			v.contentAll[ns] = wide[ns]
		}
		return v, nil
	}
	if s.opt.RoleView == nil {
		return nil, &grant.AuthError{Status: 403, Msg: "this tree service serves only unfiltered listings, /" + s.opt.Catalog +
			"/g/all/… (§B.11.5): they need a grant that would be issued namespace-wide edge grants on every namespace in them that isn't public"}
	}
	if vg == nil {
		// A subject set is resolved from the grant verified for the
		// catalog (RoleView).
		return nil, catErr
	}
	// Filtered by the subject set alone (§B.11.5).
	v.catAll = catPublic
	v.wideCat, v.wideNS, v.wideGrant, v.wideExp = unres[""], map[string]bool{}, map[string]bool{}, exp
	v.wideGrant[""] = unres[""] && !catPublic
	for _, ns := range trust {
		v.contentAll[ns] = public[ns]
		v.wideNS[ns] = unres[ns]
		v.wideGrant[ns] = unres[ns] && !public[ns]
	}
	v.subjects, v.vis, err = s.opt.RoleView.Resolve(ctx, vg)
	if err != nil {
		return nil, err
	}
	v.gs = grantcheck.SubjectSetID(v.subjects)
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

var ops = map[string]bool{
	"children": true, "lookup": true, "ancestors": true, "subtree": true, "roots": true,
	"orphans": true, "problems": true, "where": true, "manifest": true,
}

// Handler returns the query API (§B.5, §B.11.5):
//
//	GET /{catalog}/{op}?…                   302 → /{catalog}[/g/{gs}]/at/{at}/{op}?…  (head pointer)
//	GET /{catalog}/g/{gs}/{op}?…            302 → /{catalog}/g/{gs}/at/{at}/{op}?…   (head pointer)
//	GET /{catalog}/at/{at}/{op}?…            200, everyone, while all is public       (immutable)
//	GET /{catalog}/g/{gs}/at/{at}/{op}?…     200, readers of that subject set or all  (§B.11.5)
//
// at is the combined checkpoint (CombinedAt). The subject set comes before
// it, so one edge grant for the prefix /{catalog}/g/{gs} covers every
// checkpoint and the head pointer under it (§B.11.5); the form before
// v0.51, /{catalog}/at/{at}/g/{gs}/{op}?…, is moved permanently (301) to
// it. op is one of
// children?of=&after=&limit=, lookup?path=, ancestors?of=,
// subtree?of=&depth=, roots, orphans, problems, where?item=, manifest?of=.
//
// URL spaces (§B.11.5, viewer). While the catalog and every namespace in
// the combined checkpoint are public, listings are served unfiltered in
// the public URL space to everyone, any grant ignored, and a URL under
// /g/{gs} redirects there. Otherwise every listing is a subject set's:
// a request without a grant or an edge grant the service verifies is
// 401; a grant in Authorization reads only at its own gs, or at all where
// it qualifies (grantViewer), and is 403 at any other, never redirected;
// a URL without /g/{gs} redirects into the grant's, private, no-store. A
// tree service without §B.11 (no RoleView) serves only g/all.
//
// children, lookup, ancestors, subtree, roots and where show the nodes the
// reader may see, and only paths through visible folders, with no trace of hidden
// nodes (no counts); limits, cut markers and pagination count visible
// nodes only (§B.11.5). orphans, problems and manifest aren't filtered:
// they answer 403 unless the reader reads the catalog and the content
// namespaces they cover unrestricted (§2.1), and under an edge grant for
// a subject set other than all. Readers whose grants would be issued
// namespace-wide edge grants on every namespace in the combined
// checkpoint that isn't public are served unfiltered listings under
// /g/all/ (§B.11.5, viewer).
//
// Every listing computed, including the one a redirect names, is kept for
// a while (package kept), under its URL and what the reader reads whole
// (viewer.shape), and answered 200 at its at however far the checkpoint
// moves meanwhile, so one redirect suffices (§A.4 "Bounded redirects",
// §B.5 "only if it is current or that exact result was stored"); any other
// at is redirected to the current one. A children page is kept with the
// pages after it, so a tool following next pages through the folder as
// it is at that at (query.children). A purge drops the kept listings
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
// kid the epoch the item's head is served under (§E.2.6 values of another
// resource; FileMeta.Epoch), pl { ns, name, view } of the item, so
// readers given K_r by /read-grants open it, whatever the catalog's level;
// for an e2e item it is { "absent": "e2e" }, and { "absent": "pending" }
// for a head not read for it yet (§H.3). A listing holding any sealed file is
// stored and served unchanged like a sealed catalog's. While a sealed
// namespace's key can't be had for the moment, listings are 503, no-store
// (fileSealing). The "file": { "sealed" } form nests inside a sealed
// catalog's whole-listing JWE below (§E.2.6 values of another resource);
// its plaintext is { "file": value }, as F-E5's default keeps it.
//
// A sealed or e2e catalog (§E.2.5, §E.2.6; package derived). Titles and
// born are the only values a listing takes from the catalog's content
// (names, heads, hrefs, structure, order and cursors, which are positions,
// stay in the clear, and
// content namespaces contribute nothing else but file metadata, sealed on
// its own), so the catalog is the one source of what a listing seals
// whole. Each node's values are sealed under the epoch its head is
// served under (Node.Epoch; the current one where that isn't known),
// title and born alike. A g/all listing of a catalog that isn't public,
// which every reader its URL admits reads whole, whose nodes' values all
// come from one epoch, is sealed as one JWE under that epoch's key,
// Content-Type application/jose, pl { ns, view } where view is the
// listing's request target (/{catalog}/g/all/at/{at}/{op}?{query}, the
// canonical form). Any other (a public catalog's, a subject set's, whose
// readers see nodes only through roles, or one mixing epochs) is JSON in
// which every node with a title or born carries "sealed": JWE of {
// title?, born? } under that catalog resource's K_r of its epoch, pl {
// ns, name, view }, in their place (§E.2.6, viewer.sealsWhole). Sealed listings are produced once per
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
	case len(segs) == 4 && segs[0] == cat && segs[1] == "g":
		// The head pointer under the subject set's prefix, which its edge
		// grant covers (§B.11.5).
		gs, op = segs[2], segs[3]
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
	case gs != "" && isAt:
		telemetry.SetRoute(r, "/{catalog}/g/{gs}/at/{at}/"+op)
	case gs != "":
		telemetry.SetRoute(r, "/{catalog}/g/{gs}/"+op)
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

// WriteAuthError writes a grant failure (401/403) or an upstream error. A
// grant over grantSize or rulesPerGrant is 413, code limit, naming the
// limit, as the origin answers it (§C.8): services verify as the origin
// does (§C.6).
func WriteAuthError(w http.ResponseWriter, err error, logf func(string, ...any)) {
	var le *grantcheck.LimitError
	if errors.As(err, &le) {
		svcedge.Limit(le.Limit, le.Measured, le.Max).Write(w)
		return
	}
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
	// A catalog whose keys the service lacks as configured is one it
	// doesn't serve: 404 alike, before the read check, as the index
	// answers a namespace it doesn't follow (§A.4, §E.2.6). One whose keys
	// it can't fetch for now is behind (below).
	skipped, lacksKeys := s.keys.Skip(cat)
	if lacksKeys {
		WriteError(w, http.StatusNotFound, "not_found", "the tree service does not serve this catalog")
		return
	}
	v, err := s.viewer(ctx, r, gs)
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
	if !v.anon && gs != "" && gs != v.gs {
		// A grant reads only at its own subject set, or at all where it
		// qualifies (grantViewer), and is 403 at any other, never
		// redirected (§B.11.5). An edge grant covers its own prefix only.
		msg := "the grant reads only at /" + cat + "/g/" + v.gs + "/… (§B.11.5)"
		if s.opt.RoleView == nil {
			msg = "this tree service serves only unfiltered listings, /" + cat + "/g/all/… (§B.11.5)"
		}
		w.Header().Set("Cache-Control", "no-store")
		WriteError(w, http.StatusForbidden, "forbidden", msg)
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
		switch {
		case v.anon && gs == "":
			w.Header().Set("Cache-Control", ccHeadPointer)
			w.Header().Set("Cache-Tag", "ns:"+cat)
		case v.byGrant:
			// Decided by the grant in Authorization: no cache keeps it,
			// the browser's included (§B.11.5).
			w.Header().Set("Cache-Control", "private, no-store")
			edge.NoStore(w.Header())
			w.Header().Add("Vary", "Authorization")
		default:
			// Under a subject set's edge grant, or out of a subject set's
			// URL space into the public one: no shared cache keeps it,
			// since the edge serves what it holds under /g/{gs} to every
			// reader with that subject set's edge grant (§B.11.5).
			w.Header().Set("Cache-Control", ccPrivatePtr)
			edge.NoStore(w.Header())
			w.Header().Add("Vary", "Authorization")
		}
	}
	if a := s.awaitMins(ctx, vals["min"], Bearer(r)); a.status != 0 {
		a.write(w)
		return
	}
	waits, retry := s.behind(), "1"
	if skipped != "" {
		// Keys it can't fetch yet are a view it hasn't caught up with
		// (§12.1 behind, §E.2.6).
		waits, retry = cat, "60"
	}
	if waits != "" {
		// Once the reader's grant verifies (§B.5), with the namespace
		// waited for only to a reader with unrestricted read of the
		// catalog.
		body := map[string]any{"code": "behind", "message": "the tree service hasn't caught up with what its listings show yet"}
		if v.readsCatalog() {
			body["ns"] = waits
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", retry)
		WriteJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	// canon is the canonical URL of this listing at an at (§A.5): what
	// redirects name, what listings are kept and stored under (with the
	// reader's shape, keyOf), and in a sealed or e2e catalog the view a
	// listing is bound to (§E.2.6). Only it is answered 200: another form
	// of it, or one with min, is redirected.
	canon := func(at string) string { return target(at) + derived.CanonicalQuery(vals, "min") }
	keyOf := func(at string) string { return listingKey(canon(at), v) }
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
	own := isAt && gs == v.gs
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
	case errors.Is(err, errCatalogKeys):
		s.opt.Logf("tree: %v", err)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		WriteError(w, http.StatusServiceUnavailable, "behind", "the service cannot obtain the key of an epoch a catalog node is served under yet")
	case err != nil:
		s.opt.Logf("tree: sealing a listing: %v", err)
		WriteError(w, http.StatusInternalServerError, "internal", "sealing failed")
	case l.status != http.StatusOK:
		code := l.code
		if code == "" {
			code = codeFor(l.status)
		}
		WriteError(w, l.status, code, l.msg)
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
// msg, and code where it isn't the status's, codeFor).
type computed struct {
	st     derived.Stored
	at     string
	status int
	code   string
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
	if op == "lookup" && (!fs.on || info.Protected()) {
		// Titles to look up by are a file tree's, and in the clear only
		// outside sealed and e2e catalogs (§B.5, §H.3).
		return &computed{at: s.At(), status: http.StatusNotFound, code: "not_offered",
			msg: "lookup is offered only in a file tree (catalog.files) that is neither sealed nor end-to-end"}, nil
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
	// Each node's values are sealed under the epoch its head is served
	// under (Node.Epoch; §E.2.6), the current one where that isn't known:
	// the keys of every epoch a node's head is served under, read before
	// the graph is.
	keys, err := s.catalogKeys(ctx, info, key)
	if err != nil {
		return nil, err
	}
	keyAt := func(epoch int) (derived.Key, error) {
		if epoch <= 0 {
			epoch = key.Epoch
		}
		k, ok := keys[epoch]
		if !ok {
			// A head read since the keys were: asked again.
			return k, fmt.Errorf("%w %s#%d: not read yet", errCatalogKeys, cat, epoch)
		}
		return k, nil
	}
	epochOf := func(g *Graph, name string) int {
		if n := g.Node(name); n != nil && n.Epoch > 0 {
			return n.Epoch
		}
		return key.Epoch
	}
	// Sealed whole only where every reader the URL admits reads the
	// catalog whole and it isn't public, and every value derives from
	// revisions served under one epoch, else per entry (§E.2.6).
	perEntry := info.Protected() && !v.sealsWhole()
	whole := key.Epoch
	var cps map[string]string
	var more []keptPage
	s.View(func(g *Graph, curMap map[string]string) {
		l.at, nss = CombinedAt(g, curMap)
		cps = checkpointsOf(g, curMap)
		view = derived.View{NS: cat, Target: canon(l.at)}
		run := func() map[int]bool {
			more, serr = nil, nil
			epochs := map[int]bool{}
			q := &query{s: s, g: g, cur: curMap, v: v, vals: vals, tags: tagSet{}, at: l.at, files: fs, view: view, serr: &serr}
			switch {
			case perEntry:
				q.sealValues = func(name string, vals map[string]any) string {
					k, err := keyAt(epochOf(g, name))
					if err != nil {
						if serr == nil {
							serr = err
						}
						return ""
					}
					jwe, err := derived.SealItem(k, q.view, name, vals)
					if err != nil && serr == nil {
						serr = err
					}
					return jwe
				}
			case info.Protected():
				q.noteValues = func(name string) { epochs[epochOf(g, name)] = true }
			}
			if op == "children" && keep {
				// The following pages are kept with this one, each at its
				// own URL: the same at with the query their next gives.
				path, _, _ := strings.Cut(view.Target, "?")
				q.pages = &more
				q.pageView = func(query string) derived.View { return derived.View{NS: cat, Target: path + query} }
			}
			body, l.status, l.msg = q.run(op)
			tags = q.tags
			return epochs
		}
		epochs := run()
		if l.status == http.StatusOK && info.Protected() && !perEntry && len(epochs) > 1 {
			// Values of several epochs: per entry after all.
			perEntry = true
			run()
		}
		for e := range epochs {
			whole = e
		}
	})
	if l.status != http.StatusOK {
		return l, nil
	}
	// stored is a computed page as it is served: sealed whole, or JSON.
	stored := func(view derived.View, body any, tags tagSet) (derived.Stored, error) {
		st := derived.Stored{JSON: true, Tags: tags.header(cat, nss)}
		var err error
		if info.Protected() && !perEntry {
			var jwe string
			var k derived.Key
			if k, err = keyAt(whole); err != nil {
				return st, err
			}
			jwe, err = derived.SealView(k, view, body)
			st.Body, st.JSON = []byte(jwe), false
		} else {
			st.Body, err = derived.Marshal(body)
		}
		return st, err
	}
	if serr != nil {
		return nil, serr
	}
	if l.st, serr = stored(view, body, tags); serr != nil {
		return nil, serr
	}
	if !keep {
		// Neither stored nor kept: whether it may be served depends on
		// the reader.
		return l, nil
	}
	type page struct {
		key string
		st  derived.Stored
	}
	pages := []page{{keyOf(l.at), l.st}}
	for _, p := range more {
		st, err := stored(p.view, p.body, p.tags)
		if err != nil {
			// Computed when asked for, as without it.
			s.opt.Logf("tree: sealing a following page: %v", err)
			break
		}
		pages = append(pages, page{listingKey(p.view.Target, v), st})
	}
	if sealed {
		for i := range pages {
			var err error
			if pages[i].st, err = s.sealed.Put(ctx, pages[i].key, cat, l.at, pages[i].st); err != nil {
				s.opt.Logf("tree: storing a sealed listing: %v", err)
			}
		}
		if cur := s.At(); cur != l.at {
			// An apply (maybe a purge) committed meanwhile: don't keep a
			// listing it may have retired.
			if err := s.sealed.Retire(ctx, s.db, cat, cur); err != nil {
				s.opt.Logf("tree: retiring sealed listings: %v", err)
			}
		}
	}
	for i := range pages {
		pages[i].st, _ = s.kept.Put(pages[i].key, cat, gen, sealed, pages[i].st)
	}
	l.st = pages[0].st
	s.recordAt(l.at, cps)
	return l, nil
}

// dropWholeViews drops the listings stored sealed whole (derived.Cache)
// anywhere but under /{catalog}/g/all/, and there too while the catalog
// is public. Releases before v0.73 sealed a listing whole for every
// reader of the whole catalog, in the public URL space, a subject set's
// and g/all of a public catalog too, and a stored listing is served
// unchanged under the same URL and shape; now only g/all's of a catalog
// that isn't public are (viewer.sealsWhole, §E.2.6). The catalog's
// document as of its checkpoint (meta "config"), the one listings are
// served at, says whether it is; without one it counts as public, which
// costs only sealing them again. Called at Open, before the cache is
// used.
func (s *Service) dropWholeViews(ctx context.Context) error {
	var doc string
	if err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'config'`).Scan(&doc); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	m, _ := parseJSON(doc).(map[string]any)
	public := m == nil || m["read"] == "public"
	all := "/" + s.opt.Catalog + "/g/" + AllSubjects + "/"
	return s.sealed.Drop(ctx, func(view, _ string, json bool) bool {
		return !json && (public || !strings.HasPrefix(view, all))
	})
}

// errCatalogKeys is a key of an epoch a catalog node's head is served
// under, which seals its entries (§E.2.6), that the service can't obtain
// for now: the listing is 503 behind, as for the catalog's current key.
var errCatalogKeys = errors.New("the key of an epoch a catalog node is served under")

// catalogKeys are the keys that seal the entries of a sealed or e2e
// catalog's listings, by epoch: the current one's (key) and those of
// every older epoch a node's head is served under (Node.Epoch), read
// before the graph is, never under its lock. None for a catalog that is
// neither.
func (s *Service) catalogKeys(ctx context.Context, info derived.Info, key derived.Key) (map[int]derived.Key, error) {
	keys := map[int]derived.Key{key.Epoch: key}
	if !info.Protected() {
		return keys, nil
	}
	used := map[int]bool{}
	s.mu.RLock()
	for _, n := range s.g.explicit {
		if n.Epoch > 0 && n.Epoch != key.Epoch {
			used[n.Epoch] = true
		}
	}
	s.mu.RUnlock()
	for e := range used {
		k, err := s.keys.KeyAt(ctx, key.NS, e)
		if err != nil {
			return nil, fmt.Errorf("%w %s#%d: %w", errCatalogKeys, key.NS, e, err)
		}
		keys[e] = k
	}
	return keys, nil
}

// listingKey is what a listing at url is stored and kept under for reader
// v: the URL and the reader's shape, since a namespace that turns private
// moves no URL (viewer.shape).
func listingKey(url string, v *viewer) string { return url + "\n" + v.shape() }

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
	// cur is each namespace's checkpoint, as View gives it: those with
	// one are in the combined checkpoint (CombinedAt).
	cur map[string]string
	// sealValues, if set, seals the values an entry takes from the
	// catalog's content (title, born) for per-entry sealing (§E.2.6): the
	// entry carries "sealed" in their place. noteValues, if set, is told
	// of each entry whose values are given in the clear, for a listing
	// sealed whole (the epochs they derive from).
	sealValues func(name string, vals map[string]any) string
	noteValues func(name string)
	// files says how placements carry file metadata in a file tree
	// (§H.3), sealed under view; serr records a sealing failure.
	files *fileSealing
	view  derived.View
	serr  *error
	// pages, where set, collects the pages of a children listing after
	// the one asked for (children), each sealed under the view pageView
	// gives for its query, for listing to keep with it.
	pages    *[]keptPage
	pageView func(query string) derived.View
}

// values sets the values an entry of node name takes from the catalog's
// content (title, born), in the clear or, for per-entry sealing, as one
// "sealed" JWE of them (§E.2.6).
func (q *query) values(m map[string]any, name string, vals map[string]any) {
	switch {
	case len(vals) == 0:
	case q.sealValues != nil:
		m["sealed"] = q.sealValues(name, vals)
	default:
		if q.noteValues != nil {
			q.noteValues(name)
		}
		for k, v := range vals {
			m[k] = v
		}
	}
}

// title sets a node's title on an entry, in the clear or sealed.
func (q *query) title(m map[string]any, n *Node) {
	if n.Title != "" {
		q.values(m, n.Name, map[string]any{"title": n.Title})
	}
}

func (q *query) run(op string) (any, int, string) {
	switch op {
	case "children":
		return q.children()
	case "lookup":
		return q.lookup()
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

// entry is a node as listings show it. Its title and born (§B.5) are the
// values it takes from the catalog's content, sealed per entry where the
// listing is (values). An implicit placement's born is its item's, the
// created of the content document's first revision (§B.9): like the
// item's head and title, it is shown only to readers of the item, and
// only for items of namespaces that are neither sealed nor e2e, which the
// service doesn't hold it for (Apply), since §E.2.2 keeps the exact
// created of their revisions in their logs.
func (q *query) entry(n *Node) map[string]any {
	q.tags.node(q.g, n.Name)
	m := map[string]any{"href": q.g.Href(n.Name), "name": n.Name, "kind": "folder"}
	vals := map[string]any{}
	if n.Title != "" {
		vals["title"] = n.Title
	}
	if n.Born != "" && !n.Self {
		vals["born"] = n.Born
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
			if n.Title == "" && n.ItemTitle != "" {
				// The head's title (§B.5), unless the placement has its own.
				vals["title"] = n.ItemTitle
			}
			if n.Self && n.Born != "" {
				vals["born"] = n.Born
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
	q.values(m, n.Name, vals)
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

// limitParam is a children page's limit (§A.4, as /_refs pages): the
// default without one, 400 for one that isn't a positive integer or is
// above maxLimit.
func limitParam(vals url.Values) (int, bool) {
	l := defaultLimit
	if s := vals.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxLimit {
			return 0, false
		}
		l = n
	}
	return l, true
}

// children lists a folder's direct children, ordered (§B.2), with total,
// the number of visible children, and each node's born (entry), paginated
// as /_refs is (§A.4): at most limit, strictly after after, next the query
// of the following page, absent on the last. after is an opaque position
// in the listing (childCursor), never an order key, which in a sealed
// catalog is a value of its content (§E.2.6). A next sent as after, as
// §A.4 has next be the following page's after, continues where it says
// (pagingParams). The cursor of earlier releases, after={order} alone or
// with name= or unordered=1, is still accepted for one release
// (cursorBefore).
//
// The pages after the one asked for are computed with it, at the same
// at, up to keptChildren children, when q.pages is set (listing keeps
// them): a tool that follows next at that at is answered there however
// far the checkpoint moves meanwhile, as long as the pages are kept, so
// the folder it pages through is one folder (§H.3). A position given at
// another at, which a redirect leads to once its own at isn't kept,
// starts the folder again (childCursor.start).
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
		return nil, http.StatusBadRequest, "limit must be an integer from 1 to " + strconv.Itoa(maxLimit)
	}
	kids := q.visibleChildren(n.Name)
	start := 0
	pv := pagingParams(q.vals)
	after, hasAfter := pv["after"]
	hasName, legacy := pv.Has("name"), pv.Has("name") || pv.Has("unordered")
	if hasAfter && !legacy {
		c, ok := parseCursor(after[0])
		switch {
		case ok:
			start = c.start(kids, q.at)
		case looksLikeCursor(after[0]):
			return nil, http.StatusBadRequest, "malformed after: a children listing continues at the query its next gives"
		default:
			legacy = true
		}
	}
	if legacy {
		cur := Child{Node: &Node{Name: pv.Get("name")}}
		if hasAfter {
			cur.Order, cur.HasOrder = after[0], true
		}
		if pv.Get("unordered") == "1" {
			cur.HasOrder = false
		}
		start = len(kids)
		for i, c := range kids {
			if cursorBefore(cur, hasName, c) {
				start = i
				break
			}
		}
	}
	body, end, next := q.childPage(n, kids, start, limit, q.vals)
	if q.pages != nil {
		view, tags := q.view, q.tags
		for from := end; next != nil && end-from < keptChildren; {
			q.view, q.tags = q.pageView(derived.CanonicalQuery(next)), tagSet{}
			q.tags.node(q.g, n.Name)
			var b map[string]any
			b, end, next = q.childPage(n, kids, end, limit, next)
			*q.pages = append(*q.pages, keptPage{view: q.view, body: b, tags: q.tags})
		}
		q.view, q.tags = view, tags
	}
	return body, http.StatusOK, ""
}

// pagingParams are the parameters of vals that say where a children page
// starts: after, name and unordered, or, where after is itself a next
// (a query, "?after=…"), which a client reading §A.4's "next is the after
// of the following page" sends, the ones in it.
func pagingParams(vals url.Values) url.Values {
	if a := vals.Get("after"); strings.HasPrefix(a, "?") {
		if inner, err := url.ParseQuery(a[1:]); err == nil && len(inner["after"]) == 1 {
			return inner
		}
	}
	return vals
}

// keptPage is a page of a children listing computed with the one asked
// for (query.children), with the view of its own URL and its tags.
type keptPage struct {
	view derived.View
	body any
	tags tagSet
}

// childPage is the page of folder n's visible children kids from start,
// with vals its query, the end of the page in kids, and the query of the
// following page (nil on the last).
func (q *query) childPage(n *Node, kids []Child, start, limit int, vals url.Values) (map[string]any, int, url.Values) {
	page := []any{}
	end := min(start+limit, len(kids))
	for _, c := range kids[start:end] {
		e := q.entry(c.Node)
		if c.HasOrder {
			e["order"] = c.Order
		}
		page = append(page, e)
	}
	body := map[string]any{"at": q.at, "of": q.g.Href(n.Name), "children": page, "total": len(kids)}
	if end == len(kids) {
		return body, end, nil
	}
	nv := url.Values{}
	for k, v := range vals {
		nv[k] = v
	}
	for _, k := range []string{"after", "name", "unordered", "min"} {
		nv.Del(k)
	}
	nv.Set("after", childCursor{pos: end, at: q.at, last: kids[end-1].Node.Name}.String())
	body["next"] = derived.CanonicalQuery(nv)
	return body, end, nv
}

// childCursor is the position after a page of children (§A.4, §E.2.6):
// pos, the number of visible children up to the page's end, at, the at of
// the listing, and last, the node name of the page's last child, all in
// the clear like the listing's structure, never an order key.
type childCursor struct {
	pos      int
	at, last string
}

func (c childCursor) String() string { return strconv.Itoa(c.pos) + "~" + c.at + "~" + c.last }

// parseCursor parses a childCursor; ok is false for anything else, such as
// the order key of an earlier release's cursor.
func parseCursor(s string) (c childCursor, ok bool) {
	p, rest, _ := strings.Cut(s, "~")
	at, last, found := strings.Cut(rest, "~")
	if !found || p == "" || len(p) > 9 || p[0] == '0' || !client.ValidResourceName(last) {
		return c, false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return c, false
		}
	}
	if _, err := ids.Parse(at); err != nil {
		return c, false
	}
	c.pos, _ = strconv.Atoi(p)
	c.at, c.last = at, last
	return c, true
}

// looksLikeCursor reports whether s has a childCursor's shape, digits, at
// and a name joined by "~", without being one (a malformed or truncated
// position, 400) rather than an order key of the earlier releases' cursor.
func looksLikeCursor(s string) bool {
	p, rest, found := strings.Cut(s, "~")
	if !found || p == "" || strings.Trim(p, "0123456789") != "" {
		return false
	}
	_, _, found = strings.Cut(rest, "~")
	return found
}

// start is where the page after c starts in kids, the visible children at
// at: at c.pos, where c was given at this at and its last child is there.
// A position given at another at (the redirect from an at whose pages are
// no longer kept) or for another reader says nothing of where that page
// would start now: children moved, deleted or reordered meanwhile, before
// it or after, would be skipped. So the folder starts again, and a tool
// paging it sees some children twice, which is harmless, rather than miss
// one, which a sync tool takes for a delete (§H.3).
func (c childCursor) start(kids []Child, at string) int {
	if c.at == at && c.pos <= len(kids) && kids[c.pos-1].Node.Name == c.last {
		return c.pos
	}
	return 0
}

// cursorBefore reports whether the cursor of an earlier release (an order
// key with a node name, §B.2 order by UTF-8 bytes) sorts before c.
func cursorBefore(cur Child, hasName bool, c Child) bool {
	if cur.HasOrder != c.HasOrder {
		return cur.HasOrder // ordered siblings come first
	}
	if cur.HasOrder && cur.Order != c.Order {
		return cur.Order < c.Order
	}
	if !hasName {
		return false
	}
	return cur.Node.Name < c.Node.Name
}

// lookup answers the node a path of titles, joined with /, names (§B.5):
// from the folder catalog.files.root of a file tree, or, where it is
// hidden from the reader, from the reader's roots (§B.11.5), through
// visible nodes only, as children lists them. Titles compare after NFC and
// Unicode simple case folding (§H.2, files.TitleKey). Only a node's own
// title counts: a name a tool shows in its place, numbered as a duplicate
// or escaped, doesn't resolve, and the tool lists the folder. Where
// siblings share a title the earliest born answers, then the node name. A
// path that doesn't resolve to a visible node is 404, with one message
// whether a node is hidden or missing. It isn't offered outside file
// trees, nor in sealed or e2e catalogs (listing: 404 not_offered).
func (q *query) lookup() (any, int, string) {
	path := q.vals.Get("path")
	if path == "" {
		return nil, http.StatusBadRequest, "path is required"
	}
	var level []*Node
	if root := q.g.Node(q.g.FilesRoot); root != nil && root.Live() && root.Kind == KindFolder && q.v.node(q.g, root) {
		q.tags.node(q.g, root.Name)
		level = q.childNodes(root.Name)
	} else {
		level = q.rootNodes()
	}
	segs := strings.Split(path, "/")
	var n *Node
	for i, seg := range segs {
		if n = titled(level, seg); n == nil {
			return nil, http.StatusNotFound, "no node at that path"
		}
		q.tags.node(q.g, n.Name)
		if i < len(segs)-1 {
			if n.Kind != KindFolder {
				return nil, http.StatusNotFound, "no node at that path"
			}
			level = q.childNodes(n.Name)
		}
	}
	return map[string]any{"at": q.at, "path": path, "node": q.entry(n)}, http.StatusOK, ""
}

// childNodes are the nodes of visibleChildren.
func (q *query) childNodes(parent string) []*Node {
	kids := q.visibleChildren(parent)
	out := make([]*Node, len(kids))
	for i, c := range kids {
		out[i] = c.Node
	}
	return out
}

// titled is the node of nodes whose own title is title, compared as
// siblings' are (§H.2, files.TitleKey): of several, the earliest born,
// then the least node name (§B.5); nil if none.
func titled(nodes []*Node, title string) *Node {
	key := files.TitleKey(title, false)
	var best *Node
	for _, n := range nodes {
		if n.Title == "" || files.TitleKey(n.Title, false) != key {
			continue
		}
		if best == nil || bornBefore(n, best) {
			best = n
		}
	}
	return best
}

// bornBefore orders siblings that share a title (§B.5, §H.2): by born,
// those whose born the service doesn't know last, then by node name.
func bornBefore(a, b *Node) bool {
	ta, ea := time.Parse(time.RFC3339Nano, a.Born)
	tb, eb := time.Parse(time.RFC3339Nano, b.Born)
	switch {
	case (ea == nil) != (eb == nil):
		return ea == nil
	case ea == nil && !ta.Equal(tb):
		return ta.Before(tb)
	}
	return a.Name < b.Name
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

// checkpointed is every content namespace the catalog trusts that is in
// the combined checkpoint, sorted: what problems and orphans cover
// (§B.11.5). One the service can't follow has no checkpoint, and shows
// nothing in listings, as the URL spaces and g/all are judged without it
// (Service.listed).
func (q *query) checkpointed() []string {
	out := make([]string, 0, len(q.g.Trust))
	for ns := range q.g.Trust {
		if q.cur[ns] != "" {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

// unfiltered checks that the viewer may see an unfiltered listing covering
// the content namespaces nss: problems, orphans and manifests aren't
// filtered, and need namespace-wide read on the catalog and on the content
// namespaces they cover (§B.11.5).
//
// In a subject set's URL space the reader's unrestricted reads (§2.1)
// count too, those of the namespaces covered only (a public namespace
// counts as read unrestricted); an answer that needed such a grant is
// marked private (viewer.priv). Under an edge grant for a subject set
// other than all, they are 403 (§B.11.5).
func (q *query) unfiltered(nss []string) (int, string) {
	if q.v.cookie && q.v.gs != AllSubjects {
		// A gs cookie other than all authorises listings of its subject
		// set only (§B.11.5).
		return http.StatusForbidden, "this listing isn't filtered: an edge grant for a subject set doesn't authorise it (§B.11.5)"
	}
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
	if st, msg := q.unfiltered(q.checkpointed()); st != http.StatusOK {
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
	if st, msg := q.unfiltered(q.checkpointed()); st != http.StatusOK {
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
