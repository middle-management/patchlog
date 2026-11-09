package index

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// Cache-Control values (§9).
const (
	ccHeadPointer = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccImmutable   = "public, max-age=86400, s-maxage=31536000, immutable"
	ccPrivatePtr  = "private, no-store"
	ccPrivateImm  = "private, max-age=300"
	cdnImmutable  = "max-age=31536000"
)

var validNS = client.ValidNSName

// minElsewhere is the 400 for a min naming a namespace the index doesn't
// follow, or one the reader can't see (§A.5): one message for both, so it
// doesn't tell which private namespaces exist and are indexed.
const minElsewhere = "min names a namespace the service does not follow or the reader can't see"

// minOther is the 400 for a min naming another namespace on a query of
// one (§A.5): that query's checkpoint covers its namespace alone.
const minOther = "min names a namespace other than the one queried"

// Handler returns the query API (§A.4):
//
//	GET /{ns}?…                   302 → /{ns}/at/{checkpoint}?…            (head pointer)
//	GET /{ns}/at/{ns_id}?…        200 { at, ns, hits, next?, counts? }       (immutable,
//	                              tagged idx:{ns} and r:{ns}/{name} per hit)
//	                              302 → current checkpoint if ns_id is neither
//	                              current nor kept for this query
//	GET /{ns}/g/{gs}/at/{ns_id}?… private namespaces: as above, keyed by the
//	                              reader's subject set gs (§A.4, §B.11.5), the
//	                              subject set before the checkpoint
//	GET /{ns}/g/{gs}?…            the head pointer under the subject set's
//	                              prefix, which its edge grants cover
//	POST, DELETE /edge-grants     the service's own edge grants (edgegrants.go)
//
// The forms before v0.51, /g/{gs}/{ns}?… and /g/{gs}/{ns}/at/{ns_id}?…,
// are moved permanently (301) to /{ns}?… and /{ns}/g/{gs}/at/{ns_id}?….
//
// The index holds current state only (§A.3), so results are computed at the
// current checkpoint, and a redirect to it computes the result there. Every
// result computed is kept for a while (package kept), and an older ns_id is
// answered 200 while its result for the query is kept; otherwise it is one
// "the service no longer keeps results for" and is redirected
// (head-pointer class) to the current one (§A.4). A result served at an
// ns_id never changes while it is served, and any purge in its namespace
// removes it from caches, and from the kept results, through its idx:{ns}
// tag (§A.1).
//
// Redirects name the query in its canonical form (§A.5,
// derived.CanonicalQuery), and an at URL is answered 200 only in that form
// and without min: one in another form is redirected to it. A request with
// ?min= is always redirected (§A.5): once every min is reached, an at URL
// whose kept result already includes every min to itself without min,
// anything else to the current checkpoint.
//
// Private namespaces need Authorization: Bearer <grant>, which reads only
// under its own gs: an at URL of another gs is 403; the head pointer and
// an at URL without /g/{gs} are redirected into the reader's (with min, by
// the redirect above), private, no-store (§A.4, §B.11.5). A request
// without Authorization may carry instead an edge grant the service
// minted for the gs of its URL (Options.EdgeGrants), and is read as that
// subject set; one with neither is 401.
//
// Where §B.11.9 covers a namespace (filtered.go), a partial reader's
// marker is reads:{ns}:g:{gs}, gs the origin's subject set; its hits are
// those visible to it (§B.11.9 Visible); and at is the combined
// checkpoint of every namespace visibility reads there, which its answers
// list as namespaces and min may name ({ns}:{ns_id}). Its pages are filled
// to limit, as every reader's are.
//
// Sealed and e2e namespaces (§E.2.5, §E.2.6; package derived). Every
// value is sealed under the epoch the revision it derives from is served
// under (docs.epoch; the current one where that isn't known). A result
// has one source, so in a private namespace a reader of it whole (marker
// reads:{ns}) gets it sealed as one JWE under that epoch's key, when
// every hit (and, with counts, every hit counted) comes from one epoch,
// Content-Type application/jose, pl { ns, view } where view is the
// result's request target (/{ns}/g/{gs}/at/{ns_id}?{query}, the
// canonical form). A public namespace's results, which every reader gets,
// those of a reader whose grant restricts resources, who may hold only
// per-resource keys, and those mixing epochs are JSON { at, ns, hits,
// next? } in which each hit keeps resource, id and url in the clear and
// carries its score, schema and facets as "sealed": JWE under its
// resource's K_r of its epoch, pl { ns, name, view }; counts, which
// aggregate over resources, are refused (400) there.
// Sealed results are produced once per view (so per epoch: a rotation
// moves the checkpoint), stored in the database with their cache tags, and
// served unchanged, across restarts, until a purge with one of those tags
// or the next checkpoint retires them (derived.Cache); kept, they are
// served at their at for a while longer.
//
//	GET /_status                  each followed namespace's encryption level and
//	                              epoch, whether results are sealed, and why a
//	                              namespace is skipped
//
// A namespace skipped for want of keys (derived.Keys.Skip) is 404 as one
// the index doesn't follow (§A.4); one whose keys can't be fetched for now
// is 503 behind after the read check, as is a failure to get the key that
// seals its results.
func (ix *Index) Handler() http.Handler {
	return http.HandlerFunc(ix.serveHTTP)
}

func (ix *Index) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/edge-grants" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		// The index's own edge grants (edgegrants.go); a GET is a query
		// of a namespace of that name, as any other.
		ix.serveEdgeGrants(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeErr(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
		return
	}
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var gs, ns, at string
	isAt := false
	switch {
	case len(segs) == 1 && segs[0] == "_status":
		telemetry.SetRoute(r, "/_status")
		ix.serveStatus(w)
		return
	case segs[0] == "_refs": // across namespaces (refsall.go)
		ix.serveRefs(w, r, segs)
		return
	case len(segs) == 1 && segs[0] != "":
		ns = segs[0]
		telemetry.SetRoute(r, "/{ns}")
	case len(segs) == 3 && segs[1] == "at":
		ns, at, isAt = segs[0], segs[2], true
		telemetry.SetRoute(r, "/{ns}/at/{at}")
	case len(segs) == 3 && segs[1] == "g":
		// The head pointer under a subject set's prefix, which its edge
		// grants cover (§B.11.5). No subject set is "g", so the form
		// before v0.51 below, /g/{gs}/{ns}, never matches here.
		ns, gs = segs[0], segs[2]
		telemetry.SetRoute(r, "/{ns}/g/{gs}")
	case len(segs) == 5 && segs[1] == "g" && segs[3] == "at":
		ns, gs, at, isAt = segs[0], segs[2], segs[4], true
		telemetry.SetRoute(r, "/{ns}/g/{gs}/at/{at}")
	case len(segs) == 3 && segs[0] == "g" && validNS(segs[2]) && oldForm(segs[1]):
		// Before v0.51 (§A.4): /g/{gs}/{ns}, now the head pointer /{ns}.
		telemetry.SetRoute(r, "/g/{gs}/{ns}")
		moved(w, r, "/"+segs[2])
		return
	case len(segs) == 5 && segs[0] == "g" && segs[3] == "at" && validNS(segs[2]) && oldForm(segs[1], segs[4]):
		// Before v0.51: /g/{gs}/{ns}/at/{at}. A namespace named g has
		// /g/g/{gs}/at/{at}, matched above: no subject set is "g".
		telemetry.SetRoute(r, "/g/{gs}/{ns}/at/{at}")
		moved(w, r, "/"+segs[2]+"/g/"+segs[1]+"/at/"+segs[4])
		return
	default:
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	// A namespace the service doesn't follow, or a sealed or e2e one whose
	// keys it lacks, is 404 alike, before the read check (§A.4, §E.2.6).
	if _, lacks := ix.keys.Skip(ns); !client.ValidNSName(ns) || !ix.known(ns) || lacks {
		writeErr(w, http.StatusNotFound, "not_found", "namespace not indexed")
		return
	}
	if isAt {
		if _, err := ids.Parse(at); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_input", "malformed ns_id")
			return
		}
	}
	if gs != "" {
		if _, err := ids.Parse(gs); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", "malformed subject set")
			return
		}
	}
	ix.serve(w, r, gs, ns, at, isAt)
}

// access is the outcome of the read check for one request.
type access struct {
	public bool
	v      *grant.Verified // nil under an edge grant (cookie)
	all    bool            // reads every resource: no per-resource filtering
	marker string          // what the reader's answers depend on (private only, §A.4)
	gs     string          // subject-set id over marker (private only)
	// allow is the per-resource read check of a reader that isn't all:
	// the grant's, or under an edge grant the filter its marker stands
	// for (markerRec), or for a partial reader of a namespace §B.11.9
	// covers, visibility (cov).
	allow func(resource string) bool
	// filter is what a scope marker stands for, which an edge grant
	// minted for it authorises from (markerRec).
	filter *grantcheck.ReadFilter
	cookie bool // read under one of the service's edge grants
	// cov is a partial reader's view of a namespace §B.11.9 covers, at
	// the checkpoint its answers are at (filtered.go), and derive computes
	// it at another: from the grant, or from what a cookie's marker
	// stands for. Both are nil for any other reader.
	cov    *fview
	derive func(ctx context.Context, cp *fcp) (*fview, error)
}

// writeLimit answers a grant over grantSize or rulesPerGrant, which the
// checker decodes as a *grantcheck.LimitError, as the origin answers it:
// 413, code limit, naming the limit (§C.8), as the tree and catalog
// services do (§C.6); a public namespace's reads ignore the grant, so
// this comes up only where one is used. It reports whether it answered.
func writeLimit(w http.ResponseWriter, err error) bool {
	var le *grantcheck.LimitError
	if !errors.As(err, &le) {
		return false
	}
	svcedge.Limit(le.Limit, le.Measured, le.Max).Write(w)
	return true
}

func (ix *Index) access(ctx context.Context, ns string, r *http.Request) (*access, error) {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return nil, err
	}
	if cfg.Read == "public" {
		return &access{public: true, all: true}, nil
	}
	token := bearer(r)
	if token == "" {
		// One of the service's edge grants for this namespace's subject
		// set, on a request without Authorization (edgegrants.go).
		if a, ok, err := ix.cookieAccess(ctx, ns, r); ok || err != nil {
			return a, err
		}
		return nil, &grant.AuthError{Status: 401, Msg: "missing grant"}
	}
	v, err := ix.checker.Verify(ctx, ns, token)
	if err != nil {
		return nil, err
	}
	return ix.grantAccess(ctx, ns, v)
}

// grantAccess is access to private namespace ns for v, a grant verified
// there: whether the grant gets a marker in ns, and which (§A.4 Across
// namespaces). It is the one place that decides it, for a query of ns,
// for /_refs (refsReader, through access) and for an exchange
// (exchangeGrant), so each namespace is judged alone: a grant gets a
// marker where it allows read, its read rules don't refer to /now, and,
// if they fix /resource, they pass now for a name they fix (readsFixed).
// A refusal (*grant.AuthError, 403) leaves ns without a marker, which a
// query of ns answers 403 and /_refs and the exchange leave ns out for,
// refusing only where no namespace is left (§A.4 Coverage).
func (ix *Index) grantAccess(ctx context.Context, ns string, v *grant.Verified) (*access, error) {
	if ok, _ := v.Allows("read"); !ok {
		return nil, &grant.AuthError{Status: 403, Msg: "the grant does not allow read"}
	}
	// Results are keyed by a subject set over the reader's marker (§A.4,
	// as /_refs computes it, §B.11.5): reads:{ns} for a grant that would
	// be issued a namespace-wide edge grant (§C.5.2), which reads every
	// resource, so all such readers share results whatever their subjects;
	// reads:{ns}:scope:{digest} for one that reads only what its rules
	// allow, digest covering those rules and the /principal values they
	// refer to (grantcheck.ReadsScope), so readers limited alike share
	// them; and where §B.11.9 covers ns, reads:{ns}:g:{gs} for such a
	// partial reader, gs being the origin's, its hits filtered by
	// visibility (filtered.go). Where those rules refer to /now the
	// namespace counts as unreadable: a result at an at can't change with
	// the clock.
	if ix.checker.NamespaceWide(v) {
		return marked(&access{v: v, all: true, marker: "reads:" + ns}), nil
	}
	digest, ok := grantcheck.ReadsScope(v)
	if !ok {
		return nil, &grant.AuthError{Status: 403, Msg: "a rule limiting the grant's reads refers to /now"}
	}
	// One whose reads can't differ between resources, and that doesn't
	// read the namespace whole now, reads none of it.
	if !ix.checker.ReadsPerResource(v) {
		return nil, &grant.AuthError{Status: 403, Msg: "a grant or key rule refuses the read"}
	}
	// One whose rules fix /resource and pass for none of the names they
	// fix reads none of ns either: its rules, not what visibility shows
	// (§A.4: "its rules passing now for a name it fixes").
	if !readsFixed(v, func(name string) bool { return ix.checker.AllowsRead(v, name) }) {
		return nil, &grant.AuthError{Status: 403, Msg: "the grant's rules pass for none of the names they fix /resource to in " + ns + " (§A.4, §C.5.2)"}
	}
	a := &access{v: v, filter: grantcheck.FilterOf(v),
		derive: func(_ context.Context, cp *fcp) (*fview, error) { return grantFview(cp, v) }}
	switch err := ix.cover(ctx, a, ns, ""); {
	case err == nil:
		return a, nil
	case errors.Is(err, errNotReached):
		// Before the first checkpoint the query is behind anyway; the
		// marker of a namespace that may be covered can't be told yet.
		if may, err := ix.mayBeCovered(ctx, ns); err != nil || may {
			return nil, errors.Join(errNotReached, err)
		}
	case errors.Is(err, errUncovered), errors.Is(err, errPurgedNS):
	default:
		return nil, err
	}
	a.derive = nil
	a.marker = "reads:" + ns + ":scope:" + digest
	a.allow = func(resource string) bool { return ix.checker.AllowsRead(v, resource) }
	return marked(a), nil
}

// marked sets a's gs, the subject set of its marker alone.
func marked(a *access) *access {
	a.gs = grantcheck.SubjectSetID([]string{a.marker})
	return a
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// base is the path prefix of a namespace's URLs for this reader.
func base(a *access, ns string) string {
	if a.public {
		return "/" + ns
	}
	return "/" + ns + "/g/" + a.gs
}

func (ix *Index) serve(w http.ResponseWriter, r *http.Request, gs, ns, at string, isAt bool) {
	ctx := r.Context()
	vals := r.URL.Query()
	q, err := ParseQuery(vals)
	var bad *MinError
	if err != nil && !errors.As(err, &bad) {
		writeQueryErr(w, err)
		return
	}
	a, err := ix.access(ctx, ns, r)
	if bad != nil {
		// Malformed mins are 400 whoever asks, as before the read check;
		// to a reader who passes it, the 400 lists every other min refused
		// too, so that one 400 names every min refused (§A.5).
		if err == nil {
			bad = bad.With(vals["min"], judgeMinsIn(ns, q.Mins, a.covers), minOther)
		}
		writeMinErr(w, bad)
		return
	}
	if client.IsPurged(err) {
		// A purged sealed namespace's document is 410 too (§8.5): the
		// core makes the read check before answering it, as below.
		var head string
		if head, err = ix.purgedRead(ctx, ns, r, err); err == nil {
			writePurged(w, head)
			return
		}
	}
	if err != nil {
		if writeLimit(w, err) {
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
			writeErr(w, ae.Status, code, ae.Msg)
			return
		}
		if errors.Is(err, errNotReached) {
			writeBehind(w, errNotReached.Error())
			return
		}
		ix.writeUpstreamErr(w, "access check for "+ns, err, "cannot read the namespace configuration")
		return
	}
	// A purged namespace answers as the core's URLs of it do, after the
	// read check: 410 purged with head, its purge-ns entry (§8.5, §12),
	// the log's last, where the checkpoint stopped. The committed state
	// decides, as for redirects below: Apply purges the namespace's cache
	// tags after its commit and only then publishes the purge in memory,
	// and a result served in between, empty at the purge-ns entry, would
	// outlive the purge in caches.
	head, purged, err := ix.committed(ctx, ns)
	if err != nil {
		ix.opt.Logf("index: checkpoint of %s: %v", ns, err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot read the checkpoint")
		return
	}
	if purged {
		writePurged(w, head)
		return
	}
	// Keys the service fails to fetch for now (lacking them is the 404
	// above, which a config change the follower delivered meanwhile may
	// have made so): behind, as before its first checkpoint (§A.4, §12.1).
	if reason, lacks := ix.keys.Skip(ns); lacks {
		writeErr(w, http.StatusNotFound, "not_found", "namespace not indexed")
		return
	} else if reason != "" {
		writeBehind(w, "the index cannot obtain the keys of the namespace yet")
		return
	}
	// A partial reader of a namespace §B.11.9 covers reads at the combined
	// checkpoint with ns at its committed checkpoint (filtered.go): cur
	// below is that at, the reader's gs that at's.
	if a.cov != nil {
		if err := ix.cover(ctx, a, ns, head); err != nil {
			ix.writeCoverErr(w, ns, err)
			return
		}
	}
	setPtrHeaders := func() {
		if a.public {
			w.Header().Set("Cache-Control", ccHeadPointer)
			w.Header().Set("Cache-Tag", "ns:"+ns)
		} else {
			// A pointer depends on the caller's grant: no cache keeps
			// it, behind a verifying edge or not, and one that adds
			// /g/{gs} is private, no-store (§A.4, §B.11.5).
			w.Header().Set("Cache-Control", ccPrivatePtr)
			w.Header().Set("CDN-Cache-Control", "no-store")
			w.Header().Set("Surrogate-Control", "no-store")
			w.Header().Add("Vary", "Authorization")
		}
	}
	// An older at whose checkpoint the index still holds is read at the
	// reader's gs as of that at (§B.11.9, §B.11.5: a grant reads at its own
	// gs as of the URL's at): where that is the URL's gs, old is the
	// reader's view there, and the URL is the reader's own, answered as
	// any older at is below: its kept result, else a redirect to the
	// current at.
	var old *access
	if isAt && a.cov != nil && gs != "" && gs != a.gs && at != a.cov.cp.at {
		if cp := ix.keptCP(ns, at); cp != nil {
			if b := a.at(ctx, ns, cp); b != nil && b.gs == gs {
				old = b
			}
		}
	}
	// The reader's URL space: public, or keyed by its subject set. The
	// head pointer /{ns} is everyone's, and redirects there below. A grant
	// reads only at its own gs (§A.4, §B.11.5), as of the URL's at (old):
	// an at URL of another subject set is 403, with or without min, never
	// redirected. An at URL
	// without /g/{gs} of a private namespace, or one with it of a public
	// one, which no grant decides, is redirected to the same at in the
	// reader's space; with min, the redirects below land there, without
	// min (§A.5).
	if !isAt && gs != "" && gs != a.gs && !a.public {
		// The head pointer under another subject set's prefix (§B.11.5).
		w.Header().Set("Cache-Control", "no-store")
		writeErr(w, http.StatusForbidden, "forbidden", "the grant reads only at its own subject set")
		return
	}
	if isAt && gs != a.gs && old == nil {
		if gs != "" && !a.public {
			w.Header().Set("Cache-Control", "no-store")
			writeErr(w, http.StatusForbidden, "forbidden", "the grant reads only at its own subject set")
			return
		}
		if len(q.Mins) == 0 {
			setPtrHeaders()
			redirect(w, base(a, ns)+"/at/"+at+derived.CanonicalQuery(vals))
			return
		}
	}
	if refused := judgeMinsIn(ns, q.Mins, a.covers); len(refused) > 0 {
		writeMinErr(w, &MinError{Msg: minOther, Refused: refused})
		return
	}
	// target is the canonical URL of this query's result at an ns_id (§A.5):
	// what redirects name, what results are kept under, and in a sealed or
	// e2e namespace the view a result is bound to (§E.2.6).
	targetOf := func(v url.Values, id string) string {
		return base(a, ns) + "/at/" + id + derived.CanonicalQuery(v, "min")
	}
	target := func(id string) string { return targetOf(vals, id) }
	// atA and atTarget are the reader's view at the URL's at and this
	// query's canonical URL there: old's where the reader's gs there
	// differs from its current one.
	atA, atTarget := a, target(at)
	if old != nil {
		atA, atTarget = old, base(old, ns)+"/at/"+at+derived.CanonicalQuery(vals, "min")
	}
	// elsewhere is the query a redirect to another at sends (§A.4): an
	// after naming a resource is kept, applied to the new result, and an
	// opaque one, a position in this at's result, is dropped, starting
	// again.
	elsewhere := func() (url.Values, *Query) {
		if q.ByName() || !vals.Has("after") {
			return vals, q
		}
		ev := maps.Clone(vals)
		delete(ev, "after")
		eq := *q
		eq.After = 0
		return ev, &eq
	}
	if !ix.waitMins(ctx, q.Mins) {
		writeBehind(w, "the index has not reached min yet")
		return
	}
	// The committed checkpoint, not the in-memory one: Apply publishes the
	// latter just after its commit, and queries read the committed rows. A
	// redirect decided by one and a read by the other made the head pointer
	// and at URLs alternate between the old and the new at while an apply
	// sat between the two (e.g. in a slow purger), and sent ?min= readers
	// to a checkpoint behind min, which seen (committed with it) had passed.
	// The committed checkpoint only moves forward, so every redirect does.
	// Whether ns is purged is read with it: a purge-ns committed since the
	// check above (it may be the min waited for) is answered as there.
	cur := head
	if len(q.Mins) > 0 {
		// Nothing waited since the read above without min.
		cur, purged, err = ix.committed(ctx, ns)
		if err != nil {
			ix.opt.Logf("index: checkpoint of %s: %v", ns, err)
			writeErr(w, http.StatusInternalServerError, "internal", "cannot read the checkpoint")
			return
		}
		if purged {
			writePurged(w, cur)
			return
		}
		if a.cov != nil {
			// A min may have moved the heads of the namespaces the view
			// reads (waitMember): it is computed again.
			a.cov = nil
			if err := ix.cover(ctx, a, ns, cur); err != nil {
				ix.writeCoverErr(w, ns, err)
				return
			}
		}
	}
	if a.cov != nil {
		cur = a.cov.cp.at
	}
	if cur == "" {
		writeBehind(w, "the index has not reached the namespace yet")
		return
	}
	// min always redirects (§A.5): an older at whose kept result already
	// includes every min to itself without min. The current at needs no
	// judging: the redirect to the current checkpoint below names the same
	// URL, with the result computed and kept there first.
	if isAt && len(q.Mins) > 0 && at != cur && ix.atIncludes(ctx, atA, ns, at, q.Mins, atTarget) {
		setPtrHeaders()
		redirect(w, atTarget)
		return
	}
	// Only the canonical form of an at URL is answered (§A.5), and never
	// one with min.
	canonical := r.URL.RequestURI() == atTarget
	if isAt && len(q.Mins) == 0 {
		// A kept result answers its at however far the checkpoint has
		// moved since (B9).
		if st, _, ok := ix.kept.Get(atTarget); ok {
			if !canonical {
				setPtrHeaders()
				redirect(w, atTarget)
				return
			}
			ix.writeStored(w, r, atA, at, st)
			return
		}
	}
	if !isAt || at != cur || len(q.Mins) > 0 {
		// Head pointer, an ns_id whose result isn't kept, or a min waited
		// for: redirect to the current checkpoint (§A.7's second question
		// resolved as redirect, as §A.4 shows; §A.5), with the result
		// computed there and kept, so the redirect is answered even if the
		// checkpoint moves on before it is followed. If it can't be
		// computed, the at URL says why. From an at URL to another at, an
		// opaque after is dropped (elsewhere); the head pointer names no
		// at, and passes the query on whole.
		rv, rq := vals, q
		if isAt && at != cur {
			rv, rq = elsewhere()
		}
		to := cur
		if _, _, ok := ix.kept.Get(targetOf(rv, cur)); !ok {
			if info, _, err := ix.keys.Current(ctx, ns); err == nil {
				var fe *FieldError
				if _, got, err := ix.answer(ctx, a, ns, rv, rq, info); err == nil {
					to = got
				} else if !errors.As(err, &fe) && !errors.Is(err, errCounts) && !errors.Is(err, errEpochCounts) && !errors.Is(err, errLackCounts) {
					ix.opt.Logf("index: query %s: %v", r.URL, err)
				}
			}
		}
		setPtrHeaders()
		redirect(w, targetOf(rv, to))
		return
	}
	if !canonical {
		setPtrHeaders()
		redirect(w, target(at))
		return
	}

	info, _, err := ix.keys.Current(ctx, ns)
	if err != nil {
		// The key that seals results can't be had: behind (§12.1), no
		// code of its own.
		ix.opt.Logf("index: keys of %s: %v", ns, err)
		writeBehind(w, "the index cannot obtain the key that seals results of this namespace yet")
		return
	}
	if info.Protected() {
		gen := ix.kept.Generation(ns)
		if st, ok := ix.sealed.Get(ctx, target(at)); ok {
			st, _ = ix.kept.Put(target(at), ns, gen, true, st)
			ix.writeStored(w, r, a, at, st)
			return
		}
	}
	st, got, err := ix.answer(ctx, a, ns, vals, q, info)
	var fe *FieldError
	switch {
	case errors.As(err, &fe):
		writeErr(w, http.StatusBadRequest, "bad_input", fe.Error())
		return
	case errors.Is(err, errCounts) || errors.Is(err, errEpochCounts) || errors.Is(err, errLackCounts):
		writeErr(w, http.StatusBadRequest, "bad_input", err.Error())
		return
	case errors.Is(err, errEpochKey):
		writeBehind(w, err.Error()) // §12.1: no code of its own
		return
	case errors.Is(err, errVisibility), errors.Is(err, errMoving):
		ix.writeCoverErr(w, ns, err)
		return
	case errors.Is(err, errSchemas):
		ix.opt.Logf("index: query %s: %v", r.URL, err)
		writeErr(w, http.StatusBadGateway, "upstream", errSchemas.Error())
		return
	case err != nil:
		ix.opt.Logf("index: query %s: %v", r.URL, err)
		writeErr(w, http.StatusInternalServerError, "internal", "query failed")
		return
	}
	if got != at {
		// The checkpoint moved between the check and the read transaction;
		// the result is kept at the new one, or, with an opaque after,
		// computed there afresh without it (elsewhere).
		rv, rq := elsewhere()
		if len(rv) != len(vals) {
			if _, g, err := ix.answer(ctx, a, ns, rv, rq, info); err == nil {
				got = g
			}
		}
		setPtrHeaders()
		redirect(w, targetOf(rv, got))
		return
	}
	ix.writeStored(w, r, a, at, st)
}

// errMoving is a namespace whose checkpoint moved each time a partial
// reader's view was computed for it (§B.11.9, answer): behind, for now.
var errMoving = errors.New("the index is applying the namespace's log: try again")

// errVisibility wraps a failure to compute a partial reader's view
// (writeCoverErr).
var errVisibility = errors.New("visibility")

// writeCoverErr answers a failure to compute a partial reader's view of a
// namespace §B.11.9 covers (Index.cover): a refusal as such, no-store;
// one of a namespace not reached yet, or purged meanwhile, behind; and a
// namespace whose state visibility reads the service can't read, 502.
func (ix *Index) writeCoverErr(w http.ResponseWriter, ns string, err error) {
	var ae *grant.AuthError
	switch {
	case errors.As(err, &ae):
		code := "forbidden"
		if ae.Status == 401 {
			code = "unauthenticated"
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		w.Header().Set("Cache-Control", "no-store")
		writeErr(w, ae.Status, code, ae.Msg)
	case errors.Is(err, errNotReached), errors.Is(err, errPurgedNS), errors.Is(err, errMoving):
		writeBehind(w, "the index has not reached the namespace's checkpoint yet")
	default:
		ix.writeUpstreamErr(w, "visibility in "+ns, err, "cannot read a namespace visibility reads (§B.11.9)")
	}
}

// writeUpstreamErr answers err, a failure to read upstream what answering
// needs, 502 upstream with msg, or msgGrantLacks where the index's own
// grant can't read a namespace that decides §B.11.9 coverage
// (errGrantLacks); the log names it.
func (ix *Index) writeUpstreamErr(w http.ResponseWriter, what string, err error, msg string) {
	ix.opt.Logf("index: %s: %v", what, err)
	var gl *errGrantLacks
	if errors.As(err, &gl) {
		msg = msgGrantLacks
	}
	writeErr(w, http.StatusBadGateway, "upstream", msg)
}

// errCounts refuses counts over a sealed namespace to a reader whose
// results are sealed per entry (400, §E.2.6 Aggregates): counts aggregate
// over resources, so they have no entry of their own.
var errCounts = errors.New("counts over a sealed namespace are served only sealed whole, to a grant that reads the whole private namespace")

// errEpochCounts refuses counts over documents served under several
// epochs (400, §E.2.6): a result is sealed whole only when every value in
// it derives from revisions served under one epoch, and counts are served
// only sealed whole.
var errEpochCounts = errors.New("counts over documents served under several epochs can't be sealed whole under one epoch's key, and are served only sealed whole (§E.2.6)")

// errLackCounts refuses counts over documents served under an epoch whose
// key the service's grant gets none of (400, §E.2.6): such hits are served
// by name only, per entry, and counts are served only sealed whole.
var errLackCounts = errors.New("counts over documents served under an epoch the index gets no key for can't be sealed whole, and are served only sealed whole (§E.2.6)")

// errEpochKey is a key of an epoch a hit's document is served under, which
// seals it (§E.2.6), that the service can't obtain for now: 503 behind.
var errEpochKey = errors.New("the index cannot obtain the key of an epoch a hit is served under")

// lacksKey reports whether err, from fetching the key of an epoch, leaves
// the service lacking that key as its grant and keys are configured
// (§A.4, §E.2.6): /keys answered a 4xx other than 429, or gave no key for
// the epoch (ErrNoKeys) or none the service can unwrap (seal.ErrDecrypt)
// or will take (ErrUntrustedKey, §E.3.2). Any other failure, the reader's
// request ending while the key is read among them, is for now. So is any
// failure once ctx is done, which may be why it failed.
func lacksKey(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if ae, ok := client.AsAPIError(err); ok {
		return ae.Status >= 400 && ae.Status < 500 && ae.Status != 429
	}
	return errors.Is(err, client.ErrNoKeys) || errors.Is(err, seal.ErrDecrypt) || errors.Is(err, client.ErrUntrustedKey)
}

// answer runs q at the current checkpoint in one read transaction, builds
// its result, sealed in a sealed or e2e namespace, keeps it (and stores a
// sealed one), and returns the result kept with the checkpoint it is at.
//
// Each sealed value is sealed under the epoch the revision it derives
// from is served under (§E.2.6; derived.EpochOf, docs.epoch), the epoch
// current now where that isn't known: a hit under that epoch's K_r of its
// resource. A result is sealed whole only when its source isn't public,
// every reader its URL admits reads it whole, under reads:{ns}, and every
// value derives from revisions served under one epoch, under that
// epoch's K_e (§E.2.6 Whole-response sealing); otherwise it is sealed per
// entry, and counts, which have no entry, are 400.
func (ix *Index) answer(ctx context.Context, a *access, ns string, vals url.Values, q *Query, info derived.Info) (derived.Stored, string, error) {
	// A public sealed namespace's results, which anyone reads, and a
	// limited reader's, are sealed per entry whatever their epochs.
	perEntry := info.Protected() && (a.public || !a.all)
	if perEntry && len(q.Counts) > 0 {
		return derived.Stored{}, "", errCounts
	}
	// An epoch whose key the service's grant gets none of, for good (a 4xx
	// from /keys, no key for it, one it can't unwrap: lacksKey), leaves the
	// hits served under it by name only, in a result sealed per entry
	// (§E.2.6), kept so; one it can't get for now is behind.
	keys := map[int]derived.Key{}
	lacking := map[int]bool{}
	keyAt := func(epoch int) (k derived.Key, lacks bool, err error) {
		if epoch <= 0 {
			epoch = info.Epoch
		}
		if k, ok := keys[epoch]; ok {
			return k, false, nil
		}
		if lacking[epoch] {
			return k, true, nil
		}
		k, err = ix.keys.KeyAt(ctx, ns, epoch)
		switch {
		case lacksKey(ctx, err):
			ix.opt.Logf("index: key of %s epoch %d, for good: %v (its hits by name only)", ns, epoch, err)
			lacking[epoch] = true
			return k, true, nil
		case err != nil:
			ix.opt.Logf("index: key of %s epoch %d: %v", ns, epoch, err)
			return k, false, fmt.Errorf("%w (%s#%d)", errEpochKey, ns, epoch)
		}
		keys[epoch] = k
		return k, false, nil
	}
	var allow func(string) bool
	if !a.all {
		allow = a.allow
	}
	gen := ix.kept.Generation(ns)
	q.epochs = info.Protected()
	res, at, err := ix.query(ctx, ns, q, allow)
	if err != nil {
		return derived.Stored{}, "", err
	}
	// A partial reader where §B.11.9 covers ns: the view must be at the
	// checkpoint the read transaction held (an apply may have committed
	// since it was computed), and the answer is at its combined at.
	var cp *fcp
	for try := 0; a.cov != nil; try++ {
		if at == a.cov.cp.ids[ns] {
			cp, at = a.cov.cp, a.cov.cp.at
			break
		}
		if try == 2 {
			return derived.Stored{}, "", errMoving
		}
		if err := ix.cover(ctx, a, ns, at); err != nil {
			return derived.Stored{}, "", fmt.Errorf("%w: %w", errVisibility, err)
		}
		if res, at, err = ix.query(ctx, ns, q, a.allow); err != nil {
			return derived.Stored{}, "", err
		}
	}
	// The one epoch every value derives from, for a result sealed whole.
	whole := 0
	if info.Protected() && !perEntry {
		epochs := map[int]bool{}
		for _, e := range res.Epochs {
			if e <= 0 {
				e = info.Epoch
			}
			epochs[e] = true
		}
		switch {
		case len(epochs) > 1 && len(q.Counts) > 0:
			return derived.Stored{}, "", errEpochCounts
		case len(epochs) > 1:
			perEntry = true
		default:
			whole = info.Epoch
			for e := range epochs {
				whole = e
			}
			// One epoch whose key the service lacks: per entry, by name
			// only, as for several epochs.
			_, lacks, err := keyAt(whole)
			switch {
			case err != nil:
				return derived.Stored{}, "", err
			case lacks && len(q.Counts) > 0:
				return derived.Stored{}, "", errLackCounts
			case lacks:
				perEntry = true
			}
		}
	}
	view := derived.View{NS: ns, Target: base(a, ns) + "/at/" + at + derived.CanonicalQuery(vals, "min")}
	body := map[string]any{"at": at, "ns": ns}
	if cp != nil {
		// What at covers (§A.4 Private namespaces).
		body["namespaces"] = cp.ids
	}
	hits := make([]any, 0, len(res.Hits))
	for _, h := range res.Hits {
		m := map[string]any{
			"resource": h.Resource, "id": h.ID, "score": h.Score,
			"url": ix.origin + "/r/" + ns + "/" + h.Resource + "/rev/" + h.ID,
		}
		if h.Schema != "" {
			m["schema"] = h.Schema
		}
		// refs (§A.4): with ?ref=, where each matching reference sits.
		if len(h.Refs) > 0 {
			m["refs"] = h.Refs
		}
		// …facets (§A.4): every facet path of the document, as a list of values.
		for p, vs := range h.Facets {
			m[p] = vs
		}
		// …sort values and requested fields (§A.4), under the same paths.
		for p, vs := range h.Sorts {
			m[p] = vs
		}
		for p, vs := range h.Text {
			m[p] = vs
		}
		if h.Self {
			m["self"] = true
		}
		if perEntry {
			// Per-entry sealing: what the document gave (score, schema,
			// facets) under its resource's key; names, ids and URLs stay.
			values := map[string]any{}
			for k, v := range m {
				if k != "resource" && k != "id" && k != "url" {
					values[k] = v
				}
			}
			key, lacks, err := keyAt(h.epoch)
			if err != nil {
				return derived.Stored{}, "", err
			}
			if lacks {
				m = map[string]any{"resource": m["resource"], "id": m["id"], "url": m["url"]}
				hits = append(hits, m)
				continue
			}
			jwe, err := derived.SealItem(key, view, h.Resource, values)
			if err != nil {
				return derived.Stored{}, "", fmt.Errorf("sealing a hit: %w", err)
			}
			m = map[string]any{"resource": m["resource"], "id": m["id"], "url": m["url"], "sealed": jwe}
		}
		hits = append(hits, m)
	}
	body["hits"] = hits
	// Every query pages as /_refs does (§A.4): next is the after of the
	// following page, absent on the last; a resource name without q or
	// sort, else an opaque position.
	if res.More && q.ByName() {
		body["next"] = res.Hits[len(res.Hits)-1].Resource
	} else if res.More {
		body["next"] = positionAfter(q.After + len(res.Hits))
	}
	if res.Counts != nil {
		body["counts"] = res.Counts
	}
	st := derived.Stored{JSON: true, Tags: resultTags(ns, res, cp)}
	if info.Protected() && !perEntry {
		key, _, err := keyAt(whole) // found above
		if err != nil {
			return derived.Stored{}, "", err
		}
		jwe, err := derived.SealView(key, view, body)
		if err != nil {
			return derived.Stored{}, "", fmt.Errorf("encoding a result: %w", err)
		}
		st.Body, st.JSON = []byte(jwe), false
	} else {
		st.Body, err = derived.Marshal(body)
	}
	if err != nil {
		return derived.Stored{}, "", fmt.Errorf("encoding a result: %w", err)
	}
	if err := ctx.Err(); err != nil {
		// The reader went away: keep nothing built meanwhile.
		return derived.Stored{}, "", err
	}
	if info.Protected() {
		if st, err = ix.sealed.Put(ctx, view.Target, ns, at, st); err != nil {
			ix.opt.Logf("index: storing a sealed result: %v", err)
		}
		if now, _, err := ix.committed(ctx, ns); err == nil && now != at {
			// An apply (maybe a purge) committed meanwhile: don't keep a
			// result it may have retired.
			if err := ix.sealed.Retire(ctx, ix.db, ns, now); err != nil {
				ix.opt.Logf("index: retiring sealed results of %s: %v", ns, err)
			}
		}
	}
	st, _ = ix.kept.Put(view.Target, ns, gen, info.Protected(), st)
	return st, at, nil
}

// setResultHeaders sets a result's headers: a private one gets edge
// lifetimes only for a read the verifying edge verified (§9).
func (ix *Index) setResultHeaders(w http.ResponseWriter, r *http.Request, a *access, at, tags string) {
	if a.public {
		w.Header().Set("Cache-Control", ccImmutable)
	} else {
		w.Header().Set("Cache-Control", ccPrivateImm)
		ix.opt.Edge.Private(w.Header(), r, cdnImmutable)
	}
	w.Header().Set("Cache-Tag", tags)
	w.Header().Set("X-Namespace-Revision", at)
}

// writeStored writes a result as stored or kept: JSON, or in a sealed or
// e2e namespace the JWE (application/jose), or for a resource-restricted
// reader the JSON with per-hit sealed values, with its Cache-Tag.
func (ix *Index) writeStored(w http.ResponseWriter, r *http.Request, a *access, at string, st derived.Stored) {
	ix.setResultHeaders(w, r, a, at, st.Tags)
	if st.JSON {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", seal.ContentType)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(st.Body)
}

// serveStatus answers GET /_status (Addendum E): each followed namespace's
// encryption level and epoch, whether its results are sealed, and why it is
// skipped if it is. A query of one skipped for want of keys is 404, of one
// skipped for now 503 behind.
func (ix *Index) serveStatus(w http.ResponseWriter) {
	ix.mu.Lock()
	nss := make([]string, 0, len(ix.roots))
	for ns := range ix.roots {
		nss = append(nss, ns)
	}
	for ns := range ix.cur {
		if !ix.roots[ns] {
			nss = append(nss, ns)
		}
	}
	ix.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"namespaces": ix.keys.Status(nss)})
}

// resultTags is a result's Cache-Tag, at combined checkpoint cp if not
// nil.
func resultTags(ns string, res *Result, cp *fcp) string {
	// §A.4: idx:{ns} for the namespace, which every purge in it purges
	// (Apply), and r:{ns}/{name} for every resource the result shows; at a
	// combined checkpoint, idx:{m} for every other namespace in it too.
	tags := []string{"idx:" + ns}
	if cp != nil {
		tags = coverTags(cp)
	}
	for _, h := range res.Hits {
		tags = append(tags, "r:"+ns+"/"+h.Resource)
	}
	return strings.Join(tags, ",")
}

// query runs q in one read transaction, at the checkpoint the database
// holds, and returns the result with that checkpoint. Its paths are judged
// by the schemas of the namespace's documents there that the reader may
// see (allow, nil for all).
func (ix *Index) query(ctx context.Context, ns string, q *Query, allow func(string) bool) (*Result, string, error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var at string
	if err := tx.QueryRowContext(ctx, `SELECT ns_id FROM checkpoints WHERE origin = ? AND ns = ?`, ix.origin, ns).Scan(&at); err != nil {
		return nil, "", err
	}
	if err := ix.checkFields(ctx, tx, ns, q, allow); err != nil {
		return nil, "", err
	}
	res, err := ix.run(ctx, tx, ns, q, allow)
	return res, at, err
}

// committed returns the checkpoint of ns the database holds ("" if none),
// what queries read, and whether ns is purged there, in one read, so both
// as of one commit. Both are at or ahead of the in-memory ones
// (Index.state), which Apply publishes after its commit.
func (ix *Index) committed(ctx context.Context, ns string) (string, bool, error) {
	var (
		id     string
		purged bool
	)
	err := ix.db.QueryRowContext(ctx, `SELECT coalesce((SELECT ns_id FROM checkpoints WHERE origin = ? AND ns = ?), ''), coalesce((SELECT purged FROM ns_state WHERE ns = ?), 0)`,
		ix.origin, ns, ns).Scan(&id, &purged)
	return id, purged, err
}

// atIncludes reports whether the kept result of ns at an older at, which
// url names, already includes every min (§A.5 "min always redirects"),
// once waitMins has waited for them: each names ns (a min of another
// followed namespace never is: the result reflects ns alone) and is at
// itself, or an ns_id the core's log places before at (since=min is
// accepted only if min is in the chain up to at, §7.1). Only a kept
// result counts: an at whose result isn't kept is one the index no longer
// keeps results for, which redirects to the current checkpoint anyway
// (§A.4), and a redirect to it would not be answered (bounded redirects).
//
// A partial reader's at where §B.11.9 covers ns is a combined checkpoint:
// its kept result lists what it covers as namespaces, as /_refs' answers
// do (refsIncludes).
func (ix *Index) atIncludes(ctx context.Context, a *access, ns, at string, mins []MinRef, url string) bool {
	if a.cov != nil {
		st, _, ok := ix.kept.Get(url)
		return ok && ix.refsIncludes(ctx, st, mins)
	}
	for _, m := range mins {
		if m.NS != ns {
			return false
		}
	}
	if _, _, ok := ix.kept.Get(url); !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	done := map[string]bool{at: true}
	for _, m := range mins {
		if done[m.ID] {
			continue
		}
		done[m.ID] = true
		if _, _, err := ix.c.NSLogPage(ctx, ns, at, m.ID); err != nil {
			return false
		}
	}
	return true
}

// judgeMins judges the mins of a query of ns (a bare one names ns, and is
// set to) before any is waited for (§A.5): this URL's checkpoint covers ns
// alone, or, for a partial reader where §B.11.9 covers ns, the namespaces
// its combined checkpoint covers (judgeMinsIn, §A.4), so a min naming any
// other namespace is refused, whether the service follows it, the reader
// may see it, it is purged or its keys can't be had, before any of that
// is looked at (§A.4, Open 84). refused lists every refused min as given,
// so the 400 names them all. The purged-namespace exemption is /_refs' and
// tree listings' only.
func judgeMins(ns string, mins []MinRef) (refused []string) { return judgeMinsIn(ns, mins, nil) }

// judgeMinsIn is judgeMins at a checkpoint covering the namespaces covers
// accepts too (nil: ns alone).
func judgeMinsIn(ns string, mins []MinRef, covers func(string) bool) (refused []string) {
	for i, m := range mins {
		switch {
		case m.NS == "":
			mins[i].NS = ns
		case m.NS == ns, covers != nil && covers(m.NS):
		default:
			refused = append(refused, m.String())
		}
	}
	return refused
}

// covers reports whether a's answers are at a combined checkpoint that
// covers ns (§A.4, §B.11.9), a partial reader's of a covered namespace.
func (a *access) covers(ns string) bool {
	if a == nil || a.cov == nil {
		return false
	}
	_, ok := a.cov.cp.ids[ns]
	return ok
}

// waitMins waits, within one MinWait budget, until every min is reached.
func (ix *Index) waitMins(ctx context.Context, mins []MinRef) bool {
	if len(mins) == 0 {
		return true
	}
	ix.mu.Lock()
	wait := ix.opt.MinWait
	ix.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, wait+2*time.Second)
	defer cancel()
	deadline := time.Now().Add(wait)
	for _, m := range mins {
		waitFor := ix.waitMin
		if !ix.known(m.NS) {
			waitFor = ix.waitMember
		}
		if !waitFor(ctx, m.NS, m.ID, time.Until(deadline)) {
			return false
		}
	}
	return true
}

// waitMember is waitMin for a namespace a combined checkpoint covers that
// the index doesn't follow (§A.4, §B.11.9, filtered.go): it is taken at
// its head, so min is reached once the head is min or the core's log
// places min before it (since=min is accepted only if min is in the chain
// up to it, §7.1). The head is read again while waiting, and the grant
// checker, through which checkpoints read it, told of it.
func (ix *Index) waitMember(ctx context.Context, ns, minID string, wait time.Duration) bool {
	deadline := time.Now().Add(max(wait, 0))
	for {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		h, err := ix.c.NSHead(cctx, ns)
		reached := err == nil && h.ID == minID
		if err == nil && !reached {
			_, _, lerr := ix.c.NSLogPage(cctx, ns, h.ID, minID)
			reached = lerr == nil
		}
		cancel()
		if reached {
			ix.checker.Observe(ns, h.ID)
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		t := time.NewTimer(min(50*time.Millisecond, time.Until(deadline)))
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-lifecycle.Stopping(ctx):
			t.Stop()
			return false
		case <-t.C:
		}
	}
}

// waitMin waits up to MinWait until the checkpoint of ns is at or past min
// (§A.5): min is the checkpoint, or an ns_id the index has applied, or (for
// ns_ids it never saw one by one, e.g. before a branch's snapshot) an ns_id
// the core's log places at or before the checkpoint.
func (ix *Index) waitMin(ctx context.Context, ns, min string, wait time.Duration) bool {
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		cur, _, changed := ix.state(ns)
		if cur == min || ix.seen(ctx, ns, min) {
			return true
		}
		select {
		case <-changed:
			continue
		case <-ctx.Done():
			return false
		case <-timer.C:
		case <-lifecycle.Stopping(ctx):
			// Shutting down: answer now, as if the wait had run out.
		}
		break
	}
	cur, _, _ := ix.state(ns)
	if cur == "" {
		return false
	}
	// since=min is accepted only if min is in the chain up to cur: the
	// range's first page answers that (§7.1 Paging).
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _, err := ix.c.NSLogPage(cctx, ns, cur, min)
	return err == nil
}

func (ix *Index) seen(ctx context.Context, ns, id string) bool {
	var one int
	err := ix.db.QueryRowContext(ctx, `SELECT 1 FROM seen WHERE ns = ? AND ns_id = ?`, ns, id).Scan(&one)
	return err == nil
}

// writeBehind answers 503 behind (§A.4, §A.5, §12.1): no-store, with
// Retry-After.
func writeBehind(w http.ResponseWriter, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "1")
	writeErr(w, http.StatusServiceUnavailable, "behind", msg)
}

// writeMinRefused answers 400 for refused mins (§A.5, §12.1): no-store,
// with every one refused, as given, in the body's min, and one message for
// a namespace the reader can't see and one the service doesn't follow.
func writeMinRefused(w http.ResponseWriter, refused []string) {
	writeMinErr(w, &MinError{Msg: minElsewhere, Refused: refused})
}

func writeMinErr(w http.ResponseWriter, e *MinError) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusBadRequest, map[string]any{"code": "bad_input", "message": e.Msg, "min": e.Refused})
}

// writeQueryErr answers a query that doesn't parse: 400, listing malformed
// mins as refused ones are.
func writeQueryErr(w http.ResponseWriter, err error) {
	var me *MinError
	if errors.As(err, &me) {
		writeMinErr(w, me)
		return
	}
	writeErr(w, http.StatusBadRequest, "bad_input", err.Error())
}

// writePurged answers 410 purged with head, the namespace's purge-ns entry,
// as the core does (§8.5, §12).
func writePurged(w http.ResponseWriter, head string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusGone, map[string]any{"code": "purged", "message": "namespace purged", "head": head})
}

func redirect(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

// oldForm reports whether the subject set and checkpoints of a URL of a
// form before v0.51 are well formed, so that, with a valid namespace name,
// the URL moved names nothing but them.
func oldForm(gs string, ats ...string) bool {
	if _, err := ids.Parse(gs); err != nil {
		return false
	}
	for _, at := range ats {
		if _, err := ids.Parse(at); err != nil {
			return false
		}
	}
	return true
}

// moved answers a URL of a form before v0.51 (§A.4) with a permanent
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

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	if w.Header().Get("Cache-Control") == "" {
		if status == http.StatusNotFound {
			w.Header().Set("Cache-Control", "public, max-age=5")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
	}
	writeJSON(w, status, map[string]any{"code": code, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
