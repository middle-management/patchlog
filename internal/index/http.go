package index

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// Cache-Control values (§9).
const (
	ccHeadPointer = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccImmutable   = "public, max-age=86400, s-maxage=31536000, immutable"
	ccPrivatePtr  = "private, no-cache"
	ccPrivateImm  = "private, max-age=300"
	cdnImmutable  = "max-age=31536000"
)

var validNS = client.ValidNSName

// minElsewhere is the 400 for a min naming a namespace the index doesn't
// follow, or one the reader can't see (§A.5): one message for both, so it
// doesn't tell which private namespaces exist and are indexed.
const minElsewhere = "min names a namespace the service does not follow or the reader can't see"

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
// ns_id never changes while it is served, and a purge removes it from
// caches, and from the kept results, through its r: tags.
//
// Redirects name the query in its canonical form (§A.5,
// derived.CanonicalQuery), and an at URL is answered 200 only in that form
// and without min: one in another form is redirected to it. A request with
// ?min= is always redirected (§A.5): once every min is reached, an at URL
// whose kept result already includes every min to itself without min,
// anything else to the current checkpoint.
//
// Private namespaces need Authorization: Bearer <grant>; a request without
// the right gs is redirected to it (with min, by the redirect above, into
// the reader's URL space).
//
// Sealed and e2e namespaces (§E.2.5, §E.2.6; package derived). A result
// has one source, so a reader of the whole namespace gets it sealed as one
// JWE under the namespace's current epoch key, Content-Type
// application/jose, pl { ns, view } where view is the result's request
// target (/{ns}[/g/{gs}]/at/{ns_id}?{query}, the canonical form). A reader
// whose grant restricts resources may hold only per-resource keys, so it
// gets JSON { at, ns, hits, next? } in which each hit keeps resource, id
// and url in the clear and carries its score, schema and facets as
// "sealed": JWE under its resource's K_r, pl { ns, name, view }; counts,
// which aggregate over resources, are refused (400) for such readers.
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
	v      *grant.Verified
	all    bool   // reads every resource: no per-resource filtering
	gs     string // subject-set id (private only)
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
		return nil, &grant.AuthError{Status: 401, Msg: "missing grant"}
	}
	v, err := ix.checker.Verify(ctx, ns, token)
	if err != nil {
		return nil, err
	}
	if ok, _ := v.Allows("read"); !ok {
		return nil, &grant.AuthError{Status: 403, Msg: "the grant does not allow read"}
	}
	// A grant that reads the namespace unrestricted (§2.1) reads every
	// resource; one whose reads can't differ between resources and that
	// doesn't reads none.
	a := &access{v: v, all: ix.checker.ReadsUnrestricted(v)}
	if !a.all && !ix.checker.ReadsPerResource(v) {
		return nil, &grant.AuthError{Status: 403, Msg: "a grant or key rule refuses the read"}
	}
	// §B.11.5: results are keyed by the reader's subject set. Readers of the
	// whole namespace see the same hits, so their key is just their groups
	// (users share caches with their groups). A reader whose grant restricts
	// resources sees a filtered list that depends on the grant itself, so
	// its key also carries the subject and a digest of everything the
	// filter reads (principal and rules); it shares only with identical
	// grants.
	subjects := grantcheck.SubjectSet(v, !a.all)
	if !a.all {
		subjects = append(subjects, "scope:"+scopeDigest(v))
	}
	a.gs = grantcheck.SubjectSetID(subjects)
	return a, nil
}

func scopeDigest(v *grant.Verified) string {
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
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_input", err.Error())
		return
	}
	a, err := ix.access(ctx, ns, r)
	if client.IsPurged(err) {
		// A purged sealed namespace's document is 410 too (§8.5): the
		// core makes the read check before answering it, as below.
		var head string
		if head, err = ix.checker.PurgedRead(ctx, ns, bearer(r)); err == nil {
			writePurged(w, head)
			return
		}
	}
	if err != nil {
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
		ix.opt.Logf("index: access check for %s: %v", ns, err)
		writeErr(w, http.StatusBadGateway, "upstream", "cannot read the namespace configuration")
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
	// above): behind, as before its first checkpoint (§A.4, §12.1).
	if reason, _ := ix.keys.Skip(ns); reason != "" {
		writeBehind(w, "the index cannot obtain the keys of the namespace yet")
		return
	}
	setPtrHeaders := func() {
		if a.public {
			w.Header().Set("Cache-Control", ccHeadPointer)
			w.Header().Set("Cache-Tag", "ns:"+ns)
		} else {
			// A pointer depends on the caller's grant: no shared cache
			// keeps it, behind a verifying edge or not.
			w.Header().Set("Cache-Control", ccPrivatePtr)
			w.Header().Set("CDN-Cache-Control", "no-store")
			w.Header().Set("Surrogate-Control", "no-store")
			w.Header().Add("Vary", "Authorization")
		}
	}
	// The reader's URL space: public, or keyed by its subject set. The
	// head pointer /{ns} is everyone's, and redirects there below; an at
	// URL of another space is redirected to the same at in the reader's.
	// With min, the redirects below land there, without min (§A.5).
	if isAt && gs != a.gs && len(q.Mins) == 0 {
		setPtrHeaders()
		redirect(w, base(a, ns)+"/at/"+at+derived.CanonicalQuery(vals))
		return
	}
	// A min naming another namespace, which this URL's at doesn't cover,
	// goes to the current checkpoint once reached (atIncludes judges only
	// ns), in one hop, if the service follows it and the reader may see
	// it; any other is 400 (§A.5), with one message either way, as in
	// /_refs, so a min doesn't tell which private namespaces are indexed.
	// A namespace whose keys the service lacks is one it doesn't follow
	// (§A.4): no checkpoint will cover it.
	lacks := func(other string) bool { _, l := ix.keys.Skip(other); return l }
	for i, m := range q.Mins {
		switch {
		case m.NS == "":
			q.Mins[i].NS = ns
		case m.NS == ns:
		case !ix.known(m.NS) || lacks(m.NS):
			w.Header().Set("Cache-Control", "no-store")
			writeErr(w, http.StatusBadRequest, "bad_input", minElsewhere)
			return
		default:
			_, err := ix.access(ctx, m.NS, r)
			if client.IsPurged(err) {
				// A purged sealed namespace's document is 410 (§8.5):
				// the core makes the read check, as for ns above, and a
				// reader who passes goes to the current checkpoint, which
				// has reached the purge.
				_, err = ix.checker.PurgedRead(ctx, m.NS, bearer(r))
			}
			if err != nil {
				var ae *grant.AuthError
				w.Header().Set("Cache-Control", "no-store")
				if !errors.As(err, &ae) {
					ix.opt.Logf("index: access check for %s: %v", m.NS, err)
					writeErr(w, http.StatusBadGateway, "upstream", "cannot read the namespace configuration")
					return
				}
				writeErr(w, http.StatusBadRequest, "bad_input", minElsewhere)
				return
			}
		}
	}
	// target is the canonical URL of this query's result at an ns_id (§A.5):
	// what redirects name, what results are kept under, and in a sealed or
	// e2e namespace the view a result is bound to (§E.2.6).
	target := func(id string) string { return base(a, ns) + "/at/" + id + derived.CanonicalQuery(vals, "min") }
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
	}
	if cur == "" {
		writeBehind(w, "the index has not reached the namespace yet")
		return
	}
	// min always redirects (§A.5): an older at whose kept result already
	// includes every min to itself without min. The current at needs no
	// judging: the redirect to the current checkpoint below names the same
	// URL, with the result computed and kept there first.
	if isAt && len(q.Mins) > 0 && at != cur && ix.atIncludes(ctx, ns, at, q.Mins, target(at)) {
		setPtrHeaders()
		redirect(w, target(at))
		return
	}
	// Only the canonical form of an at URL is answered (§A.5), and never
	// one with min.
	canonical := r.URL.RequestURI() == target(at)
	if isAt && len(q.Mins) == 0 {
		// A kept result answers its at however far the checkpoint has
		// moved since (B9).
		if st, _, ok := ix.kept.Get(target(at)); ok {
			if !canonical {
				setPtrHeaders()
				redirect(w, target(at))
				return
			}
			ix.writeStored(w, r, a, at, st)
			return
		}
	}
	if !isAt || at != cur || len(q.Mins) > 0 {
		// Head pointer, an ns_id whose result isn't kept, or a min waited
		// for: redirect to the current checkpoint (§A.7's second question
		// resolved as redirect, as §A.4 shows; §A.5), with the result
		// computed there and kept, so the redirect is answered even if the
		// checkpoint moves on before it is followed. If it can't be
		// computed, the at URL says why.
		to := cur
		if _, _, ok := ix.kept.Get(target(cur)); !ok {
			if info, key, err := ix.keys.Current(ctx, ns); err == nil {
				var fe *FieldError
				if _, got, err := ix.answer(ctx, a, ns, vals, q, info, key); err == nil {
					to = got
				} else if !errors.As(err, &fe) && !errors.Is(err, errCounts) {
					ix.opt.Logf("index: query %s: %v", r.URL, err)
				}
			}
		}
		setPtrHeaders()
		redirect(w, target(to))
		return
	}
	if !canonical {
		setPtrHeaders()
		redirect(w, target(at))
		return
	}

	info, key, err := ix.keys.Current(ctx, ns)
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
	st, got, err := ix.answer(ctx, a, ns, vals, q, info, key)
	var fe *FieldError
	switch {
	case errors.As(err, &fe):
		writeErr(w, http.StatusBadRequest, "bad_input", fe.Error())
		return
	case errors.Is(err, errCounts):
		writeErr(w, http.StatusBadRequest, "bad_input", err.Error())
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
		// the result is kept at the new one.
		setPtrHeaders()
		redirect(w, target(got))
		return
	}
	ix.writeStored(w, r, a, at, st)
}

// errCounts refuses counts over a sealed namespace to a reader whose grant
// restricts resources (400): counts aggregate over resources, and such a
// reader may hold only per-resource keys.
var errCounts = errors.New("counts over a sealed namespace need a grant that reads the whole namespace")

// answer runs q at the current checkpoint in one read transaction, builds
// its result, sealed in a sealed or e2e namespace, keeps it (and stores a
// sealed one), and returns the result kept with the checkpoint it is at.
func (ix *Index) answer(ctx context.Context, a *access, ns string, vals url.Values, q *Query, info derived.Info, key derived.Key) (derived.Stored, string, error) {
	if info.Protected() && !a.all && len(q.Counts) > 0 {
		return derived.Stored{}, "", errCounts
	}
	var allow func(string) bool
	if !a.all {
		allow = func(resource string) bool { return ix.checker.AllowsRead(a.v, resource) }
	}
	gen := ix.kept.Generation(ns)
	res, at, err := ix.query(ctx, ns, q, allow)
	if err != nil {
		return derived.Stored{}, "", err
	}
	view := derived.View{NS: ns, Target: base(a, ns) + "/at/" + at + derived.CanonicalQuery(vals, "min")}
	body := map[string]any{"at": at, "ns": ns}
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
		if info.Protected() && !a.all {
			// Per-entry sealing: what the document gave (score, schema,
			// facets) under its resource's key; names, ids and URLs stay.
			values := map[string]any{}
			for k, v := range m {
				if k != "resource" && k != "id" && k != "url" {
					values[k] = v
				}
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
	st := derived.Stored{JSON: true, Tags: resultTags(ns, res)}
	if info.Protected() && a.all {
		var jwe string
		jwe, err = derived.SealView(key, view, body)
		st.Body, st.JSON = []byte(jwe), false
	} else {
		st.Body, err = derived.Marshal(body)
	}
	if err != nil {
		return derived.Stored{}, "", fmt.Errorf("encoding a result: %w", err)
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

// resultTags is a result's Cache-Tag.
func resultTags(ns string, res *Result) string {
	// §A.4: idx:{ns} for the namespace, r:{ns}/{name} for every resource
	// the result shows, so a purge of any of them removes it from caches
	// (Apply purges these). Facet counts aggregate values of hits beyond
	// the page too, so a result with counts also carries a counts tag
	// that every resource purge in the namespace clears.
	tags := []string{"idx:" + ns}
	for _, h := range res.Hits {
		tags = append(tags, "r:"+ns+"/"+h.Resource)
	}
	if res.Counts != nil {
		tags = append(tags, countsTag(ns))
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

// countsTag tags results with facet counts, which can reflect any resource
// of the namespace.
func countsTag(ns string) string { return "idx:" + ns + ":counts" }

// atIncludes reports whether the kept result of ns at an older at, which
// url names, already includes every min (§A.5 "min always redirects"),
// once waitMins has waited for them: each names ns (a min of another
// followed namespace never is: the result reflects ns alone) and is at
// itself, or an ns_id the core's log places before at (since=min is
// accepted only if min is in the chain up to at, §7.1). Only a kept
// result counts: an at whose result isn't kept is one the index no longer
// keeps results for, which redirects to the current checkpoint anyway
// (§A.4), and a redirect to it would not be answered (bounded redirects).
func (ix *Index) atIncludes(ctx context.Context, ns, at string, mins []MinRef, url string) bool {
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
		if !ix.waitMin(ctx, m.NS, m.ID, time.Until(deadline)) {
			return false
		}
	}
	return true
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
