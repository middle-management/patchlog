package index

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
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

// Cache-Control values (§9).
const (
	ccHeadPointer = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccImmutable   = "public, max-age=86400, s-maxage=31536000, immutable"
	ccPrivatePtr  = "private, no-cache"
	ccPrivateImm  = "private, max-age=300"
	cdnImmutable  = "max-age=31536000"
)

var validNS = client.ValidNSName

// Handler returns the query API (§A.4):
//
//	GET /{ns}?…                   302 → /{ns}/at/{checkpoint}?…            (head pointer)
//	GET /{ns}/at/{ns_id}?…        200 { at, ns, hits, next?, counts? }       (immutable,
//	                              tagged idx:{ns} and r:{ns}/{name} per hit)
//	                              302 → current checkpoint if ns_id is not current
//	GET /g/{gs}/{ns}?…            private namespaces: as above, keyed by the
//	GET /g/{gs}/{ns}/at/{ns_id}?… reader's subject set gs (§B.11.5)
//
// Only the current checkpoint's results are kept: the index holds current
// state only (§A.3), so every older ns_id is one "the service no longer
// keeps results for" and is redirected (head-pointer class) to the current
// one (§A.4). A result served at an ns_id never changes while it is served,
// and a purge removes it from caches through its r: tags.
//
// Private namespaces need Authorization: Bearer <grant>; a request without
// the right gs is redirected to it.
//
// Sealed and e2e namespaces (§E.2.5, §E.2.6; package derived). A result
// has one source, so a reader of the whole namespace gets it sealed as one
// JWE under the namespace's current epoch key, Content-Type
// application/jose, pl { ns, view } where view is the result's request
// target (/[g/{gs}/]{ns}/at/{ns_id}?{query}; an at URL whose query isn't in
// the canonical form the redirects give is redirected to it). A reader
// whose grant restricts resources may hold only per-resource keys, so it
// gets JSON { at, ns, hits, next? } in which each hit keeps resource, id
// and url in the clear and carries its score, schema and facets as
// "sealed": JWE under its resource's K_r, pl { ns, name, view }; counts,
// which aggregate over resources, are refused (400) for such readers.
// Sealed results are produced once per view (so per epoch: a rotation
// moves the checkpoint), stored in the database with their cache tags, and
// served unchanged, across restarts, until a purge with one of those tags
// or the next checkpoint retires them (derived.Cache).
//
//	GET /_status                  each followed namespace's encryption level and
//	                              epoch, whether results are sealed, and why a
//	                              namespace is skipped
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
		ix.serveStatus(w)
		return
	case len(segs) == 1 && segs[0] != "":
		ns = segs[0]
	case len(segs) == 3 && segs[1] == "at":
		ns, at, isAt = segs[0], segs[2], true
	case len(segs) == 3 && segs[0] == "g":
		gs, ns = segs[1], segs[2]
	case len(segs) == 5 && segs[0] == "g" && segs[3] == "at":
		gs, ns, at, isAt = segs[1], segs[2], segs[4], true
	default:
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !client.ValidNSName(ns) || !ix.known(ns) {
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
	a := &access{v: v, all: ix.checker.ReadsAll(v)}
	if a.all && !ix.checker.AllowsRead(v, "") {
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
	return "/g/" + a.gs + "/" + ns
}

// encodeQuery encodes the query canonically (sorted keys), without min.
func encodeQuery(v url.Values, drop ...string) string {
	c := url.Values{}
	for k, vals := range v {
		c[k] = vals
	}
	for _, d := range drop {
		delete(c, d)
	}
	s := c.Encode()
	if s == "" {
		return ""
	}
	return "?" + s
}

func (ix *Index) serve(w http.ResponseWriter, r *http.Request, gs, ns, at string, isAt bool) {
	ctx := r.Context()
	if _, purged, _ := ix.state(ns); purged {
		writeErr(w, http.StatusGone, "gone", "namespace purged")
		return
	}
	if reason := ix.keys.Skipped(ns); reason != "" {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusServiceUnavailable, "skipped", "the index does not consume this namespace: "+reason)
		return
	}
	vals := r.URL.Query()
	q, err := ParseQuery(vals)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_input", err.Error())
		return
	}
	a, err := ix.access(ctx, ns, r)
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
	// Behind a verifying edge, private reads must come through it (§9).
	if !ix.opt.Edge.Allow(r, a.public) {
		w.Header().Set("Cache-Control", "no-store")
		writeErr(w, http.StatusForbidden, edge.Code, edge.Message)
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
	// The reader's URL space: public, or keyed by its subject set.
	if gs != a.gs {
		target := base(a, ns)
		if isAt {
			target += "/at/" + at
		}
		setPtrHeaders()
		redirect(w, target+encodeQuery(vals))
		return
	}
	for i, m := range q.Mins {
		if m.NS == "" {
			q.Mins[i].NS = ns
		} else if !ix.known(m.NS) {
			w.Header().Set("Cache-Control", "no-store")
			writeErr(w, http.StatusBadRequest, "bad_input", "min names a namespace the service does not follow")
			return
		}
	}
	if !ix.waitMins(ctx, q.Mins) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "behind", "the index has not reached min yet")
		return
	}
	// The committed checkpoint, not the in-memory one: Apply publishes the
	// latter just after its commit, and queries read the committed rows. A
	// redirect decided by one and a read by the other made the head pointer
	// and at URLs alternate between the old and the new at while an apply
	// sat between the two (e.g. in a slow purger), and sent ?min= readers
	// to a checkpoint behind min, which seen (committed with it) had passed.
	// The committed checkpoint only moves forward, so every redirect does.
	cur, err := ix.committed(ctx, ns)
	if err != nil {
		ix.opt.Logf("index: checkpoint of %s: %v", ns, err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot read the checkpoint")
		return
	}
	if cur == "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "behind", "the index has not reached the namespace yet")
		return
	}
	if !isAt || at != cur {
		// Head pointer, or a stale ns_id: redirect to the current checkpoint
		// (§A.7's second question resolved as redirect, as §A.4 shows).
		setPtrHeaders()
		redirect(w, base(a, ns)+"/at/"+cur+encodeQuery(vals, "min"))
		return
	}

	info, key, err := ix.keys.Current(ctx, ns)
	if err != nil {
		ix.opt.Logf("index: keys of %s: %v", ns, err)
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "keys", "the index cannot obtain the key that seals results of this namespace")
		return
	}
	var view derived.View
	if info.Protected() {
		// view binds the result to its URL (§E.2.6): only the canonical
		// form is served.
		view = derived.View{NS: ns, Target: base(a, ns) + "/at/" + at + encodeQuery(vals, "min")}
		if r.URL.RequestURI() != view.Target {
			setPtrHeaders()
			redirect(w, view.Target)
			return
		}
		if !a.all && len(q.Counts) > 0 {
			writeErr(w, http.StatusBadRequest, "bad_input", "counts over a sealed namespace need a grant that reads the whole namespace")
			return
		}
		if st, ok := ix.sealed.Get(ctx, view.Target); ok {
			ix.writeSealed(w, a, at, st)
			return
		}
	}

	var allow func(string) bool
	if !a.all {
		allow = func(resource string) bool { return ix.checker.AllowsRead(a.v, resource) }
	}
	res, got, err := ix.query(ctx, ns, at, q, allow)
	var fe *FieldError
	if errors.As(err, &fe) {
		writeErr(w, http.StatusBadRequest, "bad_input", fe.Error())
		return
	}
	if err != nil {
		ix.opt.Logf("index: query %s: %v", r.URL, err)
		writeErr(w, http.StatusInternalServerError, "internal", "query failed")
		return
	}
	if got != at {
		// The checkpoint moved between the check and the read transaction.
		setPtrHeaders()
		redirect(w, base(a, ns)+"/at/"+got+encodeQuery(vals, "min"))
		return
	}
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
				ix.opt.Logf("index: sealing a hit: %v", err)
				writeErr(w, http.StatusInternalServerError, "internal", "sealing failed")
				return
			}
			m = map[string]any{"resource": m["resource"], "id": m["id"], "url": m["url"], "sealed": jwe}
		}
		hits = append(hits, m)
	}
	body["hits"] = hits
	if res.More {
		nv := url.Values{}
		for k, v := range vals {
			nv[k] = v
		}
		nv.Set("after", strconv.Itoa(q.After+len(res.Hits)))
		body["next"] = base(a, ns) + "/at/" + at + encodeQuery(nv, "min")
	}
	if res.Counts != nil {
		body["counts"] = res.Counts
	}
	tags := resultTags(ns, res)
	if info.Protected() {
		var b []byte
		if a.all {
			jwe, err := derived.SealView(key, view, body)
			if err != nil {
				ix.opt.Logf("index: sealing a result: %v", err)
				writeErr(w, http.StatusInternalServerError, "internal", "sealing failed")
				return
			}
			b = []byte(jwe)
		} else if b, err = derived.Marshal(body); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "encoding failed")
			return
		}
		st, err := ix.sealed.Put(ctx, view.Target, ns, at, derived.Stored{Body: b, JSON: !a.all, Tags: tags})
		if err != nil {
			ix.opt.Logf("index: storing a sealed result: %v", err)
		}
		if now, err := ix.committed(ctx, ns); err == nil && now != at {
			// An apply (maybe a purge) committed meanwhile: don't keep a
			// result it may have retired.
			if err := ix.sealed.Retire(ctx, ix.db, ns, now); err != nil {
				ix.opt.Logf("index: retiring sealed results of %s: %v", ns, err)
			}
		}
		ix.writeSealed(w, a, at, st)
		return
	}
	ix.setResultHeaders(w, a, at, tags)
	writeJSON(w, http.StatusOK, body)
}

func (ix *Index) setResultHeaders(w http.ResponseWriter, a *access, at, tags string) {
	if a.public {
		w.Header().Set("Cache-Control", ccImmutable)
	} else {
		w.Header().Set("Cache-Control", ccPrivateImm)
		ix.opt.Edge.Private(w.Header(), cdnImmutable)
	}
	w.Header().Set("Cache-Tag", tags)
	w.Header().Set("X-Namespace-Revision", at)
}

// writeSealed writes a stored sealed result: the JWE (application/jose),
// or for a resource-restricted reader the JSON with per-hit sealed values,
// with the Cache-Tag it was stored with.
func (ix *Index) writeSealed(w http.ResponseWriter, a *access, at string, st derived.Stored) {
	ix.setResultHeaders(w, a, at, st.Tags)
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
// skipped if it is.
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

// query runs q in one read transaction and returns the checkpoint it read
// at; if that isn't at, the result is nil and the caller redirects.
func (ix *Index) query(ctx context.Context, ns, at string, q *Query, allow func(string) bool) (*Result, string, error) {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var got string
	if err := tx.QueryRowContext(ctx, `SELECT ns_id FROM checkpoints WHERE origin = ? AND ns = ?`, ix.origin, ns).Scan(&got); err != nil {
		return nil, "", err
	}
	if got != at {
		return nil, got, nil
	}
	res, err := ix.run(ctx, tx, ns, q, allow)
	return res, got, err
}

// committed returns the checkpoint of ns the database holds ("" if none):
// what queries read. It is at or past the in-memory one (Checkpoint), which
// Apply publishes after its commit.
func (ix *Index) committed(ctx context.Context, ns string) (string, error) {
	var id string
	err := ix.db.QueryRowContext(ctx, `SELECT ns_id FROM checkpoints WHERE origin = ? AND ns = ?`, ix.origin, ns).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// countsTag tags results with facet counts, which can reflect any resource
// of the namespace.
func countsTag(ns string) string { return "idx:" + ns + ":counts" }

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

func redirect(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
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
