package tree

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// The service's own edge grants (§B.11.5, §C.5), with Options.EdgeGrants.
//
// Listings read with a grant in Authorization are never cached at the edge
// (§9): the grant is one reader's. A catalog service's listing depends on
// the subject set alone, so an edge may cache it for everyone bound to
// that subject set, given a cookie it can verify that says so. The service
// mints such cookies itself, with a key and kid of its own that the origin
// never holds, for the prefix /{catalog}/g/{gs}, which covers the subject
// set's listings at every checkpoint, after resolving the caller's
// subjects exactly as listings do (viewer). The default format is the
// core's (edge.Cookies), so an edge in front of the service makes the
// same six checks with the service's kid, which vouches only for those
// prefixes.
//
//	POST   /edge-grants              exchange grants for cookies, as the
//	                                 core's issuance (§C.5)
//	DELETE /edge-grants?prefix=…     withdraw them (§C.5 "Withdrawing them")
//
// A cookie carries only kid, p and exp. A read under one is the subject
// set's, so the service keeps the subjects behind each gs it minted a
// cookie for (edge_subjects, kept across restarts and -rebuild, until the
// last such cookie expires); a gs it doesn't know, minted by another
// instance with its own database, is 401, and the reader exchanges again
// here. A g/all cookie is checked against every content namespace the
// catalog trusts at issue, and covers every later at, so a read at an at
// that includes a namespace trusted since is 403 (trustedSince). The
// edge can't make that check, and serves a cached listing to every g/all
// cookie, so no shared cache keeps a g/all listing at such an at until
// every cookie issued before that namespace was trusted has expired
// (edgeHold).

// maxEdgeGrants is how many grants one exchange takes in its body (§C.5).
const maxEdgeGrants = 50

// edgeClockSkew is how far an edge's clock may lag the service's: a
// cookie the service holds expired may still pass an edge's checks that
// long (edgeHold).
const edgeClockSkew = time.Minute

// Rate is a token bucket (§6.6): Rate refills it per second, up to Burst.
type Rate struct{ Rate, Burst float64 }

// DefaultExchangeRate is exchangeRate's default (§6.6): 10/s, burst 100.
var DefaultExchangeRate = Rate{Rate: 10, Burst: 100}

// exchangeBuckets are the exchangeRate buckets of the service's exchange
// (§C.5, §6.6), one per principal, keyed as the core keys write buckets:
// the principal and the kid of its grant's key. They are the process's
// own: each instance of the service draws on its own.
type exchangeBuckets struct {
	mu sync.Mutex
	b  map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// maxIdleBuckets is how many buckets are held before full ones are
// dropped: a full bucket is the same as none.
const maxIdleBuckets = 4096

// admit draws one token from the bucket of each key if each holds one,
// and otherwise draws none and returns the wait until the emptiest
// refills one.
func (e *exchangeBuckets) admit(now time.Time, r Rate, keys []string) (time.Duration, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.b == nil {
		e.b = map[string]*tokenBucket{}
	}
	refill := func(b *tokenBucket) {
		if el := now.Sub(b.last); el > 0 {
			b.tokens = math.Min(r.Burst, b.tokens+el.Seconds()*r.Rate)
			b.last = now
		}
	}
	if len(e.b) > maxIdleBuckets {
		for k, b := range e.b {
			if refill(b); b.tokens >= r.Burst {
				delete(e.b, k)
			}
		}
	}
	var wait time.Duration
	bs := make([]*tokenBucket, len(keys))
	for i, k := range keys {
		b := e.b[k]
		if b == nil {
			b = &tokenBucket{tokens: r.Burst, last: now}
			e.b[k] = b
		}
		refill(b)
		bs[i] = b
		if b.tokens < 1 {
			wait = max(wait, time.Duration((1-b.tokens)/r.Rate*float64(time.Second)))
		}
	}
	if wait > 0 {
		return wait, false
	}
	for _, b := range bs {
		b.tokens--
	}
	return 0, true
}

// edgeSubjects is a subject set behind a gs, and the expiry of the last
// edge grant the service minted for it.
type edgeSubjects struct {
	subjects []string
	exp      int64
}

// edgePrefix is the prefix of the edge grants of a subject set: its
// listings at every at (§B.11.5).
func (s *Service) edgePrefix(gs string) string { return "/" + s.opt.Catalog + "/g/" + gs }

// edgeGS is the subject set of one of the service's prefixes,
// /{catalog}/g/{gs} with gs AllSubjects or an id: the only prefixes its
// key vouches for (§C.5 "Format").
func (s *Service) edgeGS(p string) (string, bool) {
	gs, ok := strings.CutPrefix(p, "/"+s.opt.Catalog+"/g/")
	if !ok {
		return "", false
	}
	if gs != AllSubjects {
		if _, err := ids.Parse(gs); err != nil {
			return "", false
		}
	}
	return gs, true
}

// serveEdgeGrants is /edge-grants on the service's origin: POST issues,
// DELETE withdraws. Either is no-store. Without EdgeGrants, both are
// 404 not_offered.
func (s *Service) serveEdgeGrants(w http.ResponseWriter, r *http.Request) {
	telemetry.SetRoute(r, "/edge-grants")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method != http.MethodPost && r.Method != http.MethodDelete:
		w.Header().Set("Allow", "POST, DELETE")
		WriteError(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
	case s.opt.EdgeGrants == nil:
		WriteError(w, http.StatusNotFound, "not_offered", "this service mints no edge grants")
	case r.Method == http.MethodDelete:
		s.withdrawEdgeGrants(w, r)
	default:
		s.issueEdgeGrants(w, r)
	}
}

// issueEdgeGrants is POST /edge-grants (§B.11.5, following §C.5's
// issuance): with the grant in Authorization, or 1 to maxEdgeGrants grants
// as { "grants": [ … ] } in an application/json body (415 otherwise), it
// answers 200 { prefixes, exp } and one Set-Cookie per prefix. Each grant
// is resolved as a listing resolves its reader (viewer): the prefix is
// /{catalog}/g/{gs} of its subject set, lasting until that grant's exp or
// the cookies' TTL (15 minutes at most), whichever is sooner, or
// /{catalog}/g/all for a reader with namespace-wide read on the catalog
// and every content namespace it trusts, lasting until the earliest of
// those grants. A prefix several grants give gets one cookie, lasting as
// long as the longest, and exp is the earliest. It answers all or
// nothing: if any grant is refused, the request is 401 if any is 401,
// else 403, and 502 if a namespace document can't be read. Once nothing
// is refused, it draws one token from the exchangeRate bucket of each
// distinct principal among the grants (ExchangeRate, §6.6), and is 429
// (code "rate", limit "exchangeRate", with Retry-After) while any is
// empty. While the core's authentication is disabled (§1), it is 404
// not_offered, before the body is read; it takes no query parameter
// (400, as the core's, §7). Cookies are Secure, HttpOnly and SameSite as
// EdgeGrants says (None with credentialed origins, -cors-credentials-
// origin, else Lax).
func (s *Service) issueEdgeGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	root, err := s.c.Root(ctx)
	if err != nil {
		s.opt.Logf("tree: reading the core's root: %v", err)
		WriteError(w, http.StatusBadGateway, "upstream", "cannot read the core's root")
		return
	}
	if root.AuthDisabled() {
		WriteError(w, http.StatusNotFound, "not_offered", "the core runs with authentication disabled: there are no edge grants (§C.5)")
		return
	}
	if r.URL.RawQuery != "" {
		WriteError(w, http.StatusBadRequest, "bad_input", "POST /edge-grants takes no query parameters (§7)")
		return
	}
	bearers, status, msg := edgeGrantBearers(r)
	if status != 0 {
		WriteError(w, status, "bad_input", msg)
		return
	}
	if len(bearers) == 0 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		WriteError(w, http.StatusUnauthorized, "unauthenticated", "missing grant")
		return
	}
	// Taken before any viewer reads the trust list, so a g/all cookie's
	// earliest issue (allNotBefore) is never after the trust it was
	// checked against.
	now := s.opt.Now()
	var (
		vs      []*viewer
		refusal *grant.AuthError
		upErr   error
	)
	for _, b := range bearers {
		v, err := s.grantViewer(ctx, b)
		var ae *grant.AuthError
		switch {
		case errors.As(err, &ae):
			if refusal == nil || ae.Status == http.StatusUnauthorized && refusal.Status != http.StatusUnauthorized {
				refusal = ae
			}
		case err != nil:
			upErr = err
		default:
			vs = append(vs, v)
		}
	}
	switch {
	case refusal != nil:
		WriteAuthError(w, refusal, s.opt.Logf)
		return
	case upErr != nil:
		WriteAuthError(w, upErr, s.opt.Logf)
		return
	}
	// One token per request, from each distinct principal's bucket,
	// however many grants it carries (§C.5, v0.52).
	var keys []string
	for _, v := range vs {
		if !slices.Contains(keys, v.bucket) {
			keys = append(keys, v.bucket)
		}
	}
	if wait, ok := s.exchanges.admit(now, s.opt.ExchangeRate, keys); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(max(int(math.Ceil(wait.Seconds())), 1)))
		WriteJSON(w, http.StatusTooManyRequests, map[string]any{"code": "rate", "message": "rate limit exceeded",
			"limit": "exchangeRate", "retryAfter": math.Ceil(wait.Seconds()*1000) / 1000})
		return
	}
	var prefixes []string
	exps := map[string]time.Time{}
	subjects := map[string][]string{}
	for _, v := range vs {
		exp := s.opt.EdgeGrants.Lifetime(now, v.idExp)
		if v.gs == AllSubjects {
			exp = s.opt.EdgeGrants.Lifetime(now, v.exp)
		} else {
			subjects[v.gs] = v.subjects
		}
		p := s.edgePrefix(v.gs)
		old, ok := exps[p]
		if !ok {
			prefixes = append(prefixes, p)
		}
		if !ok || exp.After(old) {
			exps[p] = exp
		}
	}
	if exp, ok := exps[s.edgePrefix(AllSubjects)]; ok {
		exps[s.edgePrefix(AllSubjects)] = s.allExp(now, exp)
	}
	for gs, subs := range subjects {
		if err := s.recordSubjects(ctx, gs, subs, exps[s.edgePrefix(gs)], now); err != nil {
			s.opt.Logf("tree: recording a subject set: %v", err)
			WriteError(w, http.StatusInternalServerError, "internal", "cannot record the subject set")
			return
		}
	}
	var first time.Time
	for _, p := range prefixes {
		http.SetCookie(w, s.opt.EdgeGrants.Issue(edge.Claims{Prefix: p, Exp: exps[p].Unix()}, now))
		if first.IsZero() || exps[p].Before(first) {
			first = exps[p]
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"prefixes": prefixes, "exp": first.UTC().Format(time.RFC3339)})
}

// edgeGrantBearers are the grants an exchange takes (§C.5): those of a
// body { "grants": [ … ] }, 1 to maxEdgeGrants tokens as they would follow
// "Bearer ", which takes no Authorization; without a body, the grant in
// Authorization, if any. The body must be application/json (415
// otherwise): a cross-site form can send text/plain without a CORS
// preflight, and would set cookies of its own grant in the reader's
// browser. status is non-zero for a request it refuses.
func edgeGrantBearers(r *http.Request) (bearers []string, status int, msg string) {
	const max = 8 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	switch {
	case err != nil:
		return nil, http.StatusBadRequest, "cannot read the body"
	case len(body) > max:
		return nil, http.StatusRequestEntityTooLarge, "body too large"
	case len(body) == 0:
		if b := Bearer(r); b != "" {
			return []string{b}, 0, ""
		}
		return nil, 0, ""
	case r.Header.Get("Authorization") != "":
		return nil, http.StatusBadRequest, "grants in the body take no Authorization (§C.5)"
	}
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		return nil, http.StatusUnsupportedMediaType, "use application/json"
	}
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, http.StatusBadRequest, "malformed body"
	}
	m, _ := v.(map[string]any)
	gs, ok := m["grants"].([]any)
	if !ok || len(m) != 1 || len(gs) < 1 || len(gs) > maxEdgeGrants {
		return nil, http.StatusBadRequest, fmt.Sprintf("body must be { grants: [ … ] }, 1 to %d grants (§C.5)", maxEdgeGrants)
	}
	for _, g := range gs {
		t, ok := g.(string)
		if !ok || strings.TrimSpace(t) == "" {
			return nil, http.StatusBadRequest, "each grant is a string: the token as it would follow \"Bearer \" (§C.5)"
		}
		bearers = append(bearers, strings.TrimSpace(t))
	}
	return bearers, 0, ""
}

// withdrawEdgeGrants is DELETE /edge-grants?prefix=… (§C.5 "Withdrawing
// them"): 204 with an expired Set-Cookie of the same name and attributes
// for each prefix named, once even if named twice. prefix is its only
// parameter, repeatable, and each must be one of the service's,
// /{catalog}/g/{gs} (400 otherwise): the core's DELETE /edge-grants takes
// only core prefixes, so the service withdraws its own. It needs no grant,
// since it only narrows, and answers the same while authentication is
// disabled; its preflight is allowed only for credentialed origins
// (internal/cors).
func (s *Service) withdrawEdgeGrants(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "bad_input", "malformed query string")
		return
	}
	var prefixes []string
	seen := map[string]bool{}
	for k, vs := range q {
		if k != "prefix" {
			WriteError(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("unknown query parameter %q", k))
			return
		}
		for _, p := range vs {
			if _, ok := s.edgeGS(p); !ok {
				WriteError(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("prefix %q isn't one this service issues: /%s/g/{gs} (§B.11.5)", p, s.opt.Catalog))
				return
			}
			if !seen[p] {
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
	}
	if len(prefixes) == 0 {
		WriteError(w, http.StatusBadRequest, "bad_input", "prefix is required (§C.5)")
		return
	}
	for _, p := range prefixes {
		http.SetCookie(w, s.opt.EdgeGrants.Withdraw(p))
	}
	w.WriteHeader(http.StatusNoContent)
}

// edgeViewer is the viewer of a read under one of the service's edge
// grants, cl, which covers the read's path (§B.11.5): the subject set of
// its prefix, read as a listing for any grant resolving to it would be,
// with no grant at all. So namespace-wide reads beyond the public
// namespaces don't count (problems, orphans and manifests need them in a
// subject set's URL space). Under g/all, the catalog and every trusted
// content namespace are read whole, and listings are kept no longer than
// the cookie; at an at including a namespace trusted since its issue the
// read is 403 (serve, trustedSince). A namespace that was public at issue
// and has turned private since is still read whole under it until it
// expires, as under a grant revoked since: the cookie's lifetime is the
// revocation latency (§C.5). A subject set the service doesn't know is
// 401.
func (s *Service) edgeViewer(ctx context.Context, cl *edge.Claims) (*viewer, error) {
	gs, _ := s.edgeGS(cl.Prefix)
	// As grantViewer; a catalog service is never a release preview (Open),
	// so actual is the namespace itself.
	cfg, err := s.checker.Config(ctx, s.actual(s.opt.Catalog))
	if err != nil {
		return nil, err
	}
	catPublic := cfg.Read == "public"
	var notBefore time.Time
	if gs == AllSubjects {
		notBefore = s.allNotBefore(cl.Exp)
	}
	var trust, checked []string
	s.View(func(g *Graph, _ map[string]string) {
		for ns := range g.Trust {
			trust = append(trust, ns)
			if since, ok := s.trusted[ns]; ok && since.Before(notBefore) {
				checked = append(checked, ns)
			}
		}
	})
	v := &viewer{gs: gs, contentAll: map[string]bool{}, wideNS: map[string]bool{}, wideGrant: map[string]bool{}}
	if gs == AllSubjects {
		// What the cookie was checked against: the catalog, and every
		// namespace trusted before its issue. A listing at an at
		// including another is refused (trustedSince), and one kept
		// from before the catalog trusted it is served.
		v.catAll, v.wideCat = true, true
		for _, ns := range checked {
			v.contentAll[ns], v.wideNS[ns] = true, true
		}
		v.exp, v.wideExp, v.notBefore = time.Unix(cl.Exp, 0), time.Unix(cl.Exp, 0), notBefore
		return v, nil
	}
	subs, ok := s.subjectsOf(ctx, gs)
	if !ok {
		return nil, &grant.AuthError{Status: 401, Msg: "an edge grant for a subject set this service doesn't know: exchange the grant again"}
	}
	v.catAll, v.wideCat, v.subjects = catPublic, catPublic, subs
	for _, ns := range trust {
		if c, err := s.checker.Config(ctx, s.actual(ns)); err == nil && c.Read == "public" {
			v.contentAll[ns], v.wideNS[ns] = true, true
		}
	}
	v.vis = s.opt.RoleView.ForSubjects(subs)
	return v, nil
}

// recordSubjects records the subjects behind gs, for an edge grant
// minted at now that expires at exp, and drops the records whose last
// edge grant has expired.
func (s *Service) recordSubjects(ctx context.Context, gs string, subjects []string, exp, now time.Time) error {
	b, err := json.Marshal(subjects)
	if err != nil {
		return err
	}
	s.emu.Lock()
	defer s.emu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM edge_subjects WHERE exp <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO edge_subjects (gs, subjects, exp) VALUES (?, ?, ?)
		ON CONFLICT (gs) DO UPDATE SET subjects = excluded.subjects, exp = max(exp, excluded.exp)`, gs, string(b), exp.Unix()); err != nil {
		return err
	}
	if s.edgeSubs == nil {
		s.edgeSubs = map[string]edgeSubjects{}
	}
	for k, e := range s.edgeSubs {
		if e.exp <= now.Unix() {
			delete(s.edgeSubs, k)
		}
	}
	e := s.edgeSubs[gs]
	s.edgeSubs[gs] = edgeSubjects{subjects: subjects, exp: max(e.exp, exp.Unix())}
	return nil
}

// subjectsOf is the subjects behind gs, recorded when an edge grant for it
// was minted.
func (s *Service) subjectsOf(ctx context.Context, gs string) ([]string, bool) {
	s.emu.Lock()
	defer s.emu.Unlock()
	if e, ok := s.edgeSubs[gs]; ok {
		return e.subjects, true
	}
	var text string
	var exp int64
	if err := s.db.QueryRowContext(ctx, `SELECT subjects, exp FROM edge_subjects WHERE gs = ?`, gs).Scan(&text, &exp); err != nil {
		return nil, false
	}
	var subs []string
	if json.Unmarshal([]byte(text), &subs) != nil {
		return nil, false
	}
	if s.edgeSubs == nil {
		s.edgeSubs = map[string]edgeSubjects{}
	}
	s.edgeSubs[gs] = edgeSubjects{subjects: subs, exp: exp}
	return subs, true
}

// allExp is the exp of a g/all edge grant issued at now to last until exp,
// recorded so a read under it can tell when it was issued (allNotBefore).
// Two cookies with the same prefix and exp are the same bytes, so while
// one with exp was issued no later than a namespace the catalog trusts
// now became trusted, a new one would be refused with it: it gets the
// second before instead. Without EdgeGrantsOwnKey nothing is recorded,
// since a record wouldn't be relied on.
func (s *Service) allExp(now, exp time.Time) time.Time {
	if !s.opt.EdgeGrantsOwnKey {
		return exp
	}
	s.mu.RLock()
	var latest time.Time
	for _, t := range s.trusted {
		if t.After(latest) {
			latest = t
		}
	}
	s.mu.RUnlock()
	s.emu.Lock()
	defer s.emu.Unlock()
	if s.allIssued == nil {
		s.allIssued = map[int64]time.Time{}
	}
	for e := range s.allIssued {
		// Kept as long as an edge may still take it (edgeHold).
		if !now.Before(time.Unix(e, 0).Add(edgeClockSkew)) {
			delete(s.allIssued, e)
		}
	}
	e := exp.Unix()
	for ; e > now.Unix()+1; e-- {
		if t, ok := s.allIssued[e]; !ok || t.After(latest) {
			break
		}
	}
	if t, ok := s.allIssued[e]; !ok || now.Before(t) {
		s.allIssued[e] = now
	}
	return time.Unix(e, 0)
}

// allNotBefore is the earliest a g/all edge grant expiring at exp may have
// been issued. A cookie carries only kid, p and exp, so every g/all cookie
// with that exp is the same bytes, whoever it was issued to and whenever:
// the process's record of the first issue (allExp) is relied on only
// with EdgeGrantsOwnKey, when no cookie under the key was minted before
// Open or by another instance. Otherwise, and without a record, it is exp
// less the cookies' longest lifetime. That is conservative: a cookie
// capped by an earlier grant's exp counts as issued earlier than it was,
// so it is refused at an at that includes a namespace trusted in the last
// minutes before its issue too, and its reader exchanges again once the
// namespace has been trusted that long.
func (s *Service) allNotBefore(exp int64) time.Time {
	if s.opt.EdgeGrantsOwnKey {
		s.emu.Lock()
		t, ok := s.allIssued[exp]
		s.emu.Unlock()
		if ok {
			return t
		}
	}
	return time.Unix(exp, 0).Add(-s.opt.EdgeGrants.MaxTTL())
}

// atTrust is when the catalog came to trust each content namespace that a
// listing at at includes (ok false for one without a record): those of
// the current at, cur, or those recorded for a kept one (recordAt); any
// other at is redirected to cur. A namespace at includes that the catalog
// no longer trusts has no record: when it became trusted is no longer
// known.
func (s *Service) atTrust(at, cur string) []trustTime {
	var nss []string
	s.amu.Lock()
	rec, ok := s.ats[at]
	s.amu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ok && at != cur {
		for ns := range rec.cps {
			if ns != s.opt.Catalog {
				nss = append(nss, ns)
			}
		}
	} else {
		for ns := range s.g.Trust {
			nss = append(nss, ns)
		}
	}
	sort.Strings(nss)
	out := make([]trustTime, len(nss))
	for i, ns := range nss {
		since, ok := s.trusted[ns]
		out[i] = trustTime{ns, since, ok}
	}
	return out
}

// trustTime is when the catalog came to trust ns, if ok.
type trustTime struct {
	ns    string
	since time.Time
	ok    bool
}

// trustedSince names a content namespace that a listing at at, for v
// under a g/all edge grant, would include but that grant wasn't checked
// against, because the catalog came to trust it no earlier than
// v.notBefore (§B.11.5), or "" if there is none or v isn't under a g/all
// edge grant. At the very instant of its issue, it can't be told whether
// the exchange read the trust list before or after: that counts as after.
// A namespace without a record (atTrust) counts as trusted since.
func (s *Service) trustedSince(v *viewer, at, cur string) string {
	if v.notBefore.IsZero() {
		return ""
	}
	for _, t := range s.atTrust(at, cur) {
		if !t.ok || !t.since.Before(v.notBefore) {
			return t.ns
		}
	}
	return ""
}

// edgeHold reports whether no shared cache may keep v's listing at at,
// because at includes a namespace the catalog came to trust so recently
// that a g/all edge grant issued before it may still be live (§B.11.5).
// The service refuses such a cookie there (trustedSince), but an edge
// serves a listing it holds to every cookie passing its six checks, and
// can't tell a cookie checked against that namespace from one that
// wasn't. So while an earlier g/all cookie may be live, at the service's
// clock and at an edge's lagging by up to edgeClockSkew, a g/all listing
// including the namespace is no-store at the edge, whoever reads it.
// With EdgeGrantsOwnKey the service knows every g/all cookie it issued
// (allExp), and holds only while one issued no later than the namespace
// became trusted is live; otherwise, for the cookies' longest lifetime
// after it. A namespace without a record (atTrust) counts as just
// trusted.
func (s *Service) edgeHold(v *viewer, at, cur string) bool {
	if s.opt.EdgeGrants == nil || v.gs != AllSubjects {
		return false
	}
	now := s.opt.Now()
	var issued []time.Time // the first issues of the g/all cookies that may be live
	if s.opt.EdgeGrantsOwnKey {
		s.emu.Lock()
		for e, t := range s.allIssued {
			if now.Before(time.Unix(e, 0).Add(edgeClockSkew)) {
				issued = append(issued, t)
			}
		}
		s.emu.Unlock()
	}
	// A cookie issued at since lives until since+MaxTTL at the latest, a
	// second more for exp's truncation.
	window := s.opt.EdgeGrants.MaxTTL() + time.Second + edgeClockSkew
	for _, t := range s.atTrust(at, cur) {
		if !s.opt.EdgeGrantsOwnKey {
			if !t.ok || now.Before(t.since.Add(window)) {
				return true
			}
			continue
		}
		for _, i := range issued {
			if !t.ok || !i.After(t.since) {
				return true
			}
		}
	}
	return false
}

// loadTrusted reads when the catalog came to trust each namespace (meta
// "trusted:{ns}", Unix nanoseconds), and records now for any it trusts
// without a record: a new database, or one rebuilt.
func (s *Service) loadTrusted(ctx context.Context) error {
	if s.opt.EdgeGrants == nil {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT substr(k, 9), v FROM meta WHERE k LIKE 'trusted:%'`)
	if err != nil {
		return err
	}
	s.trusted = map[string]time.Time{}
	for rows.Next() {
		var ns, v string
		if err := rows.Scan(&ns, &v); err != nil {
			rows.Close()
			return err
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			s.trusted[ns] = time.Unix(0, n)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	s.noteTrust(ctx)
	return nil
}

// noteTrust brings the record of when each namespace became trusted in
// line with the graph's trust list: now for one newly trusted, nothing
// for one no longer trusted. Called with mu held for writing, in the
// same critical section as the graph that changed the list is published,
// so an exchange that read the old list (allExp) sees the old record.
func (s *Service) noteTrust(ctx context.Context) {
	if s.opt.EdgeGrants == nil {
		return
	}
	if s.trusted == nil {
		s.trusted = map[string]time.Time{}
	}
	now := s.opt.Now()
	for ns := range s.trusted {
		if !s.g.Trust[ns] {
			delete(s.trusted, ns)
			if _, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE k = ?`, "trusted:"+ns); err != nil {
				s.opt.Logf("tree: forgetting when %s became trusted: %v", ns, err)
			}
		}
	}
	for ns := range s.g.Trust {
		if _, ok := s.trusted[ns]; ok {
			continue
		}
		s.trusted[ns] = now
		// Unrecorded, a restart records a later time: more refusals,
		// never fewer.
		if _, err := s.db.ExecContext(ctx, `INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
			"trusted:"+ns, strconv.FormatInt(now.UnixNano(), 10)); err != nil {
			s.opt.Logf("tree: recording when %s became trusted: %v", ns, err)
		}
	}
}
