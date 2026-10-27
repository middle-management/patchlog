package index

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/rules"
	"github.com/middle-management/patchlog/internal/svcedge"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// The service's own edge grants (§A.4: a gs and its URLs are served as in
// §B.11.5; §C.5), with Options.EdgeGrants.
//
// Results read with a grant in Authorization are never cached at the edge
// (§9): the grant is one reader's. A private result depends on the
// reader's subject set alone (its markers, Index.access), so an edge may
// cache it for every reader of that subject set, given a cookie it can
// verify that says so. The service mints such cookies itself, with a key
// and kid of its own that the origin never holds, for the prefixes of a
// subject set's URLs: /{ns}/g/{gs} for a private namespace's results, gs
// over the reader's marker there, and /_refs/g/{gs} for the answers
// across namespaces, gs over its markers in every namespace it may see
// that the service has reached (refsReader). The default format is the
// core's (edge.Cookies), so an edge in front of the service makes the
// same six checks with the service's kid, which vouches only for those
// prefixes. A namespace named r or ns gets no cookie for its results,
// whose prefix would lie under the core's.
//
//	POST   /edge-grants              exchange grants for cookies, as the
//	                                 core's issuance (§C.5.2)
//	DELETE /edge-grants?prefix=…     withdraw them (§C.5.4)
//
// A cookie carries only kid, p and exp. A read under one is the subject
// set's, so the service keeps the markers behind each gs it minted a
// cookie for (svcedge.Store: edge_subjects), and, for a marker
// reads:{ns}:scope:{digest}, what its digest covers, the rules that limit
// the reads and the /principal values they refer to (edge_filters,
// readFilter), from which it filters hits per resource as for any grant
// with that marker. Both are kept across restarts and -rebuild until the
// last such cookie expires; a gs or marker the service doesn't know,
// minted by another instance with its own database, is 401, and the
// reader exchanges again. Instances on one database share them, and share
// the exchangeRate buckets too (§B.11.5). A reader of a whole namespace
// at issue (reads:{ns}) reads it whole under the cookie until it expires,
// as under a grant revoked since: the cookie's lifetime is the revocation
// latency (§C.5).

// readFilter is what a marker reads:{ns}:scope:{digest} stands for: the
// rules a grant's reads in ns are judged by, those of its key's scope, its
// blocks and, if it carries roles, each effective role that lists read
// (any one passing), and its /principal (readsScope digests the values
// the rules refer to). A rule referring to /now gives no marker, so the
// filter judges a read as the grant's read check does, without a clock.
type readFilter struct {
	keyRules, blockRules []any
	roles                [][]any // nil: the grant carries no roles
	principal            map[string]any

	once     sync.Once
	compiled [][]*rules.Rule // keyRules, blockRules, then each role's
	err      error
}

// filterOf is the readFilter of v's reads.
func filterOf(v *grant.Verified) *readFilter {
	f := &readFilter{keyRules: v.KeyRules, blockRules: v.BlockRules, principal: v.Principal.Envelope()}
	if v.HasRoles() {
		f.roles = [][]any{}
		_, readers := v.Allows("read")
		for _, role := range readers {
			f.roles = append(f.roles, v.RoleRules(role))
		}
	}
	return f
}

// encode is f as edge_filters keeps it: canonical JSON.
func (f *readFilter) encode() string {
	m := map[string]any{"keyRules": f.keyRules, "blockRules": f.blockRules, "principal": f.principal}
	if f.roles != nil {
		roles := make([]any, len(f.roles))
		for i, r := range f.roles {
			roles[i] = r
		}
		m["roles"] = roles
	}
	return string(jsonv.Canonical(jsonv.FromGo(m)))
}

// decodeFilter reads what encode wrote.
func decodeFilter(s string) (*readFilter, error) {
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	f := &readFilter{}
	f.keyRules, _ = m["keyRules"].([]any)
	f.blockRules, _ = m["blockRules"].([]any)
	f.principal, _ = m["principal"].(map[string]any)
	if roles, ok := m["roles"].([]any); ok {
		f.roles = [][]any{}
		for _, r := range roles {
			l, _ := r.([]any)
			f.roles = append(f.roles, l)
		}
	}
	return f, nil
}

// allows reports whether the reads f stands for may read resource: every
// key-scope and block rule passes against the read envelope (§6.4.1) and,
// with roles, every rule of some role does (§C.1.1).
func (f *readFilter) allows(resource string) bool {
	f.once.Do(func() {
		lists := append([][]any{f.keyRules, f.blockRules}, f.roles...)
		for _, l := range lists {
			var rs []*rules.Rule
			for _, rv := range l {
				r, err := rules.Compile(rv)
				if err != nil {
					f.err = err
					return
				}
				rs = append(rs, r)
			}
			f.compiled = append(f.compiled, rs)
		}
	})
	if f.err != nil {
		return false
	}
	env := map[string]any{"action": "read", "resource": resource, "principal": f.principal}
	pass := func(rs []*rules.Rule) bool {
		for _, r := range rs {
			if !r.Eval(env) {
				return false
			}
		}
		return true
	}
	if !pass(f.compiled[0]) || !pass(f.compiled[1]) {
		return false
	}
	if f.roles == nil {
		return true
	}
	return slices.ContainsFunc(f.compiled[2:], pass)
}

// keptFilter is a readFilter the service holds in memory (Index.filters),
// with the Unix time its last edge grant known here expires.
type keptFilter struct {
	f   *readFilter
	exp int64
}

// recordFilters records the filters behind scope markers, for edge grants
// minted at now that expire by exp, and drops those whose last edge grant
// has expired, from the database and from memory, as svcedge.Store.Record
// does for subject sets.
func (ix *Index) recordFilters(ctx context.Context, filters map[string]*readFilter, exp, now time.Time) error {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM edge_filters WHERE exp <= ?`, now.Unix()); err != nil {
		return err
	}
	for m, f := range filters {
		if _, err := tx.ExecContext(ctx, `INSERT INTO edge_filters (marker, filter, exp) VALUES (?, ?, ?)
			ON CONFLICT (marker) DO UPDATE SET filter = excluded.filter, exp = max(exp, excluded.exp)`, m, f.encode(), exp.Unix()); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	ix.fmu.Lock()
	for m, k := range ix.filters {
		if k.exp <= now.Unix() {
			delete(ix.filters, m)
		}
	}
	for m, f := range filters {
		ix.filters[m] = keptFilter{f: f, exp: max(ix.filters[m].exp, exp.Unix())}
	}
	ix.fmu.Unlock()
	return nil
}

// filter is the readFilter behind scope marker m, recorded when an edge
// grant for it was minted, by this instance or another on the database.
func (ix *Index) filter(ctx context.Context, m string) (*readFilter, bool) {
	ix.fmu.Lock()
	k, ok := ix.filters[m]
	ix.fmu.Unlock()
	if ok {
		return k.f, true
	}
	var (
		s   string
		exp int64
	)
	if err := ix.db.QueryRowContext(ctx, `SELECT filter, exp FROM edge_filters WHERE marker = ?`, m).Scan(&s, &exp); err != nil {
		return nil, false
	}
	f, err := decodeFilter(s)
	if err != nil {
		return nil, false
	}
	ix.fmu.Lock()
	ix.filters[m] = keptFilter{f: f, exp: exp}
	ix.fmu.Unlock()
	return f, true
}

// nsPrefix is the prefix of a subject set's results of ns, refsPrefix of
// its answers across namespaces: every at, and the head pointer under the
// prefix (§B.11.5).
func nsPrefix(ns, gs string) string { return "/" + ns + "/g/" + gs }
func refsPrefix(gs string) string   { return "/_refs/g/" + gs }

// edgeGS parses one of the service's prefixes, /{ns}/g/{gs} or (ns "")
// /_refs/g/{gs}: the only prefixes its key vouches for (§C.5.3). A
// namespace named r or ns has none, since its prefix would lie under the
// core's.
func edgeGS(p string) (ns, gs string, ok bool) {
	segs := strings.Split(p, "/")
	if len(segs) != 4 || segs[0] != "" || segs[2] != "g" {
		return "", "", false
	}
	if _, err := ids.Parse(segs[3]); err != nil {
		return "", "", false
	}
	switch {
	case segs[1] == "_refs":
		return "", segs[3], true
	case validNS(segs[1]) && segs[1] != "r" && segs[1] != "ns":
		return segs[1], segs[3], true
	}
	return "", "", false
}

// edgeClaims is the edge grant the service minted that a GET or HEAD
// without Authorization carries, covering its path, if any.
func (ix *Index) edgeClaims(r *http.Request) *edge.Claims {
	if ix.opt.EdgeGrants == nil || r.Header.Get("Authorization") != "" {
		return nil
	}
	return ix.opt.EdgeGrants.FromRequest(r, ix.opt.Now())
}

// errUnknownSet is a read under an edge grant whose subject set, or the
// filter of one of its markers, the service doesn't know: minted by an
// instance with another database, or forgotten once expired.
var errUnknownSet = &grant.AuthError{Status: 401, Msg: "an edge grant for a subject set this service doesn't know: exchange the grant again"}

// cookieAccess is access to private namespace ns under one of the
// service's edge grants for /{ns}/g/{gs} (ok false without one): the
// marker its gs stands for, read as a grant with that marker would be.
func (ix *Index) cookieAccess(ctx context.Context, ns string, r *http.Request) (*access, bool, error) {
	cl := ix.edgeClaims(r)
	if cl == nil {
		return nil, false, nil
	}
	cns, gs, ok := edgeGS(cl.Prefix)
	if !ok || cns != ns {
		return nil, false, nil
	}
	subs, ok := ix.edge.Subjects(ctx, gs)
	if !ok || len(subs) != 1 {
		return nil, true, errUnknownSet
	}
	a, err := ix.markerAccess(ctx, ns, subs[0])
	if a != nil {
		a.gs = gs
	}
	return a, true, err
}

// markerAccess is access to private namespace ns of a reader with marker m
// under an edge grant: reads:{ns} reads it whole, reads:{ns}:scope:… as
// its filter allows; any other marker reads none of it.
func (ix *Index) markerAccess(ctx context.Context, ns, m string) (*access, error) {
	switch {
	case m == "reads:"+ns:
		return &access{all: true, marker: m, cookie: true}, nil
	case strings.HasPrefix(m, "reads:"+ns+":scope:"):
		f, ok := ix.filter(ctx, m)
		if !ok {
			return nil, errUnknownSet
		}
		return &access{marker: m, filter: f, allow: f.allows, cookie: true}, nil
	}
	return nil, &grant.AuthError{Status: 403, Msg: "the edge grant doesn't read this namespace"}
}

// refsCookieReader is the reader of /_refs under one of the service's
// edge grants for /_refs/g/{gs} (ok false without one): its subject set,
// whose markers decide which private namespaces it sees and how
// (markerAccess); every public one is seen too. A namespace a marker
// names whose document the service can't read is 502, as one a grant
// names.
func (ix *Index) refsCookieReader(ctx context.Context, r *http.Request, reached map[string]string) (*refsReader, bool, error) {
	cl := ix.edgeClaims(r)
	if cl == nil {
		return nil, false, nil
	}
	cns, gs, ok := edgeGS(cl.Prefix)
	if !ok || cns != "" {
		return nil, false, nil
	}
	subs, ok := ix.edge.Subjects(ctx, gs)
	if !ok {
		return nil, true, errUnknownSet
	}
	rd := &refsReader{gs: gs, public: true, allow: map[string]func(string) bool{}}
	for _, ns := range ix.refsNamespaces() {
		if _, ok := reached[ns]; !ok || ix.keys.Skipped(ns) != "" {
			continue
		}
		i := slices.IndexFunc(subs, func(m string) bool { return m == "reads:"+ns || strings.HasPrefix(m, "reads:"+ns+":scope:") })
		cfg, err := ix.checker.Config(ctx, ns)
		switch {
		case client.IsPurged(err):
			continue
		case err != nil && i >= 0:
			return nil, true, err
		case err != nil:
			continue
		case cfg.Read == "public":
			rd.nss = append(rd.nss, ns)
			continue
		case i < 0:
			continue
		}
		a, err := ix.markerAccess(ctx, ns, subs[i])
		if err != nil {
			return nil, true, err
		}
		if !a.all {
			rd.allow[ns] = a.allow
		}
		rd.public = false
		rd.nss = append(rd.nss, ns)
	}
	return rd, true, nil
}

// purgedRead is the read check of a request of purged namespace ns, whose
// document the core answered 410 purged (cfgErr): with a grant, or none,
// the core's (grantcheck.PurgedRead); under one of the service's edge
// grants for ns's subject set, which the service knows, it passes, and
// the head is cfgErr's (§8.5).
func (ix *Index) purgedRead(ctx context.Context, ns string, r *http.Request, cfgErr error) (string, error) {
	if cl := ix.edgeClaims(r); cl != nil {
		if cns, gs, ok := edgeGS(cl.Prefix); ok && cns == ns {
			if _, known := ix.edge.Subjects(ctx, gs); !known {
				return "", errUnknownSet
			}
			if ae, ok := client.AsAPIError(cfgErr); ok && ae.Head() != "" {
				return ae.Head(), nil
			}
		}
	}
	return ix.checker.PurgedRead(ctx, ns, bearer(r))
}

// serveEdgeGrants is /edge-grants on the service's origin: POST issues,
// DELETE withdraws. Either is no-store. Without EdgeGrants, both are 404
// not_offered.
func (ix *Index) serveEdgeGrants(w http.ResponseWriter, r *http.Request) {
	telemetry.SetRoute(r, "/edge-grants")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method != http.MethodPost && r.Method != http.MethodDelete:
		w.Header().Set("Allow", "GET, HEAD, POST, DELETE")
		writeErr(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
	case ix.opt.EdgeGrants == nil:
		writeErr(w, http.StatusNotFound, "not_offered", "this service mints no edge grants")
	case r.Method == http.MethodDelete:
		// The core's DELETE /edge-grants takes only core prefixes, so the
		// service withdraws its own (§C.5.3, §C.5.4).
		svcedge.Withdraw(w, r, ix.opt.EdgeGrants, func(p string) bool { _, _, ok := edgeGS(p); return ok },
			"/{ns}/g/{gs} or /_refs/g/{gs} (§A.4, §B.11.5)")
	default:
		ix.issueEdgeGrants(w, r)
	}
}

// maxPrefixes is how many distinct prefixes one exchange may give
// (§C.5.2).
const maxPrefixes = 100

// exchanged is what one grant of an exchange gives: its edge grants, the
// markers behind each gs, the filters behind its scope markers, and the
// exchangeRate bucket of its principal.
type exchanged struct {
	issues   []svcedge.Issue
	subjects map[string][]string
	filters  map[string]*readFilter
	bucket   string
}

// issueEdgeGrants is POST /edge-grants (§A.4, §B.11.5, following §C.5.2's
// issuance): with the grant in Authorization, or 1 to svcedge.MaxGrants
// grants as { "grants": [ … ] } in an application/json body (415
// otherwise, svcedge.Bearers), it answers 200 { prefixes, exp } and one
// Set-Cookie per prefix. Each grant gives, for every private namespace
// the service follows that it names, /{ns}/g/{gs} of the reader's
// marker there (exchangeGrant), and /_refs/g/{gs} of its markers in those
// the service has reached, each lasting until the grant's exp or the
// cookies' TTL (15 minutes at most), whichever is sooner. A prefix
// several grants give gets one cookie, lasting as long as the longest,
// and exp is the earliest. It answers all or nothing: a grant over
// grantSize or rulesPerGrant is 413 limit (§C.8); any other refusal is
// 401 if any is 401, else 403, and 502 if a namespace document can't be
// read; once none is, a purged namespace a grant names and verifies in is
// 410 purged, with ns and head naming the first in the order the grants
// and their root blocks list them (§8.5, exchangeGrant). More than
// maxPrefixes prefixes is 400.
// Once nothing is refused, it draws one token from the exchangeRate
// bucket of each distinct principal among the grants (ExchangeRate,
// §6.6), shared with the instances on its database (svcedge.Store), and
// is 429 (code "rate", limit "exchangeRate", with Retry-After) while any
// is empty. While the core's authentication is disabled (§1), it is 404
// not_offered, before the body is read; it takes no query parameter (400,
// §7). Cookies are Secure, HttpOnly and SameSite as EdgeGrants says.
func (ix *Index) issueEdgeGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	root, err := ix.c.Root(ctx)
	if err != nil {
		ix.opt.Logf("index: reading the core's root: %v", err)
		writeErr(w, http.StatusBadGateway, "upstream", "cannot read the core's root")
		return
	}
	if root.AuthDisabled() {
		writeErr(w, http.StatusNotFound, "not_offered", "the core runs with authentication disabled: there are no edge grants (§C.5)")
		return
	}
	if r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, "bad_input", "POST /edge-grants takes no query parameters (§7)")
		return
	}
	bearers, refusal := svcedge.Bearers(r, svcedge.DefaultGrantSize)
	if refusal != nil {
		refusal.Write(w)
		return
	}
	if len(bearers) == 0 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "missing grant")
		return
	}
	now := ix.opt.Now()
	reached, err := ix.refsCheckpoints(ctx, ix.db, ix.refsNamespaces())
	if err != nil {
		ix.opt.Logf("index: checkpoints for an exchange: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot read the checkpoints")
		return
	}
	var (
		exs    []*exchanged
		limit  *grantcheck.LimitError
		denied *grant.AuthError
		upErr  error
		purged *purgedNS
	)
	for _, b := range bearers {
		ex, pn, err := ix.exchangeGrant(ctx, b, reached, now)
		var le *grantcheck.LimitError
		var ae *grant.AuthError
		switch {
		case errors.As(err, &le):
			if limit == nil {
				limit = le
			}
		case errors.As(err, &ae):
			if denied == nil || ae.Status == http.StatusUnauthorized && denied.Status != http.StatusUnauthorized {
				denied = ae
			}
		case err != nil:
			upErr = err
		case pn != nil:
			if purged == nil {
				purged = pn
			}
		default:
			exs = append(exs, ex)
		}
	}
	switch {
	case limit != nil:
		svcedge.Limit(limit.Limit, limit.Measured, limit.Max).Write(w)
		return
	case denied != nil:
		code := "forbidden"
		if denied.Status == http.StatusUnauthorized {
			code = "unauthenticated"
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		writeErr(w, denied.Status, code, denied.Msg)
		return
	case upErr != nil:
		ix.opt.Logf("index: exchange: %v", upErr)
		writeErr(w, http.StatusBadGateway, "upstream", "cannot read a namespace configuration")
		return
	case purged != nil:
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusGone, map[string]any{"code": "purged", "message": "namespace purged", "ns": purged.ns, "head": purged.head})
		return
	}
	var issues []svcedge.Issue
	subjects := map[string][]string{}
	filters := map[string]*readFilter{}
	var keys []string
	for _, ex := range exs {
		issues = append(issues, ex.issues...)
		for gs, subs := range ex.subjects {
			subjects[gs] = subs
		}
		for m, f := range ex.filters {
			filters[m] = f
		}
		if !slices.Contains(keys, ex.bucket) {
			keys = append(keys, ex.bucket)
		}
	}
	issues = svcedge.Merge(issues)
	if len(issues) > maxPrefixes {
		writeErr(w, http.StatusBadRequest, "bad_input", "the grants give more than 100 distinct prefixes (§C.5.2)")
		return
	}
	// One token per request, from each distinct principal's bucket,
	// however many grants it carries (§C.5.2).
	switch wait, err := ix.edge.Draw(ctx, now, ix.opt.ExchangeRate, keys); {
	case err != nil:
		ix.opt.Logf("index: drawing from the exchangeRate buckets: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot draw from the exchangeRate buckets")
		return
	case wait > 0:
		svcedge.RateLimited(wait).Write(w)
		return
	}
	var last time.Time
	for _, is := range issues {
		_, gs, _ := edgeGS(is.Prefix)
		if err := ix.edge.Record(ctx, gs, subjects[gs], is.Exp, now); err != nil {
			ix.opt.Logf("index: recording a subject set: %v", err)
			writeErr(w, http.StatusInternalServerError, "internal", "cannot record the subject set")
			return
		}
		if is.Exp.After(last) {
			last = is.Exp
		}
	}
	if err := ix.recordFilters(ctx, filters, last, now); err != nil {
		ix.opt.Logf("index: recording read filters: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot record the subject set")
		return
	}
	svcedge.Mint(w, ix.opt.EdgeGrants, now, issues)
}

// purgedNS is a purged namespace an exchange refuses, and the head of its
// purge, its purge-ns entry's ns_id (§8.5).
type purgedNS struct{ ns, head string }

// exchangeGrant is what token gives at an exchange (issueEdgeGrants): for
// every namespace the service follows that the grant names, and whose
// keys the service doesn't lack, the read check of a query of it
// (Index.access): a private one gives /{ns}/g/{gs} of the reader's marker
// there, and the markers of those reached and not skipped give
// /_refs/g/{gs} over them, as refsReader computes it. A public namespace
// needs no edge grant. A grant whose rules fix /resource (§2.1) and pass
// for none of the names they fix reads nothing there, and is 403, as at
// the core's issuance. The namespaces are taken in the order the grant's
// root block names them (§C.5.2), and the refusal is the first of the
// lowest rank among them: 401, then 403, then any other, then a purged
// namespace the grant passes the read check of, the service's own purged
// state (Index.committed, as its queries answer) or the core's 410 of a
// sealed one's document (§8.5), which pn names. A grant that gives no edge
// grant at all, naming no private namespace the service follows, is 403.
func (ix *Index) exchangeGrant(ctx context.Context, token string, reached map[string]string, now time.Time) (ex *exchanged, pn *purgedNS, err error) {
	g, err := ix.checker.Decode(token)
	if err != nil {
		var le *grantcheck.LimitError
		var ae *grant.AuthError
		if errors.As(err, &le) || errors.As(err, &ae) {
			return nil, nil, err
		}
		return nil, nil, &grant.AuthError{Status: 401, Msg: "the grant can't be decoded"}
	}
	ex = &exchanged{subjects: map[string][]string{}, filters: map[string]*readFilter{}}
	var (
		markers []string
		refsExp time.Time
		refused error
	)
	refuse := func(err error) {
		if refused == nil || refusalRank(err) < refusalRank(refused) {
			refused = err
		}
	}
	for _, ns := range namedInOrder(g, ix.refsNamespaces()) {
		if refused != nil && refusalRank(refused) == 0 {
			break // 401 ranks first: nothing after it changes the answer
		}
		if _, lacks := ix.keys.Skip(ns); lacks {
			continue // one the service doesn't follow (§A.4)
		}
		head, purged, err := ix.committed(ctx, ns)
		if err != nil {
			refuse(err)
			continue
		}
		cfg, err := ix.checker.Config(ctx, ns)
		if client.IsPurged(err) {
			if head, err = ix.checker.PurgedRead(ctx, ns, token); err != nil {
				refuse(err)
			} else {
				refuse(&purgedNS{ns: ns, head: head})
			}
			continue
		}
		if err != nil {
			refuse(err)
			continue
		}
		if cfg.Read == "public" && !purged {
			continue
		}
		v, err := ix.checker.Verify(ctx, ns, token)
		if err != nil {
			refuse(err)
			continue
		}
		var a *access
		if cfg.Read != "public" {
			if a, err = ix.grantAccess(ns, v); err == nil && a.filter != nil && !readsFixed(v, a.allow) {
				err = &grant.AuthError{Status: 403, Msg: "the grant's rules pass for none of the names they fix /resource to in " + ns + " (§C.5.2)"}
			}
			if err != nil {
				refuse(err)
				continue
			}
		}
		if purged {
			// Its queries answer 410 once the read check passes (§8.5).
			refuse(&purgedNS{ns: ns, head: head})
			continue
		}
		exp := ix.opt.EdgeGrants.Lifetime(now, grantExp(v))
		if ex.bucket == "" {
			// Its principal and kid there, as the core keys write buckets
			// (§C.5.2, §6.6).
			ex.bucket = v.Principal.ID + "\x00" + v.Key.Kid
		}
		if a.filter != nil {
			ex.filters[a.marker] = a.filter
		}
		if _, _, ok := edgeGS(nsPrefix(ns, a.gs)); ok {
			ex.issues = append(ex.issues, svcedge.Issue{Prefix: nsPrefix(ns, a.gs), Exp: exp})
			ex.subjects[a.gs] = []string{a.marker}
		}
		if _, ok := reached[ns]; ok && ix.keys.Skipped(ns) == "" {
			markers = append(markers, a.marker)
			if refsExp.IsZero() || exp.Before(refsExp) {
				refsExp = exp
			}
		}
	}
	if p, ok := refused.(*purgedNS); ok {
		return nil, p, nil
	}
	if refused != nil {
		return nil, nil, refused
	}
	if len(markers) > 0 {
		gs := grantcheck.SubjectSetID(markers)
		slices.Sort(markers)
		ex.issues = append(ex.issues, svcedge.Issue{Prefix: refsPrefix(gs), Exp: refsExp})
		ex.subjects[gs] = markers
	}
	if len(ex.issues) == 0 {
		return nil, nil, &grant.AuthError{Status: 403, Msg: "the grant reads no private namespace this service follows"}
	}
	return ex, nil, nil
}

func (p *purgedNS) Error() string { return p.ns + " was purged" }

// refusalRank orders an exchange's refusals (§C.5.2, All or nothing): 401,
// then 403, then any other (a namespace document the service can't read,
// 502), and a purged namespace last, answered only when every refusal is.
func refusalRank(err error) int {
	var ae *grant.AuthError
	var pn *purgedNS
	switch {
	case errors.As(err, &ae) && ae.Status == http.StatusUnauthorized:
		return 0
	case errors.As(err, &ae):
		return 1
	case errors.As(err, &pn):
		return 3
	}
	return 2
}

// namedInOrder is those of followed that g names, in the order g's root
// block lists them (§C.5.2); one it reaches only through "*" comes where
// "*" is.
func namedInOrder(g *grant.Grant, followed []string) []string {
	var root []string
	if len(g.Blocks) > 0 {
		root = g.Blocks[0].NS
	}
	pos := func(ns string) int {
		if i := slices.Index(root, ns); i >= 0 {
			return i
		}
		if i := slices.Index(root, "*"); i >= 0 {
			return i
		}
		return len(root)
	}
	var out []string
	for _, ns := range followed {
		if g.NamesNS(ns) {
			out = append(out, ns)
		}
	}
	slices.SortStableFunc(out, func(a, b string) int { return pos(a) - pos(b) })
	return out
}

// readsFixed reports whether a grant whose rules fix /resource (§2.1)
// may read some name they fix, by allow, its read check per resource; a
// grant whose rules fix none is left to that check per resource. Names
// are fixed as the core's issuance fixes them: by each rule of its blocks
// and key scope, at top level or inside all, that tests /resource against
// one literal or a finite set (grant.ResourceLiterals), the names all of
// them allow (§C.5.2: the rules must pass with /resource set to the names
// it fixes).
func readsFixed(v *grant.Verified, allow func(string) bool) bool {
	var names []string
	fixed := false
	var walk func(rs []any)
	walk = func(rs []any) {
		for _, rv := range rs {
			if m, ok := rv.(map[string]any); ok && len(m) == 1 {
				if all, ok := m["all"].([]any); ok {
					walk(all)
					continue
				}
			}
			lits, ok := grant.ResourceLiterals(rv)
			if !ok {
				continue
			}
			var set []string
			for _, l := range lits {
				if name, ok := l.(string); ok && !slices.Contains(set, name) {
					set = append(set, name)
				}
			}
			if !fixed {
				names, fixed = set, true
				continue
			}
			names = slices.DeleteFunc(names, func(n string) bool { return !slices.Contains(set, n) })
		}
	}
	walk(v.KeyRules)
	walk(v.BlockRules)
	return !fixed || slices.ContainsFunc(names, allow)
}

// grantExp is the earliest exp among v's blocks, the zero time for none.
func grantExp(v *grant.Verified) time.Time {
	var exp time.Time
	for _, b := range v.Grant.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	return exp
}

// initEdge sets up the service's edge grants, with EdgeGrants: its key
// vouches only for its own prefixes (edgeGS), and their state lives in
// the database (svcedge.Store, and edge_filters, migration 004).
func (ix *Index) initEdge(ctx context.Context, db *sql.DB) error {
	ix.filters = map[string]keptFilter{}
	if ix.opt.EdgeGrants == nil {
		return nil
	}
	ix.opt.EdgeGrants.Vouches = func(p string) bool { _, _, ok := edgeGS(p); return ok }
	if ix.opt.ExchangeRate.Rate <= 0 || ix.opt.ExchangeRate.Burst < 1 {
		ix.opt.ExchangeRate = svcedge.DefaultExchangeRate
	}
	var err error
	ix.edge, err = svcedge.NewStore(ctx, db)
	return err
}
