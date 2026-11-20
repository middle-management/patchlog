package index

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// The service's own edge grants (§A.4, §C.5.3): the request and answer of
// its exchange endpoint, which follows the origin's issuance (§C.5.2),
// its withdrawal (§C.5.4), and the state it keeps beside them in its own
// database (edgeStore): the subjects behind each subject set (gs) it
// minted a cookie for, and its exchangeRate buckets (§6.6), shared by
// every instance on that database.
//
//	POST   /edge-grants              svcBearers, then the service's own
//	                                 checks, edgeStore.Draw, svcMerge and svcMint
//	DELETE /edge-grants?prefix=…     svcWithdraw

// svcMaxGrants is how many grants one exchange takes in its body (§C.5.2).
const svcMaxGrants = 50

// svcDefaultGrantSize is grantSize's default (§6.6), in decoded bytes: the
// most a grant verified by a service with grantcheck's defaults can be.
const svcDefaultGrantSize = 8 << 10

// svcBodyMax is the largest exchange body read for grants of at most
// grantSize decoded bytes: room for svcMaxGrants of them as base64, with the
// optional "biscuit:" prefix and padding, quoted, and some whitespace, as
// the origin's (§C.5.2).
func svcBodyMax(grantSize int) int {
	return svcMaxGrants*(len("biscuit:")+base64.URLEncoding.EncodedLen(grantSize)+4) + 4096
}

// svcError is a refusal a service's exchange answers: Status, Body ({ code,
// message, … }) and, where set, Header lines.
type svcError struct {
	Status int
	Body   map[string]any
	Header http.Header
}

func (e *svcError) Error() string { return fmt.Sprintf("%d: %v", e.Status, e.Body["message"]) }

// svcRefuse is the svcError of status with code and message msg.
func svcRefuse(status int, code, msg string) *svcError {
	return &svcError{Status: status, Body: map[string]any{"code": code, "message": msg}}
}

// Write writes e, no-store, as every answer of an exchange is (§C.5.2).
func (e *svcError) Write(w http.ResponseWriter) {
	for k, vs := range e.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	svcWriteJSON(w, e.Status, e.Body)
}

func svcWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// svcBearer returns the request's bearer token, "" for none: an
// Authorization of another scheme, or svcBearer with nothing after it,
// carries no usable grant, and its request is answered as one with a
// malformed grant (401), never as one without Authorization (§C.8,
// §C.5.3).
func svcBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// svcBearers are the grants an exchange takes (§C.5.2), for grants of at
// most grantSize decoded bytes: those of a body { "grants": [ … ] }, 1 to
// svcMaxGrants tokens as they would follow "svcBearer ", which takes no
// Authorization; without a body, the grant in Authorization, if any (none
// is the caller's 401). In order:
//
//   - a body over svcBodyMax(grantSize) is 400 bad_input before it is
//     parsed, since no grant was measured against grantSize yet: a single
//     grant over it is 413 once decoded (§C.5.2);
//   - a body together with Authorization, even an empty one (§C.5.3),
//     is 400 bad_input;
//   - a body that isn't application/json, compared as a media type whose
//     only parameter may be a charset naming UTF-8 (§7.2), is 415
//     unsupported_type: a cross-site form can send text/plain without a
//     CORS preflight, and would set cookies of its own grant in the
//     reader's browser;
//   - a body that isn't I-JSON, noncharacters included (§3.1,
//     jsonv.ParseInput), or isn't of that shape, is 400 bad_input.
func svcBearers(r *http.Request, grantSize int) ([]string, *svcError) {
	max := svcBodyMax(grantSize)
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	switch {
	case err != nil:
		return nil, svcRefuse(http.StatusBadRequest, "bad_input", "cannot read the body")
	case len(body) > max:
		return nil, svcRefuse(http.StatusBadRequest, "bad_input",
			fmt.Sprintf("the body is larger than %d grants of grantSize can be (§C.5.2)", svcMaxGrants))
	case len(body) == 0:
		if b := svcBearer(r); b != "" {
			return []string{b}, nil
		}
		return nil, nil
	case len(r.Header.Values("Authorization")) > 0: // even an empty one (§C.5.3)
		return nil, svcRefuse(http.StatusBadRequest, "bad_input", "grants in the body take no Authorization (§C.5.2)")
	}
	if !jsonv.MediaType(r.Header.Get("Content-Type"), "application/json") {
		return nil, svcRefuse(http.StatusUnsupportedMediaType, "unsupported_type", "use application/json") // §12.1
	}
	v, err := jsonv.ParseInput(body)
	if err != nil {
		return nil, svcRefuse(http.StatusBadRequest, "bad_input", "malformed body: "+err.Error())
	}
	m, _ := v.(map[string]any)
	gs, ok := m["grants"].([]any)
	if !ok || len(m) != 1 || len(gs) < 1 || len(gs) > svcMaxGrants {
		return nil, svcRefuse(http.StatusBadRequest, "bad_input", fmt.Sprintf("body must be { grants: [ … ] }, 1 to %d grants (§C.5.2)", svcMaxGrants))
	}
	bearers := make([]string, 0, len(gs))
	for _, g := range gs {
		t, ok := g.(string)
		if !ok || strings.TrimSpace(t) == "" {
			return nil, svcRefuse(http.StatusBadRequest, "bad_input", "each grant is a string: the token as it would follow \"svcBearer \" (§C.5.2)")
		}
		bearers = append(bearers, strings.TrimSpace(t))
	}
	return bearers, nil
}

// svcLimit is the 413 of a grant over grantSize or rulesPerGrant (§C.8,
// §12.1): code limit, naming the limit, with what was measured and the
// maximum.
func svcLimit(limit string, measured, max int) *svcError {
	return &svcError{Status: http.StatusRequestEntityTooLarge, Body: map[string]any{"code": "limit",
		"message": "the grant is over " + limit, "limit": limit, "measured": measured, "max": max}}
}

// svcRateLimited is the 429 of an exchange whose exchangeRate bucket is
// empty for wait more (§C.5.2, §6.6): code rate, limit exchangeRate,
// retryAfter in seconds and Retry-After in whole seconds, at least one.
func svcRateLimited(wait time.Duration) *svcError {
	e := &svcError{Status: http.StatusTooManyRequests, Header: http.Header{},
		Body: map[string]any{"code": "rate", "message": "rate limit exceeded", "limit": "exchangeRate",
			"retryAfter": math.Ceil(wait.Seconds()*1000) / 1000}}
	e.Header.Set("Retry-After", strconv.Itoa(max(int(math.Ceil(wait.Seconds())), 1)))
	return e
}

// svcIssue is one edge grant an exchange mints: its prefix, and when its
// cookie expires.
type svcIssue struct {
	Prefix string
	Exp    time.Time
}

// svcMerge merges issues by prefix (§C.5.2): one per prefix, in the order
// they first give it, lasting as long as the longest.
func svcMerge(issues []svcIssue) []svcIssue {
	var out []svcIssue
	at := map[string]int{}
	for _, is := range issues {
		i, ok := at[is.Prefix]
		switch {
		case !ok:
			at[is.Prefix] = len(out)
			out = append(out, is)
		case is.Exp.After(out[i].Exp):
			out[i].Exp = is.Exp
		}
	}
	return out
}

// svcMint answers an exchange (§C.5.2): one Set-Cookie per issue, minted by
// c at now (Secure, HttpOnly, host-only, SameSite as c says), and 200 {
// prefixes, exp }, exp the earliest, as an RFC 3339 time. issues are
// svcMerge's: one per prefix.
func svcMint(w http.ResponseWriter, c *edge.Cookies, now time.Time, issues []svcIssue) {
	prefixes := make([]string, 0, len(issues))
	var first time.Time
	for _, is := range issues {
		http.SetCookie(w, c.Issue(edge.Claims{Prefix: is.Prefix, Exp: is.Exp.Unix()}, now))
		prefixes = append(prefixes, is.Prefix)
		if first.IsZero() || is.Exp.Before(first) {
			first = is.Exp
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	svcWriteJSON(w, http.StatusOK, map[string]any{"prefixes": prefixes, "exp": first.UTC().Format(time.RFC3339)})
}

// svcWithdraw answers DELETE /edge-grants?prefix=… for a service's own edge
// grants (§C.5.3, §C.5.4): 204, no-store, with an expired Set-Cookie of
// the same name and attributes for each prefix named, once even if named
// twice. prefix is its only parameter, repeatable, and each must be one
// the service mints, which ours reports (400 bad_input otherwise, form
// naming its prefixes in the message): the origin's DELETE /edge-grants
// takes only core prefixes, so a service withdraws its own. It needs no
// grant, since it only narrows, ignores any it is sent, and answers the
// same while authentication is disabled; its preflight is allowed only
// for credentialed origins (internal/cors).
func svcWithdraw(w http.ResponseWriter, r *http.Request, c *edge.Cookies, ours func(string) bool, form string) {
	w.Header().Set("Cache-Control", "no-store")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		svcRefuse(http.StatusBadRequest, "bad_input", "malformed query string").Write(w)
		return
	}
	var prefixes []string
	seen := map[string]bool{}
	for k, vs := range q {
		if k != "prefix" {
			svcRefuse(http.StatusBadRequest, "bad_input", fmt.Sprintf("unknown query parameter %q", k)).Write(w)
			return
		}
		for _, p := range vs {
			if !ours(p) {
				svcRefuse(http.StatusBadRequest, "bad_input", fmt.Sprintf("prefix %q isn't one this service issues: %s", p, form)).Write(w)
				return
			}
			if !seen[p] {
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
	}
	if len(prefixes) == 0 {
		svcRefuse(http.StatusBadRequest, "bad_input", "prefix is required (§C.5.4)").Write(w)
		return
	}
	for _, p := range prefixes {
		http.SetCookie(w, c.Withdraw(p))
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rate is a token bucket (§6.6): Rate refills it per second, up to Burst.
type Rate struct{ Rate, Burst float64 }

// DefaultExchangeRate is exchangeRate's default (§6.6): 10/s, burst 100.
var DefaultExchangeRate = Rate{Rate: 10, Burst: 100}

// edgeStore is the state a service keeps for its edge grants in its own
// SQLite database (§A.4), shared by every instance of the service that
// opens that database, and kept across restarts and rebuilds:
//
//	edge_subjects(gs, subjects, exp)  the subjects behind each subject set
//	                                  the service minted an edge grant for,
//	                                  until the last of them expires
//	edge_buckets(k, tokens, last)     the exchangeRate buckets of its
//	                                  exchange, one per principal (Draw)
//
// A gs is the digest of its subjects, so what Subjects answers for one
// never changes, and the store keeps the answers it read in memory too.
type edgeStore struct {
	db *sql.DB

	mu   sync.Mutex
	subs map[string]edgeSubjectSet
}

// edgeSubjectSet is the subjects behind a gs, and the expiry of the last edge
// grant minted for it that the store knows of (Unix seconds).
type edgeSubjectSet struct {
	subjects []string
	exp      int64
}

// newEdgeStore opens the store in db, the index's SQLite database, whose
// migrations create its tables (migration 015).
func newEdgeStore(db *sql.DB) *edgeStore {
	return &edgeStore{db: db, subs: map[string]edgeSubjectSet{}}
}

// Record records the subjects behind gs, for an edge grant minted at now
// that expires at exp, and drops the records whose last edge grant has
// expired.
func (s *edgeStore) Record(ctx context.Context, gs string, subjects []string, exp, now time.Time) error {
	b, err := json.Marshal(subjects)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM edge_subjects WHERE exp <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO edge_subjects (gs, subjects, exp) VALUES (?, ?, ?)
		ON CONFLICT (gs) DO UPDATE SET subjects = excluded.subjects, exp = max(exp, excluded.exp)`, gs, string(b), exp.Unix()); err != nil {
		return err
	}
	for k, e := range s.subs {
		if e.exp <= now.Unix() {
			delete(s.subs, k)
		}
	}
	e := s.subs[gs]
	s.subs[gs] = edgeSubjectSet{subjects: subjects, exp: max(e.exp, exp.Unix())}
	return nil
}

// Subjects is the subjects behind gs, recorded when an edge grant for it
// was minted, by this instance or another on the same database.
func (s *edgeStore) Subjects(ctx context.Context, gs string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.subs[gs]; ok {
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
	s.subs[gs] = edgeSubjectSet{subjects: subs, exp: exp}
	return subs, true
}

// Draw draws one token from the exchangeRate bucket (§6.6) of each of
// keys at rate r, if each holds one, and otherwise draws none and returns
// how long until the emptiest refills one (§C.5.2). A bucket starts full,
// and one idle long enough to have refilled is dropped, being the same as
// none. The check and the draw are one transaction whose first statement
// writes, so it holds the database's write lock from its start (SQLite
// admits one writer): every instance of the service on the database draws
// from the same buckets, and no two draw between one's check and its draw
// (the buckets are shared across its instances as the origin's are).
func (s *edgeStore) Draw(ctx context.Context, now time.Time, r Rate, keys []string) (time.Duration, error) {
	if len(keys) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	full := time.Duration(r.Burst / r.Rate * float64(time.Second))
	if _, err := tx.ExecContext(ctx, `DELETE FROM edge_buckets WHERE last <= ?`, now.Add(-full).UnixNano()); err != nil {
		return 0, err
	}
	var wait time.Duration
	tokens, lasts := make([]float64, len(keys)), make([]int64, len(keys))
	for i, k := range keys {
		var t float64
		var last int64
		switch err := tx.QueryRowContext(ctx, `SELECT tokens, last FROM edge_buckets WHERE k = ?`, k).Scan(&t, &last); {
		case errors.Is(err, sql.ErrNoRows):
			t, last = r.Burst, now.UnixNano()
		case err != nil:
			return 0, err
		case now.UnixNano() > last:
			// Refilled since, up to Burst; a last ahead of this instance's
			// clock refills nothing until it passes.
			t = min(r.Burst, t+now.Sub(time.Unix(0, last)).Seconds()*r.Rate)
			last = now.UnixNano()
		}
		tokens[i], lasts[i] = t, last
		if t < 1 {
			wait = max(wait, time.Duration((1-t)/r.Rate*float64(time.Second)))
		}
	}
	if wait > 0 {
		return wait, nil
	}
	for i, k := range keys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO edge_buckets (k, tokens, last) VALUES (?, ?, ?)
			ON CONFLICT (k) DO UPDATE SET tokens = excluded.tokens, last = excluded.last`, k, tokens[i]-1, lasts[i]); err != nil {
			return 0, err
		}
	}
	return 0, tx.Commit()
}
