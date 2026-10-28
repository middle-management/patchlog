// Package svcedge is what a service needs to mint edge grants of its own
// (§B.11.5, §C.5.3): the request and answer of its exchange endpoint,
// which follows the origin's issuance (§C.5.2), its withdrawal (§C.5.4),
// and the state it keeps beside them in its own database (Store): the
// subjects behind each subject set (gs) it minted a cookie for, and its
// exchangeRate buckets (§6.6), shared by every instance on that database.
//
//	POST   /edge-grants              Bearers, then the service's own
//	                                 checks, Store.Draw, Merge and Mint
//	DELETE /edge-grants?prefix=…     Withdraw
//
// A cookie carries only kid, p and exp (edge.Cookies), so a service that
// reads under one as a subject set's reader looks the subjects up by the
// gs of its prefix (Store.Subjects). Which prefixes a service mints, and
// whom it admits to each, is the service's: the catalog service's are
// /{catalog}/g/{gs} (internal/tree), an index's /{ns}/g/{gs}.
package svcedge

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// MaxGrants is how many grants one exchange takes in its body (§C.5.2).
const MaxGrants = 50

// DefaultGrantSize is grantSize's default (§6.6), in decoded bytes: the
// most a grant verified by a service with grantcheck's defaults can be.
const DefaultGrantSize = 8 << 10

// BodyMax is the largest exchange body read for grants of at most
// grantSize decoded bytes: room for MaxGrants of them as base64, with the
// optional "biscuit:" prefix and padding, quoted, and some whitespace, as
// the origin's (§C.5.2).
func BodyMax(grantSize int) int {
	return MaxGrants*(len("biscuit:")+base64.URLEncoding.EncodedLen(grantSize)+4) + 4096
}

// Error is a refusal a service's exchange answers: Status, Body ({ code,
// message, … }) and, where set, Header lines.
type Error struct {
	Status int
	Body   map[string]any
	Header http.Header
}

func (e *Error) Error() string { return fmt.Sprintf("%d: %v", e.Status, e.Body["message"]) }

// Refuse is the Error of status with code and message msg.
func Refuse(status int, code, msg string) *Error {
	return &Error{Status: status, Body: map[string]any{"code": code, "message": msg}}
}

// Write writes e, no-store, as every answer of an exchange is (§C.5.2).
func (e *Error) Write(w http.ResponseWriter) {
	for k, vs := range e.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, e.Status, e.Body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// Bearer returns the request's bearer token, "" for none.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// Bearers are the grants an exchange takes (§C.5.2), for grants of at
// most grantSize decoded bytes: those of a body { "grants": [ … ] }, 1 to
// MaxGrants tokens as they would follow "Bearer ", which takes no
// Authorization; without a body, the grant in Authorization, if any (none
// is the caller's 401). In order:
//
//   - a body over BodyMax(grantSize) is 400 bad_input before it is
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
func Bearers(r *http.Request, grantSize int) ([]string, *Error) {
	max := BodyMax(grantSize)
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	switch {
	case err != nil:
		return nil, Refuse(http.StatusBadRequest, "bad_input", "cannot read the body")
	case len(body) > max:
		return nil, Refuse(http.StatusBadRequest, "bad_input",
			fmt.Sprintf("the body is larger than %d grants of grantSize can be (§C.5.2)", MaxGrants))
	case len(body) == 0:
		if b := Bearer(r); b != "" {
			return []string{b}, nil
		}
		return nil, nil
	case len(r.Header.Values("Authorization")) > 0: // even an empty one (§C.5.3)
		return nil, Refuse(http.StatusBadRequest, "bad_input", "grants in the body take no Authorization (§C.5.2)")
	}
	if !jsonv.MediaType(r.Header.Get("Content-Type"), "application/json") {
		return nil, Refuse(http.StatusUnsupportedMediaType, "unsupported_type", "use application/json") // §12.1
	}
	v, err := jsonv.ParseInput(body)
	if err != nil {
		return nil, Refuse(http.StatusBadRequest, "bad_input", "malformed body: "+err.Error())
	}
	m, _ := v.(map[string]any)
	gs, ok := m["grants"].([]any)
	if !ok || len(m) != 1 || len(gs) < 1 || len(gs) > MaxGrants {
		return nil, Refuse(http.StatusBadRequest, "bad_input", fmt.Sprintf("body must be { grants: [ … ] }, 1 to %d grants (§C.5.2)", MaxGrants))
	}
	bearers := make([]string, 0, len(gs))
	for _, g := range gs {
		t, ok := g.(string)
		if !ok || strings.TrimSpace(t) == "" {
			return nil, Refuse(http.StatusBadRequest, "bad_input", "each grant is a string: the token as it would follow \"Bearer \" (§C.5.2)")
		}
		bearers = append(bearers, strings.TrimSpace(t))
	}
	return bearers, nil
}

// Limit is the 413 of a grant over grantSize or rulesPerGrant (§C.8,
// §12.1): code limit, naming the limit, with what was measured and the
// maximum.
func Limit(limit string, measured, max int) *Error {
	return &Error{Status: http.StatusRequestEntityTooLarge, Body: map[string]any{"code": "limit",
		"message": "the grant is over " + limit, "limit": limit, "measured": measured, "max": max}}
}

// RateLimited is the 429 of an exchange whose exchangeRate bucket is
// empty for wait more (§C.5.2, §6.6): code rate, limit exchangeRate,
// retryAfter in seconds and Retry-After in whole seconds, at least one.
func RateLimited(wait time.Duration) *Error {
	e := &Error{Status: http.StatusTooManyRequests, Header: http.Header{},
		Body: map[string]any{"code": "rate", "message": "rate limit exceeded", "limit": "exchangeRate",
			"retryAfter": math.Ceil(wait.Seconds()*1000) / 1000}}
	e.Header.Set("Retry-After", strconv.Itoa(max(int(math.Ceil(wait.Seconds())), 1)))
	return e
}

// Issue is one edge grant an exchange mints: its prefix, and when its
// cookie expires.
type Issue struct {
	Prefix string
	Exp    time.Time
}

// Merge merges issues by prefix (§C.5.2): one per prefix, in the order
// they first give it, lasting as long as the longest.
func Merge(issues []Issue) []Issue {
	var out []Issue
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

// Mint answers an exchange (§C.5.2): one Set-Cookie per issue, minted by
// c at now (Secure, HttpOnly, host-only, SameSite as c says), and 200 {
// prefixes, exp }, exp the earliest, as an RFC 3339 time. issues are
// Merge's: one per prefix.
func Mint(w http.ResponseWriter, c *edge.Cookies, now time.Time, issues []Issue) {
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
	writeJSON(w, http.StatusOK, map[string]any{"prefixes": prefixes, "exp": first.UTC().Format(time.RFC3339)})
}

// Withdraw answers DELETE /edge-grants?prefix=… for a service's own edge
// grants (§C.5.3, §C.5.4): 204, no-store, with an expired Set-Cookie of
// the same name and attributes for each prefix named, once even if named
// twice. prefix is its only parameter, repeatable, and each must be one
// the service mints, which ours reports (400 bad_input otherwise, form
// naming its prefixes in the message): the origin's DELETE /edge-grants
// takes only core prefixes, so a service withdraws its own. It needs no
// grant, since it only narrows, ignores any it is sent, and answers the
// same while authentication is disabled; its preflight is allowed only
// for credentialed origins (internal/cors).
func Withdraw(w http.ResponseWriter, r *http.Request, c *edge.Cookies, ours func(string) bool, form string) {
	w.Header().Set("Cache-Control", "no-store")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		Refuse(http.StatusBadRequest, "bad_input", "malformed query string").Write(w)
		return
	}
	var prefixes []string
	seen := map[string]bool{}
	for k, vs := range q {
		if k != "prefix" {
			Refuse(http.StatusBadRequest, "bad_input", fmt.Sprintf("unknown query parameter %q", k)).Write(w)
			return
		}
		for _, p := range vs {
			if !ours(p) {
				Refuse(http.StatusBadRequest, "bad_input", fmt.Sprintf("prefix %q isn't one this service issues: %s", p, form)).Write(w)
				return
			}
			if !seen[p] {
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
	}
	if len(prefixes) == 0 {
		Refuse(http.StatusBadRequest, "bad_input", "prefix is required (§C.5.4)").Write(w)
		return
	}
	for _, p := range prefixes {
		http.SetCookie(w, c.Withdraw(p))
	}
	w.WriteHeader(http.StatusNoContent)
}
