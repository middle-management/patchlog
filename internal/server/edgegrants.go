package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
)

// WithEdgeGrants enables POST /edge-grants (§C.5): grants are exchanged
// for edge grants as cookies, issued and verified with c. Without it the
// origin still issues them, named edge.DefaultKid, under a key derived
// from the edge secret (WithEdge) if there is one, else a random key of
// this process.
func WithEdgeGrants(c *edge.Cookies) Option { return func(s *Server) { s.cookies = c } }

type edgeGrantKey struct{}

// edgeCred is the edge grant a GET or HEAD carries in a cookie covering
// its path, checked as an edge checks it (edge.Cookies.Check), when it
// carries no Authorization (§C.5). Writes, POST /edge-grants included,
// never get one. Its namespace and resource are those of its prefix.
func (s *Server) edgeCred(r *http.Request) *http.Request {
	if s.cookies == nil || r.Header.Get("Authorization") != "" {
		return r
	}
	cl := s.cookies.FromRequest(r, s.e.Now())
	if cl == nil {
		return r
	}
	ns, res, _ := edge.ParsePrefix(cl.Prefix)
	eg := &core.EdgeGrant{NS: ns, Resource: res, Prefix: cl.Prefix, Exp: time.Unix(cl.Exp, 0)}
	return r.WithContext(context.WithValue(r.Context(), edgeGrantKey{}, eg))
}

// referrerCache sets Cache-Control for a schema revision served under
// schemaReads to a reader of a referrer (§6.1, core.Rev.Referrer). It
// depends on the referrer, so it is private, and no shared cache stores
// it, whatever the edge's headers say (§9).
func referrerCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, max-age=300")
	edge.NoStore(w.Header())
}

// edgeGrants is POST /edge-grants (§C.5): with the grant in
// Authorization, or several in the body (edgeGrantBearers), 200 with
// { prefixes, exp } and one Set-Cookie per prefix: Path the prefix
// (/r/{ns}/{name}, /r/{ns}, /ns/{ns}, covering what lies below), Secure,
// HttpOnly, SameSite as the Cookies say (None with credentialed origins,
// else Lax), named per prefix. Each grant's cookies last until its exp or
// MaxGrantTTL, whichever is sooner; a prefix several grants give gets one
// cookie, lasting as long as the longest, and exp is the earliest. The
// prefixes are in the order the grants first give them. no-store.
func (s *Server) edgeGrants(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	bearers, err := s.edgeGrantBearers(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.e.IssueEdgeGrants(r.Context(), bearers)
	if err != nil {
		writeErr(w, err)
		return
	}
	prefixes := []string{}
	exps := map[string]time.Time{}
	for _, g := range res.Grants {
		exp := s.cookies.Lifetime(res.Now, g.Exp)
		for _, p := range g.Prefixes() {
			old, ok := exps[p]
			if !ok {
				prefixes = append(prefixes, p)
			}
			if !ok || exp.After(old) {
				exps[p] = exp
			}
		}
	}
	var first time.Time
	for _, p := range prefixes {
		http.SetCookie(w, s.cookies.Issue(edge.Claims{Prefix: p, Exp: exps[p].Unix()}, res.Now))
		if first.IsZero() || exps[p].Before(first) {
			first = exps[p]
		}
	}
	writeJSON(w, 200, map[string]any{"prefixes": prefixes, "exp": first.UTC().Format(time.RFC3339)})
}

// edgeGrantBearers are the grants POST /edge-grants exchanges (§C.5):
// those of a body { "grants": [ … ] }, 1 to core.MaxEdgeGrants tokens as
// they would follow "Bearer ", which takes no Authorization (400
// otherwise); without a body, the grant in Authorization, if any. A
// cookie never authorises issuing another.
func (s *Server) edgeGrantBearers(r *http.Request) ([]string, error) {
	// Room for every grant at the largest grant size, as base64 with its
	// optional prefix and padding, quoted, and some whitespace.
	max := core.MaxEdgeGrants*(len("biscuit:")+base64.URLEncoding.EncodedLen(s.e.Limits().GrantSize)+4) + 4096
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil {
		return nil, badInput("could not read body")
	}
	if len(body) == 0 {
		if c := creds(r); c.Bearer != "" {
			return []string{c.Bearer}, nil
		}
		return nil, nil
	}
	if r.Header.Get("Authorization") != "" {
		return nil, badInput("grants in the body take no Authorization (§C.5)")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	v, err := readJSON(r, max)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	gs, ok := m["grants"].([]any)
	if !ok || len(m) != 1 || len(gs) < 1 || len(gs) > core.MaxEdgeGrants {
		return nil, badInput(fmt.Sprintf("body must be { grants: [ … ] }, 1 to %d grants (§C.5)", core.MaxEdgeGrants))
	}
	out := make([]string, len(gs))
	for i, g := range gs {
		if out[i], ok = g.(string); !ok {
			return nil, badInput("each grant is a string: the token as it would follow \"Bearer \" (§C.5)")
		}
	}
	return out, nil
}
