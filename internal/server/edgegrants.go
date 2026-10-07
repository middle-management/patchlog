package server

import (
	"context"
	"net/http"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
)

// WithEdgeGrants enables POST /edge-grants (§C.5): grants are exchanged
// for edge grants as cookies, issued and verified with c. Without it the
// origin still issues them, under a key derived from the edge secret
// (WithEdge) if there is one, else a random key of this process.
func WithEdgeGrants(c *edge.Cookies) Option { return func(s *Server) { s.cookies = c } }

type edgeGrantKey struct{}

// edgeCred is the edge grant a GET or HEAD carries in a cookie covering
// its path, verified, when it carries no Authorization (§C.5). Writes,
// POST /edge-grants included, never get one.
func (s *Server) edgeCred(r *http.Request) *http.Request {
	if s.cookies == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.Header.Get("Authorization") != "" {
		return r
	}
	cl := s.cookies.FromRequest(r, s.e.Now())
	if cl == nil {
		return r
	}
	eg := &core.EdgeGrant{NS: cl.NS, Resource: cl.Resource, Sub: cl.Sub}
	return r.WithContext(context.WithValue(r.Context(), edgeGrantKey{}, eg))
}

// edgeGrants is POST /edge-grants (§C.5): with the grant in
// Authorization, 200 with { prefixes, exp } and one Set-Cookie per
// prefix, Path the prefix, Secure, HttpOnly, named per prefix. no-store.
func (s *Server) edgeGrants(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	c := creds(r)
	c.Edge = nil // a cookie never authorises issuing another
	res, err := s.e.IssueEdgeGrants(r.Context(), core.Credentials{Bearer: c.Bearer})
	if err != nil {
		writeErr(w, err)
		return
	}
	exp := s.cookies.Lifetime(res.Now, res.Exp)
	prefixes := []string{}
	for _, g := range res.Grants {
		for _, p := range g.Prefixes() {
			http.SetCookie(w, s.cookies.Issue(edge.Claims{Prefix: p, NS: g.NS, Resource: g.Resource, Sub: g.Sub, Exp: exp.Unix()}, res.Now))
			prefixes = append(prefixes, p)
		}
	}
	writeJSON(w, 200, map[string]any{"prefixes": prefixes, "exp": exp.UTC().Format(time.RFC3339)})
}
