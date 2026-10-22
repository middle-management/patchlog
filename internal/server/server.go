// Package server exposes the patch log over HTTP (§7).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// Server is the HTTP API.
type Server struct {
	e    *core.Engine
	mux  *http.ServeMux
	edge *edge.Verifier // nil: no verifying edge (§9)
	// cookies issues and verifies edge grants as cookies (§C.5).
	cookies *edge.Cookies
}

// Option configures a Server.
type Option func(*Server)

// WithEdge declares a verifying edge in front of the origin (§9): private
// reads it verified itself, carrying its secret and a prefix covering the
// URL and no other credential, get edge lifetimes. Every other private
// response, and every one without it (or with nil), is marked no-store for
// shared caches. Private reads are served either way.
func WithEdge(v *edge.Verifier) Option { return func(s *Server) { s.edge = v } }

// New builds the HTTP handler.
func New(e *core.Engine, opts ...Option) *Server {
	s := &Server{e: e, mux: http.NewServeMux()}
	for _, o := range opts {
		o(s)
	}
	if s.cookies == nil {
		// Never the key derived from the edge secret, which the services
		// that hold the secret for their own edge lifetimes could derive
		// too (edge.Verifier.CookieKey): a random key of this process.
		s.cookies = edge.NewCookies(edge.DefaultKid, nil)
	}
	m := s.mux
	m.HandleFunc("GET /{$}", s.root)

	m.HandleFunc("GET /r/{ns}/{name}", s.resourceHead)
	m.HandleFunc("PATCH /r/{ns}/{name}", s.resourcePatch)
	m.HandleFunc("DELETE /r/{ns}/{name}", s.resourceDelete)
	m.HandleFunc("GET /r/{ns}/{name}/rev/{id}", s.resourceRev)
	m.HandleFunc("GET /r/{ns}/{name}/rev/{id}/log", s.resourceRevLog)
	m.HandleFunc("GET /r/{ns}/{name}/raw", s.resourceRaw)
	m.HandleFunc("GET /r/{ns}/{name}/rev/{id}/raw", s.resourceRaw)
	m.HandleFunc("GET /r/{ns}/{name}/log", s.resourceLive)
	m.HandleFunc("GET /r/{ns}/{name}/events", s.resourceEvents)
	m.HandleFunc("POST /r/{ns}/{name}/purge", s.resourcePurge)
	m.HandleFunc("POST /r/{ns}/{name}/prune", s.resourcePrune)
	m.HandleFunc("PUT /r/{ns}/{name}/blob/{bid}", s.blobPut)
	m.HandleFunc("GET /r/{ns}/{name}/blob/{bid}", s.blobGet)
	m.HandleFunc("GET /r/{ns}/{name}/blob/{bid}/e/{e}", s.blobEpochGet)

	m.HandleFunc("GET /ns/{ns}", s.nsHead)
	m.HandleFunc("PATCH /ns/{ns}", s.nsPatch)
	m.HandleFunc("GET /ns/{ns}/rev/{id}", s.nsRev)
	m.HandleFunc("GET /ns/{ns}/rev/{id}/log", s.nsRevLog)
	m.HandleFunc("GET /ns/{ns}/rev/{id}/heads", s.nsHeads)
	m.HandleFunc("GET /ns/{ns}/log", s.nsLive)
	m.HandleFunc("GET /ns/{ns}/events", s.nsEvents)
	m.HandleFunc("GET /ns/{ns}/gestures/{gesture}", s.nsGestures)
	m.HandleFunc("GET /ns/{ns}/principal", s.nsPrincipal)
	m.HandleFunc("GET /ns/{ns}/grants/{gid}", s.nsGrant)
	m.HandleFunc("GET "+core.DefaultJWKSPath, s.operatorKeys)
	m.HandleFunc("GET /ns/{ns}/branches", s.nsBranches)
	m.HandleFunc("POST /ns/{ns}/branches", s.nsCreateBranch)
	m.HandleFunc("POST /ns/{ns}/batch", s.nsBatch)
	m.HandleFunc("POST /ns/{ns}/purge", s.nsPurge)
	m.HandleFunc("POST /ns/{ns}/keys", s.nsKeys)
	m.HandleFunc("POST /edge-grants", s.edgeGrants)
	m.HandleFunc("DELETE /edge-grants", s.withdrawEdgeGrants)
	return s
}

// ServeHTTP enforces canonical URLs (§3.6) before routing: no
// percent-escape and no empty, "." or ".." segment, a trailing "/"
// included, with the rule an edge checks them by (edge.CanonicalPath,
// §C.5.3). No route but "/" ends in "/".
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, pattern := s.mux.Handler(r)
	if blobRoutes[pattern] {
		blobHeaders(w) // the 400s below are blob responses too (§7.8 Reading)
	}
	path := r.URL.EscapedPath()
	if strings.Contains(strings.SplitN(r.RequestURI, "?", 2)[0], "%") || path != "/" && !edge.CanonicalPath(path) {
		writeErr(w, &core.Error{Status: 400, Body: map[string]any{"code": "bad_input", "message": "non-canonical URL"}})
		return
	}
	if pattern != "" {
		if err := checkQuery(pattern, r.URL.RawQuery); err != nil {
			telemetry.SetRoute(r, pattern) // the span is named by it all the same
			writeErr(w, err)
			return
		}
	}
	r = s.edgeCred(r)
	s.mux.ServeHTTP(w, r)
	annotate(r)
}

// flag marks a query parameter that takes only the value 1 (§7).
const flag = "1"

// queryParams lists, per route, the query parameters the spec defines for
// it (§7): a parameter maps to "" for any value, or to the one value it
// takes. Routes not listed take none. The JWKS (§C.4) isn't checked: like
// the services of the addenda, it isn't an endpoint of the core API.
// Signed-URL grant parameters (§C.5) never reach the origin: the edge that
// verifies them strips them before forwarding.
var queryParams = map[string]map[string]string{
	"GET /r/{ns}/{name}/rev/{id}/log": {"since": ""},                           // §7.1
	"GET /r/{ns}/{name}/log":          {"since": "", "live": "", "cursor": ""}, // §7.7 (longPoll checks live)
	"GET /r/{ns}/{name}/events":       {"since": ""},                           // §7.3
	"POST /r/{ns}/{name}/purge":       {"force": flag},                         // §6.1, §8.3
	"GET /ns/{ns}/rev/{id}/log":       {"since": ""},                           // §7.4
	"GET /ns/{ns}/rev/{id}/heads":     {"after": ""},                           // §7.4
	"GET /ns/{ns}/log":                {"since": "", "live": "", "cursor": ""}, // §7.7
	"GET /ns/{ns}/events":             {"since": ""},                           // §7.4
	"GET /ns/{ns}/gestures/{gesture}": {"after": ""},                           // §7.4
	"POST /ns/{ns}/batch":             {"dry-run": flag},                       // §7.5
	"POST /ns/{ns}/purge":             {"force": flag},                         // §8.5
	"GET " + core.DefaultJWKSPath:     nil,                                     // §C.4: not checked
	"DELETE /edge-grants":             nil,                                     // §C.5.4: prefix repeats; withdrawPrefixes checks it
}

// checkQuery answers 400 bad_input for a query parameter the route doesn't
// define, a repeated one, or a flag with a value other than 1: request-shape
// errors, answered before step 1 and not cached (§7, §6.2).
func checkQuery(pattern, raw string) error {
	allowed, listed := queryParams[pattern]
	if raw == "" || listed && allowed == nil {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return badInput("malformed query string")
	}
	for k, vs := range q {
		want, ok := allowed[k]
		switch {
		case !ok:
			return badInput(fmt.Sprintf("unknown query parameter %q (§7)", k))
		case len(vs) > 1:
			return badInput(fmt.Sprintf("query parameter %q given more than once (§7)", k))
		case want != "" && vs[0] != want:
			return badInput(fmt.Sprintf("query parameter %q takes only the value %s (§7)", k, want))
		}
	}
	return nil
}

// root is GET /: the spec version the deployment implements (§7), whether
// authentication is on ("grants") or "disabled" (§1), its canonical
// origin (§G.1) and where its operator key history is (§C.4).
func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"spec": core.SpecVersion, "auth": s.e.AuthMode(), "origin": s.e.Origin(), "jwks_uri": s.e.JWKSURI()})
}

// operatorKeys is GET /.well-known/patchlog-keys: the operator key history
// as a JWK Set (§C.4). It grows when keys are added or retired, so it is
// cached briefly. A deployment configured with another jwks_uri serves it
// here too.
func (s *Server) operatorKeys(w http.ResponseWriter, r *http.Request) {
	set, err := s.e.JWKS(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(200)
	w.Write(jsonv.Canonical(jsonv.FromGo(set)))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		w.Write(jsonv.Canonical(jsonv.FromGo(toModel(v))))
	}
}

// toModel converts encoding/json-friendly values to the jsonv model.
func toModel(v any) any {
	switch x := v.(type) {
	case nil, bool, float64, string, []any, map[string]any, []string, map[string]string, int, int64:
		return normalizeDeep(x)
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return jsonv.MustParse(b)
}

func normalizeDeep(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeDeep(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalizeDeep(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeDeep(e)
		}
		return out
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case nil, bool, float64, string, []string, map[string]string:
		return x
	}
	return toModel(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *core.Error
	if errors.As(err, &ae) {
		for k, v := range ae.Header {
			w.Header()[k] = v
		}
		if w.Header().Get("Cache-Control") == "" {
			w.Header().Set("Cache-Control", "no-store")
		}
		writeJSON(w, ae.Status, ae.Body)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// The client went away mid-request; nobody reads this response.
		writeJSON(w, 503, map[string]any{"code": "unavailable", "message": "request cancelled"})
		return
	}
	log.Printf("internal error: %v", err)
	writeJSON(w, 500, map[string]any{"code": "internal", "message": "internal error"})
}

// writeErrShort answers an error that carries its own cache class (§9),
// whose visibility the core attached: an unknown id of a known namespace,
// short, or the 410 of a purged namespace's URL, long (§8.5). It returns
// false if the error has none, leaving writeErr to answer it.
func (s *Server) writeErrShort(w http.ResponseWriter, r *http.Request, err error) bool {
	var ae *core.Error
	if !errors.As(err, &ae) || ae.Public == nil {
		return false
	}
	class := ccShort
	if ae.Status == 410 {
		class = ccLong
	}
	s.cache(w, r, class, *ae.Public)
	writeJSON(w, ae.Status, ae.Body)
	return true
}

func badInput(msg string) error {
	return &core.Error{Status: 400, Body: map[string]any{"code": "bad_input", "message": msg}}
}

// Cache classes of §9.
const (
	ccHead      = "public, max-age=0, s-maxage=1, stale-while-revalidate=5"
	ccImmutable = "public, max-age=86400, s-maxage=31536000, immutable"
	ccShort     = "public, max-age=5"
	ccLong      = "public, max-age=86400, s-maxage=31536000"
	ccPruned    = "public, max-age=3600"
)

// cache sets Cache-Control for a class, public or private (§9), and the
// cache tags. A private response gets the edge directives of s.edge: edge
// lifetimes for a read the verifying edge verified, no-store otherwise.
func (s *Server) cache(w http.ResponseWriter, r *http.Request, class string, public bool, tags ...string) {
	h := w.Header()
	if public {
		h.Set("Cache-Control", class)
	} else {
		switch class {
		case ccImmutable:
			h.Set("Cache-Control", "private, max-age=300")
		case ccShort:
			h.Set("Cache-Control", "private, max-age=5")
		default:
			h.Set("Cache-Control", "private, max-age=0")
		}
		s.edge.Private(h, r, strings.TrimPrefix(class, "public, "))
	}
	if len(tags) > 0 {
		h.Set("Cache-Tag", strings.Join(tags, ","))
		h.Set("Surrogate-Key", strings.Join(tags, " "))
	}
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func quote(id string) string { return `"` + id + `"` }

func resTags(ns, name string) []string { return []string{"ns:" + ns, "r:" + ns + "/" + name} }

// writeLog answers a log range (§7.1, §7.4), or a live read's error. A
// range longer than the log page size (§6.6) answers its first page with
// X-Log-Next naming the page's last entry, the since of the next page
// (§7.1 Paging). Every page is a prefix of its immutable range, so it
// caches as immutable too.
func (s *Server) writeLog(w http.ResponseWriter, r *http.Request, lg *core.Log, ns string, tags []string) {
	switch lg.Status {
	case 200:
		s.cache(w, r, ccImmutable, lg.Public, tags...)
		if lg.More {
			w.Header().Set("X-Log-Next", lg.Last)
		}
		writeLogBody(w, lg)
	case 404:
		s.cache(w, r, ccShort, lg.Public)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	default:
		if lg.Horizon != "" {
			s.cache(w, r, ccPruned, lg.Public, tags...)
			writeJSON(w, 410, prunedBody(lg.Horizon, lg.Archive))
			return
		}
		s.cache(w, r, ccLong, lg.Public)
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}

// writeLogBody writes a 200 log answer: the entries, or in a sealed
// namespace (Addendum E.2) the range's JWE (namespace logs) or an array of
// per-entry JWEs (resource logs).
func writeLogBody(w http.ResponseWriter, lg *core.Log) {
	switch {
	case lg.Sealed && lg.Range != "":
		w.Header().Set("Content-Type", seal.ContentType)
		w.WriteHeader(200)
		io.WriteString(w, lg.Range)
	case lg.Sealed:
		entries := make([]any, len(lg.EntryJWEs))
		for i, e := range lg.EntryJWEs {
			entries[i] = e
		}
		writeJSON(w, 200, entries)
	default:
		entries := make([]any, len(lg.Entries))
		for i, e := range lg.Entries {
			entries[i] = e
		}
		writeJSON(w, 200, entries)
	}
}

// prunedBody is the 410 of §7.1 for pruned history.
func prunedBody(horizon, archive string) map[string]any {
	b := map[string]any{"code": "pruned", "horizon": horizon}
	if archive != "" {
		b["archive"] = archive
	}
	return b
}
