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
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/seal"
)

// Server is the HTTP API.
type Server struct {
	e    *core.Engine
	mux  *http.ServeMux
	edge *edge.Verifier // nil: no verifying edge (§9)
}

// Option configures a Server.
type Option func(*Server)

// WithEdge declares a verifying edge in front of the origin (§9): private
// reads are served only to requests carrying its secret, with edge
// lifetimes. Without it (or with nil) private responses are marked no-store
// for shared caches.
func WithEdge(v *edge.Verifier) Option { return func(s *Server) { s.edge = v } }

// New builds the HTTP handler.
func New(e *core.Engine, opts ...Option) *Server {
	s := &Server{e: e, mux: http.NewServeMux()}
	for _, o := range opts {
		o(s)
	}
	m := s.mux
	m.HandleFunc("GET /{$}", s.root)

	m.HandleFunc("GET /r/{ns}/{name}", s.resourceHead)
	m.HandleFunc("PATCH /r/{ns}/{name}", s.resourcePatch)
	m.HandleFunc("DELETE /r/{ns}/{name}", s.resourceDelete)
	m.HandleFunc("GET /r/{ns}/{name}/rev/{id}", s.resourceRev)
	m.HandleFunc("GET /r/{ns}/{name}/rev/{id}/log", s.resourceRevLog)
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
	m.HandleFunc("GET /ns/{ns}/branches", s.nsBranches)
	m.HandleFunc("POST /ns/{ns}/branches", s.nsCreateBranch)
	m.HandleFunc("POST /ns/{ns}/batch", s.nsBatch)
	m.HandleFunc("POST /ns/{ns}/purge", s.nsPurge)
	m.HandleFunc("POST /ns/{ns}/keys", s.nsKeys)
	return s
}

// ServeHTTP enforces canonical URLs (§3.6) before routing.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if strings.Contains(r.RequestURI, "%") && strings.Contains(strings.SplitN(r.RequestURI, "?", 2)[0], "%") ||
		strings.Contains(path, "//") || strings.Contains(path, "/./") || strings.Contains(path, "/../") ||
		strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") {
		writeErr(w, &core.Error{Status: 400, Body: map[string]any{"code": "bad_input", "message": "non-canonical URL"}})
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"origin": s.e.Origin()})
}

// --- helpers -----------------------------------------------------------

// sourceCreds are Source-Authorization's (§7.8): the grant a copy's or a
// batch's source is read with.
func sourceCreds(r *http.Request) core.Credentials {
	var c core.Credentials
	if a := r.Header.Get("Source-Authorization"); strings.HasPrefix(a, "Bearer ") {
		c.Bearer = strings.TrimSpace(a[len("Bearer "):])
	}
	return c
}

func creds(r *http.Request) core.Credentials {
	c := core.Credentials{Author: r.Header.Get("X-Author")}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		c.Bearer = strings.TrimSpace(a[len("Bearer "):])
	}
	return c
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

func badInput(msg string) error {
	return &core.Error{Status: 400, Body: map[string]any{"code": "bad_input", "message": msg}}
}

// readJSON reads and strictly parses an I-JSON body (§3.1).
func readJSON(r *http.Request, max int) (any, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil {
		return nil, badInput("could not read body")
	}
	if len(body) > max {
		return nil, &core.Error{Status: 413, Body: map[string]any{"code": "limit", "message": "request too large"}}
	}
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, badInput(err.Error())
	}
	return v, nil
}

func mediaType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

// etag parses a single strong ETag from If-Match / If-None-Match.
func etag(h string) (string, bool) {
	h = strings.TrimSpace(h)
	if len(h) >= 2 && h[0] == '"' && h[len(h)-1] == '"' {
		return h[1 : len(h)-1], true
	}
	return "", false
}

type precond struct {
	ifMatch     string
	ifNoneMatch bool
}

func preconditions(r *http.Request) (precond, error) {
	var p precond
	if v := r.Header.Get("If-None-Match"); v != "" {
		if strings.TrimSpace(v) != "*" {
			return p, badInput("If-None-Match must be *")
		}
		p.ifNoneMatch = true
	}
	if v := r.Header.Get("If-Match"); v != "" {
		t, ok := etag(v)
		if !ok {
			return p, badInput("If-Match must be one quoted id")
		}
		p.ifMatch = t
	}
	if p.ifMatch != "" && p.ifNoneMatch {
		return p, badInput("both If-Match and If-None-Match")
	}
	return p, nil
}

func validNames(ns, name string) error {
	if !core.ValidNSName(ns) {
		return badInput("invalid namespace name")
	}
	if name != "" && !core.ValidResourceName(name) {
		return badInput("invalid resource name")
	}
	return nil
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
// lifetimes behind a verifying edge, no-store otherwise. It returns false,
// having answered 403 instead, for a private response to a request that
// didn't come through the verifying edge.
func (s *Server) cache(w http.ResponseWriter, r *http.Request, class string, public bool, tags ...string) bool {
	if !s.edgeAllow(w, r, public) {
		return false
	}
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
		s.edge.Private(h, strings.TrimPrefix(class, "public, "))
	}
	if len(tags) > 0 {
		h.Set("Cache-Tag", strings.Join(tags, ","))
		h.Set("Surrogate-Key", strings.Join(tags, " "))
	}
	return true
}

// edgeAllow answers 403 edge_required, and returns false, for a private
// response to a request without the verifying edge's secret, when the
// origin is configured with one (§9). The origin has checked the grant
// either way; this keeps responses fetched around the edge from being ones
// the edge would cache without verifying.
func (s *Server) edgeAllow(w http.ResponseWriter, r *http.Request, public bool) bool {
	if s.edge.Allow(r, public) {
		return true
	}
	writeErr(w, &core.Error{Status: 403, Body: map[string]any{"code": edge.Code, "message": edge.Message}})
	return false
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func quote(id string) string { return `"` + id + `"` }

func resTags(ns, name string) []string { return []string{"ns:" + ns, "r:" + ns + "/" + name} }

// --- resources ---------------------------------------------------------

func (s *Server) resourceHead(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	h, err := s.e.ResourceHead(r.Context(), ns, name, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	switch h.State {
	case core.NotFound:
		if !s.cache(w, r, ccShort, h.Public) {
			return
		}
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case core.Purged:
		if !s.cache(w, r, ccLong, h.Public) {
			return
		}
		writeJSON(w, 410, map[string]any{"code": "gone"})
	case core.Tombstoned:
		if !s.cache(w, r, ccHead, h.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("ETag", quote(h.Head))
		writeJSON(w, 410, map[string]any{"code": "gone", "tombstone": h.Head, "last": h.Last})
	default:
		if !s.cache(w, r, ccHead, h.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("ETag", quote(h.Head))
		w.Header().Set("Location", "/r/"+ns+"/"+name+"/rev/"+h.Head)
		w.WriteHeader(302)
	}
}

func (s *Server) resourceRev(w http.ResponseWriter, r *http.Request) {
	ns, name, id := r.PathValue("ns"), r.PathValue("name"), r.PathValue("id")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	rev, err := s.e.ResourceRev(r.Context(), ns, name, id, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	switch {
	case rev.Fold:
		// An e2e revision (§E.3): the server has no document, so the
		// client folds the log from the latest snapshot at or before it.
		// The target only changes when a prune adds a newer snapshot,
		// and the old target stays correct (§8.6), so it caches long.
		loc := "/r/" + ns + "/" + name + "/rev/" + id + "/log"
		if rev.FoldSince != "" {
			loc += "?since=" + rev.FoldSince
		}
		if !s.cache(w, r, ccLong, rev.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("ETag", quote(id))
		w.Header().Set("X-Revision", id)
		w.Header().Set("X-E2E", "fold")
		w.Header().Set("Location", loc)
		w.WriteHeader(302)
	case rev.Status == 200:
		if !s.cache(w, r, ccImmutable, rev.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("ETag", quote(id))
		w.Header().Set("X-Revision", id)
		if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, quote(id)) {
			w.WriteHeader(304)
			return
		}
		body, ct := rev.Doc, "application/json"
		if rev.JWE != "" {
			body, ct = []byte(rev.JWE), seal.ContentType
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(200)
		if r.Method != http.MethodHead {
			w.Write(body)
		}
	case rev.Status == 404:
		if !s.cache(w, r, ccShort, rev.Public) {
			return
		}
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case rev.Code == "pruned":
		if !s.cache(w, r, ccPruned, rev.Public, resTags(ns, name)...) {
			return
		}
		writeJSON(w, 410, prunedBody(rev.Horizon, rev.Archive))
	case rev.Code == "tombstone":
		// A tombstone id is immutable (§7.1).
		if !s.cache(w, r, ccImmutable, rev.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("ETag", quote(id))
		writeJSON(w, 410, map[string]any{"code": "gone"})
	default:
		// A purge is "long".
		if !s.cache(w, r, ccLong, rev.Public) {
			return
		}
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}

func (s *Server) resourceRevLog(w http.ResponseWriter, r *http.Request) {
	ns, name, id := r.PathValue("ns"), r.PathValue("name"), r.PathValue("id")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	lg, err := s.e.ResourceLog(r.Context(), ns, name, id, r.URL.Query().Get("since"), 0, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	s.writeLog(w, r, lg, ns, resTags(ns, name))
}

func (s *Server) writeLog(w http.ResponseWriter, r *http.Request, lg *core.Log, ns string, tags []string) {
	switch lg.Status {
	case 200:
		if !s.cache(w, r, ccImmutable, lg.Public, tags...) {
			return
		}
		writeLogBody(w, lg)
	case 404:
		if !s.cache(w, r, ccShort, lg.Public) {
			return
		}
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	default:
		if lg.Horizon != "" {
			if !s.cache(w, r, ccPruned, lg.Public, tags...) {
				return
			}
			writeJSON(w, 410, prunedBody(lg.Horizon, lg.Archive))
			return
		}
		if !s.cache(w, r, ccLong, lg.Public) {
			return
		}
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

func (s *Server) resourcePatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	if mediaType(r) != "application/json-patch+json" {
		writeErr(w, &core.Error{Status: 415, Body: map[string]any{"code": "bad_input", "message": "use application/json-patch+json"}})
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	body, err := readJSON(r, max(s.e.Limits().PatchSetSize, s.e.Limits().DocumentSize)*4)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := s.e.WriteResource(r.Context(), core.Request{NS: ns, Cred: creds(r), Signature: r.Header.Get("Signature")},
		core.Item{Resource: name, IfMatch: p.ifMatch, IfNoneMatch: p.ifNoneMatch, Steps: []core.Step{{Patches: body}}})
	if err != nil {
		writeErr(w, err)
		return
	}
	id := res.Items[0].IDs[len(res.Items[0].IDs)-1]
	w.Header().Set("Location", "/r/"+ns+"/"+name+"/rev/"+id)
	w.Header().Set("ETag", quote(id))
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	writeJSON(w, res.Status, res.Entry)
}

func (s *Server) resourceDelete(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if p.ifNoneMatch {
		writeErr(w, badInput("DELETE takes If-Match"))
		return
	}
	res, err := s.e.WriteResource(r.Context(), core.Request{NS: ns, Cred: creds(r)},
		core.Item{Resource: name, IfMatch: p.ifMatch, Steps: []core.Step{{Delete: true}}})
	if err != nil {
		writeErr(w, err)
		return
	}
	id := res.Items[0].IDs[0]
	w.Header().Set("ETag", quote(id))
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	writeJSON(w, 200, map[string]any{"tombstone": id})
}

func (s *Server) resourcePurge(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	force := r.URL.Query().Get("force") == "1"
	nsID, err := s.e.Purge(r.Context(), core.Request{NS: ns, Cred: creds(r)}, name, p.ifMatch, force)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Namespace-Revision", nsID)
	w.WriteHeader(204)
}

func (s *Server) resourcePrune(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	body, err := readJSON(r, 1<<20)
	if err != nil {
		writeErr(w, err)
		return
	}
	m, ok := body.(map[string]any)
	h, _ := m["horizon"].(string)
	if !ok || h == "" {
		writeErr(w, badInput("body must be { horizon, keep?, snapshot? }"))
		return
	}
	var keep []string
	if k, has := m["keep"]; has {
		arr, ok := k.([]any)
		if !ok {
			writeErr(w, badInput("keep must be an array of ids"))
			return
		}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok {
				writeErr(w, badInput("keep must be an array of ids"))
				return
			}
			keep = append(keep, s)
		}
	}
	var snapshot string
	if x, has := m["snapshot"]; has {
		if snapshot, ok = x.(string); !ok || snapshot == "" {
			writeErr(w, badInput("snapshot must be a JWE (compact serialization)"))
			return
		}
	}
	// A sealed snapshot needs no declared list (§8.6, §E.3.1): the server
	// keeps the list of the snapshot's revision.
	pr := core.PruneRequest{Horizon: h, Keep: keep, Snapshot: snapshot}
	res, err := s.e.Prune(r.Context(), core.Request{NS: ns, Cred: creds(r)}, name, pr)
	if err != nil {
		writeErr(w, err)
		return
	}
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	out := map[string]any{"horizon": res.Horizon}
	if res.Archive != "" {
		out["archive"] = res.Archive
	}
	writeJSON(w, 200, out)
}

// --- blobs (§7.8) --------------------------------------------------------

func (s *Server) blobPut(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns, name, bid := r.PathValue("ns"), r.PathValue("name"), r.PathValue("bid")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	up := core.BlobUpload{Type: r.Header.Get("Content-Type"), Nonce: r.Header.Get("Blob-Nonce"),
		From: r.Header.Get("Blob-From"), Body: r.Body, Length: r.ContentLength}
	if up.From != "" {
		// A copy has an empty body (400 if not, in its place in the order,
		// before any body is read): a declared length says so; only a
		// body of unknown length is peeked at.
		switch {
		case r.ContentLength > 0:
			up.HasBody = true
		case r.ContentLength < 0:
			var one [1]byte
			n, _ := io.ReadFull(r.Body, one[:])
			up.HasBody = n > 0
		}
	}
	req := core.Request{NS: ns, Cred: creds(r), SourceCred: sourceCreds(r)}
	if err := s.e.UploadBlob(r.Context(), req, name, bid, up); err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("ETag", quote(bid))
	w.Header().Set("Location", "/r/"+ns+"/"+name+"/blob/"+bid)
	w.WriteHeader(201)
}

func (s *Server) blobGet(w http.ResponseWriter, r *http.Request) {
	ns, name, bid := r.PathValue("ns"), r.PathValue("name"), r.PathValue("bid")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	b, err := s.e.OpenBlob(r.Context(), ns, name, bid, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	defer b.Close()
	if b.Status == 302 {
		// A sealed namespace: to the latest epoch the blob is served under,
		// cached as a head pointer (§E.2.2).
		if !s.cache(w, r, ccHead, b.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("Location", "/r/"+ns+"/"+name+"/blob/"+bid+"/e/"+strconv.Itoa(b.Epoch))
		w.WriteHeader(302)
		return
	}
	s.serveBlob(w, r, ns, name, quote(bid), b)
}

// blobEpochGet serves a blob of a sealed namespace sealed under an epoch
// (§E.2.2).
func (s *Server) blobEpochGet(w http.ResponseWriter, r *http.Request) {
	ns, name, bid, ep := r.PathValue("ns"), r.PathValue("name"), r.PathValue("bid"), r.PathValue("e")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	b, err := s.e.OpenSealedBlob(r.Context(), ns, name, bid, ep, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	defer b.Close()
	s.serveBlob(w, r, ns, name, quote(bid+"."+ep), b)
}

// serveBlob writes a blob answer (§7.8 Reading) with ETag etag for a 200.
func (s *Server) serveBlob(w http.ResponseWriter, r *http.Request, ns, name, etag string, b *core.Blob) {
	switch {
	case b.Status == 200:
		// Immutable, with the resource's tags (§9); ranges are 206.
		if !s.cache(w, r, ccImmutable, b.Public, resTags(ns, name)...) {
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", b.Type)
		http.ServeContent(w, r, "", time.Time{}, b.Content)
	case b.NoStore:
		// An epoch a sealed namespace doesn't serve the blob under, yet
		// (§E.2.2).
		if !s.edgeAllow(w, r, b.Public) {
			return
		}
		noStore(w)
		writeJSON(w, b.Status, map[string]any{"code": "not_found"})
	case b.Status == 404:
		if !s.cache(w, r, ccShort, b.Public) {
			return
		}
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case b.Code == "pruned":
		if !s.cache(w, r, ccPruned, b.Public, resTags(ns, name)...) {
			return
		}
		writeJSON(w, 410, prunedBody(b.Horizon, b.Archive))
	case b.Status == 410:
		if !s.cache(w, r, ccLong, b.Public) {
			return
		}
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}

// --- namespaces --------------------------------------------------------

func (s *Server) nsHead(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	info, err := s.e.NamespaceHead(r.Context(), ns, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !s.cache(w, r, ccHead, info.Public, "ns:"+ns) {
		return
	}
	w.Header().Set("ETag", quote(info.Head))
	w.Header().Set("X-Config-Revision", info.Config)
	w.Header().Set("Location", "/ns/"+ns+"/rev/"+info.Head)
	w.WriteHeader(302)
}

func (s *Server) nsRev(w http.ResponseWriter, r *http.Request) {
	ns, id := r.PathValue("ns"), r.PathValue("id")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	info, err := s.e.NamespaceRev(r.Context(), ns, id, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !s.cache(w, r, ccImmutable, info.Public, "ns:"+ns) {
		return
	}
	w.Header().Set("ETag", quote(id))
	w.Header().Set("X-Config-Revision", info.Config)
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, quote(id)) {
		w.WriteHeader(304)
		return
	}
	body, ct := info.Doc, "application/json"
	if info.JWE != "" {
		body, ct = []byte(info.JWE), seal.ContentType
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func (s *Server) nsRevLog(w http.ResponseWriter, r *http.Request) {
	ns, id := r.PathValue("ns"), r.PathValue("id")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	lg, err := s.e.NamespaceLog(r.Context(), ns, id, r.URL.Query().Get("since"), 0, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	s.writeLog(w, r, lg, ns, []string{"ns:" + ns})
}

func (s *Server) nsHeads(w http.ResponseWriter, r *http.Request) {
	ns, id := r.PathValue("ns"), r.PathValue("id")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	page, err := s.e.NamespaceHeads(r.Context(), ns, id, r.URL.Query().Get("after"), creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !s.cache(w, r, ccImmutable, page.Public, "ns:"+ns) {
		return
	}
	out := map[string]any{"items": page.Items}
	if page.Next != "" {
		out["next"] = page.Next
	}
	writeJSON(w, 200, out)
}

func (s *Server) nsBranches(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	list, public, err := s.e.Branches(r.Context(), ns, creds(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if !s.cache(w, r, ccHead, public, "ns:"+ns) {
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) nsPatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	if mediaType(r) != "application/json-patch+json" {
		writeErr(w, &core.Error{Status: 415, Body: map[string]any{"code": "bad_input", "message": "use application/json-patch+json"}})
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	body, err := readJSON(r, max(s.e.Limits().PatchSetSize, s.e.Limits().DocumentSize)*4)
	if err != nil {
		writeErr(w, err)
		return
	}
	if p.ifMatch == "" && !p.ifNoneMatch {
		writeErr(w, &core.Error{Status: 428, Body: map[string]any{"code": "precondition_required"}})
		return
	}
	res, err := s.e.WriteConfig(r.Context(), core.Request{NS: ns, Cred: creds(r)},
		core.ConfigChange{IfMatch: p.ifMatch, IfNoneMatch: p.ifNoneMatch, Patches: body})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Config-Revision", res.ConfigID)
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
		w.Header().Set("Location", "/ns/"+ns+"/rev/"+res.NSID)
	}
	out := map[string]any{"config": res.ConfigID}
	if res.NSID != "" {
		out["ns_id"] = res.NSID
	}
	writeJSON(w, res.Status, out)
}

func (s *Server) nsCreateBranch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	body, err := readJSON(r, max(s.e.Limits().PatchSetSize, s.e.Limits().DocumentSize)*4)
	if err != nil {
		writeErr(w, err)
		return
	}
	m, ok := body.(map[string]any)
	if !ok {
		writeErr(w, badInput("body must be { name, at?, patches? }"))
		return
	}
	if _, remote := m["remote"]; remote {
		s.registerRemote(w, r, ns, p, m)
		return
	}
	if !p.ifNoneMatch {
		writeErr(w, &core.Error{Status: 428, Body: map[string]any{"code": "precondition_required"}})
		return
	}
	for k := range m {
		if k != "name" && k != "at" && k != "patches" {
			writeErr(w, badInput("unknown member "+k))
			return
		}
	}
	name, _ := m["name"].(string)
	at, _ := m["at"].(string)
	res, err := s.e.CreateBranch(r.Context(), core.Request{NS: ns, Cred: creds(r)},
		core.BranchRequest{Name: name, At: at, Patches: m["patches"], IfNoneMatch: true})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Location", "/ns/"+name)
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	out := map[string]any{"name": name, "config": res.ConfigID}
	if res.NSID != "" {
		out["ns_id"] = res.NSID
	}
	writeJSON(w, res.Status, out)
}

// registerRemote registers or renews a remote branch (§G.3):
// { "remote": { "origin", "ns" }, "at" } with If-None-Match: * or If-Match.
func (s *Server) registerRemote(w http.ResponseWriter, r *http.Request, ns string, p precond, m map[string]any) {
	rm, ok := m["remote"].(map[string]any)
	origin, _ := rm["origin"].(string)
	name, _ := rm["ns"].(string)
	at, _ := m["at"].(string)
	if !ok || len(rm) != 2 || origin == "" || name == "" || at == "" || len(m) != 2 {
		writeErr(w, badInput("body must be { remote: { origin, ns }, at }"))
		return
	}
	if !p.ifNoneMatch && p.ifMatch == "" {
		writeErr(w, &core.Error{Status: 428, Body: map[string]any{"code": "precondition_required"}})
		return
	}
	res, err := s.e.RegisterRemoteBranch(r.Context(), core.Request{NS: ns, Cred: creds(r)},
		core.RemoteRegistration{Origin: origin, NS: name, At: at, IfNoneMatch: p.ifNoneMatch, IfMatch: p.ifMatch})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Namespace-Revision", res.NSID)
	w.Header().Set("ETag", quote(res.NSID))
	writeJSON(w, res.Status, res.Value())
}

func (s *Server) nsBatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	// Batch limits depend on the principal (§6.6): authenticate first, then
	// stop reading a body larger than that principal's batchSize (§7.5).
	req := core.Request{NS: ns, Cred: creds(r), SourceCred: sourceCreds(r)}
	max, err := s.e.BatchBodyLimit(r.Context(), req)
	if err != nil {
		writeErr(w, err)
		return
	}
	body, err := readJSON(r, max)
	if err != nil {
		writeErr(w, err)
		return
	}
	items, cc, source, err := parseBatch(body)
	if err != nil {
		writeErr(w, err)
		return
	}
	dry := r.URL.Query().Get("dry-run") == "1"
	res, err := s.e.Batch(r.Context(), req, items, cc, source, dry)
	if err != nil {
		writeErr(w, err)
		return
	}
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	report := make([]any, len(res.Items))
	for i, it := range res.Items {
		report[i] = it.Value()
	}
	out := map[string]any{"items": report}
	if res.NSID != "" {
		out["ns_id"] = res.NSID
	}
	if res.ConfigID != "" {
		out["config"] = res.ConfigID
	}
	writeJSON(w, res.Status, out)
}

func parseBatch(body any) ([]core.Item, *core.ConfigChange, any, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, nil, nil, badInput("batch body must be an object")
	}
	for k := range m {
		if k != "items" && k != "config" && k != "source" {
			return nil, nil, nil, badInput("unknown member " + k)
		}
	}
	var items []core.Item
	if iv, has := m["items"]; has {
		arr, ok := iv.([]any)
		if !ok {
			return nil, nil, nil, badInput("items must be an array")
		}
		for i, x := range arr {
			o, ok := x.(map[string]any)
			if !ok {
				return nil, nil, nil, badInput(fmt.Sprintf("item %d must be an object", i))
			}
			it := core.Item{}
			for k, v := range o {
				switch k {
				case "resource":
					it.Resource, _ = v.(string)
				case "ifMatch":
					s, ok := v.(string)
					if !ok {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: ifMatch must be an id", i))
					}
					it.IfMatch = s
				case "ifNoneMatch":
					if v != "*" {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: ifNoneMatch must be \"*\"", i))
					}
					it.IfNoneMatch = true
				case "steps":
					steps, ok := v.([]any)
					if !ok {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: steps must be an array", i))
					}
					for _, st := range steps {
						if st == "delete" {
							it.Steps = append(it.Steps, core.Step{Delete: true})
						} else if _, ok := st.([]any); ok {
							it.Steps = append(it.Steps, core.Step{Patches: st})
						} else {
							return nil, nil, nil, badInput(fmt.Sprintf("item %d: a step is a patch set or \"delete\"", i))
						}
					}
				default:
					return nil, nil, nil, badInput(fmt.Sprintf("item %d: unknown member %s", i, k))
				}
			}
			items = append(items, it)
		}
	}
	var cc *core.ConfigChange
	if cv, has := m["config"]; has {
		o, ok := cv.(map[string]any)
		if !ok {
			return nil, nil, nil, badInput("config must be an object")
		}
		cc = &core.ConfigChange{Patches: o["patches"]}
		cc.IfMatch, _ = o["ifMatch"].(string)
		if cc.Patches == nil {
			return nil, nil, nil, badInput("config needs patches")
		}
	}
	return items, cc, m["source"], nil
}

func (s *Server) nsPurge(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	p, err := preconditions(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	nsID, err := s.e.PurgeNamespace(r.Context(), core.Request{NS: ns, Cred: creds(r)}, p.ifMatch)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("X-Namespace-Revision", nsID)
	w.WriteHeader(204)
}

// --- live reads (§7.3, §7.7) --------------------------------------------

// longPoll implements §7.7 for a log fetched by fetch.
func (s *Server) longPoll(w http.ResponseWriter, r *http.Request, ns, header string, tags []string,
	fetch func(ctx context.Context, since string) (*core.Log, error)) {
	q := r.URL.Query()
	for k := range q {
		if k != "since" && k != "live" && k != "cursor" {
			writeErr(w, badInput("unknown query parameter "+k))
			return
		}
	}
	since := q.Get("since")
	if q.Get("live") != "long-poll" {
		if q.Has("live") {
			writeErr(w, badInput("live must be long-poll"))
			return
		}
		return // caller redirects
	}
	interval := s.e.LongPollInterval()
	now := time.Now()
	current := now.UnixNano() / int64(interval)
	var reqCursor int64 = -1
	if c := q.Get("cursor"); c != "" {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, badInput("invalid cursor"))
			return
		}
		if n > current+int64(time.Hour/interval) {
			writeErr(w, badInput("cursor too far ahead"))
			return
		}
		reqCursor = n
	}
	deadline := time.Unix(0, (current+1)*int64(interval))
	for {
		wait := s.e.Wait(ns)
		lg, err := fetch(r.Context(), since)
		if err != nil {
			writeErr(w, err)
			return
		}
		if lg.Status != 200 {
			s.writeLog(w, r, lg, ns, tags)
			return
		}
		if len(lg.Entries) > 0 {
			if !s.setLive(w, r, lg.Public, fmt.Sprintf("public, max-age=0, s-maxage=%d", int(interval.Seconds())), tags) {
				return
			}
			w.Header().Set(header, lg.Last)
			w.Header().Set("X-Cursor", strconv.FormatInt(time.Now().UnixNano()/int64(interval), 10))
			writeLogBody(w, lg)
			return
		}
		// Refuse a private wait around the edge before waiting.
		if !s.edgeAllow(w, r, lg.Public) {
			return
		}
		select {
		case <-wait:
			continue
		case <-time.After(time.Until(deadline)):
		case <-lifecycle.Stopping(r.Context()):
			// The server is shutting down: the normal "no change" answer
			// now, so the client polls again (elsewhere).
		case <-r.Context().Done():
			return
		}
		cur := time.Now().UnixNano() / int64(interval)
		if reqCursor+1 > cur {
			cur = reqCursor + 1
		}
		if !s.setLive(w, r, lg.Public, "public, max-age=0, s-maxage=2", tags) {
			return
		}
		w.Header().Set(header, since)
		w.Header().Set("X-Cursor", strconv.FormatInt(cur, 10))
		w.WriteHeader(204)
		return
	}
}

// setLive sets the headers of a long-poll answer (§7.7, §9); like cache it
// returns false, having answered 403, for a private answer to a request that
// didn't come through the verifying edge.
func (s *Server) setLive(w http.ResponseWriter, r *http.Request, public bool, cc string, tags []string) bool {
	if !s.edgeAllow(w, r, public) {
		return false
	}
	if public {
		w.Header().Set("Cache-Control", cc)
	} else {
		w.Header().Set("Cache-Control", "private, max-age=0")
		s.edge.Private(w.Header(), strings.TrimPrefix(cc, "public, "))
	}
	w.Header().Set("Cache-Tag", strings.Join(tags, ","))
	w.Header().Set("Surrogate-Key", strings.Join(tags, " "))
	return true
}

func (s *Server) resourceLive(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	lim := s.e.Limits().LogPageSize
	if r.URL.Query().Get("live") == "" {
		h, err := s.e.ResourceHead(r.Context(), ns, name, creds(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		if h.Head == "" {
			code := 404
			if h.State == core.Purged {
				code = 410
			}
			writeJSON(w, code, map[string]any{"code": map[int]string{404: "not_found", 410: "gone"}[code]})
			return
		}
		if !s.cache(w, r, ccHead, h.Public, resTags(ns, name)...) {
			return
		}
		loc := "/r/" + ns + "/" + name + "/rev/" + h.Head + "/log"
		if sn := r.URL.Query().Get("since"); sn != "" {
			loc += "?since=" + sn
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(302)
		return
	}
	s.longPoll(w, r, ns, "X-Revision", resTags(ns, name), func(ctx context.Context, since string) (*core.Log, error) {
		return s.e.ResourceLog(ctx, ns, name, "", since, lim, creds(r))
	})
}

func (s *Server) nsLive(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	lim := s.e.Limits().LogPageSize
	if r.URL.Query().Get("live") == "" {
		info, err := s.e.NamespaceHead(r.Context(), ns, creds(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		if !s.cache(w, r, ccHead, info.Public, "ns:"+ns) {
			return
		}
		loc := "/ns/" + ns + "/rev/" + info.Head + "/log"
		if sn := r.URL.Query().Get("since"); sn != "" {
			loc += "?since=" + sn
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(302)
		return
	}
	s.longPoll(w, r, ns, "X-Namespace-Revision", []string{"ns:" + ns}, func(ctx context.Context, since string) (*core.Log, error) {
		return s.e.NamespaceLog(ctx, ns, "", since, lim, creds(r))
	})
}

// sse writes one server-sent event.
func sse(w http.ResponseWriter, event, id string, data any) {
	sseRaw(w, event, id, string(jsonv.Canonical(jsonv.FromGo(toModel(data)))))
}

// sseRaw writes one server-sent event whose data is one line of text (a
// JWE in sealed namespaces, Addendum E.2).
func sseRaw(w http.ResponseWriter, event, id, data string) {
	fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", event, id, data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// sseEntry writes entry i of lg: its JWE in a sealed namespace.
func sseEntry(w http.ResponseWriter, event string, lg *core.Log, i int) {
	e := lg.Entries[i]
	if lg.Sealed {
		sseRaw(w, event, e["id"].(string), lg.EntryJWEs[i])
		return
	}
	sse(w, event, e["id"].(string), e)
}

// prunedBody is the 410 of §7.1 for pruned history.
func prunedBody(horizon, archive string) map[string]any {
	b := map[string]any{"code": "pruned", "horizon": horizon}
	if archive != "" {
		b["archive"] = archive
	}
	return b
}

func sinceParam(r *http.Request) string {
	if s := r.URL.Query().Get("since"); s != "" {
		return s
	}
	return r.Header.Get("Last-Event-ID")
}

// sseLogErr answers an event stream request whose replay failed (404, 410
// or 410 pruned). Like every SSE response it is no-store (§9).
func sseLogErr(w http.ResponseWriter, lg *core.Log) {
	noStore(w)
	switch {
	case lg.Status == 404:
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case lg.Horizon != "":
		writeJSON(w, 410, prunedBody(lg.Horizon, lg.Archive))
	default:
		writeJSON(w, 410, map[string]any{"code": "gone"})
	}
}

func startSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) nsEvents(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	since := sinceParam(r)
	cred := creds(r)
	// Wait before every fetch, so no entry committed in between is missed.
	wait := s.e.Wait(ns)
	lg, err := s.e.NamespaceEvents(r.Context(), ns, since, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	if lg.Status != 200 {
		sseLogErr(w, lg)
		return
	}
	startSSE(w)
	for {
		for i, e := range lg.Entries {
			sseEntry(w, e["kind"].(string), lg, i)
			since = e["id"].(string)
		}
		select {
		case <-wait:
		case <-time.After(30 * time.Second):
			fmt.Fprint(w, ": keep-alive\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-lifecycle.Stopping(r.Context()):
			// The server is shutting down: end the stream; EventSource
			// reconnects with Last-Event-ID (elsewhere).
			return
		case <-r.Context().Done():
			return
		}
		wait = s.e.Wait(ns)
		lg, err = s.e.NamespaceEvents(r.Context(), ns, since, cred)
		if err != nil || lg.Status != 200 {
			return
		}
	}
}

func (s *Server) resourceEvents(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := validNames(ns, name); err != nil {
		writeErr(w, err)
		return
	}
	cred := creds(r)
	since := sinceParam(r)
	// Wait before every fetch, so no entry committed in between is missed.
	wait := s.e.Wait(ns)
	info, err := s.e.NamespaceHead(r.Context(), ns, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	nsSince := info.Head
	lg, err := s.e.ResourceLog(r.Context(), ns, name, "", since, 0, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	if lg.Status != 200 {
		sseLogErr(w, lg)
		return
	}
	startSSE(w)
	emit := func(lg *core.Log) {
		for i, e := range lg.Entries {
			ev := "revision"
			if e["kind"] == "tombstone" {
				ev = "tombstone"
			}
			sseEntry(w, ev, lg, i)
			since = e["id"].(string)
		}
	}
	emit(lg)
	for {
		select {
		case <-wait:
		case <-time.After(30 * time.Second):
			fmt.Fprint(w, ": keep-alive\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			continue
		case <-lifecycle.Stopping(r.Context()):
			// The server is shutting down: end the stream; EventSource
			// reconnects with Last-Event-ID (elsewhere).
			return
		case <-r.Context().Done():
			return
		}
		wait = s.e.Wait(ns)
		nl, err := s.e.NamespaceEvents(r.Context(), ns, nsSince, cred)
		if err != nil || nl.Status != 200 {
			return
		}
		nsSince = nl.Last
		for i, e := range nl.Entries {
			if e["resource"] != name {
				continue
			}
			switch e["kind"] {
			case "purge":
				sseEntry(w, "purge", nl, i)
				return
			case "prune":
				sseEntry(w, "prune", nl, i)
			}
		}
		lg, err := s.e.ResourceLog(r.Context(), ns, name, "", since, 0, cred)
		if err != nil || lg.Status != 200 {
			return
		}
		emit(lg)
	}
}

// nsKeys answers POST /ns/{ns}/keys (§E.2.3): { "epochs"?: [e…],
// "resources"?: [name…] } → { "keys": [ { kid, resource?, key | suite,
// wrapped } ] }, never cached.
func (s *Server) nsKeys(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	var kr core.KeysRequest
	if r.ContentLength != 0 {
		body, err := readJSON(r, 1<<20)
		if err != nil {
			writeErr(w, err)
			return
		}
		m, ok := body.(map[string]any)
		if !ok {
			writeErr(w, badInput(`body must be { "epochs"?, "resources"? }`))
			return
		}
		for k, v := range m {
			arr, ok := v.([]any)
			if !ok {
				writeErr(w, badInput(k+" must be an array"))
				return
			}
			switch k {
			case "epochs":
				kr.Epochs = []int{}
				for _, x := range arr {
					f, ok := x.(float64)
					if !ok || f < 0 || f != float64(int(f)) {
						writeErr(w, badInput("epochs must be non-negative integers"))
						return
					}
					kr.Epochs = append(kr.Epochs, int(f))
				}
			case "resources":
				for _, x := range arr {
					n, ok := x.(string)
					if !ok {
						writeErr(w, badInput("resources must be resource names"))
						return
					}
					kr.Resources = append(kr.Resources, n)
				}
			default:
				writeErr(w, badInput("unknown member "+k))
				return
			}
		}
	}
	keys, err := s.e.Keys(r.Context(), ns, creds(r), kr)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	writeJSON(w, 200, map[string]any{"keys": out})
}
