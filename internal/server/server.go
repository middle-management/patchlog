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
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Server is the HTTP API.
type Server struct {
	e   *core.Engine
	mux *http.ServeMux
}

// New builds the HTTP handler.
func New(e *core.Engine) *Server {
	s := &Server{e: e, mux: http.NewServeMux()}
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
	log.Printf("internal error: %v", err)
	w.Header().Set("Cache-Control", "no-store")
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
// cache tags.
func cache(w http.ResponseWriter, class string, public bool, tags ...string) {
	h := w.Header()
	if public {
		h.Set("Cache-Control", class)
	} else {
		edge := strings.TrimPrefix(class, "public, ")
		switch class {
		case ccImmutable:
			h.Set("Cache-Control", "private, max-age=300")
		case ccShort:
			h.Set("Cache-Control", "private, max-age=5")
		default:
			h.Set("Cache-Control", "private, max-age=0")
		}
		h.Set("CDN-Cache-Control", edge)
	}
	if len(tags) > 0 {
		h.Set("Cache-Tag", strings.Join(tags, ","))
		h.Set("Surrogate-Key", strings.Join(tags, " "))
	}
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
		cache(w, ccShort, h.Public)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case core.Purged:
		cache(w, ccLong, h.Public)
		writeJSON(w, 410, map[string]any{"code": "gone"})
	case core.Tombstoned:
		cache(w, ccHead, h.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(h.Head))
		writeJSON(w, 410, map[string]any{"code": "gone", "tombstone": h.Head, "last": h.Last})
	default:
		cache(w, ccHead, h.Public, resTags(ns, name)...)
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
	case rev.Status == 200:
		cache(w, ccImmutable, rev.Public, resTags(ns, name)...)
		w.Header().Set("ETag", quote(id))
		w.Header().Set("X-Revision", id)
		if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, quote(id)) {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if r.Method != http.MethodHead {
			w.Write(rev.Doc)
		}
	case rev.Status == 404:
		cache(w, ccShort, rev.Public)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	case rev.Code == "pruned":
		cache(w, ccPruned, rev.Public, resTags(ns, name)...)
		writeJSON(w, 410, map[string]any{"code": "pruned", "horizon": rev.Horizon})
	default:
		// A tombstone id is immutable; a purge is "long".
		cache(w, ccLong, rev.Public)
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
	s.writeLog(w, lg, ns, resTags(ns, name))
}

func (s *Server) writeLog(w http.ResponseWriter, lg *core.Log, ns string, tags []string) {
	switch lg.Status {
	case 200:
		cache(w, ccImmutable, lg.Public, tags...)
		entries := make([]any, len(lg.Entries))
		for i, e := range lg.Entries {
			entries[i] = e
		}
		writeJSON(w, 200, entries)
	case 404:
		cache(w, ccShort, lg.Public)
		writeJSON(w, 404, map[string]any{"code": "not_found"})
	default:
		if lg.Horizon != "" {
			cache(w, ccPruned, lg.Public, tags...)
			writeJSON(w, 410, map[string]any{"code": "pruned", "horizon": lg.Horizon})
			return
		}
		cache(w, ccLong, lg.Public)
		writeJSON(w, 410, map[string]any{"code": "gone"})
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
	body, err := readJSON(r, s.e.Limits().PatchSetSize*4)
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
	if err := s.e.Purge(r.Context(), core.Request{NS: ns, Cred: creds(r)}, name, p.ifMatch, force); err != nil {
		writeErr(w, err)
		return
	}
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
		writeErr(w, badInput("body must be { horizon, keep? }"))
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
	if _, has := m["snapshot"]; has {
		writeErr(w, &core.Error{Status: 422, Body: map[string]any{"code": "invalid", "message": "snapshot is for E3 namespaces, which this server does not support"}})
		return
	}
	eff, err := s.e.Prune(r.Context(), core.Request{NS: ns, Cred: creds(r)}, name, core.PruneRequest{Horizon: h, Keep: keep})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"horizon": eff})
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
	cache(w, ccHead, info.Public, "ns:"+ns)
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
	cache(w, ccImmutable, info.Public, "ns:"+ns)
	w.Header().Set("ETag", quote(id))
	w.Header().Set("X-Config-Revision", info.Config)
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, quote(id)) {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		w.Write(info.Doc)
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
	s.writeLog(w, lg, ns, []string{"ns:" + ns})
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
	cache(w, ccImmutable, page.Public, "ns:"+ns)
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
	cache(w, ccHead, public, "ns:"+ns)
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
	body, err := readJSON(r, s.e.Limits().PatchSetSize*4)
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
	writeJSON(w, res.Status, map[string]any{"config": res.ConfigID, "ns_id": res.NSID})
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
	if !p.ifNoneMatch {
		writeErr(w, &core.Error{Status: 428, Body: map[string]any{"code": "precondition_required"}})
		return
	}
	body, err := readJSON(r, s.e.Limits().PatchSetSize*4)
	if err != nil {
		writeErr(w, err)
		return
	}
	m, ok := body.(map[string]any)
	if !ok {
		writeErr(w, badInput("body must be { name, at?, patches? }"))
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
	writeJSON(w, res.Status, map[string]any{"name": name, "config": res.ConfigID, "ns_id": res.NSID})
}

func (s *Server) nsBatch(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ns := r.PathValue("ns")
	if err := validNames(ns, ""); err != nil {
		writeErr(w, err)
		return
	}
	lim := s.e.Limits()
	body, err := readJSON(r, lim.BatchSize+lim.BatchSize/4+(1<<20))
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
	res, err := s.e.Batch(r.Context(), core.Request{NS: ns, Cred: creds(r)}, items, cc, source, dry)
	if err != nil {
		writeErr(w, err)
		return
	}
	if res.NSID != "" {
		w.Header().Set("X-Namespace-Revision", res.NSID)
	}
	out := map[string]any{"items": res.Items}
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
	if err := s.e.PurgeNamespace(r.Context(), core.Request{NS: ns, Cred: creds(r)}, p.ifMatch); err != nil {
		writeErr(w, err)
		return
	}
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
			s.writeLog(w, lg, ns, tags)
			return
		}
		if len(lg.Entries) > 0 {
			w.Header().Set(header, lg.Last)
			w.Header().Set("X-Cursor", strconv.FormatInt(time.Now().UnixNano()/int64(interval), 10))
			setLive(w, lg.Public, fmt.Sprintf("public, max-age=0, s-maxage=%d", int(interval.Seconds())), tags)
			entries := make([]any, len(lg.Entries))
			for i, e := range lg.Entries {
				entries[i] = e
			}
			writeJSON(w, 200, entries)
			return
		}
		select {
		case <-wait:
			continue
		case <-time.After(time.Until(deadline)):
		case <-r.Context().Done():
			return
		}
		cur := time.Now().UnixNano() / int64(interval)
		if reqCursor+1 > cur {
			cur = reqCursor + 1
		}
		w.Header().Set(header, since)
		w.Header().Set("X-Cursor", strconv.FormatInt(cur, 10))
		setLive(w, lg.Public, "public, max-age=0, s-maxage=2", tags)
		w.WriteHeader(204)
		return
	}
}

func setLive(w http.ResponseWriter, public bool, cc string, tags []string) {
	if public {
		w.Header().Set("Cache-Control", cc)
	} else {
		w.Header().Set("Cache-Control", "private, max-age=0")
		w.Header().Set("CDN-Cache-Control", strings.TrimPrefix(cc, "public, "))
	}
	w.Header().Set("Cache-Tag", strings.Join(tags, ","))
	w.Header().Set("Surrogate-Key", strings.Join(tags, " "))
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
		cache(w, ccHead, h.Public, resTags(ns, name)...)
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
		cache(w, ccHead, info.Public, "ns:"+ns)
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
	fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", event, id, jsonv.Canonical(jsonv.FromGo(toModel(data))))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func sinceParam(r *http.Request) string {
	if s := r.URL.Query().Get("since"); s != "" {
		return s
	}
	return r.Header.Get("Last-Event-ID")
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
	lg, err := s.e.NamespaceLog(r.Context(), ns, "", since, 0, cred)
	if err != nil {
		writeErr(w, err)
		return
	}
	if lg.Status != 200 {
		noStore(w)
		s.writeLog(w, lg, ns, nil)
		return
	}
	startSSE(w)
	for {
		wait := s.e.Wait(ns)
		for _, e := range lg.Entries {
			sse(w, e["kind"].(string), e["id"].(string), e)
			since = e["id"].(string)
		}
		select {
		case <-wait:
		case <-time.After(30 * time.Second):
			fmt.Fprint(w, ": keep-alive\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
		lg, err = s.e.NamespaceLog(r.Context(), ns, "", since, 0, cred)
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
		s.writeLog(w, lg, ns, nil)
		noStore(w)
		return
	}
	startSSE(w)
	emit := func(lg *core.Log) {
		for _, e := range lg.Entries {
			ev := "revision"
			if e["kind"] == "tombstone" {
				ev = "tombstone"
			}
			sse(w, ev, e["id"].(string), e)
			since = e["id"].(string)
		}
	}
	emit(lg)
	for {
		wait := s.e.Wait(ns)
		select {
		case <-wait:
		case <-time.After(30 * time.Second):
			fmt.Fprint(w, ": keep-alive\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			continue
		case <-r.Context().Done():
			return
		}
		nl, err := s.e.NamespaceLog(r.Context(), ns, "", nsSince, 0, cred)
		if err != nil || nl.Status != 200 {
			return
		}
		nsSince = nl.Last
		for _, e := range nl.Entries {
			if e["resource"] != name {
				continue
			}
			switch e["kind"] {
			case "purge":
				sse(w, "purge", e["id"].(string), e)
				return
			case "prune":
				sse(w, "prune", e["id"].(string), e)
			}
		}
		lg, err := s.e.ResourceLog(r.Context(), ns, name, "", since, 0, cred)
		if err != nil || lg.Status != 200 {
			return
		}
		emit(lg)
	}
}
