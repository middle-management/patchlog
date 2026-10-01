package playground

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

// SchemaImportPrefix is where the playground's schema import endpoints live.
const SchemaImportPrefix = Prefix + "schema-import/"

// Options configure what the playground serves beyond its static files.
type Options struct {
	// SchemaFetch lets the plan endpoint fetch http(s) URLs (serve
	// -schema-fetch). Off: it takes uploaded files only.
	SchemaFetch bool
	// SchemaFetchHosts, if not empty, limits fetching to these hosts, which
	// are then also trusted with private addresses (-schema-fetch-hosts).
	SchemaFetchHosts []string
}

// Limits of one plan request.
const (
	maxPlanBody  = 16 << 20
	maxPlanFiles = 50
	planTimeout  = 2 * time.Minute
)

// HandlerWith serves the playground like Handler and, under
// SchemaImportPrefix, the schema import planner. api is the API handler the
// planner reads current heads through, in process, with the headers of the
// request that asked: a caller plans against what their own grant may read.
func HandlerWith(api http.Handler, opt Options) http.Handler {
	static := Handler()
	hc := schemaimport.DisabledClient()
	if opt.SchemaFetch {
		hc = schemaimport.GuardedClient(opt.SchemaFetchHosts)
	}
	si := &importer{api: api, opt: opt, hc: hc}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, SchemaImportPrefix) {
			si.serve(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
}

type importer struct {
	api http.Handler
	opt Options
	hc  *http.Client
}

type planRequest struct {
	NS      string   `json:"ns"`
	Sources []string `json:"sources"`
	Files   []struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"files"`
	Name string `json:"name"`
}

func reply(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	reply(w, status, map[string]any{"code": code, "message": msg})
}

func (s *importer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case SchemaImportPrefix: // what the endpoint offers
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, http.StatusMethodNotAllowed, "bad_input", "GET only")
			return
		}
		hosts := append([]string{}, s.opt.SchemaFetchHosts...)
		sort.Strings(hosts)
		reply(w, http.StatusOK, map[string]any{"proxy": "schema-import", "fetch": s.opt.SchemaFetch, "hosts": hosts,
			"limits": map[string]any{"files": maxPlanFiles, "bytes": maxPlanBody, "docs": schemaimport.DefaultMaxDocs}})
	case SchemaImportPrefix + "plan":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			fail(w, http.StatusMethodNotAllowed, "bad_input", "POST only")
			return
		}
		s.plan(w, r)
	default:
		http.NotFound(w, r)
	}
}

// forward is a RoundTripper that calls the API handler in process, with the
// credentials (and edge headers) of the request being served.
type forward struct {
	api http.Handler
	hdr http.Header
}

func (f forward) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range f.hdr {
		req.Header[k] = append([]string(nil), v...)
	}
	rec := httptest.NewRecorder()
	f.api.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// forwarded are the incoming headers the in-process reads must not carry:
// per-request framing and conditionals of the plan request itself, and
// cookies (grants travel in Authorization).
var notForwarded = map[string]bool{
	"Content-Type": true, "Content-Length": true, "Accept": true, "Accept-Encoding": true, "Cookie": true,
	"Connection": true, "Range": true, "If-Match": true, "If-None-Match": true, "If-Modified-Since": true,
	"Origin": true, "Referer": true, "Transfer-Encoding": true, "Expect": true,
}

func (s *importer) plan(w http.ResponseWriter, r *http.Request) {
	var req planRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPlanBody))
	if err := dec.Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad_input", "the body is not the expected JSON: "+err.Error())
		return
	}
	if !client.ValidNSName(req.NS) {
		fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("invalid namespace name %q", req.NS))
		return
	}
	if len(req.Sources)+len(req.Files) == 0 {
		fail(w, http.StatusBadRequest, "bad_input", "give at least one URL or file")
		return
	}
	if len(req.Files) > maxPlanFiles || len(req.Sources) > maxPlanFiles {
		fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("at most %d URLs and %d files", maxPlanFiles, maxPlanFiles))
		return
	}
	files := map[string][]byte{}
	var sources []string
	for _, f := range req.Files {
		name := strings.TrimPrefix(strings.TrimSpace(f.Name), "/")
		if name == "" || strings.Contains(name, "..") {
			fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("invalid file name %q", f.Name))
			return
		}
		u := schemaimport.FileURL(name)
		if _, dup := files[name]; dup {
			fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("file name %q given twice", name))
			return
		}
		files[name] = []byte(f.Content)
		sources = append(sources, u.String())
	}
	for _, s := range req.Sources {
		s = strings.TrimSpace(s)
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("%q is not an http(s) URL", s))
			return
		}
		sources = append(sources, s)
	}
	if len(req.Sources) > 0 && !s.opt.SchemaFetch {
		fail(w, http.StatusForbidden, "fetch_disabled", schemaimport.ErrFetchDisabled.Error()+"; upload files instead")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), planTimeout)
	defer cancel()
	hdr := http.Header{}
	for k, v := range r.Header {
		if !notForwarded[k] {
			hdr[k] = v
		}
	}
	c, err := client.New("http://api.invalid", client.WithHTTPClient(&http.Client{Transport: forward{s.api, hdr}}))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// Whoever may not read the namespace gets what the API would tell them,
	// before anything is fetched on their behalf.
	if _, err := c.NSHead(ctx, req.NS); err != nil {
		if ae, ok := client.AsAPIError(err); ok {
			reply(w, ae.Status, ae.Body)
			return
		}
		fail(w, http.StatusBadGateway, "upstream", err.Error())
		return
	}
	res, err := schemaimport.Plan(ctx, c, sources, schemaimport.Options{
		NS: req.NS, Name: strings.TrimSpace(req.Name), Files: files, NoDisk: true, HTTPClient: s.hc,
	})
	if err != nil {
		if ae, ok := client.AsAPIError(err); ok {
			reply(w, ae.Status, ae.Body)
			return
		}
		fail(w, http.StatusUnprocessableEntity, "schema_import", display(err.Error()))
		return
	}
	maxItems, maxBytes := schemaimport.BatchLimits(ctx, c, req.NS)
	reply(w, http.StatusOK, planBody(res, maxItems, maxBytes))
}

// display shows uploaded files by name.
func display(s string) string { return strings.ReplaceAll(s, "file:///upload/", "") }

func planBody(res *schemaimport.Result, maxItems, maxBytes int) map[string]any {
	entries := make([]any, 0, len(res.Entries))
	for _, e := range res.Entries {
		m := map[string]any{"source": display(e.Source), "resource": e.Resource, "path": e.Path, "action": e.Action, "root": e.Root}
		entries = append(entries, m)
	}
	resources := make([]any, 0, len(res.Resources))
	for _, r := range res.Resources {
		srcs := make([]string, len(r.Sources))
		for i, s := range r.Sources {
			srcs[i] = display(s)
		}
		m := map[string]any{"name": r.Name, "sources": srcs, "action": r.Action, "id": r.ID, "path": r.Path(res.NS), "content": r.Content}
		if r.Parent != "" {
			m["parent"] = r.Parent
		}
		resources = append(resources, m)
	}
	bundled := make([]any, 0, len(res.Bundled))
	for _, b := range res.Bundled {
		l := make([]string, len(b))
		for i, s := range b {
			l[i] = display(s)
		}
		bundled = append(bundled, l)
	}
	warnings := make([]any, 0, len(res.Warnings))
	for _, w := range res.Warnings {
		warnings = append(warnings, display(w))
	}
	// The writes as the browser sends them: batches of items for
	// POST /ns/{ns}/batch, in order, each atomic, and for each item the id
	// it is predicted to get.
	batches := []any{}
	for _, ch := range res.Chunks(maxItems, maxBytes) {
		items := make([]any, 0, len(ch))
		ids := make([]any, 0, len(ch))
		for _, r := range ch {
			items = append(items, r.WireItem())
			ids = append(ids, r.ID)
		}
		batches = append(batches, map[string]any{"items": items, "ids": ids})
	}
	return map[string]any{"ns": res.NS, "changed": res.Changed(), "entries": entries, "resources": resources,
		"bundled": bundled, "warnings": warnings, "batches": batches}
}
