package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/schemaimport"
	"github.com/middle-management/patchlog/internal/server"
)

type siEnv struct {
	t   *testing.T
	s   *clienttest.Server
	api http.Handler
	pg  http.Handler
	c   *client.Client
}

func newSIEnv(t *testing.T, auth bool, opt Options) *siEnv {
	t.Helper()
	s := clienttest.New(t, clienttest.Options{Auth: auth, RealClock: auth})
	api := server.New(s.Engine)
	return &siEnv{t: t, s: s, api: api, pg: HandlerWith(api, opt)}
}

func (e *siEnv) plan(body any, hdr ...string) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", SchemaImportPrefix+"plan", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.pg.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		e.t.Fatalf("status %d, body %q", rec.Code, rec.Body)
	}
	return rec.Code, out
}

func files(kv ...string) []map[string]string {
	var out []map[string]string
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, map[string]string{"name": kv[i], "content": kv[i+1]})
	}
	return out
}

const (
	personJSON  = `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"name":{"type":"string"},"home":{"$ref":"address.json"},"work":{"$ref":"./address.json#/definitions/zip"}},"required":["name"]}`
	addressJSON = `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"zip":{"$ref":"#/definitions/zip"}},"definitions":{"zip":{"type":"string","pattern":"^[0-9]{5}$"}}}`
)

func TestSchemaImportPlanFiles(t *testing.T) {
	e := newSIEnv(t, false, Options{})
	ctx := context.Background()
	if _, err := e.s.Client(t, client.WithAuthor("a")).CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	req := map[string]any{"ns": "schemas", "files": files("person.json", personJSON, "address.json", addressJSON)}
	code, out := e.plan(req)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	entries := out["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries %v", entries)
	}
	person, addr := entries[0].(map[string]any), entries[1].(map[string]any)
	if addr["source"] != "address.json" || addr["resource"] != "address" || addr["action"] != "create" || addr["root"] != true {
		t.Errorf("address entry %v", addr)
	}
	if person["source"] != "person.json" || !strings.HasPrefix(person["path"].(string), "/r/schemas/person/rev/1") {
		t.Errorf("person entry %v", person)
	}
	// the person schema pins the address revision, through the relative reference by name
	var content map[string]any
	for _, r := range out["resources"].([]any) {
		if m := r.(map[string]any); m["name"] == "person" {
			content = m["content"].(map[string]any)
		}
	}
	home := content["properties"].(map[string]any)["home"].(map[string]any)["$ref"].(string)
	if home != addr["path"] {
		t.Errorf("home $ref %q, want %q", home, addr["path"])
	}
	if !strings.HasPrefix(content["properties"].(map[string]any)["work"].(map[string]any)["$ref"].(string), addr["path"].(string)+"#/$defs/zip") {
		t.Errorf("work $ref %v", content["properties"])
	}
	b := out["batches"].([]any)
	if len(b) != 1 || len(b[0].(map[string]any)["items"].([]any)) != 2 {
		t.Fatalf("batches %v", b)
	}
	// nothing was written
	if h, err := e.s.Client(t).Head(ctx, "schemas", "person"); err != nil || h.State != client.NotFound {
		t.Fatalf("plan wrote: %+v %v", h, err)
	}

	// The browser's write: the plan's batch as it is, with the predicted ids.
	body, _ := json.Marshal(map[string]any{"items": b[0].(map[string]any)["items"]})
	hr, _ := http.NewRequest("POST", e.s.URL+"/ns/schemas/batch", bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("X-Author", "a")
	res, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	var wrote struct {
		Items []struct {
			Resource string
			IDs      []string
		}
	}
	json.NewDecoder(res.Body).Decode(&wrote)
	res.Body.Close()
	if res.StatusCode != 201 || len(wrote.Items) != 2 {
		t.Fatalf("batch: %d %+v", res.StatusCode, wrote)
	}
	for i, id := range b[0].(map[string]any)["ids"].([]any) {
		if wrote.Items[i].IDs[0] != id {
			t.Errorf("%s got %v, predicted %v", wrote.Items[i].Resource, wrote.Items[i].IDs, id)
		}
	}
	code, again := e.plan(req)
	if code != 200 || again["changed"] != false || len(again["batches"].([]any)) != 0 {
		t.Fatalf("re-plan: %d %v", code, again)
	}
	for _, x := range again["entries"].([]any) {
		if x.(map[string]any)["action"] != "unchanged" {
			t.Errorf("re-plan entry %v", x)
		}
	}
	// a changed file appends, with the head as its precondition
	code, ch := e.plan(map[string]any{"ns": "schemas", "files": files("person.json", strings.Replace(personJSON, `"string"}`, `"string","minLength":2}`, 1), "address.json", addressJSON)})
	if code != 200 || ch["changed"] != true {
		t.Fatalf("changed: %d %v", code, ch)
	}
	item := ch["batches"].([]any)[0].(map[string]any)["items"].([]any)[0].(map[string]any)
	if item["resource"] != "person" || item["ifMatch"] == nil {
		t.Errorf("append item %v", item)
	}
}

func TestSchemaImportInputErrors(t *testing.T) {
	e := newSIEnv(t, false, Options{})
	if _, err := e.s.Client(t, client.WithAuthor("a")).CreateNamespace(context.Background(), "schemas", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]map[string]any{
		"no ns":        {"ns": "Bad Name", "files": files("a.json", "{}")},
		"nothing":      {"ns": "schemas"},
		"traversal":    {"ns": "schemas", "files": files("../etc/passwd", "{}")},
		"duplicate":    {"ns": "schemas", "files": files("a.json", "{}", "a.json", "{}")},
		"not json":     {"ns": "schemas", "files": files("a.json", "{")},
		"missing file": {"ns": "schemas", "files": files("a.json", `{"$ref":"b.json"}`)},
		"disk":         {"ns": "schemas", "files": files("a.json", `{"$ref":"file:///etc/passwd"}`)},
		"not http":     {"ns": "schemas", "sources": []string{"ftp://x/y.json"}},
	} {
		if code, out := e.plan(req); code < 400 || out["code"] == nil {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// the root name of a single source
	code, out := e.plan(map[string]any{"ns": "schemas", "name": "mine", "files": files("a.json", `{"type":"string"}`)})
	if code != 200 || out["entries"].([]any)[0].(map[string]any)["resource"] != "mine" {
		t.Errorf("name: %d %v", code, out)
	}
	// the other namespace is the caller's problem
	if code, out := e.plan(map[string]any{"ns": "nonesuch", "files": files("a.json", "{}")}); code != 404 {
		t.Errorf("unknown namespace: %d %v", code, out)
	}
	// GET probe and method checks
	rec := httptest.NewRecorder()
	e.pg.ServeHTTP(rec, httptest.NewRequest("GET", SchemaImportPrefix, nil))
	if !strings.Contains(rec.Body.String(), `"fetch":false`) {
		t.Errorf("probe: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	e.pg.ServeHTTP(rec, httptest.NewRequest("GET", SchemaImportPrefix+"plan", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET plan: %d", rec.Code)
	}
}

func schemaSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/s/root.json":
			w.Write([]byte(`{"type":"object","properties":{"x":{"$ref":"leaf.json"}}}`))
		case "/s/leaf.json":
			w.Write([]byte(`{"type":"integer"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSchemaImportFetchGuard(t *testing.T) {
	site := schemaSite(t) // bound to 127.0.0.1
	host := strings.TrimPrefix(site.URL, "http://")
	ip := strings.Split(host, ":")[0]
	mk := func(opt Options) *siEnv {
		e := newSIEnv(t, false, opt)
		if _, err := e.s.Client(t, client.WithAuthor("a")).CreateNamespace(context.Background(), "schemas", map[string]any{"read": "public"}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	req := map[string]any{"ns": "schemas", "sources": []string{site.URL + "/s/root.json"}}

	// off by default: URLs are refused before anything is fetched
	off := mk(Options{})
	if code, out := off.plan(req); code != 403 || out["code"] != "fetch_disabled" {
		t.Errorf("fetch off: %d %v", code, out)
	}
	// ...and so is a URL a file refers to
	code, out := off.plan(map[string]any{"ns": "schemas", "files": files("a.json", `{"$ref":"`+site.URL+`/s/leaf.json"}`)})
	if code != 422 || !strings.Contains(out["message"].(string), "disabled") {
		t.Errorf("reference from a file, fetch off: %d %v", code, out)
	}
	// on, without an allowlist: the loopback address is refused
	on := mk(Options{SchemaFetch: true})
	code, out = on.plan(req)
	if code != 422 || !strings.Contains(out["message"].(string), "loopback") {
		t.Errorf("loopback: %d %v", code, out)
	}
	// a name that resolves to loopback too
	code, out = on.plan(map[string]any{"ns": "schemas", "sources": []string{"http://localhost:" + strings.Split(host, ":")[1] + "/s/root.json"}})
	if code != 422 || !strings.Contains(out["message"].(string), "loopback") {
		t.Errorf("localhost: %d %v", code, out)
	}
	// on, an allowlist that doesn't have it
	other := mk(Options{SchemaFetch: true, SchemaFetchHosts: []string{"www.schemastore.org"}})
	code, out = other.plan(req)
	if code != 422 || !strings.Contains(out["message"].(string), "not on the list") {
		t.Errorf("not listed: %d %v", code, out)
	}
	// on, listed: the host is trusted, the leaf is fetched transitively
	listed := mk(Options{SchemaFetch: true, SchemaFetchHosts: []string{ip}})
	code, out = listed.plan(req)
	if code != 200 || len(out["entries"].([]any)) != 2 {
		t.Fatalf("listed: %d %v", code, out)
	}
	if e := out["entries"].([]any)[0].(map[string]any); !strings.HasSuffix(e["source"].(string), "/s/leaf.json") || e["root"] != false {
		t.Errorf("leaf entry %v", e)
	}
	// host:port entries work too
	hp := mk(Options{SchemaFetch: true, SchemaFetchHosts: []string{host}})
	if code, out = hp.plan(req); code != 200 {
		t.Errorf("host:port: %d %v", code, out)
	}
}

func TestBlockedAddresses(t *testing.T) {
	for _, tc := range []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"10.1.2.3", true}, {"172.16.0.1", true}, {"192.168.1.1", true}, {"169.254.169.254", true},
		{"fe80::1", true}, {"fd00::1", true}, {"0.0.0.0", true}, {"100.64.0.1", true}, {"::ffff:127.0.0.1", true}, {"224.0.0.1", true},
		{"93.184.216.34", false}, {"2606:4700::1111", false},
	} {
		if got := schemaimport.BlockedAddr(tc.ip); got != tc.blocked {
			t.Errorf("%s: blocked=%v", tc.ip, got)
		}
	}
}

func TestSchemaImportForwardsCredentials(t *testing.T) {
	e := newSIEnv(t, true, Options{})
	ctx := context.Background()
	admin := clienttest.NewKey("admin")
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "priv")))
	if _, err := op.CreateNamespace(ctx, "priv", map[string]any{"read": "grant", "keys": []any{admin.Entry("*")}}); err != nil {
		t.Fatal(err)
	}
	req := map[string]any{"ns": "priv", "files": files("a.json", `{"type":"string"}`)}
	// no grant: what the API says, and nothing planned
	if code, out := e.plan(req); code != 401 && code != 403 {
		t.Errorf("anonymous: %d %v", code, out)
	}
	// a grant for another namespace
	other := admin.Grant(t, e.s.Now(), "user:x", []string{"elsewhere"}, []string{"read"})
	if code, out := e.plan(req, "Authorization", "Bearer "+other); code != 401 && code != 403 {
		t.Errorf("wrong namespace: %d %v", code, out)
	}
	// a grant that reads: the heads are read with it
	g := admin.Grant(t, e.s.Now(), "user:root", []string{"priv"}, []string{"read", "create", "append"})
	code, out := e.plan(req, "Authorization", "Bearer "+g)
	if code != 200 || out["entries"].([]any)[0].(map[string]any)["action"] != "create" {
		t.Fatalf("with grant: %d %v", code, out)
	}
	// write the resource, then only a caller who may read it sees "unchanged"
	c := e.s.Client(t, client.WithBearer(g))
	if _, err := c.CreateDoc(ctx, "priv", "a", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "string", "minLength": 1}); err != nil {
		t.Fatal(err)
	}
	code, out = e.plan(req, "Authorization", "Bearer "+g)
	if code != 200 || out["entries"].([]any)[0].(map[string]any)["action"] != "append" {
		t.Fatalf("existing head: %d %v", code, out)
	}
	if out["resources"].([]any)[0].(map[string]any)["parent"] == nil {
		t.Errorf("append without parent: %v", out)
	}
}

// TestPageSchemaImport checks the Schemas tab is wired to the endpoint the
// handler serves, and that the CSP still keeps the page on its own origin.
func TestPageSchemaImport(t *testing.T) {
	html, _ := assets.ReadFile("static/index.html")
	js, _ := assets.ReadFile("static/app.js")
	if !bytes.Contains(html, []byte(`data-tab="si"`)) || !bytes.Contains(html, []byte(`id="tab-si"`)) {
		t.Error("index.html lacks the Schemas tab")
	}
	if !bytes.Contains(js, []byte("const SI_URL = '"+SchemaImportPrefix+"'")) {
		t.Errorf("app.js does not call %s", SchemaImportPrefix)
	}
	rec := httptest.NewRecorder()
	HandlerWith(http.NotFoundHandler(), Options{}).ServeHTTP(rec, httptest.NewRequest("GET", Prefix, nil))
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Error("CSP lost connect-src 'self'")
	}
}
