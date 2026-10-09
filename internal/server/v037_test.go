package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
)

// §7.4: PATCH /ns/{ns} answers 201 with X-Config-Revision,
// X-Namespace-Revision and Location naming the entry it wrote, and the body
// { config, ns_id }. A retry by the same principal answers 200 with the
// same, also when the config change was written by a batch.
func TestV037NamespacePatchResponse(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	check := func(r *resp, ns string, status int) (cfg, nsID string) {
		t.Helper()
		expect(t, r, status)
		cfg, nsID = r.H.Get("X-Config-Revision"), r.H.Get("X-Namespace-Revision")
		if b := r.Obj(); len(b) != 2 || b["config"] != cfg || b["ns_id"] != nsID || cfg == "" || nsID == "" {
			t.Fatalf("body %s, headers %v", r.Body, r.H)
		}
		if r.H.Get("Location") != "/ns/"+ns+"/rev/"+nsID {
			t.Fatalf("Location %q", r.H.Get("Location"))
		}
		return cfg, nsID
	}
	cfg0, ns0 := check(e.do(req{method: "PATCH", path: "/ns/m", ifNoneMatch: "*", body: addRoot(map[string]any{"read": "public"}), author: "admin"}), "m", 201)
	if ns0 != e.nsHead("m") || cfg0 != e.configID("m") {
		t.Fatal("create: not the head")
	}
	change := ops(op("add", "/x-title", "M"))
	cfg1, ns1 := check(e.do(req{method: "PATCH", path: "/ns/m", ifMatch: cfg0, body: change, author: "admin"}), "m", 201)
	if ns1 != e.nsHead("m") || cfg1 != e.configID("m") {
		t.Fatal("change: not the head")
	}
	e.create("m", "a", map[string]any{})
	// The retry after a lost response, though the namespace moved since.
	if c, n := check(e.do(req{method: "PATCH", path: "/ns/m", ifMatch: cfg0, body: change, author: "admin"}), "m", 200); c != cfg1 || n != ns1 {
		t.Fatalf("retry %s %s, want %s %s", c, n, cfg1, ns1)
	}
	// A config change a batch wrote: its entry is the batch.
	change2 := ops(op("add", "/x-note", "n"))
	r := e.batchReq("m", map[string]any{"config": map[string]any{"ifMatch": cfg1, "patches": change2}, "items": []any{}}, "admin")
	expect(t, r, 201)
	batchNS := r.H.Get("X-Namespace-Revision")
	if _, n := check(e.do(req{method: "PATCH", path: "/ns/m", ifMatch: cfg1, body: change2, author: "admin"}), "m", 200); n != batchNS || n == "" {
		t.Fatalf("retry of a batch's config change: ns_id %s, want %s", n, batchNS)
	}

	// The client reports what the answer says.
	c, err := plclient.New(e.srv.URL, plclient.WithAuthor("admin"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.PatchConfig(context.Background(), "m", e.configID("m"), ops(op("add", "/x-other", 1.0)))
	if err != nil || res.Status != 201 || res.NSID != e.nsHead("m") || res.Config != e.configID("m") {
		t.Fatalf("client %+v %v", res, err)
	}
}

// §6.2 step 2, §7.2: the idempotent-retry lookup doesn't apply to a purged
// resource, whose answer is 410, for single writes and batches alike.
func TestV037RetryOnPurged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{})
	create := addRoot(map[string]any{"v": 1.0})
	a1 := e.create("m", "a", map[string]any{"v": 1.0})
	next := ops(op("replace", "/v", 2.0))
	a2 := e.appendRev("m", "a", a1, next)
	// Retries answer 200 while the resource stands.
	expect(t, e.write("PATCH", "m", "a", "", create), 200)
	expect(t, e.write("PATCH", "m", "a", a1, next), 200)
	expect(t, e.purge("m", "a", a2, "admin"), 204)
	expectCode(t, e.write("PATCH", "m", "a", "", create), 410, "gone")
	expectCode(t, e.write("PATCH", "m", "a", a1, next), 410, "gone")

	batch := map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": true})}},
		map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"c": true})}},
	}}
	r := e.batchReq("m", batch, "alice")
	expect(t, r, 201)
	expect(t, e.batchReq("m", batch, "alice"), 200)
	expect(t, e.purge("m", "b", e.head("m", "b"), "admin"), 204)
	r = e.batchReq("m", batch, "alice")
	expectCode(t, r, 410, "batch")
	items, _ := r.Obj()["items"].([]any)
	if len(items) == 0 || items[0].(map[string]any)["index"] != 0.0 || items[0].(map[string]any)["status"] != 410.0 {
		t.Fatalf("batch retry on a purged item: %s", r.Body)
	}
	// A config change in the batch makes no difference.
	cfg := e.configID("m")
	withCfg := map[string]any{"config": map[string]any{"ifMatch": cfg, "patches": ops(op("add", "/x-a", 1.0))}, "items": []any{
		map[string]any{"resource": "d", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
	}}
	expect(t, e.batchReq("m", withCfg, "alice"), 201)
	expect(t, e.batchReq("m", withCfg, "alice"), 200)
	expect(t, e.purge("m", "d", e.head("m", "d"), "admin"), 204)
	// It is still 410, not the config change's 412: that would tell the
	// client its change didn't apply, though it did.
	cfgAfter := e.configID("m")
	r = e.batchReq("m", withCfg, "alice")
	expectCode(t, r, 410, "batch")
	if items, _ := r.Obj()["items"].([]any); len(items) != 1 || items[0].(map[string]any)["status"] != 410.0 {
		t.Fatalf("batch retry with a config change on a purged item: %s", r.Body)
	}
	if e.configID("m") != cfgAfter {
		t.Fatal("the config changed again")
	}

	// Purges are allowed in a frozen namespace; a retry on the purged
	// resource is 410 there too, before the frozen check (§6.2 step 2).
	e.mkNS("f", map[string]any{})
	f1 := e.create("f", "a", map[string]any{"v": 1.0})
	expect(t, e.patchNS("f", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.purge("f", "a", f1, "admin"), 204)
	expectCode(t, e.write("PATCH", "f", "a", "", create), 410, "gone")
	expectCode(t, e.write("PATCH", "f", "a", f1, next), 410, "gone")
	fb := map[string]any{"items": []any{map[string]any{"resource": "a", "ifNoneMatch": "*", "steps": []any{create}}}}
	expectCode(t, e.batchReq("f", fb, "alice"), 410, "batch")
	// A resource that isn't purged still gets 409 frozen.
	expectCode(t, e.write("PATCH", "f", "z", "", create), 409, "frozen")
}

// §7.8: a tombstoned resource accepts uploads, so a restore can reference
// blobs uploaded after the delete; a grant that may only restore may
// upload them.
func TestV037BlobBeforeRestore(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil, withBlobTuning)
	e := f.tenv
	h := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	tomb := e.del("sec", "a", h, f.adminG)
	expectCode(t, e.get("/r/sec/a", f.adminG), 410, "gone")
	restorer := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read", "restore"})
	data := []byte("back with a picture")
	bid := e.upload("sec", "a", "text/plain", data, restorer)
	// Pending until a write references it.
	expect(t, e.get(blobPath("sec", "a", bid), restorer), 404)
	r := e.write("PATCH", "sec", "a", tomb, ops(op("add", "/pic", ref(bid, "text/plain", len(data), ""))), restorer)
	expect(t, r, 201)
	if d := e.doc("sec", "a", restorer); d["v"] != 1.0 || d["pic"] == nil {
		t.Fatalf("restored %v", d)
	}
	g := e.get(blobPath("sec", "a", bid), restorer)
	expect(t, g, 200)
	if !bytes.Equal(g.Body, data) {
		t.Fatalf("blob %q", g.Body)
	}
	// A purged resource still refuses uploads.
	expect(t, e.purge("sec", "a", etagOf(r), f.adminG), 204)
	r2, _ := e.putBlob("sec", "a", "text/plain", "", []byte("late"), f.adminG)
	expectCode(t, r2, 410, "gone")
}

// §1 Conformance: with authentication disabled every request counts as
// holding a * key, so config guards and forced purges are open, and every
// entry written on a request records "grant": null (v0.38).
func TestV037DevConformance(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withoutRetentionLoop)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("docs", map[string]any{"retention": []any{map[string]any{"keep": map[string]any{"revisions": 1.0}}}})
	// Guarded members (§7.4), as anyone.
	k := newKey("k")
	for _, p := range []map[string]any{
		op("add", "/keys", []any{k.entry("*")}),
		op("add", "/merge", map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "k"}}}),
		op("add", "/roles", map[string]any{"editor": map[string]any{"can": []any{"read"}}}),
		op("add", "/read", "public"),
		op("add", "/revoked", []any{}),
	} {
		r := e.do(req{method: "PATCH", path: "/ns/docs", ifMatch: e.configID("docs"), body: ops(p), author: "nobody"})
		expect(t, r, 201)
	}
	// A forced purge of a referenced schema, outside any branch.
	s1 := e.create("schemas", "team", teamSchema(), "nobody")
	expect(t, e.typed("docs", "d", "/r/schemas/team/rev/"+s1, "nobody"), 201)
	expectCode(t, e.do(req{method: "POST", path: "/r/schemas/team/purge", ifMatch: s1, author: "nobody"}), 409, "in_use")
	expect(t, e.do(req{method: "POST", path: "/r/schemas/team/purge?force=1", ifMatch: s1, author: "nobody"}), 204)
	// Pruning below what retention keeps, with no archive (§8.6).
	revs := e.chain("docs", "c", 4, "nobody")
	e.clock.Advance(10 * time.Minute)
	r := e.prune("docs", "c", map[string]any{"horizon": revs[2]}, "nobody")
	expect(t, r, 200)
	if r.Str("horizon") != revs[2] {
		t.Fatalf("prune %s", r.Body)
	}
	for _, ns := range []string{"schemas", "docs"} {
		for _, x := range e.get("/ns/" + ns + "/rev/" + e.nsHead(ns) + "/log").Arr() {
			m := x.(map[string]any)
			if g, has := m["grant"]; !has || g != nil || m["author"] == "" {
				t.Fatalf("%s: %v", ns, m)
			}
			if m["kind"] == "purge" && m["forced"] != true {
				t.Fatalf("forced purge entry %v", m)
			}
		}
	}
}

// §7.4, §G.3 (v0.38): a deployment that reads another's namespace
// documents, as a remote branch reads its base's, ignores members it
// doesn't define: it never refuses for an unknown member, or for the spec
// version A publishes alone, later, malformed or absent.
func TestV037RemoteSpecVersion(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	f := populateA(t, a)
	ours := []byte(`"spec":"` + core.SpecVersion + `"`)
	for i, c := range []struct {
		spec   string
		member string // added to the base's namespace document as of at
	}{
		{`"spec":"0.49"`, `"wardens":[]`},
		{`"spec":"0.38-rc"`, `"wardens":[]`},
		{`"spec":"99.0"`, ""},
		{`"spec":"0.38.1"`, `"x-team":"a"`},
		{`"spec":"0.36"`, `"wardens":[]`},
		{`"spec":"0.38"`, `"policy":{"embargo":true}`},
		{"", `"wardens":[]`}, // a deployment from before v0.37
	} {
		c := c
		rt.set(tamperPaths(t, a, func(path string, body []byte) []byte {
			switch {
			case path == "/" && c.spec == "":
				return bytes.Replace(body, append([]byte(","), ours...), nil, 1)
			case path == "/":
				return bytes.Replace(body, ours, []byte(c.spec), 1)
			case strings.HasPrefix(path, "/ns/main/rev/") && strings.Count(path, "/") == 4:
				if c.member != "" && path == "/ns/main/rev/"+f.at {
					body = append([]byte("{"+c.member+","), bytes.TrimPrefix(body, []byte("{"))...)
				}
			}
			return body
		}), "")
		name := fmt.Sprintf("rel%d", i)
		expect(t, b.mkRemote(name, remoteGenesis("main", f.at, nil)), 201)
	}
}

// tamperPaths is tamper with the request path passed to rewrite.
func tamperPaths(t *testing.T, a *tenv, rewrite func(path string, body []byte) []byte) string {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hr, _ := http.NewRequest(r.Method, a.srv.URL+r.URL.RequestURI(), r.Body)
		hr.Header = r.Header.Clone()
		res, err := client.Do(hr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		body = rewrite(r.URL.Path, body)
		for k, v := range res.Header {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	}))
	t.Cleanup(p.Close)
	return p.URL
}

// §7.4: a remote branch's own first config entry is written on the
// request and records the operator's grant, as do the schema namespaces it
// mirrors (v0.38). At the source,
// registration entries record the registrant's grant.
func TestV037RemoteGrants(t *testing.T) {
	t.Parallel()
	var bPriv ed25519.PrivateKey
	a, b, _ := pair(t, nil, []envOpt{withAuth(&bPriv)})
	b.opPriv = bPriv
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	lg := b.get("/ns/rel/rev/" + b.nsHead("rel") + "/log").Arr()
	if len(lg) != 1 || !strings.HasPrefix(entryRef(t, lg[0]), "op:root operator 1") {
		t.Fatalf("remote branch log %v", lg)
	}
	sl := b.get("/ns/schemas/rev/" + b.nsHead("schemas") + "/log").Arr()
	if len(sl) < 2 {
		t.Fatalf("mirrored schemas log %v", sl)
	}
	for _, x := range sl {
		if !strings.HasPrefix(entryRef(t, x), "op:root operator 1") || x.(map[string]any)["author"] != "op:root" {
			t.Fatalf("mirrored schema entry %v", x)
		}
	}

	fa := newAuthFixture(t, nil, withOrigin(originA))
	reg := fa.grant(fa.admin, "user:b", []string{"sec"}, []string{"read", "export"})
	expect(t, fa.register("sec", "rel", fa.nsHead("sec", fa.adminG), "", reg), 201)
	al := fa.get("/ns/sec/rev/"+fa.nsHead("sec", fa.adminG)+"/log", fa.adminG).Arr()
	if last := al[len(al)-1].(map[string]any); last["remote"] == nil || entryRef(t, last) != grantRef(t, reg) {
		t.Fatalf("registration entry %v", last)
	}
}
