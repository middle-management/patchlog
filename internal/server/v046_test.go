package server

import (
	"crypto/ed25519"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/edge"
)

// v0.46 §6.1 "Schemas follow their documents": schemaReads opens a
// namespace's schema revisions to writes in, and readers of documents of,
// the listed namespaces, by revision path only.
func TestV046SchemaReads(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	sk, ck, ok, cfgKey := newKey("sk"), newKey("ck"), newKey("ok"), newKey("cfg")
	rk := newKey("rk")
	rkEntry := rk.entry("read", "create", "append")
	rkEntry["readScope"] = "resource"
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{sk.entry("*"), cfgKey.entry("config", "read")}})
	e.mkNS("content", map[string]any{"read": "grant", "keys": []any{ck.entry("*"), rkEntry}})
	e.mkNS("other", map[string]any{"read": "grant", "keys": []any{ok.entry("*")}})
	sg := e.grant(sk, "user:admin", []string{"schemas", "schemas-b"}, allVerbs)
	cg := e.grant(ck, "user:admin", []string{"content", "content-b"}, allVerbs)
	og := e.grant(ok, "user:admin", []string{"other"}, allVerbs)

	base := e.create("schemas", "base", map[string]any{"$schema": dialect, "type": "object", "properties": map[string]any{"v": map[string]any{"type": "number"}}}, sg)
	baseRef := "/r/schemas/base/rev/" + base
	s := e.create("schemas", "s", map[string]any{"$schema": dialect, "$ref": baseRef}, sg)
	sRef := "/r/schemas/s/rev/" + s
	s2 := e.appendRev("schemas", "s", s, ops(op("add", "/title", "v2")), sg)
	secret := e.create("schemas", "secret", map[string]any{"pin": 1234.0}, sg)
	secretRef := "/r/schemas/secret/rev/" + secret

	d := e.create("content", "doc", map[string]any{"v": 1.0}, cg)
	e.create("content", "doc2", map[string]any{"v": 2.0}, cg)
	only := e.grant(rk, "user:li", []string{"content", "content-b"}, []string{"read", "append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "doc"}}})
	only2 := e.grant(rk, "user:li", []string{"content"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "doc2"}}})

	// Before schemaReads: the writer can't read the schema there.
	expectCode(t, e.write("PATCH", "content", "doc", d, ops(op("add", "/$schema", sRef)), only), 422, "schema_unavailable")

	// Setting it needs a * key (§7.4).
	cfgG := e.grant(cfgKey, "user:cfg", []string{"schemas"}, []string{"config", "read"})
	sr := map[string]any{"for": []any{"content*"}}
	expect(t, e.patchNS("schemas", ops(op("add", "/schemaReads", sr)), cfgG), 403)
	expectCode(t, e.patchNS("schemas", ops(op("add", "/schemaReads", map[string]any{"for": []any{"Bad Name"}})), sg), 422, "invalid")
	expect(t, e.patchNS("schemas", ops(op("add", "/schemaReads", sr)), sg), 201)

	// Writes to a listed namespace resolve the pin and its $ref closure
	// without read on schemas.
	d2 := e.appendRev("content", "doc", d, ops(op("add", "/$schema", sRef)), only)
	expectCode(t, e.write("PATCH", "content", "doc", d2, ops(op("replace", "/v", "x")), only), 422, "invalid")
	// Only schemas: a document that isn't one stays closed.
	r := e.write("PATCH", "content", "doc", d2, ops(op("replace", "/$schema", secretRef)), only)
	expectCode(t, r, 422, "schema_unavailable")
	if r.Str("ref") != secretRef {
		t.Fatalf("ref %s", r.Body)
	}
	// A namespace that isn't listed doesn't get it.
	od := e.create("other", "x", map[string]any{"v": 1.0}, og)
	expectCode(t, e.write("PATCH", "other", "x", od, ops(op("add", "/$schema", sRef)), og), 422, "schema_unavailable")
	// Nor does schemas' own branch copy the member (§7.6).
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-b"}, sg), 201)
	if bd := e.nsDoc("schemas-b", sg); bd["schemaReads"] != nil {
		t.Fatalf("branch document %v", bd)
	}
	if e.nsDoc("schemas", sg)["schemaReads"] == nil {
		t.Fatal("schemaReads not set")
	}
	// A local branch of a listed namespace resolves it too.
	expect(t, e.branch("content", map[string]any{"name": "content-b"}, cg), 201)
	bh := e.head("content-b", "doc", only)
	e.appendRev("content-b", "doc", bh, ops(op("replace", "/v", 3.0)), only)

	// Reads by revision path, under a grant that doesn't name schemas, of
	// revisions the reader's document pins, its $ref closure included.
	for _, p := range []string{sRef, baseRef} {
		r := e.get(p, only)
		expect(t, r, 200)
		if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
			t.Fatalf("%s: Cache-Control %q", p, cc)
		}
	}
	// Nothing else: not the head, the log, another revision, a document
	// that isn't a schema, nor to a reader of a document that doesn't pin it.
	expectCode(t, e.get("/r/schemas/s", only), 403, "forbidden")
	expectCode(t, e.get(sRef+"/log", only), 403, "forbidden")
	expectCode(t, e.get("/r/schemas/s/rev/"+s2, only), 403, "forbidden")
	expectCode(t, e.get(secretRef, only), 403, "forbidden")
	expectCode(t, e.get(sRef, only2), 403, "forbidden")
	expectCode(t, e.get(sRef, og), 403, "forbidden")
	expect(t, e.get(sRef), 401)

	// Sealed and end-to-end namespaces refuse it.
	for _, lv := range []string{"sealed", "e2e"} {
		q := req{method: "PATCH", path: "/ns/z-" + lv, ifNoneMatch: "*", bearer: e.operatorGrant("z-" + lv),
			body: addRoot(map[string]any{"read": "grant", "keys": []any{sk.entry("*")}, "encryption": map[string]any{"level": lv}, "schemaReads": sr})}
		r := e.do(q)
		if r.Code != 422 || !strings.Contains(string(r.Body), "schemaReads") {
			t.Fatalf("%s: %d %s", lv, r.Code, r.Body)
		}
	}
}

// v0.46 §8.4: unfreezing a branch whose base already has
// branchesPerNamespace live branches is 422 (§6.6).
func TestV046UnfreezeCountsLiveBranches(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"read": "public", "limits": map[string]any{"branchesPerNamespace": 1.0}})
	e.create("main", "a", map[string]any{"v": 1.0})
	expect(t, e.branch("main", map[string]any{"name": "b1"}, "alice"), 201)
	expectCode(t, e.branch("main", map[string]any{"name": "b2"}, "alice"), 422, "limit")
	expect(t, e.patchNS("b1", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.branch("main", map[string]any{"name": "b2"}, "alice"), 201)
	expectCode(t, e.patchNS("b1", ops(op("replace", "/frozen", false)), ""), 422, "limit")
	expect(t, e.patchNS("b2", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.patchNS("b1", ops(op("replace", "/frozen", false)), ""), 201)
}

// v0.46 §C.4 "Keys follow the base": a branch accepts its base's current
// keys as well as its own; a shared kid is the base's.
func TestV046KeysFollowTheBase(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.adminG), 201)

	// A key added to the base after branching works in the branch.
	late := newKey("late")
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", late.entry("read"))), f.adminG), 201)
	lateG := e.grant(late, "user:late", []string{"sec-b"}, []string{"read"})
	if e.head("sec-b", "a", lateG) != a {
		t.Fatal("read through the branch")
	}

	// A kid both have is the base's: the branch's own entry stops working.
	dupB, dupBase := newKey("dup"), newKey("dup")
	expect(t, e.patchNS("sec-b", ops(op("add", "/keys/-", dupB.entry("read"))), f.adminG), 201)
	branchDup := e.grant(dupB, "user:d", []string{"sec-b"}, []string{"read"})
	e.head("sec-b", "a", branchDup)
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", dupBase.entry("read"))), f.adminG), 201)
	expect(t, e.get("/r/sec-b/a", branchDup), 401)
	e.head("sec-b", "a", e.grant(dupBase, "user:d", []string{"sec-b"}, []string{"read"}))

	// Removed in the base: stops working in the branch.
	keys := e.nsDoc("sec", f.adminG)["keys"].([]any)
	for i, k := range keys {
		if k.(map[string]any)["kid"] == "late" {
			expect(t, e.patchNS("sec", ops(map[string]any{"op": "remove", "path": "/keys/" + strconv.Itoa(i)}), f.adminG), 201)
		}
	}
	expect(t, e.get("/r/sec-b/a", lateG), 401)

	// Nested branches follow recursively.
	late2 := newKey("late2")
	expect(t, e.branch("sec-b", map[string]any{"name": "sec-c"}, e.grant(f.admin, "user:root", []string{"sec-b"}, allVerbs)), 201)
	expect(t, e.patchNS("sec", ops(op("add", "/keys/-", late2.entry("read"))), f.adminG), 201)
	e.head("sec-c", "a", e.grant(late2, "user:l2", []string{"sec-c"}, []string{"read"}))
}

// v0.46 §C.4 "Operator grants" authorise exactly creating namespaces,
// remote branches and forcing purges; anything else is 401, except reads
// of a public namespace, which ignore them.
func TestV046OperatorGrantScope(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	opG := e.operatorGrant("sec")
	opPurge := func(ns string) string {
		return mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"purge", "read", "config"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	expect(t, e.purge("sec", "a", a, opPurge("sec")), 401)
	expect(t, e.get("/r/sec/a", opPurge("sec")), 401)
	expect(t, e.get("/ns/sec", opG), 401)
	expect(t, e.get("/r/sec/a", opG), 401)
	expect(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), opG), 401)
	expect(t, e.patchNS("sec", ops(op("add", "/x-y", 1.0)), f.adminG), 201)
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: e.configID("sec", f.adminG), body: ops(op("add", "/x-z", 1.0)), bearer: opG}), 401)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, opG), 401)
	// A purge only when forced.
	expect(t, e.purge("sec", "a", a, opG), 401)
	expect(t, e.do(req{method: "POST", path: "/r/sec/a/purge?force=1", ifMatch: a, bearer: opPurge("sec")}), 204)
	// A namespace that doesn't exist: 401, except a forced purge.
	expect(t, e.get("/ns/nope", e.operatorGrant("nope")), 401)
	expect(t, e.do(req{method: "POST", path: "/r/nope/a/purge?force=1", ifMatch: a, bearer: opPurge("nope")}), 404)
	// Public reads ignore it.
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{f.admin.entry("*")}})
	p := e.create("pub", "a", map[string]any{"v": 1.0}, e.grant(f.admin, "user:root", []string{"pub"}, allVerbs))
	if e.head("pub", "a", e.operatorGrant("pub")) != p {
		t.Fatal("public head")
	}
}

// edgeCookies extracts the edge-grant cookies of a POST /edge-grants
// answer, as a Cookie header value per prefix.
func edgeCookies(t *testing.T, r *resp) map[string]*http.Cookie {
	t.Helper()
	out := map[string]*http.Cookie{}
	for _, c := range (&http.Response{Header: r.H}).Cookies() {
		out[c.Path] = c
	}
	return out
}

func cookieHdr(c *http.Cookie) map[string]string {
	return map[string]string{"Cookie": c.Name + "=" + c.Value}
}

// v0.46 §C.5 "Issuing them": POST /edge-grants exchanges a grant for edge
// grants as cookies, which authorise GET and HEAD under their prefix.
func TestV046EdgeGrants(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	e.create("sec", "b", map[string]any{"v": 2.0}, f.adminG)
	issue := func(bearer string) *resp {
		return e.do(req{method: "POST", path: "/edge-grants", bearer: bearer})
	}
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	r := issue(reader)
	expect(t, r, 200)
	if r.H.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", r.H.Get("Cache-Control"))
	}
	ps, _ := r.Obj()["prefixes"].([]any)
	if len(ps) != 2 || ps[0] != "/r/sec" || ps[1] != "/ns/sec" {
		t.Fatalf("prefixes %v", r.Obj())
	}
	if r.Str("exp") != t0.Add(edge.MaxGrantTTL).Format(time.RFC3339) {
		t.Fatalf("exp %s", r.Str("exp"))
	}
	cs := edgeCookies(t, r)
	rc, nc := cs["/r/sec"], cs["/ns/sec"]
	if rc == nil || nc == nil || !rc.Secure || !rc.HttpOnly || rc.SameSite != http.SameSiteLaxMode || rc.Name == nc.Name ||
		!strings.HasPrefix(rc.Name, edge.CookiePrefix) {
		t.Fatalf("cookies %v", r.H.Values("Set-Cookie"))
	}

	// GET and HEAD under the prefix, with the private cache class.
	h := e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(rc)})
	expect(t, h, 302)
	rev := e.do(req{method: "GET", path: h.H.Get("Location"), hdr: cookieHdr(rc)})
	expect(t, rev, 200)
	if rev.H.Get("Cache-Control") != "private, max-age=300" || rev.H.Get("CDN-Cache-Control") != "no-store" {
		t.Fatalf("cache %v", rev.H)
	}
	expect(t, e.do(req{method: "HEAD", path: "/r/sec/a", hdr: cookieHdr(rc)}), 302)
	expect(t, e.do(req{method: "GET", path: "/ns/sec", hdr: cookieHdr(nc)}), 302)
	// Not outside the prefix, never writes or /edge-grants.
	expect(t, e.do(req{method: "GET", path: "/ns/sec", hdr: cookieHdr(rc)}), 401)
	expect(t, e.do(req{method: "PATCH", path: "/r/sec/a", ifMatch: a, body: ops(op("add", "/x", 1.0)), hdr: cookieHdr(rc)}), 401)
	expect(t, e.do(req{method: "POST", path: "/edge-grants", hdr: cookieHdr(rc)}), 401)
	// Tampered, or presented under another name: ignored.
	bad := *rc
	bad.Value = strings.Replace(bad.Value, ".", ".x", 1)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(&bad)}), 401)
	renamed := *rc
	renamed.Name = nc.Name
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(&renamed)}), 401)

	// A grant whose rules fix /resource gets that resource's prefix only.
	fixed := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	r = issue(fixed)
	expect(t, r, 200)
	if ps, _ := r.Obj()["prefixes"].([]any); len(ps) != 1 || ps[0] != "/r/sec/a" {
		t.Fatalf("prefixes %v", r.Obj())
	}
	fc := edgeCookies(t, r)["/r/sec/a"]
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(fc)}), 302)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a/rev/" + a + "/log", hdr: cookieHdr(fc)}), 200)
	expect(t, e.do(req{method: "GET", path: "/r/sec/b", hdr: cookieHdr(fc)}), 401)

	// Refused: rules the edge can't evaluate, "*", no read.
	for name, g := range map[string]string{
		"unfixed": e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "z"}}}}),
		"now":     e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}}),
		"star":    mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"read"}, "exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}),
		"noread":  e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"}),
	} {
		if r := issue(g); r.Code != 403 {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	expect(t, issue(""), 401)

	// None outlives the grant's exp; expired ones stop working.
	short := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"exp": t0.Add(5 * time.Minute).Format(time.RFC3339)})
	r = issue(short)
	expect(t, r, 200)
	if r.Str("exp") != t0.Add(5*time.Minute).Format(time.RFC3339) {
		t.Fatalf("exp %s", r.Str("exp"))
	}
	e.clock.Advance(edge.MaxGrantTTL)
	expect(t, e.do(req{method: "GET", path: "/r/sec/a", hdr: cookieHdr(rc)}), 401)
}

// Behind a verifying edge, a cookie read gets the edge's lifetimes, and is
// refused around the edge (§9).
func TestV046EdgeGrantsBehindEdge(t *testing.T) {
	t.Parallel()
	v, err := edge.New([]byte("s3cret"), "")
	if err != nil {
		t.Fatal(err)
	}
	var priv ed25519.PrivateKey
	e := newEnvWith(t, []Option{WithEdge(v)}, withAuth(&priv))
	e.opPriv = priv
	k := newKey("k")
	e.mkNS("sec", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	admin := e.grant(k, "user:root", []string{"sec"}, allVerbs)
	a := e.create("sec", "a", map[string]any{"v": 1.0}, admin)
	r := e.do(req{method: "POST", path: "/edge-grants", bearer: e.grant(k, "user:bob", []string{"sec"}, []string{"read"})})
	expect(t, r, 200)
	c := edgeCookies(t, r)["/r/sec"]
	expectCode(t, e.do(req{method: "GET", path: "/r/sec/a/rev/" + a, hdr: cookieHdr(c)}), 403, edge.Code)
	h := cookieHdr(c)
	h[edge.DefaultHeader] = "s3cret"
	rev := e.do(req{method: "GET", path: "/r/sec/a/rev/" + a, hdr: h})
	expect(t, rev, 200)
	if rev.H.Get("Cache-Control") != "private, max-age=300" || rev.H.Get("CDN-Cache-Control") != "max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("cache %v", rev.H)
	}
}
