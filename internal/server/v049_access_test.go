package server

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v0.49 §6.1, §7: a referrer in a listed namespace that is public, and
// neither sealed nor end-to-end, opens the schema revisions it pins to
// every request, with or without a grant, which is then ignored; a
// referrer elsewhere needs a grant that verifies as a read of it would.
func TestV049SchemaReadsPublicReferrer(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	sk, pk, ck, rk, ok := newKey("sk"), newKey("pk"), newKey("ck"), newKey("rk"), newKey("ok")
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{sk.entry("*")}, "schemaReads": map[string]any{"for": []any{"pub*", "priv"}}})
	e.mkNS("pub", map[string]any{"read": "public", "keys": []any{pk.entry("*")}})
	e.mkNS("pubsealed", sealedDoc(map[string]any{"read": "public", "keys": []any{pk.entry("*"), rk.entry("read")}}))
	e.mkNS("priv", map[string]any{"read": "grant", "keys": []any{ck.entry("*"), rk.entry("read")}})
	e.mkNS("other", map[string]any{"read": "grant", "keys": []any{ok.entry("*")}})
	sg := e.grant(sk, "user:admin", []string{"schemas"}, allVerbs)
	pg := e.grant(pk, "user:admin", []string{"pub", "pubsealed"}, allVerbs)
	cg := e.grant(ck, "user:admin", []string{"priv"}, allVerbs)
	og := e.grant(ok, "user:o", []string{"other"}, []string{"read"})
	schemaRef := func(name string) string {
		r := e.create("schemas", name, map[string]any{"$schema": dialect, "type": "object"}, sg)
		return "/r/schemas/" + name + "/rev/" + r
	}
	sRef, pRef, tRef := schemaRef("s"), schemaRef("p"), schemaRef("t")
	d := e.create("pub", "doc", map[string]any{"$schema": sRef}, pg)
	e.create("priv", "doc", map[string]any{"$schema": pRef}, cg)
	e.wr("pubsealed", "doc", "", withNonce(addRoot(map[string]any{"$schema": tRef})), pg)

	// A public referrer: anyone, whatever grant comes along.
	stranger := e.grant(newKey("pk"), "user:x", []string{"pub", "schemas"}, []string{"read"})
	for name, bearer := range map[string]string{"none": "", "not naming schemas": og, "malformed": "not-a-grant", "badly signed": stranger} {
		r := e.get(sRef, bearer)
		expect(t, r, 200)
		if cc := r.H.Get("Cache-Control"); cc != "private, max-age=300" {
			t.Fatalf("%s: Cache-Control %q", name, cc)
		}
	}
	// Nothing else of schemas: the head, the log, a revision nobody pins.
	expect(t, e.get("/r/schemas/s"), 401)
	expect(t, e.get(sRef+"/log"), 401)
	expectCode(t, e.get("/r/schemas/s", og), 403, "forbidden")
	s2 := e.appendRev("schemas", "s", strings.TrimPrefix(sRef, "/r/schemas/s/rev/"), ops(op("add", "/title", "v2")), sg)
	expect(t, e.get("/r/schemas/s/rev/"+s2), 401)
	expect(t, e.get("/r/nope/s/rev/"+s2), 401)

	// A private referrer needs a grant that verifies there and may read it;
	// so does a public sealed one.
	reader := e.grant(rk, "user:r", []string{"priv", "pubsealed"}, []string{"read"})
	for _, ref := range []string{pRef, tRef} {
		expect(t, e.get(ref), 401)
		expectCode(t, e.get(ref, og), 403, "forbidden")
		expectCode(t, e.get(ref, e.grant(newKey("rk"), "user:r", []string{"priv", "pubsealed"}, []string{"read"})), 403, "forbidden")
		expectCode(t, e.get(ref, e.grant(rk, "user:r", []string{"priv", "pubsealed"}, []string{"read"},
			map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "other"}}})), 403, "forbidden")
		expect(t, e.get(ref, reader), 200)
	}

	// Once the public referrer no longer pins it, the revision closes.
	e.appendRev("pub", "doc", d, ops(op("remove", "/$schema")), pg)
	expect(t, e.get(sRef), 401)
	expect(t, e.get(sRef, og), 403)
}

// v0.49 §C.5, §E.2.3: POST /ns/{ns}/keys gives a grant whose rules fix
// /resource the keys of the resources it may read, and epoch keys to any
// other read grant that reads the namespace unrestricted; one that doesn't
// is 403. Existence stays hidden as for other reads (§7).
func TestV049KeysUnrestricted(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k, ok := newKey("k"), newKey("ok")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	e.mkNS("other", map[string]any{"read": "grant", "keys": []any{ok.entry("*")}})
	star := e.grant(k, "user:admin", []string{"s"}, []string{"create", "read"})
	e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": "a"})), star)
	e.wr("s", "b", "", withNonce(addRoot(map[string]any{"v": "b"})), star)
	rule := func(path string, v any) map[string]any {
		return map[string]any{"rules": []any{map[string]any{"op": "test", "path": path, "value": v}}}
	}

	keys, r := e.keysOf("s", nil, e.grant(k, "user:x", []string{"s"}, []string{"read"}))
	if r.Code != 200 || len(keys) != 1 || keys["s#1"] == nil {
		t.Fatalf("unrestricted: %d %s", r.Code, r.Body)
	}
	keys, r = e.keysOf("s", map[string]any{"resources": []any{"a", "b"}}, e.grant(k, "user:x", []string{"s"}, []string{"read"}, rule("/resource", "a")))
	if r.Code != 200 || len(keys) != 1 || keys["s#1 a"] == nil {
		t.Fatalf("fixed to a: %d %s", r.Code, r.Body)
	}
	// Its rules fail for the principal without referring to /resource.
	_, r = e.keysOf("s", nil, e.grant(k, "user:x", []string{"s"}, []string{"read"}, rule("/principal/id", "user:y")))
	expectCode(t, r, 403, "forbidden")

	// Other refusals answer as any read of the namespace does.
	_, r = e.keysOf("s", nil, "")
	expect(t, r, 401)
	_, r = e.keysOf("s", nil, e.grant(newKey("k"), "user:x", []string{"s"}, []string{"read"}))
	expect(t, r, 401)
	_, r = e.keysOf("s", nil, e.grant(k, "user:x", []string{"s"}, []string{"create"}))
	expect(t, r, 404)
	notNamed := e.grant(ok, "user:x", []string{"other"}, []string{"read"})
	_, r = e.keysOf("s", nil, notNamed)
	expectCode(t, r, 403, "forbidden")
	_, missing := e.keysOf("nope", nil, notNamed)
	expectCode(t, missing, 403, "forbidden")
	// A public namespace ignores a grant that doesn't name it, as its reads
	// do: keys still need one.
	e.mkNS("p", sealedDoc(map[string]any{"read": "public", "keys": []any{k.entry("*")}}))
	_, r = e.keysOf("p", nil, notNamed)
	expectCode(t, r, 401, "unauthenticated")
}

// v0.49 §C.5 "Writes that need it": branching and remote registration
// check read as gate step 1 checks verbs, in a public namespace too. The
// grant must allow read and read the namespace unrestricted, and its rules
// that refer only to /action, /principal or /now must pass with /action
// read; rules over the rest of the envelope, such as /doc, are judged at
// step 6 against the write's own envelope.
func TestV049BranchReadCheck(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"grant", "public"} {
		f := newAuthFixture(t, map[string]any{"read": read})
		e := f.tenv
		e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
		at := e.nsHead("sec", f.adminG)
		mk := func(can []string, rules ...any) string {
			extra := map[string]any{}
			if len(rules) > 0 {
				extra["rules"] = rules
			}
			return e.grant(f.admin, "user:x", []string{"sec", "sec-b"}, can, extra)
		}
		onlyVerb := func(verb string) any { return map[string]any{"op": "test", "path": "/action", "value": verb} }
		team := map[string]any{"op": "test", "path": "/doc/x-team", "value": "a"}

		// No read, or a rule refusing it for /action read.
		for _, g := range []string{mk([]string{"branch", "export"}), mk([]string{"read", "branch"}, onlyVerb("branch"))} {
			expectCode(t, e.branch("sec", map[string]any{"name": "sec-b"}, g), 403, "forbidden")
		}
		expectCode(t, e.register("sec", "rel", at, "", mk([]string{"read", "export"}, onlyVerb("export"))), 403, "forbidden")

		// A /doc rule is the branch's to pass, at step 6.
		g := mk([]string{"read", "branch"}, team)
		expectCode(t, e.branch("sec", map[string]any{"name": "sec-b"}, g), 403, "forbidden")
		expect(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("add", "/x-team", "a"))}, g), 201)
		expect(t, e.register("sec", "rel", at, "", mk([]string{"read", "export"})), 201)
	}
}

// v0.49 §7.4, §C.7: a namespace can't start requiring nonces while a
// dependent, a branch at any depth that isn't purged, doesn't: 409 in_use
// with the dependents, leaves first, the order to set them in.
func TestV049NonceDependents(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("m", map[string]any{"read": "grant"})
	e.create("m", "d", map[string]any{"v": 1.0})
	for _, b := range [][2]string{{"m", "b1"}, {"b1", "b2"}, {"m", "c1"}} {
		expect(t, e.branch(b[0], map[string]any{"name": b[1]}, "alice"), 201)
	}
	require := ops(op("add", "/nonce", "required"))
	dependents := func(ns string, want ...string) {
		t.Helper()
		r := e.patchNS(ns, require, "")
		expectCode(t, r, 409, "in_use")
		var got []string
		for _, d := range r.Obj()["dependents"].([]any) {
			got = append(got, d.(string))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: dependents %v, want %v", ns, got, want)
		}
	}
	dependents("m", "b2", "b1", "c1")
	dependents("b1", "b2")
	expect(t, e.patchNS("b2", require, ""), 201)
	expect(t, e.patchNS("b1", require, ""), 201)
	// A frozen branch is still a dependent; a purged one isn't.
	expect(t, e.patchNS("c1", ops(op("add", "/frozen", true)), ""), 201)
	dependents("m", "c1")
	expect(t, e.do(req{method: "POST", path: "/ns/c1/purge", ifMatch: e.nsHead("c1"), author: "admin"}), 204)
	expect(t, e.patchNS("m", require, ""), 201)
	// Turning it off needs nothing of them.
	expect(t, e.patchNS("m", ops(op("replace", "/nonce", "optional")), ""), 201)
}

// v0.49 §C.7, §G.3: a remote branch follows its base's current namespace
// document, not the one at at. Schema namespaces created to mirror for it
// start optional, since their history keeps its ids, and take their
// source's setting with a config write once it is in; they stay optional
// if B can't read the source's namespace document.
func TestV049RemoteBranchNonces(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, nil)
	schema := func(ns, name string) string {
		a.mkNS(ns, map[string]any{"read": "public", "nonce": "required"})
		return "/r/" + ns + "/" + name + "/rev/" + a.create(ns, name, map[string]any{"$schema": dialect, "type": "object", "$nonce": seal.NewNonce()})
	}
	match, team := schema("schemas", "match"), schema("hidden", "team")
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "derby", map[string]any{"$schema": match})
	a.create("main", "oaks", map[string]any{"$schema": team})
	at := a.nsHead("main")
	// Required since at.
	expect(t, a.patchNS("main", ops(op("add", "/nonce", "required")), ""), 201)
	rt.set(refusing(t, a, "/ns/hidden", 404), "")
	r := b.mkRemote("rel", remoteGenesis("main", at, nil))
	if r.Code != 422 || !strings.Contains(r.String(), "/nonce") {
		t.Fatalf("remote branch without nonce: %d %s", r.Code, r.Body)
	}
	expect(t, b.mkRemote("rel", remoteGenesis("main", at, map[string]any{"nonce": "required"})), 201)

	log := func(ns string) []any { return b.get("/ns/" + ns + "/rev/" + b.nsHead(ns) + "/log").Arr() }
	kinds := func(ns string) []string {
		var out []string
		for _, x := range log(ns) {
			m := x.(map[string]any)
			if m["author"] != "op" {
				t.Fatalf("%s: entry %v isn't the creating operator's", ns, m)
			}
			out = append(out, m["kind"].(string))
		}
		return out
	}
	if k := kinds("schemas"); !slices.Equal(k, []string{"config", "batch", "config"}) {
		t.Fatalf("schemas log %v", k)
	}
	first := b.get("/ns/schemas/rev/" + log("schemas")[0].(map[string]any)["id"].(string))
	expect(t, first, 200)
	if first.Obj()["nonce"] != nil || b.nsDoc("schemas")["nonce"] != "required" {
		t.Fatalf("schemas: genesis %s, now %v", first.Body, b.nsDoc("schemas"))
	}
	if k := kinds("hidden"); !slices.Equal(k, []string{"config", "batch"}) || b.nsDoc("hidden")["nonce"] != nil {
		t.Fatalf("hidden: log %v, document %v", k, b.nsDoc("hidden"))
	}
	h := b.head("schemas", "match")
	expectCode(t, b.write("PATCH", "schemas", "match", h, ops(op("add", "/title", "x"))), 422, "nonce")

	// Required at at but no longer: the branch may leave it optional.
	a.mkNS("old", map[string]any{"read": "public", "nonce": "required"})
	a.create("old", "x", map[string]any{"$nonce": seal.NewNonce()})
	at = a.nsHead("old")
	expect(t, a.patchNS("old", ops(op("replace", "/nonce", "optional")), ""), 201)
	expect(t, b.mkRemote("rel-old", remoteGenesis("old", at, nil)), 201)
	b.appendRev("rel-old", "x", b.head("rel-old", "x"), ops(op("add", "/v", 1.0)))
}

// v0.49 §C.5, §12: while authentication is disabled, edge-grant issuance
// is 404 not_offered; withdrawal answers as with authentication, so
// sign-out works either way.
func TestV049EdgeGrantsAuthDisabled(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("pub", map[string]any{"read": "public"})
	expectCode(t, e.do(req{method: "POST", path: "/edge-grants"}), 404, "not_offered")
	expectCode(t, e.do(req{method: "POST", path: "/edge-grants", hdr: map[string]string{"Authorization": "Bearer x"}}), 404, "not_offered")
	r := e.do(req{method: "DELETE", path: "/edge-grants?prefix=/r/pub&prefix=/r/pub"})
	expect(t, r, 204)
	if cs := (&http.Response{Header: r.H}).Cookies(); len(cs) != 1 || cs[0].Path != "/r/pub" || cs[0].MaxAge >= 0 {
		t.Fatalf("Set-Cookie %v", r.H.Values("Set-Cookie"))
	}
	expectCode(t, e.do(req{method: "DELETE", path: "/edge-grants"}), 400, "bad_input")
}

// v0.49 §C.5: issuance answers all or nothing, and decides a purged
// namespace last: 401 if any namespace would be 401, else 403 if any would
// be 403, and 410 purged only when every one refused is purged and the
// grant verifies and may read there.
func TestV049EdgeGrantsPurged(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	admin := e.grant(f.admin, "user:root", []string{"p1", "p2", "sec2"}, allVerbs)
	for _, ns := range []string{"p1", "p2", "sec2"} {
		e.mkNS(ns, map[string]any{"read": "grant", "keys": []any{f.admin.entry("*"), f.issuer.entry("read", "append")}})
	}
	for _, ns := range []string{"p1", "p2"} {
		expect(t, e.patchNS(ns, ops(op("add", "/frozen", true)), admin), 201)
		expect(t, e.do(req{method: "POST", path: "/ns/" + ns + "/purge", ifMatch: e.nsHead(ns, admin), bearer: admin}), 204)
	}
	read := []string{"read"}
	now := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}}
	for _, c := range []struct {
		name   string
		g      string
		status int
	}{
		{"purged", e.grant(f.issuer, "user:bob", []string{"p1"}, read), 410},
		{"both purged", e.grant(f.issuer, "user:bob", []string{"p1", "p2"}, read), 410},
		{"one issues", e.grant(f.issuer, "user:bob", []string{"p1", "sec"}, read), 410},
		{"no read", e.grant(f.issuer, "user:bob", []string{"p1"}, []string{"append"}), 403},
		{"a rule on /now", e.grant(f.issuer, "user:bob", []string{"p1"}, read, now), 403},
		{"another refuses", e.grant(f.issuer, "user:bob", []string{"p1", "sec2"}, []string{"append"}), 403},
		{"one missing", e.grant(f.issuer, "user:bob", []string{"p1", "nope"}, read), 401},
		{"doesn't verify", e.grant(newKey("issuer"), "user:bob", []string{"p1"}, read), 401},
	} {
		r := e.do(req{method: "POST", path: "/edge-grants", bearer: c.g})
		if r.Code != c.status || c.status == 410 && r.Str("code") != "purged" {
			t.Errorf("%s: want %d: %d %s", c.name, c.status, r.Code, r.Body)
		}
		if len(r.H.Values("Set-Cookie")) > 0 {
			t.Errorf("%s: cookies set on a refusal: %v", c.name, r.H.Values("Set-Cookie"))
		}
	}
}
