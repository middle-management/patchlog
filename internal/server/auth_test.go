package server

import (
	"strconv"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

var allVerbs = []string{"read", "create", "append", "restore", "delete", "purge", "config", "branch", "purge-ns", "prune"}

type authFixture struct {
	*tenv
	admin, issuer, svc keyPair
	adminG, issuerG    string
}

func newAuthFixture(t *testing.T, extra map[string]any, opts ...envOpt) *authFixture {
	e := newAuthEnv(t, opts...)
	f := &authFixture{tenv: e, admin: newKey("admin"), issuer: newKey("issuer"), svc: newKey("svc")}
	svcEntry := f.svc.entry("read", "append")
	svcEntry["sub"] = "svc:.*"
	doc := map[string]any{
		"read": "grant",
		"keys": []any{
			f.admin.entry("*"),
			f.issuer.entry("read", "create", "append", "restore", "delete", "config", "branch", "purge", "prune"),
			svcEntry,
		},
		"roles": map[string]any{
			"translator": map[string]any{"can": []any{"read", "append"}, "rules": []any{map[string]any{"op": "writes", "within": []any{"/i18n"}}}},
			"editor":     map[string]any{"can": []any{"read", "create", "append", "restore", "delete"}},
		},
	}
	for k, v := range extra {
		doc[k] = v
	}
	e.mkNS("sec", doc)
	f.adminG = e.grant(f.admin, "user:root", []string{"sec", "sec-b"}, allVerbs)
	f.issuerG = e.grant(f.issuer, "user:bob", []string{"sec", "sec-b"}, []string{"read", "create", "append", "restore", "delete", "config", "branch"})
	return f
}

func revocationID(t *testing.T, token string, block int) string {
	t.Helper()
	g, err := grant.Decode(token, 0)
	if err != nil {
		t.Fatal(err)
	}
	return g.RevocationIDs()[block]
}

// §C.4 bootstrapping: creating a namespace needs an operator key.
func TestAuthNamespaceCreation(t *testing.T) {
	e := newAuthEnv(t)
	k := newKey("admin")
	doc := addRoot(map[string]any{"keys": []any{k.entry("*")}})
	r := e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc})
	expectCode(t, r, 401, "unauthenticated")
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc, bearer: "garbage"})
	expectCode(t, r, 401, "unauthenticated")
	// A key that isn't an operator key can't create namespaces.
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc, bearer: e.grant(k, "user:x", []string{"n1"}, []string{"config"})})
	expect(t, r, 401)
	// An operator grant for another namespace.
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc, bearer: e.operatorGrant("n2")})
	expect(t, r, 403)
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc, bearer: e.operatorGrant("n1")})
	expect(t, r, 201)
	// Creating it again: 412 {config}, for the operator and for its own admin.
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc, bearer: e.operatorGrant("n1")})
	expectCode(t, r, 412, "stale")
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifNoneMatch: "*", body: doc, bearer: e.grant(k, "user:x", []string{"n1"}, []string{"config"})})
	expectCode(t, r, 412, "stale")
	// The operator key is not a key of the namespace.
	r = e.do(req{method: "PATCH", path: "/ns/n1", ifMatch: e.configID("n1", e.grant(k, "user:x", []string{"n1"}, []string{"read"})), body: ops(op("add", "/x", 1.0)), bearer: e.operatorGrant("n1")})
	expect(t, r, 401)
}

// §C.2: 401, 403, authorisation before the precondition.
func TestAuthChecks(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"title": "t", "i18n": map[string]any{}}, f.issuerG)

	// 401: missing, malformed, unknown key, bad signature.
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), ""), 401, "unauthenticated")
	r := e.do(req{method: "PATCH", path: "/r/sec/a", ifMatch: a, body: []any{}, bearer: "not-a-grant"})
	expectCode(t, r, 401, "unauthenticated")
	stranger := newKey("issuer") // same kid, different key
	r = e.write("PATCH", "sec", "a", a, []any{}, e.grant(stranger, "user:bob", []string{"sec"}, []string{"append"}))
	expectCode(t, r, 401, "unauthenticated")
	r = e.write("PATCH", "sec", "a", a, []any{}, e.grant(newKey("nokey"), "user:bob", []string{"sec"}, []string{"append"}))
	expectCode(t, r, 401, "unauthenticated")

	// 403: verb not allowed, namespace not listed, key may not grant the verb.
	reader := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"})
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), reader), 403, "forbidden")
	other := e.grant(f.issuer, "user:bob", []string{"elsewhere"}, []string{"append"})
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), other), 403, "forbidden")
	tooMuch := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append", "purge-ns"})
	expect(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/x", 1.0)), tooMuch), 403)
	// Authorisation comes before the precondition: no 412 (and no head) for the unauthorised.
	r = e.write("PATCH", "sec", "a", hashID(t, "", nil), []any{}, reader)
	expectCode(t, r, 403, "forbidden")
	if r.Obj()["head"] != nil {
		t.Fatal("unauthorised caller saw the head")
	}
	onlyB := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	r = e.write("PATCH", "sec", "a", hashID(t, "", nil), []any{}, onlyB)
	expectCode(t, r, 403, "forbidden")
	// Restore is checked at step 6 for a PATCH with If-Match.
	appendOnly := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append", "delete"})
	tomb := e.del("sec", "a", a, appendOnly)
	expectCode(t, e.write("PATCH", "sec", "a", tomb, []any{}, appendOnly), 403, "forbidden")
	a = e.appendRev("sec", "a", tomb, []any{}, f.issuerG)

	// Time: expired and not-yet-valid grants.
	short := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"}, map[string]any{"exp": e.clock.Now().Add(time.Minute).Format(time.RFC3339)})
	future := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"}, map[string]any{"nbf": e.clock.Now().Add(30 * time.Minute).Format(time.RFC3339)})
	if r := e.write("PATCH", "sec", "a", a, ops(op("add", "/nbf", 1.0)), future); r.Code != 401 && r.Code != 403 {
		t.Fatalf("not-yet-valid grant: %d", r.Code)
	}
	e.clock.Advance(2 * time.Minute)
	if r := e.write("PATCH", "sec", "a", a, ops(op("add", "/exp", 1.0)), short); r.Code != 401 && r.Code != 403 {
		t.Fatalf("expired grant: %d", r.Code)
	}

	// Author is the root sub; a re-minted grant for the same sub is the same principal.
	g2 := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"append"})
	p := ops(op("replace", "/title", "u"))
	a2 := e.appendRev("sec", "a", a, p, f.issuerG)
	r = e.write("PATCH", "sec", "a", a, p, g2)
	expect(t, r, 200)
	if etagOf(r) != a2 {
		t.Fatal("retry by the same sub")
	}
	carol := e.grant(f.issuer, "user:carol", []string{"sec"}, []string{"append"})
	expectCode(t, e.write("PATCH", "sec", "a", a, p, carol), 412, "stale")
	lg := e.get("/r/sec/a/rev/"+a2+"/log?since="+a, f.issuerG).Arr()
	if lg[0].(map[string]any)["author"] != "user:bob" {
		t.Fatalf("author %v", lg[0])
	}
}

// §C.5: reads of grant namespaces.
func TestAuthReads(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{}, f.issuerG)
	e.create("sec", "b", map[string]any{}, f.issuerG)

	// Without a grant: 401, whether or not the resource exists.
	expect(t, e.get("/r/sec/a"), 401)
	expect(t, e.get("/r/sec/missing"), 401)
	// Without read: 404, whether or not the resource exists.
	noRead := e.grant(f.issuer, "user:w", []string{"sec"}, []string{"append"})
	x, y := e.get("/r/sec/a", noRead), e.get("/r/sec/missing", noRead)
	if x.Code != 404 || y.Code != 404 || string(x.Body) != string(y.Body) {
		t.Fatalf("existence revealed: %d %s / %d %s", x.Code, x.Body, y.Code, y.Body)
	}
	for _, p := range []string{"/r/sec/a/rev/" + a, "/r/sec/a/rev/" + a + "/log", "/ns/sec", "/ns/sec/branches", "/r/sec/a/events", "/ns/sec/events"} {
		if r := e.get(p, noRead); r.Code != 404 {
			t.Errorf("%s without read: %d", p, r.Code)
		}
	}
	// A grant from another namespace's key: 401 (unknown key).
	expect(t, e.get("/r/sec/a", e.grant(newKey("zz"), "user:x", []string{"sec"}, []string{"read"})), 401)
	// read grants.
	reader := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"})
	h := e.get("/r/sec/a", reader)
	expect(t, h, 302)
	if cc := h.H.Get("Cache-Control"); cc != "private, max-age=0" || h.H.Get("CDN-Cache-Control") == "" {
		t.Fatalf("private head cache %v", h.H)
	}
	expect(t, e.get("/ns/sec", reader), 302)
	// A read grant fixed to one resource reads only it, and not the namespace.
	onlyA := e.grant(f.issuer, "user:r", []string{"sec"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	expect(t, e.get("/r/sec/a", onlyA), 302)
	expect(t, e.get("/r/sec/a/rev/"+a, onlyA), 200)
	expect(t, e.get("/r/sec/b", onlyA), 404)
	expect(t, e.get("/ns/sec", onlyA), 404)
	// Roles grant reads too.
	tr := e.grant(f.issuer, "user:t", []string{"sec"}, nil, map[string]any{"roles": []any{"translator"}})
	expect(t, e.get("/r/sec/a", tr), 302)
	// Resolving a schema needs read on its namespace (§6.1).
	e.mkNS("ss", map[string]any{"read": "grant", "keys": []any{f.issuer.entry("read", "create", "append")}})
	s := e.create("ss", "s", map[string]any{"$schema": dialect, "type": "object"}, e.grant(f.issuer, "user:bob", []string{"ss"}, []string{"create"}))
	ref := "/r/ss/s/rev/" + s
	w1 := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"create"})
	expectCode(t, e.write("PATCH", "sec", "typed", "", addRoot(map[string]any{"$schema": ref}), w1), 422, "schema_unavailable")
	w2 := e.grant(f.issuer, "user:bob", []string{"sec", "ss"}, []string{"create", "read"})
	e.create("sec", "typed", map[string]any{"$schema": ref}, w2)
}

// §C.1 narrowing, §C.1.1 roles, §C.4 revocation and key scopes.
func TestAuthNarrowingRolesRevocation(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"title": "t", "i18n": map[string]any{}}, f.issuerG)

	// Narrowing to a translator service: writes within /i18n only.
	root, _ := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:bob", "ns": []any{"sec"}, "can": []any{"read", "append", "delete"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	nar, err := root.Narrow(map[string]any{"via": "svc:translator", "can": []any{"append"}, "rules": []any{map[string]any{"op": "writes", "within": []any{"/i18n"}}}})
	if err != nil {
		t.Fatal(err)
	}
	narrowed := nar.Encode()
	a = e.appendRev("sec", "a", a, ops(op("add", "/i18n/sv", "hej")), narrowed)
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("replace", "/title", "x")), narrowed), 403, "forbidden")
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(map[string]any{"op": "move", "from": "/title", "path": "/i18n/t"}), narrowed), 403, "forbidden")
	expectCode(t, e.write("DELETE", "sec", "a", a, nil, narrowed), 403, "forbidden")
	// A narrowing block can't widen.
	wide, _ := root.Narrow(map[string]any{"can": []any{"append", "purge"}})
	expectCode(t, e.do(req{method: "POST", path: "/r/sec/a/purge", ifMatch: a, bearer: wide.Encode()}), 403, "forbidden")
	// The root sub is the author.
	lg := e.get("/r/sec/a/rev/"+a+"/log", f.issuerG).Arr()
	if lg[len(lg)-1].(map[string]any)["author"] != "user:bob" {
		t.Fatalf("narrowed author %v", lg[len(lg)-1])
	}

	// Roles: alternatives; role rules apply; narrowing may reduce roles.
	tr := e.grant(f.issuer, "user:t", []string{"sec"}, nil, map[string]any{"roles": []any{"translator"}})
	both := e.grant(f.issuer, "user:t", []string{"sec"}, nil, map[string]any{"roles": []any{"translator", "editor"}})
	expectCode(t, e.write("PATCH", "sec", "new", "", addRoot(map[string]any{}), tr), 403, "forbidden")
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("replace", "/title", "x")), tr), 403, "forbidden")
	a = e.appendRev("sec", "a", a, ops(op("add", "/i18n/no", "hei")), tr)
	a = e.appendRev("sec", "a", a, ops(op("replace", "/title", "by editor")), both)
	bothRoot, _ := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:t", "ns": []any{"sec"}, "roles": []any{"translator", "editor"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	onlyTr, _ := bothRoot.Narrow(map[string]any{"roles": []any{"translator"}})
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("replace", "/title", "y")), onlyTr.Encode()), 403, "forbidden")
	// Changing /roles needs a * key; removing a role revokes it at once.
	expectCode(t, e.patchNS("sec", ops(op("remove", "/roles/translator")), f.issuerG), 403, "forbidden")
	expect(t, e.patchNS("sec", ops(op("remove", "/roles/translator")), f.adminG), 201)
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/i18n/da", "hej")), tr), 403, "forbidden")

	// Revocation: a narrowing block, then a root block.
	expect(t, e.patchNS("sec", ops(op("add", "/revoked", []any{revocationID(t, narrowed, 1)})), f.adminG), 201)
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/i18n/fi", "x")), narrowed), 403, "forbidden")
	a = e.appendRev("sec", "a", a, ops(op("add", "/i18n/fi", "x")), root.Encode())
	expect(t, e.patchNS("sec", ops(op("add", "/revoked/-", revocationID(t, root.Encode(), 0))), f.adminG), 201)
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/i18n/is", "x")), root.Encode()), 403, "forbidden")
	// Revocation is by block, however re-serialised; other grants of the key still work.
	a = e.appendRev("sec", "a", a, ops(op("add", "/z", 1.0)), f.issuerG)
	// Revoking needs a * key.
	expectCode(t, e.patchNS("sec", ops(op("add", "/revoked/-", "1aaaa")), f.issuerG), 403, "forbidden")

	// Key scope: sub pattern and verbs.
	svcBad := e.grant(f.svc, "user:x", []string{"sec"}, []string{"append"})
	expectCode(t, e.write("PATCH", "sec", "a", a, ops(op("add", "/s", 1.0)), svcBad), 403, "forbidden")
	svcOK := e.grant(f.svc, "svc:indexer", []string{"sec"}, []string{"append"})
	a = e.appendRev("sec", "a", a, ops(op("add", "/s", 1.0)), svcOK)
	svcDel := e.grant(f.svc, "svc:indexer", []string{"sec"}, []string{"delete"})
	expectCode(t, e.write("DELETE", "sec", "a", a, nil, svcDel), 403, "forbidden")
}

// §7.4 guarded paths; §6.4.3 config writes are rule-checked except for * keys;
// §6.4.4 group and ownership rules with a principal.
func TestAuthConfigAndRules(t *testing.T) {
	ownership := map[string]any{
		"if": []any{
			map[string]any{"not": map[string]any{"op": "test", "path": "/principal/roles", "schema": map[string]any{"contains": map[string]any{"const": "editor"}}}},
			map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"create", "append", "restore"}}},
		},
		"then": []any{
			map[string]any{"op": "compare", "path": "/doc/owner", "eq": map[string]any{"path": "/principal/id"}},
			map[string]any{"op": "compare", "path": "/doc/region", "in": map[string]any{"path": "/principal/attrs/regions"}},
			map[string]any{
				"if": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/action", "value": "create"}}},
				"then": []any{
					map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/owner"}},
					map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/lockAt"}},
				},
			},
			map[string]any{
				"if":   []any{map[string]any{"op": "test", "path": "/doc/lockAt", "exists": true}},
				"then": []any{map[string]any{"op": "compare", "path": "/now", "lt": map[string]any{"path": "/doc/lockAt"}}},
			},
		},
	}
	opsOnly := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"delete", "purge"}}}},
		"then": []any{map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "ops"}}}},
	}
	noTitle := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "config"}},
		"then": []any{map[string]any{"not": map[string]any{"op": "writes", "overlaps": "/title"}}},
	}
	f := newAuthFixture(t, map[string]any{"rules": []any{ownership, opsOnly, noTitle}})
	e := f.tenv

	// Config: rules apply except under a * key.
	expectCode(t, e.patchNS("sec", ops(op("add", "/title", "x")), f.issuerG), 422, "rule")
	expect(t, e.patchNS("sec", ops(op("add", "/title", "x")), f.adminG), 201)
	expect(t, e.patchNS("sec", ops(op("add", "/other", "x")), f.issuerG), 201)
	// Guarded paths need a * key.
	for _, p := range [][]any{
		ops(op("add", "/keys/-", newKey("k2").entry("read"))),
		ops(op("add", "/limits", map[string]any{"opsPerSet": 10.0})),
		ops(op("add", "/revoked", []any{})),
		ops(op("add", "/retention", []any{})),
		ops(op("replace", "/read", "public")),
		ops(op("replace", "", map[string]any{"read": "grant"})),
	} {
		expectCode(t, e.patchNS("sec", p, f.issuerG), 403, "forbidden")
	}
	expect(t, e.patchNS("sec", ops(op("replace", "/read", "public")), f.adminG), 201)
	// Making read stricter needs no * key.
	expect(t, e.patchNS("sec", ops(op("replace", "/read", "grant")), f.issuerG), 201)
	// Stale config id.
	r := e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: hashID(t, "", nil), body: ops(op("add", "/y", 1.0)), bearer: f.issuerG})
	expectCode(t, r, 412, "stale")
	if r.Str("config") != e.configID("sec", f.issuerG) {
		t.Fatalf("412 config %s", r.Body)
	}

	// Ownership: without editor, own documents in own regions, no reassignment, lockAt.
	li := e.grant(f.issuer, "user:li", []string{"sec"}, []string{"read", "create", "append", "delete"}, map[string]any{"attrs": map[string]any{"regions": []any{"se", "no"}}})
	ed := e.grant(f.issuer, "user:ed", []string{"sec"}, nil, map[string]any{"roles": []any{"editor"}})
	lockAt := e.clock.Now().Add(time.Hour).Format("2006-01-02T15:04:05.000Z")
	expectCode(t, e.write("PATCH", "sec", "m", "", addRoot(map[string]any{"owner": "user:ed", "region": "se"}), li), 422, "rule")
	expectCode(t, e.write("PATCH", "sec", "m", "", addRoot(map[string]any{"owner": "user:li", "region": "dk"}), li), 422, "rule")
	m := e.create("sec", "m", map[string]any{"owner": "user:li", "region": "se", "lockAt": lockAt, "v": 1.0}, li)
	m = e.appendRev("sec", "m", m, ops(op("replace", "/v", 2.0)), li)
	expectCode(t, e.write("PATCH", "sec", "m", m, ops(op("replace", "/lockAt", "2099-01-01T00:00:00Z")), li), 422, "rule")
	expectCode(t, e.write("PATCH", "sec", "m", m, ops(op("replace", "", map[string]any{"owner": "user:li", "region": "se", "v": 3.0})), li), 422, "rule")
	// The editor role is exempt.
	m = e.appendRev("sec", "m", m, ops(op("replace", "/owner", "user:ed")), ed)
	m = e.appendRev("sec", "m", m, ops(op("replace", "/owner", "user:li")), ed)
	// After lockAt the owner can't edit.
	e.clock.Advance(2 * time.Hour)
	li = e.grant(f.issuer, "user:li", []string{"sec"}, []string{"read", "create", "append", "delete"}, map[string]any{"attrs": map[string]any{"regions": []any{"se"}}})
	expectCode(t, e.write("PATCH", "sec", "m", m, ops(op("replace", "/v", 9.0)), li), 422, "rule")

	// Only the ops group may delete.
	expectCode(t, e.write("DELETE", "sec", "m", m, nil, li), 422, "rule")
	opsG := e.grant(f.issuer, "user:o", []string{"sec"}, []string{"delete"}, map[string]any{"groups": []any{"ops"}})
	e.del("sec", "m", m, opsG)
}

// §7.6 / §C.4: branches with auth — unrestricted read, * keys kept, keys follow the base.
func TestAuthBranches(t *testing.T) {
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{}, f.issuerG)

	// Branching needs branch and unrestricted read.
	noBranch := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-b"}, noBranch), 403, "forbidden")
	restricted := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read", "branch"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "sec-b"}}})
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-b"}, restricted), 403, "forbidden")
	// Patches touching /keys need a * key of the base; * keys can't be removed.
	expectCode(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("add", "/keys/-", newKey("mine").entry("read")))}, f.issuerG), 403, "forbidden")
	expect(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("remove", "/keys/0"))}, f.adminG), 422)
	mine := newKey("mine")
	expect(t, e.branch("sec", map[string]any{"name": "sec-b", "patches": ops(op("add", "/keys/-", mine.entry("read", "append")))}, f.adminG), 201)

	// The issuer's grant works in the branch (keys were copied).
	e.appendRev("sec-b", "a", a, ops(op("add", "/x", 1.0)), f.issuerG)
	// The branch's own key works there, and not in the base.
	mineG := e.grant(mine, "user:m", []string{"sec", "sec-b"}, []string{"read", "append"})
	expect(t, e.get("/r/sec-b/a", mineG), 302)
	expect(t, e.get("/r/sec/a", mineG), 401)
	// A config write to the branch can't remove or change a base * key.
	expectCode(t, e.patchNS("sec-b", ops(op("remove", "/keys/0")), f.adminG), 422, "invalid")
	// Revocation in the base applies to the branch.
	victim := e.grant(f.issuer, "user:v", []string{"sec", "sec-b"}, []string{"read"})
	expect(t, e.get("/r/sec-b/a", victim), 302)
	expect(t, e.patchNS("sec", ops(op("add", "/revoked", []any{revocationID(t, victim, 0)})), f.adminG), 201)
	expect(t, e.get("/r/sec-b/a", victim), 404) // a rejected grant has no read: 404
	// Keys follow the base: removing the issuer key from the base disables it in the branch.
	cfg := e.get("/ns/sec/rev/"+e.nsHead("sec", f.adminG), f.adminG).Obj()
	keys := cfg["keys"].([]any)
	var idx int
	for i, k := range keys {
		if k.(map[string]any)["kid"] == "issuer" {
			idx = i
		}
	}
	expect(t, e.patchNS("sec", ops(op("remove", "/keys/"+strconv.Itoa(idx))), f.adminG), 201)
	expectCode(t, e.write("PATCH", "sec-b", "a", e.head("sec-b", "a", f.adminG), ops(op("add", "/y", 1.0)), f.issuerG), 401, "unauthenticated")
	// The branch still lists the key in its own document, but it is not accepted.
	bcfg := e.get("/ns/sec-b/rev/"+e.nsHead("sec-b", f.adminG), f.adminG).Obj()
	found := false
	for _, k := range bcfg["keys"].([]any) {
		if k.(map[string]any)["kid"] == "issuer" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the branch document to keep its copy of the key")
	}
	// Admin (a * key of the base) keeps control: freeze and purge the branch.
	expect(t, e.patchNS("sec-b", ops(op("add", "/frozen", true)), f.adminG), 201)
	r := e.do(req{method: "POST", path: "/ns/sec-b/purge", ifMatch: e.nsHead("sec-b", f.adminG), bearer: f.adminG})
	expect(t, r, 204)
	// purge-ns is its own verb.
	e.patchNS("sec", ops(op("add", "/frozen", true)), f.adminG)
	purger := e.grant(f.admin, "user:p", []string{"sec"}, []string{"read", "purge"})
	expectCode(t, e.do(req{method: "POST", path: "/ns/sec/purge", ifMatch: e.nsHead("sec", f.adminG), bearer: purger}), 403, "forbidden")
}

// §C.4, §B.11.3: requireAt bounds a grant's `at` by the namespace's maxLag.
func TestAuthRequireAtMaxLag(t *testing.T) {
	cat := newKey("cat")
	entry := cat.entry("read", "create", "append")
	entry["requireAt"] = true
	f := newAuthFixture(t, map[string]any{"maxLag": "PT60S"})
	e := f.tenv
	cid := e.configID("sec", f.adminG)
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("add", "/keys/-", entry))}), 201)

	noAt := e.grant(cat, "user:li", []string{"sec"}, []string{"read", "create"})
	expect(t, e.write("PATCH", "sec", "a", "", addRoot(map[string]any{}), noAt), 403)

	at := e.nsHead("sec", f.adminG)
	g := e.grant(cat, "user:li", []string{"sec"}, []string{"read", "create"}, map[string]any{"at": at})
	expect(t, e.write("PATCH", "sec", "b", "", addRoot(map[string]any{}), g), 201)

	// at stops being the head; within maxLag the grant still works…
	e.clock.Advance(30 * time.Second)
	expect(t, e.write("PATCH", "sec", "c", "", addRoot(map[string]any{}), g), 201)
	// …beyond it, it doesn't.
	e.clock.Advance(90 * time.Second)
	expect(t, e.write("PATCH", "sec", "d", "", addRoot(map[string]any{}), g), 403)
	fresh := e.grant(cat, "user:li", []string{"sec"}, []string{"read", "create"}, map[string]any{"at": e.nsHead("sec", f.adminG)})
	expect(t, e.write("PATCH", "sec", "d", "", addRoot(map[string]any{}), fresh), 201)

	// maxLag must be a duration.
	cid = e.configID("sec", f.adminG)
	expect(t, e.do(req{method: "PATCH", path: "/ns/sec", ifMatch: cid, bearer: f.adminG,
		body: ops(op("replace", "/maxLag", "soon"))}), 422)
}
