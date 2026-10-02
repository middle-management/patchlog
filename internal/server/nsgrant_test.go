package server

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// grantRef is the grant reference §7.4 serves for a token: "sub kid id".
func grantRef(t *testing.T, token string) string {
	t.Helper()
	g, err := grant.Decode(token, 0)
	if err != nil {
		t.Fatal(err)
	}
	return g.Blocks[0].Sub + " " + g.Blocks[0].Kid + " " + g.ID().String()
}

// entryRef is an entry's grant member as "sub kid id", or "" without one.
func entryRef(t *testing.T, x any) string {
	t.Helper()
	m := x.(map[string]any)
	g, has := m["grant"]
	if !has {
		return ""
	}
	gm, ok := g.(map[string]any)
	if !ok || len(gm) != 3 {
		t.Fatalf("grant member %v", g)
	}
	return gm["sub"].(string) + " " + gm["kid"].(string) + " " + gm["id"].(string)
}

// checkEntries compares a log with the kinds, authors and grant references
// expected, oldest first. A grant reference "op:root operator *" matches
// any id of an operator grant.
func checkEntries(t *testing.T, ns string, lg []any, want [][3]string) {
	t.Helper()
	if len(lg) != len(want) {
		t.Fatalf("%s: %d entries, want %d: %v", ns, len(lg), len(want), lg)
	}
	for i, w := range want {
		m := lg[i].(map[string]any)
		ref := entryRef(t, m)
		if strings.HasSuffix(w[2], " *") && strings.HasPrefix(ref, strings.TrimSuffix(w[2], "*")) && len(ref) == len(w[2])-1+33 {
			ref = w[2]
		}
		if m["kind"] != w[0] || m["author"] != w[1] || ref != w[2] {
			t.Fatalf("%s entry %d: %v %v grant %q, want %v", ns, i, m["kind"], m["author"], ref, w)
		}
		// The grant replaces the kid member of earlier versions, and like
		// author and created it isn't part of the hashed entry (§3.5).
		if _, has := m["kid"]; has {
			t.Fatalf("%s entry %d still has kid: %v", ns, i, m)
		}
		hashed := map[string]any{}
		for k, v := range m {
			switch k {
			case "id", "prev", "author", "created", "grant":
			default:
				hashed[k] = v
			}
		}
		prev, _ := m["prev"].(string)
		if m["id"] != hashID(t, prev, jsonv.Canonical(hashed)) {
			t.Fatalf("%s entry %d: id %v doesn't hash its entry", ns, i, m["id"])
		}
	}
}

// §5, §7.4: every kind of entry written on a request records the grant it
// was written under, served as { id, sub, kid } (the grant id of §C.3 and
// its root sub and kid) outside the hashed entry; entries the server writes
// itself, such as a purge propagated to a branch (§8.3), keep the purger as
// author but carry no grant.
func TestNSLogGrant(t *testing.T) {
	f := newAuthFixture(t, nil, withoutRetentionLoop)
	e := f.tenv
	admin, issuer := grantRef(t, f.adminG), grantRef(t, f.issuerG)
	opRef := "op:root operator *"

	a1 := e.create("sec", "a", map[string]any{"v": 1.0}, f.issuerG)
	a2 := e.appendRev("sec", "a", a1, ops(op("add", "/w", 2.0)), f.adminG)
	tomb := e.del("sec", "a", a2, f.issuerG)
	a3 := e.appendRev("sec", "a", tomb, []any{}, f.issuerG) // restore
	expect(t, e.patchNS("sec", ops(op("replace", "/read", "grant")), f.adminG), 201)
	expect(t, e.batchReq("sec", map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"b": true})}},
	}}, f.issuerG), 201)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.issuerG), 201)
	// A purge in sec propagates to sec-b, which reads b through.
	expect(t, e.purge("sec", "b", e.head("sec", "b", f.adminG), f.adminG), 204)
	e.clock.Advance(10 * time.Minute) // past the retry window (§6.6)
	r := e.prune("sec", "a", map[string]any{"horizon": a2}, f.adminG)
	expect(t, r, 200)
	if r.H.Get("X-Namespace-Revision") == "" {
		t.Fatalf("prune wrote no entry: %s", r.Body)
	}
	if e.head("sec", "a", f.adminG) != a3 {
		t.Fatal("restore")
	}

	checkEntries(t, "sec", e.get("/ns/sec/rev/"+e.nsHead("sec", f.adminG)+"/log", f.adminG).Arr(), [][3]string{
		{"config", "op:root", opRef},
		{"head", "user:bob", issuer},
		{"head", "user:root", admin},
		{"tombstone", "user:bob", issuer},
		{"head", "user:bob", issuer},
		{"config", "user:root", admin},
		{"batch", "user:bob", issuer},
		{"branch", "user:bob", issuer},
		{"purge", "user:root", admin},
		{"prune", "user:root", admin},
	})

	// The branch's own chain: its first config entry is written on the
	// request, the propagated purge by the server; then a namespace purge.
	expect(t, e.patchNS("sec-b", ops(op("add", "/frozen", true)), f.issuerG), 201)
	head := e.nsHead("sec-b", f.adminG)
	expect(t, e.do(req{method: "POST", path: "/ns/sec-b/purge", ifMatch: head, bearer: f.adminG}), 204)
	// The chain of a purged namespace is still served (§8.5).
	entries := e.get("/ns/sec-b/rev/"+e.nsHead("sec-b", f.adminG)+"/log", f.adminG).Arr()
	checkEntries(t, "sec-b", entries, [][3]string{
		{"config", "user:bob", issuer},
		{"purge", "user:root", ""},
		{"config", "user:bob", issuer},
		{"purge-ns", "user:root", admin},
	})
}

// §7.4: a sealed namespace's log ranges (§E.2.2) carry the grant
// references in the sealed plaintext, as any log does.
func TestNSLogGrantSealed(t *testing.T) {
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	w := e.grant(k, "user:w", []string{"s"}, []string{"create", "append", "read"})
	e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})), w)
	head := e.nsHead("s", w)
	r := e.get("/ns/s/rev/"+head+"/log", w)
	expect(t, r, 200)
	if !isJOSE(r) {
		t.Fatalf("log not sealed: %s", r.Body)
	}
	keys, kr := e.keysOf("s", nil, w)
	if keys == nil {
		t.Fatalf("keys %d %s", kr.Code, kr.Body)
	}
	pt := open(t, string(r.Body), keys["s#1"], "s#1", seal.RangePL("s", "", head))
	v, err := jsonv.Parse(pt)
	if err != nil {
		t.Fatal(err)
	}
	checkEntries(t, "s", v.([]any), [][3]string{
		{"config", "op:root", "op:root operator *"},
		{"head", "user:w", grantRef(t, w)},
	})
}

// §1, §7.4: with authentication disabled no entry records a grant.
func TestNSLogGrantDev(t *testing.T) {
	e := newEnv(t)
	e.mkNS("main", map[string]any{})
	a := e.create("main", "a", map[string]any{}, "ann")
	expect(t, e.branch("main", map[string]any{"name": "main-b"}, "bea"), 201)
	expect(t, e.purge("main", "a", a, "cid"), 204)
	for _, ns := range []string{"main", "main-b"} {
		for _, x := range e.get("/ns/" + ns + "/rev/" + e.nsHead(ns) + "/log").Arr() {
			if _, has := x.(map[string]any)["grant"]; has {
				t.Fatalf("%s: dev-mode entry with a grant: %v", ns, x)
			}
		}
	}
	if k := e.nsKinds("main-b"); lastOf(k) != "purge" {
		t.Fatalf("main-b kinds %v", k)
	}
}

// withOperator turns authentication on with priv as the operator key.
func withOperator(priv ed25519.PrivateKey) envOpt {
	return func(o *core.Options) {
		ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519",
			"pub": base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), "can": []any{"*"}}}))
		if err != nil {
			panic(err)
		}
		o.OperatorKeys = ks
		o.AuthDisabled = false
	}
}

// A database from before grant references (§5, §7.4) recorded only the
// root kid. Opening it adds ns_log.grant_id and gives head, tombstone and
// batch entries the grant their revisions store; other entries serve none.
func TestNSLogGrantMigration(t *testing.T) {
	path, driver := filepath.Join(t.TempDir(), "old.db"), "sqlite"
	if pgtest.Enabled() {
		path, driver = pgtest.NewDB(t), "pgx"
	}
	f := newAuthFixture(t, nil, withPath(path))
	e := f.tenv
	a1 := e.create("sec", "a", map[string]any{}, f.issuerG)
	tomb := e.del("sec", "a", a1, f.adminG)
	expect(t, e.batchReq("sec", map[string]any{"items": []any{
		map[string]any{"resource": "a", "ifMatch": tomb, "steps": []any{[]any{}}},
	}}, f.issuerG), 201)
	expect(t, e.patchNS("sec", ops(op("replace", "/read", "grant")), f.adminG), 201)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.issuerG), 201)
	e.close()

	// Back to the old layout: ns_log.kid instead of ns_log.grant_id.
	dsn := path
	if driver == "sqlite" {
		dsn = "file:" + path
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`ALTER TABLE ns_log ADD COLUMN kid TEXT`, `UPDATE ns_log SET kid = 'issuer'`, `ALTER TABLE ns_log DROP COLUMN grant_id`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()

	e2 := newEnv(t, withPath(path), withOperator(e.opPriv))
	checkEntries(t, "sec", e2.get("/ns/sec/rev/"+e2.nsHead("sec", f.adminG)+"/log", f.adminG).Arr(), [][3]string{
		{"config", "op:root", ""},
		{"head", "user:bob", grantRef(t, f.issuerG)},
		{"tombstone", "user:root", grantRef(t, f.adminG)},
		{"batch", "user:bob", grantRef(t, f.issuerG)},
		{"config", "user:root", ""},
		{"branch", "user:bob", ""},
	})
	// New entries record their grant again.
	e2.create("sec", "n", map[string]any{}, f.adminG)
	lg := e2.get("/ns/sec/rev/"+e2.nsHead("sec", f.adminG)+"/log", f.adminG).Arr()
	if got := entryRef(t, lg[len(lg)-1]); got != grantRef(t, f.adminG) {
		t.Fatalf("new entry grant %q", got)
	}
}
