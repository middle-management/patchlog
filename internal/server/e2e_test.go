package server

import (
	"context"
	"crypto/ecdh"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/seal"
)

// End-to-end namespaces (Addendum E, level E3).

func e2eDoc(doc map[string]any) map[string]any {
	doc["encryption"] = map[string]any{"level": "e2e"}
	return doc
}

// e2eFixture is an e2e namespace "e" with an admin (* key), a writer key
// and a reader recipient.
type e2eFixture struct {
	*tenv
	path          string
	admin, writer keyPair
	adminG        string // * grant
	writerG       string // read, create, append, restore, delete, prune
	readerPriv    *ecdh.PrivateKey
	readerJWK     map[string]any
	readerG       string // read, with enc
	k1            []byte
}

func newE2E(t *testing.T, opts ...envOpt) *e2eFixture {
	path := filepath.Join(t.TempDir(), "e2e.db")
	base := []envOpt{withKeyStore(newKeyStore(t)), withEncTuning, withPath(path), withoutRetentionLoop}
	e := newAuthEnv(t, append(base, opts...)...)
	f := &e2eFixture{tenv: e, path: path, admin: newKey("admin"), writer: newKey("writer")}
	e.mkNS("e", e2eDoc(map[string]any{"keys": []any{f.admin.entry("*"), f.writer.entry("read", "create", "append", "restore", "delete", "prune")}}))
	f.adminG = e.grant(f.admin, "user:admin", []string{"e"}, allVerbs)
	f.writerG = e.grant(f.writer, "user:writer", []string{"e"}, []string{"read", "create", "append", "restore", "delete", "prune"})
	var err error
	f.readerJWK, f.readerPriv, err = seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	f.readerG = e.grant(f.writer, "user:reader", []string{"e"}, []string{"read"}, map[string]any{"enc": f.readerJWK})
	return f
}

// sealed seals patches for ns/name on parent under kid.
func sealed(t *testing.T, key []byte, kid, ns, name, parent string, patches []any) string {
	t.Helper()
	b, err := seal.SealPatchSet(key, kid, ns, name, parent, jsonv.FromGo(patches))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeRaw sends a raw patch set (parent "" creates).
func (e *tenv) writeRaw(ns, name, parent, raw, bearer string) *resp {
	e.t.Helper()
	q := req{method: "PATCH", path: "/r/" + ns + "/" + name, ifMatch: parent, raw: raw, hasRaw: true, ct: "application/json-patch+json", bearer: bearer}
	if parent == "" {
		q.ifNoneMatch = "*"
	}
	return e.do(q)
}

// fold follows the fold redirect of ns/name@id and folds the log with
// keys (by kid), returning the document.
func (f *e2eFixture) fold(ns, name, id string, keys map[string][]byte, bearer string) any {
	t := f.t
	t.Helper()
	r := f.get("/r/"+ns+"/"+name+"/rev/"+id, bearer)
	expect(t, r, 302)
	if r.H.Get("X-E2E") != "fold" || !strings.HasPrefix(r.H.Get("Cache-Control"), "public") {
		t.Fatalf("fold headers %v", r.H)
	}
	loc := r.H.Get("Location")
	u, _ := url.Parse(loc)
	since := u.Query().Get("since")
	if u.Path != "/r/"+ns+"/"+name+"/rev/"+id+"/log" {
		t.Fatalf("location %s", loc)
	}
	r = f.get(loc, bearer)
	expect(t, r, 200)
	arr := r.Arr()
	var doc any
	exists := false
	prev := ""
	if since != "" {
		m := arr[0].(map[string]any)
		if m["kind"] != "snapshot" || m["id"] != since {
			t.Fatalf("no snapshot first: %v", m)
		}
		jwe := m["snapshot"].(string)
		h, _ := seal.ParseHeader(jwe)
		d, err := seal.OpenSnapshot(jwe, keys[h.Kid], h.Kid, ns, name, since)
		if err != nil {
			t.Fatal(err)
		}
		doc, exists, prev = d, true, since
		arr = arr[1:]
	}
	for _, x := range arr {
		m := x.(map[string]any)
		parent, _ := m["parent"].(string)
		if parent != prev {
			t.Fatalf("chain: %v", m)
		}
		prev = m["id"].(string)
		if m["kind"] == "tombstone" {
			continue
		}
		ps := m["patches"]
		if a, ok := ps.([]any); ok && len(a) == 0 {
			continue
		}
		jwe, ok := seal.SealedJWE(ps)
		if !ok {
			t.Fatalf("not sealed: %v", ps)
		}
		h, _ := seal.ParseHeader(jwe)
		plain, err := seal.OpenPatchSet(ps, keys[h.Kid], h.Kid, ns, name, parent)
		if err != nil {
			t.Fatal(err)
		}
		o, err := patch.Parse(plain)
		if err != nil {
			t.Fatal(err)
		}
		if doc, _, err = patch.Apply(doc, exists, o, patch.Options{}); err != nil {
			t.Fatal(err)
		}
		exists = true
	}
	if prev != id {
		t.Fatalf("log ends at %s, not %s", prev, id)
	}
	return doc
}

func mustEqual(t *testing.T, got, want any) {
	t.Helper()
	if !jsonv.Equal(jsonv.FromGo(got), jsonv.FromGo(want)) {
		t.Fatalf("got %s, want %s", jsonv.Canonical(jsonv.FromGo(got)), jsonv.Canonical(jsonv.FromGo(want)))
	}
}

func TestE2EGateAndReads(t *testing.T) {
	f := newE2E(t)
	e := f.tenv
	adminPub := newRecipient(t)
	f.k1 = seal.NewKey()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)

	// The keyring: plaintext, checked as a keyring of this namespace.
	kr, err := seal.BuildKeyring("e", 1, f.k1, []*ecdh.PublicKey{adminPub, readerPub})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := seal.BuildKeyring("x", 1, f.k1, []*ecdh.PublicKey{adminPub})
	expectCode(t, e.write("PATCH", "e", "keyring", "", addRoot(other.Value()), f.adminG), 422, "invalid")
	ahead, _ := seal.BuildKeyring("e", 2, f.k1, []*ecdh.PublicKey{adminPub})
	expectCode(t, e.write("PATCH", "e", "keyring", "", addRoot(ahead.Value()), f.adminG), 422, "invalid")
	expectCode(t, e.write("PATCH", "e", "keyring", "", addRoot(map[string]any{"v": 1.0}), f.adminG), 422, "invalid")
	expectCode(t, e.writeRaw("e", "keyring", "", sealed(t, f.k1, "e#1", "e", "keyring", "", addRoot(kr.Value())), f.adminG), 422, "invalid")
	krID := e.create("e", "keyring", kr.Value(), f.adminG)
	if d := e.doc("e", "keyring", f.readerG); d["ns"] != "e" {
		t.Fatalf("keyring doc %v", d)
	}

	// POST /keys relays the reader's wrapped key only.
	keys, r := e.keysOf("e", nil, f.readerG)
	if r == nil || len(keys) != 1 {
		t.Fatalf("keys %v %v", keys, r)
	}
	w, err := seal.ParseWrappedKey(r.Obj()["keys"].([]any)[0])
	if err != nil || w.Kid != "e#1" {
		t.Fatalf("wrapped %v %v", w, err)
	}
	if k, err := seal.UnwrapKey(f.readerPriv, w); err != nil || string(k) != string(f.k1) {
		t.Fatalf("unwrap %v", err)
	}
	_, r = e.keysOf("e", nil, e.grant(f.writer, "user:noenc", []string{"e"}, []string{"read"}))
	expectCode(t, r, 422, "invalid")
	_, r = e.keysOf("e", nil, e.grant(f.writer, "user:nonreader", []string{"e"}, []string{"create"}, map[string]any{"enc": f.readerJWK}))
	expect(t, r, 404)

	// Sealed create, append, delete, restore; ids over ciphertext.
	s0 := sealed(t, f.k1, "e#1", "e", "d", "", addRoot(map[string]any{"title": encMarker, "n": 0.0}))
	r = e.writeRaw("e", "d", "", s0, f.writerG)
	expect(t, r, 201)
	d0 := etagOf(r)
	if d0 != hashID(t, "", canonical(jsonv.MustParse([]byte(s0)))) {
		t.Fatal("id not over the ciphertext")
	}
	// Idempotent retry with the same bytes.
	expect(t, e.writeRaw("e", "d", "", s0, f.writerG), 200)
	s1 := sealed(t, f.k1, "e#1", "e", "d", d0, ops(op("replace", "/n", 1.0), op("add", "/body", encMarker+"-body")))
	d1 := etagOf(e.writeRaw("e", "d", d0, s1, f.writerG))
	expect(t, e.writeRaw("e", "d", d0, s1, f.writerG), 200)
	want := map[string]any{"title": encMarker, "n": 1.0, "body": encMarker + "-body"}
	mustEqual(t, f.fold("e", "d", d1, map[string][]byte{"e#1": f.k1}, f.readerG), want)
	mustEqual(t, f.fold("e", "d", d0, map[string][]byte{"e#1": f.k1}, f.readerG), map[string]any{"title": encMarker, "n": 0.0})
	t1 := e.del("e", "d", d1, f.writerG)
	expectCode(t, e.get("/r/e/d/rev/"+t1, f.readerG), 410, "gone")
	d2 := etagOf(e.writeRaw("e", "d", t1, "[]", f.writerG))
	mustEqual(t, f.fold("e", "d", d2, map[string][]byte{"e#1": f.k1}, f.readerG), want)
	t2 := e.del("e", "d", d2, f.writerG)
	d3 := etagOf(e.writeRaw("e", "d", t2, sealed(t, f.k1, "e#1", "e", "d", t2, ops(op("add", "/restored", true))), f.writerG))
	want["restored"] = true
	mustEqual(t, f.fold("e", "d", d3, map[string][]byte{"e#1": f.k1}, f.readerG), want)
	// The keyring still reads as a document; content never does.
	if r := e.get("/r/e/keyring/rev/"+krID, f.readerG); r.Code != 200 || r.H.Get("X-E2E") != "" {
		t.Fatalf("keyring read %d", r.Code)
	}

	// Refused patch sets.
	expectCode(t, e.write("PATCH", "e", "d", d3, ops(op("add", "/x", 1.0)), f.writerG), 422, "invalid")
	expectCode(t, e.write("PATCH", "e", "p", "", addRoot(map[string]any{}), f.writerG), 422, "invalid")
	for name, raw := range map[string]string{
		"other name":   sealed(t, f.k1, "e#1", "e", "other", d3, ops(op("add", "/x", 1.0))),
		"other parent": sealed(t, f.k1, "e#1", "e", "d", d2, ops(op("add", "/x", 1.0))),
		"other ns":     sealed(t, f.k1, "e#1", "x", "d", d3, ops(op("add", "/x", 1.0))),
		"kid ns":       sealed(t, f.k1, "x#1", "e", "d", d3, ops(op("add", "/x", 1.0))),
		"epoch 2":      sealed(t, f.k1, "e#2", "e", "d", d3, ops(op("add", "/x", 1.0))),
		"epoch 0":      sealed(t, f.k1, "e#0", "e", "d", d3, ops(op("add", "/x", 1.0))),
		"two ops":      `[{"op":"sealed","value":"a.b.c.d.e"},{"op":"sealed","value":"a.b.c.d.e"}]`,
		"not a jwe":    `[{"op":"sealed","value":"nope"}]`,
	} {
		if r := e.writeRaw("e", "d", d3, raw, f.writerG); r.Code != 422 {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	// Genesis binds parent "".
	expect(t, e.writeRaw("e", "g", "", sealed(t, f.k1, "e#1", "e", "g", d3, addRoot(map[string]any{})), f.writerG), 422)

	// Batches: the same gate per item.
	s := sealed(t, f.k1, "e#1", "e", "b", "", addRoot(map[string]any{"b": encMarker}))
	r = e.do(req{method: "POST", path: "/ns/e/batch", bearer: f.writerG, body: map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{jsonv.MustParse([]byte(s))}}}}})
	expect(t, r, 201)
	r = e.do(req{method: "POST", path: "/ns/e/batch", bearer: f.writerG, body: map[string]any{"items": []any{
		map[string]any{"resource": "b2", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}})
	expectCode(t, r, 422, "batch")

	// Namespace rules on /doc or writes fail every sealed write; rules on
	// /action and /principal still work; deletes are checked as usual.
	docRule := map[string]any{"if": []any{map[string]any{"op": "test", "path": "/action", "value": "append"}},
		"then": []any{map[string]any{"op": "test", "path": "/doc/n", "exists": true}}}
	expect(t, e.patchNS("e", ops(op("add", "/rules", []any{docRule})), f.adminG), 201)
	for _, raw := range []string{
		sealed(t, f.k1, "e#1", "e", "d", d3, ops(op("add", "/x", 1.0))),
	} {
		r := e.writeRaw("e", "d", d3, raw, f.writerG)
		expectCode(t, r, 422, "rule")
	}
	expectCode(t, e.writeRaw("e", "n1", "", sealed(t, f.k1, "e#1", "e", "n1", "", addRoot(map[string]any{})), f.writerG), 422, "rule")
	writesRule := map[string]any{"not": map[string]any{"op": "writes", "covers": ""}}
	expect(t, e.patchNS("e", ops(op("replace", "/rules", []any{writesRule})), f.adminG), 201)
	expectCode(t, e.writeRaw("e", "d", d3, sealed(t, f.k1, "e#1", "e", "d", d3, ops(op("add", "/x", 1.0))), f.writerG), 422, "rule")
	actionRule := map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"create", "append", "restore", "delete", "config"}}}
	principalRule := map[string]any{"op": "test", "path": "/principal/id", "schema": map[string]any{"pattern": "^user:"}}
	expect(t, e.patchNS("e", ops(op("replace", "/rules", []any{actionRule, principalRule})), f.adminG), 201)
	r = e.writeRaw("e", "d", d3, sealed(t, f.k1, "e#1", "e", "d", d3, ops(op("add", "/x", 1.0))), f.writerG)
	expect(t, r, 201)
	d4 := etagOf(r)
	// A /doc rule doesn't block deletes: they are checked as usual (doc null).
	expect(t, e.patchNS("e", ops(op("replace", "/rules", []any{docRule})), f.adminG), 201)
	e.del("e", "b", e.head("e", "b", f.readerG), f.writerG)
	expect(t, e.patchNS("e", ops(op("remove", "/rules")), f.adminG), 201)

	// Grant rules reading writes: 403; rules on /resource still apply.
	within := e.grant(f.writer, "user:w2", []string{"e"}, []string{"read", "append"}, map[string]any{"rules": []any{map[string]any{"op": "writes", "within": []any{"/i18n"}}}})
	expectCode(t, e.writeRaw("e", "d", d4, sealed(t, f.k1, "e#1", "e", "d", d4, ops(op("add", "/i18n", 1.0))), within), 403, "forbidden")
	onlyD := e.grant(f.writer, "user:w3", []string{"e"}, []string{"read", "append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "d"}}})
	d5 := etagOf(e.writeRaw("e", "d", d4, sealed(t, f.k1, "e#1", "e", "d", d4, ops(op("add", "/y", 1.0))), onlyD))
	if d5 == "" {
		t.Fatal("resource-scoped append")
	}
	want["x"], want["y"] = 1.0, 1.0
	mustEqual(t, f.fold("e", "d", d5, map[string][]byte{"e#1": f.k1}, f.readerG), want)

	// Nothing of the content is stored in plaintext.
	e.close()
	assertNoPlaintext(t, f.path)
	if n := queryInt(t, f.path, `SELECT COUNT(*) FROM heads h JOIN resources r ON r.res = h.res WHERE r.name != 'keyring'`); n != 0 {
		t.Fatalf("%d head documents", n)
	}
	if n := queryInt(t, f.path, `SELECT COUNT(*) FROM snapshots`); n != 0 {
		t.Fatalf("%d snapshots", n)
	}
}

func newRecipient(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	return priv.PublicKey()
}

func TestE2EPruneRetention(t *testing.T) {
	dir := t.TempDir()
	f := newE2E(t, withArchive(t, dir))
	e := f.tenv
	k := seal.NewKey()
	keys := map[string][]byte{"e#1": k}
	ids := []string{etagOf(e.writeRaw("e", "p", "", sealed(t, k, "e#1", "e", "p", "", addRoot(map[string]any{"n": 0.0})), f.writerG))}
	for i := 1; i < 6; i++ {
		ids = append(ids, etagOf(e.writeRaw("e", "p", ids[i-1], sealed(t, k, "e#1", "e", "p", ids[i-1], ops(op("replace", "/n", float64(i)))), f.writerG)))
	}
	e.clock.Advance(10 * time.Minute)
	h := ids[3]
	snap, err := seal.SealSnapshot(k, "e#1", "e", "p", h, map[string]any{"n": 3.0})
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, e.prune("e", "p", map[string]any{"horizon": h}, f.writerG), 422, "invalid")
	expectCode(t, e.prune("e", "p", map[string]any{"horizon": h, "snapshot": snap, "keep": []any{ids[1]}}, f.writerG), 422, "invalid")
	wrong, _ := seal.SealSnapshot(k, "e#1", "e", "p", ids[2], map[string]any{"n": 2.0})
	expectCode(t, e.prune("e", "p", map[string]any{"horizon": h, "snapshot": wrong}, f.writerG), 422, "invalid")
	r := e.prune("e", "p", map[string]any{"horizon": h, "snapshot": snap}, f.writerG)
	expect(t, r, 200)
	if r.Str("horizon") != h || r.Str("archive") == "" {
		t.Fatalf("prune %s", r.Body)
	}
	expectCode(t, e.get("/r/e/p/rev/"+ids[1], f.readerG), 410, "pruned")
	mustEqual(t, f.fold("e", "p", ids[5], keys, f.readerG), map[string]any{"n": 5.0})
	mustEqual(t, f.fold("e", "p", h, keys, f.readerG), map[string]any{"n": 3.0})
	// A log from genesis crosses the horizon.
	expectCode(t, e.get("/r/e/p/rev/"+ids[5]+"/log", f.readerG), 410, "pruned")

	// Snapshots are refused where the server computes documents.
	e.mkNS("plain", map[string]any{"keys": []any{f.admin.entry("*")}})
	ag := e.grant(f.admin, "user:admin", []string{"plain"}, allVerbs)
	pids := e.chain("plain", "x", 3, ag)
	e.clock.Advance(10 * time.Minute)
	expectCode(t, e.prune("plain", "x", map[string]any{"horizon": pids[2], "snapshot": snap}, ag), 422, "invalid")

	// Retention skips e2e namespaces.
	expect(t, e.patchNS("e", ops(op("add", "/retention", []any{map[string]any{"keep": map[string]any{"revisions": 1.0}}})), f.adminG), 201)
	for i := 6; i < 9; i++ {
		ids = append(ids, etagOf(e.writeRaw("e", "p", ids[i-1], sealed(t, k, "e#1", "e", "p", ids[i-1], ops(op("replace", "/n", float64(i)))), f.writerG)))
	}
	e.clock.Advance(10 * time.Minute)
	rep, err := e.e.ApplyRetention(context.Background())
	if err != nil || rep.Checked != 0 || rep.Pruned != 0 {
		t.Fatalf("retention %+v %v", rep, err)
	}
	mustEqual(t, f.fold("e", "p", ids[8], keys, f.readerG), map[string]any{"n": 8.0})

	// Without an archive, an e2e prune is refused even with a * key.
	g := newE2E(t)
	gk := seal.NewKey()
	g0 := etagOf(g.writeRaw("e", "p", "", sealed(t, gk, "e#1", "e", "p", "", addRoot(map[string]any{"n": 0.0})), g.writerG))
	g1 := etagOf(g.writeRaw("e", "p", g0, sealed(t, gk, "e#1", "e", "p", g0, ops(op("replace", "/n", 1.0))), g.writerG))
	g.clock.Advance(10 * time.Minute)
	gs, _ := seal.SealSnapshot(gk, "e#1", "e", "p", g1, map[string]any{"n": 1.0})
	expectCode(t, g.prune("e", "p", map[string]any{"horizon": g1, "snapshot": gs}, g.adminG), 422, "invalid")
}

func TestE2EEpochsBranchesLevels(t *testing.T) {
	f := newE2E(t)
	e := f.tenv
	adminPriv := func() *ecdh.PrivateKey { _, p, _ := seal.GenerateRecipient(); return p }()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	k1 := seal.NewKey()
	kr, _ := seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{adminPriv.PublicKey(), readerPub})
	krHead := e.create("e", "keyring", kr.Value(), f.adminG)
	d0 := etagOf(e.writeRaw("e", "d", "", sealed(t, k1, "e#1", "e", "d", "", addRoot(map[string]any{"n": 0.0})), f.writerG))

	// Rotation: a keyring ahead of the epoch is refused alone, and goes
	// with the epoch bump in one batch; the removed reader gets nothing of
	// the new epoch.
	k2 := seal.NewKey()
	if _, err := kr.Rotate(k2, []*ecdh.PublicKey{adminPriv.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	replace := ops(op("replace", "", kr.Value()))
	expectCode(t, e.write("PATCH", "e", "keyring", krHead, replace, f.adminG), 422, "invalid")
	r := e.do(req{method: "POST", path: "/ns/e/batch", bearer: f.adminG, body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("e", f.adminG), "patches": ops(op("add", "/encryption/epoch", 2.0))},
		"items":  []any{map[string]any{"resource": "keyring", "ifMatch": krHead, "steps": []any{replace}}}}})
	expect(t, r, 201)
	// Epochs may only move by one.
	expectCode(t, e.patchNS("e", ops(op("replace", "/encryption/epoch", 4.0)), f.adminG), 422, "invalid")
	keys, _ := e.keysOf("e", nil, f.readerG)
	if _, ok := keys["e#1"]; !ok || len(keys) != 1 {
		t.Fatalf("removed reader keys %v", keys)
	}
	adminEnc := e.grant(f.admin, "user:admin", []string{"e"}, []string{"read"}, map[string]any{"enc": seal.RecipientJWK(adminPriv.PublicKey())})
	keys, _ = e.keysOf("e", nil, adminEnc)
	if len(keys) != 2 {
		t.Fatalf("admin keys %v", keys)
	}
	keys, _ = e.keysOf("e", map[string]any{"epochs": []any{2.0}}, adminEnc)
	if _, ok := keys["e#2"]; !ok || len(keys) != 1 {
		t.Fatalf("admin epoch 2 %v", keys)
	}
	d1 := etagOf(e.writeRaw("e", "d", d0, sealed(t, k2, "e#2", "e", "d", d0, ops(op("replace", "/n", 1.0))), f.writerG))
	expect(t, e.writeRaw("e", "d", d1, sealed(t, k2, "e#3", "e", "d", d1, ops(op("replace", "/n", 2.0))), f.writerG), 422)
	mustEqual(t, f.fold("e", "d", d1, map[string][]byte{"e#1": k1, "e#2": k2}, f.readerG), map[string]any{"n": 1.0})

	// A branch of an e2e base is e2e, with its own epochs from the copied
	// one; its first write binds the foreign parent.
	expectCode(t, e.branch("e", map[string]any{"name": "low", "patches": ops(op("replace", "/encryption", map[string]any{"level": "sealed"}))}, f.adminG), 422, "invalid")
	expect(t, e.branch("e", map[string]any{"name": "eb"}, f.adminG), 201)
	bg := e.grant(f.writer, "user:writer", []string{"eb"}, []string{"read", "append"})
	expectCode(t, e.write("PATCH", "eb", "d", d1, ops(op("add", "/x", 1.0)), bg), 422, "invalid")
	expect(t, e.writeRaw("eb", "d", d1, sealed(t, k2, "eb#1", "eb", "d", d1, ops(op("add", "/x", 1.0))), bg), 422)
	expect(t, e.writeRaw("eb", "d", d1, sealed(t, k2, "e#2", "e", "d", d1, ops(op("add", "/x", 1.0))), bg), 422)
	kb := seal.NewKey()
	b1 := etagOf(e.writeRaw("eb", "d", d1, sealed(t, kb, "eb#2", "eb", "d", d1, ops(op("add", "/x", 1.0))), bg))
	if r := e.get("/r/eb/d/rev/"+d1, bg); r.Code != 302 || r.H.Get("X-E2E") != "fold" {
		t.Fatalf("read-through fold %d", r.Code)
	}
	r = e.get("/r/eb/d/rev/"+b1+"/log", bg)
	expect(t, r, 200)
	if len(r.Arr()) != 3 {
		t.Fatalf("branch log %s", r.Body)
	}

	// Levels: e2e only from the start.
	e.mkNS("ar", atRest(map[string]any{"keys": []any{f.admin.entry("*")}}))
	arG := e.grant(f.admin, "user:admin", []string{"ar"}, allVerbs)
	expectCode(t, e.patchNS("ar", ops(op("replace", "/encryption", map[string]any{"level": "e2e"})), arG), 422, "invalid")
	e.mkNS("pl", map[string]any{"keys": []any{f.admin.entry("*")}})
	plG := e.grant(f.admin, "user:admin", []string{"pl"}, allVerbs)
	expectCode(t, e.branch("pl", map[string]any{"name": "plb", "patches": ops(op("add", "/encryption", map[string]any{"level": "e2e"}))}, plG), 422, "invalid")
	expectCode(t, e.patchNS("e", ops(op("replace", "/encryption", map[string]any{"level": "sealed", "epoch": 2.0})), f.adminG), 422, "invalid")

	// Remote branches of an e2e namespace are refused.
	exp := e.grant(f.admin, "user:admin", []string{"e"}, []string{"read", "export"})
	expectCode(t, e.register("e", "rel", e.nsHead("e", exp), "", exp), 422, "invalid")
}
