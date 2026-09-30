package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/seal"
)

// §G.5.2: remote branches of sealed (E2) and e2e (E3) namespaces.

// withRemoteIdentity makes B unwrap the base's keys with the private key
// *id points to (nil: none), read at each fetch.
func withRemoteIdentity(mu *sync.Mutex, id **ecdh.PrivateKey) func(*core.RemoteOptions) {
	return func(o *core.RemoteOptions) {
		inner := o.Resolve
		o.Resolve = func(origin string) (core.RemoteEndpoint, error) {
			ep, err := inner(origin)
			mu.Lock()
			ep.Identity = *id
			mu.Unlock()
			return ep, err
		}
	}
}

// A sealed base: B fetches with its own key pair and grant, mirrors the
// plaintext (ids over it), and serves it sealed under the branch's own
// epoch keys. The branch can't be less protected than the base.
func TestRemoteBranchSealed(t *testing.T) {
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := a.grant(kA, "user:root", []string{"s"}, allVerbs)
	x1 := a.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": encMarker})), root)
	x2 := a.wr("s", "x", x1, withNonce(ops(op("add", "/w", encMarker+"-2"))), root)
	y1 := a.wr("s", "y", "", withNonce(addRoot(map[string]any{"y": true})), root)
	at := a.nsHead("s", root)
	a.wr("s", "x", x2, withNonce(ops(op("add", "/late", true))), root) // after at

	// B's key pair; A's grant for B names its public key as enc, so A
	// wraps the keys to it (§E.2.3).
	bJWK, bPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var id *ecdh.PrivateKey
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"s"}, []string{"read", "export"}, map[string]any{"enc": bJWK})}
	path := filepath.Join(t.TempDir(), "b.db")
	b := newEnv(t, withOrigin(originB), withRemote(rt, withRemoteIdentity(&mu, &id)), withKeyStore(newKeyStore(t)), withEncTuning, withPath(path))

	sealed := map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}}
	// Without the identity, the wrapped keys can't be opened.
	r := b.mkRemote("rel", remoteGenesis("s", at, sealed))
	expectCode(t, r, 502, "remote")
	expect(t, b.get("/ns/rel"), 404)
	mu.Lock()
	id = bPriv
	mu.Unlock()
	// Less protected than the base: refused (§G.5.2).
	for name, doc := range map[string]map[string]any{
		"public":   {"read": "public"},
		"private":  {"read": "grant"},
		"at-rest":  {"read": "grant", "encryption": map[string]any{"level": "at-rest"}},
		"e2e":      {"read": "grant", "encryption": map[string]any{"level": "e2e"}},
		"pub-rest": {"read": "public", "encryption": map[string]any{"level": "at-rest"}},
	} {
		if r := b.mkRemote("rel", remoteGenesis("s", at, doc)); r.Code != 422 {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	expect(t, b.mkRemote("rel", remoteGenesis("s", at, sealed)), 201)
	// A sealed public branch of a sealed base is allowed: it only serves
	// ciphertext.
	expect(t, b.mkRemote("relpub", remoteGenesis("s", at, map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}})), 201)
	assertNoPlaintext(t, path)

	// Ids over plaintext, as at A.
	if h := b.head("rel", "x"); h != x2 {
		t.Fatalf("head %s, want %s", h, x2)
	}
	// Served sealed under the branch's own keys; A's key doesn't open it.
	bk, kr := b.keysOf("rel", nil, "")
	expect(t, kr, 200)
	ak, kr := a.keysOf("s", nil, a.grant(kA, "user:k", []string{"s"}, []string{"read"}))
	expect(t, kr, 200)
	if bk["rel#1"] == nil || ak["s#1"] == nil || string(bk["rel#1"]) == string(ak["s#1"]) {
		t.Fatalf("keys A %v B %v", ak, bk)
	}
	for _, c := range []struct{ name, id string }{{"x", x1}, {"x", x2}, {"y", y1}} {
		br := b.get("/r/rel/" + c.name + "/rev/" + c.id)
		expect(t, br, 200)
		if !isJOSE(br) {
			t.Fatalf("%s@%s is served in the clear", c.name, c.id)
		}
		pt := open(t, string(br.Body), resKey(t, bk["rel#1"], "rel", c.name), "rel#1", seal.ResourcePL("rel", c.name, c.id, "doc"))
		ar := a.get("/r/s/"+c.name+"/rev/"+c.id, root)
		want := open(t, string(ar.Body), resKey(t, ak["s#1"], "s", c.name), "s#1", seal.ResourcePL("s", c.name, c.id, "doc"))
		if string(pt) != string(want) {
			t.Fatalf("%s: plaintext differs", c.name)
		}
		if _, err := seal.OpenExpect(string(br.Body), resKey(t, ak["s#1"], "s", c.name), "rel#1", seal.ResourcePL("rel", c.name, c.id, "doc")); err == nil {
			t.Fatal("A's key opened B's copy")
		}
	}
	lg := b.get("/r/rel/x/rev/" + x2 + "/log").Arr()
	if len(lg) != 2 {
		t.Fatalf("log %v", lg)
	}
	open(t, lg[1].(string), resKey(t, bk["rel#1"], "rel", "x"), "rel#1", seal.ResourcePL("rel", "x", x2, "rev"))
	// The public sealed branch has keys of its own too.
	pk, _ := b.keysOf("relpub", nil, "")
	if pk["relpub#1"] == nil || string(pk["relpub#1"]) == string(bk["rel#1"]) {
		t.Fatalf("relpub keys %v", pk)
	}
	// B writes on the foreign parent, with a nonce, sealed under its keys.
	w := b.wr("rel", "x", x2, withNonce(ops(op("add", "/b", encMarker+"-b"))))
	open(t, string(b.get("/r/rel/x/rev/"+w).Body), resKey(t, bk["rel#1"], "rel", "x"), "rel#1", seal.ResourcePL("rel", "x", w, "doc"))
	assertNoPlaintext(t, path)

	// A accepts the registration: it can't check B's level (§G.5).
	expect(t, a.register("s", "rel", at, "", rt.bearer), 201)
	// A may become more protected with a registration outstanding.
	a.mkNS("p", map[string]any{"read": "grant", "keys": []any{kA.entry("*")}})
	pg := a.grant(kA, "user:root", []string{"p"}, allVerbs)
	expect(t, a.register("p", "relp", a.nsHead("p", pg), "", a.grant(kA, "svc:b", []string{"p"}, []string{"read", "export"})), 201)
	expect(t, a.patchNS("p", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), pg), 201)
}

// A remote branch of a plain base may be made sealed later: read-through
// content is then sealed under its own keys.
func TestRemoteBranchSealedLater(t *testing.T) {
	a, b, _ := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "grant"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("rb", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant"})), 201)
	expect(t, b.patchNS("rb", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	k, _ := b.keysOf("rb", nil, "")
	pt := open(t, string(b.get("/r/rb/x/rev/"+x).Body), resKey(t, k["rb#1"], "rb", "x"), "rb#1", seal.ResourcePL("rb", "x", x, "doc"))
	if v := jsonv.MustParse(pt).(map[string]any)["v"]; v != 1.0 {
		t.Fatalf("plaintext %s", pt)
	}
}

// foldCipher folds an e2e log answer with keys by kid, checking each sealed
// patch set against the kid's namespace (the base's, for read-through).
func foldCipher(t *testing.T, arr []any, name string, keys map[string][]byte) any {
	t.Helper()
	var doc any
	exists := false
	prev := ""
	for _, x := range arr {
		m := x.(map[string]any)
		parent, _ := m["parent"].(string)
		if parent != prev {
			t.Fatalf("chain: %v", m)
		}
		prev = m["id"].(string)
		if hashID(t, parent, canonical(m["patches"])) != prev && m["kind"] == "rev" {
			t.Fatalf("%s: id not over the ciphertext", prev)
		}
		if m["kind"] == "tombstone" {
			continue
		}
		jwe, ok := seal.SealedJWE(m["patches"])
		if !ok {
			t.Fatalf("not sealed: %v", m)
		}
		h, _ := seal.ParseHeader(jwe)
		kns, _, _ := seal.ParseKid(h.Kid)
		plain, err := seal.OpenPatchSet(m["patches"], keys[h.Kid], h.Kid, kns, name, parent)
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
	return doc
}

// An e2e base: B mirrors the ciphertext and the keyring verbatim, ids over
// the ciphertext verify, and B relays the base's wrapped keys (kid of the
// base's namespace) until the branch writes a keyring of its own.
func TestRemoteBranchE2E(t *testing.T) {
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA), withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("e", e2eDoc(map[string]any{"keys": []any{kA.entry("*")}}))
	adminG := a.grant(kA, "user:admin", []string{"e"}, allVerbs)
	readerJWK, readerPriv, _ := seal.GenerateRecipient()
	readerPub := readerPriv.PublicKey()
	k1, k2 := seal.NewKey(), seal.NewKey()
	kr, _ := seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{readerPub})
	krHead := a.create("e", "keyring", kr.Value(), adminG)
	d0 := etagOf(a.writeRaw("e", "d", "", sealed(t, k1, "e#1", "e", "d", "", addRoot(map[string]any{"n": 0.0, "t": encMarker})), adminG))
	// Rotate: keyring and epoch in one batch.
	if _, err := kr.Rotate(k2, []*ecdh.PublicKey{readerPub}); err != nil {
		t.Fatal(err)
	}
	r := a.do(req{method: "POST", path: "/ns/e/batch", bearer: adminG, body: map[string]any{
		"config": map[string]any{"ifMatch": a.configID("e", adminG), "patches": ops(op("add", "/encryption/epoch", 2.0))},
		"items":  []any{map[string]any{"resource": "keyring", "ifMatch": krHead, "steps": []any{ops(op("replace", "", kr.Value()))}}}}})
	expect(t, r, 201)
	d1 := etagOf(a.writeRaw("e", "d", d0, sealed(t, k2, "e#2", "e", "d", d0, ops(op("replace", "/n", 1.0))), adminG))
	at := a.nsHead("e", adminG)

	var bPriv ed25519.PrivateKey
	rt := &route{url: a.srv.URL, bearer: a.grant(kA, "svc:b", []string{"e"}, []string{"read"})}
	path := filepath.Join(t.TempDir(), "b.db")
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(rt), withKeyStore(newKeyStore(t)), withEncTuning, withPath(path))
	b.opPriv = bPriv
	kB := newKey("badmin")
	for name, enc := range map[string]any{"none": nil, "at-rest": "at-rest", "sealed": "sealed"} {
		doc := map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}
		if enc != nil {
			doc["encryption"] = map[string]any{"level": enc}
		}
		if r := b.mkRemote("rel", remoteGenesis("e", at, doc)); r.Code != 422 {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	expect(t, b.mkRemote("rel", remoteGenesis("e", at, e2eDoc(map[string]any{"read": "grant", "keys": []any{kB.entry("*")}}))), 201)
	bAdmin := b.grant(kB, "user:b", []string{"rel"}, allVerbs)

	// Ciphertext verbatim: the same entries, ids over the ciphertext.
	la := a.get("/r/e/d/rev/"+d1+"/log", adminG).Arr()
	lb := b.get("/r/rel/d/rev/"+d1+"/log", bAdmin).Arr()
	if len(la) != 2 || len(lb) != 2 {
		t.Fatalf("logs %v %v", la, lb)
	}
	for i := range la {
		ma, mb := la[i].(map[string]any), lb[i].(map[string]any)
		if ma["id"] != mb["id"] || string(canonical(ma["patches"])) != string(canonical(mb["patches"])) {
			t.Fatalf("entry %d differs", i)
		}
	}
	if r := b.get("/r/rel/d/rev/"+d1, bAdmin); r.Code != 302 || r.H.Get("X-E2E") != "fold" {
		t.Fatalf("read-through %d %v", r.Code, r.H)
	}
	mustEqual(t, foldCipher(t, lb, "d", map[string][]byte{"e#1": k1, "e#2": k2}), map[string]any{"n": 1.0, "t": encMarker})
	// The keyring reads as a document, and its wrapped keys are relayed
	// under the base's kids to the grant's enc.
	if d := b.doc("rel", "keyring", bAdmin); d["ns"] != "e" {
		t.Fatalf("keyring %v", d)
	}
	readerG := b.grant(kB, "user:reader", []string{"rel"}, []string{"read"}, map[string]any{"enc": readerJWK})
	keys, kr2 := b.keysOf("rel", nil, readerG)
	expect(t, kr2, 200)
	if _, ok := keys["e#1"]; !ok || len(keys) != 2 {
		t.Fatalf("relayed keys %v", keys)
	}
	for _, x := range kr2.Obj()["keys"].([]any) {
		w, err := seal.ParseWrappedKey(x)
		if err != nil {
			t.Fatal(err)
		}
		k, err := seal.UnwrapKey(readerPriv, w)
		want := map[string][]byte{"e#1": k1, "e#2": k2}[w.Kid]
		if err != nil || string(k) != string(want) {
			t.Fatalf("unwrap %s: %v", w.Kid, err)
		}
	}
	// The branch's own writes are sealed under its own keys and name.
	kb := seal.NewKey()
	expect(t, b.writeRaw("rel", "d", d1, sealed(t, kb, "e#2", "e", "d", d1, ops(op("add", "/x", 1.0))), bAdmin), 422)
	w := b.writeRaw("rel", "d", d1, sealed(t, kb, "rel#1", "rel", "d", d1, ops(op("add", "/x", 1.0))), bAdmin)
	expect(t, w, 201)
	if lg := b.get("/r/rel/d/rev/"+etagOf(w)+"/log", bAdmin).Arr(); len(lg) != 3 {
		t.Fatalf("log after the branch's write %v", lg)
	}
	// Nothing was decrypted on B.
	assertNoPlaintext(t, path)
	if strings.Contains(string(b.get("/r/rel/d/rev/"+d0+"/log", bAdmin).Body), encMarker) {
		t.Fatal("plaintext served")
	}
}

// History an e2e base pruned can't be mirrored: its horizon is a sealed
// snapshot.
func TestRemoteBranchE2EPruned(t *testing.T) {
	f := newE2E(t, withOrigin(originA), withArchive(t, t.TempDir()))
	a := f.tenv
	k1 := seal.NewKey()
	d0 := etagOf(a.writeRaw("e", "d", "", sealed(t, k1, "e#1", "e", "d", "", addRoot(map[string]any{"n": 0.0})), f.writerG))
	d1 := etagOf(a.writeRaw("e", "d", d0, sealed(t, k1, "e#1", "e", "d", d0, ops(op("replace", "/n", 1.0))), f.writerG))
	snap, err := seal.SealSnapshot(k1, "e#1", "e", "d", d1, map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	a.clock.Advance(10 * time.Minute)
	expect(t, a.prune("e", "d", map[string]any{"horizon": d1, "snapshot": snap}, f.writerG), 200)
	rt := &route{url: a.srv.URL, bearer: f.readerG}
	b := newEnv(t, withOrigin(originB), withRemote(rt), withKeyStore(newKeyStore(t)))
	expectCode(t, b.mkRemote("rel", remoteGenesis("e", a.nsHead("e", f.readerG), e2eDoc(map[string]any{"read": "grant"}))), 410, "pruned")
}
