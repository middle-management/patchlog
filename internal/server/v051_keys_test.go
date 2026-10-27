package server

import (
	"crypto/ecdh"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// §E.2.3, §C.5: POST /ns/{ns}/keys names the current epoch, the level and
// pad, which a writer limited to some resources needs to seal (§E.3.1) and
// can't read in the namespace document. Keys stay wrapped to the grant's
// enc, and the answer is no-store. At E3 the relay gives such a writer
// its own keyring entries without a read of the keyring (§E.3.2). A
// namespace that isn't sealed is 404 not_offered: there is nothing to
// seal.
func TestKeysLimitedWriter(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := seal.ParseRecipientJWK(jwk)
	only := func(names ...any) map[string]any {
		return map[string]any{"enc": jwk, "rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}}
	}
	rights := []string{"read", "create", "append"}
	answer := func(r *resp, epoch float64, level string, pad bool) {
		t.Helper()
		expect(t, r, 200)
		if r.H.Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control %q", r.H.Get("Cache-Control"))
		}
		o := r.Obj()
		if o["epoch"] != epoch || o["level"] != level || o["pad"] != pad {
			t.Fatalf("keys answer %s, want epoch %v, level %s, pad %v", r.Body, epoch, level, pad)
		}
	}

	// Plain and at rest: nothing to seal, for the limited writer as for
	// anyone, once the read check passes.
	for ns, doc := range map[string]map[string]any{
		"plain": {"read": "grant", "keys": []any{k.entry("*")}},
		"rest":  atRest(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}),
	} {
		e.mkNS(ns, doc)
		li := e.grant(k, "user:li", []string{ns}, rights, only("a"))
		if r := e.get("/ns/"+ns, li); r.Code != 403 && r.Code != 404 {
			t.Fatalf("%s: the limited writer reads the namespace: %d", ns, r.Code)
		}
		_, r := e.keysOf(ns, nil, li)
		expectCode(t, r, 404, "not_offered")
		if r.H.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control %q", ns, r.H.Get("Cache-Control"))
		}
		_, r = e.keysOf(ns, nil, e.grant(k, "user:r", []string{ns}, []string{"read"}))
		expectCode(t, r, 404, "not_offered")
		// The read check comes first.
		_, r = e.keysOf(ns, nil, e.grant(k, "user:w", []string{ns}, []string{"append"}))
		expectCode(t, r, 404, "not_found")
	}

	// Sealed (E2): per-resource keys, wrapped, with the epoch and pad.
	e.mkNS("s", map[string]any{"read": "grant", "keys": []any{k.entry("*")}, "encryption": map[string]any{"level": "sealed", "pad": true}})
	star := e.grant(k, "user:admin", []string{"s"}, []string{"read", "create", "append", "config"})
	li := e.grant(k, "user:li", []string{"s"}, rights, only("a"))
	_, r := e.keysOf("s", map[string]any{"resources": []any{"a", "b"}}, li)
	expectCode(t, r, 403, "forbidden") // b isn't fixed (v0.63 §E.2.3)
	keys, r := e.keysOf("s", map[string]any{"resources": []any{"a"}}, li)
	answer(r, 1, "sealed", true)
	if len(keys) != 1 || keys["s#1 a"] != nil {
		t.Fatalf("per-resource keys %s", r.Body)
	}
	w, err := seal.ParseWrappedKey(r.Obj()["keys"].([]any)[0])
	if err != nil {
		t.Fatal(err)
	}
	ka, err := seal.UnwrapKey(priv, w)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := e.keysOf("s", nil, e.grant(k, "user:r", []string{"s"}, []string{"read"}))
	if string(ka) != string(resKey(t, raw["s#1"], "s", "a")) {
		t.Fatal("the wrapped key isn't K_a")
	}
	// Without resources: no keys, and still what sealing needs.
	keys, r = e.keysOf("s", map[string]any{"epochs": []any{}}, li)
	answer(r, 1, "sealed", true)
	if len(keys) != 0 {
		t.Fatalf("keys without resources %s", r.Body)
	}
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0), op("add", "/encryption/pad", false)), star), 201)
	_, r = e.keysOf("s", nil, li)
	answer(r, 2, "sealed", false)

	// E3: the server only relays what a key holder wrapped to the grant's
	// enc, so a writer limited to some resources gets its own entries with
	// the epoch and pad, without reading the keyring. A grant without enc
	// is 422, and one whose rules refuse every read 404.
	e.mkNS("x", map[string]any{"read": "grant", "keys": []any{k.entry("*")}, "encryption": map[string]any{"level": "e2e", "pad": true}})
	k1 := seal.NewKey()
	_, admin, _ := seal.GenerateRecipient()
	kr, err := seal.BuildKeyringV2(admin, "x", 1, k1, []*ecdh.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	e.create("x", "keyring", kr.Value(), e.grant(k, "user:admin", []string{"x"}, []string{"read", "create"}))
	li = e.grant(k, "user:li", []string{"x"}, rights, only("a"))
	if r := e.get("/r/x/keyring", li); r.Code != 404 {
		t.Fatalf("the limited writer reads the keyring: %d", r.Code)
	}
	keys, r = e.keysOf("x", nil, li)
	answer(r, 1, "e2e", true)
	if len(keys) != 1 {
		t.Fatalf("e2e keys %s", r.Body)
	}
	if w, err = seal.ParseWrappedKey(r.Obj()["keys"].([]any)[0]); err != nil || w.Kid != "x#1" || w.From != seal.Thumbprint(admin.PublicKey()) {
		t.Fatalf("wrapped %v %v", w, err)
	}
	if got, err := seal.UnwrapKeyAuth(priv, admin.PublicKey(), w); err != nil || string(got) != string(k1) {
		t.Fatalf("unwrap %v", err)
	}
	keys, r = e.keysOf("x", map[string]any{"epochs": []any{}}, li)
	answer(r, 1, "e2e", true)
	if len(keys) != 0 {
		t.Fatalf("e2e keys without epochs %s", r.Body)
	}
	noEnc := map[string]any{"rules": only("a")["rules"]}
	_, r = e.keysOf("x", nil, e.grant(k, "user:li", []string{"x"}, rights, noEnc))
	expectCode(t, r, 422, "invalid")
	refuses := map[string]any{"enc": jwk, "rules": []any{map[string]any{"op": "test", "path": "/action", "value": "append"}}}
	_, r = e.keysOf("x", nil, e.grant(k, "user:w", []string{"x"}, rights, refuses))
	expectCode(t, r, 404, "not_found")
}
