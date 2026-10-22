package server

import (
	"crypto/ecdh"
	"sort"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// keyEntries returns the entries of a 200 POST /ns/{ns}/keys answer.
func keyEntries(t *testing.T, r *resp) []map[string]any {
	t.Helper()
	expect(t, r, 200)
	var out []map[string]any
	for _, x := range r.Obj()["keys"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// P18, ENC-8 (§E.2.3): /keys entries are { kid, name?, from?, wrapped },
// or at E2 { kid, name?, key } for a grant without enc: name for a K_r,
// and no suite or resource member.
func TestV073KeysEntryShape(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", map[string]any{"read": "grant", "keys": []any{k.entry("*")}, "encryption": map[string]any{"level": "sealed"}})
	jwk, _, _ := seal.GenerateRecipient()
	fixA := []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}
	for name, c := range map[string]struct {
		extra   map[string]any
		members []string
	}{
		"K_r raw":     {map[string]any{"rules": fixA}, []string{"key", "kid", "name"}},
		"K_r wrapped": {map[string]any{"rules": fixA, "enc": jwk}, []string{"kid", "name", "wrapped"}},
		"K_e raw":     {nil, []string{"key", "kid"}},
		"K_e wrapped": {map[string]any{"enc": jwk}, []string{"kid", "wrapped"}},
	} {
		var extra []map[string]any
		if c.extra != nil {
			extra = append(extra, c.extra)
		}
		g := e.grant(k, "user:r", []string{"s"}, []string{"read"}, extra...)
		_, r := e.keysOf("s", map[string]any{"resources": []any{"a"}}, g)
		entries := keyEntries(t, r)
		if len(entries) != 1 {
			t.Fatalf("%s: %s", name, r.Body)
		}
		var got []string
		for m := range entries[0] {
			got = append(got, m)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(c.members, ",") {
			t.Errorf("%s: members %v, want %v (%s)", name, got, c.members, r.Body)
		}
		if n, ok := entries[0]["name"]; ok && n != "a" {
			t.Errorf("%s: name %v", name, n)
		}
	}
}

// P18, ENC-11 (§E.3.2): the keyring document is { "keys": [{ kid, to,
// from, wrapped }] } with nothing else but a $nonce, entries of exactly
// those members, no two for one kid and to, kids of this namespace and
// epochs not after encryption.epoch; written in plaintext, checked as
// outside E3. A keyring in the format before v0.63 is refused.
func TestV073KeyringDocument(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	_, admin, _ := seal.GenerateRecipient()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	k1 := seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{admin.PublicKey(), readerPub})
	if err != nil {
		t.Fatal(err)
	}
	good := kr.Value()
	entry := func(i int) map[string]any {
		m := map[string]any{}
		for k, v := range good["keys"].([]any)[i].(map[string]any) {
			m[k] = v
		}
		return m
	}
	legacy, _ := seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{readerPub})
	other, _ := seal.BuildKeyringV2(admin, "x", 1, k1, []*ecdh.PublicKey{readerPub})
	ahead, _ := seal.BuildKeyringV2(admin, "e", 2, k1, []*ecdh.PublicKey{readerPub})
	withSuite := entry(0)
	withSuite["suite"] = seal.Suite
	noFrom := entry(0)
	delete(noFrom, "from")
	badTo := entry(0)
	badTo["to"] = seal.RecipientID(readerPub)
	for name, doc := range map[string]any{
		"format before v0.63": legacy.Value(),
		"another member":      map[string]any{"keys": good["keys"], "ns": "e"},
		"entry with a suite":  map[string]any{"keys": []any{withSuite}},
		"entry without from":  map[string]any{"keys": []any{noFrom}},
		"to a recipient id":   map[string]any{"keys": []any{badTo}},
		"two for one kid, to": map[string]any{"keys": []any{entry(0), entry(0)}},
		"kid of another ns":   other.Value(),
		"epoch after epoch":   ahead.Value(),
		"keys not an array":   map[string]any{"keys": map[string]any{}},
		"no keys":             map[string]any{"$nonce": seal.NewNonce()},
		"$nonce not a string": map[string]any{"keys": good["keys"], "$nonce": 1.0},
		"wrapped not a key":   map[string]any{"keys": []any{map[string]any{"kid": "e#1", "to": entry(0)["to"], "from": entry(0)["from"], "wrapped": "AAAA"}}},
	} {
		r := e.write("PATCH", "e", "keyring", "", addRoot(doc), f.adminG)
		if r.Code != 422 || r.Str("code") != "invalid" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
		if name == "format before v0.63" && !strings.Contains(r.Str("message"), "before v0.63") {
			t.Errorf("legacy: %s", r.Body)
		}
	}
	// Two entries for one kid and different recipients, with a $nonce.
	withNonce := map[string]any{"keys": good["keys"], "$nonce": seal.NewNonce()}
	krID := e.create("e", "keyring", withNonce, f.adminG)
	// Plaintext: read as a document, not folded.
	if r := e.get("/r/e/keyring/rev/"+krID, f.readerG); r.Code != 200 || r.H.Get("X-E2E") != "" || r.Obj()["$nonce"] == nil {
		t.Fatalf("keyring read %d %v %s", r.Code, r.H, r.Body)
	}
	// Appending an old-format keyring onto it is refused too.
	expectCode(t, e.write("PATCH", "e", "keyring", krID, ops(op("replace", "", legacy.Value())), f.adminG), 422, "invalid")
}

// P18, ENC-9 and ENC-11 (§E.2.3, §E.3.2): /keys relays the keyring
// entries whose to is the RFC 7638 thumbprint of the grant's enc, with
// their from; a grant whose enc no entry names gets none.
func TestV073KeysRelayByThumbprint(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	_, admin, _ := seal.GenerateRecipient()
	otherJWK, other, _ := seal.GenerateRecipient()
	strangerJWK, _, _ := seal.GenerateRecipient()
	k1 := seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{f.readerPriv.PublicKey(), other.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	e.create("e", "keyring", kr.Value(), f.adminG)
	for _, c := range []struct {
		jwk  map[string]any
		priv *ecdh.PrivateKey
	}{{f.readerJWK, f.readerPriv}, {otherJWK, other}} {
		g := e.grant(f.writer, "user:r", []string{"e"}, []string{"read"}, map[string]any{"enc": c.jwk})
		_, r := e.keysOf("e", nil, g)
		entries := keyEntries(t, r)
		if len(entries) != 1 {
			t.Fatalf("relayed %s", r.Body)
		}
		w, err := seal.ParseWrappedKey(entries[0])
		if err != nil {
			t.Fatal(err)
		}
		want, _ := kr.Entry("e#1", seal.Thumbprint(c.priv.PublicKey()))
		if w.From != seal.Thumbprint(admin.PublicKey()) || string(w.Wrapped) != string(want.Wrapped) || len(entries[0]) != 3 {
			t.Fatalf("relayed entry %v", entries[0])
		}
		if k, err := seal.UnwrapKeyAuth(c.priv, admin.PublicKey(), w); err != nil || string(k) != string(k1) {
			t.Fatalf("unwrap: %v", err)
		}
	}
	g := e.grant(f.writer, "user:s", []string{"e"}, []string{"read"}, map[string]any{"enc": strangerJWK})
	_, r := e.keysOf("e", nil, g)
	if entries := keyEntries(t, r); len(entries) != 0 {
		t.Fatalf("a stranger got %s", r.Body)
	}
}
