package server

import (
	"crypto/ecdh"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
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

// kidsOf returns the kids ("kid name" for a K_r) of a 200 /keys answer,
// in order.
func kidsOf(t *testing.T, r *resp) string {
	t.Helper()
	var out []string
	for _, e := range keyEntries(t, r) {
		k := e["kid"].(string)
		if n, ok := e["name"].(string); ok {
			k += " " + n
		}
		out = append(out, k)
	}
	return strings.Join(out, ",")
}

// P18, ENC-13, ENC-14 and ENC-15 (§E.2.3): the epochs run from the one in
// force at the last namespace entry at or before the latest nbf among all
// the grant's blocks, a batch's config change included, or the first
// where there is none; the current one alone with no nbf in any block;
// with historyEpochs h, at most the current one and the h before it; and
// an epoch that began after the grant's exp isn't left out.
func TestV073KeysEpochWindow(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	long := map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339)}
	star := e.grant(k, "user:admin", []string{"s"}, []string{"create", "read", "config"}, long)
	e.clock.Advance(time.Hour)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), star), 201)
	e.clock.Advance(time.Hour)
	// Epoch 3 begins with a batch's config change.
	r := e.do(req{method: "POST", path: "/ns/s/batch", bearer: star, body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("s", star), "patches": ops(op("add", "/encryption/epoch", 3.0))},
		"items":  []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{withNonce(addRoot(map[string]any{}))}}}}})
	expect(t, r, 201)
	e.clock.Advance(10 * time.Minute) // t0+2h10m; epochs began at t0, t0+1h, t0+2h
	at := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }
	keys := func(root map[string]any, narrow ...map[string]any) string {
		t.Helper()
		root = mapsMerge(map[string]any{"kid": k.kid, "sub": "user:r", "ns": []any{"s"}, "can": []any{"read"}, "exp": at(3 * time.Hour)}, root)
		g, err := grant.Mint(root, k.priv)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range narrow {
			if g, err = g.Narrow(b); err != nil {
				t.Fatal(err)
			}
		}
		_, r := e.keysOf("s", nil, g.Encode())
		return kidsOf(t, r)
	}
	for name, c := range map[string]struct {
		root   map[string]any
		narrow []map[string]any
		want   string
	}{
		"no nbf":                         {nil, nil, "s#3"},
		"nbf before the first epoch":     {map[string]any{"nbf": at(-time.Hour)}, nil, "s#1,s#2,s#3"},
		"nbf in epoch 2":                 {map[string]any{"nbf": at(90 * time.Minute)}, nil, "s#2,s#3"},
		"a narrowing block's nbf counts": {map[string]any{"nbf": at(-time.Hour)}, []map[string]any{{"nbf": at(90 * time.Minute)}}, "s#2,s#3"},
		"only a narrowing block has nbf": {nil, []map[string]any{{"nbf": at(30 * time.Minute)}}, "s#1,s#2,s#3"},
		"the batch began epoch 3":        {map[string]any{"nbf": at(-time.Hour)}, []map[string]any{{"nbf": at(125 * time.Minute)}}, "s#3"},
	} {
		if got := keys(c.root, c.narrow...); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	// historyEpochs 1: the current epoch and the one before it.
	expect(t, e.patchNS("s", ops(op("add", "/encryption/historyEpochs", 1.0)), star), 201)
	if got := keys(map[string]any{"nbf": at(-time.Hour)}); got != "s#2,s#3" {
		t.Errorf("historyEpochs 1: %s", got)
	}
	expect(t, e.patchNS("s", ops(op("remove", "/encryption/historyEpochs")), star), 201)
	// Epoch 4 begins at t0+5h, after the grant's exp (t0+3h); the clock is
	// set back for the grant to verify.
	e.clock.set(t0.Add(5 * time.Hour))
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 4.0)), star), 201)
	e.clock.set(t0.Add(150 * time.Minute))
	if got := keys(map[string]any{"nbf": at(-time.Hour)}); got != "s#1,s#2,s#3,s#4" {
		t.Errorf("an epoch after exp: %s", got)
	}
}

func mapsMerge(dst, src map[string]any) map[string]any {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// P18, ENC-16 (§E.2.3): at E2 a grant whose rules fix /resource (§2.1)
// gets K_r for the names in resources, by default every name it fixes; a
// name it doesn't fix, or may not read, is 403. Rules that refer to
// /resource without fixing it give no K_r and, the grant not reading
// unrestricted, no K_e either.
func TestV073KeysPerResourceNames(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	enum := func(names ...any) map[string]any {
		return map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}
	}
	notB := map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "b"}}
	g := func(rules ...any) string {
		return e.grant(k, "user:li", []string{"s"}, []string{"read"}, map[string]any{"rules": rules})
	}
	for name, c := range map[string]struct {
		grant     string
		resources any // nil: absent
		status    int
		want      string
	}{
		"default: every fixed name":  {g(enum("b", "a")), nil, 200, "s#1 a,s#1 b"},
		"asked":                      {g(enum("a", "b")), []any{"b"}, 200, "s#1 b"},
		"asked twice":                {g(enum("a", "b")), []any{"a", "a"}, 200, "s#1 a"},
		"none asked":                 {g(enum("a", "b")), []any{}, 200, ""},
		"not fixed":                  {g(enum("a", "b")), []any{"a", "c"}, 403, ""},
		"fixed, not readable":        {g(enum("a", "b"), notB), []any{"b"}, 403, ""},
		"default with an unreadable": {g(enum("a", "b"), notB), nil, 403, ""},
		"readable of those":          {g(enum("a", "b"), notB), []any{"a"}, 200, "s#1 a"},
		"inside all":                 {g(map[string]any{"all": []any{enum("a", "b")}}), nil, 200, "s#1 a,s#1 b"},
		"two fixing rules intersect": {g(enum("a", "b"), map[string]any{"op": "test", "path": "/resource", "value": "a"}), nil, 200, "s#1 a"},
		"refers without fixing":      {g(notB), nil, 403, ""},
		"an invalid literal":         {g(enum("a", "b/c")), []any{"a"}, 403, ""},
		"unrestricted: K_e, ignored": {e.grant(k, "user:r", []string{"s"}, []string{"read"}), []any{"zzz"}, 200, "s#1"},
	} {
		body := map[string]any{}
		if c.resources != nil {
			body["resources"] = c.resources
		}
		r := e.do(req{method: "POST", path: "/ns/s/keys", body: body, bearer: c.grant})
		if r.Code != c.status {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
			continue
		}
		if c.status == 403 {
			if r.Str("code") != "forbidden" {
				t.Errorf("%s: %s", name, r.Body)
			}
			continue
		}
		if got := kidsOf(t, r); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

// P18, ENC-17 (§E.2.3, §6.6): each /keys request draws one token from the
// principal's exchangeRate bucket, as /edge-grants does, at E2 and E3; a
// refused request draws nothing.
func TestV073KeysExchangeRate(t *testing.T) {
	t.Parallel()
	f := newE2E(t, withExchangeRate(core.Rate{Rate: 0.001, Burst: 2}))
	e := f.tenv
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{f.admin.entry("*")}}))
	sg := e.grant(f.admin, "user:r", []string{"s"}, []string{"read"})
	refused := e.grant(f.admin, "user:r", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	for i := 0; i < 3; i++ {
		_, r := e.keysOf("s", map[string]any{"resources": []any{"b"}}, refused)
		expectCode(t, r, 403, "forbidden")
	}
	for i := 0; i < 2; i++ {
		_, r := e.keysOf("s", nil, sg)
		expect(t, r, 200)
	}
	_, r := e.keysOf("s", nil, sg)
	if r.Code != 429 || r.Str("limit") != "exchangeRate" || r.H.Get("Retry-After") == "" {
		t.Fatalf("third /keys: %d %s", r.Code, r.Body)
	}
	// At E3 too, per principal.
	for i := 0; i < 2; i++ {
		_, r := e.keysOf("e", nil, f.readerG)
		expect(t, r, 200)
	}
	_, r = e.keysOf("e", nil, f.readerG)
	if r.Code != 429 || r.Str("limit") != "exchangeRate" {
		t.Fatalf("third e2e /keys: %d %s", r.Code, r.Body)
	}
}
