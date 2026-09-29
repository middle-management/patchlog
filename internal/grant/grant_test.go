package grant

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

var now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func ts(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }

type fixture struct {
	priv ed25519.PrivateKey
	keys []Key
}

func newFixture(t *testing.T, scope map[string]any) *fixture {
	t.Helper()
	pub, priv := GenerateKey()
	k := map[string]any{"kid": "k1", "alg": "Ed25519", "pub": pub, "can": []any{"*"}}
	for n, v := range scope {
		k[n] = v
	}
	keys, err := ParseKeys(jsonv.FromGo([]any{k}))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{priv: priv, keys: keys}
}

func (f *fixture) env() Env {
	return Env{Now: now, NS: "matches", Keys: f.keys, Revoked: map[string]bool{},
		Roles: Roles{"reader": {Can: []string{"read"}}, "editor": {Can: []string{"read", "append", "create"}}}}
}

func rootBlock(extra map[string]any) map[string]any {
	b := map[string]any{"kid": "k1", "sub": "user:bob", "groups": []string{"desk"},
		"ns": []string{"matches", "docs"}, "can": []string{"read", "append"},
		"exp": ts(time.Hour), "attrs": map[string]any{"region": "se"}}
	for k, v := range extra {
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
	}
	return b
}

func mustMint(t *testing.T, f *fixture, extra map[string]any) *Grant {
	t.Helper()
	g, err := Mint(rootBlock(extra), f.priv)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func roundtrip(t *testing.T, g *Grant) *Grant {
	t.Helper()
	d, err := Decode(g.Encode(), 8192)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Status != status {
		t.Fatalf("want %d, got %v", status, err)
	}
}

func TestMintVerifyRoundtrip(t *testing.T) {
	f := newFixture(t, nil)
	g := roundtrip(t, mustMint(t, f, nil))
	v, err := Verify(g, f.env())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Can["read"] || !v.Can["append"] || v.Can["delete"] || !v.StarKey {
		t.Fatalf("can %v", v.Can)
	}
	if ok, _ := v.Allows("append"); !ok {
		t.Fatal("append should be allowed")
	}
	if ok, _ := v.Allows("delete"); ok {
		t.Fatal("delete should not be allowed")
	}
	env := v.Principal.Envelope()
	want := map[string]any{"id": "user:bob", "groups": []any{"desk"}, "roles": []any{},
		"attrs": map[string]any{"region": "se"}, "via": []any{}, "grant": g.ID().String()}
	if !jsonv.Equal(env, want) {
		t.Fatalf("envelope %s", jsonv.Canonical(env))
	}
	if _, err := Verify(g, Env{Now: now, NS: "other", Keys: f.keys}); err == nil {
		t.Fatal("wrong ns accepted")
	} else {
		wantStatus(t, err, 403)
	}
}

func TestNarrowing(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, map[string]any{"roles": []string{"reader", "editor", "ghost"}})
	n, err := g.Narrow(map[string]any{"via": "svc:tr", "can": []string{"append", "delete"},
		"ns": []string{"matches"}, "roles": []string{"editor"}, "exp": ts(30 * time.Minute),
		"rules": []any{map[string]any{"op": "writes", "within": []any{"/i18n"}}}})
	if err != nil {
		t.Fatal(err)
	}
	n2, err := n.Narrow(map[string]any{"via": "svc:sub"})
	if err != nil {
		t.Fatal(err)
	}
	d := roundtrip(t, n2)
	if d.ID() != g.ID() {
		t.Fatal("grant id changed across narrowing")
	}
	v, err := Verify(d, f.env())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Can["append"] || v.Can["read"] || v.Can["delete"] || len(v.Can) != 1 {
		t.Fatalf("can %v", v.Can)
	}
	if strings.Join(v.EffectiveRoles, ",") != "editor" {
		t.Fatalf("roles %v", v.EffectiveRoles)
	}
	if strings.Join(v.Principal.Via, ",") != "svc:tr,svc:sub" || v.Principal.ID != "user:bob" {
		t.Fatalf("principal %+v", v.Principal)
	}
	if len(v.BlockRules) != 1 {
		t.Fatalf("rules %v", v.BlockRules)
	}
	env := f.env()
	env.NS = "docs"
	if _, err := Verify(d, env); err == nil {
		t.Fatal("narrowed ns not enforced")
	}
	env = f.env()
	env.Now = now.Add(45 * time.Minute)
	_, err = Verify(d, env)
	wantStatus(t, err, 403)
	// Narrowing cannot widen exp beyond the root's.
	w, _ := g.Narrow(map[string]any{"exp": ts(48 * time.Hour)})
	env.Now = now.Add(2 * time.Hour)
	_, err = Verify(roundtrip(t, w), env)
	wantStatus(t, err, 403)
}

func TestNarrowingCannotAddIdentity(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	for _, k := range []string{"sub", "groups", "attrs", "kid", "at", "bogus"} {
		var v any = "x"
		switch k {
		case "groups":
			v = []string{"admins"}
		case "attrs":
			v = map[string]any{"a": 1}
		}
		if _, err := g.Narrow(map[string]any{k: v}); err == nil {
			t.Errorf("narrowing with %s accepted", k)
		}
	}
	// A hand-crafted chain with such a block is rejected at decode, even if
	// correctly signed.
	next, nextPriv := GenerateKey()
	raw := map[string]any{"sub": "user:eve"}
	sig := ed25519.Sign(g.proof, signingInput(raw, next, g.sigs[0]))
	bad := &Grant{Blocks: append(g.Blocks, Block{Raw: raw}), sigs: append(g.sigs, sig), nexts: append(g.nexts, next), proof: nextPriv}
	_, err := Decode(bad.Encode(), 0)
	wantStatus(t, err, 401)
	// Verbs: "*" is never valid in a grant.
	if _, err := Mint(rootBlock(map[string]any{"can": []string{"*"}}), f.priv); err == nil {
		t.Fatal("* accepted in grant")
	}
}

func decodeJSON(t *testing.T, tok string) map[string]any {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	return jsonv.MustParse(b).(map[string]any)
}

func encodeJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestTampering(t *testing.T) {
	f := newFixture(t, nil)
	g, _ := mustMint(t, f, nil).Narrow(map[string]any{"can": []string{"read"}})
	tok := g.Encode()

	// Tampered root block: root signature fails at Verify.
	m := decodeJSON(t, tok)
	m["blocks"].([]any)[0].(map[string]any)["b"].(map[string]any)["can"] = []any{"read", "append", "delete"}
	d, err := Decode(encodeJSON(m), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(d, f.env())
	wantStatus(t, err, 401)

	// Tampered narrowing block.
	m = decodeJSON(t, tok)
	m["blocks"].([]any)[1].(map[string]any)["b"].(map[string]any)["can"] = []any{"read", "append"}
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)

	// Dropping the narrowing block: the proof no longer matches.
	m = decodeJSON(t, tok)
	m["blocks"] = m["blocks"].([]any)[:1]
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)

	// Tampered signature.
	m = decodeJSON(t, tok)
	env := m["blocks"].([]any)[1].(map[string]any)
	s := []byte(env["sig"].(string))
	if s[0] == 'A' {
		s[0] = 'B'
	} else {
		s[0] = 'A'
	}
	env["sig"] = string(s)
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)

	// Missing and wrong proof.
	m = decodeJSON(t, tok)
	delete(m, "proof")
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)
	m = decodeJSON(t, tok)
	_, other := GenerateKey()
	m["proof"] = EncodePrivateKey(other)
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)

	// Unknown members.
	m = decodeJSON(t, tok)
	m["extra"] = true
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)
	m = decodeJSON(t, tok)
	m["blocks"].([]any)[0].(map[string]any)["x"] = 1.0
	_, err = Decode(encodeJSON(m), 0)
	wantStatus(t, err, 401)

	// Garbage and size.
	_, err = Decode("!!!", 0)
	wantStatus(t, err, 401)
	if _, err := Decode(tok, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestReserialisedAndRevocation(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	n, _ := g.Narrow(map[string]any{"via": "svc:x"})
	re := encodeJSON(decodeJSON(t, n.Encode()))
	if re == n.Encode() {
		t.Fatal("expected a different serialisation")
	}
	d, err := Decode(re, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(d, f.env()); err != nil {
		t.Fatal(err)
	}
	if d.RevocationIDs()[0] != g.RevocationIDs()[0] || len(d.RevocationIDs()) != 2 {
		t.Fatal("revocation ids unstable")
	}
	env := f.env()
	env.Revoked = map[string]bool{g.RevocationIDs()[0]: true}
	_, err = Verify(d, env)
	wantStatus(t, err, 403)
	env.Revoked = map[string]bool{d.RevocationIDs()[1]: true}
	_, err = Verify(d, env)
	wantStatus(t, err, 403)
	if _, err := Verify(roundtrip(t, g), env); err != nil {
		t.Fatal("revoking a narrowing block must not revoke the root")
	}
}

func TestUnknownKidAndTime(t *testing.T) {
	f := newFixture(t, nil)
	g := roundtrip(t, mustMint(t, f, map[string]any{"kid": "nope"}))
	_, err := Verify(g, f.env())
	wantStatus(t, err, 401)

	// Same kid, different key.
	other := newFixture(t, nil)
	_, err = Verify(roundtrip(t, mustMint(t, other, nil)), f.env())
	wantStatus(t, err, 401)

	g = roundtrip(t, mustMint(t, f, map[string]any{"exp": ts(-time.Minute)}))
	_, err = Verify(g, f.env())
	wantStatus(t, err, 403)
	g = roundtrip(t, mustMint(t, f, map[string]any{"nbf": ts(time.Minute)}))
	_, err = Verify(g, f.env())
	wantStatus(t, err, 403)
	env := f.env()
	env.Now = now.Add(time.Minute)
	if _, err := Verify(g, env); err != nil {
		t.Fatal(err)
	}
	if _, err := Mint(rootBlock(map[string]any{"exp": nil}), f.priv); err == nil {
		t.Fatal("root without exp accepted")
	}
}

func TestKeyScope(t *testing.T) {
	cases := []struct {
		name  string
		scope map[string]any
		extra map[string]any
		ok    bool
	}{
		{"can ok", map[string]any{"can": []any{"read", "append"}}, nil, true},
		{"can violated", map[string]any{"can": []any{"read"}}, nil, false},
		{"maxTtl ok", map[string]any{"maxTtl": "PT1H"}, nil, true},
		{"maxTtl violated", map[string]any{"maxTtl": "PT59M"}, nil, false},
		{"maxTtl from nbf", map[string]any{"maxTtl": "PT30M"}, map[string]any{"nbf": ts(-time.Hour)}, false},
		{"sub ok", map[string]any{"sub": "user:[a-z]+"}, nil, true},
		{"sub anchored", map[string]any{"sub": "user:b"}, nil, false},
		{"groups allow ok", map[string]any{"groups": map[string]any{"allow": []any{"desk", "x"}}}, nil, true},
		{"groups allow violated", map[string]any{"groups": map[string]any{"allow": []any{"x"}}}, nil, false},
		{"groups deny", map[string]any{"groups": map[string]any{"deny": []any{"desk"}}}, nil, false},
		{"roles deny", map[string]any{"roles": map[string]any{"deny": []any{"editor"}}}, map[string]any{"roles": []string{"editor"}}, false},
		{"roles deny ok", map[string]any{"roles": map[string]any{"deny": []any{"editor"}}}, map[string]any{"roles": []string{"reader"}}, true},
		{"attrs ok", map[string]any{"attrs": map[string]any{"region": "se"}}, nil, true},
		{"attrs violated", map[string]any{"attrs": map[string]any{"region": "no"}}, nil, false},
		{"requireAt missing", map[string]any{"requireAt": true}, nil, false},
		{"requireAt ok", map[string]any{"requireAt": true}, map[string]any{"at": "1" + strings.Repeat("a", 32)}, true},
		{"requireAt lag", map[string]any{"requireAt": "cat", "maxLag": "PT1M"}, map[string]any{"at": map[string]any{"ns": "cat", "id": "1" + strings.Repeat("a", 32)}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.scope)
			env := f.env()
			// Stub attrs schema check: the "schema" is the exact attrs object.
			env.ValidateAttrs = func(schema any, attrs map[string]any) error {
				if !jsonv.Equal(schema, attrs) {
					return errors.New("mismatch")
				}
				return nil
			}
			env.CheckAt = func(req, at any) (time.Duration, error) {
				if _, ok := at.(map[string]any); ok {
					return 2 * time.Minute, nil
				}
				return 0, nil
			}
			_, err := Verify(roundtrip(t, mustMint(t, f, c.extra)), env)
			if c.ok && err != nil {
				t.Fatal(err)
			}
			if !c.ok {
				wantStatus(t, err, 403)
			}
		})
	}
	// Key scope can bounds effective verbs of a narrowed grant listing extra verbs.
	f := newFixture(t, map[string]any{"can": []any{"read", "append"}})
	g, _ := mustMint(t, f, nil).Narrow(map[string]any{"can": []string{"delete"}})
	_, err := Verify(roundtrip(t, g), f.env())
	wantStatus(t, err, 403)
}

func TestRoles(t *testing.T) {
	f := newFixture(t, map[string]any{"can": []any{"read", "append"}})
	// Roles only: verbs come from roles, bounded by key.
	g := roundtrip(t, mustMint(t, f, map[string]any{"can": nil, "roles": []string{"reader", "editor", "ghost"}}))
	v, err := Verify(g, f.env())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(v.EffectiveRoles, ",") != "reader,editor" {
		t.Fatalf("roles %v", v.EffectiveRoles)
	}
	if !v.Can["read"] || !v.Can["append"] || v.Can["create"] {
		t.Fatalf("can %v", v.Can)
	}
	ok, roles := v.Allows("read")
	if !ok || strings.Join(roles, ",") != "reader,editor" {
		t.Fatalf("allows read %v %v", ok, roles)
	}
	ok, roles = v.Allows("append")
	if !ok || strings.Join(roles, ",") != "editor" {
		t.Fatalf("allows append %v %v", ok, roles)
	}
	if ok, _ := v.Allows("create"); ok {
		t.Fatal("create beyond key scope")
	}
	// Roles plus can: both must allow.
	g = roundtrip(t, mustMint(t, f, map[string]any{"can": []string{"read", "append"}, "roles": []string{"reader"}}))
	v, _ = Verify(g, f.env())
	if ok, _ := v.Allows("append"); ok {
		t.Fatal("append allowed without a role listing it")
	}
	if ok, _ := v.Allows("read"); !ok {
		t.Fatal("read denied")
	}
	// Undefined roles only: nothing allowed.
	g = roundtrip(t, mustMint(t, f, map[string]any{"roles": []string{"ghost"}}))
	v, _ = Verify(g, f.env())
	if ok, _ := v.Allows("read"); ok || len(v.EffectiveRoles) != 0 {
		t.Fatal("undefined role granted access")
	}
	// Narrowing to no roles drops them all.
	g0 := mustMint(t, f, map[string]any{"roles": []string{"reader"}})
	n, _ := g0.Narrow(map[string]any{"roles": []string{}})
	v, _ = Verify(roundtrip(t, n), f.env())
	if ok, _ := v.Allows("read"); ok {
		t.Fatal("narrowed-away role still grants")
	}
	if len(v.Principal.Envelope()["roles"].([]any)) != 0 {
		t.Fatal("envelope roles")
	}
}

func TestStored(t *testing.T) {
	f := newFixture(t, nil)
	g, _ := mustMint(t, f, nil).Narrow(map[string]any{"via": "svc"})
	s := g.Stored()
	if strings.Contains(string(s), "proof") || strings.Contains(string(s), EncodePrivateKey(g.proof)) {
		t.Fatal("stored form contains proof")
	}
	p, err := ParseStored(s)
	if err != nil {
		t.Fatal(err)
	}
	if p.HasProof() || p.ID() != g.ID() {
		t.Fatal("stored parse")
	}
	if _, err := p.Narrow(map[string]any{"via": "x"}); err == nil {
		t.Fatal("narrowed without proof")
	}
	// A stored grant is not a bearer token.
	if _, err := Decode(base64.RawURLEncoding.EncodeToString(s), 0); err == nil {
		t.Fatal("stored form accepted as bearer")
	}
}

func TestParseKeysAndRoles(t *testing.T) {
	pub, _ := GenerateKey()
	bad := []map[string]any{
		{"kid": "a", "alg": "rsa", "pub": pub, "can": []any{"read"}},
		{"kid": "a", "alg": "ed25519", "pub": "xx", "can": []any{"read"}},
		{"kid": "a", "alg": "ed25519", "pub": pub},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"fly"}},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"}, "maxTtl": "1h"},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"}, "sub": "(a)\\1"},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"}, "groups": map[string]any{"allow": []any{}, "deny": []any{}}},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"}, "readScope": "all"},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"}, "rate": map[string]any{"rate": 0.0, "burst": 1.0}},
		{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"}, "bogus": 1.0},
	}
	for i, k := range bad {
		if _, err := ParseKeys([]any{jsonv.FromGo(k)}); err == nil {
			t.Errorf("bad key %d accepted", i)
		}
	}
	good := jsonv.FromGo([]any{map[string]any{"kid": "a", "alg": "ed25519", "pub": pub, "can": []any{"read"},
		"maxTtl": "P1DT2H3M4.5S", "rate": map[string]any{"rate": 1.0, "burst": 5.0}, "readScope": "resource",
		"requireAt": "cat", "maxLag": "PT60S", "roles": map[string]any{"allow": []any{"r"}}}})
	ks, err := ParseKeys(good)
	if err != nil {
		t.Fatal(err)
	}
	k := ks[0]
	if *k.MaxTTL != 26*time.Hour+3*time.Minute+4500*time.Millisecond || k.Rate.Burst != 5 || !k.ReadScopeResource || k.RequireAt != "cat" || *k.MaxLag != time.Minute || k.IsStar() {
		t.Fatalf("key %+v", k)
	}
	if _, err := ParseKeys([]any{good.([]any)[0], good.([]any)[0]}); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if _, err := ParseRoles(jsonv.FromGo(map[string]any{"r": map[string]any{"can": []any{"*"}}})); err == nil {
		t.Fatal("* in role accepted")
	}
	rs, err := ParseRoles(jsonv.FromGo(map[string]any{"r": map[string]any{"can": []any{"read"}, "move": true, "rules": []any{}}}))
	if err != nil || rs["r"].Can[0] != "read" {
		t.Fatal(err)
	}
}

func TestPrivateKeyRoundtrip(t *testing.T) {
	_, priv := GenerateKey()
	p, err := ParsePrivateKey(EncodePrivateKey(priv))
	if err != nil || !p.Equal(priv) {
		t.Fatal("private key roundtrip")
	}
	if _, err := ParsePrivateKey("abc"); err == nil {
		t.Fatal("bad key accepted")
	}
}
