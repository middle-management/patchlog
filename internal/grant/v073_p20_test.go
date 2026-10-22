package grant

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// CIS-21 (§6.4.2): a grant whose rules carry a schema fragment that breaks
// the fragment rules (§6.1's $id ban, §6.5, §6.6, no $schema, same-document
// references only) is invalid (401); CIS-15: so is a format draft 2020-12
// doesn't define; CIS-16: \uXXXX is read as \x{XXXX}.
func TestV073P20GrantRuleFragments(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	rule := func(schema any) map[string]any {
		return map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/principal/id", "schema": schema}}}
	}
	for _, bad := range []any{
		map[string]any{"$id": "x"},
		map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema"},
		map[string]any{"items": map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema"}},
		map[string]any{"foo": 1.0},
		map[string]any{"format": "semver"},
		map[string]any{"format": "nope"},
		map[string]any{"dependencies": map[string]any{}},
		map[string]any{"$ref": "/r/schemas/s/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		map[string]any{"$dynamicRef": "x#a"},
		map[string]any{"pattern": `\ud800`},
	} {
		_, err := Decode(mustMint(t, f, rule(bad)).Encode(), 0)
		wantStatus(t, err, 401)
	}
	g, err := Decode(mustMint(t, f, rule(map[string]any{"pattern": `^user:\u00e9$`, "format": "idn-email",
		"definitions": map[string]any{"s": map[string]any{"type": "string"}}, "$ref": "#/definitions/s"})).Encode(), 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := compileRule(g.Blocks[0].Rules[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.Eval(map[string]any{"principal": map[string]any{"id": "user:é"}}) {
		t.Error("idn-email isn't asserted: user:é passed")
	}
	g, err = Decode(mustMint(t, f, rule(map[string]any{"pattern": `^user:\u00e9$`})).Encode(), 0)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = compileRule(g.Blocks[0].Rules[0])
	if !r.Eval(map[string]any{"principal": map[string]any{"id": "user:é"}}) || r.Eval(map[string]any{"principal": map[string]any{"id": "user:e"}}) {
		t.Error(`é isn't read as é`)
	}
}

// CIS-16 (§C.4, §6.6): a key scope's sub is RE2 with \uXXXX read as
// \x{XXXX}, a surrogate pair as one code point, that the whole root sub
// must match. A lone surrogate is refused (SubPattern); one RE2 took as
// written, such as \x{D800}, still parses from a stored document.
func TestV073P20KeySubPattern(t *testing.T) {
	t.Parallel()
	for _, x := range []struct {
		sub, match, miss string
	}{
		{`user:\u00e9.*`, "user:éva", "user:eva"},
		{`user:\ud83d\ude00`, "user:\U0001F600", "user:x"},
		{`user:[\u0061-\u0063]`, "user:b", "user:d"},
		{`a|b`, "a", "ab"},
	} {
		f := newFixture(t, map[string]any{"sub": x.sub})
		re := f.keys[0].SubPattern
		if !re.MatchString(x.match) || re.MatchString(x.miss) {
			t.Errorf("%s: match %q %v, miss %q %v", x.sub, x.match, re.MatchString(x.match), x.miss, re.MatchString(x.miss))
		}
		// Verification uses it.
		if _, err := Verify(mustMint(t, f, map[string]any{"sub": x.match}), f.env()); err != nil {
			t.Errorf("%s: %q: %v", x.sub, x.match, err)
		}
		_, err := Verify(mustMint(t, f, map[string]any{"sub": x.miss}), f.env())
		wantStatus(t, err, 403)
	}
	for _, bad := range []string{`\ud800`, `\udc00x`, `\x{D800}`, `(?=a)`} {
		if _, err := SubPattern(bad); err == nil {
			t.Errorf("SubPattern(%s) accepted", bad)
		}
	}
	pub, _ := GenerateKey()
	key := func(sub string) any {
		return jsonv.FromGo([]any{map[string]any{"kid": "k", "alg": "Ed25519", "pub": pub, "can": []any{"read"}, "sub": sub}})
	}
	if _, err := ParseKeys(key(`\ud800`)); err == nil {
		t.Error(`ParseKeys accepted a lone surrogate \ud800`)
	}
	if _, err := ParseKeys(key(`(?=a)`)); err == nil {
		t.Error("ParseKeys accepted a lookahead")
	}
	// Stored before §6.6 read \u: RE2 took \x{D800}, and it still loads.
	if _, err := ParseKeys(key(`a\x{D800}`)); err != nil {
		t.Errorf("a stored \\x{D800} sub: %v", err)
	}
}
