package vectors_test

// Vectors the reference proposes for Addendum I (CIS-38): the writer's list
// (RE2 \u, keyring wraps in HPKE base and auth mode) and I.11's backlog,
// each computed by production code and kept in testdata/*.json
// (internal/vectors/golden). Each test computes its group and compares it
// with the stored file; -update rewrites the files. Inputs are fixed: keys
// are the 32 bytes seq(n) = n, n+1, … n+31, and wherever the spec draws a
// random value (an IV, an HPKE ephemeral key) the reference's test hooks
// fix it (seal.SealWithIV, SealBlobWithIV, WrapKeyWithEphemeral,
// WrapKeyAuthWithEphemeral), so a vector can be reproduced, not only
// opened. Where no hook exists, as for a sealed bundle (§G.5.1.1), the
// vector is computed under a fixed seed of crypto/rand
// (testing/cryptotest) and checked by opening it.
//
// The Biscuit encodings (§C.8, §C.4) are computed in internal/grant, the
// plan digest (§F.9) in internal/merge, and the archive key and sealed
// resource events (§8.6, §E.2.2) in internal/core, where the encoders
// they need are.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pattern"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

type obj = golden.Obj

// seq is the 32 bytes n, n+1, … n+31, the vectors' fixed keys.
func seq(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n + byte(i)
	}
	return b
}

var b64u = base64.RawURLEncoding

// The fixed keys.
var (
	// nsKeySeed is the Ed25519 seed of the namespace key k1 that signs
	// the grants of the server vectors.
	nsKeySeed = seq(0xa0)
)

func nsKey() clienttest.Key {
	priv := ed25519.NewKeyFromSeed(nsKeySeed)
	return clienttest.Key{Kid: "k1", Pub: b64u.EncodeToString(priv.Public().(ed25519.PublicKey)), Priv: priv}
}

// answer is a deployment's verdict on a request: "accepted", or its
// status and §12 code.
func answer(t *testing.T, err error) obj {
	t.Helper()
	if err == nil {
		return obj{{Key: "verdict", Value: "accepted"}}
	}
	var ae *client.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("not an API answer: %v", err)
	}
	return obj{{Key: "verdict", Value: "refused"}, {Key: "status", Value: ae.Status}, {Key: "code", Value: ae.Code}}
}

// authServer is an in-process deployment with authentication on, its
// namespace ns created with the key k1 allowed every verb but config, and
// extra members in its document.
func authServer(t *testing.T, ns string, extra map[string]any) (*clienttest.Server, clienttest.Key) {
	t.Helper()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := nsKey()
	doc := map[string]any{"read": "grant", "keys": []any{k.Entry("read", "create", "append", "delete", "restore")}}
	for m, v := range extra {
		doc[m] = v
	}
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc); err != nil {
		t.Fatal(err)
	}
	return s, k
}

// ---- 1. RE2 \uXXXX (§6.6; CIS-16) ----

// TestVectorRE2Escapes: §6.6 reads \uXXXX in a pattern as \x{XXXX}, a
// surrogate pair of such escapes as the one code point, and a lone
// surrogate as a pattern RE2 doesn't accept: 422 (invalid) in a schema or
// config when written, 401 in a grant. An escaped backslash isn't
// translated. Patterns are shown as their text, which JSON writes with
// each backslash doubled.
func TestVectorRE2Escapes(t *testing.T) {
	t.Parallel()
	var vs []any
	for _, c := range []struct {
		name, re string
		in       []string
	}{
		{name: "BMP escape", re: esc(`^%u00e9$`), in: []string{"é", "e", esc(`%u00e9`)}},
		{name: "surrogate pair", re: esc(`^%ud83d%ude00$`), in: []string{"😀", "?", esc(`%ud83d%ude00`)}},
		{name: "escaped backslash", re: esc(`^\\u0041$`), in: []string{esc(`%u0041`), "A"}},
		{name: "in a class", re: esc(`^[%u00e0-%u00ff]+$`), in: []string{"àéÿ", "a"}},
		{name: "lone high surrogate", re: esc(`%ud800`)},
		{name: "lone low surrogate", re: esc(`%udc00`)},
		// I.11 refuses \x{D800} since v0.74 (it was the reference's choice).
		{name: "lone surrogate as \\x{…}", re: `\x{D800}`},
		{name: "high surrogate before a non-surrogate", re: esc(`%ud83d%u0041`)},
		// I.11's \ud83dA: a high surrogate before a literal character.
		{name: "high surrogate before a literal", re: esc(`%ud83dA`)},
	} {
		v := obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "pattern.Translate, pattern.Compile"}, {Key: "pattern", Value: c.re}}
		tr, err := pattern.Translate(c.re)
		if c.in == nil {
			if err == nil {
				t.Fatalf("%s: %q translated as %q, want refused", c.name, c.re, tr)
			}
			vs = append(vs, append(v, golden.Member{Key: "verdict", Value: "refused"}))
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		re, err := pattern.Compile(c.re)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var ms []any
		for _, s := range c.in {
			ms = append(ms, obj{{Key: "string", Value: s}, {Key: "matches", Value: re.MatchString(s)}})
		}
		vs = append(vs, append(v, golden.Member{Key: "re2", Value: tr}, golden.Member{Key: "matches", Value: ms}))
	}
	vs = append(vs, re2Server(t)...)
	golden.Check(t, "re2", obj{
		{Key: "section", Value: "§6.6"},
		{Key: "about", Value: "RE2 patterns with \\uXXXX escapes: their RE2 form, what they match, and how a deployment answers a schema, a namespace document and a grant carrying them"},
		{Key: "vectors", Value: vs},
	})
}

// re2Server is the RE2 group's answers from a deployment: a schema with
// the pattern validating documents, or refused when written; a key whose
// sub pattern has an escape; a grant whose rule has one.
func re2Server(t *testing.T) []any {
	const dialect = "https://json-schema.org/draft/2020-12/schema"
	s, k := authServer(t, "re2", nil)
	exp := map[string]any{"exp": s.Now().Add(time.Hour).Format(time.RFC3339)}
	anna := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:anna", []string{"re2"}, []string{"read", "create", "append"}, exp)))
	var vs []any
	n := 0
	schemaCase := func(name, re string, docs []string) {
		n++
		schemaDoc := map[string]any{"$schema": dialect, "type": "object", "properties": map[string]any{"t": map[string]any{"type": "string", "pattern": re}}}
		res, err := anna.CreateDoc(ctx, "re2", "schema-"+string(rune('a'+n)), schemaDoc)
		v := obj{{Key: "name", Value: name}, {Key: "fn", Value: "server: PUT /r/{ns}/{name} (core: schema compile, §6.1, §6.6)"},
			{Key: "schema", Value: string(jsonv.Canonical(schemaDoc))}}
		v = append(v, answer(t, err)...)
		if err == nil {
			var ds []any
			for i, d := range docs {
				doc := map[string]any{"$schema": "/r/re2/schema-" + string(rune('a'+n)) + "/rev/" + res.ID, "t": d}
				_, err := anna.CreateDoc(ctx, "re2", "doc-"+string(rune('a'+n))+"-"+string(rune('0'+i)), doc)
				ds = append(ds, append(obj{{Key: "t", Value: d}}, answer(t, err)...))
			}
			v = append(v, golden.Member{Key: "documents", Value: ds})
		}
		vs = append(vs, v)
	}
	schemaCase("schema, BMP escape", esc(`^%u00e9$`), []string{"é", "e"})
	schemaCase("schema, surrogate pair", esc(`^%ud83d%ude00$`), []string{"😀", "x"})
	schemaCase("schema, escaped backslash", esc(`^\\u0041$`), []string{esc(`%u0041`), "A"})
	schemaCase("schema, lone surrogate", esc(`^%ud800$`), nil)

	// A key's sub pattern (§C.4) in a namespace document.
	for i, c := range []struct{ name, sub string }{
		{"key sub, BMP escape", esc(`user:%u0062ob`)},
		{"key sub, lone surrogate", esc(`user:%ud800`)},
	} {
		ns := "re2-keys-" + string(rune('a'+i))
		e := k.Entry("read")
		e["sub"] = c.sub
		doc := map[string]any{"read": "grant", "keys": []any{e}}
		_, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc)
		v := obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "server: PUT /ns/{ns} (core: namespace document, grant.ParseKeys)"},
			{Key: "sub", Value: c.sub}}
		v = append(v, answer(t, err)...)
		if err == nil {
			var ps []any
			for _, sub := range []string{"user:bob", "user:eve"} {
				c := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), sub, []string{ns}, []string{"read"}, exp)))
				_, err := c.NSPrincipal(ctx, ns)
				ps = append(ps, append(obj{{Key: "grant sub", Value: sub}, {Key: "request", Value: "GET /ns/" + ns + "/principal"}}, answer(t, err)...))
			}
			v = append(v, golden.Member{Key: "grants", Value: ps})
		}
		vs = append(vs, v)
	}

	// A grant's rule (§6.4.2) with a pattern.
	for _, c := range []struct{ name, re string }{
		{"grant rule, BMP escape", esc(`^%u0064erby$`)},
		{"grant rule, lone surrogate", esc(`^%udfff$`)},
	} {
		rule := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "pattern": c.re}}
		g := k.Grant(t, s.Now(), "user:bob", []string{"re2"}, []string{"read", "create"}, exp, map[string]any{"rules": []any{rule}})
		bob := s.Client(t, client.WithBearer(g))
		v := obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "server: PUT /r/{ns}/{name} (grant.DecodeLimited, rules.CompileStrict)"},
			{Key: "rule", Value: string(jsonv.Canonical(rule))}}
		var ws []any
		for _, name := range []string{"derby", "cup"} {
			_, err := bob.CreateDoc(ctx, "re2", name, map[string]any{"title": name})
			ws = append(ws, append(obj{{Key: "request", Value: "PUT /r/re2/" + name}}, answer(t, err)...))
		}
		vs = append(vs, append(v, golden.Member{Key: "writes", Value: ws}))
	}

	// §6.6's verdicts, whatever the stored file says: a lone surrogate is
	// 422 (invalid) in a schema or namespace document, 401 in a grant.
	for _, v := range vs {
		o := v.(obj)
		name := o[0].Value.(string)
		if !strings.Contains(name, "lone") {
			continue
		}
		want := obj{{Key: "verdict", Value: "refused"}, {Key: "status", Value: 422}, {Key: "code", Value: "invalid"}}
		got := o[3:6]
		if strings.HasPrefix(name, "grant") {
			want = obj{{Key: "verdict", Value: "refused"}, {Key: "status", Value: 401}, {Key: "code", Value: "unauthenticated"}}
			got = o[3].Value.([]any)[0].(obj)[1:]
		}
		if string(golden.Encode(t, got)) != string(golden.Encode(t, want)) {
			t.Errorf("%s: %s, want %s", name, golden.Encode(t, got), golden.Encode(t, want))
		}
	}
	return vs
}

// ---- 11. Noncharacters in input (§3.1; CIS-1) ----

// TestVectorNoncharacters: request bodies refuse the 66 noncharacters,
// U+FDD0–U+FDEF and U+nFFFE/U+nFFFF in every plane, written raw or
// escaped (a surrogate pair included), with 400; stored rows and other
// deployments' bytes are read without that check (jsonv.Parse). U+FDCF,
// U+FDF0 and U+FFFD aren't noncharacters.
func TestVectorNoncharacters(t *testing.T) {
	t.Parallel()
	c := deployment(t, "nonchar")
	var vs []any
	for i, r := range []rune{0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF, 0xFDCF, 0xFDF0, 0xFFFD} {
		for _, form := range []string{"raw", "escaped"} {
			var lit string
			if form == "raw" {
				lit = `"` + string(r) + `"`
			} else {
				lit = `"` + escape(r) + `"`
			}
			body := `[{"op":"add","path":"","value":{"t":` + lit + `}}]`
			_, perr := jsonv.ParseInput([]byte(lit))
			stored, serr := jsonv.Parse([]byte(lit))
			if serr != nil {
				t.Fatalf("U+%04X %s: jsonv.Parse: %v", r, form, serr)
			}
			v := obj{{Key: "name", Value: fmt.Sprintf("U+%04X %s", r, form)},
				{Key: "fn", Value: "jsonv.ParseInput; server: PUT /r/{ns}/{name}"},
				{Key: "input", Value: lit}, {Key: "input_hex", Value: golden.Hex([]byte(lit))}}
			if perr != nil {
				v = append(v, golden.Member{Key: "input verdict", Value: "400"})
			} else {
				v = append(v, golden.Member{Key: "input verdict", Value: "accept"},
					golden.Member{Key: "canonical_hex", Value: golden.Hex(jsonv.Canonical(stored))})
			}
			res, err := c.Create(ctx, "nonchar", "n"+string(rune('a'+i))+form, []byte(body))
			v = append(v, golden.Member{Key: "body", Value: body})
			v = append(v, answer(t, err)...)
			if err == nil {
				v = append(v, golden.Member{Key: "revision", Value: res.ID})
				if want := ids.Revision(nil, []byte(`[{"op":"add","path":"","value":{"t":`+string(jsonv.Canonical(stored))+`}}]`)).String(); res.ID != want {
					t.Errorf("U+%04X %s: revision %s, want %s over the canonical form", r, form, res.ID, want)
				}
			}
			if (perr == nil) != (err == nil) {
				t.Errorf("U+%04X %s: ParseInput %v, deployment %v", r, form, perr, err)
			}
			// §3.1's verdict, whatever the stored file says: refused (400)
			// iff r is a noncharacter.
			if nonchar := r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFE == 0xFFFE; nonchar != (perr != nil) {
				t.Errorf("U+%04X %s: ParseInput %v, want refused %v", r, form, perr, nonchar)
			} else if ae := (*client.APIError)(nil); nonchar && !(errors.As(err, &ae) && ae.Status == 400) {
				t.Errorf("U+%04X %s: deployment %v, want 400", r, form, err)
			}
			vs = append(vs, v)
		}
	}
	golden.Check(t, "noncharacters", obj{
		{Key: "section", Value: "§3.1"},
		{Key: "about", Value: "noncharacters in a request body, raw and as \\u escapes: 400; other code points next to them are accepted, and the revision id is over the canonical form"},
		{Key: "vectors", Value: vs},
	})
}

// esc writes each "%u" of s as a backslash and "u": the patterns and JSON
// texts here spell their \uXXXX escapes so, apart from Go's own.
func esc(s string) string { return strings.ReplaceAll(s, "%u", "\\"+"u") }

// escape writes r as JSON's \u escapes, a surrogate pair above U+FFFF.
func escape(r rune) string {
	if r < 0x10000 {
		return `\u` + hex4(r)
	}
	r -= 0x10000
	return `\u` + hex4(0xD800+(r>>10)) + `\u` + hex4(0xDC00+(r&0x3FF))
}

func hex4(r rune) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[r>>12&15], digits[r>>8&15], digits[r>>4&15], digits[r&15]})
}

// ---- 11. /principal key (§7.4; RH-22) ----

// TestVectorPrincipalKey: /principal's key is the RFC 7638 thumbprint of
// the Ed25519 key that verified the root block, as the JWK
// {"crv":"Ed25519","kty":"OKP","x":…}: the same key in every namespace,
// whatever its kid.
func TestVectorPrincipalKey(t *testing.T) {
	t.Parallel()
	s, k := authServer(t, "principal", nil)
	exp := map[string]any{"exp": s.Now().Add(time.Hour).Format(time.RFC3339)}
	c := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:bob", []string{"principal"}, []string{"read"}, exp)))
	p, err := c.NSPrincipal(ctx, "principal")
	if err != nil {
		t.Fatal(err)
	}
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + k.Pub + `"}`
	if sum := sha256.Sum256([]byte(jwk)); p.Key != b64u.EncodeToString(sum[:]) {
		t.Errorf("key %s isn't the thumbprint of %s", p.Key, jwk)
	}
	golden.Check(t, "principal", obj{
		{Key: "section", Value: "§7.4"},
		{Key: "about", Value: "/principal's key: the RFC 7638 SHA-256 thumbprint of the root block's verifying key"},
		{Key: "vectors", Value: []any{obj{
			{Key: "name", Value: "Ed25519 key, seed seq(0xa0)"},
			{Key: "fn", Value: "server: GET /ns/{ns}/principal (core keyThumbprint)"},
			{Key: "seed", Value: golden.Hex(nsKeySeed)},
			{Key: "pub", Value: k.Pub},
			{Key: "jwk", Value: jwk},
			{Key: "key", Value: p.Key},
		}}},
	})
}

// ---- 10. File renderings (§H.1; GW-36) ----

// TestVectorRenderings: I.11's file renderings: a $successor left out and
// one kept (not of §8.1's form), a $nonce not of the fresh form, an array
// root, numbers in exponent form, and escapes.
func TestVectorRenderings(t *testing.T) {
	t.Parallel()
	var vs []any
	for _, c := range []struct{ name, doc string }{
		{"$successor of §8.1's form, left out", `{"$successor":"derby-2","title":"Old"}`},
		{"$successor not a resource name, kept", `{"$successor":"Not A Name","a":1}`},
		{"$nonce not of the fresh form, kept", `{"$nonce":"short","a":1}`},
		{"array root", `[1,{"b":[]},"x"]`},
		{"exponents and negative zero", `{"big":1e21,"small":1e-7,"neg":-0,"f":0.5}`},
		{"escapes", esc(`{"esc":"\"\\\/\b\f\n\r\t%u0000%u001f%u007f%u2028%ud83d%ude00é","ünï":true}`)},
	} {
		doc, err := jsonv.Parse([]byte(c.doc))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := files.Rendering(doc)
		sum := sha256.Sum256(r)
		if !utf8.Valid(r) {
			t.Fatalf("%s: not UTF-8", c.name)
		}
		vs = append(vs, obj{{Key: "name", Value: c.name}, {Key: "fn", Value: "files.Rendering"}, {Key: "document", Value: c.doc},
			{Key: "rendering", Value: string(r)}, {Key: "bytes", Value: len(r)}, {Key: "sha256", Value: golden.Hex(sum[:])}})
	}
	golden.Check(t, "renderings", obj{
		{Key: "section", Value: "§H.1"},
		{Key: "about", Value: "file renderings: the canonical JSON of the document without a fresh $nonce or a $successor of §8.1's form, laid out as JSON.stringify(value, null, 2) with JCS member order, one final LF"},
		{Key: "vectors", Value: vs},
	})
}
