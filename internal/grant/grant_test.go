package grant

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
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
	wantStatus(t, err, 401)
	// Narrowing cannot widen exp beyond the root's.
	w, _ := g.Narrow(map[string]any{"exp": ts(48 * time.Hour)})
	env.Now = now.Add(2 * time.Hour)
	_, err = Verify(roundtrip(t, w), env)
	wantStatus(t, err, 401)
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
	data, _ := encodeBlockData(`{"sub":"user:eve"}`, g.symbols)
	_, err := Decode(appendRaw(g, data), 0)
	wantStatus(t, err, 401)
	// Verbs: "*" is never valid in a grant.
	if _, err := Mint(rootBlock(map[string]any{"can": []string{"*"}}), f.priv); err == nil {
		t.Fatal("* accepted in grant")
	}
}

// appendRaw appends a block with arbitrary Block data, correctly signed.
func appendRaw(g *Grant, data []byte) string {
	prev := g.c.blocks[len(g.c.blocks)-1]
	sb, next := newBlock(g.proof, data, prev.sig)
	c := &container{blocks: append(append([]signedBlock(nil), g.c.blocks...), sb), nextSecret: next.Seed()}
	return base64.URLEncoding.EncodeToString(c.encode())
}

// mintRaw signs arbitrary authority Block data with priv.
func mintRaw(priv ed25519.PrivateKey, data []byte) string {
	sb, next := newBlock(priv, data, nil)
	return base64.URLEncoding.EncodeToString((&container{blocks: []signedBlock{sb}, nextSecret: next.Seed()}).encode())
}

func tokenBytes(t *testing.T, tok string) []byte {
	t.Helper()
	b, err := base64.URLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64tok(b []byte) string { return base64.URLEncoding.EncodeToString(b) }

// replaceOnce replaces exactly one occurrence of old in b.
func replaceOnce(t *testing.T, b []byte, old, new string) []byte {
	t.Helper()
	if bytes.Count(b, []byte(old)) != 1 || len(old) != len(new) {
		t.Fatalf("%q must occur once", old)
	}
	return bytes.Replace(b, []byte(old), []byte(new), 1)
}

func decodeOK(t *testing.T, tok string) *Grant {
	t.Helper()
	g, err := Decode(tok, 0)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestTampering(t *testing.T) {
	f := newFixture(t, nil)
	g, _ := mustMint(t, f, nil).Narrow(map[string]any{"can": []string{"read"}, "via": "svc:x"})
	tok := g.Encode()
	raw := tokenBytes(t, tok)

	// Tampered root block: the root signature fails.
	d := decodeOK(t, b64tok(replaceOnce(t, raw, "user:bob", "user:bab")))
	_, err := Verify(d, f.env())
	wantStatus(t, err, 401)

	// Tampered narrowing block.
	d = decodeOK(t, b64tok(replaceOnce(t, raw, "svc:x", "svc:y")))
	_, err = Verify(d, f.env())
	wantStatus(t, err, 401)

	// Dropping the narrowing block: the proof no longer matches.
	c := &container{blocks: g.c.blocks[:1], nextSecret: g.c.nextSecret}
	_, err = Verify(decodeOK(t, b64tok(c.encode())), f.env())
	wantStatus(t, err, 401)

	// Reordered blocks can't even be parsed as a grant (the root block is
	// the authority block).
	c = &container{blocks: []signedBlock{g.c.blocks[1], g.c.blocks[0]}, nextSecret: g.c.nextSecret}
	_, err = Decode(b64tok(c.encode()), 0)
	wantStatus(t, err, 401)

	// Tampered signature.
	sig := append([]byte(nil), g.c.blocks[1].sig...)
	sig[5] ^= 1
	c = &container{blocks: []signedBlock{g.c.blocks[0], {data: g.c.blocks[1].data, nextKey: g.c.blocks[1].nextKey, sig: sig, version: 1}}, nextSecret: g.c.nextSecret}
	_, err = Verify(decodeOK(t, b64tok(c.encode())), f.env())
	wantStatus(t, err, 401)

	// Wrong signature version: the payload differs.
	c = &container{blocks: []signedBlock{g.c.blocks[0], {data: g.c.blocks[1].data, nextKey: g.c.blocks[1].nextKey, sig: g.c.blocks[1].sig, version: 0}}, nextSecret: g.c.nextSecret}
	_, err = Verify(decodeOK(t, b64tok(c.encode())), f.env())
	wantStatus(t, err, 401)

	// Missing and wrong proof.
	c = &container{blocks: g.c.blocks}
	_, err = Decode(b64tok(c.encode()), 0)
	wantStatus(t, err, 401)
	_, other := GenerateKey()
	c = &container{blocks: g.c.blocks, nextSecret: other.Seed()}
	_, err = Verify(decodeOK(t, b64tok(c.encode())), f.env())
	wantStatus(t, err, 401)

	// Unknown protobuf fields, at the top level and in a signed block.
	_, err = Decode(b64tok(pbUint(append([]byte(nil), raw...), 9, 1)), 0)
	wantStatus(t, err, 401)

	// Garbage, trailing bytes and size.
	for _, bad := range []string{"!!!", "", "AAAA", b64tok(append(append([]byte(nil), raw...), 0xff))} {
		_, err = Decode(bad, 0)
		wantStatus(t, err, 401)
	}
	if _, err := Decode(tok, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

// The size limit (§6.6) applies to the decoded bytes, not the text.
func TestSizeOnDecodedBytes(t *testing.T) {
	f := newFixture(t, nil)
	tok := mustMint(t, f, nil).Encode()
	n := len(tokenBytes(t, tok))
	if len(tok) <= n {
		t.Fatal("base64 should be longer")
	}
	if _, err := Decode(tok, n); err != nil {
		t.Fatalf("token of exactly the limit refused: %v", err)
	}
	if _, err := Decode(tok, n-1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestTransport(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	tok := g.Encode()
	if strings.HasPrefix(tok, "biscuit:") {
		t.Fatal("tokens are written without the prefix")
	}
	for _, s := range []string{tok, "biscuit:" + tok, strings.TrimRight(tok, "="), "biscuit:" + strings.TrimRight(tok, "=")} {
		d, err := Decode(s, 8192)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if _, err := Verify(d, f.env()); err != nil {
			t.Fatal(err)
		}
	}
	// Standard (non-URL-safe) base64 is refused.
	std := base64.StdEncoding.EncodeToString(tokenBytes(t, tok))
	if std != tok {
		_, err := Decode(std, 0)
		wantStatus(t, err, 401)
	}
}

// Ed25519 is verified strictly (RFC 8032): a signature whose S is not
// reduced (S + L, which a lax verifier would accept) is refused.
func TestNonCanonicalS(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	sig := append([]byte(nil), g.c.blocks[0].sig...)
	// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
	l := []byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	carry := 0
	for i := 0; i < 32; i++ {
		v := int(sig[32+i]) + int(l[i]) + carry
		sig[32+i], carry = byte(v), v>>8
	}
	if carry != 0 {
		t.Fatal("overflow")
	}
	c := &container{blocks: []signedBlock{{data: g.c.blocks[0].data, nextKey: g.c.blocks[0].nextKey, sig: sig, version: 1}}, nextSecret: g.c.nextSecret}
	_, err := Verify(decodeOK(t, b64tok(c.encode())), f.env())
	wantStatus(t, err, 401)
}

// §C.8: each block holds exactly one fact grant_block(<canonical JSON>)
// and nothing else.
func TestBlockContent(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	good, _ := encodeBlockData(`{"via":"svc"}`, g.symbols)
	if _, err := Verify(decodeOK(t, appendRaw(g, good)), f.env()); err != nil {
		t.Fatal(err)
	}
	// A second fact, reusing the fact's own symbols.
	m, _ := schemaBlock.parse("Block", good)
	twoFacts := append(append([]byte(nil), good...), pbBytes(nil, 4, m[4][0].b)...)
	cases := map[string][]byte{
		"two facts":        twoFacts,
		"rule":             pbBytes(append([]byte(nil), good...), 5, pbBytes(nil, 1, m[4][0].b)),
		"check":            pbBytes(append([]byte(nil), good...), 6, nil),
		"scope":            pbBytes(append([]byte(nil), good...), 7, pbUint(nil, 1, 0)),
		"public key":       pbBytes(append([]byte(nil), good...), 8, encodePublicKey(g.c.blocks[0].nextKey)),
		"context":          pbBytes(append([]byte(nil), good...), 2, []byte("hello")),
		"no fact":          pbUint(nil, 3, blockVersion),
		"unknown field":    pbUint(append([]byte(nil), good...), 12, 1),
		"old version":      replaceVersion(good, 2),
		"future version":   replaceVersion(good, 7),
		"other name":       otherName(g),
		"unused symbol":    append(pbBytes(nil, 1, []byte("smuggled")), good...),
		"not canonical":    mustEncode(`{"via": "svc"}`, g),
		"not I-JSON":       mustEncode(`{"via":"a","via":"b"}`, g),
		"not an object":    mustEncode(`["via"]`, g),
		"integer too big":  mustEncode(`{"rules":[9007199254740993]}`, g),
		"unsorted members": mustEncode(`{"via":"svc","can":["read"]}`, g),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(appendRaw(g, data), 0)
			wantStatus(t, err, 401)
		})
	}
	// The same rules hold for the authority block.
	_, err := Decode(mintRaw(f.priv, mustEncode(`{"can":["read"],"exp":"2026-10-04T13:00:00Z","kid":"k1","ns":["matches"],"sub": "u"}`, nil)), 0)
	wantStatus(t, err, 401)
	root, _ := encodeBlockData(`{"can":["read"],"exp":"2026-10-04T13:00:00Z","kid":"k1","ns":["matches"],"sub":"u"}`, nil)
	if _, err := Verify(decodeOK(t, mintRaw(f.priv, root)), f.env()); err != nil {
		t.Fatal(err)
	}
}

func mustEncode(json string, g *Grant) []byte {
	var syms []string
	if g != nil {
		syms = g.symbols
	}
	d, _ := encodeBlockData(json, syms)
	return d
}

// otherName is a block whose one fact is right("{…}"): a default symbol
// for the name.
func otherName(g *Grant) []byte {
	json := `{"via":"svc"}`
	term := pbUint(nil, 3, uint64(symbolOffset+len(g.symbols)))
	fact := pbBytes(nil, 1, pbBytes(pbUint(nil, 1, 4), 2, term))
	b := pbBytes(nil, 1, []byte(json))
	b = pbUint(b, 3, blockVersion)
	return pbBytes(b, 4, fact)
}

func replaceVersion(data []byte, v uint64) []byte {
	m, _ := schemaBlock.parse("Block", data)
	var b []byte
	for _, f := range m[1] {
		b = pbBytes(b, 1, f.b)
	}
	b = pbUint(b, 3, v)
	return pbBytes(b, 4, m[4][0].b)
}

// A third-party block (one with an external signature) makes the token
// invalid, as does any algorithm but Ed25519.
func TestThirdPartyAndAlgorithm(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	n, _ := g.Narrow(map[string]any{"via": "svc"})
	sb := n.c.blocks[1]
	ext := pbBytes(pbBytes(nil, 1, sb.sig), 2, encodePublicKey(sb.nextKey))
	enc := pbBytes(sb.encode(), 4, ext)
	var b []byte
	b = pbBytes(b, 2, n.c.blocks[0].encode())
	b = pbBytes(b, 3, enc)
	b = pbBytes(b, 4, pbBytes(nil, 1, n.c.nextSecret))
	_, err := Decode(b64tok(b), 0)
	wantStatus(t, err, 401)

	// A P-256 next key.
	pk := pbBytes(pbUint(nil, 1, 1), 2, append([]byte{2}, make([]byte, 32)...))
	sb0 := g.c.blocks[0]
	var blk []byte
	blk = pbBytes(blk, 1, sb0.data)
	blk = pbBytes(blk, 2, pk)
	blk = pbBytes(blk, 3, sb0.sig)
	_, err = Decode(b64tok(pbBytes(pbBytes(nil, 2, blk), 4, pbBytes(nil, 1, g.c.nextSecret))), 0)
	wantStatus(t, err, 401)
}

func TestRevocation(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	n, _ := g.Narrow(map[string]any{"via": "svc:x"})
	// A re-serialisation (here with a rootKeyId, which is ignored) keeps
	// the revocation ids: they are over the block signatures.
	re := b64tok(append(pbUint(nil, 1, 7), tokenBytes(t, n.Encode())...))
	d := decodeOK(t, re)
	if _, err := Verify(d, f.env()); err != nil {
		t.Fatal(err)
	}
	if d.RevocationIDs()[0] != g.RevocationIDs()[0] || len(d.RevocationIDs()) != 2 {
		t.Fatal("revocation ids unstable")
	}
	if g.RevocationIDs()[0] != ids.Of(g.c.blocks[0].sig).String() {
		t.Fatal("revocation id is text(trunc160(sha256(sig)))")
	}
	// Revoking the authority block revokes everything narrowed from it.
	env := f.env()
	env.Revoked = map[string]bool{g.RevocationIDs()[0]: true}
	_, err := Verify(d, env)
	wantStatus(t, err, 401)
	s, _ := n.Seal()
	_, err = Verify(roundtrip(t, s), env)
	wantStatus(t, err, 401)
	env.Revoked = map[string]bool{d.RevocationIDs()[1]: true}
	_, err = Verify(d, env)
	wantStatus(t, err, 401)
	if _, err := Verify(roundtrip(t, g), env); err != nil {
		t.Fatal("revoking a narrowing block must not revoke the root")
	}
}

func TestSeal(t *testing.T) {
	f := newFixture(t, nil)
	g := mustMint(t, f, nil)
	n, _ := g.Narrow(map[string]any{"can": []string{"read"}})
	for _, x := range []*Grant{g, n} {
		s, err := x.Seal()
		if err != nil {
			t.Fatal(err)
		}
		d := roundtrip(t, s)
		if !d.Sealed() || d.HasProof() || d.ID() != g.ID() {
			t.Fatal("sealed flags")
		}
		v, err := Verify(d, f.env())
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Grant.Blocks) != len(x.Blocks) {
			t.Fatal("blocks")
		}
		if _, err := d.Narrow(map[string]any{"via": "x"}); err == nil {
			t.Fatal("narrowed a sealed grant")
		}
		if _, err := d.Seal(); err == nil {
			t.Fatal("sealed twice")
		}
		// A bad final signature.
		fs := append([]byte(nil), d.c.finalSig...)
		fs[0] ^= 1
		c := &container{blocks: d.c.blocks, finalSig: fs}
		_, err = Verify(decodeOK(t, b64tok(c.encode())), f.env())
		wantStatus(t, err, 401)
		// The stored form of a sealed grant.
		p, err := ParseStored(d.Stored())
		if err != nil || p.ID() != g.ID() {
			t.Fatal(err)
		}
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

	// Expired and not yet valid grants are no usable grant (§C.2).
	g = roundtrip(t, mustMint(t, f, map[string]any{"exp": ts(-time.Minute)}))
	_, err = Verify(g, f.env())
	wantStatus(t, err, 401)
	g = roundtrip(t, mustMint(t, f, map[string]any{"nbf": ts(time.Minute)}))
	_, err = Verify(g, f.env())
	wantStatus(t, err, 401)
	env := f.env()
	env.Now = now.Add(time.Minute)
	if _, err := Verify(g, env); err != nil {
		t.Fatal(err)
	}
	if _, err := Mint(rootBlock(map[string]any{"exp": nil}), f.priv); err == nil {
		t.Fatal("root without exp accepted")
	}
}

// A grant verified once (and kept, as core keeps decoded grants by token)
// skips only its signature check when verified again, and only under the
// same root key: times, revocation and key scope are checked every time.
func TestVerifyAgain(t *testing.T) {
	f := newFixture(t, nil)
	g := roundtrip(t, mustMint(t, f, nil))
	for i := 0; i < 2; i++ {
		if _, err := Verify(g, f.env()); err != nil {
			t.Fatal(err)
		}
	}
	// Another key under the same kid.
	other := newFixture(t, nil)
	_, err := Verify(g, other.env())
	wantStatus(t, err, 401)
	if _, err := Verify(g, f.env()); err != nil {
		t.Fatal(err)
	}
	env := f.env()
	env.Now = now.Add(2 * time.Hour)
	_, err = Verify(g, env)
	wantStatus(t, err, 401)
	env = f.env()
	env.Revoked = map[string]bool{g.RevocationIDs()[0]: true}
	_, err = Verify(g, env)
	wantStatus(t, err, 401)
	scoped := newFixture(t, map[string]any{"can": []any{"read"}})
	scoped.keys[0].Pub = f.keys[0].Pub
	_, err = Verify(g, scoped.env())
	wantStatus(t, err, 403)
}

// The ns check comes first, before anything is verified (§C.2): a grant
// not naming the namespace is 403 even when it would also be a 401.
func TestNSCheckFirst(t *testing.T) {
	f := newFixture(t, nil)
	other := newFixture(t, nil)
	expired := roundtrip(t, mustMint(t, other, map[string]any{"exp": ts(-time.Minute)}))
	env := f.env()
	env.NS = "elsewhere"
	_, err := Verify(expired, env)
	wantStatus(t, err, 403)
	env.NS = "matches"
	_, err = Verify(expired, env)
	wantStatus(t, err, 401)
	// Every block that carries ns must name it.
	n, _ := mustMint(t, f, nil).Narrow(map[string]any{"ns": []string{"docs"}})
	d := roundtrip(t, n)
	if d.NamesNS("matches") || !d.NamesNS("docs") {
		t.Fatal("NamesNS")
	}
	_, err = Verify(d, f.env())
	wantStatus(t, err, 403)
}

// "*" in ns names every namespace, but only operator grants may use it
// (§C.4). From a namespace key it is refused with 403: the grant is valid,
// it just doesn't apply.
func TestStarNS(t *testing.T) {
	f := newFixture(t, nil)
	g := roundtrip(t, mustMint(t, f, map[string]any{"ns": []string{"*"}}))
	if !g.NamesNS("anything") {
		t.Fatal("* names every namespace")
	}
	_, err := Verify(g, f.env())
	wantStatus(t, err, 403)
	env := f.env()
	env.Operator = true
	env.NS = "new-ns"
	if _, err := Verify(g, env); err != nil {
		t.Fatal(err)
	}
	// Also when the namespace is named alongside "*".
	g = roundtrip(t, mustMint(t, f, map[string]any{"ns": []string{"matches", "*"}}))
	_, err = Verify(g, f.env())
	wantStatus(t, err, 403)
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
		{"requireAt default lag", map[string]any{"requireAt": "cat"}, map[string]any{"at": map[string]any{"ns": "cat", "id": "1" + strings.Repeat("a", 32)}}, false},
		{"requireAt key lag laxer", map[string]any{"requireAt": "cat", "maxLag": "PT5M"}, map[string]any{"at": map[string]any{"ns": "cat", "id": "1" + strings.Repeat("a", 32)}}, false},
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
			// A map at stopped being the head 2 minutes before issuance.
			env.CheckAt = func(req, at any, issued time.Time, keyMaxLag *time.Duration) error {
				if _, ok := at.(map[string]any); ok {
					next := issued.Add(-2 * time.Minute)
					if !HeadWithin(&next, issued, EffectiveMaxLag(nil, keyMaxLag)) {
						return errors.New("too old")
					}
				}
				return nil
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
	if bytes.Contains(s, g.proof.Seed()) {
		t.Fatal("stored form contains the proof")
	}
	p, err := ParseStored(s)
	if err != nil {
		t.Fatal(err)
	}
	if p.HasProof() || p.Sealed() || p.ID() != g.ID() || len(p.Blocks) != 2 {
		t.Fatal("stored parse")
	}
	if strings.Join(p.RevocationIDs(), ",") != strings.Join(g.RevocationIDs(), ",") {
		t.Fatal("stored revocation ids")
	}
	if _, err := p.Narrow(map[string]any{"via": "x"}); err == nil {
		t.Fatal("narrowed without proof")
	}
	// A stored grant is not a bearer token, and a token is not a stored grant.
	_, err = Decode(b64tok(s), 0)
	wantStatus(t, err, 401)
	if _, err := ParseStored(tokenBytes(t, g.Encode())); err == nil {
		t.Fatal("token accepted as stored form")
	}
	// Block signatures are still checked.
	bad := replaceOnce(t, append([]byte(nil), s...), "svc", "svd")
	if _, err := ParseStored(bad); err == nil {
		t.Fatal("tampered stored form accepted")
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

func TestIssuedAndMaxLag(t *testing.T) {
	ttl := time.Hour
	exp := now.Add(30 * time.Minute)
	nbf := now.Add(-50 * time.Minute)
	withTTL := &Key{MaxTTL: &ttl}
	cases := []struct {
		name string
		root Block
		key  *Key
		want time.Time
	}{
		{"nothing", Block{Exp: &exp}, &Key{}, now},
		{"nbf, no maxTtl", Block{Exp: &exp, Nbf: &nbf}, &Key{}, nbf},
		{"exp - maxTtl", Block{Exp: &exp}, withTTL, exp.Add(-ttl)},
		{"max(nbf, exp - maxTtl)", Block{Exp: &exp, Nbf: &nbf}, withTTL, exp.Add(-ttl)},
	}
	late := now.Add(-10 * time.Minute)
	cases = append(cases, struct {
		name string
		root Block
		key  *Key
		want time.Time
	}{"later nbf", Block{Exp: &exp, Nbf: &late}, withTTL, late})
	for _, c := range cases {
		if got := Issued(c.root, c.key, now); !got.Equal(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	m := 10 * time.Second
	h := 5 * time.Minute
	if EffectiveMaxLag(nil, nil) != 60*time.Second || EffectiveMaxLag(&h, nil) != h || EffectiveMaxLag(&h, &m) != m || EffectiveMaxLag(&m, &h) != m {
		t.Fatal("EffectiveMaxLag")
	}
	next := now.Add(-time.Minute)
	if !HeadWithin(nil, now, 0) || !HeadWithin(&next, now, time.Minute) || HeadWithin(&next, now, time.Minute-time.Millisecond) {
		t.Fatal("HeadWithin")
	}
}
