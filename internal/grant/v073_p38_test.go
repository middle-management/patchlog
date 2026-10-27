package grant

// Spec v0.73, package P38 (CIS-38, GR-1, GR-27): Biscuit encodings for
// Addendum I (§C.8), with a token failing each acceptance rule, and
// revocation ids (§C.4). They are built here, beside the encoder, because
// the production minting path draws each block's next key at random and
// refuses to build the tokens a verifier must reject: the tokens below use
// the encoder's own pieces (encodeBlockData, signedBlock.payload and
// encode, container.encode, the protobuf writers) with fixed next keys, so
// they reproduce byte for byte, and the valid one's blocks are checked to
// be byte-identical to what Mint and Narrow write. The vectors are kept in
// internal/vectors/testdata/biscuit.json (internal/vectors/golden).

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// p38Seed is the 32 bytes n, n+1, … n+31.
func p38Seed(n byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n + byte(i)
	}
	return b
}

// The root key is the Ed25519 key with seed 00 01 … 1f, as the library
// tokens of biscuit_vectors_test.go; block i's next key has seed
// p38Seed(0x40 + 0x20·i).
var p38Root = ed25519.NewKeyFromSeed(p38Seed(0x00))

func p38Next(i int) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(p38Seed(byte(0x40 + 0x20*i))) }

// The valid token's blocks: I.4's root block, and a narrowing block.
const (
	p38RootBlock   = `{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}`
	p38NarrowBlock = `{"can":["read"],"via":"svc:reader"}`
)

// p38Signed signs data as block i of a token, as newBlock does but with
// the fixed next key p38Next(i).
func p38Signed(key ed25519.PrivateKey, i int, data, prevSig []byte) signedBlock {
	sb := signedBlock{data: data, nextKey: p38Next(i).Public().(ed25519.PublicKey), version: sigVersion}
	sb.sig = ed25519.Sign(key, sb.payload(prevSig))
	return sb
}

// p38Token is a bearer token of the given block data, each signed in turn
// (the authority block by the root key, each next one by the previous
// block's next key), with the last next key as its proof.
func p38Token(datas ...[]byte) (string, *container) {
	c := &container{}
	key := p38Root
	var prev []byte
	for i, d := range datas {
		sb := p38Signed(key, i, d, prev)
		c.blocks = append(c.blocks, sb)
		key, prev = p38Next(i), sb.sig
	}
	c.nextSecret = p38Next(len(datas) - 1).Seed()
	return base64.URLEncoding.EncodeToString(c.encode()), c
}

// p38Fact is the Fact grant_block(<str>) with the symbol indices given.
func p38Fact(name, str uint64) []byte {
	pred := pbBytes(pbUint(nil, 1, name), 2, pbUint(nil, 3, str))
	return pbBytes(nil, 1, pred)
}

// p38Data is the Block data of a block holding grant_block(json) as the
// authority block of a token (symbols 1024 grant_block, 1025 json), with
// extra Block fields appended.
func p38Data(json string, extra ...[]byte) []byte {
	var b []byte
	b = pbBytes(b, 1, []byte(factName))
	b = pbBytes(b, 1, []byte(json))
	b = pbUint(b, 3, blockVersion)
	b = pbBytes(b, 4, p38Fact(symbolOffset, symbolOffset+1))
	for _, x := range extra {
		b = append(b, x...)
	}
	return b
}

func TestVectorBiscuit(t *testing.T) {
	rootPub := p38Root.Public().(ed25519.PublicKey)
	rootData, syms := encodeBlockData(p38RootBlock, nil)
	narrowData, _ := encodeBlockData(p38NarrowBlock, syms)
	valid, _ := p38Token(rootData, narrowData)

	// The encoder's blocks are Mint's and Narrow's, byte for byte; only
	// the next keys, drawn at random there, differ.
	m, err := Mint(jsonv.MustParse([]byte(p38RootBlock)).(map[string]any), p38Root)
	if err != nil {
		t.Fatal(err)
	}
	n, err := m.Narrow(jsonv.MustParse([]byte(p38NarrowBlock)).(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n.c.blocks[0].data, rootData) || !bytes.Equal(n.c.blocks[1].data, narrowData) || n.c.blocks[1].version != sigVersion {
		t.Fatal("the vector's blocks aren't the ones Mint and Narrow write")
	}
	if !bytes.Equal(p38Data(p38RootBlock), rootData) {
		t.Fatal("p38Data doesn't build the authority block as encodeBlockData does")
	}

	// A refused token names the §C.8 rule it breaks; why is a fragment of
	// the reference's error, checked here so that each token fails that
	// rule and no other, but not stored: error text isn't vector content.
	type tokenCase struct {
		name, token, rule, why string
	}
	var cases []tokenCase
	add := func(name, rule, why string, datas ...[]byte) {
		tok, _ := p38Token(datas...)
		cases = append(cases, tokenCase{name, tok, rule, why})
	}
	cases = append(cases, tokenCase{"valid: root block and one narrowing block", valid, "§C.8", ""})
	sealed, err := mustDecode(t, valid).Seal()
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, tokenCase{"valid: the same token sealed", sealed.Encode(), "§C.8 Sealed tokens", ""})

	fact := p38Fact(symbolOffset, symbolOffset+1)
	pred := pbBytes(pbUint(nil, 1, symbolOffset), 2, pbUint(nil, 3, symbolOffset+1))
	rule := pbBytes(pbBytes(nil, 1, pred), 2, pred) // Rule { head, body }
	add("a second fact", "one block, one fact", "exactly one fact", p38Data(p38RootBlock, pbBytes(nil, 4, fact)))
	// A block without a fact: the symbols and version, no Fact.
	{
		var d []byte
		d = pbBytes(d, 1, []byte(factName))
		d = pbBytes(d, 1, []byte(p38RootBlock))
		d = pbUint(d, 3, blockVersion)
		add("a block without a fact", "one block, one fact", "exactly one fact", d)
	}
	add("a rule", "no rules", "must not have rules", p38Data(p38RootBlock, pbBytes(nil, 5, rule)))
	add("a check", "no checks", "must not have checks", p38Data(p38RootBlock, pbBytes(nil, 6, pbBytes(nil, 1, rule))))
	add("a scope", "no scopes", "must not have scopes", p38Data(p38RootBlock, pbBytes(nil, 7, pbUint(nil, 1, 0))))
	add("a public key", "no public keys", "must not have public keys", p38Data(p38RootBlock, pbBytes(nil, 8, encodePublicKey(p38Next(9).Public().(ed25519.PublicKey)))))
	add("a context", "only an empty context (biscuit-go writes one)", "must not have a context", append(pbBytes(nil, 2, []byte("ctx")), rootData...))
	add("an unused symbol", "nothing outside the one fact", "unused symbol", p38Data(p38RootBlock, pbBytes(nil, 1, []byte("spare"))))
	add("grant_block not canonical (members reordered)", "the string equals its canonical form", "not in canonical form",
		p38Data(`{"sub":"user:bob","can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[]}`))
	add("grant_block not canonical (whitespace)", "the string equals its canonical form", "not in canonical form",
		p38Data(strings.Replace(p38RootBlock, `,"sub"`, `, "sub"`, 1)))
	nonchar := strings.Replace(p38RootBlock, "user:bob", "user:bob"+string(rune(0xFFFE)), 1)
	add("grant_block with a noncharacter (U+FFFE, raw)", "I-JSON input without noncharacters (§3.1)", "noncharacter U+FFFE", p38Data(nonchar))
	add("grant_block with a noncharacter (U+FFFE, escaped)", "I-JSON input without noncharacters (§3.1)", "noncharacter U+FFFE",
		p38Data(strings.Replace(p38RootBlock, "user:bob", "user:bob"+"\\"+"ufffe", 1)))
	add(`"*" in can`, `"*" only in a key's can (§C.1, §C.4)`, `unknown verb "*"`, p38Data(strings.Replace(p38RootBlock, `["read","append"]`, `["*"]`, 1)))
	add("grant_block not I-JSON (a duplicate member)", "I-JSON", "duplicate key", p38Data(strings.Replace(p38RootBlock, `{"can"`, `{"sub":"user:eve","can"`, 1)))
	add("a narrowing block with a root member", "§C.1 narrowing blocks", `must not contain "sub"`, rootData, func() []byte { d, _ := encodeBlockData(`{"sub":"user:eve"}`, syms); return d }())

	// A third-party block: the narrowing block's SignedBlock carries an
	// externalSignature.
	{
		tok, c := p38Token(rootData, narrowData)
		_ = tok
		ext := pbBytes(pbBytes(nil, 1, make([]byte, 64)), 2, encodePublicKey(p38Next(9).Public().(ed25519.PublicKey)))
		blocks := [][]byte{c.blocks[0].encode(), append(c.blocks[1].encode(), pbBytes(nil, 4, ext)...)}
		cases = append(cases, tokenCase{"a third-party block", base64.URLEncoding.EncodeToString(p38Container(blocks, c.nextSecret)), "no third-party blocks", "third-party blocks"})
	}
	// A next key that isn't Ed25519: the authority block, then a
	// narrowing block, names a P-256 key (algorithm 1, SEC1 compressed)
	// and is signed over that payload.
	{
		b, _ := p38P256Block(t, p38Root, rootData, nil)
		cases = append(cases, tokenCase{"a next key that isn't Ed25519 (P-256)", base64.URLEncoding.EncodeToString(p38Container([][]byte{b}, p38Seed(0x50))), "every key Ed25519", "only Ed25519 keys"})
		root := p38Signed(p38Root, 0, rootData, nil)
		nb, _ := p38P256Block(t, p38Next(0), narrowData, root.sig)
		cases = append(cases, tokenCase{"a narrowing block whose next key isn't Ed25519 (P-256)", base64.URLEncoding.EncodeToString(p38Container([][]byte{root.encode(), nb}, p38Seed(0x50))), "every key Ed25519", "only Ed25519 keys"})
	}
	// A block signed by another key: it decodes, and fails the signature.
	{
		c := &container{blocks: []signedBlock{p38Signed(p38Next(7), 0, rootData, nil)}, nextSecret: p38Next(0).Seed()}
		cases = append(cases, tokenCase{"the authority block signed by another key", base64.URLEncoding.EncodeToString(c.encode()), "the signature chain", "bad root signature"})
	}
	// The authority block's signature with S + L in place of S: it
	// verifies under a lax check (R and S mod L are unchanged), and §C.8's
	// strict verification refuses it (RFC 8032 §5.1.7, S < L).
	{
		sb := p38Signed(p38Root, 0, rootData, nil)
		if !p38AddL(sb.sig[32:]) {
			t.Fatal("S + L doesn't fit 32 bytes")
		}
		c := &container{blocks: []signedBlock{sb}, nextSecret: p38Next(0).Seed()}
		cases = append(cases, tokenCase{"a signature with S + L (non-canonical S)", base64.URLEncoding.EncodeToString(c.encode()), "Ed25519 verified strictly, S < L", "bad root signature"})
	}

	var vs []any
	for _, c := range cases {
		v := golden.Obj{{Key: "name", Value: c.name}, {Key: "rule", Value: c.rule}, {Key: "token", Value: c.token}}
		g, err := DecodeLimited(c.token, Limits{})
		switch {
		case err != nil:
			v = append(v, golden.Member{Key: "fn", Value: "grant.DecodeLimited"}, golden.Member{Key: "verdict", Value: "401"})
			if !strings.Contains(err.Error(), c.why) {
				t.Errorf("%s: refused for another reason than %q: %v", c.name, c.rule, err)
			}
		case !g.SignedBy(rootPub):
			v = append(v, golden.Member{Key: "fn", Value: "grant.DecodeLimited, grant.Grant.SignedBy"}, golden.Member{Key: "verdict", Value: "401"})
			if err := g.verifyChain(rootPub); err == nil || !strings.Contains(err.Error(), c.why) {
				t.Errorf("%s: refused for another reason than %q: %v", c.name, c.rule, err)
			}
		default:
			var blocks []any
			for _, b := range g.Blocks {
				blocks = append(blocks, string(jsonv.Canonical(b.Raw)))
			}
			var sigs []any
			for _, sb := range g.c.blocks {
				sigs = append(sigs, golden.Hex(sb.sig))
			}
			v = append(v, golden.Member{Key: "fn", Value: "grant.DecodeLimited, grant.Grant.SignedBy, RevocationIDs, ID, Stored"},
				golden.Member{Key: "verdict", Value: "accept"},
				golden.Member{Key: "blocks", Value: blocks},
				golden.Member{Key: "signatures", Value: sigs},
				golden.Member{Key: "grant id", Value: g.ID().String()},
				golden.Member{Key: "revocation ids", Value: g.RevocationIDs()},
				golden.Member{Key: "stored", Value: golden.Hex(g.Stored())})
			// §C.4: the root block's revocation id is its grant id, a
			// narrowing block's text(trunc160(sha256(its signature))).
			r := g.RevocationIDs()
			if r[0] != ids.Of([]byte(p38RootBlock)).String() || r[0] != "15swdvi5nbnlkv76v7y6k77h52atov6ru" {
				t.Errorf("%s: root revocation id %s", c.name, r[0])
			}
			if len(r) > 1 && r[1] != ids.Of(g.c.blocks[1].sig).String() {
				t.Errorf("%s: narrowing revocation id %s", c.name, r[1])
			}
			if !strings.HasPrefix(c.name, "valid") {
				t.Errorf("%s: accepted", c.name)
			}
		}
		if strings.HasPrefix(c.name, "valid") && v[4].Value != "accept" {
			t.Errorf("%s: refused: %v", c.name, v[5].Value)
		}
		vs = append(vs, v)
	}
	golden.Check(t, "biscuit", golden.Obj{
		{Key: "section", Value: "§C.8, §C.4"},
		{Key: "about", Value: "grants as Biscuit v3 tokens (URL-safe base64): one fact grant_block(<canonical JSON>) per block, Ed25519 throughout, signature payload version 1. Root key: the Ed25519 key with seed 00 01 … 1f; block i's next key has seed n, n+1, … n+31 with n = 0x40 + 0x20·i. Each refused token is the valid one with one rule broken, signed as a writer would, so only that rule fails"},
		{Key: "root public key", Value: base64.RawURLEncoding.EncodeToString(rootPub)},
		{Key: "vectors", Value: vs},
	})
}

// p38P256Block is a SignedBlock of data whose next key is a P-256 key
// (algorithm 1, SEC1 compressed, private key p38Seed(0x50)), signed by key
// over the payload naming that algorithm, after the block whose signature
// is prevSig (nil for the authority block). It returns the encoded block
// and its signature.
func p38P256Block(t *testing.T, key ed25519.PrivateKey, data, prevSig []byte) ([]byte, []byte) {
	t.Helper()
	p, err := ecdh.P256().NewPrivateKey(p38Seed(0x50))
	if err != nil {
		t.Fatal(err)
	}
	u := p.PublicKey().Bytes() // 0x04 ‖ x ‖ y
	comp := append([]byte{0x02 | u[64]&1}, u[1:33]...)
	sb := signedBlock{data: data, nextKey: comp, version: sigVersion}
	payload := bytes.Replace(sb.payload(prevSig), []byte("\x00ALGORITHM\x00\x00\x00\x00\x00"), []byte("\x00ALGORITHM\x00\x01\x00\x00\x00"), 1)
	sb.sig = ed25519.Sign(key, payload)
	var b []byte
	b = pbBytes(b, 1, sb.data)
	b = pbBytes(b, 2, pbBytes(pbUint(nil, 1, 1), 2, comp))
	b = pbBytes(b, 3, sb.sig)
	b = pbUint(b, 5, sigVersion)
	return b, sb.sig
}

// p38L is the order of Ed25519's base point, 2^252 +
// 27742317777372353535851937790883648493, little-endian.
var p38L = [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}

// p38AddL adds L to the little-endian scalar s in place, reporting whether
// the sum fits its 32 bytes.
func p38AddL(s []byte) bool {
	carry := 0
	for i := range s {
		v := int(s[i]) + int(p38L[i]) + carry
		s[i], carry = byte(v), v>>8
	}
	return carry == 0
}

// p38Container encodes a bearer token of the SignedBlock messages given,
// with the proof's next secret.
func p38Container(blocks [][]byte, nextSecret []byte) []byte {
	var b []byte
	b = pbBytes(b, 2, blocks[0])
	for _, sb := range blocks[1:] {
		b = pbBytes(b, 3, sb)
	}
	return pbBytes(b, 4, pbBytes(nil, 1, nextSecret))
}

func mustDecode(t *testing.T, token string) *Grant {
	t.Helper()
	g, err := Decode(token, 0)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestVectorBiscuitCoversC8: biscuit.json has a refused token for each
// acceptance rule of §C.8, strict Ed25519 verification and a block without
// a fact among them, and stores no error text.
func TestVectorBiscuitCoversC8(t *testing.T) {
	var f struct {
		Vectors []map[string]any `json:"vectors"`
	}
	if !golden.Load(t, "biscuit", &f) {
		t.Fatal("biscuit.json is missing")
	}
	refused := map[string]bool{}
	for _, v := range f.Vectors {
		if _, ok := v["because"]; ok {
			t.Errorf("%s: stores the reference's error text", v["name"])
		}
		if v["verdict"] == "401" {
			refused[v["name"].(string)] = true
		}
	}
	for _, name := range []string{"a second fact", "a block without a fact", "a rule", "a check", "a scope", "a public key",
		"a third-party block", "a next key that isn't Ed25519 (P-256)", "a narrowing block whose next key isn't Ed25519 (P-256)",
		"a signature with S + L (non-canonical S)", "grant_block not canonical (whitespace)",
		"grant_block with a noncharacter (U+FFFE, raw)", `"*" in can`} {
		if !refused[name] {
			t.Errorf("no refused token %q", name)
		}
	}
}
