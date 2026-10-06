package grant

import (
	"crypto/ed25519"
	"testing"

	"github.com/middle-management/patchlog/internal/sig"
)

// §C.3.1: root blocks may list signers; an invalid list, or signers in a
// narrowing block, makes the grant invalid (401).
func TestSigners(t *testing.T) {
	f := newFixture(t, nil)
	k := sig.Key{Kid: "s1", Priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
	g := roundtrip(t, mustMint(t, f, map[string]any{"signers": []any{k.Entry()}}))
	if len(g.Blocks[0].Signers) != 1 || g.Blocks[0].Signers[0].Kid != "s1" {
		t.Fatalf("signers %+v", g.Blocks[0].Signers)
	}
	if _, err := Verify(g, f.env()); err != nil {
		t.Fatal(err)
	}
	bad := k.Entry()
	bad["alg"] = "RS256"
	for _, s := range []any{"x", []any{bad}, []any{k.Entry(), k.Entry()}, []any{map[string]any{"kid": "a:b", "alg": "Ed25519", "pub": k.Entry()["pub"]}}} {
		if _, err := Mint(rootBlock(map[string]any{"signers": s}), f.priv); err == nil {
			t.Fatalf("signers %v accepted", s)
		}
	}
	// A narrowing block can't carry them: Narrow refuses, and a token
	// built anyway doesn't decode.
	if _, err := g.Narrow(map[string]any{"signers": []any{k.Entry()}}); err == nil {
		t.Fatal("Narrow accepted signers")
	}
	n, err := mustMint(t, f, nil).NarrowUnvalidated(map[string]any{"signers": []any{k.Entry()}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(n.Encode(), 8192)
	wantStatus(t, err, 401)
	// The stored form's blocks are the token's SignedBlocks.
	if sb := g.SignedBlocks(); len(sb) != 1 || len(sb[0]) == 0 {
		t.Fatalf("signed blocks %v", sb)
	}
}
