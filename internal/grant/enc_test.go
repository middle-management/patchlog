package grant

import (
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// The root block may carry a recipient key for wrapped key responses
// (§E.2.3); it must be an X25519 JWK, and narrowing blocks can't carry it.
func TestEncField(t *testing.T) {
	_, priv := GenerateKey()
	jwk, rpriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]any{"kid": "k", "sub": "u", "ns": []any{"s"}, "can": []any{"read"}, "exp": ts(3600e9), "enc": jwk}
	g, err := Mint(root, priv)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(g.Encode(), 0)
	if err != nil || d.Blocks[0].Enc == nil || string(d.Blocks[0].Enc.Bytes()) != string(rpriv.PublicKey().Bytes()) {
		t.Fatalf("enc not parsed: %v", err)
	}
	for _, bad := range []any{"x", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}, map[string]any{"kty": "OKP", "crv": "X25519", "x": "AAAA"},
		map[string]any{"kty": "OKP", "crv": "X25519", "x": jwk["x"], "d": "secret"}} {
		root["enc"] = bad
		if _, err := Mint(root, priv); err == nil {
			t.Fatalf("enc %v accepted", bad)
		}
	}
	if _, err := g.Narrow(map[string]any{"enc": jwk}); err == nil {
		t.Fatal("a narrowing block carried enc")
	}
}
