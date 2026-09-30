package seal

import (
	"encoding/base64"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func TestParseRecipientPrivate(t *testing.T) {
	_, priv, err := GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	jwk := jsonv.Canonical(RecipientPrivateJWK(priv))
	bare := []byte(base64.RawURLEncoding.EncodeToString(priv.Bytes()) + "\n")
	for _, in := range [][]byte{jwk, bare} {
		got, err := ParseRecipientPrivate(in)
		if err != nil || !got.Equal(priv) {
			t.Fatalf("%s: %v", in, err)
		}
	}
	_, other, _ := GenerateRecipient()
	bad := RecipientPrivateJWK(priv)
	bad["x"] = RecipientJWK(other.PublicKey())["x"]
	for _, in := range [][]byte{jsonv.Canonical(bad), []byte("xx"), []byte(`{"kty":"OKP","crv":"Ed25519","d":"AA"}`)} {
		if _, err := ParseRecipientPrivate(in); err == nil {
			t.Fatalf("%s: parsed", in)
		}
	}
}
