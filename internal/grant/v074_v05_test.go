package grant

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// GRANTS-1 (§C.8, CONFORMANCE Grant scope 52): only Biscuit's version 1
// payload verifies. A block correctly signed over the version 0 payload,
// which doesn't bind the previous signature, makes the token invalid.
func TestV074BearerVersion0Refused(t *testing.T) {
	f := newFixture(t, nil)
	m := mustMint(t, f, nil)
	n, err := m.Narrow(map[string]any{"can": []string{"read"}, "via": "svc:x"})
	if err != nil {
		t.Fatal(err)
	}
	// The v1 token verifies.
	if _, err := Verify(decodeOK(t, n.Encode()), f.env()); err != nil {
		t.Fatal(err)
	}

	// The narrowing block re-signed over the version 0 payload by the
	// authority block's next key: a valid signature for that payload.
	b0 := n.c.blocks[0]
	sb := n.c.blocks[1]
	sb.version = 0
	sb.sig = ed25519.Sign(m.proof, sb.payload(b0.sig))
	if !ed25519.Verify(b0.nextKey, sb.payload(b0.sig), sb.sig) {
		t.Fatal("the v0 signature should be valid for its payload")
	}
	c := &container{blocks: []signedBlock{b0, sb}, nextSecret: n.c.nextSecret}
	_, err = Decode(b64tok(c.encode()), 0)
	wantStatus(t, err, 401)
	if !strings.Contains(err.Error(), "version 1 payload") {
		t.Fatalf("refused for another reason: %v", err)
	}

	// The authority block signed over the version 0 payload by the
	// namespace key.
	a := m.c.blocks[0]
	a.version = 0
	a.sig = ed25519.Sign(f.priv, a.payload(nil))
	c = &container{blocks: []signedBlock{a}, nextSecret: m.c.nextSecret}
	_, err = Decode(b64tok(c.encode()), 0)
	wantStatus(t, err, 401)

	// The same authority block as a stored form (§C.3) from before v0.74
	// still parses and verifies under the key.
	st, err := ParseStoredBlock(a.encode())
	if err != nil || !st.SignedBy(f.priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("stored v0 authority block: %v", err)
	}
}
