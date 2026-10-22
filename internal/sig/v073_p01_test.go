package sig

import (
	"strings"
	"testing"
)

// §C.3.1 (GR-37): <sig> is exactly 86 base64url characters without
// padding, whatever the alg or kid.
func TestV073ParseSigLength(t *testing.T) {
	ok := strings.Repeat("A", 86)
	for _, h := range []string{"Ed25519:k:" + ok, "other:k:" + ok} {
		s, err := Parse(h)
		if err != nil || len(s.Sig) != 64 {
			t.Errorf("Parse(%q): %v", h, err)
		}
	}
	for _, h := range []string{
		"Ed25519:k:abcd",
		"Ed25519:k:" + strings.Repeat("A", 85),
		"Ed25519:k:" + strings.Repeat("A", 87),
		"Ed25519:k:" + strings.Repeat("A", 88),
		"Ed25519:k:" + strings.Repeat("A", 84) + "==",
		"Ed25519:k:" + strings.Repeat("A", 85) + "/",
		"Ed25519:k:x:" + ok,
		"Ed25519::" + ok,
	} {
		if _, err := Parse(h); err == nil {
			t.Errorf("Parse(%q) accepted", h)
		}
	}
}
