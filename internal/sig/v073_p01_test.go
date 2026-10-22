package sig

import (
	"strings"
	"testing"
)

// §C.3.1 (GR-37): a request's <sig> is exactly 86 base64url characters
// without padding, whatever the alg or kid.
func TestV073ParseSigLength(t *testing.T) {
	ok := strings.Repeat("A", 86)
	for _, h := range []string{"Ed25519:k:" + ok, "other:k:" + ok} {
		s, err := ParseInput(h)
		if err != nil || len(s.Sig) != 64 {
			t.Errorf("ParseInput(%q): %v", h, err)
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
		if _, err := ParseInput(h); err == nil {
			t.Errorf("ParseInput(%q) accepted", h)
		}
	}
}

// §C.3.1 (GR-37): stored signatures keep the earlier form, unpadded
// base64url of any length, since a server at v0.55 stored an unlisted
// kid's signature whatever its length; only the shape is refused.
func TestV073ParseStoredSigAnyLength(t *testing.T) {
	for _, h := range []string{"Ed25519:other:AAAA", "Ed25519:k:" + strings.Repeat("A", 87), "x:k:" + strings.Repeat("A", 86)} {
		s, err := Parse(h)
		if err != nil {
			t.Errorf("Parse(%q): %v", h, err)
			continue
		}
		if s.String() != h {
			t.Errorf("Parse(%q).String() = %q", h, s.String())
		}
	}
	for _, h := range []string{
		"Ed25519:k:" + strings.Repeat("A", 84) + "==",
		"Ed25519:k:AA+A",
		"Ed25519:k:x:" + strings.Repeat("A", 86),
		"Ed25519::AAAA",
		"Ed25519:k:",
	} {
		if _, err := Parse(h); err == nil {
			t.Errorf("Parse(%q) accepted", h)
		}
	}
}
