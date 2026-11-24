package seal

import (
	"strings"
	"testing"
)

// v0.90 §7.9 Sealed namespaces, §E.2.2 Filtered answers (CONFORMANCE
// Filtered reads 88): a filtered answer with no keys, as one sealed under
// K_n for a /ns/{ns} cookie, has "keys": [], never the member absent.
func TestV090BFilteredNoKeysIsEmptyArray(t *testing.T) {
	for _, keys := range [][]string{nil, {}} {
		pt := FilteredPlaintext([]any{}, keys)
		if !strings.Contains(string(pt), `"keys":[]`) {
			t.Fatalf("plaintext %s, want \"keys\": []", pt)
		}
		if _, ks, err := ParseFiltered(pt); err != nil || len(ks) != 0 {
			t.Fatalf("parsed back: %v %v", ks, err)
		}
	}
}
