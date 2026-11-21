package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// P36 LEVELS-KEYS-BRANCHES: keys and remote branches after a raise to e2e
// (Addendum E Levels, §E.2.3, §G.3, §G.5.2).

// p36Keys is a 200 /keys answer's entries, unwrapped with priv, by kid
// ("kid name" for a K_r).
func p36Keys(t *testing.T, r *resp, unwrap func(seal.WrappedKey) ([]byte, error)) map[string][]byte {
	t.Helper()
	expect(t, r, 200)
	out := map[string][]byte{}
	for _, x := range keyEntries(t, r) {
		w, err := seal.ParseWrappedKey(x)
		if err != nil {
			t.Fatal(err)
		}
		label := w.Kid
		if w.Resource != "" {
			label += " " + w.Resource
		}
		k, err := unwrap(w)
		if err != nil {
			t.Fatalf("unwrapping %s: %v", label, err)
		}
		out[label] = k
	}
	return out
}
