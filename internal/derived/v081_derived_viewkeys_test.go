package derived

import (
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// KEYS-5 (SERVICES §E.2.6 Whole-response sealing, Per-entry sealing, View
// keys): a whole response is sealed under ViewKey(K_n, view) and an entry
// under ViewKey(K_r, view) of its resource, never under K_e, K_n or K_r
// themselves, so views count toward no epoch key's message bound (§E.2.1).
// The JWEs are opened here with seal directly, under keys derived in the
// test, not through OpenView and OpenItem.
func TestV081ViewKeys(t *testing.T) {
	ke := seal.NewKey()
	k := Key{NS: "n", Epoch: 3, K: ke}
	v := View{NS: "n", Target: "/n/at/1abc/children?min=a%20b&q=x"}
	kn, err := seal.NamespaceKey(ke, "n")
	if err != nil {
		t.Fatal(err)
	}
	kvn, err := seal.ViewKey(kn, v.Target)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := SealView(k, v, map[string]any{"children": []any{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.OpenExpect(whole, kvn, "n#3", v.PL()); err != nil {
		t.Fatalf("a whole response under ViewKey(K_n, view): %v", err)
	}
	for what, key := range map[string][]byte{"K_e": ke, "K_n": kn} {
		if _, err := seal.OpenExpect(whole, key, "n#3", v.PL()); !errors.Is(err, seal.ErrDecrypt) {
			t.Errorf("a whole response opened under %s alone: %v, want ErrDecrypt", what, err)
		}
	}
	// The view key binds the target's exact bytes: another spelling of the
	// same query (percent-encoding, order) is another key.
	other, _ := seal.ViewKey(kn, "/n/at/1abc/children?min=a+b&q=x")
	if _, err := seal.OpenExpect(whole, other, "n#3", v.PL()); !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("a whole response under another target's view key: %v, want ErrDecrypt", err)
	}

	// Per entry (scenario 61): ViewKey(K_r, view) of the entry's resource.
	kr, err := seal.ResourceKey(ke, "n", "r")
	if err != nil {
		t.Fatal(err)
	}
	kvr, err := seal.ViewKey(kr, v.Target)
	if err != nil {
		t.Fatal(err)
	}
	item, err := SealItem(k, v, "r", map[string]any{"title": "T"})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := seal.OpenExpect(item, kvr, "n#3", v.ItemPL("n", "r")); err != nil || string(pt) != `{"title":"T"}` {
		t.Fatalf("an entry under ViewKey(K_r, view): %q %v", pt, err)
	}
	for what, key := range map[string][]byte{"K_e": ke, "K_n": kn, "K_r": kr, "ViewKey(K_n, view)": kvn} {
		if _, err := seal.OpenExpect(item, key, "n#3", v.ItemPL("n", "r")); !errors.Is(err, seal.ErrDecrypt) {
			t.Errorf("an entry opened under %s: %v, want ErrDecrypt", what, err)
		}
	}

	// OpenView and OpenItem take the K_e and K_r a reader holds and derive
	// the same view keys.
	keyOf := func(kid string) []byte {
		if kid == "n#3" {
			return ke
		}
		return nil
	}
	if _, err := OpenView(whole, keyOf, v); err != nil {
		t.Fatalf("OpenView: %v", err)
	}
	if _, err := OpenItem(item, ItemKey(keyOf, "n", "r"), v, "n", "r"); err != nil {
		t.Fatalf("OpenItem: %v", err)
	}
	// A JWE of another view is a mismatch, judged on pl before any key is
	// derived.
	if _, err := OpenView(whole, keyOf, View{NS: "n", Target: "/n/at/1abc/children?q=y"}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("OpenView of another view: %v, want ErrMismatch", err)
	}
}

// KEYS-5: a value of another resource (§E.2.6 Values of another resource,
// a placement's file drawn from its item, §H.3) is sealed under the view
// key of that resource's K_r, with pl naming it and the response's view.
func TestV081ViewKeyOtherResource(t *testing.T) {
	ke := seal.NewKey()
	v := View{NS: "cat", Target: "/cat/at/1abc/children"}
	file, err := SealItem(Key{NS: "files", Epoch: 2, K: ke, Pad: true}, v, "notes", map[string]any{"file": "x"})
	if err != nil {
		t.Fatal(err)
	}
	kr, _ := seal.ResourceKey(ke, "files", "notes")
	kv, _ := seal.ViewKey(kr, v.Target)
	h, pt, err := seal.Open(file, kv)
	if err != nil || h.Expect("files#2", seal.PL{"ns": "files", "name": "notes", "view": v.Target}) != nil || !seal.IsPadded(h, pt) {
		t.Fatalf("a value of files/notes in a view of cat: %+v %v", h, err)
	}
	if _, _, err := seal.Open(file, kr); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("under K_r alone: %v, want ErrDecrypt", err)
	}
}
