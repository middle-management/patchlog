package grant

import "testing"

// "*" in a narrowing block's ns makes the grant invalid, an operator
// grant's included, whose root block may name it (§C.1 Narrowing only
// restricts, v0.90; CONFORMANCE Access 103).
func TestV090StarNSInNarrowingBlock(t *testing.T) {
	f := newFixture(t, nil)
	root := mustMint(t, f, map[string]any{"ns": []any{"*"}})
	if _, err := root.Narrow(map[string]any{"ns": []any{"*"}}); err == nil {
		t.Fatal(`Narrow accepted "*" in ns`)
	}
	n, err := root.NarrowUnvalidated(map[string]any{"ns": []any{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(n.Encode(), 0)
	wantStatus(t, err, 401)
	// Naming one namespace narrows as before.
	ok, err := root.Narrow(map[string]any{"ns": []any{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(ok.Encode(), 0); err != nil {
		t.Fatal(err)
	}
}
