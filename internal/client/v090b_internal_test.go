package client

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v0.90 §E.2.2 Protected header ("a filtered answer's view with the
// URL's, or, where the URL names none, with the view of the key /keys
// gave the grant the request carried"; CONFORMANCE Filtered reads 87): at
// a resource's URL, which names no view, a filtered answer whose pl.view
// is another view's is refused, even one the reader can open (here with
// a K_e, which derives every K_view); one of its own view opens.
func TestV090BFilteredViewComparedWithKeys(t *testing.T) {
	ctx := context.Background()
	const ns, name = "matches", "derby"
	kid := seal.Kid(ns, 1)
	ke := seal.NewKey()
	mine, other := "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	kMine, err := seal.FilterViewKey(ke, ns, mine)
	if err != nil {
		t.Fatal(err)
	}
	kOther, err := seal.FilterViewKey(ke, ns, other)
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeys()
	keys.AddView(kid, mine, kMine)
	keys.Add(kid, ke)
	c, err := New("http://origin.invalid", WithKeys(keys))
	if err != nil {
		t.Fatal(err)
	}
	since, last := "1ccccccccccccccccccccccccccccccc0", "1dddddddddddddddddddddddddddddddd"
	answer := func(view string, k []byte) string {
		t.Helper()
		pl := seal.WithView(seal.PL{"ns": ns, "name": name, "range": []any{since, last}}, view)
		jwe, err := seal.Seal(k, kid, pl, seal.FilteredPlaintext([]any{}, nil))
		if err != nil {
			t.Fatal(err)
		}
		return jwe
	}
	if _, err := c.openFilteredLog(ctx, ns, name, since, last, answer(mine, kMine)); err != nil {
		t.Fatalf("an answer of her own view: %v", err)
	}
	if _, err := c.openFilteredLog(ctx, ns, name, since, last, answer(other, kOther)); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("another view's answer, which opens: %v, want a mismatch", err)
	}
}
