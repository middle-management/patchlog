package client_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// E2E-12 (§E.3.2, §C.7): a keyring write that carries a $nonce carries
// new random bits each time, so the client's successive keyring writes
// all differ in it; the server checks only its form, accepting a
// well-formed $nonce it has stored before, and refuses another member or
// a malformed one (422).
func TestV082KeyringNonceNewOnEveryWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	_, admin, _ := seal.GenerateRecipient()
	_, r1, _ := seal.GenerateRecipient()
	_, r2, _ := seal.GenerateRecipient()
	ax := c.E2E(admin)
	must(ax.InitKeyring(ctx, "e"))
	kr, head, err := ax.Keyring(ctx, "e")
	if err != nil {
		t.Fatal(err)
	}
	// The keyring gains a $nonce, as one written in a namespace that
	// requires them has.
	first := seal.NewNonce()
	doc := kr.Value()
	doc["$nonce"] = first
	head = must(c.Append(ctx, "e", client.KeyringName, head, ops(op("replace", "", doc)))).ID
	// The server checks the form only: the same well-formed $nonce again
	// is accepted, a malformed one and another member are 422.
	again := must(c.Append(ctx, "e", client.KeyringName, head, ops(op("replace", "", doc)))).ID
	if again == head {
		t.Fatal("the repeated write made no revision")
	}
	head = again
	for what, bad := range map[string]func(map[string]any){
		"a malformed $nonce":         func(m map[string]any) { m["$nonce"] = "not-a-nonce" },
		"a $nonce that is no string": func(m map[string]any) { m["$nonce"] = 7.0 },
		"another member":             func(m map[string]any) { m["note"] = "x" },
	} {
		m := kr.Value()
		m["$nonce"] = seal.NewNonce()
		bad(m)
		_, err := c.Append(ctx, "e", client.KeyringName, head, ops(op("replace", "", m)))
		if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 {
			t.Fatalf("%s: %v, want 422", what, err)
		}
	}
	// The client's own keyring writes: a new $nonce each.
	seen := map[string]bool{first: true}
	nonce := func(what string) {
		t.Helper()
		k, _, err := ax.Keyring(ctx, "e")
		if err != nil {
			t.Fatal(err)
		}
		if !seal.ValidNonce(k.Nonce) || seen[k.Nonce] {
			t.Fatalf("%s: $nonce %q, seen before: %v", what, k.Nonce, seen[k.Nonce])
		}
		seen[k.Nonce] = true
	}
	must(ax.AddReader(ctx, "e", r1.PublicKey(), true))
	nonce("AddReader")
	must(ax.AddReader(ctx, "e", r2.PublicKey(), true))
	nonce("a second AddReader")
	must(ax.RotateEpoch(ctx, "e", r1.PublicKey()))
	nonce("RotateEpoch")
}

// E2E-11 (§E.2.1 Message bound, E3): each writer counts the sealings
// under a K_r that it knows of. A grant that can't read the log (§C.5)
// counts its own alone and reports the count partial; it still refuses
// past the bound.
func TestV082SealCountWithoutLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	H := ids.Revision(nil, []byte("h")).String()
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+H+`"`)
		w.WriteHeader(302)
	}
	st.routes["/r/e/d/rev/"+H+"/log"] = st.json(403, map[string]any{"code": "forbidden"})
	st.routes["/r/e/d/log"] = st.json(403, map[string]any{"code": "forbidden"})
	x := st.view().WithSealBound(2, 1)
	must(x.SealPatches(ctx, "e", "d", H, ops(op("add", "/a", 1))))
	must(x.SealPatches(ctx, "e", "d", H, ops(op("add", "/a", 2))))
	if s := must(x.SealStatus(ctx, "e", "d")); !s.Partial || s.Sealed != 2 || !s.RotationDue {
		t.Fatalf("a writer that can't read the log: %+v", s)
	}
	if _, err := x.SealPatches(ctx, "e", "d", H, ops(op("add", "/a", 3))); !errors.Is(err, client.ErrSealBound) {
		t.Fatalf("a third sealing under a bound of 2: %v", err)
	}
}
