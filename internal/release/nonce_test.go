package release_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/seal"
)

// §C.7: in a namespace that requires nonces, Write gives every revision
// of a release document a fresh $nonce: a create, an append, and an
// append by a writer whose grant can't read the namespace document, which
// goes by the $nonce the document was read with.
func TestWriteRequiredNonces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	ops, idp := clienttest.NewKey("ops"), clienttest.NewKey("idp")
	all := []string{"read", "create", "append", "delete", "restore", "config"}
	admin := s.Client(t, client.WithBearer(s.OperatorGrant(t, "releases")))
	if _, err := admin.CreateNamespace(ctx, "releases", map[string]any{"read": "grant", "nonce": "required",
		"keys": []any{ops.Entry("*"), idp.Entry(all...)}}); err != nil {
		t.Fatal(err)
	}
	anna := s.Client(t, client.WithBearer(idp.Grant(t, s.Now(), "user:anna", []string{"releases"}, all)))
	// Only release-9: rules on /resource leave the namespace document
	// unreadable (§C.5).
	li := s.Client(t, client.WithBearer(idp.Grant(t, s.Now(), "user:li", []string{"releases"}, all,
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "release-9"}}})))
	if _, err := li.NonceRequired(ctx, "releases"); err == nil {
		t.Fatal("li reads the namespace document")
	}

	nonce := func(c *client.Client, id string) string {
		t.Helper()
		d, err := c.Doc(ctx, "releases", "release-9", id)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := d.Value.(map[string]any)["$nonce"].(string)
		if !seal.ValidNonce(n) {
			t.Fatalf("revision %s has $nonce %q", id, n)
		}
		return n
	}
	ref := release.Ref{NS: "releases", Name: "release-9"}
	doc := &release.Doc{Name: "release-9", Branches: map[string]release.Branch{"matches": {NS: "matches-r9"}}}
	r1, err := release.Write(ctx, anna, ref, "", doc)
	if err != nil {
		t.Fatal(err)
	}
	n1 := nonce(anna, r1)
	doc.Owners = []string{"user:anna"}
	r2, err := release.Write(ctx, anna, ref, r1, doc)
	if err != nil {
		t.Fatal(err)
	}
	n2 := nonce(anna, r2)

	loaded, err := release.Load(ctx, li, ref.Live())
	if err != nil {
		t.Fatal(err)
	}
	loaded.Doc.Owners = append(loaded.Doc.Owners, "user:li")
	r3, err := release.Write(ctx, li, loaded.Ref, loaded.Head, loaded.Doc)
	if err != nil {
		t.Fatal(err)
	}
	n3 := nonce(li, r3)
	if n1 == n2 || n2 == n3 {
		t.Fatalf("nonces %s %s %s", n1, n2, n3)
	}
	got, err := release.Load(ctx, anna, ref.Live())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Doc.Owners) != 2 || got.Doc.Branches["matches"].NS != "matches-r9" {
		t.Fatalf("release %+v", got.Doc)
	}
}

// §C.7: a writer whose grant can't read the namespace document doesn't
// know the setting, so in a private namespace it gives a release document
// it creates a fresh $nonce: one that requires them takes it, and so does
// one that doesn't.
func TestWriteUnreadableNonces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	for _, setting := range []string{"required", "optional"} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()
			ns := "releases-" + setting
			admin := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
			if _, err := admin.CreateNamespace(ctx, ns, map[string]any{"read": "grant", "nonce": setting, "keys": []any{k.Entry("*")}}); err != nil {
				t.Fatal(err)
			}
			li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{ns}, []string{"read", "create", "append"},
				map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "release-9"}}})))
			doc := &release.Doc{Name: "release-9", Branches: map[string]release.Branch{"matches": {NS: "matches-r9"}}}
			id, err := release.Write(ctx, li, release.Ref{NS: ns, Name: "release-9"}, "", doc)
			if err != nil {
				t.Fatal(err)
			}
			d, err := li.Doc(ctx, ns, "release-9", id)
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := d.Value.(map[string]any)["$nonce"].(string); !seal.ValidNonce(n) {
				t.Fatalf("$nonce %q", n)
			}
		})
	}
}
