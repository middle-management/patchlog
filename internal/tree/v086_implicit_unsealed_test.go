package tree_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
)

// CONFORMANCE Encryption 91 (SERVICES §E.2.6 Values of another resource,
// v0.86: "A value drawn from a namespace that is neither sealed nor
// end-to-end has no K_r: it goes inside the entry's own sealed, or, in an
// entry without one, such as an implicit placement (§B.9) of such an
// item, stays in the clear"; Per-entry sealing, §B.5, §B.9). cat is a
// sealed catalog and a file tree; notes is private and not sealed, and
// the listing is sealed per entry (the catalog's heads are served under
// two epochs).
//
// The implicit placement of notes/a carries no sealed, and its title,
// born and file in the clear, shown only to a reader of notes/a. The
// explicit placement of notes/b, which has no title of its own, carries
// its item's title inside its own sealed, under the catalog's K_r of the
// node, and none in the clear.
func TestV086ValuesOfAnUnsealedItemInASealedCatalog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	all := []string{"cat", "notes"}
	cat := filesCatalog("notes")
	cat["title"] = "/title"
	for ns, doc := range map[string]map[string]any{
		"notes": {"read": "grant", "keys": []any{k.Entry("*")}},
		"cat":   {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}, "catalog": cat},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	must(w.CreateDoc(ctx, "notes", "a", map[string]any{"title": "A title", "$parents": []any{map[string]any{"href": "/r/cat/root"}}}))
	must(w.CreateDoc(ctx, "notes", "b", map[string]any{"title": "B title"}))
	createNonced(t, w, "cat", "notes.b", map[string]any{"parents": parents("root")})
	// Issued before the rotation, so that it gets the first epoch's key.
	early := map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, early)), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db"), selfPlacing: true})
	x.caughtUp("cat", "notes")
	rd := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	const path = "/cat/children?of=root"
	waitFor(t, "a listing", func() bool { return x.listingAs(path, rd).status == http.StatusOK })
	f := x.fetch(path, rd)
	if ct := f.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("the listing, of nodes served under two epochs, isn't sealed per entry: %s", ct)
	}
	es := entriesOf(t, decode(t, f.body))

	// The implicit placement: nothing sealed, its item's values in the clear.
	a := es["notes.a"]
	if a == nil || a["self"] != true || a["sealed"] != nil || a["title"] != "A title" {
		t.Errorf("the implicit placement of an item that isn't sealed: %v, want no sealed and its item's title in the clear", a)
	}
	if born, _ := a["born"].(string); born == "" {
		t.Errorf("the implicit placement carries no born in the clear: %v", a)
	}
	if file := fileOf(a); file == nil || file["sealed"] != nil || file["size"] == nil || file["type"] != "application/json" || file["modified"] == nil {
		t.Errorf("the implicit placement's file: %v, want size, type and modified in the clear", a["file"])
	}

	// The explicit placement without a title: the item's title is inside
	// the entry's own sealed, under the catalog's K_r of the node.
	b := es["notes.b"]
	jwe, _ := b["sealed"].(string)
	if b == nil || b["self"] == true || jwe == "" || b["title"] != nil {
		t.Fatalf("the explicit placement of an item that isn't sealed: %v, want its values sealed and no title in the clear", b)
	}
	keys := map[string][]byte{}
	for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
		keys[e.Kid] = e.Key
	}
	keyOf := func(kid string) []byte { return keys[kid] }
	in := decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", "notes.b"), derived.View{NS: "cat", Target: f.path}, "cat", "notes.b")))
	if in["title"] != "B title" {
		t.Errorf("inside the explicit placement's sealed: %v, want its item's title", in)
	}

	// "Listed only to readers of notes/a": this tree service serves the
	// unfiltered listing alone, to a grant that reads every namespace in
	// it; a reader of the catalog who doesn't read notes gets none.
	catOnly := k.Grant(t, s.Now(), "user:c", []string{"cat"}, []string{"read"})
	if r := x.listingAs(path, catOnly); r.status != http.StatusForbidden {
		t.Errorf("the listing, to a reader of the catalog who doesn't read notes: %d %v, want 403", r.status, r.body)
	}
}
