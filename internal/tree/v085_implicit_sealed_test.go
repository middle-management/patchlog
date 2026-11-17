package tree_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// SERVICES §E.2.6 Per-entry sealing (v0.85, Open 19; scenario 82): "A
// value ... that an entry with no revision of its own carries, such as an
// implicit placement (§B.9), is sealed in place as a value of another
// resource is". In a sealed catalog whose listing is sealed per entry
// (its nodes' heads are served under two epochs), the implicit placement
// of pub.open, an item of a namespace that is neither sealed nor e2e,
// carries its item's title and born in the clear and no "sealed": nothing
// of it is sealed under the catalog's keys, as before v0.85, when both
// were sealed under the catalog node's K_r at the catalog's current
// epoch. That of sec.hidden, an item of a sealed namespace, carries
// neither: the service holds none of its values. The catalog's own nodes
// stay sealed under their heads' epochs.
func TestV085ImplicitPlacementValuesAreItsItems(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	all := []string{"cat", "pub", "sec"}
	sealed := map[string]any{"level": "sealed"}
	for ns, doc := range map[string]map[string]any{
		"pub": {"read": "grant", "keys": []any{k.Entry("*")}},
		"sec": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": sealed},
		"cat": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": sealed,
			"catalog": map[string]any{"trust": []any{"pub", "sec"}, "mode": "dag", "title": "/title"}},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	createNonced(t, w, "cat", "one", map[string]any{"title": "One", "parents": parents("root")})
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	createNonced(t, w, "cat", "two", map[string]any{"title": "Two", "parents": parents("root")})
	self := []any{map[string]any{"href": "/r/cat/root"}}
	must(w.CreateDoc(ctx, "pub", "open", map[string]any{"title": "Open title", "$parents": self}))
	createNonced(t, w, "sec", "hidden", map[string]any{"title": "Hidden title", "$parents": self})
	// Issued before the rotation, so that it gets the first epoch's key.
	early := map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)}
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, early)), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db"), selfPlacing: true})
	x.caughtUp("cat", "pub", "sec")
	rd := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	const path = "/cat/children?of=root"
	waitFor(t, "a listing", func() bool { return x.listingAs(path, rd).status == http.StatusOK })
	f := x.fetch(path, rd)
	if ct := f.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("the listing, of nodes served under two epochs, isn't sealed per entry: %s", ct)
	}
	es := entriesOf(t, decode(t, f.body))
	open := es["pub.open"]
	if open == nil || open["self"] != true || open["sealed"] != nil || open["title"] != "Open title" {
		t.Errorf("the implicit placement of an item that isn't sealed: %v, want its item's title in the clear and nothing sealed", open)
	}
	if born, _ := open["born"].(string); born == "" {
		t.Errorf("the implicit placement of an item that isn't sealed carries no born: %v", open)
	} else if _, err := time.Parse(time.RFC3339, born); err != nil {
		t.Errorf("born %q: %v", born, err)
	}
	hidden := es["sec.hidden"]
	if hidden == nil || hidden["self"] != true || hidden["sealed"] != nil || hidden["title"] != nil || hidden["born"] != nil {
		t.Errorf("the implicit placement of a sealed item: %v, want it by name only", hidden)
	}
	for name, kid := range map[string]string{"one": "cat#1", "two": "cat#2"} {
		jwe, _ := es[name]["sealed"].(string)
		if jwe == "" || es[name]["title"] != nil {
			t.Errorf("%s: %v, want its values sealed", name, es[name])
			continue
		}
		if got := must(seal.ParseHeader(jwe)).Kid; got != kid {
			t.Errorf("%s sealed under %s, want %s", name, got, kid)
		}
	}
}
