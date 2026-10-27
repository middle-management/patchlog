package tree_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// TestV073P37ListingEpochs (ENC-32, ENC-34, §E.2.6): a sealed catalog's
// listing seals each node's values under the epoch its head is served
// under, not the epoch current when the listing is sealed: one whose
// nodes all come from epoch 1 is sealed whole under cat#1 after a
// rotation; one mixing epochs is per entry, each entry under its node's
// epoch's K_r. A file tree's file metadata is sealed, as a value of
// another resource ({ "sealed": JWE } of { "file": … }), under the
// epoch its item's head is served under. Both survive a restart.
func TestV073P37ListingEpochs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"files": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"cat": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"},
			"catalog": filesCatalog("files")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "files"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})
	createNonced(t, w, "cat", "sub", map[string]any{"title": "Sub", "parents": parents("old")})
	createNonced(t, w, "files", "notes", map[string]any{"n": 1})
	createNonced(t, w, "cat", "files.notes", map[string]any{"parents": parents("root")})
	keys := map[string][]byte{}
	addKeys := func() {
		for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
			keys[e.Kid] = e.Key
		}
		for _, e := range must(w.FetchKeys(ctx, "files", nil, nil)) {
			keys[e.Kid] = e.Key
		}
	}
	addKeys()
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	must(s.Engine.RotateEpoch(ctx, "files", "system:rotate"))
	addKeys()
	keyOf := func(kid string) []byte { return keys[kid] }
	createNonced(t, w, "cat", "new", map[string]any{"title": "New", "parents": parents("root")})
	createNonced(t, w, "files", "memo", map[string]any{"n": 2})
	createNonced(t, w, "cat", "files.memo", map[string]any{"parents": parents("root")})

	// The service's grant reaches back before the rotation (nbf), so it
	// gets epoch 1's keys too, after a restart included (§E.2.3).
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"},
		map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil)))
	opts := svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")}
	x := startSvc(t, sc, opts)
	x.caughtUp("cat", "files")
	full := k.Grant(t, s.Now(), "user:r", all, []string{"read"})

	for round := range 2 {
		// Only epoch-1 nodes: sealed whole under cat#1.
		f := x.fetch("/cat/children?of=old", full)
		if h := must(seal.ParseHeader(string(f.body))); f.header.Get("Content-Type") != seal.ContentType || h.Kid != "cat#1" {
			t.Fatalf("round %d: a listing of epoch-1 nodes: %s %s", round, f.header.Get("Content-Type"), h.Kid)
		}
		if _, err := derived.OpenView(string(f.body), keyOf, derived.View{NS: "cat", Target: f.path}); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		// Mixed: per entry, under each node's epoch; file metadata under
		// its item's.
		f = x.fetch("/cat/children?of=root", full)
		if f.header.Get("Content-Type") != "application/json" {
			t.Fatalf("round %d: a listing mixing epochs: %s", round, f.header.Get("Content-Type"))
		}
		want := map[string][2]string{"old": {"cat#1", ""}, "new": {"cat#2", ""}, "files.notes": {"", "files#1"}, "files.memo": {"", "files#2"}}
		for name, e := range entriesOf(t, decode(t, f.body)) {
			w, ok := want[name]
			if !ok {
				continue
			}
			delete(want, name)
			if jwe, _ := e["sealed"].(string); w[0] != "" {
				if jwe == "" || must(seal.ParseHeader(jwe)).Kid != w[0] {
					t.Errorf("round %d: %s sealed %q, want kid %s", round, name, jwe, w[0])
				} else if _, err := derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", name), derived.View{NS: "cat", Target: f.path}, "cat", name); err != nil {
					t.Errorf("round %d: %s: %v", round, name, err)
				}
			}
			if w[1] != "" {
				jwe, _ := fileOf(e)["sealed"].(string)
				if jwe == "" || must(seal.ParseHeader(jwe)).Kid != w[1] {
					t.Errorf("round %d: %s file sealed %q, want kid %s", round, name, jwe, w[1])
					continue
				}
				item := name[len("files."):]
				v := decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "files", item), derived.View{NS: "cat", Target: f.path}, "files", item)))
				if _, ok := v["file"].(map[string]any); !ok {
					t.Errorf("round %d: %s file opens to %v, want { file }", round, name, v)
				}
			}
		}
		if len(want) > 0 {
			t.Fatalf("round %d: entries missing: %v", round, want)
		}
		if round == 0 {
			// The epochs are kept with the nodes and items: a restart
			// seals as before, at a new at.
			x.stop()
			x = startSvc(t, sc, opts)
			x.caughtUp("cat", "files")
			createNonced(t, w, "cat", "later", map[string]any{"parents": parents("new")})
			x.caughtUp("cat")
		}
	}
}
