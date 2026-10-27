package tree_test

import (
	"context"
	"database/sql"
	"net/http"
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

// TestV073P37ListingOlderKeys (ENC-32, §E.2.3, §E.2.6): a sealed catalog
// with one node of epoch 1 and the rest of epoch 2. The key of an older
// epoch is asked for only by a listing that shows a node served under it.
// After a restart, a service whose grant has no nbf gets keys only from
// the current epoch on (§E.2.3): a listing of epoch-2 nodes is still
// sealed whole under cat#2, and one that shows the epoch-1 node too gives
// that node by name only, without its values, rather than failing every
// listing of the catalog. A key fetch that fails for now is 503 behind
// only for the listings that need that key.
func TestV073P37ListingOlderKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "c"))).CreateNamespace(ctx, "c", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"c"}, "mode": "tree"}}))
	all := []string{"cat", "c"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})
	keys := map[string][]byte{}
	for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
		keys[e.Kid] = e.Key
	}
	// No nbf: keys from the current epoch on (§E.2.3).
	svc := func() *client.Client {
		return s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	}
	opts := svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")}
	x := startSvc(t, svc(), opts)
	x.caughtUp("cat")
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
		keys[e.Kid] = e.Key
	}
	keyOf := func(kid string) []byte { return keys[kid] }
	createNonced(t, w, "cat", "new", map[string]any{"title": "New", "parents": parents("root")})
	createNonced(t, w, "cat", "kid", map[string]any{"title": "Kid", "parents": parents("new")})
	full := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	x.caughtUp("cat")
	x.fetch("/cat/children?of=root", full) // with cat#1 held from before the rotation

	// After a restart the service holds no key of epoch 1, and can't
	// get it.
	x.stop()
	x = startSvc(t, svc(), opts)
	createNonced(t, w, "cat", "later", map[string]any{"parents": parents("new")})
	x.caughtUp("cat")
	f := x.fetch("/cat/children?of=new", full)
	if h, err := seal.ParseHeader(string(f.body)); err != nil || h.Kid != "cat#2" {
		t.Fatalf("children of new: %v %v", h, err)
	}
	f = x.fetch("/cat/children?of=root", full)
	if f.header.Get("Content-Type") != "application/json" {
		t.Fatalf("children of root without cat#1: %s", f.header.Get("Content-Type"))
	}
	es := entriesOf(t, decode(t, f.body))
	if e := es["old"]; e == nil || e["sealed"] != nil || e["title"] != nil {
		t.Errorf("old without its epoch's key: %v, want it by name only", e)
	}
	if jwe, _ := es["new"]["sealed"].(string); jwe == "" || must(seal.ParseHeader(jwe)).Kid != "cat#2" {
		t.Errorf("new: %v", es["new"])
	} else if _, err := derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", "new"), derived.View{NS: "cat", Target: f.path}, "cat", "new"); err != nil {
		t.Errorf("new: %v", err)
	}

	// A grant reaching back before the rotation, whose key fetches fail
	// for now once the current key is held.
	ft := &flaky{prefix: "/ns/cat/keys"}
	sc2 := s.Client(t, client.WithHTTPClient(&http.Client{Transport: ft}), client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"},
		map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil)))
	y := startSvc(t, sc2, svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")})
	y.caughtUp("cat")
	y.fetch("/cat/children?of=new", full)
	ft.fail.Store(1 << 20)
	r := y.raw("/cat/children?of=root", full)
	if loc := r.header.Get("Location"); r.status == 302 {
		r = y.raw(loc, full)
	}
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" {
		t.Fatalf("a listing needing a key that can't be had for now: %d %v", r.status, r.body)
	}
	y.fetch("/cat/children?of=new", full) // needs no other key
	ft.fail.Store(0)
	f = y.fetch("/cat/children?of=root", full)
	es = entriesOf(t, decode(t, f.body))
	if jwe, _ := es["old"]["sealed"].(string); jwe == "" || must(seal.ParseHeader(jwe)).Kid != "cat#1" {
		t.Errorf("old once its key is had: %v", es["old"])
	} else if _, err := derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", "old"), derived.View{NS: "cat", Target: f.path}, "cat", "old"); err != nil {
		t.Errorf("old: %v", err)
	}
}

// TestV073P37EpochsBackfilled (ENC-32, ENC-34, §E.2.6): a database from
// before nodes.epoch and the epoch of items' file metadata has its heads'
// epochs read in on start (backfillEpochs), so its listings seal each
// node's values, and each item's file metadata, under the epoch the head
// is served under rather than the one current when they are sealed.
func TestV073P37EpochsBackfilled(t *testing.T) {
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
	createNonced(t, w, "cat", "files.notes", map[string]any{"parents": parents("old")})
	keys := map[string][]byte{}
	addKeys := func() {
		for _, ns := range all {
			for _, e := range must(w.FetchKeys(ctx, ns, nil, nil)) {
				keys[e.Kid] = e.Key
			}
		}
	}
	addKeys()
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	must(s.Engine.RotateEpoch(ctx, "files", "system:rotate"))
	addKeys()
	createNonced(t, w, "cat", "new", map[string]any{"title": "New", "parents": parents("root")})

	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"},
		map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "files")
	x.stop()
	// As an earlier release left it: no nodes.epoch, no epoch in items.file.
	sq := must(sql.Open("sqlite", db))
	for _, q := range []string{`ALTER TABLE nodes DROP COLUMN epoch`, `UPDATE items SET file = json_remove(file, '$.epoch') WHERE file IS NOT NULL`,
		`DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sq.Close()

	x = startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "files")
	full := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	// Only epoch-1 values: sealed whole under cat#1, the file metadata
	// inside under files#1.
	waitFor(t, "the epochs to be read in", func() bool {
		f := x.fetch("/cat/children?of=old", full)
		h, err := seal.ParseHeader(string(f.body))
		return err == nil && h.Kid == "cat#1"
	})
	keyOf := func(kid string) []byte { return keys[kid] }
	f := x.fetch("/cat/children?of=old", full)
	body := must(derived.OpenView(string(f.body), keyOf, derived.View{NS: "cat", Target: f.path}))
	jwe, _ := fileOf(entriesOf(t, decode(t, body))["files.notes"])["sealed"].(string)
	if jwe == "" || must(seal.ParseHeader(jwe)).Kid != "files#1" {
		t.Errorf("file metadata of notes sealed %q, want kid files#1", jwe)
	}
}
