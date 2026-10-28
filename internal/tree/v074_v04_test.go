package tree_test

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// TestV074RootsWithoutVisibleParent (Open 101, §B.11.5): for a subject
// set, a visible node with no visible parent is a root even when it has
// no walkable parent at all: lost, whose one parent doesn't exist, is a
// root for a reader who sees it, and its one path, empty, ends at it, not
// counted incomplete. Unfiltered, it stays an orphan (§B.5).
func TestV074RootsWithoutVisibleParent(t *testing.T) {
	t.Parallel()
	x, scope, whole := scopedWorld(t)
	bob := scope("lost")
	if got := names(x.get("/cat/roots", bob)["roots"]); got != "lost" {
		t.Errorf("roots for a reader who sees lost: %s", got)
	}
	if b := x.get("/cat/ancestors?of=lost", bob); len(b["paths"].([]any)) != 1 || pathsOf(b["paths"]) != "" || b["incomplete"] != nil {
		t.Errorf("ancestors of a root for the reader: %v", b)
	}
	if b := x.get("/cat/ancestors?of=lost", whole); len(b["paths"].([]any)) != 0 || b["incomplete"] != 1.0 {
		t.Errorf("unfiltered ancestors of an orphan: %v", b)
	}
	if got := names(x.get("/cat/orphans", whole)["orphans"]); got != "lost" {
		t.Errorf("unfiltered orphans: %s", got)
	}
}

// TestV074PurgedLeaveCombinedAt (Open 95, §B.5): the combined checkpoint
// is over the catalog and the content namespaces it follows, purged ones
// left out: once b is purged, a listing's at is that of the catalog and
// a alone, and it carries no ns:b tag.
func TestV074PurgedLeaveCombinedAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"a", "b", "cat"} {
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"a", "b"}}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat", "a", "b"}, []string{"read", "create", "config", "purge-ns"})))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "a", "x", map[string]any{"title": "X"}))
	must(w.CreateDoc(ctx, "b", "y", map[string]any{"title": "Y"}))
	must(w.CreateDoc(ctx, "cat", "a.x", map[string]any{"parents": parents("root")}))
	must(w.CreateDoc(ctx, "cat", "b.y", map[string]any{"parents": parents("root")}))
	x := startSvc(t, s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat", "a", "b"}, []string{"read"}))), svcOpts{now: s.Now})
	x.caughtUp("cat", "a", "b")
	must(w.PatchConfig(ctx, "b", must(w.NSHead(ctx, "b")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	head := must(w.PurgeNamespace(ctx, "b", must(w.NSHead(ctx, "b")).ID))
	waitFor(t, "the purge of b", func() bool { return x.s.Checkpoint("b") == head })

	var want string
	x.s.View(func(g *tree.Graph, cur map[string]string) {
		want, _ = tree.CombinedAt(g, map[string]string{"cat": cur["cat"], "a": cur["a"]})
	})
	if got := x.s.At(); got != want {
		t.Errorf("at %s, want %s, over the catalog and a", got, want)
	}
	full := k.Grant(t, s.Now(), "user:r", []string{"cat", "a", "b"}, []string{"read"})
	r := x.raw("/cat/roots", full)
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.Contains(loc, "/at/"+want+"/") {
		t.Fatalf("roots: %d %s, want at %s", r.status, loc, want)
	}
	l := x.raw(loc, full)
	tags := strings.Split(l.header.Get("Cache-Tag"), ",")
	if l.status != 200 || !contains(tags, "ns:a") || contains(tags, "ns:b") {
		t.Errorf("listing at %s: %d, tags %v", want, l.status, tags)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if strings.TrimSpace(y) == x {
			return true
		}
	}
	return false
}

// TestV074BornOfAnotherEpoch (Open 15, §E.2.6): a node's born derives
// from its first revision, its title from its head. A folder created in
// epoch 1 and retitled in epoch 2 is listed per entry, its "sealed"
// under cat#2 holding only its title, and its born sealed in place, as a
// value of another resource is, "born": { "sealed": JWE } of { born }
// under its K_r of cat#1, pl { ns, name, view }. A g/all listing whose
// values come from those two epochs isn't sealed whole. The epoch is kept
// with the node across a restart, and read in for a database from before
// it was kept (backfillEpochs).
func TestV074BornOfAnotherEpoch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "c"))).CreateNamespace(ctx, "c", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"c"}, "mode": "tree"}}))
	all := []string{"cat", "c"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})
	keys := map[string][]byte{}
	addKeys := func() {
		for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
			keys[e.Kid] = e.Key
		}
	}
	addKeys()
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	addKeys()
	keyOf := func(kid string) []byte { return keys[kid] }
	h := must(w.Head(ctx, "cat", "old"))
	must(w.Append(ctx, "cat", "old", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Older"},
		map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}))

	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"},
		map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "c")
	full := k.Grant(t, s.Now(), "user:r", all, []string{"read"})

	check := func(when string) bool {
		t.Helper()
		f := x.fetch("/cat/children?of=root", full)
		if f.header.Get("Content-Type") != "application/json" {
			t.Logf("%s: g/all listing %s, want per entry", when, f.header.Get("Content-Type"))
			return false
		}
		view := derived.View{NS: "cat", Target: f.path}
		e := entriesOf(t, decode(t, f.body))["old"]
		jwe, _ := e["sealed"].(string)
		if jwe == "" || must(seal.ParseHeader(jwe)).Kid != "cat#2" {
			t.Logf("%s: old sealed %v, want kid cat#2", when, e)
			return false
		}
		vals := decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", "old"), view, "cat", "old")))
		if vals["title"] != "Older" || vals["born"] != nil {
			t.Logf("%s: old's sealed values %v, want only its title", when, vals)
			return false
		}
		born, _ := e["born"].(map[string]any)
		bj, _ := born["sealed"].(string)
		if len(born) != 1 || bj == "" || must(seal.ParseHeader(bj)).Kid != "cat#1" {
			t.Logf("%s: old's born %v, want { sealed } under cat#1", when, e["born"])
			return false
		}
		bv := decode(t, must(derived.OpenItem(bj, derived.ItemKey(keyOf, "cat", "old"), view, "cat", "old")))
		if b, _ := bv["born"].(string); len(bv) != 1 || b == "" {
			t.Logf("%s: old's born opens to %v, want { born }", when, bv)
			return false
		}
		return true
	}
	if !check("following") {
		t.Fatal("a born of another epoch isn't sealed apart")
	}
	// Kept with the node: a restart seals it so too, at a new at.
	x.stop()
	x = startSvc(t, sc, svcOpts{now: s.Now, db: db})
	createNonced(t, w, "cat", "later", map[string]any{"parents": parents("old")})
	x.caughtUp("cat", "c")
	if !check("restarted") {
		t.Fatal("after a restart")
	}
	// A database from before born_epoch was kept reads it in.
	x.stop()
	sq := must(sql.Open("sqlite", db))
	for _, q := range []string{`UPDATE nodes SET born_epoch = NULL`, `INSERT INTO meta (k, v) VALUES ('epochs', 'pending') ON CONFLICT (k) DO NOTHING`,
		`DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sq.Close()
	x = startSvc(t, sc, svcOpts{now: s.Now, db: db})
	createNonced(t, w, "cat", "latest", map[string]any{"parents": parents("old")})
	x.caughtUp("cat", "c")
	waitFor(t, "the born epochs to be read in", func() bool { return check("backfilled") })
}

// TestV074BornEpochBackfillHeadMoved (§E.2.6): a born's epoch is that
// of the node's first revision, whatever its head. The backfill of a
// database from before born_epoch was kept reads it with the head it
// saw; a node whose head moves before the backfill applies what it read
// still gets it (Apply keeps a known born as it is and never reads its
// epoch again), so its born is sealed apart under cat#1, not under the
// head's epoch.
func TestV074BornEpochBackfillHeadMoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "c"))).CreateNamespace(ctx, "c", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"c"}, "mode": "tree"}}))
	all := []string{"cat", "c"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})
	keys := map[string][]byte{}
	addKeys := func() {
		for _, e := range must(w.FetchKeys(ctx, "cat", nil, nil)) {
			keys[e.Kid] = e.Key
		}
	}
	addKeys()
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	addKeys()
	keyOf := func(kid string) []byte { return keys[kid] }
	retitle := func(title string) {
		h := must(w.Head(ctx, "cat", "old"))
		must(w.Append(ctx, "cat", "old", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": title},
			map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}))
	}
	retitle("Older")

	grantOpts := []client.Option{client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"},
		map[string]any{"nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil))}
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, s.Client(t, grantOpts...), svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "c")
	x.stop()
	sq := must(sql.Open("sqlite", db))
	for _, q := range []string{`UPDATE nodes SET born_epoch = NULL`, `INSERT INTO meta (k, v) VALUES ('epochs', 'pending') ON CONFLICT (k) DO NOTHING`,
		`DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sq.Close()

	// The backfill's read of old's log waits until an apply has moved
	// old's head.
	var running atomic.Pointer[tree.Service]
	var once sync.Once
	moveHead := func() {
		// On the backfill's goroutine: no t.Fatal here.
		h := must(w.Head(ctx, "cat", "old"))
		if _, err := w.Append(ctx, "cat", "old", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Oldest"},
			map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}); err != nil {
			t.Errorf("moving old's head: %v", err)
			return
		}
		nh, err := w.NSHead(ctx, "cat")
		for deadline := time.Now().Add(30 * time.Second); err == nil && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if sv := running.Load(); sv != nil && sv.Checkpoint("cat") == nh.ID {
				return
			}
		}
		t.Errorf("the tree service didn't apply old's new head: %v", err)
	}
	wrap := client.WithTransport(func(rt http.RoundTripper) http.RoundTripper {
		return roundTrip(func(r *http.Request) (*http.Response, error) {
			if strings.HasPrefix(r.URL.Path, "/r/cat/old/rev/") && strings.HasSuffix(r.URL.Path, "/log") {
				once.Do(moveHead)
			}
			return rt.RoundTrip(r)
		})
	})
	x = startSvc(t, s.Client(t, append(grantOpts, wrap)...), svcOpts{now: s.Now, db: db})
	running.Store(x.s)
	waitFor(t, "the epochs backfill", func() bool { return !x.s.EpochsPending() })
	x.caughtUp("cat", "c")

	f := x.fetch("/cat/children?of=root", k.Grant(t, s.Now(), "user:r", all, []string{"read"}))
	if f.header.Get("Content-Type") != "application/json" {
		t.Fatalf("g/all listing %s, want per entry", f.header.Get("Content-Type"))
	}
	view := derived.View{NS: "cat", Target: f.path}
	e := entriesOf(t, decode(t, f.body))["old"]
	jwe, _ := e["sealed"].(string)
	if vals := decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", "old"), view, "cat", "old"))); vals["title"] != "Oldest" || vals["born"] != nil {
		t.Fatalf("old's sealed values %v, want only its new title", vals)
	}
	born, _ := e["born"].(map[string]any)
	if bj, _ := born["sealed"].(string); len(born) != 1 || bj == "" || must(seal.ParseHeader(bj)).Kid != "cat#1" {
		t.Fatalf("old's born %v, want { sealed } under cat#1", e["born"])
	}
}
