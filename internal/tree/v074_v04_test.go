package tree_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
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
