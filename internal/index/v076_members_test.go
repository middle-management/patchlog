package index_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V76-06 (v0.76): the index follows the namespaces visibility reads for a
// namespace §B.11.9 covers, without serving them (§A.4 Private namespaces:
// "the service follows the namespaces visibility reads, as §B.5 does"),
// and applies their purges and ns-purging config entries as §A.1 does for
// its own: "purge idx:{ns} from the service's own cache and drop kept
// results". Before v0.76 it read their heads through the grant checker,
// and nothing purged idx:{m} for them.

// members76Purges counts the cache purges of x that purged tag.
func members76Purges(x *svc, tag string) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := 0
	for _, tags := range x.purges {
		if slices.Contains(tags, tag) {
			n++
		}
	}
	return n
}

// members76Kept is newV75X with li's answer at A kept: li reads matches
// in part, covered through cat-season; once cat-season moves (a folder
// added), A is no longer current but still answered from the kept result.
func members76Kept(t *testing.T) (w *v75x, li, loc string) {
	t.Helper()
	w = newV75X(t, false)
	li = w.reader("user:li", []any{"fans"})
	loc, _, at := w.pointer("/matches", li)
	if got := strings.Join(resources(w.x.search(loc, li)), ","); got != "derby,shared" {
		t.Fatalf("li sees %s, want derby,shared", got)
	}
	w.put("cat-season", "extra", map[string]any{"parents": v75Parents("root")})
	if _, _, at2 := w.pointer("/matches", li); at2 == at {
		t.Fatalf("the at didn't move with cat-season: %s", at)
	}
	if r := w.x.raw(loc, li); r.status != 200 {
		t.Fatalf("A, kept, once cat-season moved: %d %v", r.status, r.body)
	}
	return w, li, loc
}

// TestV076MembersPurge (FSVC-9; §A.4 Private namespaces, §A.1: "purge,
// ... → purge idx:{ns} from the service's own cache and drop kept
// results"): the index serves matches only and covers it through
// cat-season. Once a placement in cat-season is purged, the index purges
// idx:cat-season, which li's answer at A carries, and A is no longer
// answered from the kept result (302); the current at leaves the purged
// placement's item out. Before v0.76 nothing purged idx:cat-season and A
// was still answered 200.
func TestV076MembersPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w, li, loc := members76Kept(t)
	if tags := w.x.raw(loc, li).header.Get("Cache-Tag"); !strings.Contains(tags, "idx:cat-season") {
		t.Fatalf("A's Cache-Tag %q", tags)
	}
	n := members76Purges(w.x, "idx:cat-season")
	h := must(w.admin.Head(ctx, "cat-season", "matches.shared"))
	must(w.admin.Purge(ctx, "cat-season", "matches.shared", h.ID, false))
	waitFor(t, "idx:cat-season purged", func() bool { return members76Purges(w.x, "idx:cat-season") > n })
	if r := w.x.raw(loc, li); r.status != 302 {
		t.Errorf("A after the purge in cat-season: %d %v, want 302", r.status, r.body)
	}
	loc2, _, _ := w.pointer("/matches", li)
	if got := strings.Join(resources(w.x.search(loc2, li)), ","); got != "derby" {
		t.Errorf("li sees %s after the purge, want derby", got)
	}
	if got := w.x.ix.Members()["cat-season"]; got != w.head("cat-season") {
		t.Errorf("cat-season's follower at %q, want its head %s", got, w.head("cat-season"))
	}
}

// TestV076MembersConfigPurge (FSVC-9; §A.1: "a config entry on which §9
// purges ns:{ns} → purge idx:{ns}"): once cat-season, made public, is made
// private again, the index purges idx:cat-season and drops li's kept
// answer at A. Making it public purges nothing.
func TestV076MembersConfigPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	read := func(mode string) {
		t.Helper()
		must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config,
			[]any{map[string]any{"op": "replace", "path": "/read", "value": mode}}))
	}
	read("public")
	li := w.reader("user:li", []any{"fans"})
	waitFor(t, "cat-season followed to its head", func() bool { return w.x.ix.Members()["cat-season"] == w.head("cat-season") })
	n := members76Purges(w.x, "idx:cat-season")
	loc, _, at := w.pointer("/matches", li)
	if got := strings.Join(resources(w.x.search(loc, li)), ","); got != "derby,shared" {
		t.Fatalf("li sees %s, want derby,shared", got)
	}
	w.put("cat-season", "extra", map[string]any{"parents": v75Parents("root")})
	if _, _, at2 := w.pointer("/matches", li); at2 == at {
		t.Fatalf("the at didn't move with cat-season: %s", at)
	}
	if r := w.x.raw(loc, li); r.status != 200 {
		t.Fatalf("A, kept: %d %v", r.status, r.body)
	}
	if got := members76Purges(w.x, "idx:cat-season"); got != n {
		t.Errorf("idx:cat-season purged %d times by public cat-season's writes", got-n)
	}
	read("grant")
	waitFor(t, "idx:cat-season purged", func() bool { return members76Purges(w.x, "idx:cat-season") > n })
	if r := w.x.raw(loc, li); r.status != 302 {
		t.Errorf("A once cat-season is private again: %d %v, want 302", r.status, r.body)
	}
}

// TestV076MembersStartStop (FSVC-9): the index follows cat-season while
// matches' coverage reads it: removing cat-season from matches' catalogs
// stops its follower, purging idx:cat-season once more (nothing purges it
// after), and li reads matches as an uncovered namespace's partial
// reader; adding it back starts the follower again and li's answers are
// at the combined checkpoint once more.
func TestV076MembersStartStop(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans"})
	w.pointer("/matches", li)
	followed := func() bool { _, ok := w.x.ix.Members()["cat-season"]; return ok }
	waitFor(t, "cat-season followed", followed)
	catalogs := func(op string, v any) {
		t.Helper()
		p := map[string]any{"op": op, "path": "/catalogs/cat-season"}
		if v != nil {
			p["value"] = v
		}
		must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{p}))
		w.x.caughtUp("matches")
		w.x.ix.ExpireGrantChecks()
	}
	n := members76Purges(w.x, "idx:cat-season")
	catalogs("remove", nil)
	waitFor(t, "cat-season no longer followed, and idx:cat-season purged", func() bool {
		return !followed() && members76Purges(w.x, "idx:cat-season") > n
	})
	if _, _, at := w.pointer("/matches", li); at != w.x.ix.Checkpoint("matches") {
		t.Errorf("li's at %s, uncovered, want matches' own %s", at, w.x.ix.Checkpoint("matches"))
	}
	catalogs("add", map[string]any{"place": []any{}})
	waitFor(t, "cat-season followed again", followed)
	loc, _, _ := w.pointer("/matches", li)
	b := w.x.search(loc, li)
	if ns := v75Namespaces(t, b); ns["cat-season"] != w.head("cat-season") || ns["matches"] != w.x.ix.Checkpoint("matches") {
		t.Errorf("namespaces %v once cat-season is trusted again", ns)
	}
	if got := strings.Join(resources(b), ","); got != "derby,shared" {
		t.Errorf("li sees %s, want derby,shared", got)
	}
}

// members76Start starts an index on db following matches, with hook as
// its OnMemberBootstrap, and returns it with a function that stops it.
func members76Start(t *testing.T, w *v75x, db string, hook func(ctx context.Context, m string)) (*svc, func()) {
	t.Helper()
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	x := startSvcWith(t, w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: db, ns: []string{"matches"}, untyped: true, now: w.s.Now, noRun: true},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
		})
	if hook != nil {
		x.ix.OnMemberBootstrap(hook)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { x.ix.Run(ctx); close(done) }()
	stop := func() { cancel(); <-done; x.stop() }
	t.Cleanup(func() { cancel(); <-done })
	return x, stop
}

// TestV076MembersRestart (FSVC-9; §A.1 "Store the checkpoint in the same
// transaction"): cat-season's follower's checkpoint survives a restart
// (member_checkpoints): a purge in cat-season while the index is down is
// applied once it is up again, purging idx:cat-season, and the follower
// resumes from its checkpoint rather than starting again at the head.
func TestV076MembersRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	db := filepath.Join(t.TempDir(), "i.db")
	x, stop := members76Start(t, w, db, nil)
	w.x = x
	x.caughtUp("matches")
	li := w.reader("user:li", []any{"fans"})
	w.pointer("/matches", li)
	waitFor(t, "cat-season followed to its head", func() bool { return x.ix.Members()["cat-season"] == w.head("cat-season") })
	stop()

	h := must(w.admin.Head(ctx, "cat-season", "matches.shared"))
	must(w.admin.Purge(ctx, "cat-season", "matches.shared", h.ID, false))
	var mu sync.Mutex
	var bootstrapped []string
	x, _ = members76Start(t, w, db, func(_ context.Context, m string) {
		mu.Lock()
		bootstrapped = append(bootstrapped, m)
		mu.Unlock()
	})
	w.x = x
	waitFor(t, "idx:cat-season purged after the restart", func() bool { return members76Purges(x, "idx:cat-season") > 0 })
	waitFor(t, "cat-season followed to its head", func() bool { return x.ix.Members()["cat-season"] == w.head("cat-season") })
	mu.Lock()
	if slices.Contains(bootstrapped, "cat-season") {
		t.Errorf("cat-season's follower started again at the head after the restart")
	}
	mu.Unlock()
	loc, _, _ := w.pointer("/matches", li)
	if got := strings.Join(resources(x.search(loc, li)), ","); got != "derby" {
		t.Errorf("li sees %s after the purge, want derby", got)
	}
}

// TestV076MembersBehind (FSVC-9; §A.4 Private namespaces, §B.5 Behind):
// until cat-season's follower holds its first checkpoint, li, a partial
// reader of matches, which the index covers through cat-season, is
// answered 503 behind with Retry-After, at /matches and at /_refs; a
// reader of matches whole is answered as before. Once the follower has
// its checkpoint, li's answers are at the combined checkpoint with
// cat-season at it. Before v0.76 cat-season was read at its head through
// the grant checker, followed or not.
func TestV076MembersBehind(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	release := make(chan struct{})
	x, _ := members76Start(t, w, filepath.Join(t.TempDir(), "i.db"), func(ctx context.Context, m string) {
		if m == "cat-season" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	})
	x.ix.SetMinWait(50 * time.Millisecond)
	w.x = x
	x.caughtUp("matches")

	li := w.reader("user:li", []any{"fans"})
	for _, path := range []string{"/matches", "/_refs?to=%2Fr%2Ftarget%2Fx"} {
		r := x.raw(path, li)
		if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s before cat-season's first checkpoint: %d %v %v", path, r.status, r.body, r.header)
		}
	}
	whole := w.k.Grant(t, w.s.Now(), "user:whole", []string{"matches"}, []string{"read"})
	if r := x.raw("/matches", whole); r.status != 302 {
		t.Errorf("a reader of matches whole: %d %v", r.status, r.body)
	}
	if got, ok := x.ix.Members()["cat-season"]; !ok || got != "" {
		t.Errorf("cat-season's follower: %q %v, want running without a checkpoint", got, ok)
	}

	close(release)
	waitFor(t, "cat-season's first checkpoint", func() bool { return x.ix.Members()["cat-season"] != "" })
	loc, _, _ := w.pointer("/matches", li)
	b := x.search(loc, li)
	if ns := v75Namespaces(t, b); ns["cat-season"] != x.ix.Members()["cat-season"] || ns["matches"] != x.ix.Checkpoint("matches") {
		t.Errorf("namespaces %v, want cat-season at its follower's %s", ns, x.ix.Members()["cat-season"])
	}
	if got := strings.Join(resources(b), ","); got != "derby,shared" {
		t.Errorf("li sees %s, want derby,shared", got)
	}
}
