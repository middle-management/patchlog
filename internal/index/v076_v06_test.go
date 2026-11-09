package index_test

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V76-06 review: a member whose follower is behind never uncovers a
// namespace, a purge in a member that races an answer's read drops it, and
// a member's follower stopped and started again is a new catch-up (§A.4
// Private namespaces, §A.1, §B.5 Behind).

// v06Hold holds the index's reads of a namespace's log while on is set:
// those of path, or those match picks.
type v06Hold struct {
	on    atomic.Bool
	base  http.RoundTripper
	path  string
	match func(*http.Request) bool
}

func (b *v06Hold) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.on.Load() && (r.URL.Path == b.path || b.match != nil && b.match(r)) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	return b.base.RoundTrip(r)
}

// v06Start starts an index on db following matches over hc, not running
// until the caller runs it.
func v06Start(t *testing.T, w *v75x, db string, hc *http.Client, noRun bool) *svc {
	t.Helper()
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	return startSvcWith(t, w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: db, ns: []string{"matches"}, untyped: true, now: w.s.Now, noRun: noRun, hc: hc},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
		})
}

// v06Catalogs patches matches' catalogs/cat-season with op and waits for
// x to apply it.
func v06Catalogs(t *testing.T, w *v75x, x *svc, op string, v any) {
	t.Helper()
	p := map[string]any{"op": op, "path": "/catalogs/cat-season"}
	if v != nil {
		p["value"] = v
	}
	must(w.admin.PatchConfig(context.Background(), "matches", must(w.admin.NSHead(context.Background(), "matches")).Config, []any{p}))
	if x != nil {
		x.caughtUp("matches")
		x.ix.ExpireGrantChecks()
	}
}

// TestV076V06MemberBehindKeepsCovered (§A.4 Private namespaces, §B.11.9,
// §B.5 Behind): the index has reached matches at z, covered there through
// cat-season, whose follower holds no checkpoint yet; matches' head drops
// cat-season from its catalogs, which the index hasn't applied. li, a
// partial reader of matches, is answered 503 behind, at /matches and at
// /_refs, never as the partial reader of an uncovered namespace: the
// answer would be at z, where matches is covered, by li's rules alone
// (secret, placed under tr for chiefs only, and opener, never placed).
// Before, a member behind was errNotReached, which grantAccess took for
// matches not reached and, matches' current document not trusting a
// catalog, answered by rules alone.
func TestV076V06MemberBehindKeepsCovered(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	hold := &v06Hold{base: http.DefaultTransport, path: "/ns/matches/log"}
	x := v06Start(t, w, filepath.Join(t.TempDir(), "i.db"), &http.Client{Transport: hold}, true)
	x.ix.OnMemberBootstrap(func(ctx context.Context, m string) {
		if m == "cat-season" {
			<-ctx.Done() // cat-season's first checkpoint never comes
		}
	})
	x.ix.SetMinWait(50 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { x.ix.Run(ctx); close(done) }()
	t.Cleanup(func() { hold.on.Store(false); cancel(); <-done })
	w.x = x
	z := x.caughtUp("matches")

	// matches' follower lags; its head drops cat-season from catalogs.
	hold.on.Store(true)
	time.Sleep(500 * time.Millisecond) // the long-poll in flight returns; the next one is held
	v06Catalogs(t, w, nil, "remove", nil)
	x.ix.ExpireGrantChecks()
	if got := x.ix.Checkpoint("matches"); got != z {
		t.Fatalf("matches' follower moved to %s; the test needs it at %s", got, z)
	}
	li := w.reader("user:li", []any{"fans"})
	for _, path := range []string{"/matches", "/_refs?to=%2Fr%2Ftarget%2Fx"} {
		r := x.raw(path, li)
		if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" {
			got := ""
			if loc := r.header.Get("Location"); r.status == 302 {
				got = strings.Join(resources(x.search(loc, li)), ",")
			}
			t.Errorf("%s while cat-season, which covers matches at z=%s, is behind: %d %v %q, want 503 behind", path, z, r.status, r.body, got)
		}
	}
}

// v06PurgeShared purges matches.shared's placement in cat-season once,
// from x's OnBeforeAnswer hook, and waits until x has purged
// idx:cat-season (§A.1).
func v06PurgeShared(t *testing.T, w *v75x) func() {
	var once atomic.Bool
	return func() {
		if !once.CompareAndSwap(false, true) {
			return
		}
		ctx := context.Background()
		n := members76Purges(w.x, "idx:cat-season")
		h := must(w.admin.Head(ctx, "cat-season", "matches.shared"))
		must(w.admin.Purge(ctx, "cat-season", "matches.shared", h.ID, false))
		waitFor(t, "idx:cat-season purged", func() bool { return members76Purges(w.x, "idx:cat-season") > n })
	}
}

// TestV076V06MemberPurgeRacesAnswer (§A.1: "purge idx:{ns} from the
// service's own cache and drop kept results"; §A.4): a purge in cat-season
// that its follower applies after li's view was computed (cat-season read
// before the purge) but before the answer is leaves no answer read from
// that view kept: the redirect's target, at cat-season's checkpoint before
// the purge, is not answered 200 with shared, whose placement was purged.
// Before, the answer took the kept store's generation after the view,
// after the purge, and kept it, tagged idx:cat-season, past the purge of
// that tag.
func TestV076V06MemberPurgeRacesAnswer(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans"})
	loc0, _, _ := w.pointer("/matches", li)
	if got := strings.Join(resources(w.x.search(loc0, li)), ","); got != "derby,shared" {
		t.Fatalf("li sees %s", got)
	}
	// cat-season moves, so the next head pointer computes a fresh answer.
	w.put("cat-season", "extra", map[string]any{"parents": v75Parents("root")})
	waitFor(t, "cat-season followed to its head", func() bool { return w.x.ix.Members()["cat-season"] == w.head("cat-season") })
	w.x.ix.OnBeforeAnswer(v06PurgeShared(t, w))
	r := w.x.raw("/matches", li)
	w.x.ix.OnBeforeAnswer(nil)
	if r.status != 302 {
		t.Fatalf("li: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	if got := w.x.raw(loc, li); got.status == 200 && slices.Contains(resources(got.body), "shared") {
		t.Errorf("%s after the purge of shared's placement in cat-season: 200 %v, Cache-Tag %q (kept from a view read before the purge)",
			loc, resources(got.body), got.header.Get("Cache-Tag"))
	}
	loc2, _, _ := w.pointer("/matches", li)
	if got := strings.Join(resources(w.x.search(loc2, li)), ","); got != "derby" {
		t.Errorf("li sees %s after the purge, want derby", got)
	}
}

// TestV076V06MemberPurgeRacesRefs is TestV076V06MemberPurgeRacesAnswer
// for /_refs (§A.4 Across namespaces): its answer, read from li's views
// computed before the purge, isn't kept either.
func TestV076V06MemberPurgeRacesRefs(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	li := w.reader("user:li", []any{"fans"})
	const refs = "/_refs?to=%2Fr%2Ftarget%2Fx"
	r := w.x.raw(refs, li)
	if r.status != 302 {
		t.Fatalf("li: %d %v", r.status, r.body)
	}
	if got := w.x.search(r.header.Get("Location"), li); !slices.Contains(resources(got), "shared") {
		t.Fatalf("li's referrers %v, want shared among them", resources(got))
	}
	w.put("cat-season", "extra", map[string]any{"parents": v75Parents("root")})
	waitFor(t, "cat-season followed to its head", func() bool { return w.x.ix.Members()["cat-season"] == w.head("cat-season") })
	w.x.ix.OnBeforeAnswer(v06PurgeShared(t, w))
	r = w.x.raw(refs, li)
	w.x.ix.OnBeforeAnswer(nil)
	if r.status != 302 {
		t.Fatalf("li: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	if got := w.x.raw(loc, li); got.status == 200 && slices.Contains(resources(got.body), "shared") {
		t.Errorf("%s after the purge of shared's placement in cat-season: 200 %v, Cache-Tag %q (kept from views read before the purge)",
			loc, resources(got.body), got.header.Get("Cache-Tag"))
	}
}

// TestV076V06MemberRestartsFresh (§B.5 Behind: "Caught up means reaching
// the head read when catch-up started"; §A.4): cat-season's follower,
// stopped once matches no longer trusts it, forgets its checkpoint C1.
// While nothing follows it, cat-season revokes fans' access; once matches
// trusts it again, its new follower starts at the head, and li, while
// that follower's log reads are held, sees nothing of matches, never
// visibility as of C1. Before, the follower resumed from C1, and li was
// answered at C1 once MinWait ran out.
func TestV076V06MemberRestartsFresh(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	hold := &v06Hold{base: http.DefaultTransport, path: "/ns/cat-season/log"}
	x := v06Start(t, w, filepath.Join(t.TempDir(), "i.db"), &http.Client{Transport: hold}, false)
	t.Cleanup(func() { hold.on.Store(false) })
	x.ix.SetMinWait(50 * time.Millisecond)
	w.x = x
	x.caughtUp("matches")
	li := w.reader("user:li", []any{"fans"})
	w.pointer("/matches", li)
	waitFor(t, "cat-season followed to its head", func() bool { return x.ix.Members()["cat-season"] == w.head("cat-season") })
	c1 := w.head("cat-season")
	followed := func() bool { _, ok := x.ix.Members()["cat-season"]; return ok }
	v06Catalogs(t, w, x, "remove", nil)
	waitFor(t, "cat-season no longer followed", func() bool { return !followed() })
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:nobody": []any{"reader"}}})
	hold.match = func(r *http.Request) bool {
		if !strings.HasPrefix(r.URL.Path, "/ns/cat-season/") || !strings.HasSuffix(r.URL.Path, "/log") {
			return false
		}
		buf := make([]byte, 64<<10)
		return strings.Contains(string(buf[:runtime.Stack(buf, false)]), "follow.(*nsFollower)") // the follower's reads only
	}
	hold.on.Store(true) // the new follower is slow to catch up
	v06Catalogs(t, w, x, "add", map[string]any{"place": []any{}})
	waitFor(t, "cat-season followed again", followed)
	r := x.raw("/matches", li)
	if r.status == 503 {
		return // behind: no leak
	}
	if r.status != 302 {
		t.Fatalf("li: %d %v", r.status, r.body)
	}
	b := x.search(r.header.Get("Location"), li)
	if got := strings.Join(resources(b), ","); got != "" {
		t.Errorf("li sees %s at %v once cat-season (head %s) revoked fans' access; follower at %q (stopped at %s)",
			got, v75Namespaces(t, b), w.head("cat-season"), x.ix.Members()["cat-season"], c1)
	}
}

// TestV076V06MemberForgottenAcrossRestart (§B.5 Behind): a member's
// checkpoint and read mode are forgotten in the database too once its
// follower stops (member_checkpoints, member_conf), so an index restarted
// on the same store after the member is needed again starts its follower
// at the head (bootstrapMember), not from the checkpoint nothing followed
// on from. A follower running at the restart resumes
// (TestV076MembersRestart).
func TestV076V06MemberForgottenAcrossRestart(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	db := filepath.Join(t.TempDir(), "i.db")
	x, stop := members76Start(t, w, db, nil)
	w.x = x
	x.caughtUp("matches")
	li := w.reader("user:li", []any{"fans"})
	w.pointer("/matches", li)
	waitFor(t, "cat-season followed to its head", func() bool { return x.ix.Members()["cat-season"] == w.head("cat-season") })
	n := members76Purges(x, "idx:cat-season")
	v06Catalogs(t, w, x, "remove", nil)
	waitFor(t, "cat-season no longer followed, and idx:cat-season purged", func() bool {
		_, ok := x.ix.Members()["cat-season"]
		return !ok && members76Purges(x, "idx:cat-season") > n
	})
	stop()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	for _, q := range []string{`SELECT COUNT(*) FROM member_checkpoints WHERE ns = 'cat-season'`, `SELECT COUNT(*) FROM member_conf WHERE ns = 'cat-season'`} {
		var rows int
		if err := sq.QueryRow(q).Scan(&rows); err != nil || rows != 0 {
			t.Errorf("%s: %d %v, want 0: kept once the follower stopped", q, rows, err)
		}
	}
	sq.Close()

	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:nobody": []any{"reader"}}})
	v06Catalogs(t, w, nil, "add", map[string]any{"place": []any{}})
	var mu sync.Mutex
	var bootstrapped []string
	x, _ = members76Start(t, w, db, func(_ context.Context, m string) {
		mu.Lock()
		bootstrapped = append(bootstrapped, m)
		mu.Unlock()
	})
	w.x = x
	x.caughtUp("matches")
	waitFor(t, "cat-season followed to its head", func() bool { return x.ix.Members()["cat-season"] == w.head("cat-season") })
	mu.Lock()
	if !slices.Contains(bootstrapped, "cat-season") {
		t.Errorf("cat-season's follower resumed from the checkpoint it stopped at, before the restart")
	}
	mu.Unlock()
	loc, _, _ := w.pointer("/matches", li)
	if got := strings.Join(resources(x.search(loc, li)), ","); got != "" {
		t.Errorf("li sees %s once cat-season revoked fans' access", got)
	}
}
