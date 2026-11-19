package index_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// CONFORMANCE Tree 145 at the index (SERVICES §B.11.9 gs, §A.4 gs, v0.86):
// "Once an entry after its exchange changes one of them, the cookie is
// 403 from that entry on, even where a later entry undoes the change. …
// Both changes in one batch → her cookies hold." The index judges a
// cookie by the namespace document at its head on every read, which sees
// a change and not one undone, so it ends the cookie's rows as it applies
// each config entry's document, in order. Until v0.86 it judged only the
// last document of a batch of its follower: an index that met the change
// and its undo in one batch, having been down or behind, read the cookie
// again.

// v86Restart stops d's index and starts it again on the same database,
// with the cookies' keys it had, and mods.
func v86Restart(d *v77docs, ns []string, rebuild bool, mods ...func(*indexOpts)) {
	d.t.Helper()
	db := d.x.dbPath
	d.x.stop()
	ev := must(edge.New([]byte("s3cret"), "", ""))
	d.x = startSvcWith(d.t, d.s.Client(d.t, client.WithBearer(d.admin.Grant(d.t, d.s.Now(), "svc:indexer", ns, []string{"read"}))),
		svcOpts{db: db, ns: ns, untyped: true, rebuild: rebuild, now: d.s.Now},
		append([]func(*indexOpts){func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
		}}, mods...)...)
	for _, n := range ns {
		d.x.caughtUp(n)
	}
	d.x.ix.ExpireGrantChecks()
}

// v86Config appends one config entry of ops to ns's document, the index
// not waited for.
func v86Config(d *v77docs, ns string, ops ...any) {
	d.t.Helper()
	ctx := context.Background()
	must(d.w.PatchConfig(ctx, ns, must(d.w.NSHead(ctx, ns)).Config, ops))
}

// The change and its undo, of k1's groups scope as the scenario has it:
// k1 is /keys/1 in both fixtures.
var (
	v86Change = map[string]any{"op": "add", "path": "/keys/1/groups", "value": map[string]any{"deny": []any{"banned"}}}
	v86Undo   = map[string]any{"op": "remove", "path": "/keys/1/groups"}
)

// TestV086CookieEndedStaysEnded: li holds an index cookie for docs, read
// whole (reads:docs:{k}) or in part (reads:docs:scope:{digest}). The
// index is down while docs changes k1's groups scope and changes it back
// in a later config entry, so it applies both entries in one batch of
// its follower: her cookie is 403 at the later at until she exchanges
// again. Both changes in one config entry: her cookie holds.
func TestV086CookieEndedStaysEnded(t *testing.T) {
	t.Parallel()
	for name, fixture := range map[string]func(*testing.T) *v77docs{"whole": newV82Whole, "scope": newV77Docs} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := fixture(t)
			li := v82Grant(d, d.k1, "user:li", d.s.Now().Add(10*time.Minute))
			prefixes, c := d.exchange(li)
			paths := v82Paths(prefixes)
			if got := v82Status(t, d.x, paths, c); got != v82Reads {
				t.Fatalf("li under her cookie: %s", got)
			}
			// Both changes in one entry: one document, as it was.
			d.patch(v86Change, v86Undo)
			if got := v82Status(t, d.x, paths, c); got != v82Reads {
				t.Fatalf("li under her cookie after one entry that changes k1 and changes it back: %s, want it to hold", got)
			}
			// A change to another key, and back, ends nothing of hers.
			d.patch(map[string]any{"op": "add", "path": "/keys/2/groups", "value": map[string]any{"deny": []any{"banned"}}})
			d.patch(map[string]any{"op": "remove", "path": "/keys/2/groups"})
			if got := v82Status(t, d.x, paths, c); got != v82Reads {
				t.Fatalf("li under her cookie after k2 changed and changed back: %s, want it to hold", got)
			}
			// Two entries, met in one batch.
			d.x.stop()
			v86Config(d, "docs", v86Change)
			v86Config(d, "docs", v86Undo)
			v86Restart(d, []string{"docs"}, false)
			var both bool
			for _, b := range d.x.batches() {
				n := 0
				for _, u := range b.Units {
					if u.Config != nil {
						n++
					}
				}
				both = both || n == 2
			}
			if !both {
				t.Fatalf("the index didn't meet both config entries in one batch: the test shows nothing")
			}
			if got := v82Status(t, d.x, paths, c); got != v82Refuse {
				t.Errorf("li under her cookie once k1 changed and changed back in a later entry: %s, want 403 until she exchanges again", got)
			}
			_, c2 := d.exchange(li)
			if got := v82Status(t, d.x, paths, c2); got != v82Reads {
				t.Errorf("li, having exchanged again: %s, want 200", got)
			}
			if got := v82Status(t, d.x, paths, c); got != v82Refuse {
				t.Errorf("li under the cookie she held before, after her new exchange: %s, want 403", got)
			}
		})
	}
}

// TestV086CookieEndedAtSnapshotStart: an index that starts a namespace
// from a snapshot (follow.WithSnapshot, on a rebuild) reads its document
// at one entry and none of those before. Cookie rows outlive a rebuild,
// and can't tell whether an entry it skipped changed their key and a
// later one changed it back: every cookie of the namespace is ended, and
// its reader exchanges again (fail closed; the spec doesn't say).
func TestV086CookieEndedAtSnapshotStart(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	li := v82Grant(d, d.k1, "user:li", d.s.Now().Add(10*time.Minute))
	prefixes, c := d.exchange(li)
	paths := v82Paths(prefixes)
	if got := v82Status(t, d.x, paths, c); got != v82Reads {
		t.Fatalf("li under her cookie: %s", got)
	}
	d.x.stop()
	v86Config(d, "docs", v86Change)
	v86Config(d, "docs", v86Undo)
	v86Restart(d, []string{"docs"}, true, func(o *indexOpts) { o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot()) })
	if got := v82Status(t, d.x, paths, c); got != v82Refuse {
		t.Errorf("li under her cookie after a snapshot start past a change and its undo: %s, want 403", got)
	}
	_, c = d.exchange(li)
	if got := v82Status(t, d.x, paths, c); got != v82Reads {
		t.Errorf("li, having exchanged again: %s, want 200", got)
	}
}

// TestV086BranchCookieEndedByBaseChange: docs-b is a local branch of
// docs, whose keys are its base's (§C.4, §10 Branches). li reads docs-b
// whole through k1 under an index cookie. docs changes k1's groups scope
// and changes it back in a later entry: her cookie for docs-b is 403
// from the first on, the entries met one batch each or both in one.
// Until v0.86 a branch's cookie was judged by the documents at the heads
// alone, and read again after the undo.
func TestV086BranchCookieEndedByBaseChange(t *testing.T) {
	t.Parallel()
	for _, together := range []bool{false, true} {
		name := "a batch each"
		if together {
			name = "one batch"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
			d := &v77docs{t: t, s: s, admin: clienttest.NewKey("admin"), k1: clienttest.NewKey("k1"), k2: clienttest.NewKey("k2")}
			op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs")))
			must(op.CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{d.admin.Entry("*"), d.k1.Entry("read"), d.k2.Entry("read")},
				"roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}}))
			nss := []string{"docs", "docs-b"}
			d.w = s.Client(t, client.WithBearer(d.admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append", "config", "branch"})))
			must(d.w.CreateDoc(ctx, "docs", "a", map[string]any{"title": "word a"}))
			must(d.w.CreateBranch(ctx, "docs", client.BranchRequest{Name: "docs-b"}))
			ev := must(edge.New([]byte("s3cret"), "", ""))
			d.x = startSvcWith(t, s.Client(t, client.WithBearer(d.admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}))),
				svcOpts{db: t.TempDir() + "/i.db", ns: nss, untyped: true, now: s.Now},
				func(o *indexOpts) {
					o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
				})
			d.x.caughtUp("docs")
			d.x.caughtUp("docs-b")
			grantFor := func(ns string) string {
				return d.k1.Grant(t, s.Now(), "user:li", []string{ns}, []string{"read"},
					map[string]any{"roles": []any{"reader"}, "exp": s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
			}
			exchange := func(tok string) (string, []*http.Cookie) {
				t.Helper()
				r := p37Do(t, d.x, "POST", "/edge-grants", tok, "", nil, "")
				if r.status != 200 || len(r.body["prefixes"].([]any)) == 0 {
					t.Fatalf("exchange: %d %v", r.status, r.body)
				}
				return r.body["prefixes"].([]any)[0].(string), r.cookies
			}
			pb, cb := exchange(grantFor("docs-b"))
			pd, cd := exchange(grantFor("docs"))
			status := func(p string, c []*http.Cookie) int {
				t.Helper()
				r, _ := p37Follow(t, d.x, p+"?q=word", c, "")
				return r.status
			}
			if b, base := status(pb, cb), status(pd, cd); b != 200 || base != 200 {
				t.Fatalf("li under her cookies: docs-b %d, docs %d", b, base)
			}
			if together {
				d.x.stop()
				v86Config(d, "docs", v86Change)
				v86Config(d, "docs", v86Undo)
				v86Restart(d, nss, false)
			} else {
				for _, ops := range []map[string]any{v86Change, v86Undo} {
					v86Config(d, "docs", ops)
					d.x.caughtUp("docs")
					d.x.ix.ExpireGrantChecks()
				}
			}
			if b, base := status(pb, cb), status(pd, cd); b != 403 || base != 403 {
				t.Errorf("li under her cookies once the base changed k1 and changed it back: docs-b %d, docs %d, want 403 for both", b, base)
			}
			pb2, cb2 := exchange(grantFor("docs-b"))
			if got := status(pb2, cb2); got != 200 {
				t.Errorf("li, having exchanged again for docs-b: %d, want 200", got)
			}
		})
	}
}
