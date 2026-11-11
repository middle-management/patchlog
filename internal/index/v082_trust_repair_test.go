package index_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// The catalog.trust of a purged catalog the index serves, lost by a
// release before v0.82 (SERVICES §B.11.9 Where, v0.82: "a purged
// catalog's catalog.trust is the last one the origin stored or the
// service read"; §A.4). Until v0.82 the index could apply cat-season's
// purge-ns (ns_state.purged = 1) and hold no catalog_trust row of it:
// forgetMember deleted it when the reconciler stopped cat-season's
// follower for visibility, and a snapshot that met it purged read no
// document. Both are fixed for a database written since, but a database
// already in that state stayed in it: a purged namespace has no follower,
// so nothing read its document again, across restarts, with or without
// snapshots. The tests plant that state by deleting the row.

// trustRepair is an index of a database in the state above.
type trustRepair struct {
	t     *testing.T
	core  *client.Client
	db    string
	ns    []string
	reads atomic.Int32 // of the lost trust's document, by the running index
	mods  []func(*indexOpts)
	now   func() time.Time
}

// start starts an index on r.db, with hook called before each read of
// the document of a namespace whose trust is lost, and returns it with a
// function that stops it.
func (r *trustRepair) start(snapshot bool, hook func(ctx context.Context, ns string)) (*svc, func()) {
	r.t.Helper()
	r.reads.Store(0)
	mods := append([]func(*indexOpts){func(o *indexOpts) {
		o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
		if snapshot {
			o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot())
		}
	}}, r.mods...)
	x := startSvcWith(r.t, r.core, svcOpts{db: r.db, ns: r.ns, untyped: true, noRun: true, now: r.now}, mods...)
	x.ix.OnTrustRepair(func(ctx context.Context, ns string) {
		r.reads.Add(1)
		if hook != nil {
			hook(ctx, ns)
		}
	}, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { x.ix.Run(ctx); close(done) }()
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-done; x.stop() }) }
	r.t.Cleanup(stop)
	return x, stop
}

// status is the answer to tok's query of matches, the grant checker's
// documents read anew.
func (r *trustRepair) status(x *svc, tok string) int {
	x.ix.ExpireGrantChecks()
	return x.raw("/matches", tok).status
}

// rows counts the catalog_trust rows of ns.
func (r *trustRepair) rows(x *svc, ns string) int64 {
	return must(x.ix.ExecForTest(context.Background(), `UPDATE catalog_trust SET trust = trust WHERE ns = ?`, ns))
}

// purgeApplied waits until x holds ns's purge.
func (r *trustRepair) purgeApplied(x *svc, ns string) {
	r.t.Helper()
	waitFor(r.t, "the index holds the purge of "+ns, func() bool {
		return must(x.ix.ExecForTest(context.Background(), `UPDATE ns_state SET purged = 1 WHERE ns = ? AND purged = 1`, ns)) == 1
	})
}

// newTrustRepair is the world of v75x with cat-season purged, an index
// database that applied the purge, and li, a partial reader of matches
// through a key that needs no at: matches is covered and dark.
func newTrustRepair(t *testing.T) (r *trustRepair, li string) {
	t.Helper()
	ctx := context.Background()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	rd := clienttest.NewKey("rd")
	e := rd.Entry("read")
	e["rules"] = []any{v77TypeRule}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/keys/-", "value": e}}))
	li = rd.Grant(t, w.s.Now(), "user:li", []string{"matches"}, []string{"read"}, map[string]any{"groups": []any{"fans"}, "roles": []any{"reader"}})
	v82PurgeNS(w, "cat-season")
	r = &trustRepair{t: t, db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "cat-season"}, now: w.s.Now,
		core: w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", []string{"schemas", "cat-season", "matches"}, []string{"read"})))}
	x, stop := r.start(false, nil)
	x.caughtUp("matches")
	r.purgeApplied(x, "cat-season")
	waitFor(t, "matches covered and dark", func() bool { return r.status(x, li) == 302 })
	if n := r.reads.Load(); n != 0 {
		t.Fatalf("%d reads of a trust that isn't lost", n)
	}
	stop()
	return r, li
}

// lose deletes cat-season's catalog_trust row, as v0.27.0 left it, in an
// index that isn't running: one that runs may not have looked for lost
// trusts yet, and would read this one again.
func (r *trustRepair) lose() {
	r.t.Helper()
	x := startSvcWith(r.t, r.core, svcOpts{db: r.db, ns: r.ns, untyped: true, noRun: true, now: r.now}, r.mods...)
	defer x.stop()
	if n := must(x.ix.ExecForTest(context.Background(), `DELETE FROM catalog_trust WHERE ns = 'cat-season'`)); n != 1 {
		r.t.Fatalf("deleted %d rows", n)
	}
}

// TestV082LostTrustRepaired: an index that starts on such a database
// reads cat-season's document once, at the purge-ns entry it holds as its
// checkpoint, where the origin still serves it, and records its trust:
// li, 403 with no marker until then, is redirected under a g: marker and
// reads matches dark, in the same process, and the next start reads
// nothing. With or without snapshots. Before, it was 403 for good across
// both restarts, and only -rebuild repaired it.
func TestV082LostTrustRepaired(t *testing.T) {
	t.Parallel()
	r, li := newTrustRepair(t)
	for _, c := range []struct {
		name     string
		snapshot bool
	}{{"restart", false}, {"restart -snapshot", true}} {
		r.lose()
		// The read is held: the index starts, follows and answers
		// meanwhile, li as before.
		release := make(chan struct{})
		x, stop := r.start(c.snapshot, func(ctx context.Context, ns string) {
			if ns != "cat-season" {
				t.Errorf("%s: the trust of %s is read", c.name, ns)
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		x.caughtUp("matches")
		waitFor(t, "the read of cat-season's document", func() bool { return r.reads.Load() == 1 })
		if q := x.raw("/matches", li); q.status != 403 {
			t.Errorf("%s: before the trust is read: %d %v, want 403", c.name, q.status, q.body)
		}
		// What she is answered meanwhile, at /_refs and at an exchange,
		// doesn't outlive the read (below).
		refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
		before := x.follow(refs, li)
		ex := p37Do(t, x, "POST", "/edge-grants", li, "", nil, "")
		t.Logf("%s: before the trust is read: /_refs %d %v, exchange %d %v", c.name, before.status, before.body, ex.status, ex.body)
		close(release)
		// (Not by counting its rows: rows writes, outside the index's
		// write lock, and a write it made busy is one more read.)
		waitFor(t, c.name+": the trust read again", func() bool { return x.raw("/matches", li).status != 403 })
		q := x.raw("/matches", li)
		if q.status != 302 || !strings.HasPrefix(q.header.Get("Location"), "/matches/g/") {
			t.Fatalf("%s: the lost trust of a purged served catalog is not read again: li %d %v to %q, want 302 under a g: marker", c.name, q.status, q.body, q.header.Get("Location"))
		}
		for _, path := range []string{"/matches", refs} {
			if a := x.follow(path, li); a.status != 200 || len(resources(a.body)) != 0 {
				t.Errorf("%s: li at %s: %d %v, want matches dark", c.name, path, a.status, a.body)
			}
		}
		prefix, cookies := v081Exchange(t, x, li, "matches")
		if !strings.HasPrefix(q.header.Get("Location"), prefix+"/at/") {
			t.Errorf("%s: her exchange gives %s, her query redirects to %s", c.name, prefix, q.header.Get("Location"))
		}
		if got, _ := p37Follow(t, x, prefix, cookies, ""); got.status != 200 || len(p37Hits(got.body)) != 0 {
			t.Errorf("%s: under her cookie: %d %v, want no hits", c.name, got.status, got.body)
		}
		if n, rows := r.reads.Load(), r.rows(x, "cat-season"); n != 1 || rows != 1 {
			t.Errorf("%s: %d reads of cat-season's document, %d rows of its trust, want 1 and 1", c.name, n, rows)
		}
		stop()
		// Recorded: the next start reads nothing, and answers alike.
		x, stop = r.start(c.snapshot, nil)
		x.caughtUp("matches")
		waitFor(t, c.name+": covered after another start", func() bool { return r.status(x, li) == 302 })
		if n := r.reads.Load(); n != 0 {
			t.Errorf("%s: %d reads of a trust the index holds", c.name, n)
		}
		stop()
	}
}

// trustFailing fails, while on, every read of a namespace document at a
// revision under prefix, with status and body.
type trustFailing struct {
	base   http.RoundTripper
	prefix string
	body   string
	status atomic.Int32
	n      atomic.Int32
}

func (f *trustFailing) RoundTrip(req *http.Request) (*http.Response, error) {
	if st := f.status.Load(); st != 0 && strings.HasPrefix(req.URL.Path, f.prefix) {
		f.n.Add(1)
		return &http.Response{StatusCode: int(st), Status: http.StatusText(int(st)), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header:  http.Header{"Content-Type": {"application/json"}},
			Body:    io.NopCloser(strings.NewReader(f.body)),
			Request: req}, nil
	}
	return f.base.RoundTrip(req)
}

// TestV082LostTrustRetried: while the origin fails the read of
// cat-season's document (503), the index starts, follows matches and
// answers, li 403 as before, and reads again after a pause; once the
// origin answers, the trust is recorded and li reads matches dark, with
// no restart.
func TestV082LostTrustRetried(t *testing.T) {
	t.Parallel()
	r, li := newTrustRepair(t)
	r.lose()
	f := &trustFailing{base: http.DefaultTransport, prefix: "/ns/cat-season/rev/", body: `{"code":"unavailable","message":"down"}`}
	f.status.Store(http.StatusServiceUnavailable)
	r.core = r.core.With(client.WithHTTPClient(&http.Client{Transport: f}))
	x, _ := r.start(false, nil)
	x.caughtUp("matches")
	waitFor(t, "reads of cat-season's document, failed", func() bool { return r.reads.Load() >= 3 && f.n.Load() >= 3 })
	if q := x.raw("/matches", li); q.status != 403 {
		t.Errorf("while its document can't be read: %d %v, want 403", q.status, q.body)
	}
	if n := r.rows(x, "cat-season"); n != 0 {
		t.Errorf("%d rows recorded from a read that failed", n)
	}
	f.status.Store(0)
	waitFor(t, "the trust read once the origin answers", func() bool { return r.status(x, li) == 302 })
	n := r.reads.Load()
	time.Sleep(50 * time.Millisecond)
	if m := r.reads.Load(); m != n {
		t.Errorf("read again once recorded: %d reads, then %d", n, m)
	}
}

// TestV082LostTrustGoneStays: where the purged catalog's document is 410
// too (a sealed namespace's, §8.5), or refused, the lost trust can't be
// read again:
// the index reads once, records nothing and doesn't try again while it
// runs; it starts, follows matches and answers li 403 with no marker, as
// one that never read the catalog's trust ("one a service never read
// counts as no catalog"). The 410 is the origin's own for a sealed
// catalog (sealed), or one put in its place for the unsealed cat-season
// (answered).
func TestV082LostTrustGoneStays(t *testing.T) {
	t.Parallel()
	t.Run("answered", func(t *testing.T) {
		t.Parallel()
		r, li := newTrustRepair(t)
		r.lose()
		f := &trustFailing{base: http.DefaultTransport, prefix: "/ns/cat-season/rev/", body: `{"code":"purged","message":"the namespace is purged"}`}
		f.status.Store(http.StatusGone)
		r.core = r.core.With(client.WithHTTPClient(&http.Client{Transport: f}))
		lostTrustStays(t, r, li, "cat-season")
	})
	// Nor is one the origin refuses the index (404, as §7 answers a
	// namespace the reader can't read) read again while it runs.
	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		r, li := newTrustRepair(t)
		r.lose()
		f := &trustFailing{base: http.DefaultTransport, prefix: "/ns/cat-season/rev/", body: `{"code":"not_found","message":"no such namespace"}`}
		f.status.Store(http.StatusNotFound)
		r.core = r.core.With(client.WithHTTPClient(&http.Client{Transport: f}))
		lostTrustStays(t, r, li, "cat-season")
	})
	t.Run("sealed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
		k, rd, cat := clienttest.NewKey("k"), clienttest.NewKey("rd"), clienttest.NewKey("catalog-01")
		mk := func(ns string, doc map[string]any) {
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
		}
		mk("schemas", map[string]any{"read": "public", "keys": []any{k.Entry("*")}})
		mk("cat-sec", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "catalog": map[string]any{"trust": []any{"matches"}},
			"encryption": map[string]any{"level": "sealed"}})
		e := rd.Entry("read")
		e["rules"] = []any{v77TypeRule}
		// matches trusts cat-sec through a key whose requireAt names it.
		at := cat.Entry("read")
		at["requireAt"], at["maxTtl"], at["rules"] = "cat-sec", "PT15M", []any{v77TypeRule}
		mk("matches", map[string]any{"read": "grant", "keys": []any{k.Entry("*"), at, e},
			"roles":    map[string]any{"reader": map[string]any{"can": []any{"read"}}},
			"catalogs": map[string]any{"cat-sec": map[string]any{"place": []any{}}}})
		li := rd.Grant(t, s.Now(), "user:li", []string{"matches"}, []string{"read"}, map[string]any{"groups": []any{"fans"}, "roles": []any{"reader"}})
		all := []string{"schemas", "cat-sec", "matches"}
		admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:root", all, []string{"read", "create", "config", "purge-ns"})),
			client.WithKeys(client.NewKeys(nil)))
		jwk, priv, err := seal.GenerateRecipient()
		if err != nil {
			t.Fatal(err)
		}
		r := &trustRepair{t: t, db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "cat-sec"}, now: s.Now,
			core: s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", all, []string{"read"}, map[string]any{"enc": jwk})),
				client.WithKeys(client.NewKeys(priv))),
			mods: []func(*indexOpts){func(o *indexOpts) { o.Recipient = priv }}}
		// The index applies cat-sec's document, then its purge.
		x, stop := r.start(false, nil)
		x.caughtUp("matches")
		x.caughtUp("cat-sec")
		must(admin.PatchConfig(ctx, "cat-sec", must(admin.NSHead(ctx, "cat-sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		purged := must(admin.PurgeNamespace(ctx, "cat-sec", must(admin.NSHead(ctx, "cat-sec")).ID))
		r.purgeApplied(x, "cat-sec")
		if _, err := r.core.NSDoc(ctx, "cat-sec", purged); !client.IsPurged(err) {
			t.Fatalf("the sealed catalog's document at its purge: %v, want 410", err)
		}
		if n := r.rows(x, "cat-sec"); n != 1 {
			t.Fatalf("%d rows of cat-sec's trust once its purge is applied", n)
		}
		// With the trust it recorded while it followed cat-sec, matches
		// is covered and dark: what the lost row takes away.
		waitFor(t, "matches covered and dark", func() bool { return r.status(x, li) == 302 })
		if n := must(x.ix.ExecForTest(ctx, `DELETE FROM catalog_trust WHERE ns = 'cat-sec'`)); n != 1 {
			t.Fatalf("deleted %d rows", n)
		}
		stop()
		lostTrustStays(t, r, li, "cat-sec")
	})
}

// lostTrustStays starts r's index, whose read of cat's document is 410
// or refused: read once, nothing recorded, li 403 with no marker, matches followed.
func lostTrustStays(t *testing.T, r *trustRepair, li, cat string) {
	t.Helper()
	for _, snapshot := range []bool{false, true} {
		x, stop := r.start(snapshot, nil)
		x.caughtUp("matches")
		waitFor(t, "the read of "+cat+"'s document", func() bool { return r.reads.Load() == 1 })
		time.Sleep(100 * time.Millisecond) // more than a few of the pauses of a read tried again
		if n := r.reads.Load(); n != 1 {
			t.Errorf("snapshot %v: %d reads of a document that can't be read, want 1", snapshot, n)
		}
		if n := r.rows(x, cat); n != 0 {
			t.Errorf("snapshot %v: %d rows recorded from no document", snapshot, n)
		}
		q := x.raw("/matches", li)
		if q.status != 403 || q.header.Get("Location") != "" {
			t.Errorf("snapshot %v: li %d %v, want 403 with no marker", snapshot, q.status, q.body)
		}
		if h := x.caughtUp("matches"); h == "" {
			t.Errorf("snapshot %v: matches isn't followed", snapshot)
		}
		stop()
	}
}
