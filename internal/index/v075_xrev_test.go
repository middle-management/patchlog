package index_test

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// Cross-package review of v0.75 (§B.11.9, §A.4): regressions.

// follow asks path with token, following redirects.
func (s *svc) follow(path, token string) resp {
	s.t.Helper()
	r := s.raw(path, token)
	for i := 0; r.status == 302 && i < 5; i++ {
		r = s.raw(r.header.Get("Location"), token)
	}
	return r
}

// TestV075XrevIndexCookieAfterRoleLosesRead (§B.11.9 gs, §A.4, §2.1): the
// index's cookie for reads:matches:g:{gs} is judged from what the exchange
// recorded, and is 403 at an at where the rules its marker digests differ,
// of each effective role that lists read among them. Folders give fans the
// role viewer; the reader's grant reads matches only through its role
// reader. Once reader no longer lists read, the grant reads nothing there
// (403), and neither does the cookie.
func TestV075XrevIndexCookieAfterRoleLosesRead(t *testing.T) {
	t.Parallel()
	v75xCookieLosesRead(t, "/roles/reader/can")
}

// TestV075XrevIndexCookieAfterKeyLosesRead: likewise once the key that
// signed the grant no longer lists read (§C.2).
func TestV075XrevIndexCookieAfterKeyLosesRead(t *testing.T) {
	t.Parallel()
	v75xCookieLosesRead(t, "/keys/1/can")
}

// v75xCookieLosesRead replaces can at path in matches' document with
// [create] once a reader's cookie reads derby and shared: neither its
// grant nor the cookie reads matches then.
func v75xCookieLosesRead(t *testing.T, path string) {
	ctx := context.Background()
	w := newV75X(t, false)
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
		[]any{map[string]any{"op": "add", "path": "/roles/viewer", "value": map[string]any{"can": []any{"read"}}}}))
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:fans": []any{"viewer"}}})
	w.x.caughtUp("matches")
	fan := w.reader("user:fan", []any{"fans"})
	r := p37Do(t, w.x, "POST", "/edge-grants", fan, "", nil, "")
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	var prefix string
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/matches/") {
			prefix = p.(string)
		}
	}
	got, _ := p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("under the cookie: %d %v", got.status, got.body)
	}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
		[]any{map[string]any{"op": "replace", "path": path, "value": []any{"create"}}}))
	w.x.caughtUp("matches")
	if g := w.x.raw("/matches", fan); g.status != 403 {
		t.Fatalf("the grant after %s lost read: %d %v", path, g.status, g.body)
	}
	got, _ = p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 403 {
		t.Errorf("under the cookie once %s lost read: %d %v", path, got.status, p37Hits(got.body))
	}
}

// TestV075XrevCheckpointSharedAt (§B.11.9 gs, §B.11.5): a grant reads at
// its own gs as of the URL's at, which the index judges from the
// checkpoint it holds for that at. Where it follows both a covered content
// namespace and the catalog that decides it, their combined checkpoints
// are over the same members at the same ns_ids, so they share an at: the
// catalog's checkpoint, computed for one of its readers, must not stand in
// for the content namespace's, so that TestV075IndexOldGsAt's older-at
// redirect still holds.
func TestV075XrevCheckpointSharedAt(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	x := w.start(false, "cat-season", "matches")
	w.x = x
	fan := w.reader("user:fan", []any{"fans"})
	_, gs1, at1 := w.pointer("/matches?limit=3", fan)
	r := x.raw("/cat-season", w.catReader("user:fan", "fans"))
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.HasPrefix(loc, "/cat-season/g/") {
		t.Fatalf("pointer: %d %s %v", r.status, loc, r.body)
	}
	if p := strings.Split(strings.SplitN(loc, "?", 2)[0], "/"); p[5] != at1 {
		t.Fatalf("cat-season's at %s, matches' %s: not shared", p[5], at1)
	}
	w.put("cat-season", "fanclub", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"user:fan": []any{"reader"}}})
	x.caughtUp("cat-season")
	loc2, gs2, at2 := w.pointer("/matches?limit=1", fan)
	if gs1 == gs2 || at1 == at2 {
		t.Fatalf("gs %s at %s unchanged", gs2, at2)
	}
	old := "/matches/g/" + gs1 + "/at/" + at1 + "?limit=1"
	if r := x.raw(old, fan); r.status != 302 || r.header.Get("Location") != loc2 {
		t.Errorf("GET %s: %d %q %v (want 302 to %s, as TestV075IndexOldGsAt)", old, r.status, r.header.Get("Location"), r.body, loc2)
	}
}

// TestV075XrevRefsPurgeBeforeStore (§E.2.6, §8.5, §A.4): a /_refs answer
// with a sealed hit is bound to its URL and stored. One read before a
// purge in a covered namespace it reads in part commits, and stored after
// it, would outlive the purge: the namespace moved, so the store's own
// Retire doesn't run, and the purge's tags were dropped before it was
// stored. It is served to the request that read it alone, and not stored:
// its URL serves the answer after the purge.
func TestV075XrevRefsPurgeBeforeStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	w := newV75XOn(t, s)
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec",
		map[string]any{"read": "public", "keys": []any{w.k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	sw := s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create"})))
	must(createNonced(sw, "sec", "s", w.page("s", "cup")))

	iJWK, iPriv, _ := seal.GenerateRecipient()
	all := []string{"schemas", "cat-season", "matches", "sec"}
	ic := s.Client(t, client.WithBearer(w.k.Grant(t, s.Now(), "svc:indexer", all, []string{"read"}, map[string]any{"enc": iJWK})),
		client.WithKeys(client.NewKeys(iPriv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "sec"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Recipient = iPriv })
	x.caughtUp("matches")
	x.caughtUp("sec")
	w.x = x

	fan := w.reader("user:fan", []any{"fans"})
	var once atomic.Bool
	var mu sync.Mutex
	var stale []string
	staleViews := func() {
		mu.Lock()
		defer mu.Unlock()
		for v, tags := range x.ix.SealedViews() {
			if strings.Contains(tags, "r:matches/derby") {
				stale = append(stale, v)
			}
		}
	}
	x.ix.OnRefsRead(func() {
		if !once.CompareAndSwap(false, true) {
			// The answer computed again once matches moved (refsAnswer):
			// until it is stored, the one read before the purge would be
			// served at its URL, were it stored.
			staleViews()
			return
		}
		// derby is purged after the answer has read it, before it is
		// stored.
		must(w.admin.Purge(ctx, "matches", "derby", must(w.admin.Head(ctx, "matches", "derby")).ID, false))
		x.caughtUp("matches")
	})
	p := x.raw("/_refs?to="+url.QueryEscape("/r/target/x"), fan)
	loc := p.header.Get("Location")
	if p.status != 302 || !once.Load() {
		t.Fatalf("pointer: %d %q %v (computed: %v)", p.status, loc, p.body, once.Load())
	}
	staleViews()
	if len(stale) > 0 {
		t.Errorf("an answer read before derby's purge was stored at %v", stale)
	}
	if r := x.follow(loc, fan); r.status != 200 || refsAllHits(r.body) != "matches/shared sec/s" {
		t.Errorf("GET %s after the purge: %d %v", loc, r.status, r.body)
	}
}
