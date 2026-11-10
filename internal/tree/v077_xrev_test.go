package tree_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
)

// XREV (v0.77; §A.1 via §B.5 "purges these tags itself, as §A.1 does",
// §9, §E.2.6): the index's FSVC-9 fix (answer re-reads the namespace's
// encryption after taking its kept generation, errInfoChanged) has no
// tree counterpart. serve reads info with keys.Current before listing()
// takes its kept generation; a raise of the catalog to sealed applied in
// between (its purge counted before gen) leaves the listing computed in
// the clear at the at after the raise, kept, and served there, titles of
// nodes written after the raise included. In a public catalog it is
// served public, immutable. A listing computed at the same at without
// the race carries only sealed values.
func TestV077XrevTreeRaiseBeforeListing(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"grant", "public"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ks := must(keystore.New(keystore.Generate()))
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": read, "keys": []any{k.Entry("*")},
				"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
			must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
			must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Season", "parents": parents("root@a0")}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
			x := startSvc(t, sc, svcOpts{now: s.Now}, withScopeView)
			x.caughtUp("cat")
			full := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
			x.fetch("/cat/children?of=root", full)

			var once sync.Once
			ran := false
			x.s.BeforeListing(func() {
				once.Do(func() {
					ran = true
					h := must(w.NSHead(ctx, "cat"))
					must(w.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
					createNonced(t, w, "cat", "late", map[string]any{"title": "Late zq9y", "parents": parents("root@b0")})
					x.caughtUp("cat")
				})
			})
			// A listing not kept yet, so that it is computed.
			f := x.fetch("/cat/subtree?of=root", full)
			x.s.BeforeListing(nil)
			if !ran {
				t.Fatal("the listing was not computed")
			}
			// Control: a listing computed now, at the same at, shows no
			// title in the clear.
			c := x.fetch("/cat/children?of=root", full)
			cur := "/at/" + x.s.At() + "/"
			if !strings.Contains(c.path, cur) || !strings.Contains(f.path, cur) || strings.Contains(string(c.body), "zq9y") {
				t.Fatalf("control at %s (subtree at %s, current %s): %s", c.path, f.path, x.s.At(), c.body)
			}
			if strings.Contains(string(f.body), "zq9y") {
				t.Errorf("listing at %s, the at after the raise to sealed, in the clear: %s", f.path, f.body)
			}
			again := x.fetch(f.path, full)
			if strings.Contains(string(again.body), "zq9y") {
				t.Errorf("kept listing at %s, served again: Cache-Control %q", again.path, again.header.Get("Cache-Control"))
			}
		})
	}
}

// XREV (v0.77; §A.1 via §B.5): a listing read before a purge of one of
// its tags, the purge applied after its kept generation was taken, is
// neither kept nor served. It is computed again, and while every try
// loses to a purge the answer is 503 behind, never the bytes read before.
func TestV077XrevTreePurgedSinceListing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Season", "parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat")
	rd := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
	f := x.fetch("/cat/children?of=root", rd)
	tags := strings.Split(f.header.Get("Cache-Tag"), ",")
	if len(tags) == 0 || tags[0] == "" {
		t.Fatal("a listing without a Cache-Tag")
	}
	get := func(path string) *http.Response {
		t.Helper()
		req := must(http.NewRequest("GET", x.http.URL+path, nil))
		req.Header.Set("Authorization", "Bearer "+rd)
		r := must(noRedirect.Do(req))
		r.Body.Close()
		return r
	}
	at, _, _ := strings.Cut(f.path, "/children?")

	// Every try loses to a purge of what the listing shows.
	tries := 0
	x.s.AfterGeneration(func() { tries++; x.s.PurgeKept(tags...) })
	r := get(at + "/subtree?of=root")
	x.s.AfterGeneration(nil)
	if r.StatusCode != http.StatusServiceUnavailable || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("a listing that keeps losing to purges after %d tries: %d %q, want 503 no-store", tries, r.StatusCode, r.Header.Get("Cache-Control"))
	}
	if tries < 2 {
		t.Errorf("computed %d times, want it computed again after the purge", tries)
	}

	// One purge: computed again after it, and served.
	var once sync.Once
	tries = 0
	x.s.AfterGeneration(func() { tries++; once.Do(func() { x.s.PurgeKept(tags...) }) })
	r = get(at + "/subtree?of=root")
	x.s.AfterGeneration(nil)
	if r.StatusCode != http.StatusOK || tries != 2 {
		t.Errorf("a listing that lost to one purge: %d after %d tries, want 200 computed twice", r.StatusCode, tries)
	}
}

// Cross-review (conformance lens), Tree-derived access 116 (§B.11.5):
// matches leaves cat's catalog.trust and returns while a reader's g/all
// cookie is live -> a listing at an at that includes matches -> 403 until
// she exchanges again.
func TestV077XconfScenario116(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newP24World(t, "grant", "grant").start(withEdgeGrants)
	p.s.Clock.Advance(2 * time.Second)
	amy := p.grant("user:amy", []string{"cat", "matches"})
	prefix, cookie := p.exchange(amy)
	if prefix != "/cat/g/all" {
		t.Fatalf("prefix %s", prefix)
	}
	if r := p.do("GET", "/cat/g/all/at/"+p.x.s.At()+"/children?of=root", "", "", cookie); r.status != 200 {
		t.Fatalf("before: %d %v", r.status, r.body)
	}
	trust := func(list []any) {
		h := must(p.w.NSHead(ctx, "cat"))
		adm := p.s.Client(t, client.WithBearer(p.admin.Grant(t, p.s.Now(), "user:w", []string{"cat"}, []string{"config"})))
		must(adm.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": list}}))
	}
	before := p.x.s.At()
	trust([]any{})
	waitFor(t, "the service drops matches", func() bool { return p.x.s.At() != before })
	mid := p.x.s.At()
	p.s.Clock.Advance(2 * time.Second)
	trust([]any{"matches"})
	waitFor(t, "the service trusts matches again", func() bool { return p.x.s.At() != mid })
	time.Sleep(10 * time.Millisecond)
	p.x.caughtUp("cat", "matches")
	// Trusted again, matches is waited for until its follower catches up
	// again, though the checkpoint already equals its head.
	waitFor(t, "the service catches up with matches again", func() bool { return p.x.s.CaughtUp("matches") })
	at := p.x.s.At()
	r := p.do("GET", "/cat/g/all/at/"+at+"/children?of=root", "", "", cookie)
	if r.status != 403 {
		t.Errorf("g/all cookie at an at including matches after it left and returned: %d %v", r.status, r.body)
	}
	p.s.Clock.Advance(2 * time.Second)
	_, again := p.exchange(p.grant("user:amy", []string{"cat", "matches"}))
	if r := p.do("GET", "/cat/g/all/at/"+at+"/children?of=root", "", "", again); r.status != 200 {
		t.Errorf("after exchanging again: %d %v", r.status, r.body)
	}
}
