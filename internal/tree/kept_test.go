package tree_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestKeptListings (§A.4 "Bounded redirects", §B.5): a listing stays
// answerable at its at after the checkpoint moves on, showing what it
// showed there, until a purge of a resource it shows, kept.For, or a
// change in what the reader reads whole drops it; its at is then
// redirected to the current one.
func TestKeptListings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	var mu sync.Mutex
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	x := startSvc(t, w.c, svcOpts{now: clock})
	x.caughtUp("cat", "matches")
	first := x.s.At()
	locs := map[string]string{}
	for _, q := range []string{"children?of=season", "children?of=derbies", "roots"} {
		r := x.raw("/cat/"+q, "")
		if r.status != 302 || r.header.Get("Location") != "/cat/at/"+first+"/"+q {
			t.Fatalf("%s: %d %s", q, r.status, r.header.Get("Location"))
		}
		locs[q] = r.header.Get("Location")
	}

	// The checkpoint moves on; the at the redirect named answers with what
	// it showed there, as an immutable listing.
	w.folder(t, "extra", "Extra", "season@b0")
	x.caughtUp("cat")
	r := x.raw(locs["children?of=season"], "")
	if r.status != 200 || r.body["at"] != first || r.header.Get("X-Namespace-Revision") != first || r.header.Get("Cache-Control") != "public, max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("kept: %d %v %v", r.status, r.body, r.header)
	}
	if got := names(r.body["children"]); got != "matches.opener,matches.derby" {
		t.Errorf("kept children [%s]", got)
	}
	if got := names(x.get("/cat/children?of=season", "")["children"]); !strings.Contains(got, "extra") {
		t.Errorf("current children [%s]", got)
	}
	// A listing nobody asked for there is redirected.
	if r := x.raw("/cat/at/"+first+"/children?of=root", ""); r.status != 302 || r.header.Get("Location") != "/cat/at/"+x.s.At()+"/children?of=root" {
		t.Errorf("not kept: %d %s", r.status, r.header.Get("Location"))
	}

	// A purge drops the kept listings that show the resource.
	must(w.c.Purge(ctx, "matches", "derby", must(w.c.Head(ctx, "matches", "derby")).ID, false))
	x.caughtUp("matches")
	for q, want := range map[string]int{"children?of=season": 302, "children?of=derbies": 302, "roots": 200} {
		if r := x.raw(locs[q], ""); r.status != want {
			t.Errorf("%s after the purge: %d, want %d", q, r.status, want)
		}
	}

	// kept.For later, nothing is kept.
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if r := x.raw(locs["roots"], ""); r.status != 302 {
		t.Errorf("after kept.For: %d", r.status)
	}

	// Once matches turns private, an anonymous reader isn't served what
	// was listed while it was public: neither its URL space nor a gs says.
	r = x.raw("/cat/children?of=season", "")
	loc := r.header.Get("Location")
	if b := x.get(loc, ""); b["children"].([]any)[0].(map[string]any)["head"] == nil {
		t.Fatalf("no heads while public: %v", b)
	}
	must(w.c.PatchConfig(ctx, "matches", must(w.c.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	x.caughtUp("matches")
	if r := x.raw(loc, ""); r.status != 302 {
		t.Errorf("after matches went private: %d %v", r.status, r.body)
	}
}

// TestHopsUnderWrites (§A.4 "Bounded redirects", §B.5): under a steady
// write rate, a listing from the head pointer is answered at the at it is
// redirected to, however often the checkpoint moves meanwhile: one
// redirect, never a chase. So too under a stream of purges of resources
// the listing doesn't show.
func TestHopsUnderWrites(t *testing.T) {
	t.Parallel()
	qs := []string{"children?of=season", "roots", "subtree?of=root", "where?item=" + "/r/matches/derby"}
	t.Run("writes", func(t *testing.T) {
		t.Parallel()
		w := setup(t)
		w.seed(t)
		x := startSvc(t, w.c, svcOpts{})
		x.caughtUp("cat", "matches")
		// 40 writes a second, to the catalog and to the content namespace
		// in turn; the core's clock moves a second each, so its rate
		// buckets (§6.6) refill.
		hopsUnder(t, x, 4, qs, 25*time.Millisecond, 0, func(ctx context.Context, i int) error {
			w.s.Clock.Advance(time.Second)
			var err error
			if i%2 == 0 {
				_, err = w.c.CreateDoc(ctx, "matches", fmt.Sprintf("m%d", i), map[string]any{"title": "Match"})
			} else {
				_, err = w.c.CreateDoc(ctx, "cat", fmt.Sprintf("f%d", i), map[string]any{"title": "Folder", "parents": parents("derbies")})
			}
			return err
		})
	})
	t.Run("purges", func(t *testing.T) {
		t.Parallel()
		w := setup(t)
		w.seed(t)
		ids := make([]string, 300)
		for i := range ids {
			w.s.Clock.Advance(time.Second)
			ids[i] = w.content(t, "matches", fmt.Sprintf("m%d", i))
		}
		x := startSvc(t, w.c, svcOpts{})
		x.caughtUp("cat", "matches")
		// Up to 200 purges a second, each of a document no listing shows.
		hopsUnder(t, x, 8, qs, 5*time.Millisecond, len(ids), func(ctx context.Context, i int) error {
			w.s.Clock.Advance(time.Second)
			_, err := w.c.Purge(ctx, "matches", fmt.Sprintf("m%d", i), ids[i], false)
			return err
		})
	})
}

// hops GETs path, following redirects by hand up to max times, and returns
// how many it followed and the final status and at.
func hops(base, path string, max int) (int, int, string, error) {
	for n := 0; ; n++ {
		r, err := noRedirect.Get(base + path)
		if err != nil {
			return n, 0, "", err
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != http.StatusFound || n == max {
			return n, r.StatusCode, r.Header.Get("X-Namespace-Revision"), nil
		}
		path = r.Header.Get("Location")
	}
}

// hopsUnder runs write every tick, n times (0: until the readers are done),
// while each reader follows listings from the head pointer, 40 and on until
// the checkpoint has moved 10 times, and checks that every follow took one
// redirect.
func hopsUnder(t *testing.T, x *svc, readers int, qs []string, every time.Duration, n int, write func(ctx context.Context, i int) error) {
	ctx, cancel := context.WithCancel(context.Background())
	var writes sync.WaitGroup
	writes.Add(1)
	go func() {
		defer writes.Done()
		tick := time.NewTicker(every)
		defer tick.Stop()
		for i := 0; n == 0 || i < n; i++ {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if err := write(ctx, i); err != nil && ctx.Err() == nil {
				t.Error(err)
				return
			}
		}
	}()
	defer func() { cancel(); writes.Wait() }()

	start := x.batches()
	deadline := time.Now().Add(30 * time.Second)
	var mu sync.Mutex
	hist := map[int]int{}
	ats := map[string]bool{}
	var wg sync.WaitGroup
	for r := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; (i < 40 || x.batches() < start+10) && time.Now().Before(deadline); i++ {
				n, status, at, err := hops(x.http.URL, "/cat/"+qs[(r+i)%len(qs)], 5)
				mu.Lock()
				hist[n]++
				ats[at] = true
				mu.Unlock()
				if err != nil || status != 200 {
					t.Errorf("status %d after %d redirects: %v", status, n, err)
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("redirects per listing: %v; answered at %d checkpoints; %d applied meanwhile", hist, len(ats), x.batches()-start)
	if len(hist) != 1 || hist[1] == 0 {
		t.Errorf("redirects per listing %v, want 1 each", hist)
	}
	if len(ats) < 2 {
		t.Errorf("answered at %d checkpoints: the checkpoint did not move", len(ats))
	}
}
