package index_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// hops GETs path, following redirects by hand up to max times, and returns
// how many it followed and the final status and at.
func hops(base, path string, max int) (int, int, string, error) {
	for n := 0; ; n++ {
		r, err := noFollow.Get(base + path)
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

// TestKeptAt (B9): a result stays answerable at its at after the checkpoint
// moves on, showing what it showed there, until a purge of a resource it
// shows, or of any with counts, or keepFor, drops it; its at is then
// redirected to the current one.
func TestKeptAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	var mu sync.Mutex
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, now: clock})
	derby := w.doc(t, "derby", w.match, map[string]any{"title": "The Derby", "status": "done"})
	w.doc(t, "cup", w.match, map[string]any{"title": "Cup final", "status": "planned"})
	first := s.caughtUp("matches")
	locs := map[string]string{}
	for _, q := range []string{"?q=derby", "?q=cup", "?q=cup&counts=/status"} {
		r := s.raw("/matches"+q, "")
		if r.status != 302 || !strings.HasPrefix(r.header.Get("Location"), "/matches/at/"+first+"?") {
			t.Fatalf("%s: %d %s", q, r.status, r.header.Get("Location"))
		}
		locs[q] = r.header.Get("Location")
	}

	// The checkpoint moves on; the at the redirect named answers with what
	// it showed there, as an immutable result.
	w.doc(t, "rematch", w.match, map[string]any{"title": "Derby rematch"})
	s.caughtUp("matches")
	r := s.raw(locs["?q=derby"], "")
	if r.status != 200 || r.body["at"] != first || r.header.Get("X-Namespace-Revision") != first || r.header.Get("Cache-Control") != "public, max-age=86400, s-maxage=31536000, immutable" {
		t.Fatalf("kept: %d %v %v", r.status, r.body, r.header)
	}
	if got := strings.Join(resources(r.body), ","); got != "derby" {
		t.Errorf("kept hits [%s], want [derby]", got)
	}
	s.expect("/matches?q=derby", "derby", "rematch")
	// A query nobody asked there is redirected.
	if r := s.raw("/matches/at/"+first+"?q=rematch", ""); r.status != 302 || r.header.Get("Location") != "/matches/at/"+s.ix.Checkpoint("matches")+"?q=rematch" {
		t.Errorf("not kept: %d %s", r.status, r.header.Get("Location"))
	}

	// A purge drops the kept results that show the resource, and those with
	// counts.
	must(w.c.Purge(ctx, "matches", "derby", derby.ID, false))
	s.caughtUp("matches")
	for q, want := range map[string]int{"?q=derby": 302, "?q=cup&counts=/status": 302, "?q=cup": 200} {
		if r := s.raw(locs[q], ""); r.status != want {
			t.Errorf("%s after the purge: %d, want %d", q, r.status, want)
		}
	}

	// keepFor later, nothing is kept.
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if r := s.raw(locs["?q=cup"], ""); r.status != 302 {
		t.Errorf("after keepFor: %d", r.status)
	}
}

// TestHopsUnderWrites (B9): under a steady write rate, a query from the head
// pointer is answered at the at it is redirected to, however often the
// checkpoint moves meanwhile: one redirect, never a chase (§A.4). So too
// under a stream of purges (as a §8.6 retention sweep makes) of resources
// the result doesn't show.
func TestHopsUnderWrites(t *testing.T) {
	t.Parallel()
	t.Run("writes", func(t *testing.T) {
		t.Parallel()
		w := setup(t)
		s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
		w.doc(t, "derby", w.match, map[string]any{"title": "The Derby", "status": "done"})
		s.caughtUp("matches")
		// 40 writes a second; the core's clock moves a second each, so its
		// rate buckets (§6.6) refill.
		q := []string{"?q=derby", "?facet[/status]=done", "?sort=/title&limit=5", "?schema=" + url.QueryEscape(w.match)}
		hopsUnder(t, s, 4, q, 25*time.Millisecond, 0, func(ctx context.Context, i int) error {
			w.s.Clock.Advance(time.Second)
			_, err := w.c.CreateDoc(ctx, "matches", fmt.Sprintf("m%d", i), map[string]any{"$schema": w.match, "title": "Match", "status": "planned"})
			return err
		})
	})
	t.Run("purges", func(t *testing.T) {
		t.Parallel()
		w := setup(t)
		s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
		w.doc(t, "derby", w.match, map[string]any{"title": "The Derby", "status": "done"})
		ids := make([]string, 300)
		for i := range ids {
			w.s.Clock.Advance(time.Second)
			ids[i] = w.doc(t, fmt.Sprintf("m%d", i), w.match, map[string]any{"title": "Match", "status": "planned"}).ID
		}
		s.caughtUp("matches")
		// Up to 200 purges a second, each of a document neither query shows.
		hopsUnder(t, s, 8, []string{"?q=derby", "?facet[/status]=done"}, 5*time.Millisecond, len(ids), func(ctx context.Context, i int) error {
			w.s.Clock.Advance(time.Second)
			_, err := w.c.Purge(ctx, "matches", fmt.Sprintf("m%d", i), ids[i], false)
			return err
		})
	})
}

// hopsUnder runs write every tick, n times (0: until the readers are done),
// while each reader follows queries from the head pointer, 40 and on until
// the checkpoint has moved 10 times, and checks that every follow took one
// redirect.
func hopsUnder(t *testing.T, s *svc, readers int, q []string, every time.Duration, n int, write func(ctx context.Context, i int) error) {
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

	start := len(s.batches())
	deadline := time.Now().Add(30 * time.Second)
	var mu sync.Mutex
	hist := map[int]int{}
	ats := map[string]bool{}
	var wg sync.WaitGroup
	for r := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; (i < 40 || len(s.batches()) < start+10) && time.Now().Before(deadline); i++ {
				n, status, at, err := hops(s.http.URL, "/matches"+q[(r+i)%len(q)], 5)
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
	t.Logf("redirects per query: %v; answered at %d checkpoints; %d applied meanwhile", hist, len(ats), len(s.batches())-start)
	if len(hist) != 1 || hist[1] == 0 {
		t.Errorf("redirects per query %v, want 1 each", hist)
	}
	if len(ats) < 2 {
		t.Errorf("answered at %d checkpoints: the checkpoint did not move", len(ats))
	}
}
