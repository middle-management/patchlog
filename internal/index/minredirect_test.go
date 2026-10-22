package index_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/index"
)

// follow GETs path and follows redirects by hand: it fails on a repeated
// URL or more than maxHops redirects, and returns the final status, body
// and the URLs visited.
func followHops(base, path string, maxHops int) (int, map[string]any, []string, error) {
	var seen []string
	for {
		if slices.Contains(seen, path) {
			return 0, nil, seen, fmt.Errorf("redirect cycle: %v → %s", seen, path)
		}
		seen = append(seen, path)
		if len(seen) > maxHops+1 {
			return 0, nil, seen, fmt.Errorf("more than %d redirects: %v", maxHops, seen)
		}
		r, err := noFollow.Get(base + path)
		if err != nil {
			return 0, nil, seen, err
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode == http.StatusFound {
			path = r.Header.Get("Location")
			continue
		}
		var body map[string]any
		if len(b) > 0 {
			if err := json.Unmarshal(b, &body); err != nil {
				return r.StatusCode, nil, seen, fmt.Errorf("%s: %d %s", path, r.StatusCode, b)
			}
		}
		if r.StatusCode == http.StatusServiceUnavailable && r.Header.Get("Retry-After") == "" {
			return r.StatusCode, body, seen, fmt.Errorf("503 without Retry-After")
		}
		return r.StatusCode, body, seen, nil
	}
}

// gatePurger blocks PurgeTags of one resource's tag until released: an
// apply then sits between its commit and the publication of its
// checkpoint, the window a slow purger opens.
type gatePurger struct {
	tag     string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatePurger) PurgeTags(tags []string) {
	if slices.Contains(tags, g.tag) {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
}

// TestMinDuringPublish: while an apply has committed but not yet published
// its checkpoint, the head pointer with ?min= of that write, and an at URL
// of the previous checkpoint, both settle on the new checkpoint in one
// redirect, never cycling between the old and the new at (§A.4, §A.5).
func TestMinDuringPublish(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	gate := &gatePurger{tag: "r:matches/victim", entered: make(chan struct{}), release: make(chan struct{})}
	s := startSvcWith(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, minWait: 2 * time.Second},
		func(o *index.Options) { o.Purger = gate })
	w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"})
	victim := w.doc(t, "victim", w.match, map[string]any{"title": "Gone soon"})
	old := s.caughtUp("matches")

	purged := must(w.c.Purge(ctx, "matches", "victim", victim.ID, false))
	released := false
	defer func() {
		if !released {
			close(gate.release)
		}
	}()
	select {
	case <-gate.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the purge was not applied")
	}
	q := "?schema=" + url.QueryEscape(w.match)
	for _, p := range []string{
		"/matches" + q + "&min=matches:" + purged,
		"/matches" + q + "&min=" + purged,
		"/matches/at/" + old + q,
		"/matches/at/" + purged + q,
	} {
		status, body, hops, err := followHops(s.http.URL, p, 2)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if status != 200 {
			t.Errorf("%s: %d %v (via %v)", p, status, body, hops)
			continue
		}
		if body["at"] != purged {
			t.Errorf("%s: at %v, want %s (via %v)", p, body["at"], purged, hops)
		}
		if got := strings.Join(resources(body), ","); got != "derby" {
			t.Errorf("%s: hits [%s], want [derby]", p, got)
		}
	}
	close(gate.release)
	released = true
	s.caughtUp("matches")
}

// lateLog holds each response to GET {path} for delay while armed: the
// index learns of new entries of that log late.
type lateLog struct {
	path  string
	delay time.Duration
	armed atomic.Bool
	rt    http.RoundTripper
}

func (l *lateLog) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := l.rt.RoundTrip(r)
	if l.armed.Load() && r.URL.Path == l.path {
		time.Sleep(l.delay)
	}
	return resp, err
}

// TestPurgeNSDuringPublish: while a purge-ns apply has committed, and
// purged the namespace's cache tags, but not yet published its checkpoint,
// the namespace answers as it does once that is out: 410 purged with head
// the purge-ns entry at every URL, with any ?min= too, never a result,
// which caches would keep past the purge; and /_refs leaves it out (§8.5,
// §12, §A.4). A ?min= of the purge-ns asked before the apply is answered
// so too once its wait ends.
func TestPurgeNSDuringPublish(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	gate := &gatePurger{tag: "idx:matches", entered: make(chan struct{}), release: make(chan struct{})}
	late := &lateLog{path: "/ns/matches/log", delay: 300 * time.Millisecond, rt: transport}
	s := startSvcWith(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true, minWait: 10 * time.Second, hc: &http.Client{Transport: late}},
		func(o *index.Options) { o.Purger = gate })
	old := s.caughtUp("matches")
	s.expect("/matches?q=larsson", "cup", "derby")

	must(w.c.PatchConfig(ctx, "matches", must(w.c.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	frozen := s.caughtUp("matches")
	// The index learns of the purge-ns late, so the ?min= of it asked
	// at once waits for its apply (the delay only makes that likely: if
	// the ask comes later, it is answered as in the window below).
	late.armed.Store(true)
	purged := must(w.c.PurgeNamespace(ctx, "matches", frozen))
	type answer struct {
		r   *http.Response
		err error
	}
	waited := make(chan answer, 1)
	go func() {
		r, err := noFollow.Get(s.http.URL + "/matches?q=larsson&min=" + purged)
		waited <- answer{r, err}
	}()
	never := must(w.c.NSHead(ctx, "schemas")).ID // not in matches' log
	released := false
	defer func() {
		if !released {
			close(gate.release)
		}
	}()
	select {
	case <-gate.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the purge-ns was not applied")
	}
	late.armed.Store(false)
	if s.ix.Committed("matches") != purged || s.ix.Checkpoint("matches") == purged {
		t.Fatalf("not between the commit and the publish: committed %s, published %s, purge-ns %s",
			s.ix.Committed("matches"), s.ix.Checkpoint("matches"), purged)
	}
	refs := "/_refs?to=" + url.QueryEscape("/r/matches/derby")
	check := func(when string) {
		t.Helper()
		for _, u := range []string{
			"/matches?q=larsson",
			"/matches?q=larsson&min=" + purged,
			"/matches?q=larsson&min=" + never, // 410 at once, not 503 after the wait
			"/matches/at/" + old + "?q=larsson",
			"/matches/at/" + frozen + "?q=larsson",
			"/matches/at/" + purged + "?q=larsson",
		} {
			if r := s.raw(u, ""); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != purged || r.header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: %s: %d %v %v", when, u, r.status, r.body, r.header)
			}
		}
		if b := s.search(refs, ""); len(b["namespaces"].(map[string]any)) != 0 {
			t.Errorf("%s: /_refs covers %v", when, b["namespaces"])
		}
		// A min naming a purged namespace counts as reached, without a
		// read check (§A.5, v0.71): to the current at, without min.
		if r := s.raw(refs+"&min=matches:"+purged, ""); r.status != 302 || strings.Contains(r.header.Get("Location"), "min=") {
			t.Errorf("%s: /_refs with min of the purge: %d %v %s", when, r.status, r.body, r.header.Get("Location"))
		}
	}
	check("before the publish")
	close(gate.release)
	released = true
	waitFor(t, "the purge-ns to be published", func() bool { return s.ix.Checkpoint("matches") == purged })
	check("after the publish")
	a := <-waited
	if a.err != nil {
		t.Fatalf("min of the purge-ns asked at once: %v", a.err)
	}
	r := a.r
	defer r.Body.Close()
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	if r.StatusCode != 410 || body["code"] != "purged" || body["head"] != purged {
		t.Errorf("min of the purge-ns asked at once: %d %v %s", r.StatusCode, body, r.Header.Get("Location"))
	}
}

// TestMinAfterWriteConcurrent: write, then at once query with the write's
// min from many clients, following redirects: no URL repeats, at most one
// redirect from the head pointer, and the answer covers the write.
func TestMinAfterWriteConcurrent(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, minWait: 30 * time.Second})
	s.caughtUp("matches")
	q := "?schema=" + url.QueryEscape(w.match)
	for i := range 15 {
		name := fmt.Sprintf("m%d", i)
		wr := w.doc(t, name, w.match, map[string]any{"title": "Match " + name})
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p := "/matches" + q + "&min=matches:" + wr.NSID
				status, body, hops, err := followHops(s.http.URL, p, 2)
				switch {
				case err != nil:
					errs <- fmt.Errorf("%s: %v", p, err)
				case status == 503:
					// Allowed by §A.5 when the wait runs out, but not
					// expected here.
					errs <- fmt.Errorf("%s: 503 (via %v)", p, hops)
				case status != 200:
					errs <- fmt.Errorf("%s: %d %v", p, status, body)
				case !slices.Contains(resources(body), name):
					errs <- fmt.Errorf("%s: answer at %v misses %s (via %v)", p, body["at"], name, hops)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
	}
}
