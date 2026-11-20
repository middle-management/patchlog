package server

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Spec v0.86, §7.7 Intervals and cursors (CONFORMANCE CONF-5 and the §7.7
// item; vectors §I.25, internal/vectors): a log's long-poll intervals are
// counted from the epoch plus the log's phase, for each of the three log
// URLs, and no deployment counts them from the epoch alone.

// The hashed path is the long-poll URL's, without the query, built from
// the names: "/ns/{ns}/log", "/r/{ns}/{name}/log" and "/ns/{ns}/view/{view}/log"
// (§I.25's four rows, of which the last is a filtered log's), and the
// clock of each starts interval n at epoch + phase + n × interval.
func TestV086LongPollPaths(t *testing.T) {
	t.Parallel()
	const interval = 20 * time.Second
	const view = "17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm" // I.8's
	for _, c := range []struct {
		path, want string
		phase      time.Duration
	}{
		{resourceLogPath("docs", "a"), "/r/docs/a/log", 15777 * time.Millisecond},
		{resourceLogPath("docs", "b"), "/r/docs/b/log", 1327 * time.Millisecond},
		{nsLogPath("docs"), "/ns/docs/log", 18318 * time.Millisecond},
		{filteredLogPath("matches", view), "/ns/matches/view/" + view + "/log", 12058 * time.Millisecond}, // §I.25
	} {
		if c.path != c.want {
			t.Errorf("path %q, want %q", c.path, c.want)
		}
		clock := newLiveClock(interval, c.path)
		if clock.phase != c.phase {
			t.Errorf("%s: phase %v, want %v", c.path, clock.phase, c.phase)
		}
		const n = int64(89_000_000)
		start := time.Unix(0, int64(c.phase)+n*int64(interval))
		if clock.cursor(start) != n || clock.cursor(start.Add(-time.Nanosecond)) != n-1 || !clock.end(n-1).Equal(start) {
			t.Errorf("%s: interval %d doesn't start at epoch + phase + n × interval", c.path, n)
		}
		if LongPollCursor(c.path, interval, start) != n {
			t.Errorf("%s: LongPollCursor at the start of interval %d", c.path, n)
		}
	}
	// Two logs' cursors at one instant differ by one at most, whatever
	// their phases: what lets a cursor be carried from one log to another
	// (the filtered redirect below).
	a, b := newLiveClock(interval, "/r/docs/a/log"), newLiveClock(interval, "/r/docs/b/log")
	for off := time.Duration(0); off < interval; off += 250 * time.Millisecond {
		now := time.Unix(1_800_000_000, 0).Add(off)
		if d := a.cursor(now) - b.cursor(now); d < -1 || d > 1 {
			t.Fatalf("at %v the cursors are %d apart", now, d)
		}
	}
}

// §7.7 with §7.9 Long-poll: a filtered log's wait ends at the boundary
// of its own path, "/ns/{ns}/view/{view}/log", and its 204 carries that log's
// next cursor. The namespace's unfiltered log, polled by a full reader at
// the same time, ends at its own. Not parallel: it times answers.
func TestV086FilteredLongPollPhase(t *testing.T) {
	const interval = 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval)}})
	w.seed([]string{"derby"}, nil, nil)
	li := w.li()
	gs, _ := w.filtered(li)
	since := w.nsHead("matches", w.admin)
	paths := []string{filteredLogPath("matches", gs), nsLogPath("matches")}
	bearers := []string{li, w.admin}
	clocks := []liveClock{newLiveClock(interval, paths[0]), newLiveClock(interval, paths[1])}
	curs := waitCursors(t, 800*time.Millisecond, clocks...)
	type answer struct {
		r  *resp
		at time.Time
	}
	done := []chan answer{make(chan answer, 1), make(chan answer, 1)}
	for i := range paths {
		go func() {
			r := w.get(paths[i]+"?live=long-poll&since="+since+"&cursor="+strconv.FormatInt(curs[i], 10), bearers[i])
			done[i] <- answer{r, time.Now()}
		}()
	}
	for i := range paths {
		a := <-done[i]
		expect(t, a.r, 204)
		if off := a.at.Sub(clocks[i].end(curs[i])); off < -50*time.Millisecond || off > 600*time.Millisecond {
			t.Errorf("%s answered %v from its boundary (phase %v)", paths[i], off, clocks[i].phase)
		}
		if got := a.r.H.Get("X-Cursor"); got != strconv.FormatInt(curs[i]+1, 10) {
			t.Errorf("%s: X-Cursor %s, want %d", paths[i], got, curs[i]+1)
		}
	}
}

// §7.7 with §7.9 URLs: a partial reader's long-poll of "/ns/{ns}/log"
// is redirected to "/ns/{ns}/view/{view}/log" with its cursor, which is then
// read on the filtered log's clock. The two logs' cursors are one apart at
// most, so the namespace log's cursor arrives one behind the filtered
// log's, current or one ahead: each is sent here. None is 400; the one
// behind is answered at once with the filtered log's cursor, the others
// at the filtered log's boundary, and each 204's X-Cursor is past the one
// sent, so the follower moves on. Not parallel: it times answers.
func TestV086FilteredRedirectCarriesCursor(t *testing.T) {
	const interval = 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval)}})
	w.seed([]string{"derby"}, nil, nil)
	li := w.li()
	gs, _ := w.filtered(li)
	since := w.nsHead("matches", w.admin)
	nsClock, gClock := newLiveClock(interval, nsLogPath("matches")), newLiveClock(interval, filteredLogPath("matches", gs))
	for _, d := range []int64{-1, 0, 1} {
		// Clear of both logs' boundaries, so the cursors the requests
		// meet are these.
		curs := waitCursors(t, 800*time.Millisecond, nsClock, gClock)
		n, g := curs[0], curs[1]
		if n-g < -1 || n-g > 1 {
			t.Fatalf("the namespace log's cursor %d, the filtered log's %d: more than one apart", n, g)
		}
		sent := g + d
		r := w.get("/ns/matches/log?live=long-poll&since="+since+"&cursor="+strconv.FormatInt(sent, 10), li)
		expect(t, r, 302)
		loc := r.H.Get("Location")
		if !strings.HasPrefix(loc, "/ns/matches/view/"+gs+"/log?") || !strings.Contains(loc, "cursor="+strconv.FormatInt(sent, 10)) ||
			!strings.Contains(loc, "live=long-poll") || !strings.Contains(loc, "since="+since) {
			t.Fatalf("Location %q", loc)
		}
		start := time.Now()
		r = w.get(loc, li)
		took := time.Since(start)
		expect(t, r, 204)
		// The current cursor, or the request's plus one if that is more.
		want := g + 1 + max(d, 0)
		if d < 0 {
			want = g
			if took > 500*time.Millisecond {
				t.Errorf("a cursor one behind the filtered log's: answered after %v, want at once", took)
			}
		} else if off := start.Add(took).Sub(gClock.end(g)); off < -50*time.Millisecond || off > 600*time.Millisecond {
			t.Errorf("a cursor %d ahead of the filtered log's: answered %v from its boundary", d, off)
		}
		if got := r.H.Get("X-Cursor"); got != strconv.FormatInt(want, 10) {
			t.Errorf("cursor %d sent, the filtered log's %d: X-Cursor %s, want %d", sent, g, got, want)
		}
	}
}
