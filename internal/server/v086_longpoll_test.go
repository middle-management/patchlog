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
// the names: "/ns/{ns}/log", "/r/{ns}/{name}/log" and "/ns/{ns}/g/{gs}/log"
// (§I.25's four rows, of which the last is a filtered log's), and the
// clock of each starts interval n at epoch + phase + n × interval.
func TestV086LongPollPaths(t *testing.T) {
	t.Parallel()
	const interval = 20 * time.Second
	const gs = "17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm" // I.8's
	for _, c := range []struct {
		path, want string
		phase      time.Duration
	}{
		{resourceLogPath("docs", "a"), "/r/docs/a/log", 15777 * time.Millisecond},
		{resourceLogPath("docs", "b"), "/r/docs/b/log", 1327 * time.Millisecond},
		{nsLogPath("docs"), "/ns/docs/log", 18318 * time.Millisecond},
		{filteredLogPath("matches", gs), "/ns/matches/g/" + gs + "/log", 15523 * time.Millisecond},
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

// §7.7 with §B.11.9 Long-poll: a filtered log's wait ends at the boundary
// of its own path, "/ns/{ns}/g/{gs}/log", and its 204 carries that log's
// next cursor. The namespace's unfiltered log, polled by a full reader at
// the same time, ends at its own.
func TestV086FilteredLongPollPhase(t *testing.T) {
	t.Parallel()
	const interval = 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval)}})
	w.seed([]string{"derby"}, nil, nil)
	li := w.li()
	gs, _ := w.filtered(li)
	since := w.nsHead("matches", w.admin)
	paths := []string{filteredLogPath("matches", gs), nsLogPath("matches")}
	bearers := []string{li, w.admin}
	clocks := []liveClock{newLiveClock(interval, paths[0]), newLiveClock(interval, paths[1])}
	curs := waitCursors(t, 300*time.Millisecond, clocks...)
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
		if off := a.at.Sub(clocks[i].end(curs[i])); off < -50*time.Millisecond || off > 400*time.Millisecond {
			t.Errorf("%s answered %v from its boundary (phase %v)", paths[i], off, clocks[i].phase)
		}
		if got := a.r.H.Get("X-Cursor"); got != strconv.FormatInt(curs[i]+1, 10) {
			t.Errorf("%s: X-Cursor %s, want %d", paths[i], got, curs[i]+1)
		}
	}
}

// §7.7 with §B.11.9 URLs: a partial reader's long-poll of "/ns/{ns}/log"
// is redirected to "/ns/{ns}/g/{gs}/log" with its cursor, which was the
// namespace log's and is now read on the filtered log's clock: one
// behind, current or one ahead there. It is never 400; behind is answered
// at once and otherwise at the filtered log's boundary, and each way the
// 204's X-Cursor is past the one sent, so the follower moves on. Sent at
// several instants of the interval, so the carried cursor lands on both
// sides of the filtered log's.
func TestV086FilteredRedirectCarriesCursor(t *testing.T) {
	t.Parallel()
	const interval = 2 * time.Second
	w := newV75s(t, v75sOpts{env: []envOpt{withLongPoll(interval)}})
	w.seed([]string{"derby"}, nil, nil)
	li := w.li()
	gs, _ := w.filtered(li)
	since := w.nsHead("matches", w.admin)
	nsClock, gClock := newLiveClock(interval, nsLogPath("matches")), newLiveClock(interval, filteredLogPath("matches", gs))
	seen := map[int64]bool{}
	for _, cursorOff := range []int64{0, 1, 0, 1} {
		// Clear of both logs' boundaries, so what the request meets is
		// what is computed here; a cursor one ahead of the namespace
		// log's is two ahead of the filtered log's at most.
		now := time.Now()
		_ = waitCursors(t, 300*time.Millisecond, nsClock, gClock)
		if seen[cursorOff] {
			// The second round: half an interval on, where the two logs'
			// cursors compare the other way if their phases differ.
			time.Sleep(time.Until(now.Add(interval / 2)))
			_ = waitCursors(t, 300*time.Millisecond, nsClock, gClock)
		}
		seen[cursorOff] = true
		now = time.Now()
		sent := nsClock.cursor(now) + cursorOff
		g := gClock.cursor(now)
		q := "?live=long-poll&since=" + since + "&cursor=" + strconv.FormatInt(sent, 10)
		r := w.get("/ns/matches/log"+q, li)
		expect(t, r, 302)
		loc := r.H.Get("Location")
		if !strings.HasPrefix(loc, "/ns/matches/g/"+gs+"/log?") || !strings.Contains(loc, "cursor="+strconv.FormatInt(sent, 10)) ||
			!strings.Contains(loc, "live=long-poll") || !strings.Contains(loc, "since="+since) {
			t.Fatalf("Location %q", loc)
		}
		start := time.Now()
		r = w.get(loc, li)
		took := time.Since(start)
		expect(t, r, 204)
		got, err := strconv.ParseInt(r.H.Get("X-Cursor"), 10, 64)
		if err != nil || got <= sent || got > sent+2 {
			t.Fatalf("cursor %d sent (the filtered log's was %d): X-Cursor %q", sent, g, r.H.Get("X-Cursor"))
		}
		switch {
		case sent < g:
			// Behind the filtered log's: at once, with its cursor.
			if took > 250*time.Millisecond || got != g {
				t.Errorf("cursor %d behind the filtered log's %d: answered after %v with %d", sent, g, took, got)
			}
		default:
			// Current or ahead: at the filtered log's boundary.
			if off := start.Add(took).Sub(gClock.end(g)); off < -50*time.Millisecond || off > 400*time.Millisecond {
				t.Errorf("cursor %d against the filtered log's %d: answered %v from its boundary", sent, g, off)
			}
		}
	}
}
