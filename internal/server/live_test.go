package server

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

type sseEvent struct{ event, id, data string }

// openSSE starts an event stream and returns a channel of events.
func (e *tenv) openSSE(path string, hdr map[string]string) (<-chan sseEvent, *http.Response, context.CancelFunc) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	hr, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+path, nil)
	for k, v := range hdr {
		hr.Header.Set(k, v)
	}
	r, err := httpClient.Do(hr)
	if err != nil {
		cancel()
		e.t.Fatal(err)
	}
	ch := make(chan sseEvent, 64)
	go func() {
		defer close(ch)
		defer r.Body.Close()
		sc := bufio.NewScanner(r.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.event != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.event = line[7:]
			case strings.HasPrefix(line, "id: "):
				ev.id = line[4:]
			case strings.HasPrefix(line, "data: "):
				ev.data = line[6:]
			}
		}
	}()
	e.t.Cleanup(cancel)
	return ch, r, cancel
}

func next(t *testing.T, ch <-chan sseEvent) sseEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return sseEvent{}
}

// §7.3 resource events.
func TestResourceEvents(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	r1 := e.create("docs", "a", map[string]any{"n": 1.0})
	r2 := e.appendRev("docs", "a", r1, ops(op("replace", "/n", 2.0)))
	ch, resp, _ := e.openSSE("/r/docs/a/events?since="+r1, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("SSE response %d %v", resp.StatusCode, resp.Header)
	}
	// Replay first.
	ev := next(t, ch)
	if ev.event != "revision" || ev.id != r2 || !strings.Contains(ev.data, `"patches"`) {
		t.Fatalf("replayed %v", ev)
	}
	// Then live entries, including from other resources' writes not leaking in.
	e.create("docs", "other", map[string]any{})
	r3 := e.appendRev("docs", "a", r2, ops(op("replace", "/n", 3.0)))
	if ev := next(t, ch); ev.event != "revision" || ev.id != r3 {
		t.Fatalf("live %v", ev)
	}
	tomb := e.del("docs", "a", r3)
	if ev := next(t, ch); ev.event != "tombstone" || ev.id != tomb {
		t.Fatalf("tombstone %v", ev)
	}
	// Last-Event-ID resumes.
	ch2, _, _ := e.openSSE("/r/docs/a/events", map[string]string{"Last-Event-ID": r3})
	if ev := next(t, ch2); ev.id != tomb {
		t.Fatalf("Last-Event-ID resume %v", ev)
	}
	// Purge ends the stream with a purge event.
	expect(t, e.purge("docs", "a", tomb, "admin"), 204)
	if ev := next(t, ch); ev.event != "purge" {
		t.Fatalf("purge %v", ev)
	}
	// Unknown since: 404; purged: 410.
	e.create("docs", "b", map[string]any{})
	expect(t, e.get("/r/docs/b/events?since="+r1), 404)
	expect(t, e.get("/r/docs/a/events"), 410)
}

// §7.4 namespace events.
func TestNamespaceEvents(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	ch, _, _ := e.openSSE("/ns/docs/events", nil)
	if ev := next(t, ch); ev.event != "config" {
		t.Fatalf("first event %v", ev)
	}
	a := e.create("docs", "a", map[string]any{})
	if ev := next(t, ch); ev.event != "head" || ev.id != e.nsHead("docs") || !strings.Contains(ev.data, a) {
		t.Fatalf("head event %v", ev)
	}
	r := e.do(req{method: "POST", path: "/ns/docs/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}},
		map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{})}}}}})
	expect(t, r, 201)
	if ev := next(t, ch); ev.event != "batch" || ev.id != r.Str("ns_id") {
		t.Fatalf("batch event %v", ev)
	}
	// Many writes in quick succession are all delivered, in order.
	h := a
	var want []string
	for i := 0; i < 10; i++ {
		h = e.appendRev("docs", "a", h, ops(op("add", "/n", float64(i))))
		want = append(want, e.nsHead("docs"))
	}
	for i, w := range want {
		if ev := next(t, ch); ev.id != w {
			t.Fatalf("event %d: %v, want %s", i, ev, w)
		}
	}
	// since resumes after a checkpoint.
	ch2, _, _ := e.openSSE("/ns/docs/events?since="+want[8], nil)
	if ev := next(t, ch2); ev.id != want[9] {
		t.Fatalf("resume %v", ev)
	}
	expect(t, e.get("/ns/docs/events?since="+a), 404)
}

// §7.7 long-poll. Not parallel: it bounds an answer's wall time.
func TestLongPoll(t *testing.T) {
	e := newEnv(t, withLongPoll(200*time.Millisecond))
	e.mkNS("docs", map[string]any{"read": "public"})
	first := e.nsHead("docs")
	r1 := e.create("docs", "a", map[string]any{"n": 1.0})
	r2 := e.appendRev("docs", "a", r1, ops(op("replace", "/n", 2.0)))
	head := e.nsHead("docs")

	// Entries after since: 200 at once, oldest first.
	start := time.Now()
	r := e.get("/ns/docs/log?since=" + first + "&live=long-poll")
	expect(t, r, 200)
	if len(r.Arr()) != 2 || r.H.Get("X-Namespace-Revision") != head || r.H.Get("X-Cursor") == "" {
		t.Fatalf("long-poll 200 %s %v", r.Body, r.H)
	}
	if cc := r.H.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=0, s-maxage=") || r.H.Get("Cache-Tag") != "ns:docs" {
		t.Fatalf("long-poll 200 cache %v", r.H)
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("long-poll with entries waited")
	}
	// Empty since means from the beginning.
	r = e.get("/ns/docs/log?since=&live=long-poll")
	if len(r.Arr()) != 3 {
		t.Fatalf("from the beginning %s", r.Body)
	}
	// Resource logs.
	r = e.get("/r/docs/a/log?since=" + r1 + "&live=long-poll")
	expect(t, r, 200)
	if len(r.Arr()) != 1 || r.H.Get("X-Revision") != r2 || r.H.Get("Cache-Tag") != "ns:docs,r:docs/a" {
		t.Fatalf("resource long-poll %s %v", r.Body, r.H)
	}

	// Nothing new: without a cursor, 204 at once, same since, and the
	// current cursor.
	start = time.Now()
	r = e.get("/ns/docs/log?since=" + head + "&live=long-poll")
	expect(t, r, 204)
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("long-poll without a cursor waited")
	}
	cur, err := strconv.ParseInt(r.H.Get("X-Cursor"), 10, 64)
	if err != nil || r.H.Get("X-Namespace-Revision") != head {
		t.Fatalf("204 headers %v", r.H)
	}
	if cc := r.H.Get("Cache-Control"); cc != "public, max-age=0, s-maxage=2" {
		t.Fatalf("204 Cache-Control %q", cc)
	}
	// Echoing the cursor: it waits for the boundary, and the next 204
	// cursor is at least cursor+1.
	r = e.get("/ns/docs/log?since=" + head + "&live=long-poll&cursor=" + strconv.FormatInt(cur, 10))
	expect(t, r, 204)
	if c2, _ := strconv.ParseInt(r.H.Get("X-Cursor"), 10, 64); c2 < cur+1 {
		t.Fatalf("cursor %d after %d", c2, cur)
	}
	r = e.get("/r/docs/a/log?since=" + r2 + "&live=long-poll")
	expect(t, r, 204)
	if r.H.Get("X-Revision") != r2 || r.H.Get("X-Cursor") == "" {
		t.Fatalf("resource 204 %v", r.H)
	}

	// Errors: unknown since 404, other parameters 400, far-ahead or
	// far-behind cursor 400.
	expect(t, e.get("/ns/docs/log?since="+r1+"&live=long-poll"), 404)
	expect(t, e.get("/r/docs/a/log?since="+head+"&live=long-poll"), 404)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=long-poll&limit=5"), 400)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=sse"), 400)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=long-poll&cursor="+strconv.FormatInt(cur+100000, 10)), 400)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=long-poll&cursor="+strconv.FormatInt(cur-100000, 10)), 400)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=long-poll&cursor=x"), 400)
	// Without live: 302 to the immutable range.
	r = e.get("/ns/docs/log?since=" + first)
	expect(t, r, 302)
	if r.H.Get("Location") != "/ns/docs/rev/"+head+"/log?since="+first {
		t.Fatalf("redirect %s", r.H.Get("Location"))
	}
	r = e.get("/r/docs/a/log?since=" + r1)
	expect(t, r, 302)
	if r.H.Get("Location") != "/r/docs/a/rev/"+r2+"/log?since="+r1 {
		t.Fatalf("redirect %s", r.H.Get("Location"))
	}
}

// §7.7: a waiting long-poll is answered when an entry arrives.
func TestLongPollWakes(t *testing.T) {
	e := newEnv(t, withLongPoll(20*time.Second), withFileDB(t))
	e.mkNS("docs", map[string]any{"read": "public"})
	head := e.nsHead("docs")
	// A long-poll ends at the log's next boundary (§7.7, liveClock): start
	// well before one, so the write below comes first.
	const interval = 20 * time.Second
	// With the current cursor: one without a cursor is answered at once.
	cur := strconv.FormatInt(waitCursor(t, newLiveClock(interval, "/ns/docs/log"), time.Second), 10)
	done := make(chan *resp, 1)
	go func() { done <- e.get("/ns/docs/log?since=" + head + "&live=long-poll&cursor=" + cur) }()
	time.Sleep(100 * time.Millisecond)
	e.create("docs", "a", map[string]any{})
	select {
	case r := <-done:
		if r.Code != 200 || len(r.Arr()) != 1 || r.H.Get("X-Namespace-Revision") != e.nsHead("docs") {
			t.Fatalf("woken long-poll %d %s", r.Code, r.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll not woken by a write")
	}
}

// §7.7: a resource's long-poll waits on its resource, so writes to the
// namespace's other resources don't make it read its log again (live.go,
// core.Engine.WaitResource); its own write, or a configuration change,
// does. Not parallel: it counts the reads of every long-poll.
func TestResourceLongPollIsolated(t *testing.T) {
	const interval = 20 * time.Second
	lim := core.DefaultLimits()
	fast := core.Rate{Rate: 1e6, Burst: 1e6}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e := newEnv(t, withLongPoll(interval), withFileDB(t), func(o *core.Options) { o.Limits, o.Maximums = lim, lim })
	e.mkNS("docs", map[string]any{"read": "public"})
	const waiters, writes = 50, 100
	// Each log's intervals are counted from its own phase (§7.7), so fifty
	// logs taken as they come end their waits all over the interval. These
	// fifty are the first whose phases fall in its first four seconds:
	// their boundaries come within four seconds of each other, and a
	// request sent after them has the rest of the interval to wait.
	const window = 4 * time.Second
	var names []string
	var clocks []liveClock
	for i := 0; len(names) < waiters; i++ {
		name := fmt.Sprintf("r%d", i)
		if c := newLiveClock(interval, resourceLogPath("docs", name)); c.phase < window {
			names, clocks = append(names, name), append(clocks, c)
		}
	}
	heads := make([]string, waiters)
	for i := range heads {
		heads[i] = e.create("docs", names[i], map[string]any{"n": 0.0})
	}
	other := e.create("docs", "other", map[string]any{"n": 0.0})
	// On Postgres, the tailer's wake-ups for the creates, which would
	// wake the long-polls below once each.
	if err := e.e.SyncTail(context.Background()); err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int64
	testLongPollFetch = func() { reads.Add(1) }
	t.Cleanup(func() { testLongPollFetch = nil })
	// Start well before any of their boundaries (§7.7), which would end
	// them: after the window's last, and five seconds or more before its
	// next first. Each waits with its own log's cursor.
	if in := time.Duration(time.Now().UnixNano() % int64(interval)); in < window {
		time.Sleep(window - in + 10*time.Millisecond)
	} else if rem := interval - in; rem < 5*time.Second {
		time.Sleep(rem + window + 10*time.Millisecond)
	}
	now := time.Now()
	done := make([]chan *resp, waiters)
	for i := range done {
		done[i] = make(chan *resp, 1)
		cur := clocks[i].cursor(now)
		if rem := clocks[i].end(cur).Sub(now); rem < 5*time.Second {
			t.Fatalf("%s: %v to its boundary, want 5 s or more", names[i], rem)
		}
		go func() {
			done[i] <- e.get(fmt.Sprintf("/r/docs/%s/log?since=%s&live=long-poll&cursor=%d", names[i], heads[i], cur))
		}()
	}
	// A long-poll takes its waiter's channel before its first read.
	waitFor := func(n int64, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for reads.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d reads, want %d", what, reads.Load(), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor(waiters, "the first reads")
	base := reads.Load()

	for i := 1; i <= writes; i++ {
		other = e.appendRev("docs", "other", other, ops(op("replace", "/n", float64(i))))
	}
	if err := e.e.SyncTail(context.Background()); err != nil { // the tailer's wake-ups too
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the reads any wake-up would cause
	if n := reads.Load(); n != base {
		t.Fatalf("%d writes to another resource: %d long-poll reads, want %d", writes, n, base)
	}

	// The eighth's write answers its long-poll alone.
	h7 := e.appendRev("docs", names[7], heads[7], ops(op("replace", "/n", 1.0)))
	select {
	case r := <-done[7]:
		if r.Code != 200 || len(r.Arr()) != 1 || r.H.Get("X-Revision") != h7 {
			t.Fatalf("%s's long-poll %d %s", names[7], r.Code, r.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s's long-poll not woken by its write", names[7])
	}
	if err := e.e.SyncTail(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := reads.Load(); n != base+1 {
		t.Fatalf("after %s's write: %d long-poll reads, want %d", names[7], n, base+1)
	}

	// A configuration change wakes every waiter of the namespace: each
	// reads again, finds nothing new and waits on.
	expect(t, e.patchNS("docs", []any{map[string]any{"op": "add", "path": "/x-d", "value": "d"}}, ""), 201)
	waitFor(base+waiters, "after a configuration change")

	// Each of the others is answered by its own write.
	for i := range done {
		if i == 7 {
			continue
		}
		h := e.appendRev("docs", names[i], heads[i], ops(op("replace", "/n", 1.0)))
		select {
		case r := <-done[i]:
			if r.Code != 200 || r.H.Get("X-Revision") != h {
				t.Fatalf("%s's long-poll %d %s", names[i], r.Code, r.Body)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s's long-poll not woken by its write", names[i])
		}
	}
}

// §7.3/§9: event stream errors are no-store too; a pruned replay is 410.
func TestEventsErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	h := e.create("docs", "a", map[string]any{"n": 0.0})
	h1 := e.appendRev("docs", "a", h, ops(op("replace", "/n", 1.0)))
	e.clock.Advance(10 * time.Minute)
	e.appendRev("docs", "a", h1, ops(op("replace", "/n", 2.0)))
	expect(t, e.do(req{method: "POST", path: "/r/docs/a/prune", body: map[string]any{"horizon": e.head("docs", "a")}, author: "admin"}), 200)
	for _, p := range []string{"/r/docs/a/events?since=" + h, "/r/docs/a/events?since=" + hashID(t, "", nil), "/ns/docs/events?since=" + h} {
		r := e.get(p)
		if r.Code != 410 && r.Code != 404 || r.H.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", p, r.Code, r.H)
		}
	}
	r := e.get("/r/docs/a/events?since=" + h)
	expectCode(t, r, 410, "pruned")
}

// Event streams catch up a log page at a time (§7.1 Paging, §7.3): with a
// page of 2, a stream from the beginning still delivers every entry, in
// order and once, and then goes on live.
func TestEventsPaged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withLogPageSize(2))
	e.mkNS("docs", map[string]any{"read": "public"})
	nsWant := []string{e.nsHead("docs")}
	h := e.create("docs", "a", map[string]any{})
	revs := []string{h}
	nsWant = append(nsWant, e.nsHead("docs"))
	for i := 0; i < 6; i++ {
		h = e.appendRev("docs", "a", h, ops(op("add", "/n", float64(i))))
		revs = append(revs, h)
		nsWant = append(nsWant, e.nsHead("docs"))
		if i == 2 {
			e.create("docs", "other", map[string]any{})
			nsWant = append(nsWant, e.nsHead("docs"))
		}
	}
	nsCh, _, _ := e.openSSE("/ns/docs/events", nil)
	resCh, _, _ := e.openSSE("/r/docs/a/events", nil)
	resume, _, _ := e.openSSE("/r/docs/a/events?since="+revs[1], nil)
	for i, w := range nsWant {
		if ev := next(t, nsCh); ev.id != w {
			t.Fatalf("namespace event %d: %v, want %s", i, ev, w)
		}
	}
	for i, w := range revs {
		if ev := next(t, resCh); ev.event != "revision" || ev.id != w {
			t.Fatalf("resource event %d: %v, want %s", i, ev, w)
		}
	}
	for i, w := range revs[2:] {
		if ev := next(t, resume); ev.id != w {
			t.Fatalf("resumed event %d: %v, want %s", i, ev, w)
		}
	}
	// Then live: several entries at once arrive in pages too.
	var more []string
	for i := 0; i < 5; i++ {
		h = e.appendRev("docs", "a", h, ops(op("replace", "/n", float64(10+i))))
		more = append(more, h)
	}
	for i, w := range more {
		if ev := next(t, resCh); ev.id != w {
			t.Fatalf("live event %d: %v, want %s", i, ev, w)
		}
		if ev := next(t, resume); ev.id != w {
			t.Fatalf("live resumed event %d: %v, want %s", i, ev, w)
		}
	}
	for i := range more {
		if ev := next(t, nsCh); ev.event != "head" {
			t.Fatalf("live namespace event %d: %v", i, ev)
		}
	}
	// A purge still ends a resource stream with its event.
	tomb := e.del("docs", "a", h)
	if ev := next(t, resCh); ev.id != tomb {
		t.Fatalf("tombstone %v", ev)
	}
	expect(t, e.purge("docs", "a", tomb, "admin"), 204)
	if ev := next(t, resCh); ev.event != "purge" {
		t.Fatalf("purge %v", ev)
	}
}

// A log's phase (LongPollPhase; §7.7, §I.25): the first 8 bytes of the
// SHA-256 of its path, big-endian, modulo the interval in milliseconds;
// spread evenly over the interval across logs.
func TestLogPhase(t *testing.T) {
	t.Parallel()
	const interval = 20 * time.Second
	for path, want := range map[string]time.Duration{
		"/r/docs/a/log": 15777 * time.Millisecond, // sha-256 c6b6521efdba5aa1…
		"/r/docs/b/log": 1327 * time.Millisecond,  // d88ca141ae2485cf…
		"/ns/docs/log":  18318 * time.Millisecond, // 7a75dc61743845ce…
	} {
		if got := LongPollPhase(path, interval); got != want {
			t.Errorf("phase of %s: %v, want %v", path, got, want)
		}
	}
	// 2,000 logs over twenty one-second buckets: about 100 each.
	var buckets [20]int
	for i := range 2000 {
		p := LongPollPhase(fmt.Sprintf("/r/n/r%d/log", i), interval)
		if p < 0 || p >= interval || p%time.Millisecond != 0 {
			t.Fatalf("phase %v", p)
		}
		buckets[p/time.Second]++
	}
	for i, n := range buckets {
		if n < 50 || n > 150 {
			t.Errorf("second %d of the interval: %d of 2,000 logs, want about 100", i, n)
		}
	}
	// The clock: an interval ends where the next begins, shifted by the
	// phase, and every log has one (no deployment counts them all from
	// the epoch itself, v0.86).
	c := newLiveClock(interval, "/r/docs/a/log")
	const k = int64(89_000_000)
	if end := c.end(k); c.cursor(end.Add(-time.Nanosecond)) != k || c.cursor(end) != k+1 ||
		end.UnixNano() != (k+1)*int64(interval)+int64(15777*time.Millisecond) {
		t.Fatalf("interval %d ends %v", k, c.end(k))
	}
	if start := c.end(k - 1); start.UnixNano() != k*int64(interval)+int64(15777*time.Millisecond) || c.cursor(start) != k {
		t.Fatalf("interval %d starts %v, want epoch + phase + %d × interval", k, start, k)
	}
	// The server's cursor is the log's.
	now := c.end(k).Add(time.Second)
	if cur, err := judgeCursor(now, c, k); cur != k+1 || err != nil {
		t.Fatalf("judged %d %v, want %d", cur, err, k+1)
	}
}

// §7.7 with phases: two resources' long-polls with the current cursor
// each end at their own log's boundary, not at one instant, and the 204's
// cursor is the log's next. Not parallel: it times answers.
func TestLongPollPhase(t *testing.T) {
	const interval = 2 * time.Second
	e := newEnv(t, withLongPoll(interval))
	e.mkNS("docs", map[string]any{"read": "public"})
	// Two resources whose boundaries are at least half a second apart.
	var names []string
	var clocks []liveClock
	for i := 0; len(names) < 2; i++ {
		name := fmt.Sprintf("p%d", i)
		c := newLiveClock(interval, resourceLogPath("docs", name))
		if len(clocks) == 1 {
			d := (c.phase - clocks[0].phase + interval) % interval
			if d < interval/4 || d > interval*3/4 {
				continue
			}
		}
		names, clocks = append(names, name), append(clocks, c)
	}
	heads := []string{e.create("docs", names[0], map[string]any{}), e.create("docs", names[1], map[string]any{})}
	// Sent while neither boundary is within 300 ms.
	for {
		now := time.Now()
		if time.Until(clocks[0].end(clocks[0].cursor(now))) > 300*time.Millisecond &&
			time.Until(clocks[1].end(clocks[1].cursor(now))) > 300*time.Millisecond {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	type answer struct {
		r  *resp
		at time.Time
	}
	done := make([]chan answer, 2)
	curs := make([]int64, 2)
	for i := range 2 {
		done[i] = make(chan answer, 1)
		curs[i] = clocks[i].cursor(time.Now())
		go func() {
			r := e.get(fmt.Sprintf("/r/docs/%s/log?since=%s&live=long-poll&cursor=%d", names[i], heads[i], curs[i]))
			done[i] <- answer{r, time.Now()}
		}()
	}
	for i := range 2 {
		a := <-done[i]
		expect(t, a.r, 204)
		if off := a.at.Sub(clocks[i].end(curs[i])); off < -50*time.Millisecond || off > 300*time.Millisecond {
			t.Errorf("%s answered %v from its boundary", names[i], off)
		}
		if got := a.r.H.Get("X-Cursor"); got != strconv.FormatInt(curs[i]+1, 10) {
			t.Errorf("%s: X-Cursor %s, want %d", names[i], got, curs[i]+1)
		}
	}
}
