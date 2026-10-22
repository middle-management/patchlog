package server

import (
	"strconv"
	"testing"
	"time"
)

// p28AfterBoundary waits until the current long-poll interval has at least
// three quarters of it left, so a request that waits for the boundary
// takes that long (§7.7).
func p28AfterBoundary(interval time.Duration) {
	if rem := interval - time.Duration(time.Now().UnixNano()%int64(interval)); rem < interval*3/4 {
		time.Sleep(rem + 10*time.Millisecond)
	}
}

// p28Cursor is this instant's interval number (§7.7).
func p28Cursor(interval time.Duration) int64 { return time.Now().UnixNano() / int64(interval) }

// p28LongPollEnv is a namespace with one resource, for the long-poll
// cursor tests, with helpers that check an answer came at once and what
// its cursor is.
func p28LongPollEnv(t *testing.T, interval time.Duration) (e *tenv, r1, head string, atOnce func(what, path string) *resp, cursorIs func(what string, r *resp, want int64)) {
	e = newEnv(t, withLongPoll(interval))
	e.mkNS("docs", map[string]any{"read": "public"})
	r1 = e.create("docs", "a", map[string]any{"n": 1.0})
	head = e.nsHead("docs")
	atOnce = func(what, path string) *resp {
		t.Helper()
		p28AfterBoundary(interval)
		start := time.Now()
		r := e.get(path)
		if d := time.Since(start); d > interval/4 {
			t.Fatalf("%s: answered after %v, want at once", what, d)
		}
		return r
	}
	cursorIs = func(what string, r *resp, want int64) {
		t.Helper()
		got, err := strconv.ParseInt(r.H.Get("X-Cursor"), 10, 64)
		if err != nil || got != want && got != want+1 {
			t.Fatalf("%s: X-Cursor %q, want %d", what, r.H.Get("X-Cursor"), want)
		}
	}
	return
}

// §7.7 Intervals and cursors (RH-38): a long-poll without a cursor is
// answered at once, 204 with the current cursor when nothing is new. Not
// parallel: it bounds wall time.
func TestV073P28LongPollNoCursor(t *testing.T) {
	const interval = 2 * time.Second
	_, r1, head, atOnce, cursorIs := p28LongPollEnv(t, interval)

	r := atOnce("no cursor", "/ns/docs/log?since="+head+"&live=long-poll")
	expect(t, r, 204)
	cursorIs("no cursor", r, p28Cursor(interval))
	if r.H.Get("X-Namespace-Revision") != head {
		t.Fatalf("no cursor: %v", r.H)
	}
	r = atOnce("resource, no cursor", "/r/docs/a/log?since="+r1+"&live=long-poll")
	expect(t, r, 204)
	cursorIs("resource, no cursor", r, p28Cursor(interval))
	if r.H.Get("X-Revision") != r1 {
		t.Fatalf("resource, no cursor: %v", r.H)
	}
	// With entries: 200 at once, as before.
	r = atOnce("entries", "/ns/docs/log?since=&live=long-poll")
	expect(t, r, 200)
}

// §7.7 Intervals and cursors (RH-39): a cursor behind the server's by an
// hour's worth of intervals or less is answered at once, with the current
// cursor (the greater of it and the request's plus one); one behind by
// more is 400 bad_input, as one ahead by more is. A current cursor still
// waits for the boundary. Not parallel: it bounds wall time.
func TestV073P28LongPollCursorBehind(t *testing.T) {
	const interval = 2 * time.Second
	e, r1, head, atOnce, cursorIs := p28LongPollEnv(t, interval)
	hour := int64(time.Hour / interval)

	for _, behind := range []int64{1, 5, hour} {
		cur := p28Cursor(interval)
		r := atOnce("behind "+strconv.FormatInt(behind, 10), "/ns/docs/log?since="+head+"&live=long-poll&cursor="+strconv.FormatInt(cur-behind, 10))
		expect(t, r, 204)
		cursorIs("behind", r, cur)
	}
	r := atOnce("resource, behind", "/r/docs/a/log?since="+r1+"&live=long-poll&cursor="+strconv.FormatInt(p28Cursor(interval)-1, 10))
	expect(t, r, 204)

	// Behind by more than an hour's worth: 400, the client then omits it.
	for _, path := range []string{"/ns/docs/log?since=" + head, "/r/docs/a/log?since=" + r1} {
		expectCode(t, e.get(path+"&live=long-poll&cursor="+strconv.FormatInt(p28Cursor(interval)-hour-2, 10)), 400, "bad_input")
		expectCode(t, e.get(path+"&live=long-poll&cursor="+strconv.FormatInt(p28Cursor(interval)+hour+2, 10)), 400, "bad_input")
	}

	// A current cursor waits for the interval boundary.
	p28AfterBoundary(interval)
	cur := p28Cursor(interval)
	start := time.Now()
	r = e.get("/ns/docs/log?since=" + head + "&live=long-poll&cursor=" + strconv.FormatInt(cur, 10))
	expect(t, r, 204)
	if d := time.Since(start); d < interval/2 {
		t.Fatalf("current cursor answered after %v, want the boundary", d)
	}
	cursorIs("current", r, cur+1)
}

// §7.7 Answer (RH-41): a live read of a resource with no entries waits as
// for an empty since, and its create wakes it; a 204 for an empty since
// carries no X-Revision, so the next since stays empty. Without live, the
// 404 (short) stays, and a grant that may not read the resource gets 404.
func TestV073P28LongPollNoEntries(t *testing.T) {
	const interval = 20 * time.Second
	e := newEnv(t, withLongPoll(interval), withFileDB(t))
	e.mkNS("docs", map[string]any{"read": "public"})

	// No cursor: 204 at once, without X-Revision.
	r := e.get("/r/docs/new/log?live=long-poll")
	expect(t, r, 204)
	if _, ok := r.H["X-Revision"]; ok || r.H.Get("X-Cursor") == "" {
		t.Fatalf("204 for an empty since: %v", r.H)
	}
	r = e.get("/r/docs/new/log?since=&live=long-poll")
	expect(t, r, 204)
	if _, ok := r.H["X-Revision"]; ok {
		t.Fatalf("204 for since=: %v", r.H)
	}

	// With the current cursor it waits, and the create wakes it.
	if rem := interval - time.Duration(time.Now().UnixNano()%int64(interval)); rem < 2*time.Second {
		time.Sleep(rem + 10*time.Millisecond)
	}
	done := make(chan *resp, 1)
	cur := strconv.FormatInt(p28Cursor(interval), 10)
	go func() { done <- e.get("/r/docs/new/log?live=long-poll&cursor=" + cur) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("answered before the create: %d %v", r.Code, r.H)
	default:
	}
	g := e.create("docs", "new", map[string]any{"n": 1.0})
	select {
	case r := <-done:
		if r.Code != 200 || len(r.Arr()) != 1 || r.H.Get("X-Revision") != g {
			t.Fatalf("woken long-poll %d %s %v", r.Code, r.Body, r.H)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll not woken by the create")
	}

	// Without live: 404, short; a non-empty since that is unknown: 404.
	r = e.get("/r/docs/none/log")
	expect(t, r, 404)
	if cc := r.H.Get("Cache-Control"); cc != ccShort {
		t.Fatalf("404 Cache-Control %q", cc)
	}
	expect(t, e.get("/r/docs/none/log?since="+g+"&live=long-poll"), 404)

	// A grant that may not read the resource: 404, not a wait.
	a := newAuthEnv(t, withLongPoll(interval))
	k := newKey("k")
	a.mkNS("p", map[string]any{"keys": []any{k.entry("*")}})
	other := a.grant(k, "bob", []string{"p"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "other"}}})
	expect(t, a.get("/r/p/new/log?live=long-poll", other), 404)
	r = a.get("/r/p/other/log?live=long-poll", other)
	expect(t, r, 204)
	if _, ok := r.H["X-Revision"]; ok {
		t.Fatalf("private 204 for an empty since: %v", r.H)
	}
}
