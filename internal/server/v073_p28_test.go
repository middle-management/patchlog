package server

import (
	"bufio"
	"context"
	"net/http"
	"strconv"
	"strings"
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

// p28Event is one server-sent event with its field lines as sent.
type p28Event struct {
	event, data string
	id          *string // nil: no id: line
}

// p28SSE opens an event stream and returns its status and a channel of
// its events, closed when the stream ends.
func (e *tenv) p28SSE(path string, hdr map[string]string) (int, <-chan p28Event) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(cancel)
	hr, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+path, nil)
	for k, v := range hdr {
		hr.Header.Set(k, v)
	}
	r, err := httpClient.Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	ch := make(chan p28Event, 64)
	go func() {
		defer close(ch)
		defer r.Body.Close()
		sc := bufio.NewScanner(r.Body)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		var ev p28Event
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.event != "" {
					ch <- ev
				}
				ev = p28Event{}
			case strings.HasPrefix(line, "event: "):
				ev.event = line[7:]
			case strings.HasPrefix(line, "id:"):
				id := strings.TrimPrefix(line[3:], " ")
				ev.id = &id
			case strings.HasPrefix(line, "data: "):
				ev.data = line[6:]
			}
		}
	}()
	return r.StatusCode, ch
}

func p28Next(t *testing.T, ch <-chan p28Event) p28Event {
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
	return p28Event{}
}

// p28Ends expects the stream to end within d, with no further event.
func p28Ends(t *testing.T, what string, ch <-chan p28Event, d time.Duration) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("%s: event %s %s, want the stream to end", what, ev.event, ev.data)
		}
	case <-time.After(d):
		t.Fatalf("%s: stream still open after %v", what, d)
	}
}

func p28ID(ev p28Event) string {
	if ev.id == nil {
		return ""
	}
	return *ev.id
}

func bearerHdr(g string) map[string]string { return map[string]string{"Authorization": "Bearer " + g} }

// §7.3 (RH-32): a resource stream without since, or with an empty one, on
// a resource with no entries starts and waits for the first, once the read
// check passes; a non-empty since that is unknown stays 404, a purged
// resource 410, and a grant that may not read the resource gets 404.
func TestV073P28ResourceStreamNoEntries(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	st, ch := e.p28SSE("/r/docs/new/events", nil)
	st2, ch2 := e.p28SSE("/r/docs/new2/events?since=", nil)
	if st != 200 || st2 != 200 {
		t.Fatalf("streams of resources with no entries: %d %d", st, st2)
	}
	g := e.create("docs", "new", map[string]any{"n": 1.0})
	if ev := p28Next(t, ch); ev.event != "revision" || p28ID(ev) != g {
		t.Fatalf("first entry %+v", ev)
	}
	g2 := e.create("docs", "new2", map[string]any{"n": 2.0})
	if ev := p28Next(t, ch2); ev.event != "revision" || p28ID(ev) != g2 {
		t.Fatalf("first entry (since=) %+v", ev)
	}
	// A non-empty since that is unknown: 404; purged: 410.
	expectCode(t, e.get("/r/docs/none/events?since="+g), 404, "not_found")
	tomb := e.del("docs", "new2", g2)
	expect(t, e.purge("docs", "new2", tomb, "admin"), 204)
	expect(t, e.get("/r/docs/new2/events"), 410)

	a := newAuthEnv(t)
	k := newKey("k")
	a.mkNS("p", map[string]any{"keys": []any{k.entry("*")}})
	other := a.grant(k, "bob", []string{"p"}, []string{"read"}, map[string]any{
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "other"}}})
	expect(t, a.get("/r/p/new/events", other), 404)
	if st, _ := a.p28SSE("/r/p/other/events", bearerHdr(other)); st != 200 {
		t.Fatalf("readable resource with no entries: %d", st)
	}
}

// §7.3, §8.5 (RH-35): a namespace stream ends after emitting its purge-ns
// event, and one whose since names that entry sends the headers and ends.
func TestV073P28NamespaceStreamEndsAtPurge(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	e.create("docs", "a", map[string]any{})
	before := e.nsHead("docs")
	_, ch := e.p28SSE("/ns/docs/events?since="+before, nil)
	purgeNS := e.nsPurge("docs")
	if ev := p28Next(t, ch); ev.event != "config" {
		t.Fatalf("freeze %+v", ev)
	}
	if ev := p28Next(t, ch); ev.event != "purge-ns" || p28ID(ev) != purgeNS {
		t.Fatalf("purge-ns %+v", ev)
	}
	p28Ends(t, "after purge-ns", ch, 5*time.Second)

	// Replayed: the purge-ns event, then the end.
	_, ch = e.p28SSE("/ns/docs/events?since="+before, nil)
	p28Next(t, ch)
	if ev := p28Next(t, ch); ev.event != "purge-ns" {
		t.Fatalf("replayed purge-ns %+v", ev)
	}
	p28Ends(t, "after the replayed purge-ns", ch, 5*time.Second)

	// since names the purge-ns entry: the headers, then the end.
	for _, hdr := range []map[string]string{nil, {"Last-Event-ID": purgeNS}} {
		path := "/ns/docs/events?since=" + purgeNS
		if hdr != nil {
			path = "/ns/docs/events"
		}
		st, ch := e.p28SSE(path, hdr)
		if st != 200 {
			t.Fatalf("since the purge-ns entry: %d", st)
		}
		p28Ends(t, "since the purge-ns entry", ch, 5*time.Second)
	}
}

// §7.3, §C.2, §C.5.3 (RH-36): a stream ends, at the latest, when the
// grant or the edge cookie it was admitted under expires, even when idle.
func TestV073P28StreamEndsAtCredentialExpiry(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	// Expires in 2 s (the test clock stands still; the stream times its
	// end by it).
	short := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"}, map[string]any{"exp": t0.Add(2 * time.Second).Format(time.RFC3339)})
	r := e.do(req{method: "POST", path: "/edge-grants", bearer: short})
	expect(t, r, 200)
	cs := edgeCookies(t, r)

	streams := map[string]<-chan p28Event{}
	for what, open := range map[string]func() (int, <-chan p28Event){
		"namespace, grant":   func() (int, <-chan p28Event) { return e.p28SSE("/ns/sec/events", bearerHdr(short)) },
		"resource, grant":    func() (int, <-chan p28Event) { return e.p28SSE("/r/sec/a/events?since="+a, bearerHdr(short)) },
		"namespace, cookie":  func() (int, <-chan p28Event) { return e.p28SSE("/ns/sec/events", cookieHdr(cs["/ns/sec"])) },
		"resource, cookie":   func() (int, <-chan p28Event) { return e.p28SSE("/r/sec/a/events?since="+a, cookieHdr(cs["/r/sec"])) },
		"resource, no since": func() (int, <-chan p28Event) { return e.p28SSE("/r/sec/new/events", bearerHdr(short)) },
		"namespace, from head": func() (int, <-chan p28Event) {
			return e.p28SSE("/ns/sec/events?since="+e.nsHead("sec", f.adminG), bearerHdr(short))
		},
	} {
		st, ch := open()
		if st != 200 {
			t.Fatalf("%s: %d", what, st)
		}
		streams[what] = ch
	}
	for _, what := range []string{"namespace, grant", "namespace, cookie"} {
		p28Next(t, streams[what]) // the genesis entry
		p28Next(t, streams[what]) // a's create
	}
	start := time.Now()
	for what, ch := range streams {
		p28Ends(t, what, ch, 6*time.Second)
	}
	if d := time.Since(start); d < time.Second {
		t.Fatalf("streams ended after %v, before the grant's exp", d)
	}
}

// §7.3 (RH-36): an idle stream judges its read check again before each
// keep-alive, and ends when it fails: here a grant past its exp by the
// server's clock, without a write to wake the stream. A revocation, a
// write, ends it without sending the config entry. Not parallel: it sets
// the keep-alive interval.
func TestV073P28StreamRejudgesOnKeepAlive(t *testing.T) {
	old := sseKeepAlive
	sseKeepAlive = 100 * time.Millisecond
	t.Cleanup(func() { sseKeepAlive = old })
	f := newAuthFixture(t, nil)
	e := f.tenv
	a := e.create("sec", "a", map[string]any{"v": 1.0}, f.adminG)
	reader := e.grant(f.issuer, "user:bob", []string{"sec"}, []string{"read"})
	victim := e.grant(f.issuer, "user:eve", []string{"sec"}, []string{"read"})
	_, ns := e.p28SSE("/ns/sec/events?since="+e.nsHead("sec", f.adminG), bearerHdr(reader))
	_, res := e.p28SSE("/r/sec/a/events?since="+a, bearerHdr(reader))
	_, vns := e.p28SSE("/ns/sec/events?since="+e.nsHead("sec", f.adminG), bearerHdr(victim))
	_, vres := e.p28SSE("/r/sec/a/events?since="+a, bearerHdr(victim))
	time.Sleep(300 * time.Millisecond) // a few keep-alives, each judged

	// Revoked: the config write wakes the streams, whose next read fails.
	expect(t, e.patchNS("sec", ops(op("add", "/revoked", []any{revocationID(t, victim, 0)})), f.adminG), 201)
	p28Ends(t, "namespace stream of a revoked grant", vns, 5*time.Second)
	p28Ends(t, "resource stream of a revoked grant", vres, 5*time.Second)
	if ev := p28Next(t, ns); ev.event != "config" {
		t.Fatalf("config %+v", ev)
	}

	// Past exp by the server's clock: the next keep-alive's check fails.
	e.clock.Advance(2 * time.Hour)
	p28Ends(t, "idle namespace stream", ns, 5*time.Second)
	p28Ends(t, "idle resource stream", res, 5*time.Second)
}
