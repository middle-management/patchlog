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

type sseEvent struct{ event, id, data string }

// openSSE starts an event stream and returns a channel of events.
func (e *tenv) openSSE(path string, hdr map[string]string) (<-chan sseEvent, *http.Response, context.CancelFunc) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	hr, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+path, nil)
	for k, v := range hdr {
		hr.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(hr)
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

// §7.7 long-poll.
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

	// Nothing new: 204 at the interval boundary, same since, and a cursor.
	r = e.get("/ns/docs/log?since=" + head + "&live=long-poll")
	expect(t, r, 204)
	cur, err := strconv.ParseInt(r.H.Get("X-Cursor"), 10, 64)
	if err != nil || r.H.Get("X-Namespace-Revision") != head {
		t.Fatalf("204 headers %v", r.H)
	}
	if cc := r.H.Get("Cache-Control"); cc != "public, max-age=0, s-maxage=2" {
		t.Fatalf("204 Cache-Control %q", cc)
	}
	// Echoing the cursor: the next 204 cursor is at least cursor+1.
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

	// Errors: unknown since 404, other parameters 400, far-ahead cursor 400.
	expect(t, e.get("/ns/docs/log?since="+r1+"&live=long-poll"), 404)
	expect(t, e.get("/r/docs/a/log?since="+head+"&live=long-poll"), 404)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=long-poll&limit=5"), 400)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=sse"), 400)
	expect(t, e.get("/ns/docs/log?since="+head+"&live=long-poll&cursor="+strconv.FormatInt(cur+100000, 10)), 400)
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
	done := make(chan *resp, 1)
	go func() { done <- e.get("/ns/docs/log?since=" + head + "&live=long-poll") }()
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

// §7.3/§9: event stream errors are no-store too; a pruned replay is 410.
func TestEventsErrors(t *testing.T) {
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
