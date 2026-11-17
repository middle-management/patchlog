package streams_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/streams"
)

// A stream read back with the read grant equals the upstream body, and
// the document has J.1's shape and nothing of the request (J.1 Nothing
// secret).
func TestStreamComplete(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	a := e.mustPost(postOpt{
		url:  e.up.srv.URL + "/v1/messages?marker=q-9f3a",
		body: `{"prompt":"hi"}`,
		headers: map[string]string{"Upstream-Authorization": "Bearer s3cr3t-upstream-key", "Upstream-Header-X-Api-Version": "2026-01-01",
			"Content-Type": "application/json", "Upstream-Method": "PUT"},
	})
	if want := e.s.URL + "/r/streams/" + a.ID; a.URL != want || a.Log != want+"/log" || a.Grant == "" {
		t.Fatalf("answer %+v", a)
	}
	if exp, err := time.Parse(time.RFC3339, a.Exp); err != nil || time.Until(exp) < 25*time.Minute || time.Until(exp) > 31*time.Minute {
		t.Fatalf("exp %q %v", a.Exp, err)
	}
	if !client.ValidResourceName(a.ID) {
		t.Fatalf("id %q is not a name of §3.6", a.ID)
	}
	got, closed, batches := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != sseBody() {
		t.Fatalf("read %q, want %q", got, sseBody())
	}
	if closed.Reason != streams.ReasonComplete || closed.Error != "" || closed.Next != "" {
		t.Fatalf("closed %+v", closed)
	}
	last := batches[len(batches)-1]
	if last.Upstream != (streams.Upstream{Method: "PUT", Status: 200, ContentType: "text/event-stream"}) {
		t.Fatalf("upstream %+v", last.Upstream)
	}
	// What upstream got.
	e.up.mu.Lock()
	h, body, method := e.up.lastHeader, e.up.lastBody, e.up.lastMethod
	e.up.mu.Unlock()
	if h.Get("Authorization") != "Bearer s3cr3t-upstream-key" || h.Get("X-Api-Version") != "2026-01-01" || h.Get("Content-Type") != "application/json" ||
		body != `{"prompt":"hi"}` || method != "PUT" {
		t.Fatalf("upstream got %s %v %q", method, h, body)
	}
	if h.Get("Upstream-Url") != "" || h.Get("Request-Key") != "" || strings.Contains(fmt.Sprint(h), "Biscuit") {
		t.Fatalf("upstream got the proxy's own headers: %v", h)
	}
	// The document, exactly J.1's.
	sd, d := e.doc(a.ID)
	var raw map[string]any
	json.Unmarshal(d.Raw, &raw)
	if len(raw) != 3 || raw["upstream"] == nil || raw["chunks"] == nil || raw["closed"] == nil {
		t.Fatalf("document members: %s", d.Raw)
	}
	if up := raw["upstream"].(map[string]any); len(up) != 3 || up["method"] != "PUT" || up["status"] != float64(200) || up["contentType"] != "text/event-stream" {
		t.Fatalf("upstream member: %v", up)
	}
	if strings.Join(sd.Chunks, "") != sseBody() {
		t.Fatalf("chunks %q", sd.Chunks)
	}
	for _, c := range sd.Chunks {
		if !strings.HasSuffix(c, "\n") {
			t.Fatalf("chunk %q doesn't end at a line end", c)
		}
	}
	// Nothing secret, in the document or any patch set, and each flush
	// one patch set adding to /chunks/-.
	es, err := e.pc.Log(e.ctx, nsStreams, a.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	all := string(d.Raw)
	for i, en := range es {
		b, _ := json.Marshal(en.Raw)
		all += string(b)
		for _, op := range en.Patches.([]any) {
			m := op.(map[string]any)
			path := m["path"].(string)
			if i == 0 && path == "" {
				continue
			}
			switch path {
			case "/chunks/-", "/upstream/status", "/upstream/contentType", "/closed":
			default:
				t.Fatalf("entry %d writes %s", i, path)
			}
			if m["op"] != "add" {
				t.Fatalf("entry %d: op %v", i, m["op"])
			}
		}
	}
	if gen := es[0].Patches.([]any)[0].(map[string]any)["value"].(map[string]any); len(gen["chunks"].([]any)) != 0 || gen["upstream"].(map[string]any)["status"] != nil {
		t.Fatalf("genesis %v: want the method and no chunks, before upstream is called", gen)
	}
	host := strings.TrimPrefix(e.up.srv.URL, "http://")
	_, port, _ := net.SplitHostPort(host)
	for _, secret := range []string{"s3cr3t", "q-9f3a", "/v1/messages", host, port, "X-Api-Version", "2026-01-01", "prompt"} {
		if strings.Contains(all, secret) {
			t.Fatalf("the stored stream holds %q", secret)
		}
	}
	// Health.
	resp, err := http.Get(e.srv.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()
	waitFor(t, "the stream to be forgotten", func() bool { return e.p.Open() == 0 })
}

var errStop = errors.New("stop")

// A reader that stops mid-stream resumes from the last revision it saw,
// without duplicates or gaps (J.3).
func TestResume(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	release := make(chan struct{})
	e.up.gated(sseParts[:2], release, sseParts[2:])
	a := e.mustPost(postOpt{})
	rc := e.reader(a)
	var first strings.Builder
	var pos streams.Position
	_, err := streams.Follow(e.ctx, rc, nsStreams, a.ID, streams.Position{}, func(b streams.Batch) error {
		for _, c := range b.Chunks {
			first.WriteString(c)
		}
		pos = b.Position
		if first.String() == sseParts[0]+sseParts[1] {
			return errStop
		}
		return nil
	})
	if err != errStop {
		t.Fatalf("first read: %v", err)
	}
	if pos.Resource != a.ID || pos.Rev == "" {
		t.Fatalf("position %+v", pos)
	}
	close(release)
	rest, closed, batches := e.readAll(rc, a.ID, pos)
	if first.String()+rest != sseBody() || closed.Reason != streams.ReasonComplete {
		t.Fatalf("resumed: %q then %q (%+v)", first.String(), rest, closed)
	}
	for _, b := range batches {
		if b.Rev == pos.Rev {
			t.Fatalf("the resumed read repeats revision %s", pos.Rev)
		}
	}
	// Resuming from the closing revision itself ends at once, with
	// nothing more; from the one before, with the tail.
	end := batches[len(batches)-1]
	if end.Closed == nil {
		t.Fatalf("last batch %+v", end)
	}
	if more, closed, bs := e.readAll(rc, a.ID, end.Position); more != "" || len(bs) != 0 || closed.Reason != streams.ReasonComplete {
		t.Fatalf("resumed from the end: %q %+v", more, closed)
	}
	if len(batches) > 1 {
		prev := batches[len(batches)-2]
		if tail, closed, _ := e.readAll(rc, a.ID, prev.Position); tail != strings.Join(end.Chunks, "") || closed.Reason != streams.ReasonComplete {
			t.Fatalf("resumed from the revision before the end: %q %+v", tail, closed)
		}
	}
	again, closed2, _ := e.readAll(rc, a.ID, streams.Position{})
	if again != sseBody() || closed2.Reason != streams.ReasonComplete {
		t.Fatalf("read of the closed stream: %q %+v", again, closed2)
	}
}

// A repeated request with the same Request-Key finds its stream, and
// upstream isn't called again (J.1 Names, J.2 step 1).
func TestRequestKey(t *testing.T) {
	t.Parallel()
	for _, nonce := range []bool{false, true} {
		t.Run(fmt.Sprintf("nonce=%v", nonce), func(t *testing.T) {
			t.Parallel()
			eo := envOpt{}
			if nonce {
				eo.nsDoc = map[string]any{"nonce": "required"}
			}
			e := newEnv(t, eo)
			a := e.mustPost(postOpt{key: "turn-17"})
			status, b, body := e.post(postOpt{key: "turn-17"})
			if status != 200 || b.ID != a.ID || b.URL != a.URL || b.Grant == "" || b.Exp != a.Exp {
				t.Fatalf("repeat: %d %s (first %+v)", status, body, a)
			}
			got, closed, _ := e.readAll(e.reader(b), b.ID, streams.Position{})
			if got != sseBody() || closed.Reason != streams.ReasonComplete {
				t.Fatalf("read %q %+v", got, closed)
			}
			// After it closed too.
			if status, c, _ := e.post(postOpt{key: "turn-17"}); status != 200 || c.ID != a.ID {
				t.Fatalf("repeat after close: %d %+v", status, c)
			}
			if n := e.up.hits.Load(); n != 1 {
				t.Fatalf("upstream was called %d times", n)
			}
			// Another caller's same key is another stream, as is another key.
			o := e.mustPost(postOpt{key: "turn-17", bearer: e.callerGrant("user:bo")})
			k := e.mustPost(postOpt{key: "turn-18"})
			if o.ID == a.ID || k.ID == a.ID || o.ID == k.ID {
				t.Fatalf("ids %s %s %s", a.ID, o.ID, k.ID)
			}
			e.waitClosed(o.ID)
			e.waitClosed(k.ID)
		})
	}
}

// An upstream that answers an error status is a stream like any other,
// with that status; "error" is for a call that fails, whose closed.error
// doesn't name the upstream (J.2 step 2, J.1 Nothing secret).
func TestUpstreamErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{options: func(o *streams.Options) {
		// A second allowed upstream nobody listens at.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		o.Upstreams = append(o.Upstreams, "http://"+ln.Addr().String())
		ln.Close()
	}})
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(529)
		io.WriteString(w, `{"error":"overloaded"}`)
	})
	a := e.mustPost(postOpt{})
	got, closed, batches := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != `{"error":"overloaded"}` || closed.Reason != streams.ReasonComplete || batches[len(batches)-1].Upstream.Status != 529 {
		t.Fatalf("error status: %q %+v %+v", got, closed, batches[len(batches)-1].Upstream)
	}

	dead := e.opt.Upstreams[1]
	b := e.mustPost(postOpt{url: dead + "/v1/secret-path"})
	sd := e.waitClosed(b.ID)
	if sd.Closed.Reason != streams.ReasonError || sd.Closed.Error == "" || sd.Upstream.Status != 0 || len(sd.Chunks) != 0 {
		t.Fatalf("failed call: %+v %+v", sd.Closed, sd)
	}
	_, d := e.doc(b.ID)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(dead, "http://"))
	for _, s := range []string{port, "127.0.0.1", "secret-path", "dial"} {
		if strings.Contains(string(d.Raw), s) {
			t.Fatalf("the failed stream's document holds %q: %s", s, d.Raw)
		}
	}

	// A response cut short is an error too, after what arrived.
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "1000")
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	})
	c := e.mustPost(postOpt{})
	got, closed, _ = e.readAll(e.reader(c), c.ID, streams.Position{})
	if got != "data: 1\n\n" || closed.Reason != streams.ReasonError || closed.Error == "" {
		t.Fatalf("cut short: %q %+v", got, closed)
	}
}

// A body that isn't UTF-8 text closes the stream with "error" (J.1
// Chunks).
func TestNotText(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	// The lines before the bad bytes are kept, whether they arrive ahead
	// of them or in the same read.
	for _, together := range []bool{false, true} {
		stored := make(chan struct{})
		e.up.set(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			if together {
				w.Write([]byte("data: fine\n\ndata: \xff\xfe broken\n\ndata: after\n\n"))
				return
			}
			io.WriteString(w, "data: fine\n\n")
			w.(http.Flusher).Flush()
			<-stored
			w.Write([]byte("data: \xff\xfe broken\n\n"))
		})
		a := e.mustPost(postOpt{})
		if !together {
			waitFor(t, "the first chunk", func() bool { sd, _ := e.doc(a.ID); return len(sd.Chunks) > 0 })
		}
		close(stored)
		got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
		if got != "data: fine\n\n" || closed.Reason != streams.ReasonError || !strings.Contains(closed.Error, "UTF-8") {
			t.Fatalf("not UTF-8 (together %v): %q %+v", together, got, closed)
		}
	}
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG\r\n"))
	})
	b := e.mustPost(postOpt{})
	sd := e.waitClosed(b.ID)
	if sd.Closed.Reason != streams.ReasonError || len(sd.Chunks) != 0 || sd.Upstream.Status != 200 || sd.Upstream.ContentType != "image/png" {
		t.Fatalf("not text: %+v %+v", sd.Closed, sd.Upstream)
	}
}

// An abort appended by the caller cancels the upstream request and closes
// the stream with "aborted"; one after closed is ignored (J.4).
func TestAbort(t *testing.T) {
	t.Parallel()
	for _, nonce := range []bool{false, true} {
		t.Run(fmt.Sprintf("nonce=%v", nonce), func(t *testing.T) {
			t.Parallel()
			eo := envOpt{}
			if nonce {
				eo.nsDoc = map[string]any{"nonce": "required"}
			}
			e := newEnv(t, eo)
			e.up.gated(sseParts[:2], make(chan struct{}), nil)
			a := e.mustPost(postOpt{})
			rc := e.reader(a)
			waitFor(t, "the first chunks", func() bool { sd, _ := e.doc(a.ID); return len(sd.Chunks) > 0 })
			if nonce {
				// J.4's patch as written lacks the nonce such a namespace
				// requires; with one it is still within /abort (§6.4.1).
				h, _ := rc.Head(e.ctx, nsStreams, a.ID)
				_, err := rc.Append(e.ctx, nsStreams, a.ID, h.ID, []any{map[string]any{"op": "add", "path": "/abort", "value": true}})
				if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 || ae.Code != "nonce" {
					t.Fatalf("abort without a nonce: %v", err)
				}
			}
			placed, err := streams.Abort(e.ctx, rc, nsStreams, a.ID)
			if err != nil || !placed {
				t.Fatalf("Abort: %v %v", placed, err)
			}
			select {
			case <-e.up.cancelled:
			case <-time.After(20 * time.Second):
				t.Fatal("the upstream request wasn't cancelled")
			}
			got, closed, _ := e.readAll(rc, a.ID, streams.Position{})
			if closed.Reason != streams.ReasonAborted || !strings.HasPrefix(sseBody(), got) {
				t.Fatalf("aborted stream: %q %+v", got, closed)
			}
			sd, _ := e.doc(a.ID)
			if !sd.Abort {
				t.Fatalf("no abort in the document")
			}
			// The abort entry was written under the narrowed grant: by the
			// proxy's principal, via the caller.
			es, _ := e.pc.Log(e.ctx, nsStreams, a.ID, "", "")
			found := false
			for _, en := range es {
				for _, op := range en.Patches.([]any) {
					if op.(map[string]any)["path"] == "/abort" {
						found = true
						if len(en.Via) != 1 || en.Via[0] != "user:ann" || en.Author != "svc:streams" {
							t.Fatalf("abort entry by %s via %v", en.Author, en.Via)
						}
					}
				}
			}
			if !found {
				t.Fatal("no abort entry")
			}

			// After closed: Abort leaves it alone, and an abort appended
			// anyway changes nothing.
			if placed, err := streams.Abort(e.ctx, rc, nsStreams, a.ID); err != nil || placed {
				t.Fatalf("Abort after closed: %v %v", placed, err)
			}
			e.up.set(nil)
			b := e.mustPost(postOpt{})
			rb := e.reader(b)
			if _, closed, _ := e.readAll(rb, b.ID, streams.Position{}); closed.Reason != streams.ReasonComplete {
				t.Fatalf("closed %+v", closed)
			}
			h, _ := rb.Head(e.ctx, nsStreams, b.ID)
			ops := []any{map[string]any{"op": "add", "path": "/abort", "value": true}}
			if nonce {
				ops = append(ops, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
			}
			if _, err := rb.Append(e.ctx, nsStreams, b.ID, h.ID, ops); err != nil {
				t.Fatalf("late abort: %v", err)
			}
			got, closed, _ = e.readAll(rb, b.ID, streams.Position{})
			if got != sseBody() || closed.Reason != streams.ReasonComplete {
				t.Fatalf("after a late abort: %q %+v", got, closed)
			}
		})
	}
}

// An abort the proxy doesn't see between chunks is found when its next
// append gets 412: it reads the new entries rather than resend (J.4).
func TestAbortBy412(t *testing.T) {
	t.Parallel()
	// The core holds the proxy's long-polls of the resource log back, so
	// only the 412 can tell.
	var appends atomic.Int64
	e := newEnv(t, envOpt{core: func(o *clienttest.Options) {
		o.Wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("live") == "long-poll" && r.Header.Get("X-Test-Reader") == "" && strings.HasPrefix(r.URL.Path, "/r/streams/") {
					select {
					case <-r.Context().Done():
					case <-time.After(30 * time.Second):
					}
					w.WriteHeader(204)
					return
				}
				if r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/r/streams/") {
					appends.Add(1)
				}
				next.ServeHTTP(w, r)
			})
		}
	}})
	release := make(chan struct{})
	e.up.gated(sseParts[:1], release, sseParts[1:])
	a := e.mustPost(postOpt{})
	rc := e.reader(a)
	waitFor(t, "the first chunk", func() bool { sd, _ := e.doc(a.ID); return len(sd.Chunks) > 0 })
	// Something else moves the head first: not an abort, so the proxy
	// carries on from it.
	h, _ := rc.Head(e.ctx, nsStreams, a.ID)
	if _, err := rc.Append(e.ctx, nsStreams, a.ID, h.ID, []any{map[string]any{"op": "add", "path": "/abort", "value": false}}); err != nil {
		t.Fatal(err)
	}
	if placed, err := streams.Abort(e.ctx, rc, nsStreams, a.ID); err != nil || !placed {
		t.Fatalf("Abort: %v %v", placed, err)
	}
	before := appends.Load()
	close(release) // upstream sends more: the proxy's append is stale
	sd := e.waitClosed(a.ID)
	if sd.Closed.Reason != streams.ReasonAborted {
		t.Fatalf("closed %+v", sd.Closed)
	}
	if strings.Join(sd.Chunks, "") != sseParts[0] {
		t.Fatalf("chunks after the abort landed: %q", sd.Chunks)
	}
	if n := appends.Load() - before; n < 2 {
		t.Fatalf("%d appends after the abort: want the stale one and the close", n)
	}
}

// The read grant is the proxy's, narrowed to the stream: it reads it and
// appends /abort, and nothing else (J.3).
func TestReadGrant(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	release := make(chan struct{})
	defer close(release)
	e.up.gated(sseParts[:1], release, nil)
	a := e.mustPost(postOpt{})
	other := e.mustPost(postOpt{bearer: e.callerGrant("user:bo")})
	rc := e.reader(a)
	// The proxy appends nothing more until release: the heads stay put.
	for _, id := range []string{a.ID, other.ID} {
		waitFor(t, "the first chunk", func() bool { sd, _ := e.doc(id); return len(sd.Chunks) > 0 })
	}

	g, err := grant.Decode(a.Grant, 0)
	if err != nil {
		t.Fatal(err)
	}
	blk := g.Blocks[len(g.Blocks)-1]
	if len(g.Blocks) != 2 || blk.Via != "user:ann" || fmt.Sprint(blk.Can) != "[read append]" || blk.Exp == nil || blk.Exp.Format(time.RFC3339) != a.Exp {
		t.Fatalf("narrowing block %+v", blk.Raw)
	}
	// The first rule fixes /resource to a finite set of names (§2.1): the
	// stream and its continuations.
	if names, ok := grant.ResourceLiterals(blk.Rules[0]); !ok || len(names) != 8 || names[0] != a.ID || names[1] != streams.SegmentName(a.ID, 1) {
		t.Fatalf("resource rule %v: %v %v", blk.Rules[0], names, ok)
	}
	rule := blk.Rules[1].(map[string]any)
	if w := rule["then"].([]any)[0].(map[string]any); w["op"] != "writes" || fmt.Sprint(w["within"]) != "[/abort]" {
		t.Fatalf("append rule %v", rule)
	}

	h, err := rc.Head(e.ctx, nsStreams, a.ID)
	if err != nil || h.State != client.Live {
		t.Fatalf("head: %+v %v", h, err)
	}
	if _, err := rc.Doc(e.ctx, nsStreams, a.ID, h.ID); err != nil {
		t.Fatalf("doc: %v", err)
	}
	if lp, err := rc.ResourceLongPoll(e.ctx, nsStreams, a.ID, "", ""); err != nil || len(lp.Entries) == 0 {
		t.Fatalf("long-poll from the beginning: %+v %v", lp, err)
	}
	// The core says who the grant is, and what a writer needs, though the
	// namespace document is closed to it.
	pi, err := rc.NSPrincipal(e.ctx, nsStreams)
	if err != nil || pi.Sub != "svc:streams" || fmt.Sprint(pi.Principal["via"]) != "[user:ann]" {
		t.Fatalf("principal: %+v %v", pi, err)
	}
	if _, err := rc.NSHead(e.ctx, nsStreams); err == nil {
		if _, err := rc.Heads(e.ctx, nsStreams, ""); err == nil {
			t.Fatal("the read grant lists the namespace")
		}
	}
	// Nothing but /abort.
	for _, ops := range [][]any{
		{map[string]any{"op": "add", "path": "/chunks/-", "value": "forged\n"}},
		{map[string]any{"op": "add", "path": "/closed", "value": map[string]any{"reason": "complete"}}},
		{map[string]any{"op": "add", "path": "/abort", "value": true}, map[string]any{"op": "replace", "path": "/upstream/method", "value": "GET"}},
		{map[string]any{"op": "remove", "path": "/upstream"}},
	} {
		if _, err := rc.Append(e.ctx, nsStreams, a.ID, h.ID, ops); !client.IsAuth(err) {
			t.Fatalf("append %v: %v", ops, err)
		}
	}
	if _, err := rc.Delete(e.ctx, nsStreams, a.ID, h.ID); !client.IsAuth(err) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := rc.Purge(e.ctx, nsStreams, a.ID, h.ID, false); !client.IsAuth(err) {
		t.Fatalf("purge: %v", err)
	}
	// No other resource, and no other stream.
	if _, err := rc.CreateDoc(e.ctx, nsStreams, "mine", map[string]any{"upstream": map[string]any{"method": "GET"}, "chunks": []any{}}); !client.IsAuth(err) {
		t.Fatalf("create: %v", err)
	}
	if oh, err := rc.Head(e.ctx, nsStreams, other.ID); err != nil || oh.State != client.NotFound {
		t.Fatalf("another stream's head: %+v %v", oh, err)
	}
	if _, err := rc.ResourceLongPoll(e.ctx, nsStreams, other.ID, "", ""); !client.IsNotFound(err) {
		t.Fatalf("another stream's log: %v", err)
	}
	if _, err := streams.Follow(e.ctx, rc, nsStreams, other.ID, streams.Position{}, func(streams.Batch) error { return nil }); !errors.Is(err, streams.ErrGone) {
		t.Fatalf("Follow of another stream: %v", err)
	}
	oh, _ := e.pc.Head(e.ctx, nsStreams, other.ID)
	if _, err := rc.Append(e.ctx, nsStreams, other.ID, oh.ID, []any{map[string]any{"op": "add", "path": "/abort", "value": true}}); !client.IsAuth(err) && !client.IsNotFound(err) {
		t.Fatalf("abort of another stream: %v", err)
	}
	if _, err := rc.Head(e.ctx, nsApp, "x"); err != nil {
		// 401/403/404 are all fine: it must not be readable.
	} else if h2, _ := rc.Head(e.ctx, nsApp, "x"); h2.State == client.Live {
		t.Fatal("the read grant reads the app namespace")
	}
	// And /abort it may append.
	if _, err := rc.Append(e.ctx, nsStreams, a.ID, h.ID, []any{map[string]any{"op": "add", "path": "/abort", "value": true}}); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if sd := e.waitClosed(a.ID); sd.Closed.Reason != streams.ReasonAborted {
		t.Fatalf("closed %+v", sd.Closed)
	}
	streams.Abort(e.ctx, e.pc, nsStreams, other.ID)
	e.waitClosed(other.ID)
}

// A stream about to pass documentSize closes with "size" and continues
// in the resource next names, which the reader follows with the same
// grant (J.1 Size).
func TestContinuation(t *testing.T) {
	t.Parallel()
	for _, nonce := range []bool{false, true} {
		t.Run(fmt.Sprintf("nonce=%v", nonce), func(t *testing.T) {
			t.Parallel()
			doc := map[string]any{"limits": map[string]any{"documentSize": 4096}}
			if nonce {
				doc["nonce"] = "required"
			}
			e := newEnv(t, envOpt{nsDoc: doc})
			var parts []string
			for i := 0; i < 24; i++ {
				parts = append(parts, fmt.Sprintf("data: {\"n\":%d,\"pad\":\"%s\"}\n\n", i, strings.Repeat("xÿ", 150+i)))
			}
			// One line longer than a chunk may be: cut between characters.
			parts = append(parts, "data: "+strings.Repeat("☃", 400)+"\n\n")
			want := strings.Join(parts, "")
			release := make(chan struct{})
			e.up.gated(parts[:5], release, parts[5:])
			a := e.mustPost(postOpt{})
			rc := e.reader(a)
			// A reader in the middle of the first resource.
			var first strings.Builder
			var pos streams.Position
			_, err := streams.Follow(e.ctx, rc, nsStreams, a.ID, streams.Position{}, func(b streams.Batch) error {
				for _, c := range b.Chunks {
					first.WriteString(c)
				}
				pos = b.Position
				if first.Len() >= len(parts[0])+len(parts[1]) {
					return errStop
				}
				return nil
			})
			if err != errStop {
				t.Fatal(err)
			}
			close(release)
			rest, closed, batches := e.readAll(rc, a.ID, pos)
			if first.String()+rest != want || closed.Reason != streams.ReasonComplete {
				t.Fatalf("resumed across continuations: %d+%d bytes of %d, %+v", first.Len(), len(rest), len(want), closed)
			}
			segs := map[string]bool{}
			for _, b := range batches {
				segs[b.Resource] = true
			}
			if len(segs) < 3 {
				t.Fatalf("the stream filled %d resources: %v", len(segs), segs)
			}
			got, _, all := e.readAll(rc, a.ID, streams.Position{})
			if got != want {
				t.Fatalf("read from the beginning: %d bytes of %d", len(got), len(want))
			}
			// A reader whose last revision closed a resource with "size"
			// carries on in the next, from every such point and from
			// every other.
			sizes := 0
			for _, b := range append(batches, all...) {
				if b.Closed != nil && b.Closed.Next != "" {
					sizes++
				}
			}
			if sizes < 2 {
				t.Fatalf("%d batches close with next", sizes)
			}
			var sofar strings.Builder
			for _, b := range batches {
				for _, c := range b.Chunks {
					sofar.WriteString(c)
				}
				tail, closed, _ := e.readAll(rc, a.ID, b.Position)
				if first.String()+sofar.String()+tail != want || closed.Reason != streams.ReasonComplete {
					t.Fatalf("resumed from %+v (closed %+v): %d bytes short", b.Position, b.Closed, len(want)-first.Len()-sofar.Len()-len(tail))
				}
			}
			// The first resource names the second; each is under the limit
			// and the same shape.
			sd, d := e.doc(a.ID)
			if sd.Closed.Reason != streams.ReasonSize || sd.Closed.Next != streams.SegmentName(a.ID, 1) || len(d.Raw) > 4096 {
				t.Fatalf("first resource: %+v, %d bytes", sd.Closed, len(d.Raw))
			}
			sd2, _ := e.doc(sd.Closed.Next)
			if sd2.Upstream != sd.Upstream || sd2.Upstream.Status != 200 || len(sd2.Chunks) == 0 {
				t.Fatalf("continuation: %+v", sd2.Upstream)
			}
			for name := range segs {
				s, _ := e.doc(name)
				for _, c := range s.Chunks {
					if len(c) > 800 {
						t.Fatalf("a chunk of %d bytes in a 4 KiB document", len(c))
					}
				}
			}
			waitFor(t, "the stream to be forgotten", func() bool { return e.p.Open() == 0 })
		})
	}
}

// An abort reaches a stream that has continued in another resource, and a
// stream out of segments is cut with "size" and no next.
func TestContinuationAbortAndCap(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"limits": map[string]any{"documentSize": 4096}}, options: func(o *streams.Options) { o.MaxSegments = 2 }})
	var parts []string
	for i := 0; i < 12; i++ {
		parts = append(parts, fmt.Sprintf("data: %d %s\n\n", i, strings.Repeat("a", 400)))
	}
	e.up.gated(parts, make(chan struct{}), nil)
	a := e.mustPost(postOpt{})
	rc := e.reader(a)
	next := streams.SegmentName(a.ID, 1)
	waitFor(t, "the continuation to fill", func() bool {
		h, err := e.pc.Head(e.ctx, nsStreams, next)
		if err != nil || h.State != client.Live {
			return false
		}
		sd, _ := e.doc(next)
		return len(sd.Chunks) > 0
	})
	if placed, err := streams.Abort(e.ctx, rc, nsStreams, a.ID); err != nil || !placed {
		t.Fatalf("Abort: %v %v", placed, err)
	}
	select {
	case <-e.up.cancelled:
	case <-time.After(20 * time.Second):
		t.Fatal("the upstream request wasn't cancelled")
	}
	if _, closed, _ := e.readAll(rc, a.ID, streams.Position{}); closed.Reason != streams.ReasonAborted {
		t.Fatalf("closed %+v", closed)
	}

	// Out of segments.
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("data: %d %s\n\n", i, strings.Repeat("b", 400)))
	}
	e.up.gated(many, make(chan struct{}), nil)
	b := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(b), b.ID, streams.Position{})
	if closed.Reason != streams.ReasonSize || closed.Next != "" || closed.Error == "" || !strings.HasPrefix(strings.Join(many, ""), got) || len(got) < 4000 {
		t.Fatalf("out of segments: %d bytes, %+v", len(got), closed)
	}
	select {
	case <-e.up.cancelled:
	case <-time.After(20 * time.Second):
		t.Fatal("the upstream request of the cut stream wasn't cancelled")
	}
}

// The sweeper closes an open stream nobody appends to with "timeout", and
// a proxy closes its own when upstream goes silent (J.2 Restarts).
func TestIdleTimeout(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"nonce": "required"}})
	// An orphan: created, as by a proxy that then died.
	gen := map[string]any{"upstream": map[string]any{"method": "POST"}, "chunks": []any{"data: 1\n\n"}, "$nonce": seal.NewNonce()}
	if _, err := e.pc.CreateDoc(e.ctx, nsStreams, "orphan", gen); err != nil {
		t.Fatal(err)
	}
	// And something that isn't a stream, which is left alone.
	if _, err := e.pc.CreateDoc(e.ctx, nsStreams, "note", map[string]any{"text": "hi", "$nonce": seal.NewNonce()}); err != nil {
		t.Fatal(err)
	}
	// One the proxy is writing isn't the sweeper's.
	release := make(chan struct{})
	e.up.gated(sseParts[:1], release, sseParts[1:])
	a := e.mustPost(postOpt{})
	waitFor(t, "the first chunk", func() bool { sd, _ := e.doc(a.ID); return len(sd.Chunks) > 0 })

	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if sd, _ := e.doc("orphan"); sd.Closed != nil {
		t.Fatalf("closed before the idle timeout: %+v", sd.Closed)
	}
	e.offset.Store(int64(21 * time.Second))
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	sd, _ := e.doc("orphan")
	if sd.Closed == nil || sd.Closed.Reason != streams.ReasonTimeout || len(sd.Chunks) != 1 {
		t.Fatalf("orphan: %+v", sd.Closed)
	}
	if own, _ := e.doc(a.ID); own.Closed != nil {
		t.Fatalf("the sweeper closed a stream being written: %+v", own.Closed)
	}
	if h, _ := e.pc.Head(e.ctx, nsStreams, "note"); h.State != client.Live {
		t.Fatalf("note: %+v", h)
	}
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	close(release)
	if _, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{}); closed.Reason != streams.ReasonComplete {
		t.Fatalf("closed %+v", closed)
	}
}

func TestIdleUpstream(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{options: func(o *streams.Options) { o.IdleTimeout = 300 * time.Millisecond }})
	e.up.gated(sseParts[:1], make(chan struct{}), nil)
	a := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	// On a slow machine the timeout may come before the first flush.
	if (got != sseParts[0] && got != "") || closed.Reason != streams.ReasonTimeout {
		t.Fatalf("silent upstream: %q %+v", got, closed)
	}
	select {
	case <-e.up.cancelled:
	case <-time.After(20 * time.Second):
		t.Fatal("the upstream request wasn't cancelled")
	}
}

// A proxy keeps the names of its open streams in the state file, and one
// started again closes those still open with "error" (J.2 Restarts).
func TestRestart(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "state", "streams.json")
	e := newEnv(t, envOpt{options: func(o *streams.Options) { o.StateFile = file }})
	release := make(chan struct{})
	e.up.gated(sseParts[:1], release, sseParts[1:])
	a := e.mustPost(postOpt{})
	readState := func() []string {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil
		}
		var st struct{ Open []string }
		json.Unmarshal(b, &st)
		return st.Open
	}
	if open := readState(); len(open) != 1 || open[0] != a.ID {
		t.Fatalf("state file while open: %v", open)
	}
	close(release)
	e.waitClosed(a.ID)
	waitFor(t, "the state file to empty", func() bool { return len(readState()) == 0 && e.p.Open() == 0 })

	// A proxy that died left two streams in its file: one still open, one
	// it had closed; and a name that is gone.
	gen := map[string]any{"upstream": map[string]any{"method": "POST"}, "chunks": []any{"data: 1\n\n"}}
	if _, err := e.pc.CreateDoc(e.ctx, nsStreams, "left-open", gen); err != nil {
		t.Fatal(err)
	}
	gen["closed"] = map[string]any{"reason": "complete"}
	if _, err := e.pc.CreateDoc(e.ctx, nsStreams, "left-closed", gen); err != nil {
		t.Fatal(err)
	}
	st, _ := json.Marshal(map[string]any{"ns": nsStreams, "open": []string{"left-open", "left-closed", "never-was"}})
	file2 := filepath.Join(t.TempDir(), "streams.json")
	os.WriteFile(file2, st, 0o600)
	opt := e.opt
	opt.StateFile = file2
	p2, err := streams.New(e.ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close(e.ctx)
	sd, _ := e.doc("left-open")
	if sd.Closed == nil || sd.Closed.Reason != streams.ReasonError || sd.Closed.Error == "" || len(sd.Chunks) != 1 {
		t.Fatalf("left-open: %+v", sd.Closed)
	}
	if sd, _ := e.doc("left-closed"); sd.Closed.Reason != streams.ReasonComplete {
		t.Fatalf("left-closed: %+v", sd.Closed)
	}
	b, _ := os.ReadFile(file2)
	if !strings.Contains(string(b), `"open":[]`) {
		t.Fatalf("state file after the restart: %s", b)
	}
	// A state file of another namespace is refused.
	os.WriteFile(file2, []byte(`{"ns":"elsewhere","open":["x"]}`), 0o600)
	if _, err := streams.New(e.ctx, opt); err == nil || !strings.Contains(err.Error(), "elsewhere") {
		t.Fatalf("state file of another namespace: %v", err)
	}
}

// Closing the proxy closes its open streams with "error".
func TestShutdown(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	e.up.gated(sseParts[:1], make(chan struct{}), nil)
	a := e.mustPost(postOpt{})
	waitFor(t, "the first chunk", func() bool { sd, _ := e.doc(a.ID); return len(sd.Chunks) > 0 })
	if err := e.p.Close(e.ctx); err != nil {
		t.Fatal(err)
	}
	sd, _ := e.doc(a.ID)
	if sd.Closed == nil || sd.Closed.Reason != streams.ReasonError || !strings.Contains(sd.Closed.Error, "shut down") {
		t.Fatalf("closed %+v", sd.Closed)
	}
	select {
	case <-e.up.cancelled:
	case <-time.After(20 * time.Second):
		t.Fatal("the upstream request wasn't cancelled")
	}
	if status, _, _ := e.post(postOpt{}); status != 503 {
		t.Fatalf("POST after Close: %d", status)
	}
}

// A closed stream is purged once its read grants have expired (J.4
// Expiry).
func TestExpiry(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"limits": map[string]any{"documentSize": 4096}}, options: func(o *streams.Options) { o.TTL = 10 * time.Minute }})
	var parts []string
	for i := 0; i < 12; i++ {
		parts = append(parts, fmt.Sprintf("data: %d %s\n\n", i, strings.Repeat("a", 400)))
	}
	e.up.set(func(w http.ResponseWriter, r *http.Request) { writeParts(w, parts) })
	a := e.mustPost(postOpt{key: "k"})
	rc := e.reader(a)
	if exp, _ := time.Parse(time.RFC3339, a.Exp); time.Until(exp) > 10*time.Minute || time.Until(exp) < 9*time.Minute {
		t.Fatalf("exp %s", a.Exp)
	}
	if got, _, _ := e.readAll(rc, a.ID, streams.Position{}); got != strings.Join(parts, "") {
		t.Fatal("read")
	}
	waitFor(t, "the stream to be forgotten", func() bool { return e.p.Open() == 0 })
	// An open stream that old is not purged, only timed out.
	if _, err := e.pc.CreateDoc(e.ctx, nsStreams, "open", map[string]any{"upstream": map[string]any{"method": "POST"}, "chunks": []any{}}); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	next := streams.SegmentName(a.ID, 1)
	for _, name := range []string{a.ID, next} {
		if h, _ := e.pc.Head(e.ctx, nsStreams, name); h.State != client.Live {
			t.Fatalf("%s before its grants expired: %+v", name, h)
		}
	}
	e.offset.Store(int64(9 * time.Minute))
	e.p.Sweep(e.ctx)
	if h, _ := e.pc.Head(e.ctx, nsStreams, a.ID); h.State != client.Live {
		t.Fatalf("purged a minute early: %+v", h)
	}
	e.offset.Store(int64(10*time.Minute + 5*time.Second))
	// The first sweep closes the open one; its ttl then runs from its
	// creation too.
	for i := 0; i < 2; i++ {
		if err := e.p.Sweep(e.ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{a.ID, next, "open"} {
		if h, _ := e.pc.Head(e.ctx, nsStreams, name); h.State != client.Purged {
			t.Fatalf("%s after its grants expired: %+v", name, h)
		}
	}
	if _, err := streams.Follow(e.ctx, e.pc, nsStreams, a.ID, streams.Position{}, func(streams.Batch) error { return nil }); !errors.Is(err, streams.ErrGone) {
		t.Fatalf("Follow of a purged stream: %v", err)
	}
	// Its id is spent: the same request key is answered 410 (J.2 step 1).
	if status, _, body := e.post(postOpt{key: "k"}); status != 410 {
		t.Fatalf("repeat after the purge: %d %s", status, body)
	}
}

// Only upstreams under an allowed prefix are called.
func TestAllowlist(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	base := e.up.srv.URL // the allowlist is base + "/v1"
	host := strings.TrimPrefix(base, "http://")
	for _, u := range []string{
		base + "/v2/messages",
		base + "/v1x",
		base + "/v1/../admin",
		base + "/v1/%2e%2e/admin",
		base,
		"http://" + host + ".evil.example/v1/messages",
		"http://" + host + "@evil.example/v1/messages",
		"http://user:pw@" + host + "/v1/messages",
		"https://" + host + "/v1/messages",
		"http://evil.example/v1/messages",
		"http://169.254.169.254/latest/meta-data",
	} {
		// 403, or 400 for one that isn't a URL at all.
		if status, _, body := e.post(postOpt{url: u}); status != 403 && !(status == 400 && strings.Contains(u, ".evil.example")) {
			t.Fatalf("%s: %d %s", u, status, body)
		}
	}
	for _, u := range []string{"ftp://" + host + "/v1/x", "/v1/x", "::"} {
		if status, _, body := e.post(postOpt{url: u}); status != 400 {
			t.Fatalf("%s: %d %s", u, status, body)
		}
	}
	if status, _, _ := e.post(postOpt{headers: map[string]string{"Upstream-Method": "connect"}}); status != 400 {
		t.Fatalf("method: %d", status)
	}
	if n := e.up.hits.Load(); n != 0 {
		t.Fatalf("upstream was called %d times", n)
	}
	for _, u := range []string{base + "/v1", base + "/v1/", base + "/v1/a/b?x=1"} {
		a := e.mustPost(postOpt{url: u})
		e.waitClosed(a.ID)
	}
	// A redirect isn't followed out of the allowlist: it is the stream.
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/redirect" {
			t.Errorf("upstream followed a redirect to %s", r.URL.Path)
		}
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	a := e.mustPost(postOpt{url: base + "/v1/redirect", headers: map[string]string{"Upstream-Method": "GET"}})
	if sd := e.waitClosed(a.ID); sd.Upstream.Status != 302 || sd.Closed.Reason != streams.ReasonComplete {
		t.Fatalf("redirect: %+v %+v", sd.Upstream, sd.Closed)
	}
	// A request body over the bound.
	if status, _, _ := e.post(postOpt{body: strings.Repeat("x", 1<<20+1)}); status != 413 {
		t.Fatalf("large body: %d", status)
	}
	// No allowlist refuses all.
	opt := e.opt
	opt.Upstreams = nil
	p2, err := streams.New(e.ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close(e.ctx)
	e.p, e.srv.Config.Handler = p2, p2
	if status, _, _ := e.post(postOpt{}); status != 403 {
		t.Fatalf("no allowlist: %d", status)
	}
	if _, err := streams.New(e.ctx, streams.Options{Client: e.pc, Grant: e.grant, CallerNS: nsApp, Upstreams: []string{"api.example.com"}}); err == nil {
		t.Fatal("an upstream prefix without a scheme was taken")
	}
}

// A caller the core doesn't know is refused: the caller is who the core
// says the bearer is, not who the token says.
func TestCallers(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	stranger := clienttest.NewKey("app-key") // the same kid, another key
	forged := stranger.Grant(t, e.s.Now(), "user:ann", []string{nsApp}, []string{"read"})
	expired := clienttest.Mint(t, e.appKey.Priv, map[string]any{"kid": "app-key", "sub": "user:ann", "ns": []any{nsApp}, "can": []any{"read"},
		"exp": time.Now().Add(-time.Minute).Format(time.RFC3339)})
	elsewhere := e.key.Grant(t, e.s.Now(), "user:ann", []string{nsStreams}, []string{"read"})
	for name, bearer := range map[string]string{"none": "none", "garbage": "not-a-grant", "forged": forged, "expired": expired, "another namespace's": elsewhere} {
		if status, _, body := e.post(postOpt{bearer: bearer, key: "turn-1"}); status != 401 {
			t.Fatalf("%s: %d %s", name, status, body)
		}
	}
	// X-Author is nobody when the core has grants.
	if status, _, _ := e.post(postOpt{bearer: "none", author: "ann"}); status != 401 {
		t.Fatalf("X-Author with grants: %d", status)
	}
	if n := e.up.hits.Load(); n != 0 {
		t.Fatalf("upstream was called %d times", n)
	}
	for _, path := range []string{"/", "/streams/x", "/r/streams/x"} {
		resp, err := http.Get(e.srv.URL + path)
		if err != nil || resp.StatusCode != 404 {
			t.Fatalf("GET %s: %v %v", path, resp, err)
		}
		resp.Body.Close()
	}
	if resp, _ := http.Get(e.srv.URL + "/streams"); resp.StatusCode != 405 {
		t.Fatalf("GET /streams: %d", resp.StatusCode)
	}
}

// Over a core with authentication disabled, the caller is its X-Author
// and there is no grant to hand out.
func TestDevCore(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{dev: true})
	if status, _, body := e.post(postOpt{bearer: "none"}); status != 401 {
		t.Fatalf("no X-Author: %d %s", status, body)
	}
	a := e.mustPost(postOpt{author: "ann", key: "k"})
	if a.Grant != "" || a.Exp == "" {
		t.Fatalf("answer %+v", a)
	}
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != sseBody() || closed.Reason != streams.ReasonComplete {
		t.Fatalf("read %q %+v", got, closed)
	}
	if status, b, _ := e.post(postOpt{author: "ann", key: "k"}); status != 200 || b.ID != a.ID {
		t.Fatalf("repeat: %d %+v", status, b)
	}
	if b := e.mustPost(postOpt{author: "bo", key: "k"}); b.ID == a.ID {
		t.Fatal("two authors share a keyed stream")
	} else {
		e.waitClosed(b.ID)
	}
}

// In a namespace that requires nonces every patch set of the proxy's
// carries a fresh one (J.2 step 3, §C.7).
func TestNonceRequired(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"nonce": "required"}})
	a := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != sseBody() || closed.Reason != streams.ReasonComplete {
		t.Fatalf("read %q %+v", got, closed)
	}
	es, err := e.pc.Log(e.ctx, nsStreams, a.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, en := range es {
		if !seal.HasFreshNonce(en.Patches) && i > 0 {
			t.Fatalf("entry %d has no fresh nonce: %v", i, en.Patches)
		}
		for _, op := range en.Patches.([]any) {
			m := op.(map[string]any)
			n, _ := m["value"].(string)
			if m["path"] == "" {
				n, _ = m["value"].(map[string]any)["$nonce"].(string)
			} else if m["path"] != "/$nonce" {
				continue
			}
			if !seal.ValidNonce(n) || seen[n] {
				t.Fatalf("entry %d: nonce %q", i, n)
			}
			seen[n] = true
		}
	}
	if len(seen) != len(es) {
		t.Fatalf("%d nonces in %d entries", len(seen), len(es))
	}
}

// On 429 the proxy waits and appends again, with what arrived meanwhile
// in one bigger flush; nothing is lost or doubled (J.2 Pace).
func TestRateLimited(t *testing.T) {
	t.Parallel()
	var refuse, refused atomic.Int64
	e := newEnv(t, envOpt{core: func(o *clienttest.Options) {
		o.Wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/r/streams/") && r.Header.Get("If-Match") != "" && refuse.Add(-1) >= 0 {
					refused.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(429)
					io.WriteString(w, `{"code":"rate_limited","retryAfter":0.06}`)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}})
	var parts []string
	for i := 0; i < 12; i++ {
		parts = append(parts, fmt.Sprintf("data: %d\n\n", i))
	}
	e.up.set(func(w http.ResponseWriter, r *http.Request) { writeParts(w, parts) })
	refuse.Store(4)
	a := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != strings.Join(parts, "") || closed.Reason != streams.ReasonComplete {
		t.Fatalf("read %q %+v", got, closed)
	}
	if refused.Load() != 4 {
		t.Fatalf("%d appends were refused", refused.Load())
	}
	es, _ := e.pc.Log(e.ctx, nsStreams, a.ID, "", "")
	most := 0
	for _, en := range es[1:] {
		n := 0
		for _, op := range en.Patches.([]any) {
			if op.(map[string]any)["path"] == "/chunks/-" {
				n++
			}
		}
		most = max(most, n)
	}
	if most < 2 {
		t.Fatalf("no flush carried what arrived during the wait: %d entries", len(es))
	}
}

// The real limits: a stream flushed faster than ratePerResource allows
// still arrives whole.
func TestRealRateLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"limits": map[string]any{"ratePerResource": map[string]any{"rate": 5, "burst": 3}}},
		options: func(o *streams.Options) { o.Flush = time.Millisecond }})
	var parts []string
	for i := 0; i < 14; i++ {
		parts = append(parts, fmt.Sprintf("data: %d\n\n", i))
	}
	e.up.set(func(w http.ResponseWriter, r *http.Request) { writeParts(w, parts) })
	a := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != strings.Join(parts, "") || closed.Reason != streams.ReasonComplete {
		t.Fatalf("read %q %+v", got, closed)
	}
}

// What the proxy refuses at start.
func TestStartChecks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, KeyStore: ks})
	k := clienttest.NewKey("k")
	mk := func(ns string, doc map[string]any, can ...string) (*client.Client, string) {
		if doc["read"] == nil {
			doc["read"] = "grant"
		}
		doc["keys"] = []any{k.Entry("*")}
		if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc); err != nil {
			t.Fatal(err)
		}
		g := k.Grant(t, s.Now(), "svc:streams", []string{ns}, can)
		return s.Client(t, client.WithBearer(g)), g
	}
	all := []string{"create", "append", "read", "purge"}
	for _, tc := range []struct {
		ns   string
		doc  map[string]any
		can  []string
		want string
	}{
		{"sealed", map[string]any{"encryption": map[string]any{"level": "sealed"}}, all, "sealed"},
		{"e2e", map[string]any{"encryption": map[string]any{"level": "e2e"}}, all, "end-to-end"},
		{"nopurge", map[string]any{}, []string{"create", "append", "read"}, "purge"},
		{"open", map[string]any{"read": "public"}, all, "public"},
		{"tiny", map[string]any{"limits": map[string]any{"documentSize": 900}}, all, "too small"},
	} {
		c, g := mk(tc.ns, tc.doc, tc.can...)
		_, err := streams.New(ctx, streams.Options{Client: c, Grant: g, NS: tc.ns, CallerNS: "app"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.ns, err)
		}
	}
	c, g := mk("fine", map[string]any{"encryption": map[string]any{"level": "at-rest"}}, all...)
	if _, err := streams.New(ctx, streams.Options{Client: c, Grant: g, NS: "missing", CallerNS: "app"}); err == nil {
		t.Fatal("a namespace that doesn't exist")
	}
	if _, err := streams.New(ctx, streams.Options{Client: c, Grant: g, NS: "fine"}); err == nil || !strings.Contains(err.Error(), "caller namespace") {
		t.Fatalf("no caller namespace: %v", err)
	}
	sealedGrant, _ := grant.Decode(g, 0)
	sg, _ := sealedGrant.Seal()
	if _, err := streams.New(ctx, streams.Options{Client: c, Grant: sg.Encode(), NS: "fine", CallerNS: "app"}); err == nil || !strings.Contains(err.Error(), "narrowed") {
		t.Fatalf("a sealed grant: %v", err)
	}
	p, err := streams.New(ctx, streams.Options{Client: c, Grant: g, NS: "fine", CallerNS: "app"})
	if err != nil {
		t.Fatalf("an at-rest namespace: %v", err)
	}
	p.Close(ctx)
}
