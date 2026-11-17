package streams_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/streams"
)

// Spec v0.85, TOOLS Addendum J as it answers the reference's notes on
// streams (SPEC-FEEDBACK v0.82 Open 93–100).

// J.1 Names (v0.85): the proxy learns its caller from GET
// /ns/{ns}/principal, and "a grant narrowed to "can": [] suffices". Such
// a grant is the same caller as the grant it was narrowed from: the same
// key and principal.id, so the same Request-Key finds the same stream.
func TestV085CallerNarrowedToNoVerbs(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	full := e.callerGrant("user:ann")
	g, err := grant.Decode(full, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := g.Narrow(map[string]any{"can": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	identity := n.Encode()
	status, a, body := e.post(postOpt{bearer: identity, key: "turn-1"})
	if status != 201 || a.Grant == "" {
		t.Fatalf("a caller grant narrowed to no verbs: %d %s", status, body)
	}
	if got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{}); got != sseBody() || closed.Reason != streams.ReasonComplete {
		t.Fatalf("its stream: %q %+v", got, closed)
	}
	status, b, body := e.post(postOpt{bearer: full, key: "turn-1"})
	if status != 200 || b.ID != a.ID {
		t.Fatalf("the grant it was narrowed from, the same Request-Key: %d %s, id %s want %s", status, body, b.ID, a.ID)
	}
	if n := e.up.hits.Load(); n != 1 {
		t.Fatalf("upstream was called %d times", n)
	}
}

// J.2 step 2 (v0.85): "An answer of any status, a 3xx included and not
// followed, is kept with its body and closed "complete"."
func TestV085RedirectKeptNotFollowed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("the proxy followed the redirect to %s", r.URL.Path)
		}
		w.Header().Set("Location", "/v1/elsewhere")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusFound)
		io.WriteString(w, "moved\n")
	})
	a := e.mustPost(postOpt{})
	got, closed, batches := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != "moved\n" || closed.Reason != streams.ReasonComplete || closed.Error != "" || batches[len(batches)-1].Upstream.Status != 302 {
		t.Fatalf("a 302: %q %+v %+v", got, closed, batches[len(batches)-1].Upstream)
	}
	if n := e.up.hits.Load(); n != 1 {
		t.Fatalf("upstream was called %d times", n)
	}
	// Nothing of where it pointed is in the document (J.1 Nothing secret).
	if _, d := e.doc(a.ID); strings.Contains(string(d.Raw), "elsewhere") {
		t.Fatalf("the stream document holds the redirect's target: %s", d.Raw)
	}
}

// J.4 Expiry (v0.85): the proxy purges a stream "and its continuations"
// once the stream is closed and its read grants, counted from the
// stream's creation, have expired. A first resource that filled up
// ("size" with next) isn't the stream closed: it stays while a
// continuation is still carried, however old, and goes with the
// continuations once the last is closed.
func TestV085PurgeWithContinuations(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"limits": map[string]any{"documentSize": 4096}}, options: func(o *streams.Options) { o.TTL = 10 * time.Minute }})
	var parts []string
	for i := 0; i < 12; i++ {
		parts = append(parts, fmt.Sprintf("data: %d %s\n\n", i, strings.Repeat("a", 400)))
	}
	release := make(chan struct{})
	e.up.gated(parts, release, []string{"data: last\n\n"})
	a := e.mustPost(postOpt{})
	next := streams.SegmentName(a.ID, 1)
	live := func(name string) bool {
		h, err := e.pc.Head(e.ctx, nsStreams, name)
		return err == nil && h.State == client.Live
	}
	waitFor(t, "the stream to continue in its next resource", func() bool {
		d, _ := e.doc(a.ID)
		return d != nil && d.Closed != nil && d.Closed.Next == next && live(next)
	})
	// Past the read grants' exp, the stream still carried.
	e.offset.Store(int64(11 * time.Minute))
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if !live(a.ID) || !live(next) {
		t.Fatalf("a resource of a stream still carried was purged: %s live %v, %s live %v", a.ID, live(a.ID), next, live(next))
	}
	close(release)
	waitFor(t, "the stream to be forgotten", func() bool { return e.p.Open() == 0 })
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{a.ID, next} {
		h, err := e.pc.Head(e.ctx, nsStreams, name)
		if err != nil || h.State != client.Purged {
			t.Fatalf("%s after the stream closed, its grants expired: %+v %v", name, h, err)
		}
	}
	// Any later continuation went with them.
	for i := 2; i < 8; i++ {
		if live(streams.SegmentName(a.ID, i)) {
			t.Fatalf("continuation %d outlived its stream", i)
		}
	}
}

// J.2 Restarts (v0.85): "A proxy that finds its stream closed by another
// cancels upstream and appends nothing more." It finds out from the log
// it follows, at once, not at its next append or its own idle timeout.
func TestV085ClosedByAnotherStopsUpstream(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{}) // IdleTimeout 20s: longer than the test waits
	e.up.gated(sseParts[:1], make(chan struct{}), nil)
	a := e.mustPost(postOpt{})
	waitFor(t, "the first chunk", func() bool {
		d, _ := e.doc(a.ID)
		return d != nil && len(d.Chunks) > 0
	})
	// Another proxy closes it, as its sweep does with a stream it takes
	// for an orphan.
	h, err := e.pc.Head(e.ctx, nsStreams, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pc.Append(e.ctx, nsStreams, a.ID, h.ID, []any{map[string]any{"op": "add", "path": "/closed",
		"value": map[string]any{"reason": streams.ReasonTimeout, "error": "no append for 1s"}}}); err != nil {
		t.Fatalf("closing the stream as another proxy: %v", err)
	}
	select {
	case <-e.up.cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream request wasn't cancelled when another proxy closed the stream")
	}
	waitFor(t, "the stream to be forgotten", func() bool { return e.p.Open() == 0 })
	// Nothing more was appended: the other proxy's close is the head.
	after, err := e.pc.Head(e.ctx, nsStreams, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.doc(a.ID); d.Closed == nil || d.Closed.Reason != streams.ReasonTimeout || d.Closed.Error != "no append for 1s" {
		t.Fatalf("closed: %+v", d.Closed)
	}
	es, err := e.pc.Log(e.ctx, nsStreams, a.ID, after.ID, h.ID)
	if err != nil || len(es) != 1 {
		t.Fatalf("entries after the head the other proxy closed on: %d %v", len(es), err)
	}
}

// J.1 Size (v0.85): "where latency matters a stream continues well below
// documentSize". SegmentSize is that size: the stream continues in
// {id}.1 though the namespace's documentSize would hold it all.
func TestV085SegmentSize(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{options: func(o *streams.Options) { o.SegmentSize = 4096 }})
	var parts []string
	for i := 0; i < 12; i++ {
		parts = append(parts, fmt.Sprintf("data: %d %s\n\n", i, strings.Repeat("a", 400)))
	}
	e.up.set(func(w http.ResponseWriter, r *http.Request) { writeParts(w, parts) })
	a := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != strings.Join(parts, "") || closed.Reason != streams.ReasonComplete {
		t.Fatalf("read: %d bytes, %+v", len(got), closed)
	}
	d, raw := e.doc(a.ID)
	if d.Closed == nil || d.Closed.Reason != streams.ReasonSize || d.Closed.Next != streams.SegmentName(a.ID, 1) {
		t.Fatalf("the first resource: %+v", d.Closed)
	}
	if len(raw.Raw) > 4096 {
		t.Fatalf("the first resource is %d bytes, over the segment size", len(raw.Raw))
	}
}
