package streams_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/streams"
)

// A namespace anyone may read is no place for streams: the core serves
// its reads without a grant, whatever the read grant's rules say. And a
// proxy that can't read the namespace's configuration doesn't start.
func TestPublicNamespaceRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{nsDoc: map[string]any{"read": "public"}, noProxy: true})
	if _, err := streams.New(e.ctx, e.opt); err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("a public namespace: %v", err)
	}
	// What the refusal is for: the document of a resource there is served
	// to anyone.
	if _, err := e.pc.CreateDoc(e.ctx, nsStreams, "s", map[string]any{"upstream": map[string]any{"method": "POST"}, "chunks": []any{"secret\n"}}); err != nil {
		t.Fatal(err)
	}
	if h, err := e.s.Client(t).Head(e.ctx, nsStreams, "s"); err != nil || h.State != client.Live {
		t.Fatalf("anonymous read of a public namespace: %+v %v", h, err)
	}

	// A grant whose rules keep it from the namespace document can't
	// verify the configuration: refused too.
	f := newEnv(t, envOpt{noProxy: true})
	f.opt.Grant = f.key.Grant(t, f.s.Now(), "svc:streams", []string{nsStreams}, []string{"create", "append", "read", "purge"},
		map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "never"}}}})
	f.opt.Client = f.s.Client(t, client.WithBearer(f.opt.Grant))
	if _, err := f.opt.Client.NonceRequired(f.ctx, nsStreams); err == nil {
		t.Skip("the restricted grant reads the namespace document")
	}
	if _, err := streams.New(f.ctx, f.opt); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("a namespace document the proxy can't read: %v", err)
	}
}

// Once a stream's history is pruned its creation time is gone: a repeated
// request gets no new grant, rather than one that outlives the first.
func TestRepeatAfterPrune(t *testing.T) {
	t.Parallel()
	for _, nonce := range []bool{false, true} {
		t.Run(fmt.Sprintf("nonce=%v", nonce), func(t *testing.T) { t.Parallel(); repeatAfterPrune(t, nonce) })
	}
}

func repeatAfterPrune(t *testing.T, nonce bool) {
	// The core's clock is the test's: a prune reaches only what is older
	// than the retry window (§8.6).
	eo := envOpt{noProxy: true, core: func(o *clienttest.Options) { o.RealClock = false }}
	if nonce {
		eo.nsDoc = map[string]any{"nonce": "required"}
	}
	e := newEnv(t, eo)
	e.opt.Now = func() time.Time { return e.s.Now().Add(time.Duration(e.offset.Load())) }
	e.start()
	a := e.mustPost(postOpt{key: "k"})
	sd := e.waitClosed(a.ID)
	if sd.Closed.Reason != streams.ReasonComplete {
		t.Fatalf("closed %+v", sd.Closed)
	}
	// While its history is whole, a repeat is answered with the same exp.
	e.s.Clock.Advance(10 * time.Minute)
	if status, b, body := e.post(postOpt{key: "k"}); status != 200 || b.Exp != a.Exp {
		t.Fatalf("repeat: %d %s (first exp %s)", status, body, a.Exp)
	}
	h, _ := e.pc.Head(e.ctx, nsStreams, a.ID)
	pruner := e.s.Client(t, client.WithBearer(e.adminKey.Grant(t, e.s.Now(), "svc:retention", []string{nsStreams}, []string{"prune", "read"})))
	if res, err := pruner.Prune(e.ctx, nsStreams, a.ID, client.PruneRequest{Horizon: h.ID}); err != nil || res.Horizon != h.ID {
		t.Fatalf("prune: %+v %v", res, err)
	}
	if _, _, err := e.pc.LogPage(e.ctx, nsStreams, a.ID, h.ID, ""); !client.IsPruned(err) {
		t.Fatalf("the log after the prune: %v", err)
	}
	// Where the core still answers the repeated create with the genesis
	// entry (an identical create, without nonces), the exp is the first
	// one's; where it can't be had (412), there is no new grant.
	status, b, body := e.post(postOpt{key: "k"})
	if nonce {
		if status != 409 || b.Grant != "" || !strings.Contains(body, "pruned") {
			t.Fatalf("repeat after the prune: %d %s", status, body)
		}
	} else if status != 200 || b.Exp != a.Exp {
		t.Fatalf("repeat after the prune: %d %s (first exp %s)", status, body, a.Exp)
	}
	// The stream is still read with the first grant, and swept by its
	// head's time, which is no earlier than its creation: not before
	// the first grant's exp.
	if got, _, _ := e.readAll(e.reader(a), a.ID, streams.Position{}); got != sseBody() {
		t.Fatalf("read %q", got)
	}
	exp, _ := time.Parse(time.RFC3339, a.Exp)
	e.offset.Store(int64(exp.Sub(e.s.Now()) - time.Second))
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if h, _ := e.pc.Head(e.ctx, nsStreams, a.ID); h.State != client.Live {
		t.Fatalf("purged before its grant's exp: %+v", h)
	}
	e.offset.Store(int64(exp.Sub(e.s.Now()) + 5*time.Second))
	if err := e.p.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if h, _ := e.pc.Head(e.ctx, nsStreams, a.ID); h.State != client.Purged {
		t.Fatalf("after its ttl: %+v", h)
	}
}

// The read grant is of the stream namespace alone, though the proxy's
// grant names others, and a keyed id is the namespace's own.
func TestReadGrantNamespace(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{noProxy: true})
	const other = "other"
	if _, err := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, other))).CreateNamespace(e.ctx, other,
		map[string]any{"read": "grant", "keys": []any{e.key.Entry("create", "append", "read", "purge")}}); err != nil {
		t.Fatal(err)
	}
	e.grant = e.key.Grant(t, e.s.Now(), "svc:streams", []string{nsStreams, other}, []string{"create", "append", "read", "purge"})
	e.pc = e.s.Client(t, client.WithBearer(e.grant))
	e.opt.Grant, e.opt.Client = e.grant, e.pc
	e.start()
	a := e.mustPost(postOpt{key: "k"})
	e.waitClosed(a.ID)
	// A resource of the same name in the other namespace.
	res, err := e.pc.CreateDoc(e.ctx, other, a.ID, map[string]any{"secret": "not a stream"})
	if err != nil {
		t.Fatal(err)
	}
	rc := e.reader(a)
	if h, err := rc.Head(e.ctx, other, a.ID); err == nil && h.State != client.NotFound {
		t.Fatalf("the read grant reads %s/%s: %+v", other, a.ID, h)
	}
	if _, err := rc.Doc(e.ctx, other, a.ID, res.ID); err == nil {
		t.Fatalf("the read grant reads the document of %s/%s", other, a.ID)
	}
	if _, err := rc.Append(e.ctx, other, a.ID, res.ID, []any{map[string]any{"op": "add", "path": "/abort", "value": true}}); err == nil {
		t.Fatalf("the read grant appends to %s/%s", other, a.ID)
	}
	if got, _, _ := e.readAll(rc, a.ID, streams.Position{}); got != sseBody() {
		t.Fatalf("read %q", got)
	}
	// A proxy over the other namespace gives the same caller and key
	// another id.
	opt := e.opt
	opt.NS = other
	p2, err := streams.New(e.ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close(e.ctx)
	e.p, e.srv.Config.Handler = p2, p2
	if b := e.mustPost(postOpt{key: "k"}); b.ID == a.ID {
		t.Fatalf("the same keyed id %s in two namespaces", b.ID)
	}
}

// A fast upstream is held back while the proxy can't append: what it has
// read and not yet written is bounded.
func TestBackpressure(t *testing.T) {
	t.Parallel()
	var limited atomic.Bool
	limited.Store(true)
	e := newEnv(t, envOpt{core: func(o *clienttest.Options) {
		o.Wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if limited.Load() && r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/r/streams/") && r.Header.Get("If-Match") != "" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(429)
					io.WriteString(w, `{"code":"rate_limited","retryAfter":0.2}`)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}})
	const total = 96 << 20
	line := []byte(strings.Repeat("x", 1023) + "\n")
	var written atomic.Int64
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for written.Load() < total {
			n, err := w.Write(line)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	})
	a := e.mustPost(postOpt{})
	// The upstream handler writes until the proxy stops reading.
	last, since := int64(-1), time.Now()
	waitFor(t, "upstream to be held back", func() bool {
		if n := written.Load(); n != last {
			last, since = n, time.Now()
		}
		return last > 0 && time.Since(since) > 400*time.Millisecond
	})
	if last >= 32<<20 {
		t.Fatalf("upstream wrote %d MiB while the proxy could append nothing", last>>20)
	}
	// An abort is still served while it waits.
	limited.Store(false)
	if _, err := streams.Abort(e.ctx, e.pc, nsStreams, a.ID); err != nil {
		t.Fatal(err)
	}
	if sd := e.waitClosed(a.ID); sd.Closed.Reason != streams.ReasonAborted {
		t.Fatalf("closed %+v", sd.Closed)
	}
}

// A response cut short keeps what arrived of its last line.
func TestCutShortKeepsRemainder(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{})
	e.up.set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "1000")
		io.WriteString(w, "data: 1\n\ndata: par")
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	})
	a := e.mustPost(postOpt{})
	got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
	if got != "data: 1\n\ndata: par" || closed.Reason != streams.ReasonError || !strings.Contains(closed.Error, "ended early") {
		t.Fatalf("cut short: %q %+v", got, closed)
	}
}

// valueSize measures a string as canonical JSON, where a control
// character is six bytes: chunks are cut by that measure.
func TestEscapedChunks(t *testing.T) {
	t.Parallel()
	for name, doc := range map[string]map[string]any{"default": nil, "small": {"limits": map[string]any{"documentSize": 8192}}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, envOpt{nsDoc: doc, options: func(o *streams.Options) { o.MaxSegments = 32 }})
			body := strings.Repeat("\x1b", 16384) + "\n" + strings.Repeat("\"\\", 9000) + "\nplain\n" + strings.Repeat("\x01é", 5000)
			if name == "small" {
				body = strings.Repeat("\x1b", 3000) + "\n" + strings.Repeat("\"\\", 1000) + "\nplain\n" + strings.Repeat("\x01é", 500)
			}
			e.up.set(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				io.WriteString(w, body)
			})
			a := e.mustPost(postOpt{})
			got, closed, _ := e.readAll(e.reader(a), a.ID, streams.Position{})
			if got != body || closed.Reason != streams.ReasonComplete {
				t.Fatalf("read %d bytes of %d, %+v", len(got), len(body), closed)
			}
		})
	}
}

// MaxStreams holds for requests that arrive together.
func TestMaxStreamsConcurrent(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOpt{options: func(o *streams.Options) { o.MaxStreams = 2 }, core: func(o *clienttest.Options) {
		o.Wrap = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" && r.Header.Get("If-None-Match") != "" && strings.HasPrefix(r.URL.Path, "/r/streams/") {
					time.Sleep(100 * time.Millisecond) // every request is past the check before one stream exists
				}
				next.ServeHTTP(w, r)
			})
		}
	}})
	release := make(chan struct{})
	e.up.gated(sseParts[:1], release, sseParts[1:])
	bearer := e.callerGrant("user:ann")
	var wg sync.WaitGroup
	var made, busy, others atomic.Int64
	ids := make(chan string, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch status, a, _ := e.post(postOpt{bearer: bearer}); status {
			case 201:
				made.Add(1)
				ids <- a.ID
			case 503:
				busy.Add(1)
			default:
				others.Add(1)
			}
		}()
	}
	wg.Wait()
	if made.Load() != 2 || busy.Load() != 6 || others.Load() != 0 || e.p.Open() != 2 {
		t.Fatalf("%d streams started, %d refused, %d other answers, %d open; the most is 2", made.Load(), busy.Load(), others.Load(), e.p.Open())
	}
	// A request for a stream that exists takes no slot, and a slot is
	// free again when a stream ends.
	k := fmt.Sprint("k", time.Now().UnixNano())
	close(release)
	close(ids)
	for id := range ids {
		e.waitClosed(id)
	}
	waitFor(t, "the slots to free", func() bool { return e.p.Open() == 0 })
	e.up.gated(sseParts[:1], make(chan struct{}), nil)
	first := e.mustPost(postOpt{key: k})
	for i := 0; i < 4; i++ {
		if status, b, body := e.post(postOpt{key: k}); status != 200 || b.ID != first.ID {
			t.Fatalf("repeat %d: %d %s", i, status, body)
		}
	}
	second := e.mustPost(postOpt{})
	if status, _, _ := e.post(postOpt{}); status != 503 {
		t.Fatalf("a third stream: %d", status)
	}
	for _, id := range []string{first.ID, second.ID} {
		streams.Abort(e.ctx, e.pc, nsStreams, id)
		e.waitClosed(id)
	}
}
