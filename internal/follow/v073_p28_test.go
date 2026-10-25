package follow_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
)

// cursorSkew gives the first long-poll answer of path the cursor "1", far
// more than an hour's worth of intervals behind any server's, as after a
// long pause or a clock change (§7.7), and counts the 400s that follow.
type cursorSkew struct {
	path    string
	skewed  atomic.Bool
	refused atomic.Int64
}

func (cs *cursorSkew) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cs.path || r.URL.Query().Get("live") != "long-poll" {
			h.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(&skewWriter{ResponseWriter: w, cs: cs}, r)
	})
}

type skewWriter struct {
	http.ResponseWriter
	cs    *cursorSkew
	wrote bool
}

func (w *skewWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if code == 400 {
			w.cs.refused.Add(1)
		}
		if w.Header().Get("X-Cursor") != "" && w.cs.skewed.CompareAndSwap(false, true) {
			w.Header().Set("X-Cursor", "1")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *skewWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}

// §7.7, §10 (RH-43): a long-poll follower whose cursor the server refuses,
// 400 bad_input for one too far behind, drops it and polls again, and goes
// on following.
func TestV073P28FollowerDropsRefusedCursor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := &cursorSkew{path: "/ns/main/log"}
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, Wrap: cs.wrap})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))

	cp := &follow.MemoryCheckpoints{}
	rec := &recorder{cp: cp}
	var reported atomic.Int64
	r := start(follow.New(c, "main", cp, rec, follow.WithBackoff(time.Millisecond, 10*time.Millisecond),
		follow.WithOnError(func(string, error) { reported.Add(1) })))
	waitFor(t, "catch-up", checkpointIs(t, cp, c, "main"))
	waitFor(t, "the skewed cursor's 400", func() bool { return cs.refused.Load() > 0 })

	must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	caught := checkpointIs(t, cp, c, "main")
	deadline := time.Now().Add(10 * time.Second)
	for !caught() {
		select {
		case err := <-r.done:
			t.Fatalf("the follower stopped after its cursor was refused: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the follower didn't deliver the write after its cursor was refused")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := cs.refused.Load(); n != 1 {
		t.Fatalf("%d refusals, want 1: the follower polls again without the cursor", n)
	}
	if n := reported.Load(); n != 0 {
		t.Fatalf("%d errors reported for a refused cursor", n)
	}
	r.stop(t)
}

// §7.3, §8.5, §10 (RH-35; review): a namespace stream whose since is the
// purge-ns entry sends the headers and ends, and a long-poll from there
// times out empty, so a follower restarted at that checkpoint, where an
// earlier run stopped with ErrPurged, would reconnect forever. Finding
// the checkpoint at the head, it asks /heads, 410 purged at any revision
// of a purged namespace, and ends with ErrPurged, delivering nothing more.
// From an earlier checkpoint it delivers the purge-ns entry and ends with
// ErrPurged, in either mode. A namespace that isn't purged, frozen or
// not, is followed as before.
func TestV073P28FollowerRestartedAtPurge(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"long-poll", "sse"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			testFollowerRestartedAtPurge(t, mode)
		})
	}
}

func testFollowerRestartedAtPurge(t *testing.T, mode string) {
	ctx := context.Background()
	var streams, polls atomic.Int64
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/ns/main/events":
				streams.Add(1)
			case r.URL.Path == "/ns/main/log" && r.URL.Query().Get("live") != "":
				polls.Add(1)
			}
			h.ServeHTTP(w, r)
		})
	}})
	c := s.Client(t, client.WithAuthor("admin"))
	opts := func(extra ...follow.Option) []follow.Option {
		o := append([]follow.Option{follow.WithBackoff(5*time.Millisecond, 20*time.Millisecond)}, extra...)
		if mode == "sse" {
			o = append(o, follow.WithSSE())
		}
		return o
	}
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	must(c.PatchConfig(ctx, "main", must(c.NSHead(ctx, "main")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	frozen := must(c.NSHead(ctx, "main")).ID

	// Frozen, not purged, at the head: followed, and the purge delivered
	// when it comes.
	cp := &follow.MemoryCheckpoints{}
	cp.Save(clienttest.Origin, "main", frozen)
	rec := &recorder{cp: cp}
	live := start(follow.New(c, "main", cp, rec, opts()...))
	waitFor(t, "following", func() bool { return streams.Load()+polls.Load() > 0 })
	select {
	case err := <-live.done:
		t.Fatalf("%s: a follower of a frozen namespace at its head stopped: %v", mode, err)
	case <-time.After(100 * time.Millisecond):
	}
	purged := must(c.PurgeNamespace(ctx, "main", frozen))
	select {
	case err := <-live.done:
		if !errors.Is(err, follow.ErrPurged) {
			t.Fatalf("%s: following at the purge: %v", mode, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: the follower didn't end at the purge", mode)
	}
	if k := rec.kinds("main"); len(k) != 1 || k[0] != "purge-ns" {
		t.Fatalf("%s: following: kinds %v", mode, k)
	}

	run := func(at string) (error, *recorder) {
		t.Helper()
		cp := &follow.MemoryCheckpoints{}
		cp.Save(clienttest.Origin, "main", at)
		rec := &recorder{cp: cp}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var states []follow.State
		err := follow.New(c, "main", cp, rec, opts(follow.WithOnState(func(st follow.State) { states = append(states, st) }))...).Run(rctx)
		if errors.Is(err, follow.ErrPurged) && (len(states) == 0 || !states[len(states)-1].Purged) {
			t.Fatalf("%s: from %s: no purged state: %+v", mode, at, states)
		}
		return err, rec
	}

	// From the checkpoint before the purge: the purge-ns entry.
	err, rec := run(frozen)
	if !errors.Is(err, follow.ErrPurged) {
		t.Fatalf("%s: from before the purge: %v", mode, err)
	}
	if k := rec.kinds("main"); len(k) != 1 || k[0] != "purge-ns" {
		t.Fatalf("%s: from before the purge: kinds %v", mode, k)
	}

	// Restarted at the purge: nothing more, and no stream or poll.
	streams.Store(0)
	polls.Store(0)
	err, rec = run(purged)
	if !errors.Is(err, follow.ErrPurged) {
		t.Fatalf("%s: restarted at the purge: %v after %d streams, %d polls", mode, err, streams.Load(), polls.Load())
	}
	if bs := rec.snapshot(); len(bs) != 0 {
		t.Fatalf("%s: restarted at the purge: delivered %+v", mode, bs)
	}
	if n := streams.Load() + polls.Load(); n != 0 {
		t.Fatalf("%s: restarted at the purge: %d streams or polls", mode, n)
	}
}
