package follow_test

import (
	"context"
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
