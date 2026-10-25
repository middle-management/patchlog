package main

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// cursorSkew gives the first long-poll answer of path the cursor "1", far
// more than an hour's worth of intervals behind any server's (§7.7), and
// counts the 400s that follow.
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

// §7.7 (RH-43): a long-poll follower of the fan-out measurement whose
// cursor the server refuses, 400 bad_input for one too far behind, drops
// it and polls again at once, rather than counting an error and asking
// again with the same cursor.
func TestV073P28WaitEntriesDropsRefusedCursor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := &cursorSkew{path: "/ns/live/log"}
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond, Wrap: cs.wrap})
	c := s.Client(t, client.WithAuthor("admin"))
	if _, err := c.CreateNamespace(ctx, "live", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	head, err := c.NSHead(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	var errs atomic.Int64
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- waitEntries(wctx, c, "live", head.ID, &errs, t.Logf) }()
	deadline := time.Now().Add(5 * time.Second)
	for cs.refused.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no request with the skewed cursor")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // polling again, without the cursor
	if _, err := c.CreateDoc(ctx, "live", "doc", map[string]any{"n": 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if !got {
			t.Fatal("no entries")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the write didn't reach the follower")
	}
	if n, e := cs.refused.Load(), errs.Load(); n != 1 || e != 0 {
		t.Fatalf("%d refusals and %d errors, want 1 and 0", n, e)
	}
}
