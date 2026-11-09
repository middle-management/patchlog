package index

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// TestV075XrevFlightCancel (cross-package review of v0.75): the index's
// catalog and live-name reads of a covered namespace's members are shared
// (filtered.go liveAt, catalogAt, Index.shared). A reader that joins the
// read must not fail because the request that started it went away: its
// own context is fine.
func TestV075XrevFlightCancel(t *testing.T) {
	var hits atomic.Int32
	started := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/heads") {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		started <- struct{}{}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"heads":[]}`))
	}))
	defer srv.Close()
	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
	ix.c = c
	ix.fs.init()
	id := ids.Of([]byte("x")).String()

	first, cancel := context.WithCancel(context.Background())
	errA := make(chan error, 1)
	go func() {
		_, err := ix.liveAt(first, "cat", id)
		errA <- err
	}()
	<-started
	errB := make(chan error, 1)
	go func() {
		_, err := ix.liveAt(context.Background(), "cat", id)
		errB <- err
	}()
	time.Sleep(100 * time.Millisecond) // B joins A's flight
	cancel()
	<-errA
	if err := <-errB; err != nil {
		t.Errorf("a reader that joined another's read of the heads failed when that one went away: %v (%d upstream reads)", err, hits.Load())
	}
}
