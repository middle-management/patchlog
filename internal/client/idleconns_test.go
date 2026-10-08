package client_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// TestIdleConns: a client WithIdleConns(n) sending bursts of n requests
// reuses its connections from one burst to the next; on
// http.DefaultTransport all but 2 close after each burst and the next one
// dials again. Not parallel: other tests' requests share
// http.DefaultTransport's idle connections.
func TestIdleConns(t *testing.T) {
	const n, bursts = 8, 3
	var (
		dials   atomic.Int32
		arrived = make(chan struct{})
		mu      sync.Mutex
		release = make(chan struct{})
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Each burst is answered once all of it is in flight, so it takes
		// n connections.
		mu.Lock()
		rel := release
		mu.Unlock()
		arrived <- struct{}{}
		<-rel
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"origin":"https://cms.example","auth":"disabled"}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			dials.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	for _, tc := range []struct {
		name string
		opts []client.Option
		want int32
	}{
		{"http.DefaultTransport", nil, n + (bursts-1)*(n-2)},
		{"WithIdleConns", []client.Option{client.WithIdleConns(n)}, n},
	} {
		dials.Store(0)
		c := must(client.New(srv.URL, tc.opts...))
		for range bursts {
			var wg sync.WaitGroup
			for range n {
				wg.Go(func() {
					if _, err := c.AuthDisabled(context.Background()); err != nil {
						t.Error(err)
					}
				})
			}
			for range n {
				select {
				case <-arrived:
				case <-time.After(10 * time.Second):
					t.Fatalf("%s: burst never all in flight", tc.name)
				}
			}
			mu.Lock()
			close(release)
			release = make(chan struct{})
			mu.Unlock()
			wg.Wait()
		}
		if got := dials.Load(); got != tc.want {
			t.Errorf("%s: %d connections for %d bursts of %d requests, want %d", tc.name, got, bursts, n, tc.want)
		}
	}
}
