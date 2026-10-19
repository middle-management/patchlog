package client_test

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// roundTrip adapts a function to http.RoundTripper.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// WithTransport wraps the transport a client already had (an earlier
// WithHTTPClient's included), on a copy, so the wrapper sees every answer,
// a write's X-Namespace-Revision among them; clients derived with With
// share it, and the client it was applied to keeps its own.
func TestWithTransport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	var inner atomic.Int32
	base := s.Client(t, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		inner.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})}))
	var mu sync.Mutex
	var seen []string
	c := base.With(client.WithTransport(func(next http.RoundTripper) http.RoundTripper {
		return roundTrip(func(r *http.Request) (*http.Response, error) {
			res, err := next.RoundTrip(r)
			if err == nil && r.Method != http.MethodGet {
				mu.Lock()
				seen = append(seen, res.Header.Get("X-Namespace-Revision"))
				mu.Unlock()
			}
			return res, err
		})
	}))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	w := must(c.With(client.WithBearer("")).CreateDoc(ctx, "main", "a", map[string]any{"n": 1}))
	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 2 || got[1] != w.NSID || w.NSID == "" {
		t.Fatalf("seen %q, the create's ns_id %q", got, w.NSID)
	}
	if inner.Load() < 2 {
		t.Fatalf("the earlier transport saw %d requests", inner.Load())
	}
	must(base.CreateDoc(ctx, "main", "b", map[string]any{"n": 2}))
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("the client WithTransport was applied to sees its copy's requests: %q", seen)
	}
}

// Bearer is the grant a client sends, "" for none.
func TestBearer(t *testing.T) {
	t.Parallel()
	c := must(client.New("https://cms.example", client.WithBearer("g1")))
	if c.Bearer() != "g1" || c.With(client.WithBearer("g2")).Bearer() != "g2" || c.With(client.WithAuthor("x")).Bearer() != "g1" {
		t.Fatal("Bearer")
	}
	if must(client.New("https://cms.example")).Bearer() != "" {
		t.Fatal("Bearer without a grant")
	}
}
