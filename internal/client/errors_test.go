package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// A 429's wait is its body's retryAfter, in decimal seconds, where it has
// one, else its Retry-After, which is whole seconds rounded up (§6.6).
func TestRetryAfterBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		body string
		want time.Duration
	}{
		{`{"code":"rate","limit":"allowance","retryAfter":0.004}`, 4 * time.Millisecond},
		{`{"code":"rate","limit":"ratePerPrincipal","retryAfter":2.5}`, 2500 * time.Millisecond},
		{`{"code":"rate","limit":"ratePerPrincipal"}`, time.Second},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(tc.body))
		}))
		t.Cleanup(s.Close)
		c := must(client.New(s.URL))
		_, err := c.Head(context.Background(), "main", "a")
		if ae, ok := client.AsAPIError(err); !ok || !client.IsRateLimited(err) || ae.RetryAfter != tc.want {
			t.Fatalf("%s: %v, want a wait of %v", tc.body, err, tc.want)
		}
	}
}

// v0.55 §6.6, §12: a limit refusal names the limit and the sizes, and a
// batch's carries them in the refused item's report.
func TestLimitRefusal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "l", map[string]any{"limits": map[string]any{"opsPerSet": 2, "retryWindow": "PT5M"}}))
	_, err := c.Create(ctx, "l", "a", ops(op("add", "", map[string]any{}), op("add", "/a", 1), op("add", "/b", 2)))
	ae, ok := client.AsAPIError(err)
	if !ok || !client.IsLimit(err) {
		t.Fatalf("create: %v", err)
	}
	if k, m, x, sized, ok := ae.Limit(); !ok || !sized || k != "opsPerSet" || m != 3 || x != 2 {
		t.Fatalf("limit %q %d %d %v %v", k, m, x, sized, ok)
	}
	_, err = c.Batch(ctx, "l", client.BatchRequest{Items: []client.BatchItem{{Resource: "b", IfNoneMatch: true,
		Steps: []client.Step{{Patches: ops(op("add", "", map[string]any{}), op("add", "/a", 1), op("add", "/b", 2))}}}}}, false)
	ae, _ = client.AsAPIError(err)
	if k, m, x, sized, ok := ae.Limit(); !ok || !sized || k != "opsPerSet" || m != 3 || x != 2 || ae.Code != "batch" {
		t.Fatalf("batch limit %q %d %d %v %v: %v", k, m, x, sized, ok, err)
	}
	// A duration carries the key alone.
	_, err = c.CreateNamespace(ctx, "d", map[string]any{"limits": map[string]any{"retryWindow": "P400D"}})
	ae, _ = client.AsAPIError(err)
	if k, _, _, sized, ok := ae.Limit(); !ok || sized || k != "retryWindow" {
		t.Fatalf("duration limit %q %v %v: %v", k, sized, ok, err)
	}
	if _, err := c.Head(ctx, "nope", "x"); client.IsLimit(err) {
		t.Fatalf("not a limit: %v", err)
	}
}
