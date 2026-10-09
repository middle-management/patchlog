package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
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
