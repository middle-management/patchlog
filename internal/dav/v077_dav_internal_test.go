package dav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// OTHER-2 (§H.4 "The base"): a failed read is no answer, a timeout, or the
// core's 408, 429 or 5xx, also wrapped by a key fetch; a refusal and no
// keys here are not. upstream answers 408 and 429 with 503, 5xx with 502.
func TestV077FailedRead(t *testing.T) {
	t.Parallel()
	api := func(status int) error { return &client.APIError{Status: status, Code: "x"} }
	for _, c := range []struct {
		err      error
		failed   bool
		upstream int
	}{
		{api(408), true, http.StatusServiceUnavailable},
		{api(429), true, http.StatusServiceUnavailable},
		{api(500), true, http.StatusBadGateway},
		{api(503), true, http.StatusBadGateway},
		{fmt.Errorf("%w: docs epoch 1: %w", client.ErrKeyFetch, api(503)), true, http.StatusBadGateway},
		{fmt.Errorf("%w: docs epoch 1: %w", client.ErrKeyFetch, api(408)), true, http.StatusServiceUnavailable},
		{&url.Error{Op: "Get", URL: "http://core", Err: errors.New("connection refused")}, true, http.StatusBadGateway},
		{context.DeadlineExceeded, true, http.StatusServiceUnavailable},
		{api(403), false, http.StatusForbidden},
		{api(404), false, http.StatusNotFound},
		{fmt.Errorf("%w: docs epoch 1: %w", client.ErrKeyFetch, api(403)), false, http.StatusForbidden},
		{client.ErrNoKeys, false, http.StatusNotFound},
		{nil, false, 0},
	} {
		if got := failedRead(c.err); got != c.failed {
			t.Errorf("failedRead(%v) = %v", c.err, got)
		}
		if c.err == nil {
			continue
		}
		var de *davError
		if !errors.As(upstream(c.err), &de) || de.status != c.upstream {
			t.Errorf("upstream(%v) = %v, want %d", c.err, upstream(c.err), c.upstream)
		}
	}
}
