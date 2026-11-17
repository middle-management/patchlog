package dav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// OTHER-2 (§H.4 "The base"): a failed read is no answer, a timeout, or the
// core's 408, 429 or 5xx, also wrapped by a key fetch; a refusal and no
// keys here are not. upstream answers 408, 429 and a timeout with 503 and
// Retry-After, 5xx with 502.
func TestV077FailedRead(t *testing.T) {
	t.Parallel()
	api := func(status int) error { return &client.APIError{Status: status, Code: "x"} }
	for _, c := range []struct {
		err      error
		failed   bool
		upstream int
	}{
		{api(408), true, http.StatusBadGateway},
		{api(429), true, http.StatusServiceUnavailable},
		{api(500), true, http.StatusBadGateway},
		{api(503), true, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: docs epoch 1: %w", client.ErrKeyFetch, api(503)), true, http.StatusServiceUnavailable},
		{fmt.Errorf("%w: docs epoch 1: %w", client.ErrKeyFetch, api(408)), true, http.StatusBadGateway},
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
		} else if de.status == http.StatusServiceUnavailable && de.header.Get("Retry-After") == "" {
			// §H.4 Answers: "503 with Retry-After".
			t.Errorf("upstream(%v) = 503 without Retry-After", c.err)
		}
	}
}

// §H.4 "Answers" (v0.85) for a tree or catalog service that gave no
// response: 503 with Retry-After where no answer came in time, 502 where
// there is no connection; neither says the service's address.
func TestV085Unreached(t *testing.T) {
	t.Parallel()
	refused := &url.Error{Op: "Get", URL: "http://tree.internal:8082/cat/roots", Err: errors.New("dial tcp 10.0.0.7:8082: connect: connection refused")}
	slow := &url.Error{Op: "Get", URL: "http://tree.internal:8082/cat/roots", Err: context.DeadlineExceeded}
	for _, c := range []struct {
		err  error
		want int
	}{{refused, http.StatusBadGateway}, {slow, http.StatusServiceUnavailable}, {context.DeadlineExceeded, http.StatusServiceUnavailable}} {
		de := unreached("catalog cat's tree service", c.err)
		if de.status != c.want || (c.want == http.StatusServiceUnavailable) != (de.header.Get("Retry-After") != "") {
			t.Errorf("unreached(%v) = %d %v, want %d", c.err, de.status, de.header, c.want)
		}
		if strings.Contains(de.msg, "tree.internal") || strings.Contains(de.msg, "10.0.0.7") || de.cause == nil {
			t.Errorf("unreached(%v): %q, cause %v", c.err, de.msg, de.cause)
		}
	}
}
