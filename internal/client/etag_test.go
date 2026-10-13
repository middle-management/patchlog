package client

import (
	"net/http"
	"testing"
)

// A proxy that compresses responses makes the server's strong ETags weak,
// around the same id: the client reads the id either way.
func TestETagWeak(t *testing.T) {
	for h, want := range map[string]string{`"1abc"`: "1abc", `W/"1abc"`: "1abc", "": ""} {
		r := &response{header: http.Header{}}
		if h != "" {
			r.header.Set("ETag", h)
		}
		if got := r.etag(); got != want {
			t.Errorf("ETag %s: %q, want %q", h, got, want)
		}
	}
}
