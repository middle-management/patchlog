package index

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// SERVICES-5 (§E.2.6, §A.4): an epoch key is lacking for good only on a
// positive list (a 4xx from /keys but 429, no key, none the service can
// unwrap or will take); anything else, the reader's request ending while
// the key is read among them, is for now (503 behind), and so is any
// failure once the request is done. The single-namespace query and
// /_refs both judge by it.
func TestV074V03LacksKey(t *testing.T) {
	t.Parallel()
	for _, x := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("%w: sec#1", client.ErrNoKeys), true},
		{&client.APIError{Status: 403}, true},
		{&client.APIError{Status: 404}, true},
		{&client.APIError{Status: 400}, true},
		{fmt.Errorf("derived: unwrapping sec#1: %w", seal.ErrDecrypt), true},
		{fmt.Errorf("%w: sec#1 from x", client.ErrUntrustedKey), true},
		{&client.APIError{Status: 429}, false},
		{&client.APIError{Status: 503}, false},
		{context.Canceled, false},
		{context.DeadlineExceeded, false},
		{json.Unmarshal([]byte("{"), new(any)), false},
		{errors.New("derived: sec#1 is wrapped to the grant's enc and no recipient key is configured"), false},
		{nil, false},
	} {
		if got := lacksKey(context.Background(), x.err); got != x.want {
			t.Errorf("lacksKey(%v) = %v, want %v", x.err, got, x.want)
		}
	}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if lacksKey(done, client.ErrNoKeys) {
		t.Error("lacksKey after the request ended = true, want false (for now)")
	}
}
