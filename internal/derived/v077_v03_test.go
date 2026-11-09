package derived_test

import (
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
)

// A /keys 408 is retried (§A.4: "a transport error, 5xx, 408, 429"), not
// a skip for want of keys (ENC-3).
func TestV077Retryable408(t *testing.T) {
	ae := &client.APIError{Status: 408, Path: "/ns/x/keys"}
	if !derived.Retryable(ae) || !derived.Retryable(fmt.Errorf("%w: %w", client.ErrKeyFetch, ae)) {
		t.Error("408 is not Retryable")
	}
	if derived.Retryable(&client.APIError{Status: 403, Path: "/ns/x/keys"}) {
		t.Error("403 is Retryable")
	}
}
