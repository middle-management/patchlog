package follow_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
)

// A /keys 408 is transient, retried like a 429 or 5xx, so it never leaves
// the keys lacking (§A.4 "a 4xx other than 408 and 429", ENC-3).
func TestV077LacksKey408(t *testing.T) {
	ctx := context.Background()
	for _, s := range []int{408, 429, 500, 503} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: s, Path: "/ns/x/keys"})
		if follow.LacksKey(ctx, err) {
			t.Errorf("/keys %d lacks the key", s)
		}
	}
	for _, s := range []int{400, 403, 404} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: s, Path: "/ns/x/keys"})
		if !follow.LacksKey(ctx, err) {
			t.Errorf("/keys %d doesn't lack the key", s)
		}
	}
}
