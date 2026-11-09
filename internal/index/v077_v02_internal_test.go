package index

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// V77-02 (v0.77): unit tests of the index's own predicates and mappings.

// TestV077LacksKey408 (FSVC-11 / ENC-3; §A.4: "a 4xx other than 408 and
// 429" lacks keys; §A.1: "a schema or key fetch that fails transiently
// (transport error, 5xx, 408, 429) is retried"): a /keys 408 is for now,
// never lacking the key, and a schema revision answering 408 isn't final.
func TestV077LacksKey408(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, st := range []int{408, 429, 500, 503} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: st, Path: "/ns/x/keys"})
		if lacksKey(ctx, err) {
			t.Errorf("lacksKey of a /keys %d: true, want false (transient)", st)
		}
		if unavailable(&client.APIError{Status: st, Path: "/r/schemas/s/rev/x"}) {
			t.Errorf("a schema %d is final, want retried", st)
		}
	}
	for _, st := range []int{400, 401, 403, 404, 410} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: st, Path: "/ns/x/keys"})
		if !lacksKey(ctx, err) {
			t.Errorf("lacksKey of a /keys %d: false, want true", st)
		}
		if !unavailable(&client.APIError{Status: st, Path: "/r/schemas/s/rev/x"}) {
			t.Errorf("a schema %d isn't final", st)
		}
	}
}
