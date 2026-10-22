package bundle

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// §7.2, §8.1 (GB-55): an import batch failing because the target moved
// since classification: a 412, or a 410 whose items are all gone with
// head, the tombstone a create now meets instead of a 412. A purged
// resource's 410 (no head) or a purged namespace's isn't.
func TestV073P15TargetMoved(t *testing.T) {
	batch := func(status int, items ...map[string]any) *client.APIError {
		arr := make([]any, len(items))
		for i, it := range items {
			arr[i] = it
		}
		return &client.APIError{Status: status, Code: "batch", Body: map[string]any{"code": "batch", "items": arr}}
	}
	gone := map[string]any{"index": 0.0, "status": 410.0, "code": "gone", "head": "1abc"}
	purged := map[string]any{"index": 1.0, "status": 410.0, "code": "gone"}
	for _, c := range []struct {
		name string
		ae   *client.APIError
		want bool
	}{
		{"412", batch(412, map[string]any{"index": 0.0, "status": 412.0, "code": "stale"}), true},
		{"create on a tombstone", batch(410, gone), true},
		{"purged resource", batch(410, gone, purged), false},
		{"purged namespace", &client.APIError{Status: 410, Code: "purged", Body: map[string]any{"code": "purged", "head": "1abc"}}, false},
	} {
		if got := targetMoved(c.ae); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
