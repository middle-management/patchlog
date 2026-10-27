package merge

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// §7.2, §8.1 (GB-55): a write's 410 gone with head, the tombstone, is a
// resource that moved since it was read, as a 412 is; a purged resource's
// 410 (no head) and a purged namespace's (code purged) aren't.
func TestV073P15DeletedSince(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&client.APIError{Status: 410, Code: "gone", Body: map[string]any{"code": "gone", "head": "1abc"}}, true},
		{&client.APIError{Status: 410, Code: "gone", Body: map[string]any{"code": "gone"}}, false},
		{&client.APIError{Status: 410, Code: "purged", Body: map[string]any{"code": "purged", "head": "1abc"}}, false},
		{&client.APIError{Status: 412, Code: "stale", Body: map[string]any{"code": "stale", "head": "1abc"}}, false},
	} {
		if got := deletedSince(c.err); got != c.want {
			t.Errorf("%v: %v, want %v", c.err, got, c.want)
		}
	}
	if !itemMoved(map[string]any{"status": 410.0, "code": "gone", "head": "1abc"}) || !itemMoved(map[string]any{"status": 412.0, "code": "stale"}) {
		t.Error("a 412 item, or a 410 gone one with head, moved")
	}
	if itemMoved(map[string]any{"status": 410.0, "code": "gone"}) || itemMoved(map[string]any{"status": 428.0, "code": "precondition_required"}) {
		t.Error("a purged resource's item, or a 428 one, didn't move")
	}
}
