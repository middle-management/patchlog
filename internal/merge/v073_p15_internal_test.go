package merge

import (
	"testing"
)

// §7.2, §8.1 (GB-55): a write's 410 gone with head, the tombstone, is a
// resource that moved since it was read, as a 412 is; a purged resource's
// 410 (no head) and a purged namespace's (code purged) aren't.
func TestV073P15DeletedSince(t *testing.T) {
	if !itemMoved(map[string]any{"status": 410.0, "code": "gone", "head": "1abc"}) || !itemMoved(map[string]any{"status": 412.0, "code": "stale"}) {
		t.Error("a 412 item, or a 410 gone one with head, moved")
	}
	if itemMoved(map[string]any{"status": 410.0, "code": "gone"}) || itemMoved(map[string]any{"status": 428.0, "code": "precondition_required"}) {
		t.Error("a purged resource's item, or a 428 one, didn't move")
	}
}
