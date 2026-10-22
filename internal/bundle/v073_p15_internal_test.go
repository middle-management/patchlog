package bundle

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
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

// §7.5 (GB-55): a batch failing at step 2.5 has the status of its first
// failing item in request order and lists every item that failed there,
// so a create meeting a tombstone (410 gone with head) before an append
// whose parent moved (412) is a 410 listing both: the target moved, as in
// the other order. An item that failed step 2.5 otherwise (428, or 410
// without head) isn't a move, whatever comes first; a 412 without items
// is the epoch raise's stale config change.
func TestV073P15TargetMovedMixed(t *testing.T) {
	batch := func(status int, items ...map[string]any) *client.APIError {
		arr := make([]any, len(items))
		for i, it := range items {
			arr[i] = it
		}
		return &client.APIError{Status: status, Code: "batch", Body: map[string]any{"code": "batch", "items": arr}}
	}
	gone := map[string]any{"index": 0.0, "status": 410.0, "code": "gone", "head": "1abc"}
	stale := map[string]any{"index": 1.0, "status": 412.0, "code": "stale", "head": "1def"}
	needs := map[string]any{"index": 2.0, "status": 428.0, "code": "precondition_required"}
	purged := map[string]any{"index": 2.0, "status": 410.0, "code": "gone"}
	for _, c := range []struct {
		name string
		ae   *client.APIError
		want bool
	}{
		{"410 first, then 412", batch(410, gone, stale), true},
		{"412 first, then 410", batch(412, stale, gone), true},
		{"412 with a 428 item", batch(412, stale, needs), false},
		{"410 with a 428 item", batch(410, gone, needs), false},
		{"412 with a 410 item without head", batch(412, stale, purged), false},
		{"config change 412", &client.APIError{Status: 412, Code: "stale", Body: map[string]any{"code": "stale", "config": "1abc"}}, true},
		{"428", batch(428, needs), false},
	} {
		if got := targetMoved(c.ae); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// §F.3, §G.4.4 (carry-over): the bundle's side is replayed onto the
// target, as a branch's is in a merge, so a copy it makes from a path the
// target changed since the common ancestor conflicts; a copy on the
// target's side from a path the bundle changed doesn't.
func TestV073P15ImportCopyFromConflicts(t *testing.T) {
	anc := map[string]any{"title": "T", "score": "0-0"}
	cp := func(from, path string) []client.Step {
		return []client.Step{client.PatchStep([]any{map[string]any{"op": "copy", "from": from, "path": path}})}
	}
	set := func(path string, v any) []client.Step {
		return []client.Step{client.PatchStep([]any{map[string]any{"op": "replace", "path": path, "value": v}})}
	}
	cs := sides(anc, true, cp("/title", "/subtitle"), set("/title", "U"), false)
	if len(cs) != 1 || cs[0].Kind != merge.ConflictOverlap || len(cs[0].Paths) != 1 || cs[0].Paths[0] != "/title" {
		t.Fatalf("incoming copy from a path the target changed: %+v", cs)
	}
	if cs := sides(anc, true, set("/score", "1-0"), cp("/score", "/half"), false); len(cs) != 0 {
		t.Fatalf("a target copy from a path the bundle changed: %+v", cs)
	}
}
