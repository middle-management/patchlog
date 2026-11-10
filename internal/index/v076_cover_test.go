package index_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// Branch fixtures. Since v0.78 no branch is covered (§B.11.9 Where); the
// v0.76 tests of covered branches are gone with it.

// cover76Branch is newV75X with branches, matches-r7 cut from matches and
// reached.
func cover76Branch(t *testing.T) *v75x {
	t.Helper()
	w := newV75X(t, true)
	must(w.admin.CreateBranch(context.Background(), "matches", client.BranchRequest{Name: "matches-r7"}))
	w.x.caughtUp("matches-r7")
	return w
}

// patchKeys replaces matches' keys with what edit makes of them, and waits
// for the index to apply it.
func (w *v75x) patchKeys(edit func(keys []any) []any) {
	w.t.Helper()
	ctx := context.Background()
	doc := must(w.admin.NSDoc(ctx, "matches", w.head("matches"))).Value
	keys := edit(doc["keys"].([]any))
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": keys}}))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
}
