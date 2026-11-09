package index_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// V76-02 (v0.76): a covered branch at the index (§B.11.9 Branches, URLs;
// §A.4 Answers): it stays covered only while its root, at its head, still
// trusts the catalog through every key counted at the branch's baseAt,
// each unchanged; its at lists the root at its head, while visibility
// still reads the root and every base as of the baseAt.

// cover76Branch is newV75X with branches, matches-r7 cut from matches and
// reached: the index covers it.
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

// TestV076CoverBranchRootKeys (FSVC-5; §B.11.9 Branches: "A branch stays
// covered (Where) only while the namespace that trusts the catalog still
// trusts it, at its head, through every key item 1 counts, each unchanged
// (§C.4)"; changelog v0.76 "a rotated decider key uncovers a branch read
// through it"; scenario 105): once matches, after matches-r7 was cut,
// rotates catalog-01's pub under the same kid, replaces catalog-01 by
// catalog-02, or edits catalog-01's entry otherwise, the index's cookie
// for a partial reader of matches-r7 is 403 "no longer read filtered", and
// a grant that still verifies there gets no marker (since v0.77 a base
// naming a catalog gives an uncovered partial reader none, §A.4), not
// reads:matches-r7:g:…. A key added at the
// head leaves the branch covered. Before v0.76 the branch stayed covered,
// judged through catalog-01 as of baseAt.
func TestV076CoverBranchRootKeys(t *testing.T) {
	t.Parallel()
	entry := func(k clienttest.Key) map[string]any {
		e := k.Entry("read")
		e["requireAt"], e["maxTtl"] = "cat-season", "PT15M"
		e["rules"] = []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}
		return e
	}
	for _, c := range []struct {
		name    string
		edit    func(w *v75x, keys []any) []any
		covered bool
	}{
		{"pub rotated", func(w *v75x, keys []any) []any { keys[1] = entry(clienttest.NewKey("catalog-01")); return keys }, false},
		{"catalog-01 replaced by catalog-02", func(w *v75x, keys []any) []any { keys[1] = entry(clienttest.NewKey("catalog-02")); return keys }, false},
		{"maxTtl edited", func(w *v75x, keys []any) []any { keys[1].(map[string]any)["maxTtl"] = "PT14M"; return keys }, false},
		{"a key added", func(w *v75x, keys []any) []any { return append(keys, entry(clienttest.NewKey("catalog-03"))) }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := cover76Branch(t)
			fan := w.reader("user:fan", []any{"fans"}, "matches-r7")
			_, gs, _ := w.pointer("/matches-r7", fan)
			r := p37Do(t, w.x, "POST", "/edge-grants", fan, "", nil, "")
			if r.status != 200 {
				t.Fatalf("exchange: %d %v", r.status, r.body)
			}
			prefix := "/matches-r7/g/" + gs
			if got, _ := p37Follow(t, w.x, prefix, r.cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
				t.Fatalf("under the cookie, covered: %d %v", got.status, got.body)
			}
			w.patchKeys(func(keys []any) []any { return c.edit(w, keys) })
			got, _ := p37Follow(t, w.x, prefix, r.cookies, "")
			switch {
			case c.covered && (got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared"):
				t.Errorf("under the cookie, still covered: %d %v", got.status, got.body)
			case !c.covered && (got.status != 403 || !strings.Contains(got.body["message"].(string), "no longer read filtered")):
				t.Errorf("under the cookie, uncovered: %d %v", got.status, got.body)
			}
			if c.name != "maxTtl edited" {
				return
			}
			// The grant still verifies, but matches-r7's base names a
			// catalog: an uncovered partial reader has no marker there
			// (v0.77, §A.4; scenarios 113, 119): 403.
			if r := w.x.raw("/matches-r7", fan); r.status != 403 {
				t.Errorf("the grant once uncovered: %d %v", r.status, r.body)
			}
		})
	}
}

// TestV076CoverBranchAtLayout (FSVC-6; §B.11.9 URLs: a branch's bases "as
// of the at the branch reads them at, which its entry fixes (§7.6), one
// ns_id per namespace as in §A.4 Answers"; §A.4 Answers: "a namespace read
// at its head is listed at it, even where a branch also reads it as of
// the branch's at"; scenario 107): once matches has moved past
// matches-r7's baseAt (derby deleted, a new document written), a partial
// reader's answer in matches-r7 lists matches at its head, the index's
// checkpoint of it, being a catalog.trust member read there, and at is
// the combined checkpoint over what it lists; its hits are still judged
// as of baseAt, where derby was live. Before v0.76 matches was listed at
// baseAt.
func TestV076CoverBranchAtLayout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := cover76Branch(t)
	base := w.head("matches")
	h := must(w.admin.Head(ctx, "matches", "derby"))
	must(w.admin.Delete(ctx, "matches", "derby", h.ID))
	w.put("matches", "late", w.page("late", "cup"))
	w.x.caughtUp("matches")
	if w.x.ix.Checkpoint("matches") == base {
		t.Fatal("matches didn't move")
	}
	fan := w.reader("user:fan", []any{"fans"}, "matches-r7")
	_, _, at := w.pointer("/matches-r7", fan)
	b := w.x.search("/matches-r7", fan)
	ns := v75Namespaces(t, b)
	if ns["matches"] != w.x.ix.Checkpoint("matches") || ns["matches-r7"] != w.x.ix.Checkpoint("matches-r7") || ns["cat-season"] != w.head("cat-season") || len(ns) != 3 {
		t.Errorf("namespaces %v, want matches at its head %s", ns, w.x.ix.Checkpoint("matches"))
	}
	if at != grantcheck.CombinedAt(ns) || b["at"] != at {
		t.Errorf("at %s (answer %v), want the combined checkpoint of %v", at, b["at"], ns)
	}
	if got := strings.Join(resources(b), ","); got != "derby,shared" {
		t.Errorf("fan sees %s in the branch, want derby,shared as of baseAt", got)
	}
	// So in matches itself, at its head: derby gone.
	mfan := w.reader("user:fan", []any{"fans"})
	if got := strings.Join(resources(w.x.search("/matches", mfan)), ","); got != "shared" {
		t.Errorf("fan sees %s in matches", got)
	}
}
