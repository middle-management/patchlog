package janitor

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/merge"
)

// §F.6 superseded, §7.4 (v0.63): the successor may be a branch of the
// branch's base or of a namespace further up its base chain, as after
// retargeting a stacked branch onto its base's base (§F.4); the janitor
// looks it up in that namespace's branches. The core refuses to name such a
// successor until §7.4's v0.63 rule is in (RH-54), so this drives the check
// on the branch's document as it would then read.
func TestV073SuccessorUpTheBaseChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	authors := map[string]any{"authors": []any{map[string]any{"sub": "alice", "kid": "dev"}}}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "merge": authors}))
	must(c.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
	must(c.CreateNamespace(ctx, "other", map[string]any{"read": "public"}))
	for _, br := range [][2]string{{"matches", "b1"}, {"b1", "r7"}, {"other", "o1"}} {
		must(c.CreateBranch(ctx, br[0], client.BranchRequest{Name: br[1]}))
	}
	h, err := c.Head(ctx, "r7", "derby")
	if err != nil {
		t.Fatal(err)
	}
	must(c.Append(ctx, "r7", "derby", h.ID, []any{map[string]any{"op": "replace", "path": "/score", "value": "1-0"}}))
	// r7 replayed into r7-b, a branch of matches, b1's base.
	must(merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Onto: "matches"}))

	check := func(succ string) (bool, string) {
		t.Helper()
		j := New(c, Options{})
		head, err := c.NSHead(ctx, "r7")
		if err != nil {
			t.Fatal(err)
		}
		doc, err := c.NSDoc(ctx, "r7", head.ID)
		if err != nil {
			t.Fatal(err)
		}
		log, err := c.NSLog(ctx, "r7", head.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		v := maps.Clone(doc.Value)
		v["frozen"], v["successor"] = true, succ
		b := &branch{j: j, base: "b1", ns: "r7", doc: v, log: log,
			docs: map[string]nsAt{"r7": {head.ID, v}}, keyCache: map[string]map[string]nsKey{}}
		ok, why, err := b.verifySuperseded(ctx, succ, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return ok, why
	}
	if ok, why := check("r7-b"); !ok {
		t.Fatalf("a successor based on the base's base: %s", why)
	}
	if ok, why := check("o1"); ok || !strings.Contains(why, "successor o1 is a branch of other, not of a namespace in the branch's base chain (b1, matches") {
		t.Fatalf("a successor based elsewhere: %v %s", ok, why)
	}
}
