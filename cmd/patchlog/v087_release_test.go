package main

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/release"
)

// TOOLS §F.9 (v0.87): `patchlog merge release plan --publish` plans step
// 3, which approve and apply take from the stored plan; --publish
// anywhere else is refused.
func TestV087ReleasePublishFlag(t *testing.T) {
	if v077Child() {
		return
	}
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	for _, ns := range []string{"matches", "releases"} {
		if _, err := c.CreateNamespace(ctx, ns, map[string]any{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0", "published": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDoc(ctx, "r7", "final", map[string]any{"score": "2-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Write(ctx, c, release.Ref{NS: "releases", Name: "rel"}, "", &release.Doc{Name: "rel", Branches: map[string]release.Branch{"matches": {NS: "r7"}}}); err != nil {
		t.Fatal(err)
	}
	tool := func(args ...string) (string, bool) {
		return v077Tool(t, "TestV087ReleasePublishFlag", append(append([]string{"release"}, args...), "-api", s.URL, "-author", "alice", "/r/releases/rel")...)
	}
	out, ok := tool("plan", "--publish", "/published", "--publish-value", `"yes"`)
	if !ok || !strings.Contains(out, `step 3 sets /published to "yes"`) || !strings.Contains(out, "step 3 publish") || !strings.Contains(out, "final") {
		t.Fatalf("plan: ok %v\n%s", ok, out)
	}
	if out, ok := tool("approve", "--publish", "/published"); ok || !strings.Contains(out, "--publish is planned") {
		t.Fatalf("approve --publish: ok %v\n%s", ok, out)
	}
	if out, ok := tool("approve"); !ok {
		t.Fatalf("approve: %s", out)
	}
	if out, ok := tool("apply"); !ok || !strings.Contains(out, "done") {
		t.Fatalf("apply: ok %v\n%s", ok, out)
	}
	_, d, err := c.Load(ctx, "matches", "final")
	if err != nil || d.Value.(map[string]any)["published"] != "yes" {
		t.Fatalf("matches/final %v %v", d, err)
	}
}
