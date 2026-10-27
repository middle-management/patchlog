package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
)

// §F.9, §7.4, §8.5 (RH-19): once a release's target is purged too, after
// its purged branch (dependents first), GET /ns/{target}/branches is 410;
// the planner reports the listed branch as a purged conflict, as it did
// when /branches listed it, instead of failing.
func TestV073ReleaseTargetPurged(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "merge": devAuthors}))
	must(c.Create(ctx, "matches", "derby", client.GenesisPatches(map[string]any{"score": "0-0"})))
	must(c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r1"}))
	must(c.CreateNamespace(ctx, "releases", map[string]any{"read": "public"}))
	ref := release.Ref{NS: "releases", Name: "r1"}
	must(release.Write(ctx, c, ref, "", &release.Doc{Name: "r1", Branches: map[string]release.Branch{"matches": {NS: "matches-r1"}}}))
	for _, ns := range []string{"matches-r1", "matches"} {
		must(c.PatchConfig(ctx, ns, must(c.NSHead(ctx, ns)).Config, []any{op("add", "/frozen", true)}))
		must(c.PurgeNamespace(ctx, ns, must(c.NSHead(ctx, ns)).ID))
	}
	if _, err := c.Branches(ctx, "matches"); !client.IsPurged(err) {
		t.Fatalf("branches of a purged namespace: %v, want 410 purged", err)
	}
	rp, err := merge.PlanRelease(ctx, c, merge.ReleaseOptions{Release: ref.Live(), Who: "alice"})
	if err != nil {
		t.Fatalf("PlanRelease with a purged target: %v", err)
	}
	purged := false
	for _, x := range rp.Conflicts {
		purged = purged || x.Kind == merge.RCPurged && x.NS == "matches-r1"
	}
	if !purged {
		t.Fatalf("conflicts %+v, want matches-r1 purged", rp.Conflicts)
	}
}
