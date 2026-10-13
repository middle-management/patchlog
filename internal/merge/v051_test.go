package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/seal"
)

// A listed branch that is purged is a "purged" conflict (§F.9 Merging),
// sealed or not: a sealed branch's document and log are 410 purged once
// it is purged (§8.5), and that 410 is how the planner learns of it,
// where at rest only the branch's document still reads.
func TestReleaseSealedPurged(t *testing.T) {
	t.Parallel()
	for _, level := range []string{"at-rest", "sealed"} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			ks, err := keystore.New(keystore.Generate())
			if err != nil {
				t.Fatal(err)
			}
			s := clienttest.New(t, clienttest.Options{KeyStore: ks})
			c := s.Client(t, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
			must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "merge": devAuthors, "encryption": map[string]any{"level": level}}))
			must(c.Create(ctx, "matches", "derby", append(client.GenesisPatches(map[string]any{"score": "0-0"}), op("add", "/$nonce", seal.NewNonce()))))
			must(c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r1"}))
			h := must(c.Head(ctx, "matches-r1", "derby"))
			must(c.Append(ctx, "matches-r1", "derby", h.ID, []any{op("replace", "/score", "1-0"), op("replace", "/$nonce", seal.NewNonce())}))
			must(c.CreateNamespace(ctx, "releases", map[string]any{"read": "public"}))
			ref := release.Ref{NS: "releases", Name: "r1"}
			must(release.Write(ctx, c, ref, "", &release.Doc{Name: "r1", Branches: map[string]release.Branch{"matches": {NS: "matches-r1"}}}))

			must(c.PatchConfig(ctx, "matches-r1", must(c.NSHead(ctx, "matches-r1")).Config, []any{op("add", "/frozen", true)}))
			must(c.PurgeNamespace(ctx, "matches-r1", must(c.NSHead(ctx, "matches-r1")).ID))
			if _, err := c.NSDoc(ctx, "matches-r1", must(c.NSHead(ctx, "matches-r1")).ID); client.IsPurged(err) != (level == "sealed") {
				t.Fatalf("the purged branch's document: %v", err)
			}

			rp, err := merge.PlanRelease(ctx, c, merge.ReleaseOptions{Release: ref.Live(), Who: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			// At rest, the purge's freeze is reported too.
			purged := false
			for _, x := range rp.Conflicts {
				purged = purged || x.Kind == merge.RCPurged && x.NS == "matches-r1"
			}
			if !purged {
				t.Fatalf("conflicts %+v, want matches-r1 purged", rp.Conflicts)
			}
			if level != "sealed" {
				return
			}
			// Merges and rebases of it have no log to classify.
			if _, err := merge.NewPlan(ctx, c, "matches", "matches-r1", merge.Options{}); !client.IsPurged(err) {
				t.Fatalf("plan of the purged sealed branch: %v", err)
			}
			if _, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "matches-r1", New: "matches-r2"}); !client.IsPurged(err) {
				t.Fatalf("rebase of the purged sealed branch: %v", err)
			}
		})
	}
}
