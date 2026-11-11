package index

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// OnTrustRepair sets a hook called before each read of a purged
// namespace's document whose catalog.trust the index lost (repairTrustOf),
// and the first pause between two reads. Set before Run.
func (ix *Index) OnTrustRepair(f func(ctx context.Context, ns string), pause time.Duration) {
	ix.testTrustRepair, ix.testTrustRepairPause = f, pause
}

// TestV082TrustLostServedOnly (§B.11.9 Where, "as their documents alone
// decide"): the namespaces whose catalog.trust the index reads again
// (trustLost) are those it serves, applied the purge of and holds none
// of, and no other: not one it served once and no longer does, purged or
// not, whose trust dropUnfollowedTrust forgets or never held, not one that
// has a trust, not a live one, not one purged without a checkpoint. Nor is
// one recorded for a namespace that is none of them by the time its
// document is read (recordTrustLost). With Branches every namespace the
// index holds a checkpoint of is served (known).
func TestV082TrustLostServedOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		name     string
		branches bool
		want     []string
	}{
		{"roots", false, []string{"lost"}},
		{"branches", true, []string{"lost", "unserved"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
			ix.origin = "o"
			for _, q := range []string{
				`INSERT INTO checkpoints (origin, ns, ns_id) VALUES ('o', 'lost', '1x'), ('o', 'unserved', '1x'), ('o', 'held', '1x'), ('o', 'live', '1x'), ('other', 'elsewhere', '1x')`,
				`INSERT INTO ns_state (ns, purged) VALUES ('lost', 1), ('unserved', 1), ('held', 1), ('live', 0), ('nocp', 1), ('elsewhere', 1)`,
				`INSERT INTO catalog_trust (ns, trust) VALUES ('held', '["a"]')`,
			} {
				if _, err := ix.db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			ix.roots = map[string]bool{"lost": true, "held": true, "live": true, "nocp": true, "elsewhere": true}
			ix.cur, ix.purged, ix.stopped = map[string]string{}, map[string]bool{}, map[string]string{}
			ix.opt.Branches = c.branches
			if err := ix.loadState(ctx); err != nil {
				t.Fatal(err)
			}
			lost, err := ix.trustLost(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Sorted(maps.Keys(lost)); !slices.Equal(got, c.want) {
				t.Errorf("the index reads again the trust of %v, want %v", got, c.want)
			}
			doc := map[string]any{"catalog": map[string]any{"trust": []any{"m"}}}
			for _, ns := range []string{"unserved", "held", "live", "nocp", "elsewhere", "lost"} {
				at := "1x"
				if ns == "lost" {
					at = "2x" // not the checkpoint it holds
				}
				want := ns == "unserved" && c.branches
				if ok, err := ix.recordTrustLost(ctx, ns, at, doc); err != nil || ok != want {
					t.Errorf("recording a trust for %s at %s: %v, %v; want %v", ns, at, ok, err, want)
				}
			}
			if ok, err := ix.recordTrustLost(ctx, "lost", "1x", doc); err != nil || !ok {
				t.Errorf("recording the trust lost: %v, %v", ok, err)
			}
			if ok, err := ix.recordTrustLost(ctx, "lost", "1x", map[string]any{}); err != nil || ok {
				t.Errorf("recording it over the one recorded: %v, %v", ok, err)
			}
			if trust, ok, err := ix.lastTrust(ctx, "lost"); err != nil || !ok || len(trust) != 1 || trust[0] != "m" {
				t.Errorf("the trust recorded: %v, %v, %v", trust, ok, err)
			}
			var held string
			if err := ix.db.QueryRow(`SELECT trust FROM catalog_trust WHERE ns = 'held'`).Scan(&held); err != nil || held != `["a"]` {
				t.Errorf("the trust held: %q, %v", held, err)
			}
		})
	}
}
