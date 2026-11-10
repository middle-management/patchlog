package index

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

// TestV0261UnfollowedTrustDropped (I-L2; §B.11.9 Where, "as their
// documents alone decide"): opening the index, as Open does (initSchema),
// forgets the catalog.trust of a namespace it served (a checkpoint of it)
// and no longer serves, whose config entries it no longer applies: once
// that namespace is purged, fsTrust would read the stale trust. It keeps
// the trust of a namespace it serves, of one whose purge it applied
// (ns_state), of a member it follows (member_checkpoints), and of a
// purged member it forgot (no checkpoint left, forgetMember); with or
// without a rebuild, which keeps catalog_trust; and with Branches, where
// every namespace it holds a checkpoint of is served (known).
func TestV0261UnfollowedTrustDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		name              string
		rebuild, branches bool
		want              []string
	}{
		{"open", false, false, []string{"forgotten", "member", "purged", "served"}},
		{"rebuild", true, false, []string{"forgotten", "member", "purged", "served"}},
		{"branches", false, true, []string{"forgotten", "gone", "member", "purged", "served"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
			for _, q := range []string{
				`INSERT INTO catalog_trust (ns, trust) VALUES ('served', '["a"]'), ('gone', '["a"]'), ('purged', '["a"]'), ('member', '["a"]'), ('forgotten', '["a"]')`,
				`INSERT INTO checkpoints (origin, ns, ns_id) VALUES ('o', 'served', '1x'), ('o', 'gone', '1x'), ('o', 'purged', '1x'), ('o', 'member', '1x')`,
				`INSERT INTO ns_state (ns, purged) VALUES ('purged', 1)`,
				`INSERT INTO member_checkpoints (origin, ns, ns_id) VALUES ('o', 'member', '1x')`,
			} {
				if _, err := ix.db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			ix.roots = map[string]bool{"served": true}
			ix.opt.Rebuild, ix.opt.Branches = c.rebuild, c.branches
			if err := ix.initSchema(ctx); err != nil {
				t.Fatal(err)
			}
			var got []string
			rows, err := ix.db.Query(`SELECT ns FROM catalog_trust ORDER BY ns`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var ns string
				if err := rows.Scan(&ns); err != nil {
					t.Fatal(err)
				}
				got = append(got, ns)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("catalog_trust after opening: %v, want %v", got, c.want)
			}
		})
	}
}
