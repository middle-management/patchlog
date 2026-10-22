package janitor_test

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

// §7.4, §8.5 (RH-19): a purged namespace's /branches is 410. A Check of a
// purged branch whose claim verifies reports it already purged instead of
// failing on its dependents' listing, and a successor whose base is purged
// doesn't verify, with that as the reason, instead of failing on the
// base's listing.
func TestV073JanitorPurgedBranchListings(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"superseded": "P1D"})
	e.edit("r7", "derby", "1-0")
	must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true}))
	purge := func(ns string) {
		t.Helper()
		if f, _ := must(e.c.NSDoc(ctx, ns, must(e.c.NSHead(ctx, ns)).ID)).Value["frozen"].(bool); !f {
			e.config(ns, op("add", "/frozen", true))
		}
		must(e.c.PurgeNamespace(ctx, ns, must(e.c.NSHead(ctx, ns)).ID))
	}
	e.s.Clock.Advance(time.Minute)
	purge("r7-b") // after r7's freeze: the claim still verifies (§F.6)
	purge("r7")
	e.s.Clock.Advance(2 * day)
	j := janitor.New(e.c, janitor.Options{Bases: []string{"matches"}, Now: e.s.Clock.Now})

	d, err := j.Check(ctx, "matches", "r7")
	if err != nil {
		t.Fatalf("Check of a purged branch: %v", err)
	}
	if d.Action != janitor.ActionKeep || !strings.HasPrefix(d.Reason, "already purged") {
		t.Fatalf("decision %+v, want keep, already purged", d)
	}

	purge("matches")
	d, err = j.Check(ctx, "matches", "r7")
	if err != nil {
		t.Fatalf("Check with the successor's base purged: %v", err)
	}
	wantKeep(t, d, "superseded claim not verified: the successor's base matches is purged")
}
