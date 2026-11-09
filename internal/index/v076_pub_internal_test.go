package index

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// TestV076PubKeysKept (§B.11.9 gs, §C.4): each exchange for a g: marker
// adds the key its grant came from beside those of the marker's other
// live cookies, never in their place, and one key's record lasts until
// the last cookie minted under it expires; gsKeys reads them from the
// database, as every instance on it shares them, and forgets the expired.
func TestV076PubKeysKept(t *testing.T) {
	ctx := context.Background()
	ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
	ix.filters = map[string]keptFilter{}
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	const m = "reads:matches:g:1abc"
	rec := func(pub string) *markerRec {
		return &markerRec{f: &grantcheck.ReadFilter{Principal: map[string]any{}}, subjects: []string{"group:fans"},
			key: gsKey{kid: "catalog-01", roles: []string{"reader"}, pub: pub}}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	pubs := func(now time.Time) []string {
		t.Helper()
		ks, err := ix.gsKeys(ctx, m, now)
		must(err)
		var out []string
		for _, k := range ks {
			if k.kid != "catalog-01" || len(k.roles) != 1 || k.roles[0] != "reader" {
				t.Errorf("key %+v", k)
			}
			out = append(out, k.pub)
		}
		return out
	}
	must(ix.recordFilters(ctx, map[string]*markerRec{m: rec("P1")}, t0.Add(15*time.Minute), t0))
	must(ix.recordFilters(ctx, map[string]*markerRec{m: rec("P2")}, t0.Add(20*time.Minute), t0.Add(5*time.Minute)))
	must(ix.recordFilters(ctx, map[string]*markerRec{m: rec("P2")}, t0.Add(25*time.Minute), t0.Add(10*time.Minute)))
	if got := pubs(t0.Add(10 * time.Minute)); len(got) != 2 || got[0] != "P1" || got[1] != "P2" {
		t.Errorf("keys while both live: %v, want [P1 P2]", got)
	}
	if got := pubs(t0.Add(15 * time.Minute)); len(got) != 1 || got[0] != "P2" {
		t.Errorf("keys once P1's cookie expired: %v, want [P2]", got)
	}
	if got := pubs(t0.Add(25 * time.Minute)); len(got) != 0 {
		t.Errorf("keys once every cookie expired: %v", got)
	}
}
