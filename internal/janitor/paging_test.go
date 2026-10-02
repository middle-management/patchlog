package janitor_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The janitor with a log page size of 2 (§7.1 Paging): the branch and base
// logs it checks merged claims against (§F.6) span pages.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"merged": TestPurgesGenuinelyMergedAfterPeriod, "forged": TestRefusesForgedMergedClaim, "superseded": TestPurgesSupersededBranch,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
