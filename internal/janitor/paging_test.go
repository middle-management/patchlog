package janitor_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The janitor with a log page size of 2 (§7.1 Paging): the branch and base
// logs it checks merged claims against (§F.6) span pages.
//
// Paged sets the environment, so these flows run serially and call the
// tests' bodies, not the parallel TestX.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"merged": testPurgesGenuinelyMergedAfterPeriod, "forged": testRefusesForgedMergedClaim, "superseded": testPurgesSupersededBranch,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
