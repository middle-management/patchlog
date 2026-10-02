package bundle_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Exports and imports with a log page size of 2 (§7.1 Paging): the
// namespace logs and resource histories an export verifies (§G.4), and the
// target logs an import reads, span pages, e2e ciphertext included.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"history": TestHistoryRoundTrip, "moved target": TestFullImportOntoMovedTarget, "branch": TestBranchExport, "e2e": TestBundleE2E,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
