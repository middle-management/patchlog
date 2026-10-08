package bundle_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Exports and imports with a log page size of 2 (§7.1 Paging): the
// namespace logs and resource histories an export verifies (§G.4), and the
// target logs an import reads, span pages, e2e ciphertext included, as do
// the target heads an import lists (§7.4).
//
// Paged sets the environment, so these flows run serially and call the
// tests' bodies, not the parallel TestX.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"history": testHistoryRoundTrip, "moved target": testFullImportOntoMovedTarget, "branch": testBranchExport, "e2e": testBundleE2E,
		"heads":        func(t *testing.T) { testHeadsListing(t, bundle.Full, false, false) },
		"branch heads": func(t *testing.T) { testHeadsListing(t, bundle.Full, false, true) },
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
