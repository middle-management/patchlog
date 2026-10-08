package tree_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The tree service with a log page size of 2 (§7.1 Paging): it follows its
// catalogs and their trusted namespaces through paged logs and /heads
// pages (§B.5, §10).
//
// Paged sets the environment, so these flows run serially and call the
// tests' bodies, not the parallel TestX.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"listings": testTreeListings, "moves": testMovesAndDeletes, "restart": testTrustAndRestart,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
