package tree_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The tree service with a log page size of 2 (§7.1 Paging): it follows its
// catalogs and their trusted namespaces through paged logs and /heads
// pages (§B.5, §10).
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"listings": TestTreeListings, "moves": TestMovesAndDeletes, "restart": TestTrustAndRestart,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
