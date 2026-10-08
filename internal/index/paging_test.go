package index_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The index with a log page size of 2 (§7.1 Paging): it catches up from
// its checkpoint page by page (§A.1, §10), on a first start and after a
// restart or a rebuild.
//
// Paged sets the environment, so these flows run serially and call the
// tests' bodies, not the parallel TestX.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"updates": testUpdatesTombstonePurge, "restart": testCheckpointSurvivesRestart, "rebuild": testRebuild,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
