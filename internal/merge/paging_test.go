package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Merges, rebases and releases with a log page size of 2 (§7.1 Paging):
// the branch logs, base logs and resource histories they read (§F.3, §F.5,
// §F.9) all span pages.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"fast-forward": TestFastForwardReproducesIDs, "second merge": TestSecondMergePicksUpNewChanges,
		"rebase": TestRebaseAndSwitch, "purges": TestPurges, "e2e": TestE2EReplayAndConflicts, "release": TestReleaseMerge,
		"release rebase": TestReleaseRebaseAndJanitor,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
