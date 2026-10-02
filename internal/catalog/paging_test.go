package catalog_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The catalog with a log page size of 2 (§7.1 Paging): the catalog logs it
// reads when issuing grants (§B.11.4) span pages.
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"grants": TestEffectiveAccessAndContentGrants, "behind": TestIssueRefusesWhenBehind, "merge grants": TestMergeGrants,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
