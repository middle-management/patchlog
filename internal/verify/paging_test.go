package verify_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Verification with a log page size of 2 (§7.1 Paging): chains fetched page
// by page verify as one range (§G.2).
func TestPagedFlows(t *testing.T) {
	for name, f := range map[string]func(*testing.T){
		"genuine": TestVerifyGenuineChains, "tampering": TestVerifyDetectsTampering,
	} {
		t.Run(name, func(t *testing.T) { clienttest.Paged(t, 2, f) })
	}
}
