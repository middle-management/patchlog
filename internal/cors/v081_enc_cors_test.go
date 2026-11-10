package cors

import (
	"strings"
	"testing"
)

// v0.81 (§7.1 End-to-end namespaces): the server never folds, so it sends
// no X-E2E header, and pages are offered none to read.
func TestV081NoE2EHeaderExposed(t *testing.T) {
	for _, h := range strings.Split(Exposed, ", ") {
		if strings.EqualFold(h, "X-E2E") {
			t.Fatalf("Exposed lists %s", h)
		}
	}
}
