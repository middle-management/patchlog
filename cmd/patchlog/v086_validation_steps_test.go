package main

import (
	"strings"
	"testing"
)

// §6.6 Validation work (v0.86), LIM-7: "No deployment leaves
// validationSteps unbounded". --max-validation-steps 0, which lifted the
// limit before, is refused, as a negative count is, for serve and for the
// services, which take the same flag with the same default.
func TestV086MaxValidationStepsFlag(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1} {
		if _, err := validationSteps(n); err == nil || !strings.Contains(err.Error(), "--max-validation-steps") {
			t.Errorf("%d: %v", n, err)
		}
	}
	if n, err := validationSteps(7); n != 7 || err != nil {
		t.Errorf("7: %d %v", n, err)
	}
	// v0.88 SERVICES §A.4: the index takes the origin's from /principal
	// unless the flag overrides it.
	var ix indexCmd
	parseArgs(t, &ix, "--ns", "docs")
	if ix.MaxValidationSteps != 0 {
		t.Errorf("service default: index %d, want 0, the origin's", ix.MaxValidationSteps)
	}
	parseArgs(t, &ix, "--ns", "docs", "--max-validation-steps", "1234")
	if ix.MaxValidationSteps != 1234 {
		t.Errorf("index flag: %d", ix.MaxValidationSteps)
	}
}
