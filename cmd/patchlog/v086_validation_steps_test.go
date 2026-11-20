package main

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
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
	var ix indexCmd
	parseArgs(t, &ix, "--ns", "docs")
	if ix.MaxValidationSteps != core.DefaultMaxValidationSteps {
		t.Errorf("service default: index %d", ix.MaxValidationSteps)
	}
	parseArgs(t, &ix, "--ns", "docs", "--max-validation-steps", "1234")
	if ix.MaxValidationSteps != 1234 {
		t.Errorf("index flag: %d", ix.MaxValidationSteps)
	}
}
