package core

import (
	"regexp"
	"testing"
)

// §7: GET / publishes the spec version as dotted decimal numbers, compared
// component by component ("0.38", "0.38.1"), without leading zeros.
func TestSpecVersionFormat(t *testing.T) {
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$`).MatchString(SpecVersion) {
		t.Fatalf("spec version %q is not dotted decimal", SpecVersion)
	}
	if SpecVersion != "0.40" {
		t.Fatalf("spec version %s", SpecVersion)
	}
}
