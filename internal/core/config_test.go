package core

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// documentSize is 1 MiB by default, and a namespace may set it up to the
// deployment maximum, 4 MiB by default (docs/CAPACITY.md).
func TestDocumentSizeDefaultAndMaximum(t *testing.T) {
	if got := DefaultLimits().DocumentSize; got != 1<<20 {
		t.Fatalf("default documentSize %d", got)
	}
	if got := DefaultMaximums().DocumentSize; got != 4<<20 {
		t.Fatalf("maximum documentSize %d", got)
	}
	c, err := parseConfig(map[string]any{"read": "public"}, DefaultLimits(), DefaultMaximums())
	if err != nil || c.Limits.DocumentSize != 1<<20 {
		t.Fatalf("unset: %v %v", c, err)
	}
	c, err = parseConfig(map[string]any{"read": "public", "limits": map[string]any{"documentSize": float64(4 << 20)}}, DefaultLimits(), DefaultMaximums())
	if err != nil || c.Limits.DocumentSize != 4<<20 {
		t.Fatalf("4 MiB: %v %v", c, err)
	}
	if _, err := parseConfig(map[string]any{"read": "public", "limits": map[string]any{"documentSize": float64(4<<20 + 1)}}, DefaultLimits(), DefaultMaximums()); err == nil {
		t.Fatal("over the maximum accepted")
	}
}

// v0.55 §7.4: FormatDuration writes what ParseDuration reads back.
func TestFormatDuration(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{
		0:                                "PT0S",
		5 * time.Minute:                  "PT5M",
		24 * time.Hour:                   "P1D",
		30 * 24 * time.Hour:              "P30D",
		36*time.Hour + 90*time.Second:    "P1DT12H1M30S",
		1500 * time.Millisecond:          "PT1.5S",
		2*time.Hour + 3*time.Millisecond: "PT2H0.003S",
	} {
		got := FormatDuration(d)
		back, err := ParseDuration(got)
		if got != want || err != nil || back != d {
			t.Errorf("%v: %q (%v, %v), want %q", d, got, back, err, want)
		}
	}
}

// v0.55 §7.4, §6.6: Limits.Doc writes every limit as a namespace document
// writes it, so the namespace-settable ones parse back to the same limits.
func TestLimitsDoc(t *testing.T) {
	t.Parallel()
	l := DefaultMaximums()
	l.RetryWindow = 10 * time.Minute
	l.RetryWindowMin = time.Minute
	doc := jsonv.FromGo(l.Doc()).(map[string]any)
	for k := range deploymentOnlyLimits {
		if k == "validationSteps" {
			continue // the engine's option, not a field: limitsInForce adds it
		}
		if _, ok := doc[k]; !ok {
			t.Fatalf("no %s in %v", k, doc)
		}
		delete(doc, k)
	}
	var back Limits
	back.LogPageSize, back.LogPageBytes, back.BranchDepth, back.ExchangeRate, back.RetryWindowMin = l.LogPageSize, l.LogPageBytes, l.BranchDepth, l.ExchangeRate, l.RetryWindowMin
	back.GrantSize, back.RulesPerGrant = l.GrantSize, l.RulesPerGrant
	if err := parseLimits(doc, &back, l, configMode{}); err != nil {
		t.Fatal(err)
	}
	if back != l {
		t.Fatalf("round trip\n%+v\nwant\n%+v", back, l)
	}
}
