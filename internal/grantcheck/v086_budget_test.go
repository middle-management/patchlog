package grantcheck

import (
	"fmt"
	"testing"
)

// doublingSchema takes more than 2^levels validation steps on any value:
// each level applies the next twice.
func doublingSchema(levels int) map[string]any {
	defs := map[string]any{fmt.Sprintf("a%d", levels): true}
	for i := 0; i < levels; i++ {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/a%d", i+1)}
		defs[fmt.Sprintf("a%d", i)] = map[string]any{"allOf": []any{next, next}}
	}
	return map[string]any{"$ref": "#/$defs/a0", "$defs": defs}
}

// §6.6 Validation work (v0.86), LIM-7, conformance scenario 90: each item
// a service filters by a grant has its own budget of validationSteps, and
// one whose rule's schema test runs out is left out, the rest listed:
// never the item shown, under a not either, and never the whole listing
// failed.
func TestV086ReadFilterItemBudget(t *testing.T) {
	t.Parallel()
	slow := map[string]any{"op": "test", "path": "/resource", "schema": doublingSchema(30)}
	onB := func(then any) map[string]any {
		return map[string]any{"if": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}, "then": []any{then}}
	}
	principal := map[string]any{"id": "user:li"}
	for name, f := range map[string]*ReadFilter{
		"block rule":       {BlockRules: []any{onB(slow)}, Principal: principal, Steps: 2000},
		"key rule":         {KeyRules: []any{onB(slow)}, Principal: principal, Steps: 2000},
		"under a not":      {BlockRules: []any{onB(map[string]any{"not": slow})}, Principal: principal, Steps: 2000},
		"beside a pass":    {BlockRules: []any{onB(map[string]any{"any": []any{slow, map[string]any{"op": "test", "path": "/action", "value": "read"}}})}, Principal: principal, Steps: 2000},
		"its only role":    {Roles: [][]any{{onB(slow)}}, Principal: principal, Steps: 2000},
		"before a role":    {Roles: [][]any{{onB(slow)}, {}}, Principal: principal, Steps: 2000},
		"the default":      {BlockRules: []any{onB(slow)}, Principal: principal},
		"decoded, default": decoded(t, &ReadFilter{BlockRules: []any{onB(slow)}, Principal: principal, Steps: 2000}),
	} {
		for _, item := range []string{"a", "b", "c"} {
			want := item != "b"
			if got := f.Allows(item); got != want {
				t.Errorf("%s: Allows(%q) = %v", name, item, got)
			}
		}
	}

	// Within the budget the same rules decide as ever.
	fast := map[string]any{"op": "test", "path": "/resource", "schema": doublingSchema(4)}
	f := &ReadFilter{BlockRules: []any{onB(fast)}, Principal: principal, Steps: 2000}
	if !f.Allows("b") {
		t.Error("a rule within the budget refused")
	}
	if f = (&ReadFilter{BlockRules: []any{onB(map[string]any{"not": fast})}, Principal: principal, Steps: 2000}); f.Allows("b") {
		t.Error("a not within the budget allowed")
	}
}

// decoded is f as a service reads it back: Steps isn't kept, and a
// decoded filter has the default.
func decoded(t *testing.T, f *ReadFilter) *ReadFilter {
	t.Helper()
	d, err := DecodeReadFilter(f.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if d.Steps != 0 {
		t.Fatalf("Steps %d kept by Encode", d.Steps)
	}
	return d
}

// Key-scope attrs are validated within a budget too: no schema work a
// grant can cause is unbounded (§6.6 "No deployment leaves
// validationSteps unbounded"; no clause names attrs).
func TestV086AttrsBudget(t *testing.T) {
	t.Parallel()
	if err := validateAttrs(doublingSchema(30), map[string]any{"desk": "x"}, 2000); err == nil {
		t.Error("attrs matched a schema that ran out of steps")
	}
	if err := validateAttrs(map[string]any{"not": doublingSchema(30)}, map[string]any{"desk": "x"}, 2000); err == nil {
		t.Error("attrs matched under a not that ran out of steps")
	}
	if err := validateAttrs(doublingSchema(4), map[string]any{"desk": "x"}, 2000); err != nil {
		t.Error(err)
	}
	if err := ValidateAttrs(doublingSchema(30), nil); err == nil {
		t.Error("attrs matched at the default budget")
	}
}
