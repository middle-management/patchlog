package rules

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §6.6 Validation work (v0.86), LIM-7: a schema test cut short by the
// budget is Unknown, not False, so a rule that is False with the meter
// over fails outright, whatever the tests cut short would have said,
// which is what lets a step-1 check that fails outright answer before
// the run-out. Passes is a read check's reading: only True within the
// budget passes, so a run-out inside a not, or beside an any member that
// holds, never passes (scenario 89).
func TestV086MeterCutShort(t *testing.T) {
	doc := make([]any, 50)
	for i := range doc {
		doc[i] = float64(i)
	}
	env := map[string]any{"action": "append", "doc": doc}
	const test = `{"op":"test","path":"/doc","schema":{"items":{"type":"number"}}}`
	const isAppend = `{"op":"test","path":"/action","value":"append"}`
	const isDelete = `{"op":"test","path":"/action","value":"delete"}`
	compile := func(s string) *Rule {
		t.Helper()
		r, err := Compile(jsonv.MustParse([]byte(s)))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		return r
	}
	for rule, want := range map[string]Tri{
		test:                   Unknown,
		`{"not":` + test + `}`: Unknown,
		`{"all":[` + test + `,` + isAppend + `]}`:         Unknown,
		`{"all":[` + test + `,` + isDelete + `]}`:         False, // fails whatever the test would have said
		`{"all":[` + isDelete + `,` + test + `]}`:         False,
		`{"any":[` + test + `,` + isDelete + `]}`:         Unknown,
		`{"any":[` + test + `,` + isAppend + `]}`:         True, // holds whatever the test would have said
		`{"if":[` + test + `],"then":[` + isDelete + `]}`: Unknown,
		`{"if":[` + isDelete + `],"then":[` + test + `]}`: True,
	} {
		m := &Meter{Max: 10}
		got := compile(rule).EvalMetered(env, m)
		// The last form never runs the test: its if is false.
		ran := rule != `{"if":[`+isDelete+`],"then":[`+test+`]}` && rule != `{"all":[`+isDelete+`,`+test+`]}`
		if got != want || m.Over != ran && want != False {
			t.Errorf("%s: %v (over %v), want %v", rule, got, m.Over, want)
		}
		// A read check passes only what is True within the budget.
		m = Budget(10)
		if pass := compile(rule).Passes(env, m); pass != (want == True && !m.Over) || pass && ran {
			t.Errorf("%s: Passes %v with over %v", rule, pass, m.Over)
		}
	}

	// Once the budget is spent, a test isn't run and is Unknown too, and
	// no rule passes a read check, one without a schema test included.
	m := Budget(10)
	compile(test).EvalMetered(env, m)
	if v := compile(test).EvalMetered(env, m); v != Unknown || !m.Over {
		t.Fatalf("after the run-out: %v, over %v", v, m.Over)
	}
	if compile(isAppend).Passes(env, m) {
		t.Fatal("a rule passed a read check whose budget was spent")
	}

	// No budget is unbounded: one that isn't positive is the default.
	for _, n := range []int{0, -1} {
		if b := Budget(n); b.Max != DefaultValidationSteps {
			t.Fatalf("Budget(%d).Max = %d", n, b.Max)
		}
	}
	if b := Budget(7); b.Max != 7 {
		t.Fatalf("Budget(7).Max = %d", b.Max)
	}
}
