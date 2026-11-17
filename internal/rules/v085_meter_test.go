package rules

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §6.6 Validation work (v0.85): the schema tests of a write's rules draw
// on its validationSteps with its validation. A Meter counts them, and
// once they run out it says so itself (Over): the value of a rule cut
// short means nothing, whatever combines it, a not included.
func TestV085Meter(t *testing.T) {
	doc := make([]any, 50)
	for i := range doc {
		doc[i] = float64(i)
	}
	env := map[string]any{"action": "append", "doc": doc}
	const test = `{"op":"test","path":"/doc","schema":{"items":{"type":"number"}}}`
	compile := func(s string) *Rule {
		t.Helper()
		r, err := Compile(jsonv.MustParse([]byte(s)))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		return r
	}

	// What the test costs: counted, and the same without a limit.
	m := &Meter{}
	if v := compile(test).EvalMetered(env, m); v != True || m.Over || m.Steps < len(doc) {
		t.Fatalf("no limit: %v, steps %d, over %v", v, m.Steps, m.Over)
	}
	cost := m.Steps
	if v := compile(test).EvalMetered(env, nil); v != True {
		t.Fatalf("no meter: %v", v)
	}

	// Exactly enough passes; the next schema test finds nothing left, and
	// is refused without being run (a budget of 0 is no limit to jsv).
	m = &Meter{Max: cost}
	if v := compile(test).EvalMetered(env, m); v != True || m.Over || m.Steps != cost {
		t.Fatalf("exact: %v, steps %d, over %v", v, m.Steps, m.Over)
	}
	if compile(test).EvalMetered(env, m); !m.Over || m.Steps != cost {
		t.Fatalf("nothing left: steps %d, over %v", m.Steps, m.Over)
	}
	// Steps another part of the write took count.
	m = &Meter{Max: cost + 5, Steps: 6}
	if compile(test).EvalMetered(env, m); !m.Over || m.Steps <= m.Max {
		t.Fatalf("with earlier steps: steps %d, over %v", m.Steps, m.Over)
	}

	// One step short, under every form that could turn a test cut short
	// into a pass: Over is set, so the caller never reads the value.
	for _, rule := range []string{
		test,
		`{"not":` + test + `}`,
		`{"any":[` + test + `,{"op":"test","path":"/action","value":"append"}]}`,
		`{"if":[` + test + `],"then":[{"op":"test","path":"/action","value":"delete"}]}`,
		`{"all":[{"not":` + test + `},{"not":` + test + `}]}`,
	} {
		m := &Meter{Max: cost - 1}
		compile(rule).EvalMetered(env, m)
		if !m.Over || m.Steps <= m.Max {
			t.Errorf("%s: steps %d of %d, over %v", rule, m.Steps, m.Max, m.Over)
		}
	}

	// A list stops at the rule that ran out, and stays within the limit
	// when it names the failing form of a rule that failed within it.
	list, err := CompileList(jsonv.MustParse([]byte(`[` + test + `,` + test + `,` + test + `]`)))
	if err != nil {
		t.Fatal(err)
	}
	m = &Meter{Max: 2*cost + 1}
	if i, _, _ := EvalMetered(list, env, m); !m.Over || i != 2 {
		t.Fatalf("list: rule %d, steps %d, over %v", i, m.Steps, m.Over)
	}
	failing, err := CompileList(jsonv.MustParse([]byte(`[{"all":[{"op":"test","path":"/doc","schema":{"items":{"type":"string"}}}]}]`)))
	if err != nil {
		t.Fatal(err)
	}
	m = &Meter{}
	if i, path, v := EvalMetered(failing, env, m); v != False || i != 0 || path != "/rules/0/all/0" || m.Over {
		t.Fatalf("failing: %d %q %v over %v", i, path, v, m.Over)
	}
	once := m.Steps / 2 // the rule is evaluated again to find the path
	m = &Meter{Max: once}
	if i, path, v := EvalMetered(failing, env, m); v != False || i != 0 || path != "/rules/0" || m.Over || m.Steps > m.Max {
		t.Fatalf("failing at the limit: %d %q %v, steps %d of %d, over %v", i, path, v, m.Steps, m.Max, m.Over)
	}
	m = &Meter{Max: 2 * once}
	if _, path, v := EvalMetered(failing, env, m); v != False || path != "/rules/0/all/0" || m.Over || m.Steps != 2*once {
		t.Fatalf("failing within the limit: %q %v, steps %d, over %v", path, v, m.Steps, m.Over)
	}
}
