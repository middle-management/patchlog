package merge

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
)

func applyDiff(t *testing.T, a any, d []any) any {
	t.Helper()
	ops, err := patch.Parse(jsonv.FromGo(d))
	if err != nil {
		t.Fatalf("parse %v: %v", d, err)
	}
	out, _, err := patch.Apply(a, true, ops, patch.Options{})
	if err != nil {
		t.Fatalf("apply %v to %v: %v", d, a, err)
	}
	return out
}

func TestDiffCases(t *testing.T) {
	cases := []struct{ a, b string }{
		{`{}`, `{}`},
		{`{"a":1}`, `{"a":2}`},
		{`{"a":1}`, `{"b":1}`},
		{`{"a":{"b":[1,2,3]}}`, `{"a":{"b":[1,3]}}`},
		{`[1,2,3]`, `[0,1,2,3,4]`},
		{`[1,2,3]`, `[]`},
		{`[1,{"x":1},3]`, `[1,{"x":2},3]`},
		{`{"a":[1]}`, `{"a":{"0":1}}`},
		{`"s"`, `{"a":1}`},
		{`{"a/b":1,"c~d":2}`, `{"a/b":2}`},
		{`null`, `[null]`},
		{`{"k":[[1,2],[3]]}`, `{"k":[[3],[1,2]]}`},
	}
	for _, c := range cases {
		a, b := jsonv.MustParse([]byte(c.a)), jsonv.MustParse([]byte(c.b))
		d := Diff(a, b)
		if got := applyDiff(t, a, d); !jsonv.Equal(got, b) {
			t.Fatalf("diff(%s, %s) = %v gives %v", c.a, c.b, d, got)
		}
		if c.a == c.b && len(d) != 0 {
			t.Fatalf("diff of equal docs %v", d)
		}
	}
	// Only add, replace and remove.
	d := Diff(jsonv.MustParse([]byte(`{"a":[1,2],"b":1}`)), jsonv.MustParse([]byte(`{"a":[2],"c":1}`)))
	for _, o := range d {
		switch o.(map[string]any)["op"] {
		case "add", "replace", "remove":
		default:
			t.Fatalf("op %v", o)
		}
	}
}

// randomValue builds a random JSON value of bounded depth.
func randomValue(r *rand.Rand, depth int) any {
	k := r.IntN(7)
	if depth <= 0 {
		k = r.IntN(4)
	}
	switch k {
	case 0:
		return nil
	case 1:
		return r.IntN(2) == 0
	case 2:
		return float64(r.IntN(5))
	case 3:
		return fmt.Sprintf("s%d", r.IntN(4))
	case 4, 5:
		n := r.IntN(5)
		m := map[string]any{}
		for i := 0; i < n; i++ {
			m[[]string{"a", "b", "c", "d/e", "f~g", "0", "-"}[r.IntN(7)]] = randomValue(r, depth-1)
		}
		return m
	default:
		n := r.IntN(5)
		a := make([]any, n)
		for i := range a {
			a[i] = randomValue(r, depth-1)
		}
		return a
	}
}

// mutate returns a variation of v: similar enough that diffs recurse.
func mutate(r *rand.Rand, v any, depth int) any {
	if r.IntN(6) == 0 || depth <= 0 {
		return randomValue(r, 2)
	}
	switch x := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, val := range x {
			switch r.IntN(4) {
			case 0: // drop
			case 1:
				m[k] = mutate(r, val, depth-1)
			default:
				m[k] = jsonv.Clone(val)
			}
		}
		if r.IntN(2) == 0 {
			m[fmt.Sprintf("n%d", r.IntN(3))] = randomValue(r, 1)
		}
		return m
	case []any:
		var a []any
		for _, val := range x {
			switch r.IntN(5) {
			case 0: // drop
			case 1:
				a = append(a, mutate(r, val, depth-1))
			case 2:
				a = append(a, randomValue(r, 1), jsonv.Clone(val))
			default:
				a = append(a, jsonv.Clone(val))
			}
		}
		if a == nil {
			a = []any{}
		}
		return a
	}
	return randomValue(r, 1)
}

func TestDiffRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 3000; i++ {
		a := randomValue(r, 4)
		b := mutate(r, a, 4)
		if r.IntN(10) == 0 {
			b = randomValue(r, 4)
		}
		d := Diff(a, b)
		got := applyDiff(t, jsonv.Clone(a), d)
		if !jsonv.Equal(got, b) {
			t.Fatalf("case %d: diff(%s, %s) = %v gives %s", i, jsonv.Canonical(a), jsonv.Canonical(b), d, jsonv.Canonical(got))
		}
		if jsonv.Equal(a, b) && len(d) != 0 {
			t.Fatalf("case %d: non-empty diff of equal documents", i)
		}
	}
}
