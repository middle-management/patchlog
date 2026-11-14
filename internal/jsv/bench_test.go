package jsv

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// structuredDoc is the "structured 1 MiB" document: about 9,500 small
// typed objects.
func structuredDoc(n int) any {
	items := make([]any, n)
	for i := range items {
		items[i] = map[string]any{
			"id":    float64(i),
			"name":  fmt.Sprintf("item-%06d", i),
			"score": float64(i%1000) / 10,
			"tags":  []any{"a", "bb"},
			"at":    "2026-10-15T12:00:00Z",
			"ok":    i%2 == 0,
		}
	}
	return map[string]any{"n": 0.0, "items": items}
}

const structuredItems = 9500

// unionTree is a full binary tree of the given depth whose nodes are of
// kind k0..k3 by depth.
func unionTree(depth, levels int) any {
	n := map[string]any{"kind": "k" + string(rune('0'+depth%4))}
	if depth+1 < levels {
		n["children"] = []any{unionTree(depth+1, levels), unionTree(depth+1, levels)}
	}
	return n
}

// benchUnionSchema is unionSchema as the benchmark states it, without the
// maxItems the generated documents of the other tests need.
var benchUnionSchema = strings.ReplaceAll(unionSchema, `"maxItems": 3, `, "")

func TestStructuredDocSize(t *testing.T) {
	data, err := json.Marshal(structuredDoc(structuredItems))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 900<<10 || len(data) > 1100<<10 {
		t.Errorf("the structured document is %d bytes, not about 1 MiB", len(data))
	}
}

// TestNoAllocations: validating a valid document allocates nothing.
func TestNoAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	sch, err := Compile(mustJSON(structuredSchema), "", Options{AssertFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	doc := structuredDoc(200)
	changed := []string{"/items/100/score"}
	if err := sch.Validate(doc, ValidateOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(20, func() { _ = sch.Validate(doc, ValidateOptions{}) }); n != 0 {
		t.Errorf("Validate allocates %v times", n)
	}
	union, err := Compile(mustJSON(benchUnionSchema), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	tree := unionTree(0, 6)
	if n := testing.AllocsPerRun(20, func() { _ = union.Validate(tree, ValidateOptions{}) }); n != 0 {
		t.Errorf("Validate of the union allocates %v times", n)
	}
	// ValidateChange allocates only the tree of changed locations.
	if n := testing.AllocsPerRun(20, func() { _ = sch.ValidateChange(doc, changed, ValidateOptions{}) }); n > 12 {
		t.Errorf("ValidateChange allocates %v times", n)
	}
}

func TestBudget(t *testing.T) {
	sch, err := Compile(mustJSON(benchUnionSchema), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	tree := unionTree(0, 10)
	var st Stats
	if err := sch.Validate(tree, ValidateOptions{Stats: &st}); err != nil {
		t.Fatal(err)
	}
	steps := st.Steps
	t.Logf("recursive union, 1,023 nodes: %d steps", steps)
	if steps > 40*1023 {
		t.Errorf("%d steps for 1,023 nodes: not linear in the tree", steps)
	}
	if err := sch.Validate(tree, ValidateOptions{Budget: steps, Stats: &st}); err != nil || st.Steps != steps {
		t.Errorf("budget of exactly %d steps: %v after %d", steps, err, st.Steps)
	}
	for _, budget := range []int{1, 100, steps - 1} {
		err := sch.Validate(tree, ValidateOptions{Budget: budget, Stats: &st})
		if !errors.Is(err, ErrBudget) {
			t.Errorf("budget %d: %v, want ErrBudget", budget, err)
		}
		// Once over, the evaluations still on the stack each stop at their
		// next step: a few more are counted.
		if st.Steps < budget || st.Steps > budget+100 {
			t.Errorf("budget %d: stopped after %d steps", budget, st.Steps)
		}
		if err := sch.ValidateChange(tree, []string{""}, ValidateOptions{Budget: budget}); !errors.Is(err, ErrBudget) {
			t.Errorf("ValidateChange, budget %d: %v, want ErrBudget", budget, err)
		}
	}
	// An invalid document is invalid, not over budget, if found so in time.
	bad := unionTree(0, 10)
	bad.(map[string]any)["kind"] = "k9"
	var ve *ValidationError
	if err := sch.Validate(bad, ValidateOptions{Budget: 100}); !errors.As(err, &ve) {
		t.Errorf("invalid root within budget: %v", err)
	}

	// Running out inside a branch is not that branch failing: "not" must
	// not turn it into a pass.
	not, err := Compile(mustJSON(`{"not": {"items": {"type": "integer"}}}`), "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	ints := make([]any, 1000)
	for i := range ints {
		ints[i] = float64(i)
	}
	if err := not.Validate(ints, ValidateOptions{}); !errors.As(err, &ve) {
		t.Errorf("not, no budget: %v", err)
	}
	if err := not.Validate(ints, ValidateOptions{Budget: 10}); !errors.Is(err, ErrBudget) {
		t.Errorf("not, budget 10: %v, want ErrBudget", err)
	}
}

// TestLibraryUnionTime times the library on the recursive union once: it
// is too slow to benchmark by default. Run with -run TestLibraryUnionTime -v.
func TestLibraryUnionTime(t *testing.T) {
	if testing.Short() || !testing.Verbose() {
		t.Skip("slow: run with -v")
	}
	lib, err := libCompile(mustJSON(benchUnionSchema), nil)
	if err != nil {
		t.Fatal(err)
	}
	tree := unionTree(0, 10)
	start := time.Now()
	if err := lib.Validate(tree); err != nil {
		t.Fatal(err)
	}
	t.Logf("library, recursive union, 1,023 nodes: %v", time.Since(start))
}

func BenchmarkStructured(b *testing.B) {
	raw := mustJSON(structuredSchema)
	doc := structuredDoc(structuredItems)
	lib, err := libCompile(raw, nil)
	if err != nil {
		b.Fatal(err)
	}
	sch, err := Compile(raw, "", repoOptions(nil))
	if err != nil {
		b.Fatal(err)
	}
	b.Run("library-full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := lib.Validate(doc); err != nil {
				b.Fatal(err)
			}
		}
	})
	run := func(name string, changed []string) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var st Stats
			o := ValidateOptions{Stats: &st}
			for i := 0; i < b.N; i++ {
				var err error
				if changed == nil {
					err = sch.Validate(doc, o)
				} else {
					err = sch.ValidateChange(doc, changed, o)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(st.Steps), "steps/op")
		})
	}
	run("jsv-full", nil)
	run("jsv-change-n", []string{"/n"})
	run("jsv-change-score", []string{"/items/5000/score"})
}

// BenchmarkUnion is the recursive union on a binary tree of depth 10. The
// library takes seconds per validation: -bench 'Union/jsv' leaves it out.
func BenchmarkUnion(b *testing.B) {
	raw := mustJSON(benchUnionSchema)
	tree := unionTree(0, 10)
	sch, err := Compile(raw, "", repoOptions(nil))
	if err != nil {
		b.Fatal(err)
	}
	run := func(name string, changed []string) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var st Stats
			o := ValidateOptions{Stats: &st}
			for i := 0; i < b.N; i++ {
				var err error
				if changed == nil {
					err = sch.Validate(tree, o)
				} else {
					err = sch.ValidateChange(tree, changed, o)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(st.Steps), "steps/op")
		})
	}
	run("jsv-full", nil)
	leaf := strings.Repeat("/children/1", 9)
	run("jsv-change-leaf", []string{leaf + "/kind"})
	b.Run("library-full", func(b *testing.B) {
		lib, err := libCompile(raw, nil)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := lib.Validate(tree); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCompile compiles the structured schema, with and without the
// check against the meta-schema, which compiles the meta-schema each time.
func BenchmarkCompile(b *testing.B) {
	raw := mustJSON(structuredSchema)
	for _, skip := range []bool{false, true} {
		name := "meta-checked"
		if skip {
			name = "unchecked"
		}
		b.Run("jsv-"+name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Compile(raw, "", Options{AssertFormat: true, SkipMetaSchema: skip}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	b.Run("library", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := libCompile(raw, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}
