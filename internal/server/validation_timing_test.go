package server

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// TestAppendTimingLargeTyped times appends of a one-field patch to a 1 MiB
// document of 9,500 small typed objects (docs/CAPACITY.md, "Large
// documents"), through the HTTP handler, with no schema, validated in
// full and validated by the patch's changes. It measures; it asserts
// nothing, and runs only when asked:
//
//	PATCHLOG_TEST_TIMING=1 go test ./internal/server -run TestAppendTimingLargeTyped -v
func TestAppendTimingLargeTyped(t *testing.T) {
	if os.Getenv("PATCHLOG_TEST_TIMING") == "" {
		t.Skip("PATCHLOG_TEST_TIMING is not set")
	}
	j := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	schemaDoc := j("$schema", "https://json-schema.org/draft/2020-12/schema", "type", "object", "required", []any{"n", "items"},
		"properties", j("n", j("type", "integer"), "items", j("type", "array", "items", j(
			"type", "object", "additionalProperties", false, "required", []any{"id", "name", "score", "tags", "at", "ok"},
			"properties", j(
				"id", j("type", "integer", "minimum", 0),
				"name", j("type", "string", "pattern", "^item-[0-9]{6}$"),
				"score", j("type", "number", "minimum", 0, "maximum", 100),
				"tags", j("type", "array", "maxItems", 4, "items", j("type", "string", "maxLength", 16)),
				"at", j("type", "string", "format", "date-time"),
				"ok", j("type", "boolean"))))))
	doc := func() map[string]any {
		items := make([]any, 9500)
		for i := range items {
			items[i] = j("id", i, "name", fmt.Sprintf("item-%06d", i), "score", float64(i%1000)/10,
				"tags", []any{"a", "bb"}, "at", "2026-10-15T12:00:00Z", "ok", i%2 == 0)
		}
		return j("n", 0, "items", items)
	}
	for _, mode := range []string{"no schema", "schema, in full", "schema, by changes"} {
		e := newEnv(t, func(o *core.Options) { o.FullValidation = mode == "schema, in full" })
		e.mkNS("s", map[string]any{})
		d := doc()
		if mode != "no schema" {
			d["$schema"] = "/r/s/schema/rev/" + e.create("s", "schema", schemaDoc)
		}
		head := e.create("s", "doc", d)
		var times []time.Duration
		for i := 1; i <= 61; i++ {
			e.clock.Advance(1e9)
			start := time.Now()
			head = e.appendRev("s", "doc", head, ops(op("replace", "/n", i)))
			times = append(times, time.Since(start))
		}
		times = times[1:] // the first finds the document in no cache
		sort.Slice(times, func(a, b int) bool { return times[a] < times[b] })
		full, change := e.e.ValidationCounts()
		t.Logf("%-20s append p50 %6.2f ms, p90 %6.2f ms (validated %d in full, %d by changes)", mode,
			float64(times[len(times)/2].Microseconds())/1000, float64(times[len(times)*9/10].Microseconds())/1000, full, change)
	}
}
