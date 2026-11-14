package server

import (
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
)

// unionTree is a full binary tree of the given number of levels whose
// nodes are of kind k0..k3 by depth, for unionSchemaDoc.
func unionTree(depth, levels int) map[string]any {
	n := map[string]any{"kind": fmt.Sprintf("k%d", depth%4)}
	if depth+1 < levels {
		n["children"] = []any{unionTree(depth+1, levels), unionTree(depth+1, levels)}
	}
	return n
}

// unionSchemaDoc is a recursive union: a node is one of four kinds, each
// with children that are nodes. Validating a tree against it the slow way
// tries every branch at every node in full, which is exponential in the
// tree's depth.
func unionSchemaDoc() map[string]any {
	defs := map[string]any{"node": map[string]any{"oneOf": []any{
		map[string]any{"$ref": "#/$defs/k0"}, map[string]any{"$ref": "#/$defs/k1"},
		map[string]any{"$ref": "#/$defs/k2"}, map[string]any{"$ref": "#/$defs/k3"}}}}
	for i := 0; i < 4; i++ {
		k := fmt.Sprintf("k%d", i)
		defs[k] = map[string]any{"type": "object", "required": []any{"kind"}, "properties": map[string]any{
			"kind":     map[string]any{"const": k},
			"children": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/node"}}}}
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$ref": "#/$defs/node", "$defs": defs}
}

// A document whose validation takes more steps than the deployment allows
// is refused with the limit validationSteps (the reference's addition to
// §6.6), measured being the steps taken when it stopped; one within it is
// accepted, and an invalid one within it is invalid, not over the limit.
func TestValidationStepsLimit(t *testing.T) {
	t.Parallel()
	const budget = 3000
	e := newEnv(t, func(o *core.Options) { o.MaxValidationSteps = budget })
	e.mkNS("s", map[string]any{})
	rev := e.create("s", "tree", unionSchemaDoc())
	typed := func(levels int) map[string]any {
		doc := unionTree(0, levels)
		doc["$schema"] = "/r/s/tree/rev/" + rev
		return doc
	}

	// 127 nodes: some 1,800 steps.
	head := e.create("s", "small", typed(7))

	// 1,023 nodes: 14,833 steps.
	r := e.write("PATCH", "s", "big", "", addRoot(typed(10)))
	expectCode(t, r, 422, "limit")
	m := r.Obj()
	if m["limit"] != "validationSteps" || m["max"] != float64(budget) || m["measured"] != float64(budget+1) {
		t.Fatalf("limit %v, measured %v, max %v; want validationSteps, %d, %d", m["limit"], m["measured"], m["max"], budget+1, budget)
	}

	// A patch is held to it as a create is: it validates the document it
	// results in.
	r = e.write("PATCH", "s", "small", head, ops(op("replace", "/children/0/children", []any{unionTree(2, 10), unionTree(2, 10)})))
	expectCode(t, r, 422, "limit")
	if r.Obj()["limit"] != "validationSteps" {
		t.Fatalf("limit %v: %s", r.Obj()["limit"], r.Body)
	}

	// Invalid within the budget: every failure is listed, as ever.
	bad := typed(7)
	bad["kind"] = "k9"
	bad["children"].([]any)[1].(map[string]any)["kind"] = 5
	r = e.write("PATCH", "s", "bad", "", addRoot(bad))
	expectCode(t, r, 422, "invalid")
	if errs, _ := r.Obj()["errors"].([]any); len(errs) < 2 {
		t.Fatalf("errors: %s", r.Body)
	}

	// No limit.
	e2 := newEnv(t, func(o *core.Options) { o.MaxValidationSteps = -1 })
	e2.mkNS("s", map[string]any{})
	rev2 := e2.create("s", "tree", unionSchemaDoc())
	doc := unionTree(0, 10)
	doc["$schema"] = "/r/s/tree/rev/" + rev2
	e2.create("s", "big", doc)
}
