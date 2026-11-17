package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
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
// is refused with the limit validationSteps (§6.6 Validation work, §6.2
// step 5), measured being the steps taken when it stopped; one within it is
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

// unionFragment is unionSchemaDoc as a rule's schema fragment: the same
// recursive union, without the dialect.
func unionFragment() map[string]any {
	f := unionSchemaDoc()
	delete(f, "$schema")
	return f
}

// doubling is a schema fragment that takes more than 2^levels steps on
// any value, however small: each level applies the next twice.
func doubling(levels int) map[string]any {
	defs := map[string]any{fmt.Sprintf("a%d", levels): true}
	for i := 0; i < levels; i++ {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/a%d", i+1)}
		defs[fmt.Sprintf("a%d", i)] = map[string]any{"allOf": []any{next, next}}
	}
	return map[string]any{"$ref": "#/$defs/a0", "$defs": defs}
}

// §6.6 Validation work (v0.85), LIM-7: a write's validation and its
// rules' schema tests take at most validationSteps steps together. A
// document within the limit on its own is refused once a namespace rule
// tests it against a schema that takes the rest, and each step of each
// batch item has the limit to itself (§7.5: every step is checked with
// its own envelope).
func TestV085ValidationStepsWithRules(t *testing.T) {
	t.Parallel()
	const budget = 3000
	// (Validated in full: a patch is otherwise validated only where it
	// changed the document, in far fewer steps.)
	e := newEnv(t, func(o *core.Options) { o.MaxValidationSteps, o.FullValidation = budget, true })
	e.mkNS("s", map[string]any{})
	rev := e.create("s", "tree", unionSchemaDoc())
	typed := func(levels int) map[string]any {
		doc := unionTree(0, levels)
		doc["$schema"] = "/r/s/tree/rev/" + rev
		return doc
	}
	// 127 nodes: some 1,800 steps against the schema, well within 3,000.
	head := e.create("s", "small", typed(7))

	// A rule that tests appended documents against the same union: as many
	// steps again.
	rule := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "append"}},
		"then": []any{map[string]any{"op": "test", "path": "/doc", "schema": unionFragment()}}}
	expect(t, e.patchNS("s", ops(op("add", "/rules", []any{rule})), ""), 201)

	// A create isn't judged by it: still within the limit, also as two
	// items of one batch, which together take more than it.
	e.create("s", "small2", typed(7))
	batch := map[string]any{"items": []any{
		map[string]any{"resource": "b1", "ifNoneMatch": "*", "steps": []any{addRoot(typed(7))}},
		map[string]any{"resource": "b2", "ifNoneMatch": "*", "steps": []any{addRoot(typed(7))}},
	}}
	expect(t, e.batchReq("s", batch, "alice"), 201)

	// An append is: its validation and the rule's test together need
	// more, though either alone fits.
	r := e.write("PATCH", "s", "small", head, ops(op("add", "/x-note", "n")))
	expectCode(t, r, 422, "limit")
	m := r.Obj()
	if m["limit"] != "validationSteps" || m["max"] != float64(budget) {
		t.Fatalf("limit %v max %v: %s", m["limit"], m["max"], r.Body)
	}
	if got, _ := m["measured"].(float64); got <= budget {
		t.Fatalf("measured %v, want more than %d: %s", m["measured"], budget, r.Body)
	}
	// A dry run reports it for the item.
	r = e.do(req{method: "POST", path: "/ns/s/batch?dry-run=1", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "small", "ifMatch": head, "steps": []any{ops(op("add", "/x-note", "n"))}},
		map[string]any{"resource": "b3", "ifNoneMatch": "*", "steps": []any{addRoot(typed(7))}},
	}}})
	expect(t, r, 200)
	items := r.Obj()["items"].([]any)
	if it := items[0].(map[string]any); it["status"] != 422.0 || it["code"] != "limit" || it["limit"] != "validationSteps" {
		t.Fatalf("dry run item 0: %v", it)
	}
	if it := items[1].(map[string]any); it["status"] != 201.0 {
		t.Fatalf("dry run item 1: %v", it)
	}
	// With the limit raised the same append passes: the rule itself holds.
	e2 := newEnv(t, func(o *core.Options) { o.MaxValidationSteps, o.FullValidation = 2*budget, true })
	e2.mkNS("s", map[string]any{"rules": []any{rule}})
	rev2 := e2.create("s", "tree", unionSchemaDoc())
	doc := unionTree(0, 7)
	doc["$schema"] = "/r/s/tree/rev/" + rev2
	e2.appendRev("s", "small", e2.create("s", "small", doc), ops(op("add", "/x-note", "n")))

	// validationSteps is the deployment's: a namespace document that sets
	// it is invalid (§12.2).
	r = e.patchNS("s", ops(op("add", "/limits", map[string]any{"validationSteps": 10.0})), "")
	expectCode(t, r, 422, "invalid")
}

// §6.6 Validation work, conformance scenario 82: under a narrowing block
// whose rule tests /doc against a schema that takes more than
// validationSteps, the write is 422 limit, not the 403 a failing grant
// rule gives, with max and, for a writer who can't read the resource,
// without measured. A rule of step 1 counts too, and its 422 comes before
// the rate limits, drawing nothing.
func TestV085ValidationStepsGrantRules(t *testing.T) {
	t.Parallel()
	const budget = 3000
	f := newAuthFixture(t, map[string]any{"limits": map[string]any{
		"ratePerResource": map[string]any{"rate": 0.001, "burst": 1.0}}},
		func(o *core.Options) { o.MaxValidationSteps = budget })
	e := f.tenv
	// (Only writes are judged by it: a read has no /doc, and the reader
	// below must stay one.)
	onDoc := map[string]any{"rules": []any{map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"create", "append"}}}},
		"then": []any{map[string]any{"op": "test", "path": "/doc", "schema": unionFragment()}}}}}
	root, err := grant.Mint(map[string]any{"kid": "issuer", "sub": "user:w", "ns": []any{"sec"}, "can": []any{"read", "create", "append"},
		"exp": e.clock.Now().Add(time.Hour).Format(time.RFC3339)}, f.issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	reader := narrowed(t, root, onDoc)
	blind := narrowed(t, root, map[string]any{"can": []any{"create", "append"}, "rules": onDoc["rules"]})

	// Within the limit the rule passes or refuses as ever.
	e.create("sec", "ok", unionTree(0, 7), reader)
	expectCode(t, e.write("PATCH", "sec", "no", "", addRoot(map[string]any{"kind": "k9"}), reader), 403, "forbidden")

	// 1,023 nodes: 14,833 steps.
	r := e.write("PATCH", "sec", "big", "", addRoot(unionTree(0, 10)), reader)
	expectCode(t, r, 422, "limit")
	m := r.Obj()
	if got, _ := m["measured"].(float64); m["limit"] != "validationSteps" || m["max"] != float64(budget) || got <= budget {
		t.Fatalf("reader: %s", r.Body)
	}
	r = e.write("PATCH", "sec", "big2", "", addRoot(unionTree(0, 10)), blind)
	expectCode(t, r, 422, "limit")
	m = r.Obj()
	if _, has := m["measured"]; has || m["limit"] != "validationSteps" || m["max"] != float64(budget) {
		t.Fatalf("writer without read: %s", r.Body)
	}

	// A rule of step 1, on /resource: a billion steps and more on a name,
	// for the write and again for the read check that decides whether the
	// refusal may carry measured, which is held to the limit too. Its
	// 422 comes before the rate limits, so it draws no token: the one the
	// bucket of that resource holds is still there for a grant without
	// the rule.
	onName := narrowed(t, root, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": doubling(30)}}})
	for i := 0; i < 2; i++ {
		r = e.write("PATCH", "sec", "named", "", addRoot(map[string]any{}), onName)
		expectCode(t, r, 422, "limit")
		if _, has := r.Obj()["measured"]; has || r.Obj()["limit"] != "validationSteps" {
			t.Fatalf("step 1: %s", r.Body)
		}
	}
	expect(t, e.write("PATCH", "sec", "named", "", addRoot(map[string]any{}), root.Encode()), 201)
	expectCode(t, e.write("PATCH", "sec", "named", "", addRoot(map[string]any{}), root.Encode()), 429, "rate")
}

// A deployment run without a bound on validation (MaxValidationSteps
// negative, serve --max-validation-steps 0), which §6.6 doesn't provide
// for, bounds nothing and leaves validationSteps out of /principal.
func TestV085ValidationStepsUnbounded(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *core.Options) { o.MaxValidationSteps = -1 })
	e.mkNS("s", map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": doubling(12)}}})
	e.create("s", "a", map[string]any{})
	r := e.principalOf("s", "")
	expect(t, r, 200)
	l, _ := r.Obj()["writer"].(map[string]any)["limits"].(map[string]any)
	if _, has := l["validationSteps"]; has || l["documentSize"] == nil {
		t.Fatalf("limits %v", l)
	}
}
