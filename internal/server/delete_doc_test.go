package server

import (
	"strings"
	"testing"
)

// Delete envelopes carry the document being deleted as doc, so a rule can
// decide deletes by content: here, only a document's owner may delete it.
// The base is read through in a branch, and a batch's delete step sees the
// document its earlier steps produced.
func TestDeleteRuleSeesDoc(t *testing.T) {
	t.Parallel()
	ownerDeletes := map[string]any{
		"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "delete"}},
		"then": []any{map[string]any{"op": "compare", "path": "/doc/owner", "eq": map[string]any{"path": "/principal/id"}}},
	}
	f := newAuthFixture(t, map[string]any{"rules": []any{ownerDeletes}})
	e := f.tenv
	li := e.grant(f.issuer, "user:li", []string{"sec", "sec-b"}, []string{"read", "create", "append", "restore", "delete"})

	a := e.create("sec", "a", map[string]any{"owner": "user:li"}, li)
	expectCode(t, e.write("DELETE", "sec", "a", a, nil, f.issuerG), 422, "rule")
	e.del("sec", "a", a, li)

	// A branch reads the document through from its base.
	b := e.create("sec", "b", map[string]any{"owner": "user:li"}, li)
	expect(t, e.branch("sec", map[string]any{"name": "sec-b"}, f.issuerG), 201)
	expectCode(t, e.write("DELETE", "sec-b", "b", b, nil, f.issuerG), 422, "rule")
	e.del("sec-b", "b", b, li)
	if e.head("sec", "b", li) != b {
		t.Fatal("the branch's delete reached the base")
	}

	// A batch: the delete step sees the document the step before it made.
	item := func(owner string) map[string]any {
		return map[string]any{"resource": "b", "ifMatch": b, "steps": []any{ops(op("replace", "/owner", owner)), "delete"}}
	}
	r := e.batchReq("sec", map[string]any{"items": []any{item("user:bob")}}, li)
	expectCode(t, r, 422, "batch")
	if !strings.Contains(string(r.Body), `"code":"rule"`) {
		t.Fatalf("batch refusal %s", r.Body)
	}
	expect(t, e.batchReq("sec", map[string]any{"items": []any{item("user:li")}}, li), 201)

	// Two deletes in a row in one item: 422 (§7.5).
	c := e.create("sec", "c", map[string]any{"owner": "user:li"}, li)
	r = e.batchReq("sec", map[string]any{"items": []any{map[string]any{"resource": "c", "ifMatch": c, "steps": []any{"delete", "delete"}}}}, li)
	expectCode(t, r, 422, "batch")
	if !strings.Contains(string(r.Body), `"code":"invalid"`) {
		t.Fatalf("double delete %s", r.Body)
	}
	// A delete, a restore, then a delete again is fine.
	steps := []any{"delete", addRoot(map[string]any{"owner": "user:li"}), "delete"}
	expect(t, e.batchReq("sec", map[string]any{"items": []any{map[string]any{"resource": "c", "ifMatch": c, "steps": steps}}}, li), 201)
}
