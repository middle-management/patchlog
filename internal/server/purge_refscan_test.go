package server

import (
	"fmt"
	"os"
	"testing"
)

// A purge of a document nothing references as a schema doesn't read every
// document of the deployment for references (§6.1): only a change that
// touches a copy of a schema revision something may reference does. Not
// parallel: it counts the engine's scans.
func TestPurgeReferenceScan(t *testing.T) {
	// PATCHLOG_TEST_VALIDATE_BOTH scans on every purge, to compare.
	counted := !validateBothSet()
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("docs", map[string]any{})
	base := e.create("schemas", "base", map[string]any{"$schema": dialect, "type": "string"})
	baseRef := "/r/schemas/base/rev/" + base
	// outer is referenced by a document; base only from inside outer.
	outer := e.create("schemas", "outer", map[string]any{"$schema": dialect, "type": "object",
		"properties": map[string]any{"team": map[string]any{"$ref": baseRef}}})
	expect(t, e.typed("docs", "d1", "/r/schemas/outer/rev/"+outer), 201)
	// A branch that reads d1 through, and so references outer too.
	expect(t, e.branch("docs", map[string]any{"name": "docs-b"}, "admin"), 201)
	plain := e.create("schemas", "plain", map[string]any{"a": 1})
	other := e.create("docs", "other", map[string]any{"a": 1})
	// A document named as a schema's resource is, in another namespace.
	same := e.create("docs", "base", map[string]any{"a": 1})

	scans := e.e.SchemaScans()
	expect(t, e.purge("schemas", "plain", plain, "admin"), 204)
	expect(t, e.purge("docs", "other", other, "admin"), 204)
	expect(t, e.purge("docs", "base", same, "admin"), 204)
	if got := e.e.SchemaScans() - scans; counted && got != 0 {
		t.Fatalf("%d scans for purges of unreferenced documents", got)
	}
	// Referenced only through $ref: refused, after a scan.
	r := e.purge("schemas", "base", base, "admin")
	expectCode(t, r, 409, "in_use")
	if got := fmt.Sprint(referencing(r)); got != "[docs docs-b]" {
		t.Fatalf("referencing %s", got)
	}
	expectCode(t, e.purge("schemas", "outer", outer, "admin"), 409, "in_use")
	if e.e.SchemaScans() == scans {
		t.Fatal("no scan for a referenced schema")
	}
	// With the referencing documents gone, the schemas may go; the
	// branch's read-through reference went with d1's purge in the base.
	expect(t, e.purge("docs", "d1", e.head("docs", "d1"), "admin"), 204)
	expect(t, e.purge("schemas", "base", base, "admin"), 204)
	expect(t, e.purge("schemas", "outer", outer, "admin"), 204)
}

func validateBothSet() bool { return os.Getenv("PATCHLOG_TEST_VALIDATE_BOTH") != "" }
