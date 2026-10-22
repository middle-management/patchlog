package server

import "testing"

// Schema dialect rules of v0.73 over HTTP (§6.1, §6.2 step 5, §6.5, §6.6):
// what a written schema may hold, and the codes of what it may not.
func TestV073SchemaDialect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{"read": "public"})
	e.mkNS("docs", map[string]any{"read": "public"})
	obj := func(kv ...any) map[string]any {
		m := map[string]any{"$schema": dialect}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	prop := func(name string, s any) map[string]any {
		return map[string]any{name: s}
	}

	// CIS-10, CIS-11, CIS-15, CIS-18, CIS-19: 422 invalid, not schema_ref.
	for name, doc := range map[string]map[string]any{
		"id-root":        obj("$id", "https://example.com/s"),
		"id-nested":      obj("properties", prop("a", map[string]any{"$id": "x"})),
		"schema-nested":  obj("properties", prop("a", map[string]any{"$schema": dialect})),
		"format-unknown": obj("format", "semver"),
		"dependencies":   obj("dependencies", map[string]any{}),
		"recursive-ref":  obj("$recursiveRef", "#"),
		"successor-bad":  obj("$successor", "Bad Name"),
		"lone-surrogate": obj("pattern", `\uD800`),
	} {
		expectCode(t, e.write("PATCH", "schemas", name, "", addRoot(doc)), 422, "invalid")
	}

	// CIS-18, CIS-19, CIS-16: accepted.
	defs := e.create("schemas", "defs", obj("type", "object", "properties", prop("s", map[string]any{"$ref": "#/definitions/s"}),
		"definitions", prop("s", map[string]any{"type": "string", "pattern": `^\u00e9+$`})))
	e.create("schemas", "moved", obj("$successor", "defs", "type", "object"))
	defsPath := "/r/schemas/defs/rev/" + defs
	e.create("docs", "e", map[string]any{"$schema": defsPath, "s": "éé"})
	expectCode(t, e.write("PATCH", "docs", "e2", "", addRoot(map[string]any{"$schema": defsPath, "s": "e"})), 422, "invalid")

	// Malformed references stay schema_ref.
	expectCode(t, e.write("PATCH", "schemas", "space", "", addRoot(obj("$ref", defsPath+"#a b"))), 422, "schema_ref")
}
