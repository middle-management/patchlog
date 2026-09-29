package server

import (
	"strings"
	"testing"
)

const dialect = "https://json-schema.org/draft/2020-12/schema"

func matchSchema() map[string]any {
	return map[string]any{
		"$schema":    dialect,
		"type":       "object",
		"properties": map[string]any{"score": map[string]any{"type": "string", "pattern": "^[0-9]+-[0-9]+$"}},
		"required":   []any{"score"},
	}
}

// §6.1 schema references, §6.2 step 5, §6.3.
func TestSchemas(t *testing.T) {
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{"read": "public"})
	e.mkNS("docs", map[string]any{"read": "public"})
	s1 := e.create("schemas", "match", matchSchema())
	ref := "/r/schemas/match/rev/" + s1

	// Valid and invalid typed documents.
	d1 := e.create("docs", "derby", map[string]any{"$schema": ref, "score": "1-0"})
	r := e.write("PATCH", "docs", "derby", d1, ops(op("replace", "/score", 3.0)))
	expectCode(t, r, 422, "invalid")
	errs, _ := r.Obj()["errors"].([]any)
	if len(errs) == 0 || errs[0].(map[string]any)["pointer"] == nil || errs[0].(map[string]any)["message"] == nil {
		t.Fatalf("validation errors %s", r.Body)
	}
	// Format assertions are on.
	fs := e.create("schemas", "fmt", map[string]any{"$schema": dialect, "properties": map[string]any{"at": map[string]any{"format": "date-time"}}})
	r = e.write("PATCH", "docs", "fmt", "", addRoot(map[string]any{"$schema": "/r/schemas/fmt/rev/" + fs, "at": "yesterday"}))
	expectCode(t, r, 422, "invalid")

	// Malformed references: schema_ref.
	unknownID := hashID(t, "", []byte("x"))
	for _, bad := range []any{
		"/r/schemas/match",
		"https://cms.example" + ref,
		"/r/schemas/./match/rev/" + s1,
		ref + "?x=1",
		"/r/schemas/m%61tch/rev/" + s1,
		ref + "#",
		"/r/schemas/match/rev/" + strings.ToUpper(s1),
		"http://json-schema.org/draft-07/schema#",
		3.0,
	} {
		r := e.write("PATCH", "docs", "x", "", addRoot(map[string]any{"$schema": bad, "score": "1-0"}))
		if r.Code != 422 || r.Str("code") != "schema_ref" {
			t.Errorf("$schema %v: %d %s", bad, r.Code, r.Body)
		}
	}
	// Unknown references: schema_unavailable.
	for _, bad := range []string{
		"/r/schemas/match/rev/" + unknownID,
		"/r/nons/match/rev/" + s1,
		"/r/schemas/nope/rev/" + s1,
		"/r/docs/derby/rev/" + s1, // an id of another resource
	} {
		r := e.write("PATCH", "docs", "x", "", addRoot(map[string]any{"$schema": bad, "score": "1-0"}))
		if r.Code != 422 || r.Str("code") != "schema_unavailable" {
			t.Errorf("$schema %v: %d %s", bad, r.Code, r.Body)
		}
	}

	// A branch namespace is never a schema namespace, even for read-through revisions.
	r = e.do(req{method: "POST", path: "/ns/schemas/branches", ifNoneMatch: "*", body: map[string]any{"name": "schemas-b"}, author: "admin"})
	expect(t, r, 201)
	expect(t, e.get("/r/schemas-b/match/rev/"+s1), 200)
	r = e.write("PATCH", "docs", "x", "", addRoot(map[string]any{"$schema": "/r/schemas-b/match/rev/" + s1, "score": "1-0"}))
	expectCode(t, r, 422, "schema_ref")

	// Dialect documents: validated against the meta-schema; unknown keywords
	// invalid, x-* allowed; $id only the revision path.
	r = e.write("PATCH", "schemas", "bad1", "", addRoot(map[string]any{"$schema": dialect, "type": 5.0}))
	expect(t, r, 422)
	r = e.write("PATCH", "schemas", "bad2", "", addRoot(map[string]any{"$schema": dialect, "frobnicate": true}))
	expect(t, r, 422)
	r = e.write("PATCH", "schemas", "bad3", "", addRoot(map[string]any{"$schema": dialect, "$id": "https://example.com/s"}))
	expect(t, r, 422)
	r = e.write("PATCH", "schemas", "bad4", "", addRoot(map[string]any{"$schema": dialect, "properties": map[string]any{"a": map[string]any{"pattern": "(a)\\1"}}}))
	expect(t, r, 422)
	r = e.write("PATCH", "schemas", "bad5", "", addRoot(map[string]any{"$schema": dialect, "$ref": "https://example.com/other"}))
	expect(t, r, 422)
	e.create("schemas", "ok", map[string]any{"$schema": dialect, "x-index": map[string]any{"a": true}, "type": "object"})

	// $ref to another schema revision, transitively validated.
	base := e.create("schemas", "base", map[string]any{"$schema": dialect, "type": "string", "maxLength": 5.0})
	baseRef := "/r/schemas/base/rev/" + base
	s2 := e.create("schemas", "match2", map[string]any{"$schema": dialect, "type": "object", "properties": map[string]any{"score": map[string]any{"$ref": baseRef}}})
	ref2 := "/r/schemas/match2/rev/" + s2
	e.create("docs", "cup", map[string]any{"$schema": ref2, "score": "2-2"})
	r = e.write("PATCH", "docs", "cup2", "", addRoot(map[string]any{"$schema": ref2, "score": "1234567"}))
	expectCode(t, r, 422, "invalid")
	// A revision path with a fragment is not one of the accepted $ref forms.
	r = e.write("PATCH", "schemas", "frag", "", addRoot(map[string]any{"$schema": dialect, "$ref": baseRef + "#/x"}))
	expectCode(t, r, 422, "schema_ref")
	// A $ref to an unknown revision makes the schema unusable.
	r = e.write("PATCH", "schemas", "dangling", "", addRoot(map[string]any{"$schema": dialect, "$ref": "/r/schemas/base/rev/" + unknownID}))
	expectCode(t, r, 422, "schema_unavailable")

	// §6.3: adding $schema to an untyped document validates the whole document.
	u := e.create("docs", "untyped", map[string]any{"score": 5.0})
	r = e.write("PATCH", "docs", "untyped", u, ops(op("add", "/$schema", ref)))
	expectCode(t, r, 422, "invalid")
	u = e.appendRev("docs", "untyped", u, ops(op("add", "/$schema", ref), op("replace", "/score", "0-0")))
	// Changing $schema to another revision.
	u = e.appendRev("docs", "untyped", u, ops(op("replace", "/$schema", ref2)))
	// Removing $schema makes it untyped: anything goes.
	u = e.appendRev("docs", "untyped", u, ops(op("remove", "/$schema"), op("replace", "/score", 7.0)))

	// Tombstoned schema resources still resolve, for old and new references.
	sh := e.head("schemas", "match")
	e.del("schemas", "match", sh)
	e.appendRev("docs", "derby", d1, ops(op("replace", "/score", "2-0")))
	e.create("docs", "new", map[string]any{"$schema": ref, "score": "0-1"})

	// Purge refused while referenced (§6.1): directly, and through $ref.
	tomb := e.nsHeadOf("schemas", "match")
	r = e.do(req{method: "POST", path: "/r/schemas/match/purge", ifMatch: tomb, author: "admin"})
	expectCode(t, r, 409, "in_use")
	r = e.do(req{method: "POST", path: "/r/schemas/base/purge", ifMatch: base, author: "admin"})
	expectCode(t, r, 409, "in_use")
	// A tombstoned referencing document still counts.
	dh := e.head("docs", "new")
	e.del("docs", "new", dh)
	e.del("docs", "derby", e.head("docs", "derby"))
	r = e.do(req{method: "POST", path: "/r/schemas/match/purge", ifMatch: tomb, author: "admin"})
	expectCode(t, r, 409, "in_use")
	// Once the referencing documents are purged, the schema can be purged.
	for _, name := range []string{"new", "derby"} {
		r = e.do(req{method: "POST", path: "/r/docs/" + name + "/purge", ifMatch: e.nsHeadOf("docs", name), author: "admin"})
		expect(t, r, 204)
	}
	r = e.do(req{method: "POST", path: "/r/schemas/match/purge", ifMatch: tomb, author: "admin"})
	expect(t, r, 204)
	// References to it are now unavailable.
	r = e.write("PATCH", "docs", "later", "", addRoot(map[string]any{"$schema": ref, "score": "1-0"}))
	expectCode(t, r, 422, "schema_unavailable")
	// A forced purge ignores references.
	r = e.do(req{method: "POST", path: "/r/schemas/base/purge?force=1", ifMatch: base, author: "admin"})
	expect(t, r, 204)
	r = e.write("PATCH", "docs", "later", "", addRoot(map[string]any{"$schema": ref2, "score": "1-0"}))
	expectCode(t, r, 422, "schema_unavailable")
}

// nsHeadOf returns the head or tombstone id of a resource.
func (e *tenv) nsHeadOf(ns, name string) string {
	e.t.Helper()
	r := e.get("/r/" + ns + "/" + name)
	if r.Code != 302 && r.Code != 410 {
		e.t.Fatalf("head of %s/%s: %d", ns, name, r.Code)
	}
	return etagOf(r)
}

// §6.4.4 examples and §6.4.3 evaluation.
func TestRulesExamples(t *testing.T) {
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{"read": "public"})
	e.mkNS("other", map[string]any{"read": "public"})
	s := e.create("schemas", "match", matchSchema())
	o := e.create("other", "match", matchSchema())
	ref := "/r/schemas/match/rev/" + s
	rules := []any{
		map[string]any{
			"if":   []any{map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"create", "append", "restore"}}}},
			"then": []any{map[string]any{"op": "test", "path": "/doc/$schema", "schema": map[string]any{"type": "string", "pattern": "^/r/schemas/match/rev/"}}},
		},
		map[string]any{
			"if": []any{
				map[string]any{"not": map[string]any{"op": "test", "path": "/action", "value": "create"}},
				map[string]any{"op": "writes", "overlaps": "/$schema"},
			},
			"then": []any{map[string]any{"op": "test", "path": "/doc/$schema", "exists": true}},
		},
		map[string]any{
			"if":   []any{map[string]any{"op": "test", "path": "/action", "schema": map[string]any{"enum": []any{"delete", "purge"}}}},
			"then": []any{map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "ops"}}}},
		},
		map[string]any{
			"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "append"}},
			"then": []any{map[string]any{"not": map[string]any{"op": "writes", "covers": ""}}},
		},
	}
	e.mkNS("matches", map[string]any{"read": "public", "rules": rules})

	ruleFail := func(r *resp, idx float64, path string) {
		t.Helper()
		expectCode(t, r, 422, "rule")
		if r.Obj()["rule"] != idx || r.Obj()["path"] != path {
			t.Fatalf("rule failure %s, want rule %v path %q", r.Body, idx, path)
		}
	}
	// Rule 0: every document is typed with the match schema.
	ruleFail(e.write("PATCH", "matches", "a", "", addRoot(map[string]any{"score": "1-0"})), 0, "/doc/$schema")
	ruleFail(e.write("PATCH", "matches", "a", "", addRoot(map[string]any{"$schema": "/r/other/match/rev/" + o, "score": "1-0"})), 0, "/doc/$schema")
	h := e.create("matches", "a", map[string]any{"$schema": ref, "score": "1-0"})
	// Rule 1 (reached only for non-rule-0 cases: remove) — removing $schema.
	r := e.write("PATCH", "matches", "a", h, ops(op("remove", "/$schema")))
	expectCode(t, r, 422, "rule")
	if idx := r.Obj()["rule"]; idx != 0.0 && idx != 1.0 {
		t.Fatalf("remove $schema: %s", r.Body)
	}
	// Rule 3: no whole-document replace on appends, even keeping $schema.
	ruleFail(e.write("PATCH", "matches", "a", h, ops(op("replace", "", map[string]any{"$schema": ref, "score": "2-0"}))), 3, "")
	h = e.appendRev("matches", "a", h, ops(op("replace", "/score", "2-0")))
	// Rule 2: only the ops group may delete (dev mode has no principal).
	ruleFail(e.write("DELETE", "matches", "a", h, nil), 2, "/principal/groups")
	r = e.do(req{method: "POST", path: "/r/matches/a/purge", ifMatch: h, author: "x"})
	ruleFail(r, 2, "/principal/groups")
	// Rules don't run on reads, and failed writes wrote nothing.
	if e.head("matches", "a") != h {
		t.Fatal("head moved")
	}

	// Rules with more than the limit are refused; malformed rules are 422.
	r = e.patchNS("matches", ops(op("add", "/rules/-", map[string]any{"op": "frob"})), "")
	expect(t, r, 422)
	r = e.patchNS("matches", ops(op("add", "/rules/-", map[string]any{"op": "test", "path": "/doc/x", "schema": map[string]any{"pattern": "(?=x)"}})), "")
	expect(t, r, 422)
}

// §6.4.1: writes computed per op (move writes both; a fresh $nonce is left out).
func TestRulesWritesAndNonce(t *testing.T) {
	e := newEnv(t)
	e.mkNS("tr", map[string]any{"read": "public", "rules": []any{
		map[string]any{
			"if":   []any{map[string]any{"op": "test", "path": "/action", "value": "append"}},
			"then": []any{map[string]any{"op": "writes", "within": []any{"/i18n"}}},
		},
	}})
	h := e.create("tr", "a", map[string]any{"title": "t", "i18n": map[string]any{}, "tags": []any{}})
	h = e.appendRev("tr", "a", h, ops(op("add", "/i18n/sv", "x"), op("add", "/$nonce", "abcdefghijklmnopqrstuvwxyz")))
	r := e.write("PATCH", "tr", "a", h, ops(map[string]any{"op": "move", "from": "/title", "path": "/i18n/title"}))
	expectCode(t, r, 422, "rule")
	r = e.write("PATCH", "tr", "a", h, ops(op("add", "/$nonce", "not-a-nonce")))
	expectCode(t, r, 422, "rule")
	r = e.write("PATCH", "tr", "a", h, ops(op("add", "/tags/-", "x")))
	expectCode(t, r, 422, "rule")
	// test ops write nothing.
	e.appendRev("tr", "a", h, ops(op("test", "/title", "t"), op("replace", "/i18n/sv", "y")))
}
