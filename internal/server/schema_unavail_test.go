package server

import "testing"

// B2: a writer whose read is fixed to one resource (readScope "resource")
// appends a document whose $schema, or $ref closure, pins a revision of
// another resource in the same namespace. The answer names that revision
// path, never the dialect URL the schema itself carries (§6.1, §12).
func TestSchemaUnavailableNamesPin(t *testing.T) {
	e := newAuthEnv(t)
	k := newKey("k")
	rk := newKey("rk")
	rkEntry := rk.entry("read", "create", "append")
	rkEntry["readScope"] = "resource"
	e.mkNS("c", map[string]any{"read": "grant", "keys": []any{k.entry("*"), rkEntry}})
	star := e.grant(k, "user:admin", []string{"c"}, []string{"create", "append", "read"})
	s := e.create("c", "s", map[string]any{"$schema": dialect, "type": "object"}, star)
	sRef := "/r/c/s/rev/" + s
	d := e.create("c", "doc", map[string]any{"v": 1.0}, star)

	only := e.grant(rk, "user:li", []string{"c"}, []string{"read", "append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "doc"}}})
	r := e.write("PATCH", "c", "doc", d, ops(op("add", "/$schema", sRef)), only)
	expectCode(t, r, 422, "schema_unavailable")
	if got := r.Str("ref"); got != sRef {
		t.Fatalf("$schema pin: ref %q, want %q (%s)", got, sRef, r.Body)
	}
	// An unknown revision answers the same way, so the answer doesn't
	// reveal whether an unreadable revision exists (§7).
	unknown := "/r/c/s/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	r2 := e.write("PATCH", "c", "doc", d, ops(op("add", "/$schema", unknown)), only)
	expectCode(t, r2, 422, "schema_unavailable")
	if got := r2.Str("ref"); got != unknown {
		t.Fatalf("unknown pin: ref %q, want %q (%s)", got, unknown, r2.Body)
	}
	if r.Str("message") != r2.Str("message") {
		t.Fatalf("unreadable and unknown differ: %s vs %s", r.Body, r2.Body)
	}

	// The reported case: the document written is itself a schema ($schema is
	// the dialect URL) whose $ref closure pins the unreadable revision.
	only2 := e.grant(rk, "user:li", []string{"c"}, []string{"read", "append"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "sch"}}})
	h := e.create("c", "sch", map[string]any{"$schema": dialect, "type": "object"}, star)
	for _, fresh := range []bool{true, false} {
		if !fresh {
			// The validator now holds s, compiled for a writer who may read it.
			e.create("c", "typed", map[string]any{"$schema": sRef}, star)
		}
		for _, ref := range []string{sRef, sRef + "#/properties", unknown} {
			r := e.write("PATCH", "c", "sch", h, ops(op("add", "/$ref", ref)), only2)
			expectCode(t, r, 422, "schema_unavailable")
			want := ref
			if i := len(sRef); len(ref) > i && ref[:i] == sRef {
				want = sRef
			}
			if got := r.Str("ref"); got != want {
				t.Fatalf("schema $ref %s (fresh=%v): ref %q, want %q (%s)", ref, fresh, got, want, r.Body)
			}
		}
	}
	// Whoever may read it is served.
	e.appendRev("c", "sch", h, ops(op("add", "/$ref", sRef)), star)
}
