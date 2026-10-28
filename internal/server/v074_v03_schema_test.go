package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/schema"
)

// schemaErrorAt reports whether r is a 422 invalid whose errors include
// one at pointer (§6.2 step 5).
func schemaErrorAt(r *resp, pointer string) bool {
	if r.Code != 422 || r.Str("code") != "invalid" {
		return false
	}
	errs, _ := r.Obj()["errors"].([]any)
	for _, e := range errs {
		if m, _ := e.(map[string]any); m["pointer"] == pointer {
			return true
		}
	}
	return false
}

// CORE-2 (§6.2 step 5, Open 55): over HTTP, idn-hostname and idn-email are
// judged by RFC 5890 without UTS 46 mapping: a fullwidth or uppercase
// letter in a U-label is 422 with an error at its pointer; an all-ASCII
// host name in any case passes.
func TestV074V03IDNHostnameWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	s := e.create("schemas", "host", map[string]any{"$schema": dialect, "type": "object",
		"properties": map[string]any{
			"h": map[string]any{"type": "string", "format": "idn-hostname"},
			"m": map[string]any{"type": "string", "format": "idn-email"}}})
	e.mkNS("main", map[string]any{})
	typed := func(v map[string]any) []any {
		v["$schema"] = "/r/schemas/host/rev/" + s
		return addRoot(v)
	}
	expect(t, e.write("PATCH", "main", "ok", "", typed(map[string]any{"h": "bücher.example", "m": "a@EXAMPLE.com"})), 201)
	expect(t, e.write("PATCH", "main", "ascii", "", typed(map[string]any{"h": "EXAMPLE.com"})), 201)
	for _, x := range []struct {
		name, member, value string
	}{
		{"fullwidth", "h", "ｅｘａｍｐｌｅ.com"},
		{"upper", "h", "Bücher.example"},
		{"mail", "m", "a@Bücher.example"},
	} {
		r := e.write("PATCH", "main", x.name, "", typed(map[string]any{x.member: x.value}))
		if !schemaErrorAt(r, "/"+x.member) {
			t.Errorf("%s %q: %d %s, want 422 invalid at /%s", x.member, x.value, r.Code, r.Body, x.member)
		}
	}
}

// CORE-3 (§6.1, §6.2 step 5): every schema compiles under this version,
// whatever marker its revision row carries. A schema revision stored
// before markers (rules NULL, read as Legacy, which v0.73 compiled without
// asserting idn-hostname) now asserts it: a document pinning it with an
// invalid host name is 422 with an error at its pointer.
func TestV074V03LegacyMarkerCompilesCurrent(t *testing.T) {
	t.Parallel()
	path, blobs := v073DB(t), t.TempDir()
	at := func(o *core.Options) { o.Path, o.BlobDir = path, blobs }
	e := newEnv(t, at)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("main", map[string]any{})
	s := e.create("schemas", "host", map[string]any{"$schema": dialect, "type": "object",
		"properties": map[string]any{"h": map[string]any{"type": "string", "format": "idn-hostname"}}})
	e.srv.Close()
	e.e.Close()
	db, q := v073SQL(t, path)
	if _, err := db.Exec(q(`UPDATE revisions SET rules = NULL`)); err != nil {
		t.Fatal(err)
	}
	e = newEnv(t, at)
	if r := e.get("/r/schemas/host/rev/" + s); r.H.Get(schema.RulesHeader) != "legacy" {
		t.Fatalf("the revision's marker %q, want legacy", r.H.Get(schema.RulesHeader))
	}
	doc := func(h string) []any {
		return addRoot(map[string]any{"$schema": "/r/schemas/host/rev/" + s, "h": h})
	}
	if r := e.write("PATCH", "main", "bad", "", doc("-bad-")); !schemaErrorAt(r, "/h") {
		t.Errorf("-bad- under a Legacy revision: %d %s, want 422 invalid at /h", r.Code, r.Body)
	}
	expect(t, e.write("PATCH", "main", "good", "", doc("example.com")), 201)
}
