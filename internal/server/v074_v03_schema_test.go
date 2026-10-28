package server

import (
	"testing"
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
