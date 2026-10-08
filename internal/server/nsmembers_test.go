package server

import (
	"strings"
	"testing"
)

// expectMember expects the 422 of a namespace-document member that isn't
// defined and doesn't start with "x-" (§7.4): code invalid, with
// errors [{ pointer, message }] naming it, as for schema validation.
func expectMember(t *testing.T, r *resp, path string) {
	t.Helper()
	expectCode(t, r, 422, "invalid")
	if errPointer(t, r) != path || !strings.Contains(r.Str("message"), `must start with "x-"`) {
		t.Fatalf("unknown member %s: %s", path, r.Body)
	}
}

// errPointer is the pointer of a 422 invalid's only error (§7.4, §12).
func errPointer(t *testing.T, r *resp) string {
	t.Helper()
	errs, _ := r.Obj()["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("errors: %s", r.Body)
	}
	m := errs[0].(map[string]any)
	if m["message"] == "" {
		t.Fatalf("error without a message: %s", r.Body)
	}
	p, _ := m["pointer"].(string)
	return p
}

// §7.4: namespace creation, config writes, batch config changes and branch
// creation validate the members the spec defines strictly, and accept any
// other member only if it starts with "x-", storing it as data.
func TestNamespaceMembers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	create := func(ns string, doc map[string]any) *resp {
		return e.do(req{method: "PATCH", path: "/ns/" + ns, ifNoneMatch: "*", body: addRoot(doc), author: "op"})
	}
	// Creation: a typo, or a setting this version doesn't know, is refused.
	expectMember(t, create("docs", map[string]any{"read": "public", "title": "Docs"}), "/title")
	expectMember(t, create("docs", map[string]any{"read": "public", "rule": []any{}}), "/rule")
	expectMember(t, create("docs", map[string]any{"read": "public", "export": false}), "/export")
	expect(t, e.get("/ns/docs"), 404)
	e.mkNS("docs", map[string]any{"read": "public", "x-title": "Docs", "x-ui": map[string]any{"color": "red"}})
	r := e.get("/ns/docs/rev/" + e.nsHead("docs"))
	if r.Obj()["x-title"] != "Docs" || r.Obj()["x-ui"].(map[string]any)["color"] != "red" {
		t.Fatalf("x- members are stored as data: %s", r.Body)
	}

	// Config writes.
	expectMember(t, e.patchNS("docs", ops(op("add", "/titel", "x")), ""), "/titel")
	expectMember(t, e.patchNS("docs", []any{map[string]any{"op": "move", "from": "/x-title", "path": "/title"}}, ""), "/title")
	expect(t, e.patchNS("docs", ops(op("replace", "/x-title", "Documents"), op("add", "/x-", 1.0)), ""), 201)

	// The addenda's members are checked in their shapes (Addenda B, F).
	id := e.nsHead("docs")
	for name, patch := range map[string]map[string]any{
		"catalog mode":     op("add", "/catalog", map[string]any{"trust": strs([]string{"matches"}), "mode": "forest"}),
		"catalog trust":    op("add", "/catalog", map[string]any{"trust": "matches"}),
		"catalog field":    op("add", "/catalog", map[string]any{"trusted": strs([]string{"matches"})}),
		"catalogs subject": op("add", "/catalogs", map[string]any{"cat": map[string]any{"place": strs([]string{"match-desk"})}}),
		"catalogs field":   op("add", "/catalogs", map[string]any{"cat": map[string]any{"move": strs([]string{"group:x"})}}),
		"merged":           op("add", "/merged", true),
		"merged at":        op("add", "/merged", map[string]any{"at": "yesterday"}),
		"cleanup":          op("add", "/cleanup", map[string]any{"merged": "a week"}),
		"cleanup field":    op("add", "/cleanup", map[string]any{"purged": "P7D"}),
		"abandoned":        op("add", "/abandoned", "yes"),
		"revoked":          op("add", "/revoked", strs([]string{"not-a-revocation-id"})),
	} {
		r := e.patchNS("docs", ops(patch), "")
		if r.Code != 422 || r.Str("code") != "invalid" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	expect(t, e.patchNS("docs", ops(
		op("add", "/catalog", map[string]any{"trust": strs([]string{"matches"}), "mode": "dag"}),
		op("add", "/catalogs", map[string]any{"cat": map[string]any{"place": strs([]string{"group:match-desk", "user:anna"})}}),
		op("add", "/merged", map[string]any{"at": id}),
		op("add", "/cleanup", map[string]any{"merged": "P7D", "superseded": "P30D", "abandoned": "P30D"}),
		op("add", "/abandoned", false),
		op("add", "/revoked", strs([]string{hashID(t, "", []byte("a block signature"))})),
	), ""), 201)

	// A batch's config change is a config write.
	r = e.do(req{method: "POST", path: "/ns/docs/batch", author: "admin", body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("docs"), "patches": ops(op("add", "/notes", "x"))}}})
	expectMember(t, r, "/notes")

	// Branch creation: the base's document plus the patches.
	expectMember(t, e.branch("docs", map[string]any{"name": "docs-b", "patches": ops(op("add", "/branchNote", "x"))}, "alice"), "/branchNote")
	expect(t, e.get("/ns/docs-b"), 404)
	expect(t, e.branch("docs", map[string]any{"name": "docs-b", "patches": ops(op("add", "/x-branchNote", "x"))}, "alice"), 201)
	r = e.get("/ns/docs-b/rev/" + e.nsHead("docs-b"))
	if r.Obj()["x-branchNote"] != "x" || r.Obj()["x-title"] != "Documents" {
		t.Fatalf("branch document %s", r.Body)
	}

	// A remote branch's genesis is checked before anything is fetched (§G.3).
	at := hashID(t, "", []byte("an ns_id at A"))
	expectMember(t, e.mkRemote("rel", remoteGenesis("main", at, map[string]any{"title": "B's release"})), "/title")
}
