package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// §1, §7, §G.1 (v0.38): GET / publishes the spec version, whether
// authentication is on ("grants") or "disabled", and the origin. Clients
// read the mode from there (client.Root, client.AuthDisabled).
func TestV038Root(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		e    *tenv
		auth string
	}{
		{"dev", newEnv(t), "disabled"},
		{"grants", newAuthEnv(t), "grants"},
	} {
		r := tc.e.get("/")
		expect(t, r, 200)
		if m := r.Obj(); len(m) != 4 || m["jwks_uri"] != "https://cms.example/.well-known/patchlog-keys" || m["spec"] != core.SpecVersion || m["auth"] != tc.auth || m["origin"] != "https://cms.example" {
			t.Fatalf("%s: GET / %s", tc.name, r.Body)
		}
		c, err := plclient.New(tc.e.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		root, err := c.Root(context.Background())
		if err != nil || root.Spec != core.SpecVersion || root.Auth != tc.auth || root.Origin != "https://cms.example" {
			t.Fatalf("%s: client root %+v %v", tc.name, root, err)
		}
		if off, err := c.AuthDisabled(context.Background()); err != nil || off != (tc.auth == "disabled") {
			t.Fatalf("%s: AuthDisabled %v %v", tc.name, off, err)
		}
	}
}

// §1 (v0.38): with authentication disabled, config writes skip namespace
// rules, as *-key writes do (§6.4.3); resource writes are still checked.
func TestV038DevRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "ok"}}})
	expect(t, e.patchNS("main", ops(op("add", "/x-note", "config writes skip the rules")), ""), 201)
	r := e.do(req{method: "POST", path: "/ns/main/batch", author: "admin", body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("main"), "patches": ops(op("add", "/x-batch", true))}}})
	expect(t, r, 201)
	e.create("main", "ok", map[string]any{}, "ann")
	expectCode(t, e.write("PATCH", "main", "other", "", addRoot(map[string]any{}), "ann"), 422, "rule")
}

// §1, §7.4 (v0.38): the client tells "grant": null, written while
// authentication was disabled, from an entry without "grant" (the
// server's own).
func TestV038ClientGrantNull(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("main", map[string]any{})
	a := e.create("main", "a", map[string]any{}, "ann")
	expect(t, e.branch("main", map[string]any{"name": "main-b"}, "bea"), 201)
	expect(t, e.purge("main", "a", a, "cid"), 204)
	c, err := plclient.New(e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h, err := c.NSHead(ctx, "main-b")
	if err != nil {
		t.Fatal(err)
	}
	lg, err := c.NSLog(ctx, "main-b", h.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	last := lg[len(lg)-1]
	if first := lg[0]; !first.GrantNull || first.Grant != nil || first.Author != "bea" {
		t.Fatalf("branch entry %+v", first)
	}
	if last.Kind != "purge" || last.GrantNull || last.Grant != nil {
		t.Fatalf("propagated purge %+v", last)
	}
}

// §1, §7.4 (v0.38): entries a development server wrote before it recorded
// "grant": null can't be told from the server's own, so after the
// migration they serve no grant, and count for no one; entries written
// from then on serve null.
func TestV038GrantNullMigration(t *testing.T) {
	t.Parallel()
	path, driver := filepath.Join(t.TempDir(), "old.db"), "sqlite"
	if pgtest.Enabled() {
		path, driver = pgtest.FreshDB(t), "pgx"
	}
	e := newEnv(t, withPath(path))
	e.mkNS("main", map[string]any{})
	e.create("main", "a", map[string]any{}, "ann")
	e.close()

	dsn := path
	if driver == "sqlite" {
		dsn = "file:" + path
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE ns_log DROP COLUMN no_auth`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	e2 := newEnv(t, withPath(path))
	e2.create("main", "b", map[string]any{}, "ann")
	lg := e2.get("/ns/main/rev/" + e2.nsHead("main") + "/log").Arr()
	if len(lg) != 3 {
		t.Fatalf("log %v", lg)
	}
	for i, want := range []string{"", "", "null"} {
		if got := entryRef(t, lg[i]); got != want {
			t.Fatalf("entry %d: grant %q, want %q", i, got, want)
		}
	}
}

// §7.4 (v0.38): the addenda's objects may carry x- members, stored as
// data; the keys of catalogs are catalog names; other members of them are
// 422 invalid with a pointer to the member.
func TestV038AddendaXMembers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	id := e.nsHead("docs")
	expect(t, e.patchNS("docs", ops(
		op("add", "/catalog", map[string]any{"mode": "tree", "x-label": "Season"}),
		op("add", "/catalogs", map[string]any{"cat": map[string]any{"place": strs([]string{"group:desk"}), "x-since": "2025"}}),
		op("add", "/merge", map[string]any{"authors": []any{}, "x-note": "bots"}),
		op("add", "/merged", map[string]any{"at": id, "x-by": "release"}),
		op("add", "/cleanup", map[string]any{"merged": "P7D", "x-why": "short"}),
		op("add", "/roles", map[string]any{"editor": map[string]any{"can": strs([]string{"read"}), "move": true, "label": "Editors"}}),
	), ""), 201)
	doc := e.get("/ns/docs/rev/" + e.nsHead("docs")).Obj()
	if doc["catalog"].(map[string]any)["x-label"] != "Season" || doc["merge"].(map[string]any)["x-note"] != "bots" {
		t.Fatalf("document %v", doc)
	}
	for ptr, patch := range map[string]map[string]any{
		"/catalog/label":        op("replace", "/catalog", map[string]any{"label": "Season"}),
		"/catalogs/cat/since":   op("replace", "/catalogs", map[string]any{"cat": map[string]any{"since": "2025"}}),
		"/catalogs/X-desk":      op("replace", "/catalogs", map[string]any{"X-desk": map[string]any{}}),
		"/merge/note":           op("replace", "/merge", map[string]any{"authors": []any{}, "note": "bots"}),
		"/merged/by":            op("replace", "/merged", map[string]any{"at": id, "by": "release"}),
		"/cleanup/why":          op("replace", "/cleanup", map[string]any{"why": "short"}),
		"/merge/authors/0":      op("replace", "/merge", map[string]any{"authors": []any{map[string]any{"sub": "a", "kid": "k", "x-n": 1.0}}}),
		"/catalogs/cat/place/0": op("replace", "/catalogs", map[string]any{"cat": map[string]any{"place": strs([]string{"desk"})}}),
		"/cleanup/merged":       op("replace", "/cleanup", map[string]any{"merged": "a week"}),
		"/abandoned":            op("add", "/abandoned", "yes"),
		"/notes":                op("add", "/notes", "x"),
	} {
		r := e.patchNS("docs", ops(patch), "")
		expectCode(t, r, 422, "invalid")
		if got := errPointer(t, r); got != ptr {
			t.Errorf("%s: pointer %q: %s", ptr, got, r.Body)
		}
	}
}
