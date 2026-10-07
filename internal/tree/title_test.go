package tree_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// entryOf finds the entry with the given name in a listing's list.
func entryOf(t *testing.T, list any, name string) map[string]any {
	t.Helper()
	for _, x := range list.([]any) {
		if m := x.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no entry %s in %v", name, list)
	return nil
}

// TestItemTitles: catalog.title is a pointer into an item's head whose
// string listings carry as title (§B.5).
func TestItemTitles(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	w.folder(t, "root", "Root")
	doc := func(name string, d map[string]any) {
		t.Helper()
		must(w.c.CreateDoc(ctx, "matches", name, d))
	}
	doc("derby", map[string]any{"title": "Derby", "alt": map[string]any{"name": "The Derby"}, "n": 7})
	doc("opener", map[string]any{"alt": map[string]any{"name": "Opener"}})
	doc("numeric", map[string]any{"title": 5})
	w.place(t, "matches.derby", "root@a1")
	w.place(t, "matches.opener", "root@a0")
	w.place(t, "matches.numeric", "root@a2")
	must(w.c.CreateDoc(ctx, "cat", "matches.own", map[string]any{"title": "Own", "parents": parents("root@a3")}))
	doc("own", map[string]any{"title": "Theirs"})

	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, w.c, svcOpts{db: db})
	x.caughtUp("cat", "matches")
	children := func(s *svc) any { return s.get("/cat/children?of=root", "")["children"] }
	if e := entryOf(t, children(x), "matches.derby"); e["title"] != nil {
		t.Errorf("title without a pointer: %v", e)
	}
	setPtr := func(op, v any) {
		t.Helper()
		h := must(w.c.NSHead(ctx, "cat"))
		must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": op, "path": "/catalog/title", "value": v}}))
		x.caughtUp("cat")
	}
	titleOf := func(s *svc, name string) any { return entryOf(t, children(s), name)["title"] }

	// Naming a pointer reads the heads that are already there.
	setPtr("add", "/title")
	if got := titleOf(x, "matches.derby"); got != "Derby" {
		t.Errorf("derby: %v", got)
	}
	if got := titleOf(x, "matches.opener"); got != nil {
		t.Errorf("no member at the pointer: %v", got)
	}
	if got := titleOf(x, "matches.numeric"); got != nil {
		t.Errorf("only strings: %v", got)
	}
	// The placement's own title wins.
	if got := titleOf(x, "matches.own"); got != "Own" {
		t.Errorf("own title: %v", got)
	}
	// A head change moves the title (and the listing's checkpoint).
	w.replace(t, "matches", "derby", "/title", "Derby day")
	x.caughtUp("matches")
	if got := titleOf(x, "matches.derby"); got != "Derby day" {
		t.Errorf("after head change: %v", got)
	}
	// New items are read as they come.
	doc("late", map[string]any{"title": "Late"})
	w.place(t, "matches.late", "root@a5")
	x.caughtUp("cat", "matches")
	if got := titleOf(x, "matches.late"); got != "Late" {
		t.Errorf("late: %v", got)
	}
	// Changing the pointer reads every head again.
	setPtr("replace", "/alt/name")
	if got := titleOf(x, "matches.derby"); got != "The Derby" {
		t.Errorf("derby after pointer change: %v", got)
	}
	if got := titleOf(x, "matches.opener"); got != "Opener" {
		t.Errorf("opener after pointer change: %v", got)
	}
	if got := titleOf(x, "matches.late"); got != nil {
		t.Errorf("late after pointer change: %v", got)
	}
	// It survives a restart.
	x.stop()
	y := startSvc(t, w.c, svcOpts{db: db})
	y.caughtUp("cat", "matches")
	if got := titleOf(y, "matches.opener"); got != "Opener" {
		t.Errorf("after restart: %v", got)
	}
	// A deleted item leaves the listing (its placement dangles).
	w.del(t, "matches", "opener")
	y.caughtUp("matches")
	for _, x := range children(y).([]any) {
		if x.(map[string]any)["name"] == "matches.opener" {
			t.Errorf("deleted item listed: %v", x)
		}
	}
	// The core refuses a title that isn't a JSON Pointer.
	h := must(w.c.NSHead(ctx, "cat"))
	for _, bad := range []any{"alt/name", 3, "/a~2"} {
		if _, err := w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "replace", "path": "/catalog/title", "value": bad}}); !isStatus(err, 422) {
			t.Errorf("title %v: %v", bad, err)
		}
	}
	// Dropping it takes the titles away.
	h = must(w.c.NSHead(ctx, "cat"))
	must(w.c.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "remove", "path": "/catalog/title"}}))
	y.caughtUp("cat")
	if got := titleOf(y, "matches.derby"); got != nil {
		t.Errorf("after removing the pointer: %v", got)
	}
}

func isStatus(err error, status int) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == status
}
