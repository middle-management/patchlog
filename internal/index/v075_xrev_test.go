package index_test

import (
	"context"
	"strings"
	"testing"
)

// Cross-package review of v0.75 (§B.11.9, §A.4): regressions.

// TestV075XrevIndexCookieAfterRoleLosesRead (§B.11.9 gs, §A.4, §2.1): the
// index's cookie for reads:matches:g:{gs} is judged from what the exchange
// recorded, and is 403 at an at where the rules its marker digests differ,
// of each effective role that lists read among them. Folders give fans the
// role viewer; the reader's grant reads matches only through its role
// reader. Once reader no longer lists read, the grant reads nothing there
// (403), and neither does the cookie.
func TestV075XrevIndexCookieAfterRoleLosesRead(t *testing.T) {
	t.Parallel()
	v75xCookieLosesRead(t, "/roles/reader/can")
}

// TestV075XrevIndexCookieAfterKeyLosesRead: likewise once the key that
// signed the grant no longer lists read (§C.2).
func TestV075XrevIndexCookieAfterKeyLosesRead(t *testing.T) {
	t.Parallel()
	v75xCookieLosesRead(t, "/keys/1/can")
}

// v75xCookieLosesRead replaces can at path in matches' document with
// [create] once a reader's cookie reads derby and shared: neither its
// grant nor the cookie reads matches then.
func v75xCookieLosesRead(t *testing.T, path string) {
	ctx := context.Background()
	w := newV75X(t, false)
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
		[]any{map[string]any{"op": "add", "path": "/roles/viewer", "value": map[string]any{"can": []any{"read"}}}}))
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:fans": []any{"viewer"}}})
	w.x.caughtUp("matches")
	fan := w.reader("user:fan", []any{"fans"})
	r := p37Do(t, w.x, "POST", "/edge-grants", fan, "", nil, "")
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	var prefix string
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/matches/") {
			prefix = p.(string)
		}
	}
	got, _ := p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("under the cookie: %d %v", got.status, got.body)
	}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
		[]any{map[string]any{"op": "replace", "path": path, "value": []any{"create"}}}))
	w.x.caughtUp("matches")
	if g := w.x.raw("/matches", fan); g.status != 403 {
		t.Fatalf("the grant after %s lost read: %d %v", path, g.status, g.body)
	}
	got, _ = p37Follow(t, w.x, prefix, r.cookies, "")
	if got.status != 403 {
		t.Errorf("under the cookie once %s lost read: %d %v", path, got.status, p37Hits(got.body))
	}
}

// TestV075XrevCheckpointSharedAt (§B.11.9 gs, §B.11.5): a grant reads at
// its own gs as of the URL's at, which the index judges from the
// checkpoint it holds for that at. Where it follows both a covered content
// namespace and the catalog that decides it, their combined checkpoints
// are over the same members at the same ns_ids, so they share an at: the
// catalog's checkpoint, computed for one of its readers, must not stand in
// for the content namespace's, so that TestV075IndexOldGsAt's older-at
// redirect still holds.
func TestV075XrevCheckpointSharedAt(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	x := w.start(false, "cat-season", "matches")
	w.x = x
	fan := w.reader("user:fan", []any{"fans"})
	_, gs1, at1 := w.pointer("/matches?limit=3", fan)
	r := x.raw("/cat-season", w.catReader("user:fan", "fans"))
	loc := r.header.Get("Location")
	if r.status != 302 || !strings.HasPrefix(loc, "/cat-season/g/") {
		t.Fatalf("pointer: %d %s %v", r.status, loc, r.body)
	}
	if p := strings.Split(strings.SplitN(loc, "?", 2)[0], "/"); p[5] != at1 {
		t.Fatalf("cat-season's at %s, matches' %s: not shared", p[5], at1)
	}
	w.put("cat-season", "fanclub", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"user:fan": []any{"reader"}}})
	x.caughtUp("cat-season")
	loc2, gs2, at2 := w.pointer("/matches?limit=1", fan)
	if gs1 == gs2 || at1 == at2 {
		t.Fatalf("gs %s at %s unchanged", gs2, at2)
	}
	old := "/matches/g/" + gs1 + "/at/" + at1 + "?limit=1"
	if r := x.raw(old, fan); r.status != 302 || r.header.Get("Location") != loc2 {
		t.Errorf("GET %s: %d %q %v (want 302 to %s, as TestV075IndexOldGsAt)", old, r.status, r.header.Get("Location"), r.body, loc2)
	}
}
