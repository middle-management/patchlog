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
