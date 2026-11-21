package index_test

import (
	"context"
	"strings"
	"testing"
)

// TestV087GCookieEndedAtOldAt (§7.9 view: "Every cookie of a view is 403,
// at every URL, once an entry after its exchange changes those rules"):
// under a g: cookie, an at answered before the change is 403 too, and
// one from an exchange after the change reads there. The index ends
// a cookie's recorded entry as it applies the change (cookieEnds), so
// this guards the behaviour rather than a fix.
func TestV087GCookieEndedAtOldAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	r := p37Do(t, w.x, "POST", "/edge-grants", w.reader("user:al", []any{"fans"}), "", nil, "")
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	path := ""
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/matches/view/") {
			path = p.(string) + "?q=derby"
		}
	}
	if path == "" {
		t.Fatalf("no /matches/view/ prefix: %v", r.body)
	}
	got, at := p37Follow(t, w.x, path, r.cookies, "")
	if got.status != 200 || !strings.Contains(at, "/at/") {
		t.Fatalf("under the cookie: %d at %s", got.status, at)
	}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/keys/1/groups", "value": map[string]any{"deny": []any{"banned"}}}}))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
	if got := p37Do(t, w.x, "GET", at, "", "", r.cookies, ""); got.status != 403 {
		t.Errorf("the cookie at the at answered before the change: %d %v, want 403", got.status, got.body)
	}
	// A cookie from an exchange after the change isn't ended: it reads at
	// every at, the one from before the change included (SPEC-FEEDBACK
	// v0.87, settled 17).
	r2 := p37Do(t, w.x, "POST", "/edge-grants", w.reader("user:al", []any{"fans"}), "", nil, "")
	if r2.status != 200 {
		t.Fatalf("exchange again: %d %v", r2.status, r2.body)
	}
	if got := p37Do(t, w.x, "GET", at, "", "", r2.cookies, ""); got.status != 200 {
		t.Errorf("the new cookie at the at answered before the change: %d %v, want 200", got.status, got.body)
	}
}
