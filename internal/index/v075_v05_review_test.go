package index_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
)

// exchange exchanges tok at the index and returns its prefixes for
// matches and /_refs, and the cookies.
func (w *v75x) exchange(tok string) (ns, refs string, cookies []*http.Cookie) {
	w.t.Helper()
	r := p37Do(w.t, w.x, "POST", "/edge-grants", tok, "", nil, "")
	if r.status != 200 {
		w.t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	for _, p := range r.body["prefixes"].([]any) {
		switch s := p.(string); {
		case strings.HasPrefix(s, "/matches/"):
			ns = s
		case strings.HasPrefix(s, "/_refs/"):
			refs = s
		}
	}
	if ns == "" || refs == "" {
		w.t.Fatalf("prefixes %v", r.body["prefixes"])
	}
	return ns, refs, r.cookies
}

// TestV075IndexScopeCookieCovered (§A.4, §B.11.9): an edge grant for the
// marker reads:matches:scope:{digest}, issued while §B.11.9 didn't cover
// matches, reads by rules alone; once matches is covered, a partial
// reader's marker there is reads:matches:g:{gs}, its hits filtered by
// visibility, so the cookie is 403, as across namespaces, until the
// reader exchanges its grant again. Before, it went on reading opener
// (never placed) and secret (under an inherit false folder).
func TestV075IndexScopeCookieCovered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	// Since v0.77 a namespace whose catalogs names a catalog that doesn't
	// trust it gives a partial reader no marker (§A.4), so matches is
	// left uncovered by naming no catalog, and covered by naming
	// cat-season again.
	catalogs := func(v map[string]any) {
		cfg := must(w.admin.NSHead(ctx, "matches")).Config
		must(w.admin.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "replace", "path": "/catalogs", "value": v}}))
		w.x.caughtUp("matches")
		w.x.ix.ExpireGrantChecks()
	}
	catalogs(map[string]any{})
	fan := w.reader("user:fan", []any{"fans"})
	prefix, refs, cookies := w.exchange(fan)
	if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,opener,secret,shared" {
		t.Fatalf("uncovered, under the cookie: %d %v", got.status, got.body)
	}
	if got, _ := p37Follow(t, w.x, refs+"?to=/r/target/x", cookies, ""); got.status != 200 || len(p37Hits(got.body)) != 4 {
		t.Fatalf("uncovered, /_refs under the cookie: %d %v", got.status, got.body)
	}
	catalogs(map[string]any{"cat-season": map[string]any{"place": []any{}}})
	if _, _, at := w.pointer("/matches", fan); at == w.x.ix.Checkpoint("matches") {
		t.Fatal("matches is not covered again")
	}
	for _, p := range []string{prefix, refs + "?to=/r/target/x"} {
		got, _ := p37Follow(t, w.x, p, cookies, "")
		if msg, _ := got.body["message"].(string); got.status != 403 || !strings.Contains(msg, "read filtered now") || got.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s once covered, under the scope cookie: %d %v", p, got.status, got.body)
		}
	}
	prefix, _, cookies = w.exchange(fan)
	if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Errorf("exchanged again: %d %v", got.status, got.body)
	}
}

// TestV075IndexOldGsAt (§A.4, §B.11.5, §B.11.9 gs): a grant reads at its
// own gs as of the URL's at. Once its deciding subjects change, so does
// its gs; at an older at the index still holds, under the gs the grant
// had there, an URL whose result isn't kept is redirected to the current
// at, a non-canonical form of a kept one to its canonical form, and one
// with min to the kept result that includes it, as at any older at; the
// kept result is served. Before, all but the last were 403. Another
// reader's gs, or an at the index doesn't hold under a gs other than the
// grant's current one, stays 403.
func TestV075IndexOldGsAt(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	intern := w.reader("user:intern", []any{"interns"})
	loc1, gs1, at1 := w.pointer("/matches?limit=3", fan)
	_, igs, _ := w.pointer("/matches", intern)
	mHead := w.x.ix.Checkpoint("matches")
	w.put("cat-season", "fanclub", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"user:fan": []any{"reader"}}})
	loc2, gs2, at2 := w.pointer("/matches?limit=1", fan)
	if gs1 == gs2 || at1 == at2 {
		t.Fatalf("gs %s at %s unchanged", gs2, at2)
	}
	old := "/matches/g/" + gs1 + "/at/" + at1
	if r := w.x.raw(loc1, fan); r.status != 200 {
		t.Errorf("the kept result: %d %v", r.status, r.body)
	}
	for _, c := range []struct{ path, want string }{
		{old + "?limit=1", loc2},
		{old + "?limit=%33", loc1},
		{old + "?limit=3&min=matches:" + mHead, loc1},
	} {
		r := w.x.raw(c.path, fan)
		if r.status != 302 || r.header.Get("Location") != c.want || r.header.Get("Cache-Control") != "private, no-store" {
			t.Errorf("GET %s: %d %q %v (want 302 to %s)", c.path, r.status, r.header.Get("Location"), r.body, c.want)
		}
	}
	for _, p := range []string{
		"/matches/g/" + igs + "/at/" + at1 + "?limit=3",
		"/matches/g/" + gs1 + "/at/" + ids.Of([]byte("never an at")).String() + "?limit=3",
	} {
		if r := w.x.raw(p, fan); r.status != 403 {
			t.Errorf("GET %s: %d %v (want 403)", p, r.status, r.body)
		}
	}
}

// TestV075IndexRefsOldGs (§A.4 Across namespaces, §B.11.5): /_refs's gs
// is as in §B.11.5, a grant's own as of the URL's at, its marker in a
// covered namespace depending on that at. Once the reader's deciding
// subjects change, a kept answer at the older at under the gs the grant
// had there is still served, and the form with a min it includes is
// redirected to it. Before, both were 403. Another reader's gs stays
// 403, as does an older at whose answer isn't kept, whose checkpoints
// the index can't tell.
func TestV075IndexRefsOldGs(t *testing.T) {
	t.Parallel()
	w := newV75X(t, false)
	fan := w.reader("user:fan", []any{"fans"})
	intern := w.reader("user:intern", []any{"interns"})
	at1, gs1, loc := w.x.refsPointer("?to=/r/target/x", fan)
	first := w.x.raw(loc, fan)
	if first.status != 200 {
		t.Fatalf("first: %d %v", first.status, first.body)
	}
	_, igs, _ := w.x.refsPointer("?to=/r/target/x", intern)
	cHead := w.head("cat-season")
	w.put("cat-season", "fanclub", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"user:fan": []any{"reader"}}})
	_, gs2, _ := w.x.refsPointer("?to=/r/target/x", fan)
	if gs1 == gs2 {
		t.Fatal("gs unchanged")
	}
	if r := w.x.raw(loc, fan); r.status != 200 || refsAllHits(r.body) != refsAllHits(first.body) || r.header.Get("X-Namespace-Revision") != at1 {
		t.Errorf("the kept answer at the grant's gs as of its at: %d %v", r.status, r.body)
	}
	if r := w.x.raw(loc+"&min=cat-season:"+cHead, fan); r.status != 302 || r.header.Get("Location") != loc {
		t.Errorf("with a min it includes: %d %q %v (want 302 to %s)", r.status, r.header.Get("Location"), r.body, loc)
	}
	for _, p := range []string{
		"/_refs/g/" + igs + "/at/" + at1 + "?to=%2Fr%2Ftarget%2Fx",
		"/_refs/g/" + gs1 + "/at/" + at1 + "?to=%2Fr%2Ftarget%2Fy",
	} {
		if r := w.x.raw(p, fan); r.status != 403 {
			t.Errorf("GET %s: %d %v (want 403)", p, r.status, r.body)
		}
	}
}
