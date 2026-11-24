package index_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/index"
)

// v0.90 SERVICES §A.4 Private namespaces ("Other moves of the namespace
// document while an exchange is judged are retried, the exchange
// answering 503 only after a bounded number of tries"; v0.89 Open 2): a
// config write that changes no key or role the view draws on (it adds a
// role without read), landing while li's exchange is judged, is retried,
// and her exchange mints a cookie; only a document that moves at every try is 503 (behind),
// minting none. Until v0.90 any move was 503 at once. Not parallel: it
// sets a hook of the package.
func TestV090BExchangeRetriesAMove(t *testing.T) {
	d := newV77Docs(t)
	ctx := context.Background()
	moves := 0
	move := func(string) {
		moves++
		must(d.w.PatchConfig(ctx, "docs", must(d.w.NSHead(ctx, "docs")).Config,
			[]any{map[string]any{"op": "add", "path": "/roles/other" + string(rune('a'+moves)), "value": map[string]any{"can": []any{"append"}}}}))
		d.x.ix.ExpireGrantChecks()
	}
	t.Cleanup(func() { index.SetExchangeEntryHook(nil) })

	// One move, at the first try: judged again, and minted.
	index.SetExchangeEntryHook(func(ns string) {
		if moves == 0 {
			move(ns)
		}
	})
	r := p37Do(t, d.x, "POST", "/edge-grants", d.reader(d.k1), "", nil, "")
	if r.status != 200 || len(r.cookies) == 0 || moves != 1 {
		t.Fatalf("exchange with one move: %d %v, %d cookies, %d moves; want 200 with a cookie", r.status, r.body, len(r.cookies), moves)
	}

	// A move at every try: 503 behind, no cookie, after a bounded number.
	moves = 0
	index.SetExchangeEntryHook(move)
	r = p37Do(t, d.x, "POST", "/edge-grants", d.reader(d.k1), "", nil, "")
	if r.status != 503 || r.body["code"] != "behind" || len(r.cookies) != 0 {
		t.Fatalf("exchange moved at every try: %d %v, %d cookies; want 503 behind", r.status, r.body, len(r.cookies))
	}
	if moves < 2 || moves > 5 {
		t.Fatalf("%d tries, want a few", moves)
	}
}
