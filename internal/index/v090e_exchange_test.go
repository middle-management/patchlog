package index_test

import (
	"strings"
	"testing"
	"time"
)

// SERVICES §A.4 Coverage ("It leaves out namespaces not yet reached,
// purged ones, and sealed or end-to-end ones whose keys it lacks. Only a
// reader who may see none of the namespaces gets 401 or 403 ..."), with
// "The exchange refuses only as Coverage and Private namespaces say" and
// Unavailable namespaces ("404, at its exchange too, which mints no cookie
// and answers 404 only where no other refusal is 401 or 403"): the
// index's exchange judges each namespace a grant names alone. One it
// doesn't follow is left out, minting no cookie for it, as one the grant
// can't read is (TestV076AccessExchangePerNamespace); only a grant left
// with no edge grant is refused, 404 where no refusal is 401 or 403. A
// grant naming docs, which the index follows and li reads, and docs-b,
// which it doesn't follow, is exchanged for docs's prefixes alone.
func TestV090EExchangeLeavesOutUnfollowed(t *testing.T) {
	t.Parallel()
	d, _ := newV86Branch(t)
	v86Restart(d, []string{"docs"}, false)
	both := d.k1.Grant(d.t, d.s.Now(), "user:li", []string{"docs", "docs-b"}, []string{"read"},
		map[string]any{"roles": []any{"reader"}, "exp": d.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	r := p37Do(t, d.x, "POST", "/edge-grants", both, "", nil, "")
	if r.status != 200 || len(r.cookies) == 0 {
		t.Fatalf("exchange naming docs and the unfollowed docs-b: %d %v, %d cookies; want 200 for docs", r.status, r.body, len(r.cookies))
	}
	var docs bool
	for _, p := range r.body["prefixes"].([]any) {
		switch s := p.(string); {
		case strings.HasPrefix(s, "/docs-b/"):
			t.Errorf("a prefix for the unfollowed docs-b: %s", s)
		case strings.HasPrefix(s, "/docs/view/"):
			docs = true
		}
	}
	if !docs {
		t.Errorf("no /docs/view/ prefix: %v", r.body["prefixes"])
	}
	if q := p37Do(t, d.x, "GET", "/docs-b?q=word", both, "", nil, ""); q.status != 404 {
		t.Errorf("a docs-b query: %d %v, want 404", q.status, q.body)
	}
	if r := p37Do(t, d.x, "POST", "/edge-grants", v86GrantFor(d, "docs-b"), "", nil, ""); r.status != 404 || len(r.cookies) != 0 {
		t.Errorf("exchange naming docs-b alone: %d %v, %d cookies; want 404 and none", r.status, r.body, len(r.cookies))
	}
}
