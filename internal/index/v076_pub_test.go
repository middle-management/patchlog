package index_test

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// pub76Cookie exchanges a partial reader's grant of matches at w's index
// and returns its /matches/g/{gs} prefix and cookies, read once under them.
func pub76Cookie(t *testing.T, w *v75x) (string, []*http.Cookie) {
	t.Helper()
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
	if got, _ := p37Follow(t, w.x, prefix, r.cookies, ""); got.status != 200 || strings.Join(p37Hits(got.body), ",") != "derby,shared" {
		t.Fatalf("under the cookie: %d %v", got.status, got.body)
	}
	return prefix, r.cookies
}

// TestV076PubKeyReplaced (FSVC-7; §B.11.9 gs: a gs cookie is 403 where "a
// key or role they came from is gone or, as §C.4 judges a base's keys, no
// longer accepted"; §C.4: a shared kid is accepted "only while the base
// has it with the same pub"): a partial reader's cookie for
// reads:matches:g:{gs}, exchanged through catalog-01, is 403 "exchange the
// grant again" once matches gives catalog-01 another pub, its scope,
// requireAt and roles unchanged. Before v0.76 edge_gs kept only the kid,
// and the cookie was still served.
func TestV076PubKeyReplaced(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	prefix, cookies := pub76Cookie(t, w)
	doc := must(w.admin.NSDoc(ctx, "matches", w.head("matches"))).Value
	keys := doc["keys"].([]any)
	old := keys[1].(map[string]any)
	e := clienttest.NewKey("catalog-01").Entry("read")
	for k, v := range old {
		if k != "pub" {
			e[k] = v
		}
	}
	if e["pub"] == old["pub"] {
		t.Fatal("the same pub")
	}
	keys[1] = e
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": keys}}))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
	got, _ := p37Follow(t, w.x, prefix, cookies, "")
	if got.status != 403 || !strings.Contains(got.body["message"].(string), "exchange the grant again") {
		t.Errorf("under the cookie once catalog-01's pub changed: %d %v", got.status, got.body)
	}
}

// TestV076PubNoneStored (FSVC-7, §B.11.9 gs): a g: marker whose key was
// recorded without its pub (migration 006 gives such a row an empty pub),
// or recorded before edge_gs_keys kept every key a marker's cookies came
// from (migration 007: no row there), is 403 under its cookie, until the
// reader exchanges again, which records the key and its pub.
func TestV076PubNoneStored(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, q string }{
		{"no pub", `UPDATE edge_gs_keys SET pub = ''`},
		{"before 007", `DELETE FROM edge_gs_keys`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newV75X(t, false)
			prefix, cookies := pub76Cookie(t, w)
			restart := func() {
				w.x = startSvcWith(t, w.x.core, svcOpts{db: w.x.dbPath, ns: []string{"matches"}, untyped: true, now: w.s.Now},
					func(o *indexOpts) {
						o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
					})
				w.x.caughtUp("matches")
			}
			w.x.stop()
			sdb := must(sql.Open("sqlite", sqlitedsn.DSN(w.x.dbPath, "_pragma=busy_timeout(10000)")))
			res := must(sdb.Exec(c.q))
			sdb.Close()
			if n := must(res.RowsAffected()); n != 1 {
				t.Fatalf("%d edge_gs_keys rows", n)
			}
			restart()
			if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 403 {
				t.Errorf("under a cookie whose key isn't recorded with its pub: %d %v", got.status, got.body)
			}
			if c.name == "no pub" {
				return // the row without a pub stays until its cookie expires
			}
			if prefix2, _ := pub76Cookie(t, w); prefix2 != prefix {
				t.Errorf("exchanged again: %s, was %s", prefix2, prefix)
			}
		})
	}
}

// TestV076PubSharedMarker (§B.11.9 gs, §C.4): a g: marker's subjects
// include catvis.KeySubject(kid, pub), so readers whose grants come from
// different keys, or from one kid under different pubs, never share a
// marker. Reader A's cookie came from catalog-01's old pub; once matches
// gives catalog-01 another pub, A's cookie is 403, and stays 403 after
// reader B, with the same subjects and rules, exchanges a grant signed under
// the new pub: B gets a marker of its own, which reads. Before v0.76, B's
// exchange overwrote the shared marker's pub and A's cookie was served
// again. edge_gs_keys still keeps every key of a marker, for readers who
// share one key.
func TestV076PubSharedMarker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	prefix, cookies := pub76Cookie(t, w)
	doc := must(w.admin.NSDoc(ctx, "matches", w.head("matches"))).Value
	keys := doc["keys"].([]any)
	old := keys[1].(map[string]any)
	nk := clienttest.NewKey("catalog-01")
	e := nk.Entry("read")
	for k, v := range old {
		if k != "pub" {
			e[k] = v
		}
	}
	keys[1] = e
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": keys}}))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
	if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 403 {
		t.Fatalf("A under its cookie once catalog-01's pub changed: %d %v", got.status, got.body)
	}
	w.cat = nk
	b := w.reader("user:other", []any{"fans"})
	r := p37Do(t, w.x, "POST", "/edge-grants", b, "", nil, "")
	if r.status != 200 {
		t.Fatalf("B's exchange: %d %v", r.status, r.body)
	}
	var bp string
	for _, p := range r.body["prefixes"].([]any) {
		if strings.HasPrefix(p.(string), "/matches/g/") {
			bp = p.(string)
		}
	}
	if bp == "" || bp == prefix {
		t.Fatalf("B's prefixes %v: want a /matches/g/ prefix other than A's %s", r.body["prefixes"], prefix)
	}
	if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 403 || !strings.Contains(got.body["message"].(string), "exchange the grant again") {
		t.Errorf("A under its cookie (from the replaced pub) after B exchanged: %d %v", got.status, got.body)
	}
	if got, _ := p37Follow(t, w.x, bp, r.cookies, ""); got.status != 200 {
		t.Errorf("B under its own cookie: %d %v", got.status, got.body)
	}
	if got := p37Do(t, w.x, "GET", "/matches?q=derby", b, "", nil, ""); got.status != 302 {
		t.Errorf("B's grant in Authorization: %d %v", got.status, got.body)
	}
}
