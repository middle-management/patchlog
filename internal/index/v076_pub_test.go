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

// TestV076PubNoneStored (FSVC-7, §B.11.9 gs): a g: marker recorded before
// edge_gs kept the key's pub (migration 006 gives such a row an empty pub) is
// 403 under its cookie, until the reader exchanges again, which records
// the pub.
func TestV076PubNoneStored(t *testing.T) {
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
	res := must(sdb.Exec(`UPDATE edge_gs SET pub = ''`))
	sdb.Close()
	if n := must(res.RowsAffected()); n != 1 {
		t.Fatalf("%d edge_gs rows", n)
	}
	restart()
	if got, _ := p37Follow(t, w.x, prefix, cookies, ""); got.status != 403 {
		t.Errorf("under a cookie whose row has no pub: %d %v", got.status, got.body)
	}
	if prefix2, _ := pub76Cookie(t, w); prefix2 != prefix {
		t.Errorf("exchanged again: %s, was %s", prefix2, prefix)
	}
}
