package index_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// V82-05 (v0.82), SVC-10 and SPEC §8.5: the 410 of a purged namespace,
// with the purge's head, is for a request that passes the read check. A
// cookie that had ended (SERVICES §A.4 gs, §B.11.9 gs), or that no key
// was recorded for with its entry, doesn't pass it once the namespace is
// purged either: it is 403 as before, and a cookie that held is 410.

// v82Hows are the states a cookie is in when its namespace is purged,
// and the status of a read under it then: change, if set, is a patch of
// the namespace's document that ends it.
func v82Hows(change map[string]any) map[string]int {
	hows := map[string]int{"holds": 410, "no row": 403, "no entry": 403}
	if change != nil {
		hows["key changed"] = 403
	}
	return hows
}

// v82Plant puts the index's records of its cookies in state how.
func v82Plant(t *testing.T, x *svc, how string) {
	t.Helper()
	ctx := context.Background()
	switch how {
	case "no row": // as every cookie minted before migration 011
		if n := must(x.ix.ExecForTest(ctx, `DELETE FROM edge_gs_keys`)); n == 0 {
			t.Fatal("no edge_gs_keys row")
		}
	case "no entry": // an exchange that couldn't vouch for its key's entry
		if n := must(x.ix.ExecForTest(ctx, `UPDATE edge_gs_keys SET entry = ''`)); n == 0 {
			t.Fatal("no edge_gs_keys row")
		}
	}
}

// TestV082EndedCookiePurged: cookies of reads:docs (whole) and of
// reads:docs:scope:{digest} (scope), whose namespace's document the core
// still serves once it is purged: each is judged by it as before the
// purge. An anonymous request, and a grant by a key docs never had, are
// 401 throughout.
func TestV082EndedCookiePurged(t *testing.T) {
	t.Parallel()
	stranger := clienttest.NewKey("stranger")
	for name, setup := range map[string]func(*testing.T) *v77docs{"whole": newV82Whole, "scope": newV77Docs} {
		for how, want := range v82Hows(map[string]any{"op": "remove", "path": "/keys/1"}) {
			t.Run(name+"/"+how, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				d := setup(t)
				prefixes, cookies := d.exchange(d.reader(d.k1))
				paths := v82Paths(prefixes)[:1]
				if got := v82Status(t, d.x, paths, cookies); got != "OK" {
					t.Fatalf("under the cookie: %s", got)
				}
				if how == "key changed" {
					d.patch(map[string]any{"op": "remove", "path": "/keys/1"})
				}
				v82Plant(t, d.x, how)
				if got := v82Status(t, d.x, paths, cookies); (got == "OK") != (how == "holds") {
					t.Fatalf("under the cookie before the purge: %s", got)
				}
				d.patch(map[string]any{"op": "add", "path": "/frozen", "value": true})
				purger := d.s.Client(t, client.WithBearer(d.admin.Grant(t, d.s.Now(), "user:root", []string{"docs"}, []string{"purge-ns"})))
				head := must(purger.PurgeNamespace(ctx, "docs", must(d.w.NSHead(ctx, "docs")).ID))
				d.x.caughtUp("docs")
				d.x.ix.ExpireGrantChecks()
				if anon, _ := p37Follow(t, d.x, paths[0], nil, ""); anon.status != 401 {
					t.Errorf("an anonymous request: %d %v", anon.status, anon.body)
				}
				if r := p37Do(t, d.x, "GET", "/docs?q=word", stranger.Grant(t, d.s.Now(), "user:x", []string{"docs"}, []string{"read"}), "", nil, ""); r.status != 401 {
					t.Errorf("a grant by an unknown key: %d %v", r.status, r.body)
				}
				got, _ := p37Follow(t, d.x, paths[0], cookies, "")
				if got.status != want || want == 410 && got.body["head"] != head || want == 403 && got.body["head"] != nil {
					t.Errorf("under the cookie once docs is purged: %d %v, want %d", got.status, got.body, want)
				}
			})
		}
	}
}

// TestV082EndedGCookiePurged: the same for a cookie of
// reads:matches:g:{gs} (§B.11.9), which has no checkpoint left to be
// judged at once matches is purged: by the document matches had.
func TestV082EndedGCookiePurged(t *testing.T) {
	t.Parallel()
	for how, want := range v82Hows(map[string]any{}) {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			w := newV75X(t, false)
			prefix, cookies := pub76Cookie(t, w)
			if how == "key changed" {
				must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config,
					[]any{map[string]any{"op": "replace", "path": "/keys/1/maxTtl", "value": "PT14M"}}))
				w.x.caughtUp("matches")
				w.x.ix.ExpireGrantChecks()
			}
			v82Plant(t, w.x, how)
			if got, _ := p37Follow(t, w.x, prefix, cookies, ""); (got.status == 200) != (how == "holds") || got.status != 200 && got.status != 403 {
				t.Fatalf("under the cookie before the purge: %d %v", got.status, got.body)
			}
			v82PurgeNS(w, "matches")
			w.x.caughtUp("matches")
			w.x.ix.ExpireGrantChecks()
			got, _ := p37Follow(t, w.x, prefix, cookies, "")
			if got.status != want || want == 410 && got.body["head"] != w.head("matches") || want == 403 && got.body["head"] != nil {
				t.Errorf("under the cookie once matches is purged: %d %v, want %d", got.status, got.body, want)
			}
		})
	}
}

// TestV082EndedCookieSealedPurged: a purged sealed namespace's document
// is 410 at the core too (§8.5), so nothing is left to judge a cookie's
// keys by: one recorded with its key's entry passes, and gets the 410
// with the purge's head; one with no key recorded, or recorded without
// its entry, never held, and is 403.
func TestV082EndedCookieSealedPurged(t *testing.T) {
	t.Parallel()
	for how, want := range v82Hows(nil) {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec",
				map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec"}, []string{"read", "create", "config", "purge-ns"})),
				client.WithKeys(client.NewKeys(nil)))
			must(createNonced(w, "sec", "a", map[string]any{"title": "secret"}))
			jwk, priv, err := seal.GenerateRecipient()
			if err != nil {
				t.Fatal(err)
			}
			ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"}, map[string]any{"enc": jwk})),
				client.WithKeys(client.NewKeys(priv)))
			x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now}, func(o *indexOpts) {
				o.Recipient = priv
				o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate
			})
			x.caughtUp("sec")
			r := p37Do(t, x, "POST", "/edge-grants", k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"}), "", nil, "")
			if r.status != 200 {
				t.Fatalf("exchange: %d %v", r.status, r.body)
			}
			var path string
			for _, p := range r.body["prefixes"].([]any) {
				if strings.HasPrefix(p.(string), "/sec/g/") {
					path = p.(string) + "?q=secret"
				}
			}
			status := func() (int, map[string]any) {
				t.Helper()
				got, _ := p37Follow(t, x, path, r.cookies, "")
				return got.status, got.body
			}
			if st, b := status(); st != http.StatusOK {
				t.Fatalf("under the cookie: %d %v", st, b)
			}
			v82Plant(t, x, how)
			if st, b := status(); (st == 200) != (how == "holds") {
				t.Fatalf("under the cookie before the purge: %d %v", st, b)
			}
			must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
			purged := must(w.PurgeNamespace(ctx, "sec", must(w.NSHead(ctx, "sec")).ID))
			waitFor(t, "the purge", func() bool { return x.ix.Checkpoint("sec") == purged })
			x.ix.ExpireGrantChecks()
			if st, b := status(); st != want || want == 410 && b["head"] != purged || want == 403 && b["head"] != nil {
				t.Errorf("under the cookie once sec is purged: %d %v, want %d", st, b, want)
			}
		})
	}
}
