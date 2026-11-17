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

// Scenario 135 (SERVICES §A.4 Unavailable namespaces, v0.85: purged,
// "410 (purged), once the read check passes against the last namespace
// document the service read"), for a sealed namespace, whose document is
// 410 too once it is purged, so that nothing but what the index read
// before judges a cookie. The index has applied a change to the key
// behind a reader's cookie, and sec is then purged: a query under that
// cookie is 403, with no head, not 410; under a cookie exchanged after
// the change, which still passes, it is 410 purged with the purge's
// head. Before v0.85 the first got the 410 too, no read under it having
// come between the change and the purge.
func TestV085EndedCookieSealedPurged(t *testing.T) {
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
	reader := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})
	exchange := func() (string, []*http.Cookie) {
		t.Helper()
		r := p37Do(t, x, "POST", "/edge-grants", reader, "", nil, "")
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.body)
		}
		for _, p := range r.body["prefixes"].([]any) {
			if strings.HasPrefix(p.(string), "/sec/g/") {
				return p.(string) + "?q=secret", r.cookies
			}
		}
		t.Fatalf("no prefix for sec: %v", r.body)
		return "", nil
	}
	path, before := exchange()
	if got, _ := p37Follow(t, x, path, before, ""); got.status != 200 {
		t.Fatalf("under the cookie: %d %v", got.status, got.body)
	}
	// The key behind the cookie changes, and the index applies it; no
	// read under the cookie comes before the purge.
	z := x.ix.Checkpoint("sec")
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/keys/0/maxTtl", "value": "PT2H"}}))
	waitFor(t, "the index applies the key's change", func() bool { return x.ix.Checkpoint("sec") != z })
	x.ix.ExpireGrantChecks()
	path2, after := exchange()
	if path2 != path {
		t.Fatalf("her prefix changed with the key's maxTtl: %s, was %s", path2, path)
	}
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.PurgeNamespace(ctx, "sec", must(w.NSHead(ctx, "sec")).ID))
	waitFor(t, "the purge", func() bool { return x.ix.Checkpoint("sec") == purged })
	x.ix.ExpireGrantChecks()
	if got, _ := p37Follow(t, x, path, before, ""); got.status != 403 || got.body["head"] != nil {
		t.Errorf("under the cookie the key's change ended, once sec is purged: %d %v, want 403", got.status, got.body)
	}
	if got, _ := p37Follow(t, x, path, after, ""); got.status != 410 || got.body["code"] != "purged" || got.body["head"] != purged {
		t.Errorf("under the cookie that still passes, once sec is purged: %d %v, want 410 purged", got.status, got.body)
	}
}
