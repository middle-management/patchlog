package index_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// TestSealedPurged (§8.5, §10): a sealed namespace's log, long-polls and
// documents are 410 purged once it is purged, with head its purge-ns
// entry. An indexer following it takes that as the purge, at that head,
// and so does one started after the purge; both then answer the purge's
// 410 as for any purged namespace.
func TestSealedPurged(t *testing.T) {
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
	withKey := func(o *indexOpts) { o.Recipient = priv }
	start := func() *svc {
		return startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now}, withKey)
	}
	x := start()
	x.caughtUp("sec")

	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	purged := must(w.PurgeNamespace(ctx, "sec", must(w.NSHead(ctx, "sec")).ID))
	if _, err := ic.NSLog(ctx, "sec", purged, ""); !client.IsPurged(err) {
		t.Fatalf("the sealed log after the purge: %v", err)
	}
	// The index can't read the configuration any more: the core makes the
	// read check, and answers the 410 only to a grant that passes it.
	reader := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"})
	writer := k.Grant(t, s.Now(), "user:n", []string{"sec"}, []string{"create"})
	for name, x := range map[string]*svc{"following": x, "started after": start()} {
		waitFor(t, name+": the purge", func() bool { return x.ix.Checkpoint("sec") == purged })
		if r := x.raw("/sec?q=secret", reader); r.status != 410 || r.body["code"] != "purged" || r.body["head"] != purged {
			t.Errorf("%s: %d %v", name, r.status, r.body)
		}
		for tok, want := range map[string]int{"": 401, writer: 403} {
			if r := x.raw("/sec?q=secret", tok); r.status != want {
				t.Errorf("%s: token %.10q: %d %v, want %d", name, tok, r.status, r.body, want)
			}
		}
		// Left out of /_refs, as any purged namespace.
		if r := x.raw("/_refs?to=%2Fr%2Fsec%2Fa", reader); r.status != 302 {
			t.Errorf("%s: /_refs: %d %v", name, r.status, r.body)
		}
	}
}
