package index_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// w4x (P36 x P37), Addendum E Levels, §E.2.6: TestV073W4IntIndexAcrossRaiseFromSealed
// with a restart. The first run replays the log from genesis and asks for
// e#1 while its Info still says sealed; restarted on its database, past
// the raise, the index's Info says e2e, and it takes e#1, which no keyring
// entry names, as the key of an epoch before the raise, as /keys gives it
// without a sender (derived.Keys.preRaiseKey), rather than through
// E2E.SealKey, which refuses keys without a sender. A query that shows the
// pre-raise hit is sealed under e#1 again.
func TestV073W4xIndexRestartAfterRaiseFromSealed(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	t0 := s.Now()
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "public", "keys": []any{admin.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	idxJWK, idxPriv, _ := seal.GenerateRecipient()
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"e", "schemas"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": adminJWK, "nbf": t0.Format(time.RFC3339)})))
	ad := ac.E2E(adminPriv)
	sch := must(ac.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	must(ac.Create(ctx, "e", "a", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "zq a"}},
		map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}))
	s.Clock.Advance(time.Minute)
	h := must(ac.NSHead(ctx, "e"))
	must(ac.PatchConfig(ctx, "e", h.Config, []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}))
	must(ad.InitKeyring(ctx, "e", idxPriv.PublicKey()))
	must(ad.CreateDocSealed(ctx, "e", "b", map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "zq b"}))
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e"}, []string{"read"}, map[string]any{"enc": idxJWK, "nbf": t0.Format(time.RFC3339)})),
		client.WithKeyringSenders(adminPriv.PublicKey()), client.WithKeys(client.NewKeys(idxPriv)))
	o := svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, untyped: true, now: s.Now}
	x := startSvcWith(t, ic, o, func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	f := x.fetch("/e?q=zq", "")
	if got := p37Kids(t, f.body); fmt.Sprint(got) != "map[a:e#1 b:e#2]" {
		t.Fatalf("first run: kids %v (%s)", got, f.body)
	}
	x.stop()
	y := startSvcWith(t, ic, o, func(o *indexOpts) { o.Recipient = idxPriv })
	y.caughtUp("e")
	var r resp
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if r = y.answerOf("/e?q=zq&limit=5", ""); r.status == 200 {
			break
		}
	}
	if r.status != 200 {
		t.Fatalf("after a restart past the raise: %d %v", r.status, r.body)
	}
	g := y.fetch("/e?q=zq&limit=5", "")
	if got := p37Kids(t, g.body); fmt.Sprint(got) != "map[a:e#1 b:e#2]" {
		t.Fatalf("after a restart past the raise: kids %v (%s)", got, g.body)
	}
}
