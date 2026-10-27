package index_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.73 §E.2.6, Addendum E Levels (P35 x P37; ENC-32, IX-25): an index
// following a namespace raised from sealed to e2e seals hits on documents
// from before the raise under the epoch those revisions are served under,
// the epoch before the raise, whose key /keys gives as at E2 with no
// sender, and hits on documents written end to end under their sealed
// op's epoch; the hits of the two epochs come per entry.
func TestV073W4IntIndexAcrossRaiseFromSealed(t *testing.T) {
	t.Parallel()
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
	// The service's grant reaches back before the raise (§E.2.3, Levels).
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"e"}, []string{"read"}, map[string]any{"enc": idxJWK, "nbf": t0.Format(time.RFC3339)})),
		client.WithKeyringSenders(adminPriv.PublicKey()), client.WithKeys(client.NewKeys(idxPriv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	f := x.fetch("/e?q=zq", "")
	if got := p37Kids(t, f.body); fmt.Sprint(got) != "map[a:e#1 b:e#2]" {
		t.Fatalf("kids %v (%s)", got, f.body)
	}
	for _, hit := range decodeJSON(t, f.body)["hits"].([]any) {
		hit := hit.(map[string]any)
		name := hit["resource"].(string)
		keyOf := func(kid string) []byte { return must(ad.Key(ctx, kid)) }
		if _, err := derived.OpenItem(hit["sealed"].(string), derived.ItemKey(keyOf, "e", name), derived.View{NS: "e", Target: f.path}, "e", name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
