package tree_test

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// v081Preview is an e2e catalog cat, e2e from its creation, holding root
// and n, sealed by w under cat#1, and its e2e branch catb, which a
// release preview service follows in place of cat (§B.5, §F.9): n's head
// there is cat's op, read through, so the snapshot of its revision takes
// catb's epoch in force, judged once (§E.3.1, §E.2.6), as a revision
// written in the clear before a raise did before v0.78 (a raise to e2e
// is 422 since). rotate rotates the epochs of both, so the epoch in force
// in catb and the key the preview's values name (cat#{e}) move together;
// reach waits for the service to reach catb's head.
type v081Preview struct {
	s       *clienttest.Server
	k       clienttest.Key
	wr      *client.Client
	x2      *client.E2E
	svcPriv *ecdh.PrivateKey
	db      string
	sc      func() *client.Client
	opts    func(o *tree.Options)
	keyOf   func(kid string) []byte
}

func newV081Preview(t *testing.T) *v081Preview {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "e2e"}, "catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	svcJWK, svcPriv := must2(seal.GenerateRecipient())
	wJWK, wPriv := must2(seal.GenerateRecipient())
	both := []string{"cat", "catb"}
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "append", "config", "branch"},
		map[string]any{"enc": wJWK})), client.WithKeys(client.NewKeys(wPriv)))
	x2 := wr.E2E(wPriv)
	must(x2.InitKeyring(ctx, "cat", svcPriv.PublicKey()))
	must(x2.CreateDocSealed(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(x2.CreateDocSealed(ctx, "cat", "n", map[string]any{"title": "N", "parents": parents("root@a0")}))
	must(wr.CreateBranch(ctx, "cat", client.BranchRequest{Name: "catb"}))
	must(x2.InitKeyring(ctx, "catb", svcPriv.PublicKey()))
	p := &v081Preview{s: s, k: k, wr: wr, x2: x2, svcPriv: svcPriv, db: filepath.Join(t.TempDir(), "tree.db")}
	p.sc = func() *client.Client {
		return s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"}, map[string]any{"enc": svcJWK})),
			client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	}
	p.opts = func(o *tree.Options) { o.Recipient = svcPriv; o.Branches = map[string]string{"cat": "catb"} }
	p.keyOf = func(kid string) []byte { return must(x2.SealKey(ctx, kid)) }
	return p
}

// start starts the preview service on p's database, reached.
func (p *v081Preview) start(t *testing.T) *svc {
	t.Helper()
	x := startSvc(t, p.sc(), svcOpts{now: p.s.Now, db: p.db}, p.opts)
	p.reach(t, x)
	return x
}

func (p *v081Preview) reach(t *testing.T, x *svc) {
	t.Helper()
	waitFor(t, "the preview to reach catb", func() bool {
		h, err := p.wr.NSHead(context.Background(), "catb")
		return err == nil && x.s.Checkpoint("cat") == h.ID
	})
}

func (p *v081Preview) rotate(t *testing.T) {
	t.Helper()
	for _, ns := range []string{"cat", "catb"} {
		must(p.x2.RotateEpoch(context.Background(), ns, p.svcPriv.PublicKey()))
	}
}

// v081SealedPrivate raises a namespace to sealed and makes it private in
// one config write: for a service whose client holds no keys and never
// fetches any (client.StaticKeys), a namespace it can no longer follow
// for keys it can't have (§B.5 Behind, §E.2.6), which is what the v0.26.1
// tests of a raise to e2e pinned before a raise to e2e became 422 (v0.78).
var v081SealedPrivate = []any{
	map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}},
	map[string]any{"op": "replace", "path": "/read", "value": "grant"},
}

// v081PendingHead sets the store at db, the service stopped, as one from
// before v0.78 holds the only revision of e2e catalog node name, written
// in the clear before a raise to e2e: its epoch NULL, pending, judged by
// the first listing that seals it, its born's with it (bornWithHead;
// §E.2.6, §E.3.1), and no listing stored. A raise to e2e is 422 since
// v0.78, so no core a test reaches serves such a revision.
func v081PendingHead(t *testing.T, db, name string) {
	t.Helper()
	sq := must(sql.Open("sqlite", db))
	defer sq.Close()
	for _, q := range []string{`UPDATE nodes SET epoch = NULL, born_epoch = -3 WHERE name = '` + name + `'`, `DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}
