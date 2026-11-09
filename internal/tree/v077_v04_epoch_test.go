package tree_test

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// v077Sealed is node name's entry in the listing at path, read by rd:
// its values and the kid they are sealed under, whole or per entry, and
// whether its born is sealed apart from them.
func v077Sealed(t *testing.T, x *svc, path, rd, name string, keyOf func(string) []byte) (kid string, vals map[string]any, bornApart bool) {
	t.Helper()
	waitFor(t, "a listing", func() bool { return x.listingAs(path, rd).status == http.StatusOK })
	f := x.fetch(path, rd)
	view := derived.View{NS: "cat", Target: f.path}
	if f.header.Get("Content-Type") == seal.ContentType {
		kid = must(seal.ParseHeader(string(f.body))).Kid
		return kid, entriesOf(t, decode(t, must(derived.OpenView(string(f.body), keyOf, view))))[name], false
	}
	e := entriesOf(t, decode(t, f.body))[name]
	jwe, _ := e["sealed"].(string)
	if jwe == "" {
		t.Fatalf("%s not sealed: %v", name, e)
	}
	_, bornApart = e["born"]
	kid = must(seal.ParseHeader(jwe)).Kid
	return kid, decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", name), view, "cat", name))), bornApart
}

// v077Epochs is node name's epoch and born_epoch as stored (0 for NULL).
func v077Epochs(t *testing.T, db, name string) (epoch, born int) {
	t.Helper()
	sq := must(sql.Open("sqlite", db))
	defer sq.Close()
	var e, b sql.NullInt64
	if err := sq.QueryRow(`SELECT epoch, born_epoch FROM nodes WHERE name = ?`, name).Scan(&e, &b); err != nil {
		t.Fatal(err)
	}
	return int(e.Int64), int(b.Int64)
}

// §E.2.6 Per-entry sealing, §E.3.1 snapshot rule (v0.77, scenario 74):
// at E3 an entry's kid is the one a prune's snapshot of its revision
// would carry, judged once, when the service first seals a value derived
// from it. Catalog cat is raised from none to e2e, so node n's head,
// written in the clear before the raise, has a snapshot that takes cat's
// epoch in force, as a base's op read through does: first listed at
// cat#1, its title is sealed under cat#1; after cat rotates to 2, a
// listing at a new at still seals it under cat#1, and so does one after
// a restart. A node written after the rotation is sealed under cat#2.
// (Before, every listing took the current epoch: cat#2.)
func TestV077V04JudgedOnceE3(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	svcJWK, svcPriv := must2(seal.GenerateRecipient())
	wJWK, wPriv := must2(seal.GenerateRecipient())
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": wJWK})), client.WithKeys(client.NewKeys(wPriv)))
	x2 := wr.E2E(wPriv)
	must(wr.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(wr.CreateDoc(ctx, "cat", "n", map[string]any{"title": "N", "parents": parents("root@a0")}))
	must(wr.PatchConfig(ctx, "cat", must(wr.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "e2e"}}}))
	must(x2.InitKeyring(ctx, "cat", svcPriv.PublicKey()))
	keyOf := func(kid string) []byte { return must(x2.SealKey(ctx, kid)) }

	sc := func() *client.Client {
		return s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"}, map[string]any{"enc": svcJWK})),
			client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	}
	db := filepath.Join(t.TempDir(), "tree.db")
	withRecipient := func(o *tree.Options) { o.Recipient = svcPriv }
	x := startSvc(t, sc(), svcOpts{now: s.Now, db: db}, withRecipient)
	x.caughtUp("cat")
	rd := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
	check := func(when, name, title, kid string) {
		t.Helper()
		got, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, name, keyOf)
		if got != kid || vals["title"] != title {
			t.Errorf("%s: %s %v under %s, want title %s under %s", when, name, vals, got, title, kid)
		}
	}
	if e, _ := v077Epochs(t, db, "n"); e != 0 {
		t.Fatalf("n's epoch %d before any listing, want it pending", e)
	}
	check("first listing", "n", "N", "cat#1")
	if e, _ := v077Epochs(t, db, "n"); e != 1 {
		t.Errorf("n's epoch %d once listed, want 1 recorded", e)
	}

	must(x2.RotateEpoch(ctx, "cat", svcPriv.PublicKey()))
	must(x2.CreateDocSealed(ctx, "cat", "later", map[string]any{"title": "Later", "parents": parents("root@a1")}))
	x.caughtUp("cat")
	check("after the rotation", "n", "N", "cat#1")
	check("after the rotation", "later", "Later", "cat#2")

	x.stop()
	x = startSvc(t, sc(), svcOpts{now: s.Now, db: db}, withRecipient)
	must(x2.CreateDocSealed(ctx, "cat", "last", map[string]any{"title": "Last", "parents": parents("root@a2")}))
	x.caughtUp("cat")
	check("after a restart", "n", "N", "cat#1")
}

// §E.2.6, §E.3.1 (v0.77, scenario 74): born and head values from one
// revision share one judgement. In a release preview of e2e catalog cat
// through its e2e branch catb, node n's only revision is cat's op, read
// through: its born is pending with its head's (bornWithHead), not
// judged as it is applied. The first listing seals n's title and born
// together, and records the one epoch for both; root, whose values no
// listing sealed yet, stays pending.
func TestV077V04JudgedOnceBornWithHead(t *testing.T) {
	t.Parallel()
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
	keyOf := func(kid string) []byte { return must(x2.SealKey(ctx, kid)) }

	sc := func() *client.Client {
		return s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"}, map[string]any{"enc": svcJWK})),
			client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	}
	db := filepath.Join(t.TempDir(), "tree.db")
	preview := func(o *tree.Options) { o.Recipient = svcPriv; o.Branches = map[string]string{"cat": "catb"} }
	x := startSvc(t, sc(), svcOpts{now: s.Now, db: db}, preview)
	waitFor(t, "the preview to reach catb", func() bool {
		h, err := wr.NSHead(ctx, "catb")
		return err == nil && x.s.Checkpoint("cat") == h.ID
	})
	rd := k.Grant(t, s.Now(), "user:r", both, []string{"read"})
	for _, name := range []string{"root", "n"} {
		if e, b := v077Epochs(t, db, name); e != 0 || b >= 0 {
			t.Fatalf("%s's epochs %d, %d before any listing, want both pending", name, e, b)
		}
	}
	for _, when := range []string{"first listing", "after a restart"} {
		kid, vals, apart := v077Sealed(t, x, "/cat/children?of=root", rd, "n", keyOf)
		if b, _ := vals["born"].(string); kid != "cat#1" || vals["title"] != "N" || b == "" || apart {
			t.Errorf("%s: n %v under %s (born apart %v), want its title and born together under cat#1", when, vals, kid, apart)
		}
		if e, b := v077Epochs(t, db, "n"); e != 1 || b != 1 {
			t.Errorf("%s: n's epochs %d, %d, want 1 recorded for both", when, e, b)
		}
		if e, b := v077Epochs(t, db, "root"); e != 0 || b >= 0 {
			t.Errorf("%s: root's epochs %d, %d, want both still pending", when, e, b)
		}
		x.stop()
		x = startSvc(t, sc(), svcOpts{now: s.Now, db: db}, preview)
	}
}
