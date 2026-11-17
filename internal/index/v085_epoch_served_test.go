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

// v0.85 SERVICES §E.2.6 Per-entry sealing, SPEC §E.2.2 (v0.82 Open 17;
// ENC-32): a hit's kid names "the epoch the revision it derives from is
// served under", and it is the origin that fixes a revision's epoch, when
// it first seals it. pr is indexed in the clear, so its document's head
// has no kid; pr is raised to sealed, the origin serves the head under
// epoch 1, and pr rotates to epoch 2 before the index first seals a value
// derived from that head. The index reads the head again and seals the
// hit under pr#1, the origin's epoch, where it used to judge it as the
// epoch in force, pr#2; the epoch stands for later answers, and a
// document written after the rotation is under pr#2.
func TestV085E2EpochFromOriginSealing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	a := must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret a"}))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"}, map[string]any{"enc": jwk})), client.WithKeys(client.NewKeys(priv)))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("pr")
	config := func(op, path string, value any) {
		t.Helper()
		must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": op, "path": path, "value": value}}))
		x.appliedUpTo(x.caughtUp("pr"))
	}
	config("add", "/encryption", map[string]any{"level": "sealed"})
	// The origin seals a's head, under the epoch current now.
	if d := must(w.Doc(ctx, "pr", "a", a.ID)); d.Kid != "pr#1" {
		t.Fatalf("the origin serves a under %q, want pr#1", d.Kid)
	}
	config("add", "/encryption/epoch", 2.0)
	must(createNonced(w, "pr", "b", map[string]any{"title": "secret b"}))
	x.appliedUpTo(x.caughtUp("pr"))
	if d := must(w.Doc(ctx, "pr", "a", a.ID)); d.Kid != "pr#1" {
		t.Fatalf("after the rotation the origin serves a under %q, want pr#1", d.Kid)
	}
	for i := 0; i < 2; i++ {
		r := x.fetch("/pr?limit=5", "")
		if kids := p37Kids(t, r.body); kids["a"] != "pr#1" || kids["b"] != "pr#2" {
			t.Errorf("query %d: kids %v, want a under pr#1, the origin's epoch for it, and b under pr#2", i, kids)
		}
	}
}

// The same where the index's grant gets no key for the origin's epoch
// (encryption.historyEpochs 0: readers get the current epoch only,
// §E.2.3; the index restarted since the rotation): the head's epoch is still the origin's, read from the served
// JWE's header, which needs no key, so the hit is served by name only
// (§E.2.6: "An entry whose epoch the service's grant gets no key for is
// served by name only"), never sealed under the epoch in force, and the
// query still answers.
func TestV085E2EpochFromOriginSealingWithoutItsKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	a := must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret a"}))
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"}, map[string]any{"enc": jwk})), client.WithKeys(client.NewKeys(priv)))
	db := filepath.Join(t.TempDir(), "i.db")
	x := startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("pr")
	config := func(path string, value any) {
		t.Helper()
		must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "add", "path": path, "value": value}}))
		x.appliedUpTo(x.caughtUp("pr"))
	}
	config("/encryption", map[string]any{"level": "sealed", "historyEpochs": 0.0})
	if d := must(w.Doc(ctx, "pr", "a", a.ID)); d.Kid != "pr#1" {
		t.Fatalf("the origin serves a under %q, want pr#1", d.Kid)
	}
	config("/encryption/epoch", 2.0)
	must(createNonced(w, "pr", "b", map[string]any{"title": "secret b"}))
	x.appliedUpTo(x.caughtUp("pr"))
	if kid := must(ic.DocKid(ctx, "pr", "a", a.ID)); kid != "pr#1" {
		t.Fatalf("DocKid of a: %q, want pr#1", kid)
	}
	// A restart: the index holds the keys its grant gets now, pr#2's alone.
	x.stop()
	ic = ic.With(client.WithKeys(client.NewKeys(priv)))
	if _, err := ic.Doc(ctx, "pr", "a", a.ID); err == nil {
		t.Fatal("the index's grant opens a under pr#1; the test needs it not to")
	}
	x = startSvcWith(t, ic, svcOpts{db: db, ns: []string{"pr"}, untyped: true, now: s.Now}, func(o *indexOpts) { o.Recipient = priv })
	x.caughtUp("pr")
	r := x.fetch("/pr?limit=5", "")
	kids := p37Kids(t, r.body)
	if kid, listed := kids["a"]; !listed || kid != "" || kids["b"] != "pr#2" {
		t.Errorf("kids %v, want a by name only (its epoch pr#1 is one the index has no key for) and b under pr#2: %s", kids, r.body)
	}
}
