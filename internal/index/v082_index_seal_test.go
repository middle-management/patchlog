package index_test

import (
	"context"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// V82-05 (v0.82), SVC-06: the index seals nothing derived from a revision
// whose epoch it hasn't judged (SERVICES §E.2.6 Per-entry sealing).

// v82Pending is an index of e-b, an e2e branch of e, in which r's head is
// e's op read through: its epoch is pending until an answer first seals a
// value derived from it (§E.2.6). write appends a revision of r in e-b
// and waits for the index to apply it, so the row of r holds another head
// than the one an answer under way has read.
func v82Pending(t *testing.T) (x *svc, write func() string) {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e", map[string]any{"read": "public", "keys": []any{admin.Entry("*")},
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	idxJWK, idxPriv, _ := seal.GenerateRecipient()
	nss := []string{"e", "e-b", "schemas"}
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", nss, []string{"read", "create", "append", "config", "branch"}, map[string]any{"enc": adminJWK})))
	ad := ac.E2E(adminPriv)
	sch := must(ac.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	must(ad.InitKeyring(ctx, "e", idxPriv.PublicKey()))
	first := must(ad.CreateDocSealed(ctx, "e", "r", map[string]any{"$schema": ref, "title": "zq r", "related": []any{"/r/target/x"}}))
	must(ac.CreateBranch(ctx, "e", client.BranchRequest{Name: "e-b"}))
	must(ad.InitKeyring(ctx, "e-b", idxPriv.PublicKey()))
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}, map[string]any{"enc": idxJWK})),
		client.WithKeyringSenders(adminPriv.PublicKey()))
	x = startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, branches: true, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	x.caughtUp("e-b")
	return x, func() string {
		res := must(ad.AppendSealed(ctx, "e-b", "r", first.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "zq r again"}}))
		x.appliedUpTo(x.caughtUp("e-b"))
		return res.ID
	}
}

// TestV082NothingSealedUnjudged (SVC-06; §E.2.6 Per-entry sealing,
// v0.82: "the epoch is judged once, when the service first seals a value
// derived from that revision. Until it can judge it, the service seals
// nothing derived from that revision"): r's epoch in e-b is pending. An
// answer has read r's row when a write gives r another head, so the
// judgement finds no row for the revision the answer read and judges
// nothing. The answer seals nothing derived from that revision: it is
// computed again, and serves r's new head under the epoch that head is
// served under. Before v0.82 the revision it couldn't judge was sealed
// under the epoch current then, and that answer served and kept.
func TestV082NothingSealedUnjudged(t *testing.T) {
	x, write := v82Pending(t)
	var once atomic.Bool
	var head string
	x.ix.OnBeforeJudge(func() {
		if once.CompareAndSwap(false, true) {
			head = write()
		}
	})
	got := x.fetch("/e-b?q=zq", "")
	if !once.Load() {
		t.Fatal("never judged")
	}
	hits := decodeJSON(t, got.body)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("hits %v", hits)
	}
	h := hits[0].(map[string]any)
	if h["id"] != head {
		t.Errorf("the answer serves r at %v, a revision whose epoch it couldn't judge: want its head %s, judged", h["id"], head)
	}
	if kid := p37Kids(t, got.body)["r"]; kid != "e-b#1" {
		t.Errorf("r sealed under %q, want e-b#1, the epoch its head is served under", kid)
	}
}

// TestV082RefsNothingSealedUnjudged (SVC-06; §E.2.6 Per-entry sealing,
// v0.82) is TestV082NothingSealedUnjudged on /_refs: the answer across
// namespaces that read r's row before its head moved seals nothing
// derived from the revision it couldn't judge, and serves r's head.
func TestV082RefsNothingSealedUnjudged(t *testing.T) {
	x, write := v82Pending(t)
	var once atomic.Bool
	var head string
	x.ix.OnRefsRead(func() {
		if once.CompareAndSwap(false, true) {
			head = write()
		}
	})
	got := x.fetch("/_refs?to="+url.QueryEscape("/r/target/x"), "")
	if !once.Load() {
		t.Fatal("never read")
	}
	var seen bool
	for _, hv := range decodeJSON(t, got.body)["hits"].([]any) {
		h := hv.(map[string]any)
		if h["ns"] != "e-b" || h["resource"] != "r" {
			continue
		}
		seen = true
		if h["id"] != head {
			t.Errorf("/_refs serves e-b/r at %v, a revision whose epoch it couldn't judge: want its head %s", h["id"], head)
		}
	}
	if !seen {
		t.Errorf("/_refs shows nothing of e-b/r: %s", got.body)
	}
}
