package tree_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// w4x (P35 x P37 x the tree service), Addendum E Levels, §E.2.6: a sealed
// catalog followed by a running tree service is raised from sealed to
// e2e. Listings keep working, and keep working after a restart past the
// raise, when the service's Info already says e2e and it takes cat#1 as
// the key of an epoch before the raise (derived.Keys.preRaiseKey):
// pre-raise nodes are sealed under cat#1 (the epoch they are served
// under), nodes written end to end under cat#2.
func TestV073W4xTreeFollowsRaiseFromSealed(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	t0 := s.Now()
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	svcJWK, svcPriv, _ := seal.GenerateRecipient()
	wJWK, wPriv, _ := seal.GenerateRecipient()
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": wJWK, "nbf": t0.Format(time.RFC3339)})), client.WithKeys(client.NewKeys(wPriv)))
	createNonced(t, wr, "cat", "root", map[string]any{"title": "Root", "parents": []any{}})
	createNonced(t, wr, "cat", "old", map[string]any{"title": "Old", "parents": parents("root@a0")})
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"},
		map[string]any{"enc": svcJWK, "nbf": t0.Format(time.RFC3339)})),
		client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	db := t.TempDir() + "/tree.db"
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Recipient = svcPriv })
	x.caughtUp("cat")
	rd := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
	f := x.fetch("/cat/children?of=root", rd)
	t.Logf("before the raise: %s", f.header.Get("Content-Type"))

	s.Clock.Advance(time.Minute)
	h := must(wr.NSHead(ctx, "cat"))
	must(wr.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}))
	x2 := wr.E2E(wPriv)
	must(x2.InitKeyring(ctx, "cat", svcPriv.PublicKey()))
	must(x2.CreateDocSealed(ctx, "cat", "new", map[string]any{"title": "New", "parents": parents("root@a1")}))
	x.caughtUp("cat")
	restart := false
again:
	st := func() resp {
		r := x.raw("/cat/children?of=root", rd)
		for i := 0; r.status == 302 && i < 4; i++ {
			r = x.raw(r.header.Get("Location"), rd)
		}
		return r
	}
	var r resp
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if r = st(); r.status == http.StatusOK {
			break
		}
	}
	if r.status != http.StatusOK {
		t.Fatalf("listing after the raise: %d %v", r.status, r.body)
	}
	last := x.fetch("/cat/children?of=root", rd)
	kids := map[string]string{}
	if last.header.Get("Content-Type") == seal.ContentType {
		t.Fatalf("listing mixing epochs sealed whole: %s", must(seal.ParseHeader(string(last.body))).Kid)
	}
	for name, e := range entriesOf(t, decode(t, last.body)) {
		if jwe, _ := e["sealed"].(string); jwe != "" {
			kids[name] = must(seal.ParseHeader(jwe)).Kid
		} else {
			kids[name] = ""
		}
	}
	if kids["old"] != "cat#1" || kids["new"] != "cat#2" {
		t.Fatalf("kids %v, want old cat#1, new cat#2", kids)
	}
	if restart {
		return
	}
	x.stop()
	x = startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Recipient = svcPriv })
	createNonced2 := func() {
		must(x2.CreateDocSealed(ctx, "cat", "later", map[string]any{"title": "Later", "parents": parents("root@a2")}))
	}
	createNonced2()
	x.caughtUp("cat")
	restart = true
	goto again
}
