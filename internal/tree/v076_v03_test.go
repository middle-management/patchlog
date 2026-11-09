package tree_test

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// v076V03Rewrap sends a POST /ns/{ns}/keys asking for epoch 1 alone
// under other once on is set, so that the keys come back wrapped to
// another recipient than the service's.
type v076V03Rewrap struct {
	ns    string
	other string
	on    atomic.Bool
}

func (rw *v076V03Rewrap) RoundTrip(r *http.Request) (*http.Response, error) {
	if rw.on.Load() && r.URL.Path == "/ns/"+rw.ns+"/keys" && r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(bytes.NewReader(b))
		if strings.Contains(string(b), `"epochs":[1]`) {
			r.Header.Set("Authorization", "Bearer "+rw.other)
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// §A.4, §E.2.6 (v0.76): an older epoch's key that comes back wrapped to
// a recipient the service can't open is lacking for good, not 503
// behind: a listing that shows a node served under that epoch gives it
// by name only.
func TestV076V03ListingUnwrappableKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "c"))).CreateNamespace(ctx, "c", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{"c"}, "mode": "tree"}}))
	all := []string{"cat", "c"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "cat", "old", map[string]any{"title": "Old", "parents": parents("root")})

	jwk, priv := must2(seal.GenerateRecipient())
	otherJWK, _ := must2(seal.GenerateRecipient())
	extra := func(enc map[string]any) map[string]any {
		return map[string]any{"enc": enc, "nbf": s.Now().Add(-24 * time.Hour).Format(time.RFC3339)}
	}
	rw := &v076V03Rewrap{ns: "cat", other: k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, extra(otherJWK))}
	svcClient := func() *client.Client {
		return s.Client(t, client.WithHTTPClient(&http.Client{Transport: rw}),
			client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, extra(jwk))), client.WithKeys(client.NewKeys(priv)))
	}
	withRecipient := func(o *tree.Options) { o.Recipient = priv }
	opts := svcOpts{now: s.Now, db: filepath.Join(t.TempDir(), "tree.db")}
	x := startSvc(t, svcClient(), opts, withRecipient)
	x.caughtUp("cat", "c")
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	createNonced(t, w, "cat", "new", map[string]any{"title": "New", "parents": parents("root")})
	x.caughtUp("cat", "c")

	// After a restart, epoch 1's key comes back wrapped to another
	// recipient.
	x.stop()
	rw.on.Store(true)
	x = startSvc(t, svcClient(), opts, withRecipient)
	x.caughtUp("cat", "c")
	full := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	r := x.listingAs("/cat/children?of=root", full)
	if r.status != http.StatusOK {
		t.Fatalf("children of root without an openable cat#1: %d %v", r.status, r.body)
	}
	f := x.fetch("/cat/children?of=root", full)
	es := entriesOf(t, decode(t, f.body))
	if e := es["old"]; e == nil || e["sealed"] != nil || e["title"] != nil {
		t.Errorf("old without an openable key: %v, want it by name only", e)
	}
	if jwe, _ := es["new"]["sealed"].(string); jwe == "" || must(seal.ParseHeader(jwe)).Kid != "cat#2" {
		t.Errorf("new: %v", es["new"])
	}
}

// §E.2.6 Per-entry sealing, §E.3.1 snapshot kid (v0.76, B-67): at E3 a
// node's born takes the epoch a prune's snapshot of its first revision
// would carry, the epoch of its own sealed op, never the served kid of
// a log the server gives in the clear. n, created in epoch 1 and retitled
// in epoch 2, is listed per entry under cat#2 with only its title, its
// born sealed apart under cat#1. A born whose epoch isn't known is left
// out, never sealed with the head's values; one a database from before
// v0.76 stored without it is read in again on start.
func TestV076V03BornEpochE3(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "e2e"}, "catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	svcJWK, svcPriv := must2(seal.GenerateRecipient())
	wJWK, wPriv := must2(seal.GenerateRecipient())
	wr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "append", "config"},
		map[string]any{"enc": wJWK})), client.WithKeys(client.NewKeys(wPriv)))
	x2 := wr.E2E(wPriv)
	must(x2.InitKeyring(ctx, "cat", svcPriv.PublicKey()))
	must(x2.CreateDocSealed(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(x2.CreateDocSealed(ctx, "cat", "n", map[string]any{"title": "N", "parents": parents("root@a0")}))
	must(x2.RotateEpoch(ctx, "cat", svcPriv.PublicKey()))
	h := must(wr.Head(ctx, "cat", "n"))
	must(x2.AppendSealed(ctx, "cat", "n", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Newer"}}))
	keyOf := func(kid string) []byte { return must(x2.SealKey(ctx, kid)) }

	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"}, map[string]any{"enc": svcJWK})),
		client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	db := filepath.Join(t.TempDir(), "tree.db")
	withRecipient := func(o *tree.Options) { o.Recipient = svcPriv }
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db}, withRecipient)
	x.caughtUp("cat")
	rd := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})

	// n's entry: its title under cat#2; its born per bornWant ("cat#1":
	// sealed apart under that epoch, "": absent).
	check := func(when, bornWant string) {
		t.Helper()
		var f fetched
		waitFor(t, when+": a listing", func() bool {
			r := x.listingAs("/cat/children?of=root", rd)
			return r.status == http.StatusOK
		})
		f = x.fetch("/cat/children?of=root", rd)
		view := derived.View{NS: "cat", Target: f.path}
		if f.header.Get("Content-Type") == seal.ContentType && bornWant == "" {
			// Every value shown is of cat#2: sealed whole.
			if kid := must(seal.ParseHeader(string(f.body))).Kid; kid != "cat#2" {
				t.Fatalf("%s: listing sealed whole under %s", when, kid)
			}
			e := entriesOf(t, decode(t, must(derived.OpenView(string(f.body), keyOf, view))))["n"]
			if e["title"] != "Newer" || e["born"] != nil {
				t.Errorf("%s: n %v, want its title and no born", when, e)
			}
			return
		}
		if f.header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: listing %s, want per entry", when, f.header.Get("Content-Type"))
		}
		e := entriesOf(t, decode(t, f.body))["n"]
		jwe, _ := e["sealed"].(string)
		if jwe == "" || must(seal.ParseHeader(jwe)).Kid != "cat#2" {
			t.Fatalf("%s: n sealed %v, want kid cat#2", when, e)
		}
		vals := decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "cat", "n"), view, "cat", "n")))
		if vals["title"] != "Newer" || vals["born"] != nil {
			t.Errorf("%s: n's values under cat#2 %v, want its title only", when, vals)
		}
		if bornWant == "" {
			if e["born"] != nil {
				t.Errorf("%s: n's born %v, want none", when, e["born"])
			}
			return
		}
		born, _ := e["born"].(map[string]any)
		bj, _ := born["sealed"].(string)
		if bj == "" || must(seal.ParseHeader(bj)).Kid != bornWant {
			t.Fatalf("%s: n's born %v, want sealed under %s", when, e["born"], bornWant)
		}
		bv := decode(t, must(derived.OpenItem(bj, derived.ItemKey(keyOf, "cat", "n"), view, "cat", "n")))
		if b, _ := bv["born"].(string); len(bv) != 1 || b == "" {
			t.Errorf("%s: n's born opens to %v", when, bv)
		}
	}
	check("following", "cat#1")

	// A born whose epoch isn't known (a record without it, not pending
	// a fill) is left out.
	x.stop()
	sq := must(sql.Open("sqlite", db))
	for _, q := range []string{`UPDATE nodes SET born_epoch = NULL WHERE name = 'n'`, `DELETE FROM meta WHERE k = 'epochs'`, `DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sq.Close()
	x = startSvc(t, sc, svcOpts{now: s.Now, db: db}, withRecipient)
	must(x2.CreateDocSealed(ctx, "cat", "later", map[string]any{"title": "Later", "parents": parents("root@a2")}))
	x.caughtUp("cat")
	check("unknown", "")

	// A database from before v0.76, which stored an E3 born's epoch from
	// its first entry's served kid, none for an own sealed op, and
	// recorded the fill done: its borns are read in again, once
	// (markBornEpochs), under their snapshot's epoch.
	x.stop()
	sq = must(sql.Open("sqlite", db))
	for _, q := range []string{`UPDATE nodes SET born_epoch = NULL WHERE name = 'n'`, `DELETE FROM meta WHERE k IN ('epochs', 'bornsnap')`, `DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sq.Close()
	x = startSvc(t, sc, svcOpts{now: s.Now, db: db}, withRecipient)
	x.caughtUp("cat")
	waitFor(t, "the borns read in again", func() bool {
		return x.listingAs("/cat/children?of=root", rd).header.Get("Content-Type") == "application/json"
	})
	check("upgraded", "cat#1")
}
