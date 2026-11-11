package tree_test

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
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
// whether its born is sealed apart from them. The namespace whose keys
// seal it is the one its kid names: the catalog, or in a release preview
// its branch (v0.82, §E.2.6 Per-entry sealing), which pl.ns must name
// too (OpenView, OpenItem).
func v077Sealed(t *testing.T, x *svc, path, rd, name string, keyOf func(string) []byte) (kid string, vals map[string]any, bornApart bool) {
	t.Helper()
	waitFor(t, "a listing", func() bool { return x.listingAs(path, rd).status == http.StatusOK })
	f := x.fetch(path, rd)
	if f.header.Get("Content-Type") == seal.ContentType {
		kid = must(seal.ParseHeader(string(f.body))).Kid
		ns, _ := must2(seal.ParseKid(kid))
		return kid, entriesOf(t, decode(t, must(derived.OpenView(string(f.body), keyOf, derived.View{NS: ns, Target: f.path}))))[name], false
	}
	e := entriesOf(t, decode(t, f.body))[name]
	jwe, _ := e["sealed"].(string)
	if jwe == "" {
		t.Fatalf("%s not sealed: %v", name, e)
	}
	_, bornApart = e["born"]
	kid = must(seal.ParseHeader(jwe)).Kid
	ns, _ := must2(seal.ParseKid(kid))
	return kid, decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keyOf, ns, name), derived.View{NS: ns, Target: f.path}, ns, name))), bornApart
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
// from it. In a release preview of e2e catalog cat through its e2e branch
// catb (v081Preview), node n's head is cat's op, read through, so its
// snapshot takes catb's epoch in force: first listed at catb#1, its title
// is sealed under catb#1, the branch's key (v0.82: a preview's entries
// are sealed under the branch's keys, §E.2.6; before, under cat#1); after
// the epochs rotate to 2, a listing at a new at still seals it under
// catb#1, later written after the rotation under catb#2, and n stays
// under catb#1 after a restart.
// (Before, every listing took the current epoch.) Until v0.81 n was
// written in the clear in cat before cat was raised to e2e, which is 422
// since v0.78.
func TestV077V04JudgedOnceE3(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := newV081Preview(t)
	x := p.start(t)
	rd := p.k.Grant(t, p.s.Now(), "user:r", []string{"cat", "catb"}, []string{"read"})
	check := func(when string) {
		t.Helper()
		got, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "n", p.keyOf)
		if got != "catb#1" || vals["title"] != "N" {
			t.Errorf("%s: n %v under %s, want title N under catb#1", when, vals, got)
		}
	}
	if e, _ := v077Epochs(t, p.db, "n"); e != 0 {
		t.Fatalf("n's epoch %d before any listing, want it pending", e)
	}
	check("first listing")
	if e, _ := v077Epochs(t, p.db, "n"); e != 1 {
		t.Errorf("n's epoch %d once listed, want 1 recorded", e)
	}

	p.rotate(t)
	must(p.x2.CreateDocSealed(ctx, "catb", "later", map[string]any{"title": "Later", "parents": parents("root@a1")}))
	p.reach(t, x)
	check("after the rotation")
	if got, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "later", p.keyOf); got != "catb#2" || vals["title"] != "Later" {
		t.Errorf("later, written after the rotation: %v under %s, want title Later under catb#2", vals, got)
	}

	x.stop()
	x = p.start(t)
	must(p.x2.CreateDocSealed(ctx, "catb", "last", map[string]any{"title": "Last", "parents": parents("root@a2")}))
	p.reach(t, x)
	check("after a restart")
	if e, _ := v077Epochs(t, p.db, "n"); e != 1 {
		t.Errorf("n's epoch %d after a restart, want 1", e)
	}
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
		if b, _ := vals["born"].(string); kid != "catb#1" || vals["title"] != "N" || b == "" || apart {
			t.Errorf("%s: n %v under %s (born apart %v), want its title and born together under catb#1 (the branch's key, v0.82)", when, vals, kid, apart)
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

// v077Unfill makes db's a database from before nodes.epoch was kept: the
// heads' epochs not known, to be read in (meta "epochs"), and no sealed
// listing stored.
func v077Unfill(t *testing.T, db string) {
	t.Helper()
	sq := must(sql.Open("sqlite", db))
	defer sq.Close()
	for _, q := range []string{`UPDATE nodes SET epoch = NULL`, `INSERT INTO meta (k, v) VALUES ('epochs', 'pending') ON CONFLICT (k) DO NOTHING`,
		`DELETE FROM sealed_views`} {
		if _, err := sq.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// v077Blocking is a transport that holds every request whose path starts
// with prefix until release is closed.
func v077Blocking(prefix string, release chan struct{}) client.Option {
	return client.WithTransport(func(rt http.RoundTripper) http.RoundTripper {
		return roundTrip(func(r *http.Request) (*http.Response, error) {
			if strings.HasPrefix(r.URL.Path, prefix) {
				<-release
			}
			return rt.RoundTrip(r)
		})
	})
}

// §E.2.6, §E.3.1 (v0.77; v0.82): an own sealed op's snapshot carries its
// own kid's epoch, never the one in force. While a database's head epochs
// are still being read in (meta "epochs"), a Node.Epoch of 0 may be one
// not read in yet: a listing served meanwhile judges nothing and, since
// v0.82, seals nothing derived from that head (§E.2.6 Per-entry sealing;
// v0.77 sealed it under the current epoch, cat#2): n is by name only.
// The fill gives it its own: n, an own op of epoch 1, is then listed
// under cat#1, with 1 stored.
func TestV077V04NotJudgedDuringBackfill(t *testing.T) {
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
	keyOf := func(kid string) []byte { return must(x2.SealKey(ctx, kid)) }

	release := make(chan struct{})
	sc := func(block bool) *client.Client {
		opts := []client.Option{client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"}, map[string]any{"enc": svcJWK})),
			client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey())}
		if block {
			opts = append(opts, v077Blocking("/r/cat/n", release))
		}
		return s.Client(t, opts...)
	}
	db := filepath.Join(t.TempDir(), "tree.db")
	withRecipient := func(o *tree.Options) { o.Recipient = svcPriv }
	x := startSvc(t, sc(false), svcOpts{now: s.Now, db: db}, withRecipient)
	x.caughtUp("cat")
	if e, _ := v077Epochs(t, db, "n"); e != 1 {
		t.Fatalf("n's epoch %d, want 1 (its own op's kid)", e)
	}
	x.stop()
	v077Unfill(t, db)
	x = startSvc(t, sc(true), svcOpts{now: s.Now, db: db}, withRecipient)
	rd := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
	waitFor(t, "a listing", func() bool { return x.listingAs("/cat/children?of=root", rd).status == http.StatusOK })
	during := x.fetch("/cat/children?of=root", rd)
	if during.header.Get("Content-Type") == seal.ContentType {
		t.Errorf("during the fill: a listing sealed whole with an unjudged node")
	} else if e := entriesOf(t, decode(t, during.body))["n"]; e == nil || e["sealed"] != nil || e["title"] != nil || e["born"] != nil {
		t.Errorf("during the fill: n %v, want it by name only", e)
	}
	if e, _ := v077Epochs(t, db, "n"); e != 0 {
		t.Errorf("during the fill: n's epoch %d stored, want none judged", e)
	}
	close(release)
	waitFor(t, "the epochs backfill", func() bool { return !x.s.EpochsPending() })
	must(x2.CreateDocSealed(ctx, "cat", "later", map[string]any{"title": "Later", "parents": parents("root@a1")}))
	x.caughtUp("cat")
	if kid, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "n", keyOf); kid != "cat#1" || vals["title"] != "N" {
		t.Errorf("after the fill: n %v under %s, want under cat#1, its revision's epoch", vals, kid)
	}
	if e, _ := v077Epochs(t, db, "n"); e != 1 {
		t.Errorf("n's epoch %d stored after the fill, want 1", e)
	}
}

// §E.2.6 Per-entry sealing (v0.82; inverted from v0.77, which sealed it
// under the current epoch unjudged): a listing served while the head
// epochs are read in seals nothing derived from a head whose epoch isn't
// judged (here n's in a release preview of e2e catalog cat through its
// branch catb: cat's op, read through): n is by name only, and no epoch
// is recorded. The fill, which changes no epoch, still drops the listings
// that left n's values out, and the first listing after it judges n,
// under the branch's epoch (catb#1).
func TestV077V04BackfillDropsUnjudged(t *testing.T) {
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

	release := make(chan struct{})
	sc := func(block bool) *client.Client {
		opts := []client.Option{client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"}, map[string]any{"enc": svcJWK})),
			client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey())}
		if block {
			opts = append(opts, v077Blocking("/r/catb/n", release))
		}
		return s.Client(t, opts...)
	}
	db := filepath.Join(t.TempDir(), "tree.db")
	preview := func(o *tree.Options) { o.Recipient = svcPriv; o.Branches = map[string]string{"cat": "catb"} }
	x := startSvc(t, sc(false), svcOpts{now: s.Now, db: db}, preview)
	waitFor(t, "the preview to reach catb", func() bool {
		h, err := wr.NSHead(ctx, "catb")
		return err == nil && x.s.Checkpoint("cat") == h.ID
	})
	x.stop()
	v077Unfill(t, db)
	x = startSvc(t, sc(true), svcOpts{now: s.Now, db: db}, preview)
	rd := k.Grant(t, s.Now(), "user:r", both, []string{"read"})
	waitFor(t, "a listing", func() bool { return x.listingAs("/cat/children?of=root", rd).status == http.StatusOK })
	during := x.fetch("/cat/children?of=root", rd)
	if during.header.Get("Content-Type") == seal.ContentType {
		t.Fatalf("during the fill: a listing sealed whole with an unjudged node")
	}
	if e := entriesOf(t, decode(t, during.body))["n"]; e == nil || e["sealed"] != nil || e["title"] != nil || e["born"] != nil || e["href"] != "/r/cat/n" {
		t.Errorf("during the fill: n %v, want it by name only", e)
	}
	if e, _ := v077Epochs(t, db, "n"); e != 0 {
		t.Fatalf("during the fill: n's epoch %d stored; want none judged", e)
	}
	close(release)
	waitFor(t, "the epochs backfill", func() bool { return !x.s.EpochsPending() })
	// The listing that left n's values out isn't served again at its
	// at: the fill dropped it, kept and stored.
	if kid, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "n", keyOf); kid != "catb#1" || vals["title"] != "N" {
		t.Errorf("after the fill: n %v under %s, want its title under catb#1", vals, kid)
	}
	if e, b := v077Epochs(t, db, "n"); e != 1 || b != 1 {
		t.Errorf("after the fill: n's epochs %d, %d stored, want 1 judged for both", e, b)
	}
}

// §E.2.6, §E.3.1 (v0.77): a born is judged once, as its revision, whatever
// the head. In a release preview of e2e catalog cat through its branch
// catb, node n's born is cat's op, read through (pending), and its head
// catb's own op. A listing judges the born under epoch 1, and a new head
// of n is applied before the listing records it: the born's revision is
// unchanged, so the judgement stands, and later listings keep it.
// (Before, it was dropped with the head's, and the born left pending, to
// be judged again, under whatever epoch is current then.)
func TestV077V04BornJudgedAcrossHeads(t *testing.T) {
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
	retitle := func(title string) {
		h := must(wr.Head(ctx, "catb", "n"))
		must(x2.AppendSealed(ctx, "catb", "n", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": title}}))
	}
	retitle("N1")

	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"}, map[string]any{"enc": svcJWK})),
		client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	db := filepath.Join(t.TempDir(), "tree.db")
	preview := func(o *tree.Options) { o.Recipient = svcPriv; o.Branches = map[string]string{"cat": "catb"} }
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db}, preview)
	reached := func() {
		t.Helper()
		waitFor(t, "the preview to reach catb", func() bool {
			h, err := wr.NSHead(ctx, "catb")
			return err == nil && x.s.Checkpoint("cat") == h.ID
		})
	}
	reached()
	if e, b := v077Epochs(t, db, "n"); e != 1 || b >= 0 {
		t.Fatalf("n's epochs %d, %d before any listing, want 1 (its head's own op) and its born pending", e, b)
	}
	var once sync.Once
	x.s.BeforeJudge(func() {
		once.Do(func() {
			retitle("N2")
			reached()
		})
	})
	rd := k.Grant(t, s.Now(), "user:r", both, []string{"read"})
	if r := x.listingAs("/cat/children?of=root", rd); r.status != http.StatusOK {
		t.Fatalf("children: %d %v", r.status, r.body)
	}
	x.s.BeforeJudge(nil)
	if _, b := v077Epochs(t, db, "n"); b != 1 {
		t.Errorf("n's born epoch %d once listed, want 1 recorded though its head moved on", b)
	}
	retitle("N3")
	reached()
	if r := x.listingAs("/cat/children?of=root", rd); r.status != http.StatusOK {
		t.Fatalf("children: %d %v", r.status, r.body)
	}
	if _, b := v077Epochs(t, db, "n"); b != 1 {
		t.Errorf("n's born epoch %d after another listing, want 1, judged once", b)
	}
}
