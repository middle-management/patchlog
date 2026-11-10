package index_test

// v0.26.1 security fixes (I1): results computed while a namespace turns
// private are neither kept nor served in its public URL space.

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// v0261NarrowPR is pr, public, with one document, and an index of it;
// narrow turns pr private (read: grant) and waits until the index applied
// it (§9: narrowing purges idx:pr, §A.1).
func v0261NarrowPR(t *testing.T) (x *svc, narrow func()) {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	x = startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second }) // the default (index.Open)
	x.caughtUp("pr")
	return x, func() {
		must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
		x.appliedUpTo(x.caughtUp("pr"))
	}
}

// TestV0261NarrowBeforeAnswer: pr turns private, its narrowing applied with
// its purge of idx:pr, between the head pointer's read check (public) and
// its answer. answer re-reads only the encryption (errInfoChanged), so the
// result at the private at is computed for the public URL space and kept
// there; is it served, and with public caching?
func TestV0261NarrowBeforeAnswer(t *testing.T) {
	x, narrow := v0261NarrowPR(t)
	var once atomic.Bool
	x.ix.OnBeforeAnswer(func() {
		if once.CompareAndSwap(false, true) {
			narrow()
		}
	})
	r := x.raw("/pr?limit=7", "")
	if !once.Load() {
		t.Fatalf("never computed: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	t.Logf("anonymous /pr after the narrowing: %d Location=%q Cache-Control=%q", r.status, loc, r.header.Get("Cache-Control"))
	if r.status == 302 && strings.HasPrefix(loc, "/pr/at/") {
		t.Errorf("anonymous head pointer of pr, private now, redirected into the public URL space: %s (Cache-Control %q)", loc, r.header.Get("Cache-Control"))
		if x.ix.KeptHas(loc) {
			t.Errorf("a result at %s, an at where pr is private, is kept under the public URL", loc)
		}
		f := x.raw(loc, "")
		t.Logf("anonymous GET %s: %d Cache-Control=%q body=%v", loc, f.status, f.header.Get("Cache-Control"), f.body)
		if f.status == 200 {
			t.Errorf("anonymous GET %s: 200, pr's hits at an at where it is private, Cache-Control %q", loc, f.header.Get("Cache-Control"))
		}
	}
}

// TestV0261NarrowServedInApplyWindow: pr turns private. Apply commits the
// narrowing, purges idx:pr (kept results, the CDN's copies) and publishes
// the checkpoint, and only at its very end tells the grant checker
// (checker.Observe); keys.Observe, the encryption's, is at its start. An
// anonymous reader in between (here: from OnApply, which runs in that
// window) passes the read check on the checker's cached document (it
// keeps it for CheckerTTL, 30 s by default), and gets pr's result at the
// at where it is private, kept, with public immutable caching: cached by
// the CDN after the purge that was to drop pr's public results.
func TestV0261NarrowServedInApplyWindow(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	var x *svc
	var armed atomic.Bool
	type seen struct {
		ptr, at resp
		loc     string
	}
	got := make(chan seen, 1)
	x = startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.CheckerTTL = 30 * time.Second // the default (index.Open)
			rec := o.OnApply
			o.OnApply = func(b *follow.Batch) {
				rec(b)
				for _, u := range b.Units {
					if u.Config != nil && armed.CompareAndSwap(true, false) {
						var sn seen
						sn.ptr = x.raw("/pr?limit=9", "")
						sn.loc = sn.ptr.header.Get("Location")
						if strings.HasPrefix(sn.loc, "/pr/at/") {
							sn.at = x.raw(sn.loc, "")
						}
						got <- sn
					}
				}
			}
		})
	x.caughtUp("pr")
	// The read check reads pr's document once, public, while it is.
	if r := x.raw("/pr?limit=8", ""); r.status != 302 {
		t.Fatalf("public: %d %v", r.status, r.body)
	}
	armed.Store(true)
	must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	head := x.caughtUp("pr")
	sn := <-got
	t.Logf("in the window: /pr %d Location=%q; %s: %d Cache-Control=%q body=%v", sn.ptr.status, sn.loc, sn.loc, sn.at.status, sn.at.header.Get("Cache-Control"), sn.at.body)
	if sn.at.status == 200 {
		t.Errorf("anonymous GET %s (pr private since %s): 200 with Cache-Control %q and Cache-Tag %q: %v",
			sn.loc, head, sn.at.header.Get("Cache-Control"), sn.at.header.Get("Cache-Tag"), sn.at.body)
	}
	if x.ix.KeptHas(sn.loc) {
		t.Errorf("kept under the public URL after the purge: %s", sn.loc)
	}
}

// TestV0261NarrowWrittenPrivateServedPublic: as TestV0261NarrowServedInApplyWindow,
// with a document written after pr turned private applied in the same
// batch as the narrowing: in the window it is served to anonymous readers.
func TestV0261NarrowWrittenPrivateServedPublic(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "public"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	var x *svc
	var hold, armed atomic.Bool
	got := make(chan resp, 1)
	x = startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) {
			o.CheckerTTL = 30 * time.Second
			rec := o.OnApply
			o.OnApply = func(b *follow.Batch) {
				rec(b)
				if hold.CompareAndSwap(true, false) {
					// The follower waits here: both entries are in the log
					// when it next reads it.
					must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
					must(w.CreateDoc(ctx, "pr", "b", map[string]any{"title": "written while private"}))
					armed.Store(true)
					return
				}
				for _, u := range b.Units {
					if u.Config != nil && armed.CompareAndSwap(true, false) {
						p := x.raw("/pr?limit=9", "")
						loc := p.header.Get("Location")
						if strings.HasPrefix(loc, "/pr/at/") {
							got <- x.raw(loc, "")
						} else {
							got <- p
						}
						return
					}
				}
			}
		})
	x.caughtUp("pr")
	if r := x.raw("/pr?limit=8", ""); r.status != 302 {
		t.Fatalf("public: %d %v", r.status, r.body)
	}
	hold.Store(true)
	must(w.CreateDoc(ctx, "pr", "a0", map[string]any{"title": "public too"}))
	x.caughtUp("pr")
	var r resp
	select {
	case r = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the narrowing was never applied with a config unit")
	}
	t.Logf("anonymous in the window: %d Cache-Control=%q body=%v", r.status, r.header.Get("Cache-Control"), r.body)
	if r.status == 200 && strings.Contains(fmt.Sprint(r.body), "resource:b") {
		t.Errorf("pr/b, written after pr turned private, served to an anonymous reader with Cache-Control %q: %v", r.header.Get("Cache-Control"), r.body)
	}
}

// TestV0261RefsNarrowRetry: an anonymous /_refs answer over pr and pub,
// both public, reads its hits; pr then turns private (its purge of idx:pr
// applied) and pr/b is written. The answer lost to the purge and
// refsAnswer computes it again (recover) with the reader of before (pr
// still among its public namespaces), and keeps it. Once the grant checker
// has observed the change, is that kept answer, showing pr/b, served at
// its URL to an anonymous reader, whose gs is the empty set's either way?
func TestV0261RefsNarrowRetry(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"pr", "pub", "schemas"} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	}
	nss := []string{"pr", "pub", "schemas"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", nss, []string{"read", "create", "config"})))
	sch := must(w.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{"title": map[string]any{"type": "string"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"$schema": ref, "title": "public", "related": []any{"/r/target/x"}}))
	must(w.CreateDoc(ctx, "pub", "p", map[string]any{"$schema": ref, "title": "public", "related": []any{"/r/target/x"}}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr", "pub"}, untyped: true, now: s.Now})
	x.caughtUp("pr")
	x.caughtUp("pub")
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	if got := refsAllHits(x.follow(refs, "").body); got != "pr/a pub/p" {
		t.Fatalf("before: %s", got)
	}
	p := x.raw(refs, "")
	at := strings.SplitN(p.header.Get("Location"), "?", 2)[0] + "?limit=7&to=" + url.QueryEscape("/r/target/x")
	var once atomic.Bool
	x.ix.OnRefsRead(func() {
		if once.CompareAndSwap(false, true) {
			must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
			must(w.CreateDoc(ctx, "pr", "b", map[string]any{"$schema": ref, "title": "written while private", "related": []any{"/r/target/x"}}))
			x.caughtUp("pr")
		}
	})
	r := x.raw(at, "")
	if !once.Load() {
		t.Fatalf("never computed: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	t.Logf("anonymous GET %s: %d Location=%q Cache-Control=%q hits=%v", at, r.status, loc, r.header.Get("Cache-Control"), r.body["hits"])
	if r.status == 200 && strings.Contains(refsAllHits(r.body), "pr/") {
		t.Errorf("served at once: %s", refsAllHits(r.body))
	}
	if r.status != 302 || loc == "" {
		return
	}
	time.Sleep(100 * time.Millisecond) // the grant checker observed pr's change by now
	if r := x.raw("/pr?limit=3", ""); r.status != 401 {
		t.Fatalf("anonymous /pr: %d, want 401: the checker hasn't observed yet", r.status)
	}
	r2 := x.raw(loc, "")
	t.Logf("anonymous GET %s: %d Cache-Control=%q body=%v", loc, r2.status, r2.header.Get("Cache-Control"), r2.body)
	if r2.status == 200 && strings.Contains(refsAllHits(r2.body), "pr/") {
		t.Errorf("anonymous GET %s with pr private: 200 %s, Cache-Control %q, Cache-Tag %q", loc, refsAllHits(r2.body), r2.header.Get("Cache-Control"), r2.header.Get("Cache-Tag"))
	}
	if r3 := x.raw(refs, ""); r3.status == 302 {
		t.Logf("anonymous head pointer now: %s", r3.header.Get("Location"))
	}
}

// TestV0261RevokedBeforeAnswer: pr is private; r's grant is revoked
// (§C.4), the revocation applied, between its head pointer's read check
// and its answer. A revocation purges nothing (§9), so only a read check
// made again once gen is taken refuses r: its head pointer is 401, not a
// redirect to a result computed and kept for it at the checkpoint that
// revoked it.
func TestV0261RevokedBeforeAnswer(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pr"))).CreateNamespace(ctx, "pr", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"pr"}, []string{"read", "create", "config"})))
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"title": "secret"}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"pr"}, []string{"read"})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second })
	x.caughtUp("pr")
	r := k.Grant(t, s.Now(), "user:r", []string{"pr"}, []string{"read"})
	if p := x.raw("/pr?limit=6", r); p.status != 302 {
		t.Fatalf("r before: %d %v", p.status, p.body)
	}
	g := must(grant.Decode(r, 0))
	var once atomic.Bool
	x.ix.OnBeforeAnswer(func() {
		if once.CompareAndSwap(false, true) {
			must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "add", "path": "/revoked", "value": []any{g.ID().String()}}}))
			x.appliedUpTo(x.caughtUp("pr"))
		}
	})
	p := x.raw("/pr?limit=7", r)
	if !once.Load() {
		t.Fatalf("never computed: %d %v", p.status, p.body)
	}
	if p.status != 401 {
		t.Errorf("r's head pointer, its grant revoked before its answer: %d Location=%q, want 401", p.status, p.header.Get("Location"))
	}
}

// TestV0261RefsNarrowBeforeAnswer: as TestV0261NarrowBeforeAnswer, for
// /_refs: pr turns private, its narrowing applied with its purge of
// idx:pr, between an anonymous answer's read check (pr public then) and
// its computation. No answer showing pr's hits is kept or served at the
// public /_refs URL.
func TestV0261RefsNarrowBeforeAnswer(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"pr", "pub", "schemas"} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	}
	nss := []string{"pr", "pub", "schemas"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", nss, []string{"read", "create", "config"})))
	sch := must(w.CreateDoc(ctx, "schemas", "item", pageSchemaWith(map[string]any{"title": map[string]any{"type": "string"}})))
	ref := "/r/schemas/item/rev/" + sch.ID
	must(w.CreateDoc(ctx, "pr", "a", map[string]any{"$schema": ref, "title": "public", "related": []any{"/r/target/x"}}))
	must(w.CreateDoc(ctx, "pub", "p", map[string]any{"$schema": ref, "title": "public", "related": []any{"/r/target/x"}}))
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"pr", "pub"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.CheckerTTL = 30 * time.Second })
	x.caughtUp("pr")
	x.caughtUp("pub")
	refs := "/_refs?to=" + url.QueryEscape("/r/target/x")
	if got := refsAllHits(x.follow(refs, "").body); got != "pr/a pub/p" {
		t.Fatalf("before: %s", got)
	}
	var once atomic.Bool
	x.ix.OnBeforeAnswer(func() {
		if once.CompareAndSwap(false, true) {
			must(w.PatchConfig(ctx, "pr", must(w.NSHead(ctx, "pr")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
			must(w.CreateDoc(ctx, "pr", "b", map[string]any{"$schema": ref, "title": "written while private", "related": []any{"/r/target/x"}}))
			x.appliedUpTo(x.caughtUp("pr"))
		}
	})
	r := x.raw(refs+"&limit=5", "")
	if !once.Load() {
		t.Fatalf("never computed: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	t.Logf("anonymous /_refs after the narrowing: %d Location=%q", r.status, loc)
	if r.status == 200 && strings.Contains(refsAllHits(r.body), "pr/") {
		t.Errorf("served at once: %s", refsAllHits(r.body))
	}
	if r.status != 302 || loc == "" {
		return
	}
	if x.ix.KeptHas(loc) {
		t.Logf("kept: %s", loc)
	}
	r2 := x.raw(loc, "")
	if r2.status == 200 && strings.Contains(refsAllHits(r2.body), "pr/") {
		t.Errorf("anonymous GET %s with pr private: 200 %s, Cache-Control %q", loc, refsAllHits(r2.body), r2.header.Get("Cache-Control"))
	}
}

// TestV0261RotationBeforeJudge (I-L1; §E.2.6: a pending epoch is "judged
// once, when the service first seals a value derived from it"): in e-b,
// an e2e branch of e, r's head is e's op read through, its epoch pending.
// e-b rotates, the rotation applied, after the first answer that seals r
// has read its rows and before it judges r. A rotation purges nothing,
// so r isn't judged under the epoch the rotation replaced (a reader
// revoked by it would read r): it is judged under the epoch current once
// it is, the rotation's.
func TestV0261RotationBeforeJudge(t *testing.T) {
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
	must(ad.CreateDocSealed(ctx, "e", "r", map[string]any{"$schema": ref, "title": "zq r"}))
	must(ac.CreateBranch(ctx, "e", client.BranchRequest{Name: "e-b"}))
	must(ad.InitKeyring(ctx, "e-b", idxPriv.PublicKey()))
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}, map[string]any{"enc": idxJWK})),
		client.WithKeyringSenders(adminPriv.PublicKey()))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, branches: true, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	x.caughtUp("e-b")
	var once atomic.Bool
	var e int
	x.ix.OnBeforeJudge(func() {
		if once.CompareAndSwap(false, true) {
			e = must(ad.RotateEpoch(ctx, "e-b", idxPriv.PublicKey()))
			x.appliedUpTo(x.caughtUp("e-b"))
		}
	})
	got := p37Kids(t, x.fetch("/e-b?q=zq", "").body)["r"]
	if !once.Load() {
		t.Fatal("never judged")
	}
	if want := fmt.Sprintf("e-b#%d", e); got != want {
		t.Errorf("e-b/r, pending, judged after e-b rotated to %d: under %q, want %q", e, got, want)
	}
}

// TestV0261RotationWhileJudging (F3; I-L1's remaining window): as
// TestV0261RotationBeforeJudge, with e-b's rotation applied after the
// answer read the encryption a last time, as the pending epoch is about
// to be judged. Judged under the epoch the rotation replaced, r would be
// sealed under it for good; it is judged under the rotation's.
func TestV0261RotationWhileJudging(t *testing.T) {
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
	must(ad.CreateDocSealed(ctx, "e", "r", map[string]any{"$schema": ref, "title": "zq r"}))
	must(ac.CreateBranch(ctx, "e", client.BranchRequest{Name: "e-b"}))
	must(ad.InitKeyring(ctx, "e-b", idxPriv.PublicKey()))
	ic := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"}, map[string]any{"enc": idxJWK})),
		client.WithKeyringSenders(adminPriv.PublicKey()))
	x := startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"e"}, branches: true, untyped: true, now: s.Now},
		func(o *indexOpts) { o.Recipient = idxPriv })
	x.caughtUp("e")
	x.caughtUp("e-b")
	var once atomic.Bool
	var e int
	x.ix.OnJudge(func() {
		if once.CompareAndSwap(false, true) {
			e = must(ad.RotateEpoch(ctx, "e-b", idxPriv.PublicKey()))
			x.appliedUpTo(x.caughtUp("e-b"))
		}
	})
	got := p37Kids(t, x.fetch("/e-b?q=zq", "").body)["r"]
	if !once.Load() {
		t.Fatal("never judged")
	}
	if want := fmt.Sprintf("e-b#%d", e); got != want {
		t.Errorf("e-b/r, pending, judged after e-b rotated to %d: under %q, want %q", e, got, want)
	}
}

// v0261Start starts an index of w following nss on the database db, as
// v75x.start does; rebuild replays it, snapshot bootstraps each namespace
// from its /heads listing (follow.WithSnapshot).
func v0261Start(w *v75x, db string, rebuild, snapshot bool, nss ...string) *svc {
	w.t.Helper()
	ev := must(edge.New([]byte("s3cret"), "", ""))
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	x := startSvcWith(w.t, w.s.Client(w.t, client.WithBearer(w.k.Grant(w.t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: db, ns: nss, untyped: true, rebuild: rebuild, now: w.s.Now},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate, o.Edge = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), svcedge.DefaultExchangeRate, ev
			if snapshot {
				o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot())
			}
		})
	for _, ns := range nss {
		x.caughtUp(ns)
	}
	return x
}

// v0261Freeze freezes cat-season, as a purge-ns needs (§8.5), and
// v0261Purge purges it.
func v0261Freeze(w *v75x) {
	w.t.Helper()
	ctx := context.Background()
	must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
}

func v0261Purge(w *v75x) {
	w.t.Helper()
	purger := w.s.Client(w.t, client.WithBearer(w.k.Grant(w.t, w.s.Now(), "user:root", []string{"cat-season"}, []string{"purge-ns"})))
	must(purger.PurgeNamespace(context.Background(), "cat-season", w.head("cat-season")))
}

// TestV0261SnapshotRefreshesTrust (I-L2; §B.11.9 Where, "as their
// documents alone decide"): the index serves cat-season and matches, and
// records cat-season's catalog.trust, matches. While it is down,
// cat-season stops trusting matches and is frozen; the index is rebuilt
// from snapshots, which carry no config entry, and cat-season is then
// purged, its purge-ns the only entry after the snapshot. matches is
// uncovered: li, a partial reader, is 403, with no marker. Before, the
// trust recorded before the rebuild was read once cat-season was purged,
// and li got a g: marker and empty answers.
func TestV0261SnapshotRefreshesTrust(t *testing.T) {
	t.Parallel()
	w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
	db := filepath.Join(t.TempDir(), "i.db")
	x1 := v0261Start(w, db, false, false, "matches", "cat-season")
	li := w.reader("user:li", []any{"fans"})
	if r := x1.raw("/matches", li); r.status != 302 || !strings.Contains(r.header.Get("Location"), "/g/") {
		t.Fatalf("li while cat-season trusts matches: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	x1.stop()
	ctx := context.Background()
	must(w.admin.PatchConfig(ctx, "cat-season", must(w.admin.NSHead(ctx, "cat-season")).Config,
		[]any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
	v0261Freeze(w)
	x := v0261Start(w, db, true, true, "matches", "cat-season")
	if r := x.raw("/matches", li); r.status != 403 {
		t.Fatalf("li once cat-season no longer trusts matches: %d %s %v", r.status, r.header.Get("Location"), r.body)
	}
	v0261Purge(w)
	waitFor(t, "the index applies cat-season's purge", func() bool {
		for _, b := range x.batches() {
			if b.NS == "cat-season" && b.Coalesce().PurgedNS {
				return true
			}
		}
		return false
	})
	x.ix.ExpireGrantChecks()
	if r := x.raw("/matches", li); r.status != 403 {
		t.Errorf("li once cat-season, which no longer trusted matches as of the snapshot, is purged: %d %s %v, want 403 with no marker", r.status, r.header.Get("Location"), r.body)
	}
}
