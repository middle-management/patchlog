package tree_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	"github.com/middle-management/patchlog/internal/tree"
)

// T1 (security review of v0.26.0), §9, §A.1, §E.2.6: a listing reads the
// catalog's encryption again right after it takes its kept generation
// (cb3320c), and a raise applied later must still keep it from being
// computed in the clear at the at after the raise. Before v0.26.1 a raise
// purged nothing (applyLocked's tags), so one landing after that re-read
// and before the graph was read (fileSealing, the key fetches) left the
// listing computed in the clear at the at after the raise, kept, and
// served there (public, immutable in a public catalog). Now the raise
// purges ns:{catalog}, and the encryption is read again once the graph
// is read.
func TestV0261RaiseAfterInfoReread(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"grant", "public"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ks := must(keystore.New(keystore.Generate()))
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": read, "keys": []any{k.Entry("*")},
				"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
			must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
			must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Season", "parents": parents("root@a0")}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
			x := startSvc(t, sc, svcOpts{now: s.Now}, withScopeView)
			x.caughtUp("cat")
			full := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})
			x.fetch("/cat/children?of=root", full)

			var once sync.Once
			ran := false
			// AfterGeneration runs after listing() took its generation
			// AND re-read keys.Info (http.go:1203-1215).
			x.s.AfterGeneration(func() {
				once.Do(func() {
					ran = true
					h := must(w.NSHead(ctx, "cat"))
					must(w.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
					createNonced(t, w, "cat", "late", map[string]any{"title": "Late zq9y", "parents": parents("root@b0")})
					x.caughtUp("cat")
				})
			})
			f := x.fetch("/cat/subtree?of=root", full)
			x.s.AfterGeneration(nil)
			if !ran {
				t.Fatal("the listing was not computed")
			}
			c := x.fetch("/cat/children?of=root", full)
			cur := "/at/" + x.s.At() + "/"
			if !strings.Contains(c.path, cur) || strings.Contains(string(c.body), "zq9y") {
				t.Fatalf("control at %s (current %s): %s", c.path, x.s.At(), c.body)
			}
			if strings.Contains(f.path, cur) && strings.Contains(string(f.body), "zq9y") {
				t.Errorf("listing at %s, the at after the raise to sealed, in the clear (Cache-Control %q): %s", f.path, f.header.Get("Cache-Control"), f.body)
			}
			again := x.fetch(f.path, full)
			if strings.Contains(string(again.body), "zq9y") {
				t.Errorf("kept listing at %s served again in the clear: Cache-Control %q", again.path, again.header.Get("Cache-Control"))
			}
			if read == "public" {
				anon := x.fetch(f.path, "")
				if strings.Contains(string(anon.body), "zq9y") {
					t.Errorf("anonymous read of %s in the clear: Cache-Control %q", anon.path, anon.header.Get("Cache-Control"))
				}
			}
		})
	}
}

// T2 (security review of v0.26.0), §9, §A.1 via §B.5, §E.2.6 ("until a
// config entry on which §9 purges a source's ns:{ns} drops it"): a raise
// to sealed purges ns:{catalog} in the tree service, as the index's
// narrowed purge does. Before v0.26.1 it purged nothing: a listing kept
// in the clear at the at before the raise stayed kept and was served
// there, public immutable, after the service applied the raise, and the
// service's Purger (its own CDN) was never told.
func TestV0261RaiseLeavesKeptClearListing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Secret qx7w", "parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now}, withScopeView)
	x.caughtUp("cat")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "qx7w") {
		t.Fatalf("setup: %s", before.body)
	}
	x.mu.Lock()
	npurges := len(x.purges)
	x.mu.Unlock()

	h := must(w.NSHead(ctx, "cat"))
	must(w.PatchConfig(ctx, "cat", h.Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
	x.caughtUp("cat")

	x.mu.Lock()
	after := append([][]string(nil), x.purges[npurges:]...)
	x.mu.Unlock()
	purgedCat := false
	for _, tags := range after {
		for _, tg := range tags {
			if tg == "ns:cat" {
				purgedCat = true
			}
		}
	}
	if !purgedCat {
		t.Errorf("raise to sealed applied: the service purged %v, never ns:cat", after)
	}
	r := x.raw(before.path, "")
	if r.status == 200 {
		b, _ := jsonMarshal(r.body)
		if strings.Contains(b, "qx7w") {
			t.Errorf("after the raise to sealed, %s is still served 200 in the clear, Cache-Control %q, Cache-Tag %q: %s", before.path, r.header.Get("Cache-Control"), r.header.Get("Cache-Tag"), b)
		}
	}
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// v0261Purges is how many purges x's Purger was sent, and how many of
// those, and of its queued second purges, carry tag.
func v0261Purges(x *svc, tag string) (n, sent, queued int) {
	x.mu.Lock()
	n = len(x.purges)
	for _, tags := range x.purges {
		if slices.Contains(tags, tag) {
			sent++
		}
	}
	x.mu.Unlock()
	for _, tags := range x.s.QueuedRepurges() {
		if slices.Contains(tags, tag) {
			queued++
		}
	}
	return n, sent, queued
}

// §9, §A.1 via §B.5, §E.2.6 (v0.26.1): a config entry that narrows the
// catalog, or a content namespace it trusts, purges ns:{ns} in the tree
// service: kept and stored listings go, and so do the service's own CDN
// copies (Purger) with their second purge queued. A listing kept at the
// at before it, public and with the item's title in the clear, is not
// served there after it. A config entry that narrows nothing (maxLag, or
// a rotation of a namespace already sealed) purges nothing.
func TestV0261NarrowingPurges(t *testing.T) {
	t.Parallel()
	type step struct {
		ns    string
		patch []any
	}
	sealed := []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}
	private := []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}
	maxLag := []any{map[string]any{"op": "add", "path": "/maxLag", "value": "PT90S"}}
	rotate := []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": 2.0}}
	cases := []struct {
		name   string
		before []step // applied, and purging, first
		step   step
		purges bool
	}{
		{name: "catalog private", step: step{"cat", private}, purges: true},
		{name: "catalog sealed", step: step{"cat", sealed}, purges: true},
		{name: "trusted sealed", step: step{"sec", sealed}, purges: true},
		{name: "trusted private", step: step{"sec", private}, purges: true},
		{name: "catalog maxLag", step: step{"cat", maxLag}},
		{name: "trusted maxLag", step: step{"sec", maxLag}},
		{name: "trusted rotation", before: []step{{"sec", sealed}}, step: step{"sec", rotate}},
	}
	for _, tc := range cases {
		for _, view := range []bool{false, true} {
			name := tc.name
			if view {
				name += " role view"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
				k := clienttest.NewKey("k")
				for _, ns := range []string{"cat", "sec"} {
					doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
					if ns == "cat" {
						doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag", "title": "/title"}
					}
					must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
				}
				both := []string{"cat", "sec"}
				w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
				must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
				must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "Secret vw3k"}))
				must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
				sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
				var mods []func(*tree.Options)
				if view {
					mods = append(mods, withScopeView)
				}
				x := startSvc(t, sc, svcOpts{now: s.Now}, mods...)
				x.caughtUp("cat", "sec")
				apply := func(st step) {
					t.Helper()
					h := must(w.NSHead(ctx, st.ns))
					must(w.PatchConfig(ctx, st.ns, h.Config, st.patch))
					x.caughtUp(st.ns)
				}
				for _, st := range tc.before {
					apply(st)
				}
				before := x.fetch("/cat/children?of=root", "")
				if len(tc.before) == 0 && !strings.Contains(string(before.body), "vw3k") {
					t.Fatalf("setup: %s", before.body)
				}
				tag := "ns:" + tc.step.ns
				_, sent0, queued0 := v0261Purges(x, tag)
				apply(tc.step)
				_, sent1, queued1 := v0261Purges(x, tag)
				if sent, queued := sent1 > sent0, queued1 > queued0; sent != tc.purges || queued != tc.purges {
					t.Errorf("%s: sent %s to the Purger %v, its second purge queued %v; want %v", tc.name, tag, sent, queued, tc.purges)
				}
				if !tc.purges {
					return
				}
				r := x.raw(before.path, "")
				if r.status == 200 {
					if b, _ := jsonMarshal(r.body); strings.Contains(b, "vw3k") {
						t.Errorf("%s: %s still served 200 with the title, Cache-Control %q: %s", tc.name, before.path, r.header.Get("Cache-Control"), b)
					}
				}
			})
		}
	}
}

// §9, §E.2.6 (v0.26.1): a raise of the catalog to e2e that a service
// without a keyring recipient key can't follow stops its follower, and
// the batch isn't applied (Apply, keys.Recheck), so no apply purges for
// it: the catalog is 404 at the service, and ns:cat is still sent to its
// Purger, so a CDN copy of a listing kept in the clear before the raise
// goes too.
func TestV0261RaiseToE2EWithoutKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	wJWK, wPriv := must2(seal.GenerateRecipient())
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": wJWK})),
		client.WithKeys(client.NewKeys(wPriv)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Secret m4zt", "parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "m4zt") {
		t.Fatalf("setup: %s", before.body)
	}
	_, sent0, _ := v0261Purges(x, "ns:cat")

	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "e2e"}}}))
	waitFor(t, "the raise to e2e", func() bool { return x.raw("/cat/roots", "").status == 404 })
	waitFor(t, "ns:cat sent to the Purger", func() bool { _, sent, _ := v0261Purges(x, "ns:cat"); return sent > sent0 })
	if r := x.raw(before.path, ""); r.status == 200 {
		t.Errorf("after the raise to e2e, %s is served 200: %v", before.path, r.body)
	}
}

// §E.2.6, §E.3.1 (v0.26.1): a rotation purges nothing, so a listing reads
// the catalog's encryption again once its graph is read, before it
// judges any epoch by it. In e2e catalog cat, node n's head is pending
// (written in the clear before the raise); a rotation to cat#2 applied
// after the listing took its kept generation and read the encryption
// again (AfterGeneration), during fileSealing and the key fetches, has
// the listing view the graph after it: n is judged by cat#2, the epoch
// in force, never cat#1, the one it read first.
func TestV0261RotationAfterInfoReread(t *testing.T) {
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
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"}, map[string]any{"enc": svcJWK})),
		client.WithKeys(client.NewKeys(svcPriv)), client.WithKeyringSenders(wPriv.PublicKey()))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Recipient = svcPriv })
	x.caughtUp("cat")
	if e, _ := v077Epochs(t, db, "n"); e != 0 {
		t.Fatalf("n's epoch %d before any listing, want it pending", e)
	}
	rd := k.Grant(t, s.Now(), "user:r", []string{"cat"}, []string{"read"})

	var once sync.Once
	ran := false
	x.s.AfterGeneration(func() {
		once.Do(func() {
			ran = true
			must(x2.RotateEpoch(ctx, "cat", svcPriv.PublicKey()))
			x.caughtUp("cat")
		})
	})
	x.fetch("/cat/children?of=root", rd)
	x.s.AfterGeneration(nil)
	if !ran {
		t.Fatal("the listing was not computed")
	}
	if e, _ := v077Epochs(t, db, "n"); e != 2 {
		t.Errorf("n judged by cat#%d, want cat#2, the epoch in force as the listing read the graph", e)
	}
	if kid, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "n", keyOf); kid != "cat#2" || vals["title"] != "N" {
		t.Errorf("n %v sealed under %s, want under cat#2", vals, kid)
	}
}

// §H.3, §E.2.6 (v0.26.1): a listing reads what its file metadata is
// sealed by (fileSealing) before its graph, so it reads it again once the
// graph is read. In public file tree cat over public namespace files, a
// raise of files to sealed applied between the two, with files.late
// written after it, has the listing view a graph in which files.late's
// file metadata is a sealed namespace's: it is computed again, and
// gives that metadata sealed, never in the clear.
func TestV0261FileSealingAfterRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"files": {"read": "public", "keys": []any{k.Entry("*")}},
		"cat":   {"read": "public", "keys": []any{k.Entry("*")}, "catalog": filesCatalog("files")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	both := []string{"cat", "files"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"parents": []any{}}))
	createNonced(t, w, "files", "notes", map[string]any{"title": "Notes"})
	must(w.CreateDoc(ctx, "cat", "files.notes", map[string]any{"parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "files")
	if f := fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.notes"]); f["size"] == nil {
		t.Fatalf("setup: file metadata %v, want it in the clear", f)
	}

	var once sync.Once
	ran := false
	x.s.AfterFileSealing(func() {
		once.Do(func() {
			ran = true
			must(w.PatchConfig(ctx, "files", must(w.NSHead(ctx, "files")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
			createNonced(t, w, "files", "late", map[string]any{"title": "Late"})
			must(w.CreateDoc(ctx, "cat", "files.late", map[string]any{"parents": parents("root@a1")}))
			x.caughtUp("cat", "files")
		})
	})
	f := x.fetch("/cat/subtree?of=root", "")
	x.s.AfterFileSealing(nil)
	if !ran {
		t.Fatal("the listing was not computed")
	}
	// The listing computed, and kept, and the same listing read again.
	for _, g := range []fetched{f, x.fetch(f.path, "")} {
		tree, _ := decode(t, g.body)["tree"].(map[string]any)
		kids, _ := tree["children"].([]any)
		for _, c := range kids {
			e := c.(map[string]any)
			if fileOf(e)["size"] != nil {
				t.Errorf("%s at %s: file metadata in the clear after the raise to sealed (Cache-Control %q): %v", e["name"], g.path, g.header.Get("Cache-Control"), fileOf(e))
			}
		}
	}
}

// v0261Get follows up to 5 redirects without failing the test: the final
// status, headers, body and path.
func v0261Get(x *svc, path, token string) (int, http.Header, string, string) {
	for range 5 {
		req := must(http.NewRequest("GET", x.http.URL+path, nil))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		r := must(noRedirect.Do(req))
		b := must(io.ReadAll(r.Body))
		r.Body.Close()
		if r.StatusCode == 302 {
			path = r.Header.Get("Location")
			continue
		}
		return r.StatusCode, r.Header, string(b), path
	}
	return 0, nil, "", path
}

// v0261HoldWAL opens a read transaction on the service's database and reads
// from it, so that its snapshot predates the next commit: a later
// PRAGMA wal_checkpoint(TRUNCATE) waits for it (busy_timeout, 10 s). The
// returned func ends it.
func v0261HoldWAL(t *testing.T, db string) func() {
	t.Helper()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	tx := must(sq.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true}))
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM meta`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	done := false
	release := func() {
		if done {
			return
		}
		done = true
		_ = tx.Rollback()
		_ = sq.Close()
	}
	t.Cleanup(release)
	return release
}

// §9 ("making a namespace private ... requires the origin to purge the
// tag ns:{ns}"), §B.11.5 ("served at /{catalog}/at/{at}/…, unfiltered,
// while they stay public"), §A.1 ("serving or keeping none computed from
// what was read before it"): whether a reader is the anonymous public
// viewer is decided from the grant checker's cached namespace document
// (publicViewer, checker.Config), which Apply refreshes (checker.Observe)
// only at its very end: after the narrowing's purge went out, after the
// new checkpoint is published (s.cur), and after the WAL checkpoint the
// purge triggers. unchanged() re-reads only the encryption, never the read
// mode. In that window an anonymous reader is served the listing at the
// at AFTER the catalog (or a namespace it trusts) turned private, with
// what the same batch wrote after the config entry, public immutable,
// and it is kept after the purge.
//
// The window is widened here, without touching the service, by holding a
// read transaction on its database so the WAL checkpoint waits.
//
// Fixed in v0.26.1: Apply tells the checker (checker.Observe) as it
// starts, before the graph moves.
func TestV0261PrivateServedPublicBeforeCheckerObserve(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"cat", "sec"} {
		t.Run(which, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			for _, ns := range []string{"cat", "sec"} {
				doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
				if ns == "cat" {
					doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag", "title": "/title"}
				}
				must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
			}
			both := []string{"cat", "sec"}
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
			must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
			must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "A"}))
			must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
			db := filepath.Join(t.TempDir(), "tree.db")
			// The default checker TTL (the harness sets 1 ms).
			x := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.CheckerTTL = 30 * time.Second })
			x.caughtUp("cat", "sec")
			if st, _, b, _ := v0261Get(x, "/cat/children?of=root", ""); st != 200 {
				t.Fatalf("setup: %d %s", st, b)
			}
			at0, nb0 := x.s.At(), x.batches()

			// One batch: the narrowing config entry, then a write.
			release := v0261HoldWAL(t, db)
			private := []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}
			h := must(w.NSHead(ctx, which))
			req := client.BatchRequest{Config: &client.BatchConfig{IfMatch: h.Config, Patches: private}}
			if which == "cat" {
				req.Items = []client.BatchItem{{Resource: "late", IfNoneMatch: true,
					Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": "Late qz8v", "parents": parents("root@b0")}))}}}
			} else {
				// sec's item is already placed; its new title is written
				// after sec turned private.
				req.Items = []client.BatchItem{{Resource: "a", IfMatch: must(w.Head(ctx, "sec", "a")).ID,
					Steps: []client.Step{client.PatchStep([]any{map[string]any{"op": "replace", "path": "/title", "value": "Late qz8v"}})}}}
			}
			must(w.Batch(ctx, which, req, false))
			waitFor(t, "the narrowing applied", func() bool { return x.s.At() != at0 })

			st, hdr, body, path := v0261Get(x, "/cat/children?of=root", "")
			release()
			if st == 200 && strings.Contains(body, "qz8v") {
				t.Errorf("%s made private: anonymous GET served %s 200 with what the batch wrote after the config entry, Cache-Control %q: %s",
					which, path, hdr.Get("Cache-Control"), body)
			}
			// Apply ends (OnApply runs after checker.Observe).
			waitFor(t, "the apply to end", func() bool { return x.batches() > nb0 })
			// Control: once Apply has told the checker, the same reads
			// are 401. What the window served stays in a CDN until the
			// second purge (repurge, 2 min by default; the harness
			// disables the loop) and in browsers for max-age (a day).
			if st, _, b, _ := v0261Get(x, "/cat/children?of=root", ""); st != 401 {
				t.Errorf("control: anonymous GET after the apply: %d %s", st, b)
			}
		})
	}
}

// §9, §B.11.5 (v0.26.1): a load the grant checker began before Apply told
// it of a config entry (checker.Observe) can end after it, and hold the
// document from before the entry for its TTL (30 s): the catalog, or a
// namespace it trusts, still public there after it was made private. Who
// reads public is judged against what the service applied too
// (readPublic): a document it has applied, older than the entry, no longer
// says public. Here the checker's read of the document is held until the
// narrowing, and a write after it in the same batch, are applied.
func TestV0261PrivateStaleChecker(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"cat", "sec"} {
		t.Run(which, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			var gate atomic.Value // the path of the document read held
			gate.Store("")
			hit, release := make(chan struct{}), make(chan struct{})
			var hitOnce sync.Once
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
				Wrap: func(h http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if p := gate.Load().(string); p != "" && r.Method == "GET" && r.URL.Path == p {
							hitOnce.Do(func() { close(hit) })
							<-release
						}
						h.ServeHTTP(w, r)
					})
				}})
			k := clienttest.NewKey("k")
			for _, ns := range []string{"cat", "sec"} {
				doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
				if ns == "cat" {
					doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag", "title": "/title"}
				}
				must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
			}
			both := []string{"cat", "sec"}
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "append", "config"})), client.WithKeys(client.NewKeys(nil)))
			must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
			must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "A"}))
			must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
			x := startSvc(t, sc, svcOpts{now: s.Now}, func(o *tree.Options) { o.CheckerTTL = 30 * time.Second })
			x.caughtUp("cat", "sec")

			// The checker's first read of which's document is held.
			gate.Store("/ns/" + which + "/rev/" + must(w.NSHead(ctx, which)).ID)
			type answer struct {
				st         int
				hdr        http.Header
				body, path string
			}
			first := make(chan answer, 1)
			go func() {
				st, hdr, body, path := v0261Get(x, "/cat/children?of=root", "")
				first <- answer{st, hdr, body, path}
			}()
			<-hit
			private := []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}
			h := must(w.NSHead(ctx, which))
			req := client.BatchRequest{Config: &client.BatchConfig{IfMatch: h.Config, Patches: private}}
			if which == "cat" {
				req.Items = []client.BatchItem{{Resource: "late", IfNoneMatch: true,
					Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"title": "Late qz8v", "parents": parents("root@b0")}))}}}
			} else {
				req.Items = []client.BatchItem{{Resource: "a", IfMatch: must(w.Head(ctx, "sec", "a")).ID,
					Steps: []client.Step{client.PatchStep([]any{map[string]any{"op": "replace", "path": "/title", "value": "Late qz8v"}})}}}
			}
			nb := x.batches()
			must(w.Batch(ctx, which, req, false))
			waitFor(t, "the narrowing applied", func() bool { return x.batches() > nb })
			gate.Store("")
			close(release)
			// The read held, then one after it, while the checker holds
			// what that read loaded.
			answers := []answer{<-first}
			st, hdr, body, path := v0261Get(x, "/cat/children?of=root", "")
			answers = append(answers, answer{st, hdr, body, path})
			for i, a := range answers {
				if a.st == 200 && strings.Contains(a.body, "qz8v") {
					t.Errorf("%s made private, read %d: anonymous GET served %s 200, Cache-Control %q: %s", which, i, a.path, a.hdr.Get("Cache-Control"), a.body)
				}
			}
		})
	}
}

// §9, §B.11.5 (v0.26.1): the other way, a catalog just made public reads
// public before the service applies it: the grant checker's document is
// newer than any the service applied, and decides. Here the service is
// kept from reading the catalog's log meanwhile.
func TestV0261PublicBeforeApplied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var block atomic.Bool
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
		Wrap: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if block.Load() && strings.HasPrefix(r.URL.Path, "/ns/cat/") && strings.HasSuffix(r.URL.Path, "/log") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(503)
					w.Write([]byte(`{"code":"unavailable","message":"injected"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat")
	if st, _, b, _ := v0261Get(x, "/cat/roots", ""); st != 401 {
		t.Fatalf("setup: %d %s", st, b)
	}
	at := x.s.At()
	block.Store(true)
	time.Sleep(500 * time.Millisecond) // the long poll in flight ends (LongPoll)
	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "public"}}))
	waitFor(t, "an anonymous read", func() bool { st, _, _, _ := v0261Get(x, "/cat/roots", ""); return st == 200 })
	if x.s.At() != at {
		t.Fatal("the service applied the entry")
	}
	block.Store(false)
}

// v0261SawTag reports whether x's Purger was sent tag, and whether a second
// purge of it is queued.
func v0261SawTag(x *svc, tag string) (sent, queued bool) {
	_, s, q := v0261Purges(x, tag)
	return s > 0, q > 0
}

// §9, §E.2.6 (purgeStopped, 5a462d3): a raise of the catalog to e2e that
// the service can't follow (no keyring recipient key) purges ns:{catalog}
// when a running follower meets it (Apply, keys.Recheck). One applied
// while the service was down is met at startup instead, by keys.Check in
// follow(), which returns for good without purging: the CDN copies of the
// listings it served public and in the clear before the raise (Purger,
// immutable for a year) are never purged, nor is a second purge queued.
//
// Fixed in v0.26.1: a namespace follow() skips for lack of keys purges
// ns:{ns} once (purgeStopped), at a start too.
func TestV0261RaiseToE2EWhileDown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	wJWK, wPriv := must2(seal.GenerateRecipient())
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": wJWK})),
		client.WithKeys(client.NewKeys(wPriv)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Secret m4zt", "parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "m4zt") || !strings.Contains(before.header.Get("Cache-Control"), "immutable") {
		t.Fatalf("setup: %q %s", before.header.Get("Cache-Control"), before.body)
	}
	x.stop()

	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "e2e"}}}))
	y := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	waitFor(t, "the catalog skipped", func() bool { return y.raw("/cat/roots", "").status == 404 })
	deadline := time.Now().Add(3 * time.Second)
	sent, queued := v0261SawTag(y, "ns:cat")
	for !sent && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		sent, queued = v0261SawTag(y, "ns:cat")
	}
	if !sent || !queued {
		t.Errorf("raised to e2e while the service was down: at startup it skips cat (404) but sent ns:cat to its Purger %v, queued its second purge %v; "+
			"%s was served %q with the title in the clear", sent, queued, before.path, before.header.Get("Cache-Control"))
	}
}

// §9, §A.1 via §B.5 (narrowedBy, 5a462d3: "at its first batch none shows
// it yet"): a catalog made private while the service was down is purged
// on a restart (the checkpoint is kept, so the config entry is not the
// first batch), but not after -rebuild (Options.Rebuild; reset deletes
// checkpoints and meta, access:* included): the follower replays the log
// from "" in one batch (WithMaxUnits(0)), genesis and narrowing together,
// with s.cur[cat] == "", so nothing is purged, though the CDN holds the
// listings the previous instance served public, immutable, under the same
// ats (the combined checkpoint is the same).
//
// Fixed in v0.26.1: a rebuild keeps the access:{ns} records, so the
// replay is compared with what was last served.
func TestV0261NarrowedWhileDownThenRebuilt(t *testing.T) {
	t.Parallel()
	for _, rebuild := range []bool{false, true} {
		name := "restart"
		if rebuild {
			name = "rebuild"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
			k := clienttest.NewKey("k")
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
				"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
			w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
			must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
			must(w.CreateDoc(ctx, "cat", "season", map[string]any{"title": "Secret m4zt", "parents": parents("root@a0")}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
			db := filepath.Join(t.TempDir(), "tree.db")
			x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
			x.caughtUp("cat")
			before := x.fetch("/cat/children?of=root", "")
			if !strings.Contains(before.header.Get("Cache-Control"), "public") {
				t.Fatalf("setup: %q", before.header.Get("Cache-Control"))
			}
			x.stop()
			must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
			y := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Rebuild = rebuild })
			y.caughtUp("cat")
			if sent, queued := v0261SawTag(y, "ns:cat"); !sent || !queued {
				t.Errorf("%s after cat was made private while down: sent ns:cat %v, queued %v; %s was served %q",
					name, sent, queued, before.path, before.header.Get("Cache-Control"))
			}
		})
	}
}

// §9, §E.2.6 (purgeStopped, 5a462d3): purgeStopped runs only when the
// follower delivers the narrowing batch and keys.Recheck finds the keys
// lacking. A trusted namespace raised to sealed whose keys the service
// can't have never gets that far: the follower can't read the sealed log
// entry itself ("namespace log sec: ... no key is available") and retries
// forever, so ns:sec is never purged, and the listings the service
// served public, with sec's titles in the clear, stay in its CDN.
//
// Fixed in v0.26.1: a follower that can't read past an entry for lack
// of keys purges ns:{ns} once (purgeStopped).
func TestV0261SealedTrustedWithoutKeys(t *testing.T) {
	t.Parallel()
	for _, refused := range []bool{false, true} {
		name := "static keys"
		if refused {
			name = "keys 403"
		}
		t.Run(name, func(t *testing.T) { v0261SealedTrustedWithoutKeys(t, refused) })
	}
}

// v0261SealedTrustedWithoutKeys: the service's client holds no keys
// (StaticKeys), or, as deployed, the core refuses its /keys requests for
// sec (403; nothing else asks for sec's keys here).
func v0261SealedTrustedWithoutKeys(t *testing.T, refused bool) {
	t.Parallel()
	ctx := context.Background()
	var refuse atomic.Bool
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
		Wrap: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if refuse.Load() && strings.HasPrefix(r.URL.Path, "/ns/sec/keys") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					w.Write([]byte(`{"code":"forbidden","message":"injected"}`))
					return
				}
				h.ServeHTTP(w, r)
			})
		}})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"cat", "sec"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag", "title": "/title"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	both := []string{"cat", "sec"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "Secret vw3k"}))
	must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
	// The service can't have sec's keys once it is sealed.
	tok := k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})
	keys := client.StaticKeys()
	if refused {
		keys = client.NewKeys(nil)
		refuse.Store(true)
	}
	sc := s.Client(t, client.WithBearer(tok), client.WithKeys(keys))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "vw3k") {
		t.Fatalf("setup: %s", before.body)
	}
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
	deadline := time.Now().Add(3 * time.Second)
	sent, queued := v0261SawTag(x, "ns:sec")
	for !sent && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		sent, queued = v0261SawTag(x, "ns:sec")
	}
	if !sent || !queued {
		t.Errorf("sec raised to sealed, its keys out of the service's reach: ns:sec sent %v, queued %v (sec held at %s); %s was served %q with sec's title in the clear",
			sent, queued, x.s.Checkpoint("sec"), before.path, before.header.Get("Cache-Control"))
	}
}

// §9, §B.5 ("tagged ... every namespace in the checkpoint (ns:{ns}); a
// service whose cache the origin's purges don't reach purges these tags
// itself"): listings at ats whose combined checkpoint held sec carry
// ns:sec. Once the catalog stops trusting sec, the service stops
// following it, and without edge grants it purges nothing for the
// untrust (applyLocked: ns:{catalog} only under EdgeGrants), so sec made
// private afterwards is never seen: no tag the old listing carries is
// ever sent to the service's Purger, and a CDN the origin's purges don't
// reach keeps the listing at the old at, sec's title in the clear, public
// immutable. (The service itself no longer serves it: the anonymous
// viewer's shape changed with the trust list, so the kept copy misses.)
// Pre-existing; not something 5a462d3 claims to cover.
//
// Fixed in v0.26.1: every untrust purges ns:{catalog}.
func TestV0261UntrustedThenPrivate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for _, ns := range []string{"cat", "sec"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if ns == "cat" {
			doc["catalog"] = map[string]any{"trust": []any{"sec"}, "mode": "dag", "title": "/title"}
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	both := []string{"cat", "sec"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", both, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "Secret vw3k"}))
	must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "vw3k") {
		t.Fatalf("setup: %s", before.body)
	}
	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "replace", "path": "/catalog/trust", "value": []any{}}}))
	x.caughtUp("cat")
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	time.Sleep(500 * time.Millisecond) // the service would have met it by now, were it following sec
	purged := false
	for _, tg := range strings.Split(before.header.Get("Cache-Tag"), ",") {
		if sent, _ := v0261SawTag(x, strings.TrimSpace(tg)); sent {
			purged = true
		}
	}
	if !purged {
		t.Errorf("sec made private after cat stopped trusting it: none of %s's tags %q was ever purged; it was served %q with sec's title in the clear",
			before.path, before.header.Get("Cache-Tag"), before.header.Get("Cache-Control"))
	}
}
