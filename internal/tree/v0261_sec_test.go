package tree_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
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
//
// Since v0.81 the raise is to sealed and private (v081SealedPrivate) for
// a service that holds no keys and fetches none: a raise to e2e is 422
// (v0.78), and this is the namespace it can no longer read another way.
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
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.StaticKeys()))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "m4zt") {
		t.Fatalf("setup: %s", before.body)
	}
	_, sent0, _ := v0261Purges(x, "ns:cat")

	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, v081SealedPrivate))
	waitFor(t, "the raise to e2e", func() bool { return x.raw("/cat/roots", "").status == 404 })
	waitFor(t, "ns:cat sent to the Purger", func() bool { _, sent, _ := v0261Purges(x, "ns:cat"); return sent > sent0 })
	if r := x.raw(before.path, ""); r.status == 200 {
		t.Errorf("after the raise to e2e, %s is served 200: %v", before.path, r.body)
	}
}

// §E.2.6, §E.3.1 (v0.26.1): a rotation purges nothing, so a listing reads
// the catalog's encryption again once its graph is read, before it
// judges any epoch by it. In a release preview of e2e catalog cat through
// its e2e branch catb (v081Preview), node n's head is pending (cat's op,
// read through; until v0.81, written in the clear before a raise, which
// is 422 since v0.78); a rotation to epoch 2 applied after the listing
// took its kept generation and read the encryption again
// (AfterGeneration), during fileSealing and the key fetches, has the
// listing view the graph after it: n is judged by epoch 2, the epoch in
// force, never epoch 1, the one it read first.
func TestV0261RotationAfterInfoReread(t *testing.T) {
	t.Parallel()
	p := newV081Preview(t)
	x := p.start(t)
	if e, _ := v077Epochs(t, p.db, "n"); e != 0 {
		t.Fatalf("n's epoch %d before any listing, want it pending", e)
	}
	rd := p.k.Grant(t, p.s.Now(), "user:r", []string{"cat", "catb"}, []string{"read"})

	var once sync.Once
	ran := false
	x.s.AfterGeneration(func() {
		once.Do(func() {
			ran = true
			p.rotate(t)
			p.reach(t, x)
		})
	})
	x.fetch("/cat/children?of=root", rd)
	x.s.AfterGeneration(nil)
	if !ran {
		t.Fatal("the listing was not computed")
	}
	if e, _ := v077Epochs(t, p.db, "n"); e != 2 {
		t.Errorf("n judged by epoch %d, want 2, the epoch in force as the listing read the graph", e)
	}
	if kid, vals, _ := v077Sealed(t, x, "/cat/children?of=root", rd, "n", p.keyOf); kid != "cat#2" || vals["title"] != "N" {
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
// public only once the service applies that: anonymous readers are 401
// meanwhile (a grant reads by its grant), however the grant checker's
// document reads, and are served once it is applied. A document the
// service hasn't applied may be one public between two private ones
// (TestV0261LaggingFlipNotPublic). Here the service is kept from reading
// the catalog's log meanwhile.
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
	for range 5 {
		if st, _, b, _ := v0261Get(x, "/cat/roots", ""); st != 401 {
			t.Fatalf("made public, not applied: anonymous GET %d %s, want 401", st, b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if x.s.At() != at {
		t.Fatal("the service applied the entry")
	}
	block.Store(false)
	waitFor(t, "an anonymous read, once applied", func() bool { st, _, _, _ := v0261Get(x, "/cat/roots", ""); return st == 200 })
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
//
// Since v0.81 the raise is to sealed and private (v081SealedPrivate), as
// in TestV0261RaiseToE2EWithoutKeys.
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
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.StaticKeys()))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "m4zt") || !strings.Contains(before.header.Get("Cache-Control"), "immutable") {
		t.Fatalf("setup: %q %s", before.header.Get("Cache-Control"), before.body)
	}
	x.stop()

	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, v081SealedPrivate))
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
	// Nor does the service serve it again to an anonymous reader, which
	// would undo the purge.
	for _, path := range []string{before.path, "/cat/children?of=root"} {
		if st, hdr, body, at := v0261Get(x, path, ""); st == 200 && strings.Contains(body, "vw3k") {
			t.Errorf("after the purge, anonymous GET %s served %s 200 with sec's title, Cache-Control %q", path, at, hdr.Get("Cache-Control"))
		}
	}
}

// §9, §A.1 via §B.5 (v0.26.1): a rebuild's replay of a database from a
// release that kept no access:{ns} record (v0.26.0 and before) purges
// ns:{catalog} when the catalog ends private, though the replay starts
// with no record to compare with: the previous instance may have served
// it public under the same ats.
func TestV0261RebuiltWithoutRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat")
	x.fetch("/cat/children?of=root", "")
	x.stop()
	// As an earlier release left it.
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	if _, err := sq.Exec(`DELETE FROM meta WHERE k LIKE 'access:%'`); err != nil {
		t.Fatal(err)
	}
	sq.Close()
	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	y := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Rebuild = true })
	y.caughtUp("cat")
	if sent, queued := v0261SawTag(y, "ns:cat"); !sent || !queued {
		t.Errorf("rebuilt with no record after cat was made private: sent ns:cat %v, queued %v", sent, queued)
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

// Review R2-A: a content namespace made private and raised to sealed in one
// config write that the service can't follow (it can't have sec's keys).
// The follower stops before the entry (LacksKey) or Apply's Recheck skips
// it: the batch is never applied, so Graph.appliedPublic[sec] stays
// "public" from the last applied entry, and nothing makes the grant
// checker drop the document it holds (no Apply reaches Observe on the
// LacksKey path). purgeStopped purges ns:sec once; an anonymous read
// within the checker's TTL (30 s by default) is then judged public by the
// cached document and the stale record, and served sec's title in the
// clear, public immutable, after that purge. Bounded: the CDN copy lasts
// until the second purge (repurge, 2 min) or the next start's stop-purge,
// browsers keep it for max-age. TestV0261SealedTrustedWithoutKeys' "nor
// does the service serve it again" holds only under the harness's 1 ms
// TTL. Incomplete fix of d64b8a0/b6b14cb, not a regression.
//
// Fixed in v0.26.1: purgeStopped marks the namespace stopped (meta
// "stopped:{ns}") and has the checker drop it before it purges; a stopped
// namespace reads public to no one, and a stopped catalog is 404.
func TestV0261StoppedNotServedPublic(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, ns string
		private  bool
		ttl      time.Duration
	}{
		{"sec private+sealed ttl30s", "sec", true, 30 * time.Second},
		{"sec sealed only ttl30s", "sec", false, 30 * time.Second},
		{"cat private+sealed ttl30s", "cat", true, 30 * time.Second},
		{"control sec private+sealed ttl1ms", "sec", true, time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) { v0261StopPurge(t, c.ns, c.private, c.ttl) })
	}
}

func v0261StopPurge(t *testing.T, which string, private bool, ttl time.Duration) {
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
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.StaticKeys()))
	x := startSvc(t, sc, svcOpts{now: s.Now}, func(o *tree.Options) { o.CheckerTTL = ttl })
	x.caughtUp("cat", "sec")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "vw3k") || !strings.Contains(before.header.Get("Cache-Control"), "public") {
		t.Fatalf("setup: %q %s", before.header.Get("Cache-Control"), before.body)
	}
	patch := []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}
	if private {
		patch = append(patch, map[string]any{"op": "replace", "path": "/read", "value": "grant"})
	}
	must(w.PatchConfig(ctx, which, must(w.NSHead(ctx, which)).Config, patch))
	waitFor(t, "ns:"+which+" purged (purgeStopped)", func() bool { sent, _ := v0261SawTag(x, "ns:"+which); return sent })
	n0, _, _ := v0261Purges(x, "ns:"+which)
	for _, path := range []string{"/cat/children?of=root", before.path} {
		st, hdr, body, at := v0261Get(x, path, "")
		if st == 200 && strings.Contains(body, "vw3k") {
			t.Errorf("%s raised (private %v), its entry never applied: after ns:%s was purged, anonymous GET %s served %s 200, Cache-Control %q, with sec's title: %s",
				which, private, which, path, at, hdr.Get("Cache-Control"), body)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if n, _, _ := v0261Purges(x, "ns:"+which); n != n0 {
		t.Logf("ns:%s purged again since: %d -> %d", which, n0, n)
	} else {
		t.Logf("ns:%s not purged again (%d)", which, n)
	}
}

// v0261Core is a core whose GET /ns/cat head pointer can be answered from
// one recorded earlier (as a CDN serves it within s-maxage=1,
// stale-while-revalidate=5, §9), and whose cat log reads can be refused.
type v0261Core struct {
	s       *clienttest.Server
	mu      sync.Mutex
	ptrs    map[string]http.Header // by head, as last answered
	replay  atomic.Value           // the head whose pointer is replayed, "" for none
	blockLg atomic.Bool
}

func newV0261Core(t *testing.T) *v0261Core {
	c := &v0261Core{ptrs: map[string]http.Header{}}
	c.replay.Store("")
	c.s = clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
		Wrap: func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.blockLg.Load() && strings.HasPrefix(r.URL.Path, "/ns/cat/") && strings.HasSuffix(r.URL.Path, "/log") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(503)
					w.Write([]byte(`{"code":"unavailable","message":"injected"}`))
					return
				}
				if r.Method != "GET" || r.URL.Path != "/ns/cat" {
					h.ServeHTTP(w, r)
					return
				}
				if id := c.replay.Load().(string); id != "" {
					c.mu.Lock()
					hd := c.ptrs[id]
					c.mu.Unlock()
					for k, v := range hd {
						w.Header()[k] = v
					}
					w.WriteHeader(302)
					return
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				if rec.Code == 302 {
					c.mu.Lock()
					c.ptrs[strings.Trim(rec.Header().Get("ETag"), `"`)] = rec.Header().Clone()
					c.mu.Unlock()
				}
				for k, v := range rec.Header() {
					w.Header()[k] = v
				}
				w.WriteHeader(rec.Code)
				w.Write(rec.Body.Bytes())
			})
		}})
	return c
}

// head reads cat's head through the core, recording its pointer.
func (c *v0261Core) head(t *testing.T, cl *client.Client) string {
	h := must(cl.NSHead(context.Background(), "cat"))
	c.mu.Lock()
	_, ok := c.ptrs[h.ID]
	c.mu.Unlock()
	if !ok {
		t.Fatalf("pointer at %s not recorded", h.ID)
	}
	return h.ID
}

func v0261Read(w *client.Client, mode string) error {
	ctx := context.Background()
	_, err := w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": mode}})
	return err
}

// Review R2-C (main target, residual): the widening branch trusts a document at
// an entry the service hasn't applied. With cat private as applied and
// the service unable to read its log, cat is made public (X) and private
// again (Y). A head pointer at X (stale, as a CDN serves it for ~6 s, or
// the checker's own cached document for its 30 s TTL) has the now-private
// catalog served to an anonymous reader, public immutable, at the at the
// service holds, which includes what was written while it was private.
// Bounded: once the service applies X and Y, ns:cat is purged after it,
// and the same pointer is 401.
//
// Fixed in v0.26.1: a namespace reads public only if public as the
// service applied it too (publicAsApplied); this asserts 401.
func TestV0261LaggingFlipNotPublic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := newV0261Core(t)
	s := c.s
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	v0261Must(t, v0261Read(w, "grant"))
	must(w.CreateDoc(ctx, "cat", "secret", map[string]any{"title": "Secret p7qa", "parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat")
	if st, _, b, _ := v0261Get(x, "/cat/roots", ""); st != 401 {
		t.Fatalf("setup: %d %s", st, b)
	}
	c.blockLg.Store(true)
	time.Sleep(500 * time.Millisecond)
	v0261Must(t, v0261Read(w, "public"))
	hx := c.head(t, w)
	v0261Must(t, v0261Read(w, "grant"))
	c.replay.Store(hx)
	st, hdr, body, path := v0261Get(x, "/cat/children?of=root", "")
	c.replay.Store("")
	n0, _, _ := v0261Purges(x, "ns:cat")
	if st != 401 {
		t.Errorf("cat private again at the head; checker answered the pointer at %s (public, not applied): anonymous GET served %s %d, Cache-Control %q: %s",
			hx, path, st, hdr.Get("Cache-Control"), body)
	}
	c.blockLg.Store(false)
	x.caughtUp("cat")
	if n, _, _ := v0261Purges(x, "ns:cat"); n <= n0 {
		t.Errorf("applied X and Y: ns:cat purged %d times, %d before", n, n0)
	}
	c.replay.Store(hx)
	if st, _, b, p := v0261Get(x, "/cat/children?of=root", ""); st != 401 {
		t.Errorf("after the apply, the pointer at %s: %s %d %s", hx, p, st, b)
	}
	c.replay.Store("")
}

func v0261Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Review R2-D (purgeStopped's cost): the catalog raised to e2e, which the service
// can't follow (no keyring recipient key). The stop is remembered only in
// follow()'s closure, so every start of the service (and the live raise
// itself, once in Apply and once more when follow() re-checks) sends
// ns:cat to the Purger again and queues another second purge, though
// nothing was served since the first.
//
// Fixed in v0.26.1: the stop is recorded per checkpoint (meta
// "stopped:{ns}"), so it purges once.
//
// Since v0.81 the raise is to sealed and private (v081SealedPrivate), as
// in TestV0261RaiseToE2EWithoutKeys.
func TestV0261StopPurgeOnce(t *testing.T) {
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
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.StaticKeys()))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat")
	x.fetch("/cat/children?of=root", "")
	must(w.PatchConfig(ctx, "cat", must(w.NSHead(ctx, "cat")).Config, v081SealedPrivate))
	waitFor(t, "the raise to e2e", func() bool { return x.raw("/cat/roots", "").status == 404 })
	time.Sleep(500 * time.Millisecond)
	_, sent, queued := v0261Purges(x, "ns:cat")
	t.Logf("live raise: ns:cat sent %d, queued %d", sent, queued)
	total := sent
	x.stop()
	for i := 0; i < 3; i++ {
		y := startSvc(t, sc, svcOpts{now: s.Now, db: db})
		waitFor(t, "skipped", func() bool { return y.raw("/cat/roots", "").status == 404 })
		time.Sleep(300 * time.Millisecond)
		_, sent, queued := v0261Purges(y, "ns:cat")
		t.Logf("start %d: ns:cat sent %d, queued (in the database) %d", i+1, sent, queued)
		total += sent
		y.stop()
	}
	if total > 1 {
		t.Errorf("one raise, nothing served since: ns:cat sent to the Purger %d times (each start purges again)", total)
	}
}

// Review R2-E (purgeStopped's coverage): sec is made private and the service's
// grant stops verifying for it in the same config write (its key is
// replaced). The follower can't read the entry (401/403: setUnfollowed),
// so no apply purges for the narrowing, and follow() purges only for a
// lack of keys: ns:sec is never sent to the Purger, and the public
// immutable copies the service served of listings showing sec stay in a
// CDN the origin's purges don't reach (§9, §B.5).
//
// Fixed in v0.26.1: a refusal (401, 403) that unfollows a shown
// namespace stops it too (purgeStopped).
func TestV0261PrivateAndLockedOutPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k, k2 := clienttest.NewKey("k"), clienttest.NewKey("k2")
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
	if !strings.Contains(string(before.body), "vw3k") || !strings.Contains(before.header.Get("Cache-Control"), "public") {
		t.Fatalf("setup: %q %s", before.header.Get("Cache-Control"), before.body)
	}
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{
		map[string]any{"op": "replace", "path": "/read", "value": "grant"},
		map[string]any{"op": "replace", "path": "/keys", "value": []any{k2.Entry("*")}},
	}))
	time.Sleep(1500 * time.Millisecond)
	if sent, queued := v0261SawTag(x, "ns:sec"); !sent && !queued {
		t.Errorf("sec made private with the service locked out (checkpoint %s): ns:sec never sent to the Purger nor queued; %s was served %q with sec's title",
			x.s.Checkpoint("sec"), before.path, before.header.Get("Cache-Control"))
	}
	for _, path := range []string{before.path, "/cat/children?of=root"} {
		if st, hdr, body, at := v0261Get(x, path, ""); st == 200 && strings.Contains(body, "vw3k") {
			t.Errorf("anonymous GET %s served %s 200, Cache-Control %q, with sec's title", path, at, hdr.Get("Cache-Control"))
		}
	}
}

// v0261DropAccess removes the access:{ns} records, as a database of
// v0.26.0 or before has none.
func v0261DropAccess(t *testing.T, db string) {
	t.Helper()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	defer sq.Close()
	if _, err := sq.Exec(`DELETE FROM meta WHERE k LIKE 'access:%'`); err != nil {
		t.Fatal(err)
	}
}

// §B.11.5 (v0.26.1): a database from v0.26.0 or before has no record of
// the read mode the service applied. It is made from the namespace
// documents at the checkpoints the service holds, as first needed
// (seedAccess): a public catalog, and a public namespace it trusts, are
// still read publicly after the upgrade; and a stale document the grant
// checker is answered, public, from before a narrowing the service has
// applied, by the release before, reads private (401).
func TestV0261UpgradeWithoutAccessRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := newV0261Core(t)
	s := c.s
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
	must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "A"}))
	must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "sec")
	x.stop()

	v0261DropAccess(t, db)
	y := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	y.caughtUp("cat", "sec")
	if st, _, b, _ := v0261Get(y, "/cat/children?of=root", ""); st != 200 || !strings.Contains(b, `"A"`) {
		t.Fatalf("upgraded, public: anonymous GET %d %s, want 200", st, b)
	}
	h0 := c.head(t, w)
	y.stop()

	// The same, cat made private and applied before the upgrade (as by
	// v0.26.0, which kept no record).
	v0261Must(t, v0261Read(w, "grant"))
	must(w.CreateDoc(ctx, "cat", "secret", map[string]any{"title": "Secret p7qa", "parents": parents("root@a1")}))
	old := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	old.caughtUp("cat", "sec")
	old.stop()
	v0261DropAccess(t, db)
	z := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	z.caughtUp("cat", "sec")
	c.replay.Store(h0)
	st, hdr, body, path := v0261Get(z, "/cat/children?of=root", "")
	c.replay.Store("")
	if st != 401 {
		t.Errorf("upgraded, cat made private before, the checker answered the pointer from before: anonymous GET served %s %d, Cache-Control %q: %s",
			path, st, hdr.Get("Cache-Control"), body)
	}
}

// Review R2-B (main target, the widening branch of readPublic): cat flips
// private -> public -> private while the service can't read its log, then
// the service applies all three in one batch. The grant checker is then
// answered stale head pointers (one at the intermediate public entry, one
// from before the flips): each is an entry the service applied (seen
// holds every entry id of a batch, tree.go applyLocked), so neither is
// read public. Then the same after a restart on the same database (seen
// persists), and during a rebuild's replay (seen emptied, access:cat
// kept): 503 behind, never 200.
//
// Holds in v0.26.1 with publicAsApplied; its snapshot part needed a
// snapshot's document recorded (narrowedBy).
func TestV0261StalePointerAfterFlips(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := newV0261Core(t)
	s := c.s
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat")
	h0 := c.head(t, w)
	if st, _, b, _ := v0261Get(x, "/cat/roots", ""); st != 200 {
		t.Fatalf("setup: %d %s", st, b)
	}
	c.blockLg.Store(true)
	time.Sleep(500 * time.Millisecond)
	v0261Must(t, v0261Read(w, "grant"))
	must(w.CreateDoc(ctx, "cat", "secret", map[string]any{"title": "Secret p7qa", "parents": parents("root@a0")}))
	v0261Must(t, v0261Read(w, "public"))
	hx := c.head(t, w)
	v0261Must(t, v0261Read(w, "grant"))
	c.blockLg.Store(false)
	x.caughtUp("cat")
	check := func(t *testing.T, x *svc, when string, want ...int) {
		t.Helper()
		for _, id := range []string{hx, h0} {
			c.replay.Store(id)
			st, hdr, body, path := v0261Get(x, "/cat/children?of=root", "")
			c.replay.Store("")
			t.Logf("%s ptr %s: %d %s", when, id, st, path)
			if !slices.Contains(want, st) {
				t.Errorf("%s, checker answered the pointer at %s: anonymous GET served %s %d, Cache-Control %q: %s", when, id, path, st, hdr.Get("Cache-Control"), body)
			}
		}
	}
	check(t, x, "applied", 401)
	x.stop()
	y := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	check(t, y, "restarted", 401)
	y.stop()
	c.blockLg.Store(true)
	z := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Rebuild = true })
	time.Sleep(300 * time.Millisecond)
	check(t, z, "rebuilding, log refused", 401, 503)
	c.blockLg.Store(false)
	z.caughtUp("cat")
	check(t, z, "rebuilt", 401)
	z.stop()
	// Library-only (cmd/patchlog passes no follow.WithSnapshot): a
	// rebuild, and a fresh database, bootstrapped from a snapshot, whose
	// batch has no config unit and whose seen holds only its head.
	t.Run("snapshot", func(t *testing.T) {
		snap := func(o *tree.Options) { o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot()) }
		q := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) { o.Rebuild = true }, snap)
		q.caughtUp("cat")
		check(t, q, "rebuilt from a snapshot", 401)
		q.stop()
		f := startSvc(t, sc, svcOpts{now: s.Now}, snap)
		f.caughtUp("cat")
		check(t, f, "fresh database, snapshot", 401)
	})
}

// Review R2-F (library-only: follow.WithSnapshot, which cmd/patchlog doesn't
// pass): cat made private while the service was down, then a rebuild (or
// a restart) bootstrapped from a snapshot. A snapshot batch has no config
// unit, so narrowedBy never runs: ns:cat isn't purged, though the
// previous instance served cat public under listings a CDN keeps (the
// index's 475ff96 purges at a snapshot that narrows).
//
// Fixed in v0.26.1: a snapshot's document at its checkpoint goes
// through narrowedBy.
func TestV0261SnapshotRebuildNarrowPurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "public", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{}, "mode": "dag"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"cat"}, []string{"read", "create", "config"})), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", []string{"cat"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat")
	before := x.fetch("/cat/children?of=root", "")
	x.stop()
	v0261Must(t, v0261Read(w, "grant"))
	y := startSvc(t, sc, svcOpts{now: s.Now, db: db}, func(o *tree.Options) {
		o.Rebuild = true
		o.FollowOptions = append(o.FollowOptions, follow.WithSnapshot())
	})
	y.caughtUp("cat")
	time.Sleep(200 * time.Millisecond)
	if sent, queued := v0261SawTag(y, "ns:cat"); !sent || !queued {
		t.Errorf("rebuilt from a snapshot after cat was made private while down: sent ns:cat %v, queued %v; %s was served %q",
			sent, queued, before.path, before.header.Get("Cache-Control"))
	}
}

// v0261Stopped reports whether db records ns stopped (purgeStopped).
func v0261Stopped(t *testing.T, db, ns string) bool {
	t.Helper()
	sq := must(sql.Open("sqlite", sqlitedsn.DSN(db, "")))
	defer sq.Close()
	var n int
	if err := sq.QueryRow(`SELECT count(*) FROM meta WHERE k = ?`, "stopped:"+ns).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// §9, §B.11.5 (v0.26.1): a stop ends without a new entry once the
// service follows the namespace to the checkpoint it stopped at again:
// the core refusing the service's reads of the catalog's or sec's log for
// a while (403) stops it (purgeStopped: ns:{ns} purged, the catalog 404,
// sec reading public to no one and, not followed, out of the listings,
// v0.81 ACCESS-11), and once the refusal passes, with nothing written
// meanwhile, its items are listed again and the stop is no longer
// recorded.
func TestV0261StopEnds(t *testing.T) {
	t.Parallel()
	for _, which := range []string{"cat", "sec"} {
		t.Run(which, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			var refuse atomic.Bool
			s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond,
				Wrap: func(h http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if refuse.Load() && strings.HasPrefix(r.URL.Path, "/ns/"+which+"/") && strings.HasSuffix(r.URL.Path, "/log") {
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
			must(w.CreateDoc(ctx, "sec", "a", map[string]any{"title": "A"}))
			must(w.CreateDoc(ctx, "cat", "sec.a", map[string]any{"parents": parents("root@a0")}))
			sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
			db := filepath.Join(t.TempDir(), "tree.db")
			x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
			x.caughtUp("cat", "sec")
			if st, _, b, _ := v0261Get(x, "/cat/children?of=root", ""); st != 200 {
				t.Fatalf("setup: %d %s", st, b)
			}
			refuse.Store(true)
			waitFor(t, "ns:"+which+" purged (purgeStopped)", func() bool { sent, _ := v0261SawTag(x, "ns:"+which); return sent })
			// A stopped catalog isn't served (404). A stopped content
			// namespace isn't followed (§B.5 Behind, v0.81 ACCESS-11): the
			// public catalog's listings are served without it, its
			// placement dangling, never its item.
			st, _, b, _ := v0261Get(x, "/cat/children?of=root", "")
			switch {
			case which == "cat" && st != 404:
				t.Errorf("stopped: anonymous GET %d %s, want 404", st, b)
			case which == "sec" && (st != 200 || strings.Contains(b, "sec.a")):
				t.Errorf("stopped: anonymous GET %d %s, want 200 without sec.a", st, b)
			}
			if !v0261Stopped(t, db, which) {
				t.Errorf("stopped: no stopped:%s recorded", which)
			}
			refuse.Store(false)
			waitFor(t, "anonymous reads again", func() bool {
				st, _, b, _ := v0261Get(x, "/cat/children?of=root", "")
				return st == 200 && strings.Contains(b, "sec.a")
			})
			if v0261Stopped(t, db, which) {
				t.Errorf("followed again: stopped:%s still recorded", which)
			}
		})
	}
}

// §9, §B.11.5 (v0.26.1): a listing whose viewer was judged public before
// the service stopped a namespace it shows (purgeStopped) isn't served
// after the stop's purge: the stop moves no at, so the listing would be
// answered as computed; the read mode is judged again once its graph is
// read (stillPublic). Here sec is raised to sealed, which a service with
// no keys can't follow, after the listing took its generation.
func TestV0261StopAfterViewerJudged(t *testing.T) {
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
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.StaticKeys()))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	x.caughtUp("cat", "sec")

	var once sync.Once
	ran := false
	x.s.AfterGeneration(func() {
		once.Do(func() {
			ran = true
			must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}}}))
			waitFor(t, "ns:sec purged (purgeStopped)", func() bool { sent, _ := v0261SawTag(x, "ns:sec"); return sent })
		})
	})
	// At the current at's URL, which the stop doesn't move: the listing
	// computed is the answer.
	st, hdr, body, path := v0261Get(x, "/cat/at/"+x.s.At()+"/subtree?of=root", "")
	x.s.AfterGeneration(nil)
	if !ran {
		t.Fatal("the listing was not computed")
	}
	if st == 200 && strings.Contains(body, "vw3k") {
		t.Errorf("sec stopped while the listing was computed: anonymous GET served %s 200, Cache-Control %q: %s", path, hdr.Get("Cache-Control"), body)
	}
}

// v0261Gate holds the service's requests whose path starts with prefix
// until open is closed; reached is closed at the first one.
type v0261Gate struct {
	prefix  string
	once    sync.Once
	reached chan struct{}
	open    chan struct{}
}

func (g *v0261Gate) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.URL.Path, g.prefix) {
		g.once.Do(func() { close(g.reached) })
		<-g.open
	}
	return http.DefaultTransport.RoundTrip(r)
}

// Final review (I2): a narrowing must end in an apply (narrowedBy) or a
// stop (purgeStopped). One the follower has read, whose batch's Apply is
// then refused, ends in neither: Apply returns the refusal (FetchDoc's
// default case), the follower retries the handler for ever
// (nsFollower.apply), and OnError stops only for a lack of keys. Here sec
// is made private, with a write in the same batch, while the service is
// down; on restart the follower reads both, and while Apply fetches the
// write's head, sec drops the service's key (as in
// TestV0261PrivateAndLockedOutPurged, one entry later). ns:sec is never
// sent to the Purger nor queued, so the public, immutable copies of
// listings showing sec's title that the service served stay in a CDN the
// origin's purges don't reach (§9, §B.5).
//
// Fixed in v0.26.1: a refusal of a read of the namespace that the
// follower reports (OnError), the handler's among them, stops it too
// (purgeStopped).
func TestV0261RefusedInsideApplyPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k, ks := clienttest.NewKey("k"), clienttest.NewKey("ks")
	for _, ns := range []string{"cat", "sec"} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*"), ks.Entry("read")}}
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
	gate := &v0261Gate{prefix: "/r/sec/b/", reached: make(chan struct{}), open: make(chan struct{})}
	sc := s.Client(t, client.WithBearer(ks.Grant(t, s.Now(), "svc:tree", both, []string{"read"})), client.WithKeys(client.NewKeys(nil)),
		client.WithHTTPClient(&http.Client{Transport: gate}))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	x.caughtUp("cat", "sec")
	before := x.fetch("/cat/children?of=root", "")
	if !strings.Contains(string(before.body), "vw3k") || !strings.Contains(before.header.Get("Cache-Control"), "public") {
		t.Fatalf("setup: %q %s", before.header.Get("Cache-Control"), before.body)
	}
	x.stop()

	// While down: a write, then sec made private (the service still reads it).
	must(w.CreateDoc(ctx, "sec", "b", map[string]any{"title": "Later"}))
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))

	y := startSvc(t, sc, svcOpts{now: s.Now, db: db})
	select {
	case <-gate.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the follower never fetched sec/b")
	}
	// The batch is read; now the service's key goes.
	must(w.PatchConfig(ctx, "sec", must(w.NSHead(ctx, "sec")).Config, []any{map[string]any{"op": "replace", "path": "/keys", "value": []any{k.Entry("*")}}}))
	close(gate.open)

	deadline := time.Now().Add(3 * time.Second)
	sent, queued := v0261SawTag(y, "ns:sec")
	for !sent && !queued && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		sent, queued = v0261SawTag(y, "ns:sec")
	}
	if !sent && !queued {
		t.Errorf("sec made private, then the service locked out while it applied that: ns:sec never sent to the Purger nor queued (sec held at %s, applies %d); %s was served %q with sec's title",
			y.s.Checkpoint("sec"), y.batches(), before.path, before.header.Get("Cache-Control"))
	}
	for _, path := range []string{before.path, "/cat/children?of=root"} {
		if st, hdr, body, at := v0261Get(y, path, ""); st == 200 && strings.Contains(body, "vw3k") {
			t.Errorf("anonymous GET %s served %s 200, Cache-Control %q, with sec's title", path, at, hdr.Get("Cache-Control"))
		}
	}
}
