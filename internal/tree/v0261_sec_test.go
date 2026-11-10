package tree_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
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
