package core

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/tree"
)

// V75-01 (v0.75): the visibility engine of filtered namespace reads
// (§B.11.9) in the core: coverage, access classification, catalog graphs
// at a checkpoint, the visible predicate, gs, stored state, admission and
// the exchange.

// v75World is an engine with authentication on and the catalog setup of
// §B.11.3: cat-season trusts matches, whose key catalog-01 has requireAt
// cat-season and a scope rule testing /resource by type, so its grants
// read matches only in part. k is a * key in both.
type v75World struct {
	t       *testing.T
	e       *Engine
	path    string
	clock   *atomic.Int64
	opPub   string
	opPriv  ed25519.PrivateKey
	kPriv   ed25519.PrivateKey
	catPriv ed25519.PrivateKey
	kPub    string
	catPub  string
	admin   Credentials
}

// v75Opts adjust a world's namespace documents before they are written.
type v75Opts struct {
	matches func(doc map[string]any)
	cat     func(doc map[string]any)
	engine  func(o *Options)
	// file: a SQLite database in a file, which a restart keeps, unless
	// the tests run on Postgres.
	file bool
}

func newV75World(t *testing.T, o v75Opts) *v75World {
	t.Helper()
	w := &v75World{t: t, clock: &atomic.Int64{}, path: pgtest.DB(t)}
	if o.file && w.path == ":memory:" {
		w.path = filepath.Join(t.TempDir(), "core.db")
	}
	w.clock.Store(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).UnixMilli())
	w.opPub, w.opPriv = grant.GenerateKey()
	w.kPub, w.kPriv = grant.GenerateKey()
	w.catPub, w.catPriv = grant.GenerateKey()
	w.open(o.engine)
	w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"cat-season", "matches", "matches-r7"},
		"can": []any{"read", "create", "append", "delete", "restore", "purge", "config", "branch"}})
	// cat-reader's scope rule tests /resource by type: its grants read
	// cat-season in part (catReader).
	cat := map[string]any{"read": "grant", "keys": []any{w.kEntry(), map[string]any{"kid": "cat-reader", "alg": "ed25519", "pub": w.catPub,
		"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}},
		"catalog": map[string]any{"trust": []any{"matches"}}}
	if o.cat != nil {
		o.cat(cat)
	}
	w.mkNS("cat-season", cat)
	matches := map[string]any{"read": "grant", "keys": []any{w.kEntry(), map[string]any{"kid": "catalog-01", "alg": "ed25519", "pub": w.catPub,
		"can": []any{"read"}, "requireAt": "cat-season", "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}},
		"roles":    map[string]any{"reader": map[string]any{"can": []any{"read"}}},
		"catalogs": map[string]any{"cat-season": map[string]any{"place": []any{}}}}
	if o.matches != nil {
		o.matches(matches)
	}
	w.mkNS("matches", matches)
	return w
}

func (w *v75World) open(adjust func(o *Options)) {
	w.t.Helper()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": w.opPub, "can": []any{"*"}}}))
	if err != nil {
		w.t.Fatal(err)
	}
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		w.t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	opt := Options{Path: w.path, BlobDir: w.t.TempDir(), OperatorKeys: ops, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		BlobSweepInterval: -1, Limits: lim, Purger: discardPurger{}, KeyStore: ks, Now: func() time.Time { return time.UnixMilli(w.clock.Load()) }}
	opt.Maximums = lim
	opt.Maximums.ExchangeRate = Rate{1e9, 1e9}
	if adjust != nil {
		adjust(&opt)
	}
	e, err := Open(opt)
	if err != nil {
		w.t.Fatal(err)
	}
	w.e = e
	w.t.Cleanup(func() { e.Close() })
}

func (w *v75World) kEntry() map[string]any {
	return map[string]any{"kid": "k", "alg": "ed25519", "pub": w.kPub, "can": []any{"*"}}
}

func (w *v75World) now() time.Time { return time.UnixMilli(w.clock.Load()) }

func (w *v75World) cred(priv ed25519.PrivateKey, root map[string]any) Credentials {
	w.t.Helper()
	if _, ok := root["exp"]; !ok {
		root["exp"] = w.now().Add(time.Hour).UTC().Format(time.RFC3339)
	}
	g, err := grant.Mint(root, priv)
	if err != nil {
		w.t.Fatal(err)
	}
	return Credentials{Bearer: g.Encode()}
}

func (w *v75World) mkNS(ns string, doc map[string]any) {
	w.t.Helper()
	op := w.cred(w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"config"}})
	if _, err := w.e.WriteConfig(context.Background(), Request{NS: ns, Cred: op}, ConfigChange{IfNoneMatch: true,
		Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
		w.t.Fatalf("creating %s: %v", ns, err)
	}
}

// patchConfig applies ops to ns's document.
func (w *v75World) patchConfig(ns string, ops ...any) {
	w.t.Helper()
	info, err := w.e.NamespaceHead(context.Background(), ns, w.admin)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.e.WriteConfig(context.Background(), Request{NS: ns, Cred: w.admin}, ConfigChange{IfMatch: info.Config, Patches: ops}); err != nil {
		w.t.Fatalf("config of %s: %v", ns, err)
	}
}

// put creates or replaces ns/name with doc.
func (w *v75World) put(ns, name string, doc map[string]any) {
	w.t.Helper()
	it := Item{Resource: name}
	h, err := w.e.ResourceHead(context.Background(), ns, name, w.admin)
	if err == nil && h.State == Live {
		it.IfMatch = h.Head
		it.Steps = []Step{{Patches: []any{map[string]any{"op": "replace", "path": "", "value": doc}}}}
	} else {
		it.IfNoneMatch = true
		if err == nil && h.State == Tombstoned {
			it.IfNoneMatch, it.IfMatch = false, h.Head
		}
		it.Steps = []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}}
	}
	if _, err := w.e.WriteResource(context.Background(), Request{NS: ns, Cred: w.admin}, it); err != nil {
		w.t.Fatalf("writing %s/%s: %v", ns, name, err)
	}
}

func (w *v75World) del(ns, name string) {
	w.t.Helper()
	h, err := w.e.ResourceHead(context.Background(), ns, name, w.admin)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.e.WriteResource(context.Background(), Request{NS: ns, Cred: w.admin}, Item{Resource: name, IfMatch: h.Head, Steps: []Step{{Delete: true}}}); err != nil {
		w.t.Fatalf("deleting %s/%s: %v", ns, name, err)
	}
}

func (w *v75World) head(ns string) string {
	w.t.Helper()
	info, err := w.e.NamespaceHead(context.Background(), ns, w.admin)
	if err != nil {
		w.t.Fatal(err)
	}
	return info.Head
}

func v75Parents(names ...string) []any {
	out := []any{}
	for _, n := range names {
		out = append(out, map[string]any{"href": "/r/cat-season/" + n})
	}
	return out
}

// seed writes the catalog of the conformance scenarios: root, whose
// $access gives editors and li reader, and season under it, with
// placements of derby, shared and final; and matches's derby, shared and
// opener, which is never placed.
func (w *v75World) seed() {
	w.t.Helper()
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"reader"}, "user:li": []any{"reader"}}})
	w.put("cat-season", "season", map[string]any{"parents": v75Parents("root")})
	w.put("cat-season", "embargo", map[string]any{"parents": v75Parents("root"), "$access": map[string]any{"inherit": false, "group:chiefs": []any{"reader"}}})
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75Parents("season")})
	w.put("cat-season", "matches.shared", map[string]any{"parents": v75Parents("season")})
	w.put("cat-season", "matches.secret", map[string]any{"parents": v75Parents("embargo")})
	for _, n := range []string{"derby", "shared", "opener", "secret"} {
		w.put("matches", n, map[string]any{"title": n})
	}
}

// li is a partial reader of matches: catalog-01's grant for user:li, in
// editors and interns, with the reader role, at cat-season's head.
func (w *v75World) li(extra ...map[string]any) Credentials {
	return w.catGrant("user:li", []any{"editors", "interns"}, extra...)
}

func (w *v75World) catGrant(sub string, groups []any, extra ...map[string]any) Credentials {
	w.t.Helper()
	root := map[string]any{"kid": "catalog-01", "sub": sub, "groups": groups, "roles": []any{"reader"}, "ns": []any{"matches"},
		"can": []any{"read"}, "at": map[string]any{"ns": "cat-season", "id": w.head("cat-season")},
		"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)}
	for _, x := range extra {
		for k, v := range x {
			root[k] = v
		}
	}
	return w.cred(w.catPriv, root)
}

// inTx runs f in a read transaction of w's engine.
func (w *v75World) inTx(f func(t *tx)) {
	w.t.Helper()
	if err := w.e.read(context.Background(), func(t *tx) error { f(t); return nil }); err != nil {
		w.t.Fatal(err)
	}
}

func v75Status(err error) int {
	if e, ok := err.(*Error); ok && e != nil {
		return e.Status
	}
	if err != nil {
		return -1
	}
	return 0
}

// §B.11.9 Where: what filteredScope covers.
func TestV075FilteredScope(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		if fs == nil || fs.kind != fsContent || fs.root.name != "matches" || len(fs.cats) != 1 || fs.cats[0].n.name != "cat-season" ||
			fs.cats[0].e2e || !reflect.DeepEqual(fs.cats[0].kids, []string{"catalog-01"}) {
			t.Fatalf("matches: %+v", fs)
		}
		if fs := t2.filteredScope(t2.nsByName("cat-season")); fs == nil || fs.kind != fsCatalog || fs.cats[0].n.name != "cat-season" {
			t.Fatalf("cat-season: %+v", fs)
		}
	})
	// A local branch of matches: branch kind, with its chain.
	if _, err := w.e.CreateBranch(context.Background(), Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.inTx(func(t2 *tx) {
		m, b := t2.nsByName("matches"), t2.nsByName("matches-r7")
		fs := t2.filteredScope(b)
		if fs == nil || fs.kind != fsBranch || fs.root.id != m.id || len(fs.chain) != 1 || fs.chain[0].n.id != m.id || fs.chain[0].at != b.baseAt.Int64 {
			t.Fatalf("matches-r7: %+v", fs)
		}
	})
	// NoFilteredReads covers nothing.
	w2 := newV75World(t, v75Opts{engine: func(o *Options) { o.NoFilteredReads = true }})
	w2.inTx(func(t2 *tx) {
		if fs := t2.filteredScope(t2.nsByName("matches")); fs != nil {
			t.Fatalf("NoFilteredReads: %+v", fs)
		}
	})

	for name, o := range map[string]v75Opts{
		"requireAt true": {matches: func(doc map[string]any) {
			doc["keys"].([]any)[1].(map[string]any)["requireAt"] = true
		}},
		"sealed": {matches: func(doc map[string]any) { doc["encryption"] = map[string]any{"level": "sealed"} }},
		"public": {matches: func(doc map[string]any) { doc["read"] = "public" }},
		"not in catalog.trust": {cat: func(doc map[string]any) {
			doc["catalog"] = map[string]any{"trust": []any{}}
		}},
	} {
		w := newV75World(t, o)
		w.inTx(func(t2 *tx) {
			if fs := t2.filteredScope(t2.nsByName("matches")); fs != nil {
				t.Errorf("%s: matches covered: %+v", name, fs)
			}
			if fs := t2.filteredScope(t2.nsByName("cat-season")); fs != nil {
				t.Errorf("%s: cat-season covered: %+v", name, fs)
			}
		})
	}
	// An e2e catalog is trusted, flagged, and stays out of at.
	w = newV75World(t, v75Opts{cat: func(doc map[string]any) { doc["encryption"] = map[string]any{"level": "e2e"} }})
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		if fs == nil || len(fs.cats) != 1 || !fs.cats[0].e2e {
			t.Fatalf("e2e catalog: %+v", fs)
		}
		cp := t2.filteredCurrent(fs)
		if _, ok := cp.ids["cat-season"]; ok || len(cp.cats) != 0 {
			t.Fatalf("e2e catalog in at: %+v", cp)
		}
	})
}

// §B.11.9 Partial reader: nsAccess classifies; uncovered namespaces keep
// nsReader's answers; a GS edge grant reads nothing unfiltered.
func TestV075NSAccess(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	li := w.li()
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		a, kind, fs, err := t2.nsAccess(n, li)
		if err != nil || kind != accessPartial || fs == nil || a == nil || a.principal.ID != "user:li" {
			t.Fatalf("li: %v %v %+v %v", a, kind, fs, err)
		}
		if _, err := t2.nsReader(n, li); err == nil || err.Status != 403 {
			t.Fatalf("nsReader for li: %v", err)
		}
		if _, kind, _, err := t2.nsAccess(n, w.admin); err != nil || kind != accessUnrestricted {
			t.Fatalf("admin: %v %v", kind, err)
		}
		if _, _, _, err := t2.nsAccess(n, Credentials{}); err == nil || err.Status != 401 {
			t.Fatalf("no credentials: %v", err)
		}
	})
	// The same grant in an uncovered namespace is nsReader's 403.
	w2 := newV75World(t, v75Opts{matches: func(doc map[string]any) { delete(doc, "catalogs") }})
	li2 := w2.li()
	w2.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		if _, _, _, err := t2.nsAccess(n, li2); err == nil || err.Status != 403 {
			t.Fatalf("uncovered: %v", err)
		}
	})
	gs := v075GS(t, w, li)
	if _, err := w.e.NamespaceHeads(context.Background(), "matches", w.head("matches"), "", Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs}}); v75Status(err) != 403 {
		t.Fatalf("NamespaceHeads under a GS edge grant: %v", err)
	}
	w.inTx(func(t2 *tx) {
		a := &actor{principal: grant.Principal{ID: "edge:x"}, gs: gs}
		n := t2.nsByName("matches")
		if t2.readsNS(n, t2.config(n.configSeq), a, false) || t2.canRead(n, t2.config(n.configSeq), a, "derby") {
			t.Fatal("a GS actor reads unrestricted")
		}
	})
}

// v075GS is li's gs at the current checkpoint.
func v075GS(t *testing.T, w *v75World, cred Credentials) string {
	t.Helper()
	var gs string
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		a, kind, fs, err := t2.nsAccess(n, cred)
		if err != nil || kind != accessPartial {
			t.Fatalf("nsAccess: %v %v", kind, err)
		}
		fv, err := t2.grantView(fs, t2.filteredCurrent(fs), a)
		if err != nil {
			t.Fatal(err)
		}
		gs = fv.GS()
	})
	return gs
}

// v075View is cred's view of ns at the current checkpoint.
func v075View(t *testing.T, t2 *tx, ns string, cred Credentials) *fview {
	t.Helper()
	n := t2.nsByName(ns)
	a, kind, fs, err := t2.nsAccess(n, cred)
	if err != nil || kind != accessPartial {
		t.Fatalf("nsAccess %s: %v %v", ns, kind, err)
	}
	fv, err := t2.grantView(fs, t2.filteredCurrent(fs), a)
	if err != nil {
		t.Fatal(err)
	}
	return fv
}

func v075Visible(t *testing.T, w *v75World, ns string, cred Credentials, names ...string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	w.inTx(func(t2 *tx) {
		fv := v075View(t, t2, ns, cred)
		for _, n := range names {
			out[n] = fv.visible(t2, n)
		}
	})
	return out
}

// §B.11.9 Visible, Placement, Deleted resources (conformance 60–63, 65,
// 87, 92 at engine level).
func TestV075Visible(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	li := w.li()
	got := v075Visible(t, w, "matches", li, "derby", "shared", "opener", "secret", "never")
	if want := map[string]bool{"derby": true, "shared": true, "opener": false, "secret": false, "never": false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("li sees %v, want %v", got, want)
	}
	// A reader whose block excludes derby.
	noDerby := w.li(map[string]any{"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "derby"}}}})
	if got := v075Visible(t, w, "matches", noDerby, "derby", "shared"); got["derby"] || !got["shared"] {
		t.Fatalf("block excluding derby: %v", got)
	}
	// derby tombstoned: still visible to li, still hidden from the other.
	w.del("matches", "derby")
	if got := v075Visible(t, w, "matches", li, "derby"); !got["derby"] {
		t.Fatal("tombstoned derby hidden from li")
	}
	if got := v075Visible(t, w, "matches", noDerby, "derby"); got["derby"] {
		t.Fatal("tombstoned derby visible past the block")
	}
	// A placement whose item doesn't exist yet (place before create).
	w.put("cat-season", "matches.final", map[string]any{"parents": v75Parents("season")})
	// derby's placement deleted: hidden at the new checkpoint.
	w.del("cat-season", "matches.derby")
	if got := v075Visible(t, w, "matches", li, "derby", "shared"); got["derby"] || !got["shared"] {
		t.Fatalf("after unplacing derby: %v", got)
	}
	// Placed again: visible as a tombstone.
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75Parents("season")})
	if got := v075Visible(t, w, "matches", li, "derby"); !got["derby"] {
		t.Fatal("re-placed tombstoned derby hidden")
	}
	// A purged resource is judged at its placement as if live.
	h, _ := w.e.ResourceHead(context.Background(), "matches", "derby", w.admin)
	if _, err := w.e.Purge(context.Background(), Request{NS: "matches", Cred: w.admin}, "derby", h.Head, false); err != nil {
		t.Fatal(err)
	}
	if got := v075Visible(t, w, "matches", li, "derby"); !got["derby"] {
		t.Fatal("purged derby hidden from li")
	}
	// bo, in no group the catalog names, sees nothing.
	bo := w.catGrant("user:bo", []any{"interns"})
	if got := v075Visible(t, w, "matches", bo, "derby", "shared"); got["derby"] || got["shared"] {
		t.Fatalf("bo sees %v", got)
	}
	// Candidates: the root's placements, in byte order.
	w.inTx(func(t2 *tx) {
		fv := v075View(t, t2, "matches", li)
		var names []string
		fv.candidates(t2, "", "", func(n string) bool { names = append(names, n); return true })
		if !reflect.DeepEqual(names, []string{"derby", "final", "secret", "shared"}) {
			t.Errorf("candidates %v", names)
		}
		names = nil
		fv.candidates(t2, "derby", "s", func(n string) bool { names = append(names, n); return true })
		if !reflect.DeepEqual(names, []string{"secret", "shared"}) {
			t.Errorf("candidates after derby under s: %v", names)
		}
	})
}

// §B.11.9 Branches (conformance 63, 65): a branch's document is visible
// when live in its base as of the branch's at and placed in the root.
func TestV075VisibleBranch(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.put("matches-r7", "final", map[string]any{"title": "final"})
	w.put("cat-season", "matches.final", map[string]any{"parents": v75Parents("season")})
	// derby tombstoned in matches after the branch was cut.
	w.del("matches", "derby")
	li := w.cred(w.catPriv, map[string]any{"kid": "catalog-01", "sub": "user:li", "groups": []any{"editors"}, "roles": []any{"reader"},
		"ns": []any{"matches-r7"}, "can": []any{"read"}, "at": map[string]any{"ns": "cat-season", "id": w.head("cat-season")},
		"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	got := v075Visible(t, w, "matches-r7", li, "derby", "shared", "final", "opener")
	if want := map[string]bool{"derby": true, "shared": true, "final": false, "opener": false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("in the branch li sees %v, want %v", got, want)
	}
}

// §B.11.9 Catalogs (conformance 92): a catalog shows a node only if the
// node test passes, never a placement whose item doesn't exist or is
// tombstoned; a deleted node visible live is visible as a tombstone.
func TestV075VisibleCatalog(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{
		// catalog-01 without scope rules, so roles count for folders
		// through it (§B.11.5).
		matches: func(doc map[string]any) { delete(doc["keys"].([]any)[1].(map[string]any), "rules") },
	})
	w.seed()
	w.put("cat-season", "matches.final", map[string]any{"parents": v75Parents("season")})
	w.put("cat-season", "old", map[string]any{"parents": v75Parents("root")})
	w.put("cat-season", "matches.gone", map[string]any{"parents": v75Parents("season")})
	li := w.catReader("user:li", "editors")
	all := []string{"root", "season", "embargo", "matches.derby", "matches.shared", "matches.secret", "matches.final", "old", "matches.gone"}
	got := v075Visible(t, w, "cat-season", li, all...)
	want := map[string]bool{"root": true, "season": true, "embargo": false, "matches.derby": true, "matches.shared": true,
		"matches.secret": false, "matches.final": false, "old": true, "matches.gone": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("li sees %v, want %v", got, want)
	}
	// An item tombstoned hides its live placement; a deleted node that was
	// visible live is visible as a tombstone, a hidden one stays hidden,
	// a placement whose item never existed included (Catalogs).
	w.del("matches", "shared")
	w.del("cat-season", "old")
	w.del("cat-season", "matches.derby")
	w.del("cat-season", "embargo")
	w.del("cat-season", "matches.gone")
	got = v075Visible(t, w, "cat-season", li, "matches.shared", "old", "matches.derby", "embargo", "matches.gone")
	if want := map[string]bool{"matches.shared": false, "old": true, "matches.derby": true, "embargo": false, "matches.gone": false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after deletes li sees %v, want %v", got, want)
	}
	w.inTx(func(t2 *tx) {
		fv := v075View(t, t2, "cat-season", li)
		var names []string
		fv.candidates(t2, "matches.f", "matches.", func(n string) bool { names = append(names, n); return true })
		if !reflect.DeepEqual(names, []string{"matches.final", "matches.gone", "matches.secret", "matches.shared"}) {
			t.Errorf("catalog candidates %v", names)
		}
	})
}

// catReader is a partial reader of cat-season: a cat-reader grant for
// sub in groups.
func (w *v75World) catReader(sub string, groups ...any) Credentials {
	return w.cred(w.catPriv, map[string]any{"kid": "cat-reader", "sub": sub, "groups": groups, "ns": []any{"cat-season"}, "can": []any{"read"}})
}

var _ = slices.Contains[[]string]
var _ = catvis.Partial

// §B.11.9 Visible, D: catalogAt builds the graph tree.BuildGraph would
// from the catalog's documents at the checkpoint's seq, and an earlier
// checkpoint's graph doesn't change with later writes.
func TestV075CatalogAt(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	w.put("cat-season", "deep", map[string]any{"parents": v75Parents("season")})
	w.put("cat-season", "matches.opener", map[string]any{"parents": v75Parents("deep")})
	type snap struct {
		names   []string
		parents map[string][]string
	}
	shape := func(g *tree.Graph) snap {
		s := snap{names: g.Names(), parents: map[string][]string{}}
		for _, n := range s.names {
			s.parents[n] = g.WalkableParents(g.Node(n))
		}
		return s
	}
	var before snap
	var oldCP *fcp
	var fs0 *fscope
	w.inTx(func(t2 *tx) {
		fs0 = t2.filteredScope(t2.nsByName("matches"))
		oldCP = t2.filteredCurrent(fs0)
		c := t2.catalogAt(&oldCP.cats[0], oldCP)
		docs := map[string]any{}
		cat := t2.nsByName("cat-season")
		for _, h := range t2.listHeads(cat, nil) {
			d, err := t2.docAt(h.row)
			if err != nil {
				t.Fatal(err)
			}
			docs[h.name] = d
		}
		want := tree.BuildGraph("cat-season", t2.config(cat.configSeq).Doc, docs)
		before = shape(c.G)
		if !reflect.DeepEqual(before, shape(want)) || !reflect.DeepEqual(before.parents["matches.opener"], []string{"deep"}) {
			t.Fatalf("catalogAt %+v, BuildGraph %+v", before, shape(want))
		}
	})
	// Move opener under root.
	w.put("cat-season", "matches.opener", map[string]any{"parents": v75Parents("root")})
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		cp := t2.filteredCurrent(fs)
		if cp.at == oldCP.at {
			t.Fatal("a catalog write left the checkpoint")
		}
		if got := shape(t2.catalogAt(&cp.cats[0], cp).G); !reflect.DeepEqual(got.parents["matches.opener"], []string{"root"}) {
			t.Fatalf("after the move: %v", got.parents["matches.opener"])
		}
		old, ok := t2.filteredAt(fs, oldCP.at)
		if ok {
			t.Fatal("an unrecorded at resolved")
		}
		_ = old
		cat := t2.nsByName("cat-season")
		c := &fsCat{n: cat}
		if got := shape(t2.catalogAt(c, oldCP).G); !reflect.DeepEqual(got, before) {
			t.Fatalf("the old checkpoint's graph changed: %+v", got)
		}
	})
}

// §B.11.9 gs (conformance 69, 71, 79, 85).
func TestV075GS(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	subjects := func(cred Credentials) ([]string, string) {
		t.Helper()
		var subs []string
		var gs string
		w.inTx(func(t2 *tx) {
			fv := v075View(t, t2, "matches", cred)
			subs, gs = fv.subjects, fv.GS()
		})
		return subs, gs
	}
	liSubs, liGS := subjects(w.li())
	var digest string
	for _, s := range liSubs {
		if d, ok := strings.CutPrefix(s, "scope:"); ok {
			digest = d
		}
	}
	if want := []string{"group:editors", "partial", "scope:" + digest, "user:li"}; digest == "" || !reflect.DeepEqual(liSubs, want) {
		t.Fatalf("li's subjects %v", liSubs)
	}
	if liGS == "all" || liGS != grantcheck.SubjectSetID(liSubs) {
		t.Fatalf("gs %s", liGS)
	}
	// bo, in the same groups but without a direct entry: another gs.
	boSubs, boGS := subjects(w.catGrant("user:bo", []any{"editors", "interns"}))
	if boGS == liGS || slices.Contains(boSubs, "user:bo") {
		t.Fatalf("bo's subjects %v", boSubs)
	}
	// Other /resource block rules: another gs.
	_, narrowGS := subjects(w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^d"}}}}))
	if narrowGS == liGS {
		t.Fatal("a narrowed grant shares the gs")
	}
	// A /now block rule: unreadable this way.
	nowRule := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		a, kind, fs, err := t2.nsAccess(n, nowRule)
		if err != nil || kind != accessPartial {
			t.Fatalf("nsAccess: %v %v", kind, err)
		}
		if _, err := t2.grantView(fs, t2.filteredCurrent(fs), a); err == nil || err.Status != 403 {
			t.Fatalf("/now rule: %v", err)
		}
		if err := t2.partialRedirect(n, fs, a); v75Status(err) != 403 {
			t.Fatalf("partialRedirect with a /now rule: %v", err)
		}
	})
	// A role rule reading /principal/groups by position keeps every group:
	// no partial.
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/reader/rules",
		"value": []any{map[string]any{"op": "test", "path": "/principal/groups/0", "exists": true}}})
	if subs, _ := subjects(w.li()); !reflect.DeepEqual(subs[:3], []string{"group:editors", "group:interns", "scope:" + subs[2][6:]}) || slices.Contains(subs, "partial") {
		t.Fatalf("all groups kept: %v", subs)
	}
}

// v075GSRedirect is cred's partialRedirect in matches.
func v075GSRedirect(t *testing.T, w *v75World, cred Credentials) *FilteredRedirect {
	t.Helper()
	var red *FilteredRedirect
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		a, kind, fs, err := t2.nsAccess(n, cred)
		if err != nil || kind != accessPartial {
			t.Fatalf("nsAccess: %v %v", kind, err)
		}
		r, ok := t2.partialRedirect(n, fs, a).(*FilteredRedirect)
		if !ok {
			t.Fatal("no redirect")
		}
		red = r
	})
	return red
}

// §B.11.9 at, G: checkpoints are recorded and resolve while their members
// do; subject sets are stored and survive a restart.
func TestV075State(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{file: true})
	w.seed()
	ctx := context.Background()
	li := w.li()
	red := v075GSRedirect(t, w, li)
	if red.NS != "matches" || red.At != red.CP.at || red.CP.nsID("matches") != w.head("matches") ||
		!reflect.DeepEqual(red.CP.others("matches"), []string{"cat-season"}) {
		t.Fatalf("redirect %+v", red)
	}
	if err := w.e.recordFilteredAt(ctx, red.CP); err != nil {
		t.Fatal(err)
	}
	// A catalog-only move: a new at; the recorded one still resolves.
	w.put("cat-season", "matches.derby", map[string]any{"parents": v75Parents("root")})
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		cur := t2.filteredCurrent(fs)
		if cur.at == red.At {
			t.Fatal("same at after a catalog write")
		}
		old, ok := t2.filteredAt(fs, red.At)
		if !ok || !reflect.DeepEqual(old.ids, red.CP.ids) || len(old.cats) != 1 {
			t.Fatalf("recorded at: %v %+v", ok, old)
		}
		if _, ok := t2.filteredAt(fs, cur.at); !ok {
			t.Fatal("current at")
		}
		if _, ok := t2.filteredAt(fs, grantcheck.CombinedAt(map[string]string{"matches": cur.ids["matches"]})); ok {
			t.Fatal("an unknown at resolved")
		}
	})
	// A subject set, recorded, survives a restart on the same database.
	var rec *gsRecord
	w.inTx(func(t2 *tx) { rec = gsRecordOf(v075View(t, t2, "matches", li), w.now().Add(10*time.Minute).Unix()) })
	if err := w.e.recordFilteredGS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// A second record keeps the later exp.
	short := *rec
	short.exp = w.now().Add(time.Minute).Unix()
	if err := w.e.recordFilteredGS(ctx, &short); err != nil {
		t.Fatal(err)
	}
	w.e.Close()
	w.open(nil)
	w.inTx(func(t2 *tx) {
		got := t2.loadGS("matches", rec.gs)
		if got == nil || got.exp != rec.exp || !reflect.DeepEqual(got.subjects, rec.subjects) || got.kid != "catalog-01" ||
			!reflect.DeepEqual(got.roles, []string{"reader"}) || got.digest != rec.digest || got.filter != rec.filter || !got.partial {
			t.Fatalf("after a restart: %+v, want %+v", got, rec)
		}
		if t2.loadGS("matches", grantcheck.SubjectSetID([]string{"x"})) != nil {
			t.Fatal("a gs never recorded")
		}
		if t2.loadGS("cat-season", rec.gs) != nil {
			t.Fatal("a gs recorded in another namespace")
		}
	})
	// Past its exp the row is a miss.
	w.clock.Add((11 * time.Minute).Milliseconds())
	w.inTx(func(t2 *tx) {
		if t2.loadGS("matches", rec.gs) != nil {
			t.Fatal("an expired row")
		}
	})
}

// §B.11.9 URLs, design H: filteredAdmit (conformance 74, 76, 78).
func TestV075FilteredAdmit(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	liGS := v075GS(t, w, li)
	other := grantcheck.SubjectSetID([]string{"group:editors"})
	exp := w.now().Add(10 * time.Minute)
	nsCookie := Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: exp}}
	gCookie := func(gs string, exp time.Time) Credentials {
		return Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs, Exp: exp}}
	}
	admit := func(gs string, cred Credentials) (*fview, int) {
		t.Helper()
		var fv *fview
		var st int
		w.inTx(func(t2 *tx) {
			n := t2.nsByName("matches")
			fs := t2.filteredScope(n)
			v, err := t2.filteredAdmit(n, fs, gs, t2.filteredCurrent(fs), cred)
			if err != nil {
				st = err.Status
				return
			}
			fv = v
			if !v.visible(t2, "shared") || v.visible(t2, "opener") {
				t.Errorf("admitted at %s: wrong visibility", gs)
			}
		})
		return fv, st
	}
	if fv, st := admit(liGS, li); fv == nil || fv.GS() != liGS {
		t.Fatalf("li at her gs: %d", st)
	}
	for name, c := range map[string]struct {
		gs   string
		cred Credentials
		want int
	}{
		"li at another gs":               {other, li, 403},
		"no credentials":                 {liGS, Credentials{}, 401},
		"an unrestricted grant":          {liGS, w.admin, 403},
		"a cookie before any exchange":   {liGS, gCookie(liGS, exp), 401},
		"a /ns cookie before any record": {liGS, nsCookie, 401},
		"a cookie for another gs":        {liGS, gCookie(other, exp), 403},
		"an expired cookie":              {liGS, gCookie(liGS, w.now()), 401},
		"a cookie of another namespace":  {liGS, Credentials{Edge: &EdgeGrant{NS: "cat-season", Prefix: "/ns/cat-season", Exp: exp}}, 403},
	} {
		if _, st := admit(c.gs, c.cred); st != c.want {
			t.Errorf("%s: %d, want %d", name, st, c.want)
		}
	}
	// Exchanged: the cookie, and the unrestricted reader's /ns cookie,
	// read at the stored gs.
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS != liGS {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	for name, cred := range map[string]Credentials{"g cookie": gCookie(liGS, exp), "/ns cookie": nsCookie} {
		fv, st := admit(liGS, cred)
		if fv == nil || fv.GS() != liGS || !reflect.DeepEqual(fv.subjects, v075View0(t, w, li).subjects) || fv.a.gs != liGS {
			t.Fatalf("%s: %d", name, st)
		}
	}
	// Record the current at, then add a role whose rule refers to the
	// groups negatively: a partial cookie is 403 at the new at, still
	// admitted at the recorded one.
	var oldCP *fcp
	w.inTx(func(t2 *tx) { oldCP = t2.filteredCurrent(t2.filteredScope(t2.nsByName("matches"))) })
	if err := w.e.recordFilteredAt(ctx, oldCP); err != nil {
		t.Fatal(err)
	}
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/auditor", "value": map[string]any{"can": []any{"read"},
		"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "contractors"}}}}}}})
	if _, st := admit(liGS, gCookie(liGS, exp)); st != 403 {
		t.Fatalf("partial cookie where every group decides: %d", st)
	}
	atOld := func(cred Credentials) int {
		var st int
		w.inTx(func(t2 *tx) {
			n := t2.nsByName("matches")
			fs := t2.filteredScope(n)
			cp, ok := t2.filteredAt(fs, oldCP.at)
			if !ok {
				t.Fatal("the recorded at")
			}
			if _, err := t2.filteredAdmit(n, fs, liGS, cp, cred); err != nil {
				st = err.Status
			}
		})
		return st
	}
	if st := atOld(gCookie(liGS, exp)); st != 0 {
		t.Fatalf("at the recorded at: %d", st)
	}
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/roles/auditor"})
	if _, st := admit(liGS, gCookie(liGS, exp)); st != 0 {
		t.Fatalf("after removing auditor: %d", st)
	}
	// Changing reader's rules changes the digest: 403 at the new at, as
	// for a removed kid; the recorded at still admits it.
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/reader/rules",
		"value": []any{map[string]any{"op": "test", "path": "/action", "value": "read"}}})
	if _, st := admit(liGS, gCookie(liGS, exp)); st != 403 {
		t.Fatalf("after reader's rules changed: %d", st)
	}
	if st := atOld(gCookie(liGS, exp)); st != 0 {
		t.Fatalf("at the recorded at after reader's rules changed: %d", st)
	}
}

// v075View0 is cred's view of matches at the current checkpoint.
func v075View0(t *testing.T, w *v75World, cred Credentials) *fview {
	var fv *fview
	w.inTx(func(t2 *tx) { fv = v075View(t, t2, "matches", cred) })
	return fv
}

// §B.11.9 Edge grants (conformance 75, Grant scope 58, 59): a partial
// reader whose grant doesn't fix /resource gets /ns/{ns}/g/{gs} alone.
func TestV075Exchange(t *testing.T) {
	t.Parallel()
	// A role that tests /resource by pattern, and a key without rules.
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		delete(doc["keys"].([]any)[1].(map[string]any), "rules")
		doc["roles"].(map[string]any)["reader"] = map[string]any{"can": []any{"read"},
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^[a-z]"}}}}
	}})
	w.seed()
	ctx := context.Background()
	li := w.li()
	gs := v075GS(t, w, li)
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	if got := res.Grants[0].Prefixes(); !reflect.DeepEqual(got, []string{"/ns/matches/g/" + gs}) {
		t.Fatalf("prefixes %v", got)
	}
	w.inTx(func(t2 *tx) {
		if r := t2.loadGS("matches", gs); r == nil || r.ns != "matches" || !r.partial || r.exp > w.now().Add(10*time.Minute).Unix() {
			t.Fatalf("filtered_gs row %+v", r)
		}
	})
	// A /now block rule: 403.
	now := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	if _, err := w.e.IssueEdgeGrants(ctx, []string{now.Bearer}); v75Status(err) != 403 {
		t.Fatalf("/now rule: %v", err)
	}
	// A block rule failing now, not referring to /resource: 403.
	notLi := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/principal/id", "value": "user:bo"}}})
	if _, err := w.e.IssueEdgeGrants(ctx, []string{notLi.Bearer}); v75Status(err) != 403 {
		t.Fatalf("a failing block rule: %v", err)
	}
	// Fifty fixed names: only /r prefixes, as before.
	names := make([]any, 50)
	for i := range names {
		names[i] = "m" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	fixed := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}}})
	res, err = w.e.IssueEdgeGrants(ctx, []string{fixed.Bearer})
	if err != nil || len(res.Grants) != 50 {
		t.Fatalf("fixed names: %+v %v", res, err)
	}
	for _, g := range res.Grants {
		if g.GS != "" || g.Resource == "" || !strings.HasPrefix(g.Prefixes()[0], "/r/matches/") {
			t.Fatalf("fixed names gave %+v", g)
		}
	}
	// An unrestricted grant: /r and /ns, as before.
	reader := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"matches"}, "can": []any{"read"}})
	res, err = w.e.IssueEdgeGrants(ctx, []string{reader.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS != "" || len(res.Grants[0].Prefixes()) != 2 {
		t.Fatalf("unrestricted: %+v %v", res, err)
	}
	// NoFilteredReads: the partial reader is refused as before v0.75.
	w2 := newV75World(t, v75Opts{engine: func(o *Options) { o.NoFilteredReads = true }})
	if _, err := w2.e.IssueEdgeGrants(ctx, []string{w2.li().Bearer}); v75Status(err) != 403 {
		t.Fatalf("NoFilteredReads: %v", err)
	}
}

// §3.6: the core's name rules are the client's, which internal/edge's
// tests check its prefix grammar against (they can't import the core,
// which imports internal/tree and so internal/edge).
func TestV075NameRulesAreClients(t *testing.T) {
	t.Parallel()
	for _, n := range []string{"a", "demo", "a-b_c", "a.b", "-a", "_a", ".a", "A", "a b", "", strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("a", 128), strings.Repeat("a", 129)} {
		if ValidNSName(n) != client.ValidNSName(n) || ValidResourceName(n) != client.ValidResourceName(n) {
			t.Errorf("name %q judged otherwise than by the client", n)
		}
	}
}
