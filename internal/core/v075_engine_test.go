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

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// V75-01 (v0.75): the visibility engine of filtered namespace reads
// (§7.9) in the core: coverage, access classification, the visible
// predicate, view, stored state, admission and
// the exchange.

// v75World is an engine with authentication on and two private
// namespaces, cat-season and matches. matches's key reader-01 has a
// scope rule allowing /resource derby and shared only, so its grants read
// matches only in part, and §7.9 covers both. k is a * key in both.
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

// v75Visible is the schema reader-01's rule tests /resource with: the
// names its grants read in matches.
var v75Visible = map[string]any{"pattern": "^(derby|shared)$"}

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
		"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}}}
	if o.cat != nil {
		o.cat(cat)
	}
	w.mkNS("cat-season", cat)
	matches := map[string]any{"read": "grant", "keys": []any{w.kEntry(), map[string]any{"kid": "reader-01", "alg": "ed25519", "pub": w.catPub,
		"can": []any{"read"}, "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": v75Visible}}}},
		"roles": map[string]any{"reader": map[string]any{"can": []any{"read"}}}}
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
	opt := Options{Path: w.path, BlobDir: w.t.TempDir(), OperatorKeys: ops, RetentionInterval: -1,
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

// seed writes cat-season's documents and matches's derby, shared,
// opener and secret, of which reader-01's rule allows derby and shared.
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

// li is a partial reader of matches: reader-01's grant for user:li, in
// editors and interns, with the reader role.
func (w *v75World) li(extra ...map[string]any) Credentials {
	return w.catGrant("user:li", []any{"editors", "interns"}, extra...)
}

// bo is a partial reader of matches who sees none of it: reader-01's
// grant for user:bo in chiefs, whose block rule allows only secret, which
// the key's rule doesn't.
func (w *v75World) bo() Credentials {
	return w.catGrant("user:bo", []any{"chiefs"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^secret$"}}}})
}

func (w *v75World) catGrant(sub string, groups []any, extra ...map[string]any) Credentials {
	w.t.Helper()
	root := map[string]any{"kid": "reader-01", "sub": sub, "groups": groups, "roles": []any{"reader"}, "ns": []any{"matches"},
		"can": []any{"read"},
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

// §7.9 Where: what filteredScope covers.
func TestV075FilteredScope(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.inTx(func(t2 *tx) {
		for _, ns := range []string{"matches", "cat-season"} {
			if fs := t2.filteredScope(t2.nsByName(ns)); fs == nil || fs.n.name != ns {
				t.Fatalf("%s: %+v", ns, fs)
			}
		}
	})
	// A local branch of matches isn't covered (v0.78, §7.9 Where).
	if _, err := w.e.CreateBranch(context.Background(), Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.inTx(func(t2 *tx) {
		if fs := t2.filteredScope(t2.nsByName("matches-r7")); fs != nil {
			t.Fatalf("matches-r7 covered: %+v", fs)
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
		"sealed": {matches: func(doc map[string]any) { doc["encryption"] = map[string]any{"level": "sealed"} }},
		"public": {matches: func(doc map[string]any) { doc["read"] = "public" }},
	} {
		w := newV75World(t, o)
		w.inTx(func(t2 *tx) {
			if fs := t2.filteredScope(t2.nsByName("matches")); fs != nil {
				t.Errorf("%s: matches covered: %+v", name, fs)
			}
		})
	}
	// The checkpoint is {ns}'s ns_id at its head.
	head := w.head("matches")
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		if cp := t2.filteredCurrent(fs); cp.at != head {
			t.Fatalf("at %s, want %s", cp.at, head)
		}
	})
}

// §7.9 Partial reader: nsAccess classifies; uncovered namespaces keep
// nsReader's answers; a View edge grant reads nothing unfiltered.
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
	w2 := newV75World(t, v75Opts{matches: func(doc map[string]any) { doc["encryption"] = map[string]any{"level": "sealed"} }})
	li2 := w2.li()
	w2.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		if _, _, _, err := t2.nsAccess(n, li2); err == nil || err.Status != 403 {
			t.Fatalf("uncovered: %v", err)
		}
	})
	vid := v075ViewID(t, w, li)
	if _, err := w.e.NamespaceHeads(context.Background(), "matches", w.head("matches"), "", Credentials{Edge: &EdgeGrant{NS: "matches", View: vid, Prefix: "/ns/matches/view/" + vid}}); v75Status(err) != 403 {
		t.Fatalf("NamespaceHeads under a View edge grant: %v", err)
	}
	w.inTx(func(t2 *tx) {
		a := &actor{principal: grant.Principal{ID: "edge:x"}, view: vid}
		n := t2.nsByName("matches")
		if t2.readsNS(n, t2.config(n.configSeq), a, false) || t2.canRead(n, t2.config(n.configSeq), a, "derby") {
			t.Fatal("a View actor reads unrestricted")
		}
	})
}

// v075View is li's view at the current checkpoint.
func v075ViewID(t *testing.T, w *v75World, cred Credentials) string {
	t.Helper()
	var vid string
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
		vid = fv.View()
	})
	return vid
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
			out[n] = fv.visibleHead(t2, n)
		}
	})
	return out
}

// §7.9 Visible: a name is visible where the grant's rules allow
// reading it, live, tombstoned or purged alike.
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
	// A purged resource is judged as if live.
	h, _ := w.e.ResourceHead(context.Background(), "matches", "derby", w.admin)
	if _, err := w.e.Purge(context.Background(), Request{NS: "matches", Cred: w.admin}, "derby", h.Head, false); err != nil {
		t.Fatal(err)
	}
	if got := v075Visible(t, w, "matches", li, "derby"); !got["derby"] {
		t.Fatal("purged derby hidden from li")
	}
	// Candidates: the namespace's names, in byte order.
	w.inTx(func(t2 *tx) {
		fv := v075View(t, t2, "matches", li)
		var names []string
		fv.candidates(t2, "", "", func(n string) bool { names = append(names, n); return true })
		if !reflect.DeepEqual(names, []string{"derby", "opener", "secret", "shared"}) {
			t.Errorf("candidates %v", names)
		}
		names = nil
		fv.candidates(t2, "derby", "s", func(n string) bool { names = append(names, n); return true })
		if !reflect.DeepEqual(names, []string{"secret", "shared"}) {
			t.Errorf("candidates after derby under s: %v", names)
		}
	})
}

// §7.9 Where (v0.78: "Filtered reads cover no branch"; conformance
// TDA 63): li, a partial reader of matches, isn't one of its branch: her
// unfiltered read of matches-r7 is 403, with no redirect. Before v0.78 a
// branch's document was visible when live in its base as of the branch's
// at and placed in the root.
func TestV075VisibleBranch(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.put("matches-r7", "final", map[string]any{"title": "final"})
	li := w.cred(w.catPriv, map[string]any{"kid": "reader-01", "sub": "user:li", "groups": []any{"editors"}, "roles": []any{"reader"},
		"ns": []any{"matches-r7"}, "can": []any{"read"},
		"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	w.inTx(func(t2 *tx) {
		a, kind, fs, err := t2.nsAccess(t2.nsByName("matches-r7"), li)
		if err == nil || err.Status != 403 || kind != accessNone || fs != nil || a != nil {
			t.Fatalf("li in the branch: %v %v %+v %v, want 403", a, kind, fs, err)
		}
	})
	// An unrestricted reader of the branch sees final, unfiltered.
	if _, err := w.e.ResourceHead(ctx, "matches-r7", "final", w.admin); err != nil {
		t.Fatalf("admin reading final: %v", err)
	}
}

// catReader is a partial reader of cat-season: a cat-reader grant for
// sub in groups.
func (w *v75World) catReader(sub string, groups ...any) Credentials {
	return w.cred(w.catPriv, map[string]any{"kid": "cat-reader", "sub": sub, "groups": groups, "ns": []any{"cat-season"}, "can": []any{"read"}})
}

var _ = slices.Contains[[]string]

// §7.9 view: a partial reader's subjects are its scope digest and its
// key subject alone: readers with the same rules through the same key
// share a view, whatever their sub or groups.
func TestV075View(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	subjects := func(cred Credentials) ([]string, string) {
		t.Helper()
		var subs []string
		var vid string
		w.inTx(func(t2 *tx) {
			fv := v075View(t, t2, "matches", cred)
			subs, vid = fv.subjects, fv.View()
		})
		return subs, vid
	}
	liSubs, liView := subjects(w.li())
	var digest string
	for _, s := range liSubs {
		if d, ok := strings.CutPrefix(s, "scope:"); ok {
			digest = d
		}
	}
	if want := []string{grantcheck.KeySubject("reader-01", w.catPub), "scope:" + digest}; digest == "" || !reflect.DeepEqual(liSubs, want) {
		t.Fatalf("li's subjects %v, want %v", liSubs, want)
	}
	if liView != grantcheck.ViewID(liSubs) {
		t.Fatalf("vid %s", liView)
	}
	// bo, in other groups: the same view.
	if _, boView := subjects(w.catGrant("user:bo", []any{"interns"})); boView != liView {
		t.Fatal("bo's vid differs")
	}
	// Other /resource block rules: another view.
	_, narrowView := subjects(w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^d"}}}}))
	if narrowView == liView {
		t.Fatal("a narrowed grant shares the vid")
	}
	// A /now block rule: refused in the read check, before any view
	// (§C.2 item 5).
	nowRule := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "schema": map[string]any{"type": "string"}}}})
	w.inTx(func(t2 *tx) {
		if _, kind, _, err := t2.nsAccess(t2.nsByName("matches"), nowRule); err == nil || err.Status != 403 || kind != accessNone {
			t.Fatalf("/now rule: %v %v, want 403", kind, err)
		}
	})
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

// §7.9 at, G: checkpoints are entries of {ns}'s chain; subject sets
// are stored and survive a restart.
func TestV075State(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{file: true})
	w.seed()
	ctx := context.Background()
	li := w.li()
	red := v075GSRedirect(t, w, li)
	if red.NS != "matches" || red.At != w.head("matches") {
		t.Fatalf("redirect %+v", red)
	}
	// A move: a new at; the old one still resolves, as any entry of the
	// chain does.
	w.put("matches", "derby", map[string]any{"title": "moved"})
	catHead := w.head("cat-season")
	w.inTx(func(t2 *tx) {
		fs := t2.filteredScope(t2.nsByName("matches"))
		cur := t2.filteredCurrent(fs)
		if cur.at == red.At {
			t.Fatal("same at after a write")
		}
		if old, ok := t2.filteredAt(fs, red.At); !ok || old.at != red.At {
			t.Fatalf("old at: %v %+v", ok, old)
		}
		if _, ok := t2.filteredAt(fs, cur.at); !ok {
			t.Fatal("current at")
		}
		if _, ok := t2.filteredAt(fs, catHead); ok {
			t.Fatal("another namespace's ns_id resolved")
		}
	})
	// A subject set, recorded, survives a restart on the same database.
	var rec *viewRecord
	w.inTx(func(t2 *tx) { rec = viewRecordOf(v075View(t, t2, "matches", li), w.now().Add(10*time.Minute).Unix()) })
	if err := w.e.recordFilteredView(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// A second record keeps the later exp.
	short := *rec
	short.exp = w.now().Add(time.Minute).Unix()
	if err := w.e.recordFilteredView(ctx, &short); err != nil {
		t.Fatal(err)
	}
	w.e.Close()
	w.open(nil)
	w.inTx(func(t2 *tx) {
		got := t2.loadView("matches", rec.view)
		if got == nil || got.exp != rec.exp || !reflect.DeepEqual(got.subjects, rec.subjects) || got.kid != "reader-01" ||
			!reflect.DeepEqual(got.roles, []string{"reader"}) || got.digest != rec.digest || got.filter != rec.filter {
			t.Fatalf("after a restart: %+v, want %+v", got, rec)
		}
		if t2.loadView("matches", grantcheck.ViewID([]string{"x"})) != nil {
			t.Fatal("a vid never recorded")
		}
		if t2.loadView("cat-season", rec.view) != nil {
			t.Fatal("a vid recorded in another namespace")
		}
	})
	// Past its exp the row is a miss.
	w.clock.Add((11 * time.Minute).Milliseconds())
	w.inTx(func(t2 *tx) {
		if t2.loadView("matches", rec.view) != nil {
			t.Fatal("an expired row")
		}
	})
}

// §7.9 URLs, design H: filteredAdmit (conformance 74, 76, 78).
func TestV075FilteredAdmit(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	liView := v075ViewID(t, w, li)
	other := grantcheck.ViewID([]string{"group:editors"})
	exp := w.now().Add(10 * time.Minute)
	nsCookie := Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: exp}}
	gCookie := func(vid string, exp time.Time) Credentials {
		return Credentials{Edge: &EdgeGrant{NS: "matches", View: vid, Prefix: "/ns/matches/view/" + vid, Exp: exp}}
	}
	admit := func(vid string, cred Credentials) (*fview, int) {
		t.Helper()
		var fv *fview
		var st int
		w.inTx(func(t2 *tx) {
			n := t2.nsByName("matches")
			fs := t2.filteredScope(n)
			v, err := t2.filteredAdmit(n, fs, vid, t2.filteredCurrent(fs), cred)
			if err != nil {
				st = err.Status
				return
			}
			fv = v
			if !v.visibleHead(t2, "shared") || v.visibleHead(t2, "opener") {
				t.Errorf("admitted at %s: wrong visibility", vid)
			}
		})
		return fv, st
	}
	if fv, st := admit(liView, li); fv == nil || fv.View() != liView {
		t.Fatalf("li at her vid: %d", st)
	}
	for name, c := range map[string]struct {
		vid  string
		cred Credentials
		want int
	}{
		"li at another vid":             {other, li, 403},
		"no credentials":                {liView, Credentials{}, 401},
		"an unrestricted grant":         {liView, w.admin, 403},
		"a cookie before any exchange":  {liView, gCookie(liView, exp), 401},
		"a cookie for another vid":      {liView, gCookie(other, exp), 403},
		"an expired cookie":             {liView, gCookie(liView, w.now()), 401},
		"a cookie of another namespace": {liView, Credentials{Edge: &EdgeGrant{NS: "cat-season", Prefix: "/ns/cat-season", Exp: exp}}, 403},
	} {
		if _, st := admit(c.vid, c.cred); st != c.want {
			t.Errorf("%s: %d, want %d", name, st, c.want)
		}
	}
	// Exchanged: the cookie, and the unrestricted reader's /ns cookie,
	// read at the stored view.
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].View != liView {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	fv, st := admit(liView, gCookie(liView, exp))
	if fv == nil || fv.View() != liView || !reflect.DeepEqual(fv.subjects, v075View0(t, w, li).subjects) || fv.a.view != liView {
		t.Fatalf("view cookie: %d", st)
	}
	// An unrestricted reader's /ns cookie counts as the view's cookie
	// and reads there unrestricted, record or not (§7.9 Partial reader).
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		fs := t2.filteredScope(n)
		v, err := t2.filteredAdmit(n, fs, liView, t2.filteredCurrent(fs), nsCookie)
		if err != nil || !v.unrestricted || !v.visibleHead(t2, "opener") {
			t.Fatalf("/ns cookie: %v", err)
		}
	})
	// Record the current at, then add a role that lists read: every
	// cookie of the view is 403 from that entry on, even once a later one
	// removes it (v0.87, §7.9 view), at the recorded at too: "at every
	// URL".
	var oldCP *fcp
	w.inTx(func(t2 *tx) { oldCP = t2.filteredCurrent(t2.filteredScope(t2.nsByName("matches"))) })
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/auditor", "value": map[string]any{"can": []any{"read"},
		"rules": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "contractors"}}}}}}})
	if _, st := admit(liView, gCookie(liView, exp)); st != 403 {
		t.Fatalf("a cookie after a role listing read was added: %d, want 403", st)
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
			if _, err := t2.filteredAdmit(n, fs, liView, cp, cred); err != nil {
				st = err.Status
			}
		})
		return st
	}
	if st := atOld(gCookie(liView, exp)); st != 403 {
		t.Fatalf("at the recorded at: %d, want 403", st)
	}
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/roles/auditor"})
	if _, st := admit(liView, gCookie(liView, exp)); st != 403 {
		t.Fatalf("after removing auditor: %d, want 403", st)
	}
}

// v075View0 is cred's view of matches at the current checkpoint.
func v075View0(t *testing.T, w *v75World, cred Credentials) *fview {
	var fv *fview
	w.inTx(func(t2 *tx) { fv = v075View(t, t2, "matches", cred) })
	return fv
}

// §7.9 Edge grants (conformance 75, Grant scope 58, 59): a partial
// reader whose grant doesn't fix /resource gets /ns/{ns}/view/{view} alone.
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
	vid := v075ViewID(t, w, li)
	res, err := w.e.IssueEdgeGrants(ctx, []string{li.Bearer})
	if err != nil || len(res.Grants) != 1 {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	if got := res.Grants[0].Prefixes(); !reflect.DeepEqual(got, []string{"/ns/matches/view/" + vid}) {
		t.Fatalf("prefixes %v", got)
	}
	w.inTx(func(t2 *tx) {
		if r := t2.loadView("matches", vid); r == nil || r.ns != "matches" || r.exp > w.now().Add(10*time.Minute).Unix() {
			t.Fatalf("filtered_views row %+v", r)
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
		if g.View != "" || g.Resource == "" || !strings.HasPrefix(g.Prefixes()[0], "/r/matches/") {
			t.Fatalf("fixed names gave %+v", g)
		}
	}
	// An unrestricted grant: /r and /ns, as before.
	reader := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"matches"}, "can": []any{"read"}})
	res, err = w.e.IssueEdgeGrants(ctx, []string{reader.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].View != "" || len(res.Grants[0].Prefixes()) != 2 {
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
