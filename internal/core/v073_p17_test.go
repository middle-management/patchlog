package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// p17Keys are signing keys a test lists in a namespace it creates: the
// key entries, and a mint for each kid.
type p17Keys struct {
	entries []any
	priv    map[string]ed25519.PrivateKey
}

// add lists a key kid with scope (can and the rest of its entry).
func (k *p17Keys) add(kid string, scope map[string]any) {
	pub, priv := grant.GenerateKey()
	e := map[string]any{"kid": kid, "alg": "ed25519", "pub": pub}
	for f, v := range scope {
		e[f] = v
	}
	k.entries = append(k.entries, e)
	if k.priv == nil {
		k.priv = map[string]ed25519.PrivateKey{}
	}
	k.priv[kid] = priv
}

// mint mints a grant whose root block is root, signed by root["kid"].
func (k *p17Keys) mint(t *testing.T, root map[string]any) Credentials {
	t.Helper()
	if _, ok := root["exp"]; !ok {
		root["exp"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	}
	g, err := grant.Mint(root, k.priv[root["kid"].(string)])
	if err != nil {
		t.Fatal(err)
	}
	return Credentials{Bearer: g.Encode()}
}

// p17Fast is a deployment's limits with fast write rates.
func p17Fast() Limits {
	l := DefaultLimits()
	fast := Rate{1e9, 1e9}
	l.RatePerResource, l.RatePerPrincipal, l.RatePerNamespace = fast, fast, fast
	return l
}

// v073CreateIn writes a create of name in ns under cred.
func v073CreateIn(e *Engine, ns string, cred Credentials, name string) (*WriteResult, error) {
	it := Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}
	return e.WriteResource(context.Background(), Request{NS: ns, Cred: cred}, it)
}

// Config writes and a branch's patches covering or overlapping /catalogs
// or /maxLag need a * key, as the other members §7.4 lists do (§7.4,
// §C.2, v0.67).
func TestV073P17CatalogsAndMaxLagNeedStarKey(t *testing.T) {
	e := v073Engine(t, p17Fast(), p17Fast(), map[string]any{"read": "grant"})
	ctx := context.Background()
	var ks p17Keys
	ks.add("star", map[string]any{"can": []any{"*"}})
	ks.add("cfg", map[string]any{"can": []any{"config", "read", "branch"}})
	e.create("p", map[string]any{"read": "grant", "keys": ks.entries})
	cfgOnly := ks.mint(t, map[string]any{"kid": "cfg", "sub": "user:c", "ns": []any{"p"}, "can": []any{"config", "read", "branch"}})
	star := ks.mint(t, map[string]any{"kid": "star", "sub": "user:s", "ns": []any{"p"}, "can": []any{"config", "read", "branch"}})
	cur := func() string {
		t.Helper()
		info, err := e.NamespaceHead(ctx, "p", star)
		if err != nil {
			t.Fatal(err)
		}
		return info.Config
	}
	members := map[string]any{
		"/maxLag":            "PT30S",
		"/catalogs":          map[string]any{"cat": map[string]any{"place": []any{"group:editors"}}},
		"/catalogs/cat":      map[string]any{"place": []any{"group:editors"}},
		"/maxLag-and-x-note": nil,
	}
	i := 0
	for path, v := range members {
		i++
		patches := []any{map[string]any{"op": "add", "path": path, "value": v}}
		if path == "/maxLag-and-x-note" {
			patches = []any{map[string]any{"op": "add", "path": "/x-note", "value": "n"}, map[string]any{"op": "add", "path": "/maxLag", "value": "PT1M"}}
		}
		if path == "/catalogs/cat" {
			patches = []any{map[string]any{"op": "add", "path": "/catalogs", "value": map[string]any{}}, patches[0]}
		}
		_, err := e.WriteConfig(ctx, Request{NS: "p", Cred: cfgOnly}, ConfigChange{IfMatch: cur(), Patches: patches})
		if v073Status(err) != 403 {
			t.Errorf("config write to %s under a key that isn't *: want 403, got %v", path, err)
		}
		_, err = e.CreateBranch(ctx, Request{NS: "p", Cred: cfgOnly}, BranchRequest{Name: "br" + string(rune('a'+i)), IfNoneMatch: true, Patches: patches})
		if v073Status(err) != 403 {
			t.Errorf("branch patches at %s under a key that isn't *: want 403, got %v", path, err)
		}
	}
	// The same key may write other members, and a * key these.
	if _, err := e.WriteConfig(ctx, Request{NS: "p", Cred: cfgOnly}, ConfigChange{IfMatch: cur(), Patches: []any{map[string]any{"op": "add", "path": "/x-note", "value": "n"}}}); err != nil {
		t.Fatalf("x- member under a key that isn't *: %v", err)
	}
	if _, err := e.WriteConfig(ctx, Request{NS: "p", Cred: star}, ConfigChange{IfMatch: cur(), Patches: []any{
		map[string]any{"op": "add", "path": "/maxLag", "value": "PT30S"},
		map[string]any{"op": "add", "path": "/catalogs", "value": map[string]any{"cat": map[string]any{"place": []any{"group:editors"}}}},
	}}); err != nil {
		t.Fatalf("under a * key: %v", err)
	}
}

// The first matching allowance whose until hasn't passed applies: one that
// has ended doesn't hide a later match. With authentication disabled an
// entry matches the author's sub alone, so two entries can match (§6.6
// Allowances).
func TestV073P17EndedAllowanceDoesNotHideLater(t *testing.T) {
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: p17Fast(), Maximums: p17Fast(), TailInterval: tailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mkNS(t, e, "n", map[string]any{"allowances": []any{
		map[string]any{"sub": "w", "kid": "k1", "bucket": map[string]any{"rate": 1000.0, "burst": 1000.0}, "until": "2020-01-01T00:00:00Z"},
		map[string]any{"sub": "w", "kid": "k2", "bucket": map[string]any{"rate": 0.001, "burst": 1.0}},
	}})
	w := Credentials{Author: "w"}
	if _, err := v073CreateIn(e, "n", w, "a"); err != nil {
		t.Fatal(err)
	}
	_, err = v073CreateIn(e, "n", w, "b")
	if ae, ok := err.(*Error); !ok || ae.Status != 429 || ae.Body["limit"] != "allowance" {
		t.Fatalf("second write: want 429 on the later allowance, got %v", err)
	}
	// Another author has no allowance: the namespace's fast buckets.
	for _, name := range []string{"c", "d"} {
		if _, err := v073CreateIn(e, "n", Credentials{Author: "x"}, name); err != nil {
			t.Fatal(err)
		}
	}
}

// For branching (and registration), a role that counts for read must pass
// all its rules against a read envelope, as a read does, not only those a
// step-1 check evaluates: a role whose rule reads /doc doesn't count, so
// the grant doesn't read the base unrestricted (§C.2 item 2, v0.66).
func TestV073P17BranchRoleRulesInFull(t *testing.T) {
	e := v073Engine(t, p17Fast(), p17Fast(), map[string]any{"read": "grant", "roles": map[string]any{
		"doc-reader": map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/doc/x", "exists": true}}},
		"reader":     map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/action", "value": "read"}}},
		"z-reader":   map[string]any{"can": []any{"read"}, "rules": []any{map[string]any{"op": "test", "path": "/principal/id", "value": "user:z"}}},
		"brancher":   map[string]any{"can": []any{"branch"}},
	}})
	ctx := context.Background()
	for i, c := range []struct {
		name  string
		roles []any
		want  int
	}{
		{"role reading /doc", []any{"doc-reader", "brancher"}, 403},
		{"role failing a step-1 rule", []any{"z-reader", "brancher"}, 403},
		{"role passing all its rules", []any{"reader", "brancher"}, 0},
		{"one role of two counts", []any{"doc-reader", "reader", "brancher"}, 0},
	} {
		cred := Credentials{Bearer: e.mint(map[string]any{"kid": "k", "sub": "user:b", "ns": []any{"n"}, "roles": c.roles})}
		_, err := e.CreateBranch(ctx, Request{NS: "n", Cred: cred}, BranchRequest{Name: "b" + string(rune('a'+i)), IfNoneMatch: true})
		if got := v073Status(err); got != c.want {
			t.Errorf("%s: got %d (%v), want %d", c.name, got, err, c.want)
		}
	}
}

// A grant its key's scope doesn't allow (readScope, sub, groups, maxTtl,
// requireAt) is 403 on every request that doesn't ignore it: writes,
// /principal, POST /keys, and /ns/{ns} and the URLs under it in a private
// namespace. Only a read of a resource URL there answers 404 (§C.2 item 1,
// §7).
func TestV073P17KeyScopeFailureIs403(t *testing.T) {
	e := v073Engine(t, p17Fast(), p17Fast(), map[string]any{"read": "grant"})
	ctx := context.Background()
	var ks p17Keys
	ks.add("admin", map[string]any{"can": []any{"*"}})
	ks.add("scoped", map[string]any{"can": []any{"read", "create"}, "readScope": "resource"})
	ks.add("subs", map[string]any{"can": []any{"read", "create"}, "sub": "user:a.*"})
	ks.add("groups", map[string]any{"can": []any{"read", "create"}, "groups": map[string]any{"allow": []any{"staff"}}})
	ks.add("ttl", map[string]any{"can": []any{"read", "create"}, "maxTtl": "PT1M"})
	for _, ns := range []string{"p", "q"} {
		doc := map[string]any{"read": "grant", "keys": ks.entries}
		if ns == "q" {
			doc["read"] = "public"
		}
		e.create(ns, doc)
	}
	admin := ks.mint(t, map[string]any{"kid": "admin", "sub": "user:root", "ns": []any{"p", "q"}, "can": []any{"read", "create"}})
	w, err := e.WriteResource(ctx, Request{NS: "p", Cred: admin}, Item{Resource: "doc", IfNoneMatch: true,
		Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteResource(ctx, Request{NS: "q", Cred: admin}, Item{Resource: "doc", IfNoneMatch: true,
		Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}); err != nil {
		t.Fatal(err)
	}
	gid, _ := w.Entry.Grant["id"].(string)
	if gid == "" {
		t.Fatal("the entry names no grant")
	}
	gesture := strings.Repeat("a", 26)
	refused := map[string]Credentials{
		"readScope": ks.mint(t, map[string]any{"kid": "scoped", "sub": "user:r", "ns": []any{"p", "q"}, "can": []any{"read"}}),
		"sub":       ks.mint(t, map[string]any{"kid": "subs", "sub": "user:x", "ns": []any{"p", "q"}, "can": []any{"read"}}),
		"groups":    ks.mint(t, map[string]any{"kid": "groups", "sub": "user:g", "groups": []any{"guests"}, "ns": []any{"p", "q"}, "can": []any{"read"}}),
		"maxTtl":    ks.mint(t, map[string]any{"kid": "ttl", "sub": "user:t", "ns": []any{"p", "q"}, "can": []any{"read"}}),
	}
	for name, cred := range refused {
		ns := map[string]func() error{
			"GET /ns/p":            func() error { _, err := e.NamespaceHead(ctx, "p", cred); return err },
			"GET /ns/p/log":        func() error { _, err := e.NamespaceLog(ctx, "p", "", "", 0, cred); return err },
			"GET /ns/p/events":     func() error { _, err := e.NamespaceEvents(ctx, "p", "", 0, cred); return err },
			"GET /ns/p/heads":      func() error { _, err := e.NamespaceHeads(ctx, "p", "", "", cred); return err },
			"GET /ns/p/branches":   func() error { _, _, err := e.Branches(ctx, "p", cred); return err },
			"GET /ns/p/grants/…":   func() error { _, err := e.Grant(ctx, "p", gid, cred); return err },
			"GET /ns/p/gestures/…": func() error { _, err := e.Gestures(ctx, "p", gesture, "", cred); return err },
			"POST /ns/p/keys":      func() error { _, err := e.Keys(ctx, "p", cred, KeysRequest{}); return err },
			"POST /ns/q/keys":      func() error { _, err := e.Keys(ctx, "q", cred, KeysRequest{}); return err },
			"GET /ns/p/principal":  func() error { _, err := e.Principal(ctx, "p", cred); return err },
			"GET /ns/q/principal":  func() error { _, err := e.Principal(ctx, "q", cred); return err },
			"PATCH /r/p/new":       func() error { _, err := v073CreateIn(e.Engine, "p", cred, "new"); return err },
			"PATCH /r/q/new":       func() error { _, err := v073CreateIn(e.Engine, "q", cred, "new"); return err },
		}
		for what, call := range ns {
			if err := call(); v073Status(err) != 403 {
				t.Errorf("%s grant, %s: want 403, got %v", name, what, err)
			}
		}
		res := map[string]func() error{
			"GET /r/p/doc":     func() error { _, err := e.ResourceHead(ctx, "p", "doc", cred); return err },
			"GET /r/p/doc/log": func() error { _, err := e.ResourceLog(ctx, "p", "doc", "", "", 0, cred); return err },
			"GET /r/p/doc/events": func() error {
				_, err := e.ResourceEvents(ctx, "p", "doc", "", 0, cred)
				return err
			},
			"GET /r/p/absent": func() error { _, err := e.ResourceHead(ctx, "p", "absent", cred); return err },
		}
		for what, call := range res {
			if err := call(); v073Status(err) != 404 {
				t.Errorf("%s grant, %s: want 404, got %v", name, what, err)
			}
		}
		// A public namespace's reads ignore the grant (§7).
		if _, err := e.NamespaceHead(ctx, "q", cred); err != nil {
			t.Errorf("%s grant, GET /ns/q: %v", name, err)
		}
		if _, err := e.ResourceHead(ctx, "q", "doc", cred); err != nil {
			t.Errorf("%s grant, GET /r/q/doc: %v", name, err)
		}
	}
	// A verified grant without read keeps the 404 of a read it may not make.
	writer := ks.mint(t, map[string]any{"kid": "admin", "sub": "user:w", "ns": []any{"p"}, "can": []any{"create"}})
	if _, err := e.NamespaceHead(ctx, "p", writer); v073Status(err) != 404 {
		t.Errorf("grant without read, GET /ns/p: want 404, got %v", err)
	}
}

// p17RateEngine opens an engine on path with authentication disabled, a
// clock that stands still at now unless the test moves it, and lim as the
// namespace defaults (maximums fast), and creates namespace n.
func p17RateEngine(t *testing.T, path, dir string, clock *atomic.Int64, lim Limits, local bool) *Engine {
	t.Helper()
	e, err := Open(Options{Path: path, BlobDir: dir, AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, Maximums: p17Fast(), TailInterval: tailEvery, Purger: discardPurger{}, LocalRateBuckets: local,
		Now: func() time.Time { return time.UnixMilli(clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// p17Rate checks err is a 429 rate refusal naming limit, with retryAfter
// wait (seconds) and Retry-After its whole seconds rounded up.
func p17Rate(t *testing.T, what string, err error, limit string, wait float64) {
	t.Helper()
	e, ok := err.(*Error)
	if !ok || e.Status != 429 || e.Body["code"] != "rate" || e.Body["limit"] != limit {
		t.Fatalf("%s: want 429 rate %s, got %v", what, limit, err)
	}
	if e.Body["retryAfter"] != wait || e.Header["Retry-After"][0] != fmt.Sprint(int(math.Ceil(wait))) {
		t.Fatalf("%s: retryAfter %v, Retry-After %v, want %v", what, e.Body["retryAfter"], e.Header["Retry-After"], wait)
	}
}

// A dry run draws tokens as the submit would, and against a drained
// bucket is 429 rate with Retry-After (§6.6 Dry runs, §7.5).
func TestV073P17DryRunRateLimited(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	lim := p17Fast()
	lim.RatePerPrincipal = Rate{1, 2}
	e := p17RateEngine(t, pgtest.DB(t), t.TempDir(), &clock, lim, false)
	mkNS(t, e, "n", map[string]any{})
	w := Credentials{Author: "w"}
	create := func(name string) Item {
		return Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}
	}
	ctx := context.Background()
	if _, err := v073CreateIn(e, "n", w, "a"); err != nil {
		t.Fatal(err)
	}
	// The dry run takes the bucket's last token, so the submit finds it
	// empty.
	if _, err := e.Batch(ctx, Request{NS: "n", Cred: w}, []Item{create("b")}, nil, nil, true); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	_, err := e.Batch(ctx, Request{NS: "n", Cred: w}, []Item{create("b")}, nil, nil, false)
	p17Rate(t, "submit after the dry run", err, "ratePerPrincipal", 1)
	_, err = e.Batch(ctx, Request{NS: "n", Cred: w}, []Item{create("b")}, nil, nil, true)
	p17Rate(t, "dry run on the drained bucket", err, "ratePerPrincipal", 1)
}

// With two buckets empty, retryAfter is the wait until both hold a token:
// the longer one, whichever bucket it is (§6.6 Exceeding one).
func TestV073P17RetryAfterLongestWait(t *testing.T) {
	for _, c := range []struct {
		principal, resource Rate
		limit               string
		wait                float64
	}{
		{Rate{1, 1}, Rate{0.25, 1}, "ratePerResource", 4},
		{Rate{0.2, 1}, Rate{0.5, 1}, "ratePerPrincipal", 5},
	} {
		var clock atomic.Int64
		clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
		lim := p17Fast()
		lim.RatePerPrincipal, lim.RatePerResource = c.principal, c.resource
		e := p17RateEngine(t, pgtest.DB(t), t.TempDir(), &clock, lim, false)
		mkNS(t, e, "n", map[string]any{})
		id, err := put(e, "n", "a", "", 1)
		if err != nil {
			t.Fatal(err)
		}
		_, err = put(e, "n", "a", id, 2)
		p17Rate(t, c.limit, err, c.limit, c.wait)
		// Half the wait refills the faster bucket only: still refused, by
		// the slower one, for what is left of its wait.
		clock.Add(int64(c.wait * 500))
		_, err = put(e, "n", "a", id, 2)
		p17Rate(t, c.limit+", halfway", err, c.limit, c.wait/2)
		clock.Add(int64(c.wait * 500))
		if _, err := put(e, "n", "a", id, 2); err != nil {
			t.Fatalf("%s: after the wait: %v", c.limit, err)
		}
	}
}

// Instances sharing a Postgres database share their buckets: a bucket's
// check and deduction are one atomic step across them, so together they
// admit no more than its burst before it refills, and a request refused
// after admission keeps its deduction for both (§6.6 Cost, D.8).
// LocalRateBuckets keeps a bucket per instance.
func TestV073P17SharedBucketsAcrossInstances(t *testing.T) {
	const burst = 5
	for _, local := range []bool{false, true} {
		var clock atomic.Int64
		clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
		lim := p17Fast()
		lim.RatePerPrincipal = Rate{0.001, burst}
		url, dir := pgtest.NewDB(t), t.TempDir()
		a := p17RateEngine(t, url, dir, &clock, lim, local)
		b := p17RateEngine(t, url, dir, &clock, lim, local)
		mkNS(t, a, "n", map[string]any{})

		// Concurrent writes of one principal through both instances.
		var admitted, limited atomic.Int64
		var wg sync.WaitGroup
		for i := range 4 * burst {
			e := a
			if i%2 == 1 {
				e = b
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := v073CreateIn(e, "n", Credentials{Author: "w"}, fmt.Sprintf("r%d", i))
				switch status(err) {
				case 0:
					admitted.Add(1)
				case 429:
					limited.Add(1)
				default:
					t.Errorf("write %d: %v", i, err)
				}
			}()
		}
		wg.Wait()
		want := int64(burst)
		if local {
			want = 2 * burst
		}
		if admitted.Load() != want || limited.Load() != 4*burst-want {
			t.Fatalf("local %v: %d admitted, %d limited, want %d admitted", local, admitted.Load(), limited.Load(), want)
		}

		// A create refused after admission (412, the name is taken) keeps
		// its deduction, which the other instance sees.
		x := Credentials{Author: "x"}
		for i := range burst - 1 {
			e := a
			if i > 0 {
				e = b
			}
			// Each create differs, so none is a retry of the first (§7.2).
			it := Item{Resource: "x", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"i": float64(i)}}}}}}
			if _, err := e.WriteResource(context.Background(), Request{NS: "n", Cred: x}, it); i > 0 && status(err) != 412 || i == 0 && err != nil {
				t.Fatalf("local %v: create %d of x: %v", local, i, err)
			}
		}
		_, errA := v073CreateIn(a, "n", x, "x2")
		_, errB := v073CreateIn(b, "n", x, "x3")
		if local {
			if errA != nil || errB != nil {
				t.Fatalf("local buckets: %v, %v", errA, errB)
			}
			continue
		}
		if errA != nil {
			t.Fatalf("the last token: %v", errA)
		}
		if status(errB) != 429 {
			t.Fatalf("after the burst, refusals included: %v", errB)
		}
	}
}

// The store's draw and charge: a charge deducts whatever the bucket holds,
// below zero, and the next draw waits for the bucket to refill to one
// token; buckets never drawn on are full, and a sweep deletes the rows of
// full ones only (ratebuckets.go).
func TestV073P17BucketStore(t *testing.T) {
	url := pgtest.NewDB(t)
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	e := p17RateEngine(t, url, t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	if s == nil {
		t.Fatal("no bucket store on Postgres")
	}
	ctx := context.Background()
	now := time.UnixMilli(clock.Load())
	d := draw{"b\x00test", Rate{100, 1000}, 400, "blobRate"}
	other := draw{"p\x00test", Rate{1, 10}, 1, "ratePerPrincipal"}
	for i := range 2 {
		if _, _, ok, err := s.admit(ctx, now, []draw{d, other}); err != nil || !ok {
			t.Fatalf("draw %d: %v %v", i, ok, err)
		}
	}
	// 200 left; a charge of 500 takes it to -300.
	d.cost = 500
	if err := s.charge(ctx, now, d); err != nil {
		t.Fatal(err)
	}
	wait, hit, ok, err := s.admit(ctx, now, []draw{other, d})
	if err != nil || ok || hit != "blobRate" || wait != 3010*time.Millisecond {
		t.Fatalf("after the charge: wait %v hit %q ok %v err %v", wait, hit, ok, err)
	}
	var rows int
	count := func() int {
		t.Helper()
		if err := e.db.QueryRow(`SELECT count(*) FROM rate_buckets`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	// The first draw started this instance's first sweep, which found
	// nothing full.
	s.wg.Wait()
	if count() != 2 {
		t.Fatalf("after the first sweep: %d rows, want 2", rows)
	}
	// A minute on, both have refilled to their bursts (8 + 60 × 1 ≥ 10,
	// -300 + 60 × 100 ≥ 1000), and go when a draw starts this instance's
	// next sweep; the bucket that draw takes from isn't full, and stays.
	clock.Add(int64(sweepEvery/time.Millisecond) + 1)
	now = time.UnixMilli(clock.Load())
	fresh := draw{"r\x00test", Rate{0.001, 3}, 1, "ratePerResource"}
	if _, _, ok, err := s.admit(ctx, now, []draw{fresh}); err != nil || !ok {
		t.Fatalf("fresh draw: %v %v", ok, err)
	}
	s.wg.Wait()
	if count() != 1 {
		t.Fatalf("after the sweep: %d rows, want the one bucket not full", rows)
	}
}

// p17SlowBuckets adds triggers to rate_buckets that only stretch two
// moments, so that an interleaving otherwise a window of microseconds
// happens every time: an insert of the bucket ins (a draw's insert of the
// buckets it hasn't seen, before it locks the ones it has) and a delete
// of the bucket del (a sweep's, between rows). They take no lock.
func p17SlowBuckets(t *testing.T, e *Engine, ins, del string) {
	t.Helper()
	for _, q := range []string{
		`CREATE FUNCTION p17_slow_ins() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.key = '\x` + fmt.Sprintf("%x", ins) + `'::bytea THEN PERFORM pg_sleep(0.3); END IF; RETURN NEW; END $$`,
		`CREATE TRIGGER p17_slow_ins BEFORE INSERT ON rate_buckets FOR EACH ROW EXECUTE FUNCTION p17_slow_ins()`,
		`CREATE FUNCTION p17_slow_del() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.key = '\x` + fmt.Sprintf("%x", del) + `'::bytea THEN PERFORM pg_sleep(0.5); END IF; RETURN OLD; END $$`,
		`CREATE TRIGGER p17_slow_del BEFORE DELETE ON rate_buckets FOR EACH ROW EXECUTE FUNCTION p17_slow_del()`,
	} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// p17FullBuckets adds full buckets with keys, in that order on the heap.
func p17FullBuckets(t *testing.T, e *Engine, now time.Time, r Rate, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, err := e.db.Exec(`INSERT INTO rate_buckets (key, tokens, last, rate, burst) VALUES ($1, $2, $3, $4, $2)`, []byte(k), r.Burst, now.UnixMicro(), r.Rate); err != nil {
			t.Fatal(err)
		}
	}
}

// A sweep never waits on a draw, so the two never wait on each other in a
// cycle: a draw that saw buckets a and b and is adding c, while the sweep
// deletes the full b, m and a in that order (the table's), finds the
// rows gone, and no deadlock. Deleting in the table's order, the sweep
// held b and waited for a, which the draw had locked while it waited for
// b: Postgres rolled one back (ratebuckets.go).
func TestV073P17SweepNeverWaitsOnDraw(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	e := p17RateEngine(t, pgtest.FreshDB(t), t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	now := time.UnixMilli(clock.Load())
	r := Rate{1, 10}
	p17FullBuckets(t, e, now, r, "b", "m", "a")
	p17SlowBuckets(t, e, "c", "m")
	type res struct {
		tokens map[string]float64
		err    error
	}
	done := make(chan res, 1)
	go func() {
		// drawOnce, which runs rate_draw once: a deadlock is its error.
		tokens, _, err := s.drawOnce(context.Background(), now, [][]byte{[]byte("a"), []byte("b"), []byte("c")},
			[]float64{1, 1, 1}, []float64{10, 10, 10}, []float64{1, 1, 1}, false)
		done <- res{tokens, err}
	}()
	// The draw has seen a and b, and is adding c.
	time.Sleep(100 * time.Millisecond)
	s.maybeSweep(now)
	got := <-done
	s.wg.Wait()
	if got.err != nil {
		t.Fatalf("draw during a sweep: %v", got.err)
	}
	if len(got.tokens) == 3 {
		t.Fatalf("draw during a sweep found every row: %v", got.tokens)
	}
	// The draw runs again on what the sweep left.
	if _, _, ok, err := s.admit(context.Background(), now, []draw{{"a", r, 1, "x"}, {"b", r, 1, "x"}, {"c", r, 1, "x"}}); err != nil || !ok {
		t.Fatalf("draw after the sweep: %v %v", ok, err)
	}
}

// End to end: a dry run, whose draw runs in a read transaction that
// nothing runs again, during that sweep is admitted, not an internal
// error (§6.6 Dry runs). Its buckets: n\x00n < p\x00w < r\x00n\x00a\x00w
// (new); the sweep's order: p\x00w, m, n\x00n.
func TestV073P17SweepDuringDryRun(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	e := p17RateEngine(t, pgtest.FreshDB(t), t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	mkNS(t, e, "n", map[string]any{})
	s.wg.Wait()
	if _, err := e.db.Exec(`DELETE FROM rate_buckets`); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.swept = time.Time{}
	s.mu.Unlock()
	now := time.UnixMilli(clock.Load())
	p17FullBuckets(t, e, now, Rate{1e9, 1e9}, "p\x00w", "m", "n\x00n")
	p17SlowBuckets(t, e, "r\x00n\x00a\x00w", "m")
	done := make(chan error, 1)
	go func() {
		it := Item{Resource: "a", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}
		_, err := e.Batch(context.Background(), Request{NS: "n", Cred: Credentials{Author: "w"}}, []Item{it}, nil, nil, true)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	s.maybeSweep(now)
	err := <-done
	s.wg.Wait()
	if err != nil {
		t.Fatalf("dry run during a sweep: %v", err)
	}
}

// A draw Postgres rolls back for a deadlock (with a statement that locks
// bucket rows out of key order) deducted nothing, and runs again.
func TestV073P17DrawRetriesDeadlock(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	e := p17RateEngine(t, pgtest.NewDB(t), t.TempDir(), &clock, p17Fast(), false)
	s := e.rate.store
	now := time.UnixMilli(clock.Load())
	r := Rate{1, 10}
	p17FullBuckets(t, e, now, r, "a", "b")
	ctx := context.Background()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT 1 FROM rate_buckets WHERE key = 'b' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		// The draw locks a, then waits for b.
		_, _, ok, err := s.admit(ctx, now, []draw{{"a", r, 1, "x"}, {"b", r, 1, "x"}})
		if err == nil && !ok {
			err = fmt.Errorf("refused")
		}
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	// Waiting for a closes the cycle. The draw, waiting longer, finds the
	// deadlock first, and Postgres rolls it back.
	if _, err := tx.Exec(`SELECT 1 FROM rate_buckets WHERE key = 'a' FOR UPDATE`); err != nil {
		t.Fatalf("the other statement was the deadlock's victim: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("draw in a deadlock: %v", err)
	}
	var tokens float64
	if err := e.db.QueryRow(`SELECT tokens FROM rate_buckets WHERE key = 'a'`).Scan(&tokens); err != nil || tokens != 9 {
		t.Fatalf("a after the draw: %v tokens, %v; want one deduction", tokens, err)
	}
}

// merged gives one draw per bucket, in the order of the keys' bytes (as
// rate_draw locks them): a bucket drawn on twice keeps its first draw's
// rate and limit, with the costs added.
func TestV073P17Merged(t *testing.T) {
	r1, r2, r3 := Rate{1, 2}, Rate{3, 4}, Rate{5, 6}
	got := merged([]draw{
		{"r\x00n\x00b\x00w", r1, 1, "ratePerResource"},
		{"p\x00w", r2, 3, "ratePerPrincipal"},
		{"r\x00n\x00\xc3\xa9\x00w", r1, 1, "ratePerResource"},
		{"r\x00n\x00z\x00w", r1, 1, "ratePerResource"},
		{"r\x00n\x00b\x00w", r3, 2, "other"},
		{"n\x00n", r3, 3, "ratePerNamespace"},
	})
	want := []draw{
		{"n\x00n", r3, 3, "ratePerNamespace"},
		{"p\x00w", r2, 3, "ratePerPrincipal"},
		{"r\x00n\x00b\x00w", r1, 3, "ratePerResource"},
		{"r\x00n\x00z\x00w", r1, 1, "ratePerResource"},
		{"r\x00n\x00\xc3\xa9\x00w", r1, 1, "ratePerResource"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("merged:\n got %#v\nwant %#v", got, want)
	}
}

// merged takes time in proportion to a request's draws, give or take a
// sort: a batch of n items draws on n per-resource buckets, and an atomic
// import's batch is many thousands (§6.6 Allowances). Searching the
// entries so far for each draw took seconds for 20000.
func TestV073P17MergedLargeBatch(t *testing.T) {
	const n = 50000
	draws := []draw{{"p\x00w", Rate{1, 1}, n, "ratePerPrincipal"}, {"n\x00import", Rate{1, 1}, n, "ratePerNamespace"}}
	for i := range n {
		draws = append(draws, draw{fmt.Sprintf("r\x00import\x00doc-%06d\x00w", n-1-i), Rate{1, 1}, 1, "ratePerResource"})
	}
	// Each item draws on its resource's bucket twice.
	draws = append(draws, draws[2:]...)
	start := time.Now()
	got := merged(draws)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("merged of %d draws took %v", len(draws), el)
	}
	if len(got) != n+2 || got[0].key != "n\x00import" || got[1].key != "p\x00w" {
		t.Fatalf("merged: %d draws, first %q %q", len(got), got[0].key, got[1].key)
	}
	for i, d := range got[2:] {
		if d.key != fmt.Sprintf("r\x00import\x00doc-%06d\x00w", i) || d.cost != 2 {
			t.Fatalf("merged: draw %d is %q, cost %v", i+2, d.key, d.cost)
		}
	}
}

// POST /ns/{ns}/keys doesn't ignore the grant in a public namespace, as
// its reads do: it keeps the 403 and 401 answers of steps 2 and 3 (§7,
// §E.2.3), so a grant that doesn't name the namespace is 403 there, one
// that can't be used or none 401, and one with read passes to the answer
// (404 not_offered, the namespace isn't sealed).
func TestV073P17KeysPublicNamespaceKeepsGrant(t *testing.T) {
	e := v073Engine(t, p17Fast(), p17Fast(), map[string]any{"read": "grant"})
	ctx := context.Background()
	var ks p17Keys
	ks.add("admin", map[string]any{"can": []any{"*"}})
	e.create("q", map[string]any{"read": "public", "keys": ks.entries})
	other := ks.mint(t, map[string]any{"kid": "admin", "sub": "user:o", "ns": []any{"elsewhere"}, "can": []any{"read"}})
	reader := ks.mint(t, map[string]any{"kid": "admin", "sub": "user:r", "ns": []any{"q"}, "can": []any{"read"}})
	for _, c := range []struct {
		what   string
		cred   Credentials
		status int
		code   string
	}{
		{"a grant not naming q", other, 403, "forbidden"},
		{"a token that isn't a grant", Credentials{Bearer: "not-a-grant"}, 401, "unauthenticated"},
		{"no grant", Credentials{}, 401, "unauthenticated"},
		{"a grant with read", reader, 404, "not_offered"},
	} {
		_, err := e.Keys(ctx, "q", c.cred, KeysRequest{})
		if ae, ok := err.(*Error); !ok || ae.Status != c.status || ae.Body["code"] != c.code {
			t.Errorf("POST /ns/q/keys, %s: want %d %s, got %v", c.what, c.status, c.code, err)
		}
		// Its reads ignore the grant.
		if _, err := e.NamespaceHead(ctx, "q", c.cred); err != nil {
			t.Errorf("GET /ns/q, %s: %v", c.what, err)
		}
	}
}
