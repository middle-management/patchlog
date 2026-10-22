package core

import (
	"context"
	"crypto/ed25519"
	"strings"
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
