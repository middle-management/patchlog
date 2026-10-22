package core

import (
	"context"
	"crypto/ed25519"
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
