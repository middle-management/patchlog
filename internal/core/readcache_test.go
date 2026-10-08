package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// authTailEvery is authEngine's TailInterval. On Postgres the read cache
// serves nothing unless the tailer polled within 3 intervals, and keeps head
// pointers as long: tests that expect an answer served from it can't rely
// on a poll every tailEvery (20 ms) when the machine is busy.
const authTailEvery = time.Second

// tailed returns once the tailer (Postgres) has seen the commit to ns made
// after ns's counter read gen. The commit moves the counter by 2 and the
// tailer, which sees this instance's commits too, by 2 more when it polls
// (tailer.go): whatever is cached in between is retired then. Tests that
// cache answers after a write wait for that first. The tailer must have
// seen ns's earlier commits, or one poll may count several.
func tailed(t testing.TB, e *Engine, ns string, gen uint64) {
	t.Helper()
	if e.rc.fresh != nil {
		within(t, 10*time.Second, "the tailer", func() bool { return e.rc.nsGen(ns).Load() >= gen+4 && e.fresh() })
	}
}

// authEngine opens an engine with authentication on, a namespace n whose
// read isn't public, and a clock the test moves. It returns a function
// minting grants of n's key, and n's configuration id.
func authEngine(t testing.TB, clock *atomic.Int64) (*Engine, func(root map[string]any) string, string) {
	t.Helper()
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	clock.Store(time.Now().UnixMilli())
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), OperatorKeys: ops, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: authTailEvery, Purger: discardPurger{}, Now: func() time.Time { return time.UnixMilli(clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mint := func(priv ed25519.PrivateKey, root map[string]any) string {
		t.Helper()
		if _, ok := root["exp"]; !ok {
			root["exp"] = time.UnixMilli(clock.Load()).Add(time.Hour).UTC().Format(time.RFC3339)
		}
		g, err := grant.Mint(root, priv)
		if err != nil {
			t.Fatal(err)
		}
		return g.Encode()
	}
	pub, priv := grant.GenerateKey()
	doc := map[string]any{"read": "grant", "keys": []any{
		map[string]any{"kid": "k", "alg": "ed25519", "pub": pub, "can": []any{"*"}},
	}}
	opG := mint(opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}})
	gen := e.rc.nsGen("n").Load()
	res, err := e.WriteConfig(context.Background(), Request{NS: "n", Cred: Credentials{Bearer: opG}}, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}})
	if err != nil {
		t.Fatal(err)
	}
	tailed(t, e, "n", gen)
	return e, func(root map[string]any) string { return mint(priv, root) }, res.ConfigID
}

// With authentication on, a namespace whose read isn't public has its
// revisions and head pointers cached too, but they are served only after
// the request's read check: a refused request gets the refusal it gets
// without the cache, and an allowed one exactly the uncached answer.
func TestReadCacheAuthenticated(t *testing.T) {
	var clock atomic.Int64
	e, mint, cfg := authEngine(t, &clock)
	ctx := context.Background()
	admin := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"n"}, "can": []any{"read", "create", "append", "config"}})}
	reader := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})}
	onlyB := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:b", "ns": []any{"n"}, "can": []any{"read"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}})}
	elsewhere := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"m"}, "can": []any{"read"}})}
	short := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:s", "ns": []any{"n"}, "can": []any{"read"},
		"exp": time.UnixMilli(clock.Load()).Add(time.Minute).UTC().Format(time.RFC3339)})}

	it := Item{Resource: "a", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"t": "x"}}}}}}
	gen := e.rc.nsGen("n").Load()
	res, err := e.WriteResource(ctx, Request{NS: "n", Cred: admin}, it)
	if err != nil {
		t.Fatal(err)
	}
	id := res.Items[0].IDs[0]
	tailed(t, e, "n", gen)

	cold, err := e.ResourceRev(ctx, "n", "a", id, reader)
	if err != nil || cold.Status != 200 || cold.Public {
		t.Fatalf("cold read: %+v %v", cold, err)
	}
	coldHead, err := e.ResourceHead(ctx, "n", "a", reader)
	if err != nil || coldHead.Head != id || coldHead.Public {
		t.Fatalf("cold head: %+v %v", coldHead, err)
	}
	// Cached, but not for transaction-free reads, which serve public
	// namespaces only.
	g := e.rc.load("n")
	if e.rc.revFor(g, "n", "a", id) == nil || e.rc.rev("n", "a", id) != nil {
		t.Fatal("the revision isn't cached for authenticated reads only")
	}
	if _, ok := e.rc.headFor(g, "n", "a"); !ok {
		t.Fatal("the head isn't cached")
	}
	if _, ok := e.rc.head("n", "a"); ok {
		t.Fatal("a private head is served without a transaction")
	}
	for _, c := range []Credentials{reader, short} {
		warm, err := e.ResourceRev(ctx, "n", "a", id, c)
		if err != nil || !reflect.DeepEqual(warm, cold) {
			t.Fatalf("warm read %+v %v, want %+v", warm, err, cold)
		}
		warmHead, err := e.ResourceHead(ctx, "n", "a", c)
		if err != nil || !reflect.DeepEqual(warmHead, coldHead) {
			t.Fatalf("warm head %+v %v, want %+v", warmHead, err, coldHead)
		}
	}

	// Mark the cached answers: what follows shows who is served from them.
	g = e.rc.load("n")
	e.rc.putRev(g, "n", "a", id, []byte(`"cached"`), false)
	h := *coldHead
	h.Head = "cached"
	e.rc.putHead(g, "n", "a", h, false)
	if r, err := e.ResourceRev(ctx, "n", "a", id, reader); err != nil || string(r.Doc) != `"cached"` {
		t.Fatalf("an allowed read isn't served from the cache: %+v %v", r, err)
	}
	if r, err := e.ResourceHead(ctx, "n", "a", reader); err != nil || r.Head != "cached" {
		t.Fatalf("an allowed head read isn't served from the cache: %+v %v", r, err)
	}
	// Refusals are as without the cache: 401 without a usable grant, 403
	// for one that doesn't name the namespace, 404 for one whose rules
	// don't reach the resource, exactly as for a resource that doesn't
	// exist.
	refused := []struct {
		cred Credentials
		code int
	}{
		{Credentials{}, 401},
		{Credentials{Bearer: "garbage"}, 401},
		{elsewhere, 403},
		{onlyB, 404},
	}
	for _, c := range refused {
		r, err := e.ResourceRev(ctx, "n", "a", id, c.cred)
		if status(err) != c.code || r != nil {
			t.Fatalf("%+v: rev %+v %v, want %d", c.cred, r, err, c.code)
		}
		hd, err := e.ResourceHead(ctx, "n", "a", c.cred)
		if status(err) != c.code || hd != nil {
			t.Fatalf("%+v: head %+v %v, want %d", c.cred, hd, err, c.code)
		}
		_, absent := e.ResourceRev(ctx, "n", "zz", id, c.cred)
		if !reflect.DeepEqual(err, absent) {
			t.Fatalf("%+v: %v, but %v for a resource that doesn't exist", c.cred, err, absent)
		}
	}
	// A grant that expires, cached or not, stops working.
	clock.Add(2 * time.Minute.Milliseconds())
	if _, err := e.ResourceRev(ctx, "n", "a", id, short); status(err) != 401 {
		t.Fatalf("an expired grant: %v", err)
	}
	// So does a revoked one.
	rid, err := grant.Decode(reader.Bearer, 0)
	if err != nil {
		t.Fatal(err)
	}
	g = e.rc.load("n")
	e.rc.putRev(g, "n", "a", id, []byte(`"cached"`), false)
	revoke := []any{map[string]any{"op": "add", "path": "/revoked", "value": []any{rid.RevocationIDs()[0]}}}
	if _, err := e.WriteConfig(ctx, Request{NS: "n", Cred: admin}, ConfigChange{Patches: revoke, IfMatch: cfg}); err != nil {
		t.Fatal(err)
	}
	if r, err := e.ResourceRev(ctx, "n", "a", id, reader); status(err) != 401 {
		t.Fatalf("a revoked grant: %+v %v", r, err)
	}
	// The configuration change retired the cached answer: the document
	// comes from the database again.
	if r, err := e.ResourceRev(ctx, "n", "a", id, admin); err != nil || !bytes.Equal(r.Doc, cold.Doc) {
		t.Fatalf("after a configuration change: %+v %v", r, err)
	}
}

// Only grants whose signature chain verified are kept by token: a
// well-formed grant signed by a key the namespace doesn't list, however
// large, is decoded on each request and holds nothing. The kept tokens are
// bounded by their total length as well as by their number.
func TestGrantCacheVerifiedOnly(t *testing.T) {
	var clock atomic.Int64
	e, mint, _ := authEngine(t, &clock)
	ctx := context.Background()
	admin := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"n"}, "can": []any{"read", "create", "append", "config"}})}
	it := Item{Resource: "a", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"t": "x"}}}}}}
	if _, err := e.WriteResource(ctx, Request{NS: "n", Cred: admin}, it); err != nil {
		t.Fatal(err)
	}
	cached := func() (int, int) {
		e.bearers.mu.Lock()
		defer e.bearers.mu.Unlock()
		return len(e.bearers.m), e.bearers.bytes
	}
	before, _ := cached()

	_, evil := grant.GenerateKey()
	empties := make([]any, 1900)
	for i := range empties {
		empties[i] = []any{}
	}
	for i := 0; i < 50; i++ {
		g, err := grant.Mint(map[string]any{"kid": "k", "sub": fmt.Sprintf("user:%d", i), "ns": []any{"n"}, "can": []any{"read"},
			"exp":   time.UnixMilli(clock.Load()).Add(time.Hour).UTC().Format(time.RFC3339),
			"rules": []any{map[string]any{"op": "test", "path": "/x", "value": empties}}}, evil)
		if err != nil {
			t.Fatal(err)
		}
		forged := Credentials{Bearer: g.Encode()}
		if _, err := e.ResourceHead(ctx, "n", "a", forged); status(err) != 401 {
			t.Fatalf("a forged grant: %v", err)
		}
		if _, err := e.ResourceRev(ctx, "n", "a", "zz", forged); status(err) != 401 {
			t.Fatalf("a forged grant: %v", err)
		}
	}
	elsewhere := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"m"}, "can": []any{"read"}})}
	if _, err := e.ResourceHead(ctx, "n", "a", elsewhere); status(err) != 403 {
		t.Fatalf("a grant for another namespace: %v", err)
	}
	if n, _ := cached(); n != before {
		t.Fatalf("%d grants kept after refused requests, want %d", n, before)
	}

	reader := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})}
	if _, err := e.ResourceHead(ctx, "n", "a", reader); err != nil {
		t.Fatal(err)
	}
	g := e.bearers.get(reader.Bearer)
	if g == nil || !g.ChainVerified() {
		t.Fatal("a verified grant isn't kept")
	}
	if _, err := e.ResourceHead(ctx, "n", "a", reader); err != nil {
		t.Fatal(err)
	}

	// The total token length stays within its bound.
	var c grantCache
	for i := 0; i < 20; i++ {
		c.put(fmt.Sprintf("%d%s", i, strings.Repeat("x", 200<<10)), g)
		if c.bytes > maxGrantCacheBytes || len(c.m) == 0 {
			t.Fatalf("%d tokens of %d bytes kept", len(c.m), c.bytes)
		}
	}
	unverified, err := grant.Decode(reader.Bearer, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.put(reader.Bearer, unverified)
	if c.get(reader.Bearer) != nil {
		t.Fatal("an unverified grant is kept")
	}
}
