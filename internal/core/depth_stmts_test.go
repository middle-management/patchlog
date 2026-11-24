package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// depthCounts are the statements of one request in the deepest branch of
// a chain of local branches: a head read of a resource read through from
// the root, a document create and a create of a document typed by a schema
// of the root.
type depthCounts struct {
	read, create, typed int
	byQuery             map[string]map[string]int
}

// depthPath is a path a resource write takes to its commit: the default
// one, and on Postgres the two a contended namespace's writes take.
type depthPath struct {
	name string
	// optimistic checks outside the lock and re-checks inside it (D.3), as
	// SQLite always does; grouped queues every write for a group commit.
	optimistic, grouped bool
}

// countDepth builds a chain of depth local branches on an engine of its
// own, with authentication on (keys and revocations follow the bases,
// §C.4) and no background loop that runs transactions, and counts the
// statements of each request once the engine's caches are warm. Lock
// statements count too (Postgres).
func countDepth(t *testing.T, depth int, path depthPath) depthCounts {
	t.Helper()
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	opt := Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), OperatorKeys: ops, Limits: lim, Purger: discardPurger{},
		RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1}
	if path.optimistic {
		opt.LockedCheckBytes = -1
	}
	e, err := Open(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	e.noSolo = path.grouped
	pub, priv := grant.GenerateKey()
	mint := func(priv ed25519.PrivateKey, root map[string]any) string {
		t.Helper()
		root["exp"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		g, err := grant.Mint(root, priv)
		if err != nil {
			t.Fatal(err)
		}
		return g.Encode()
	}
	doc := map[string]any{"read": "grant", "keys": []any{map[string]any{"kid": "k", "alg": "ed25519", "pub": pub, "can": []any{"*"}}}}
	opG := mint(opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}})
	if _, err := e.WriteConfig(context.Background(), Request{NS: "n", Cred: Credentials{Bearer: opG}},
		ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	names := []any{"n"}
	for i := 1; i <= depth; i++ {
		names = append(names, fmt.Sprintf("d%d", i))
	}
	cred := Credentials{Bearer: mint(priv, map[string]any{"kid": "k", "sub": "user:w", "ns": names, "can": []any{"read", "create", "append", "branch"}})}
	req := func(ns string) Request { return Request{NS: ns, Cred: cred} }
	put := func(ns, name string, doc any) string {
		t.Helper()
		res, err := e.WriteResource(ctx, req(ns), createItem(name, doc))
		if err != nil {
			t.Fatalf("create %s/%s: %v", ns, name, err)
		}
		return res.Items[0].IDs[0]
	}
	schemaID := put("n", "s", kSchema(1))
	for _, name := range []string{"r0", "r1"} {
		put("n", name, map[string]any{"k": 1.0})
	}
	for i := 1; i <= depth; i++ {
		if _, err := e.CreateBranch(ctx, req(names[i-1].(string)), BranchRequest{Name: names[i].(string), IfNoneMatch: true}); err != nil {
			t.Fatalf("branch %v: %v", names[i], err)
		}
	}
	deep := names[depth].(string)
	schemaPath := "/r/n/s/rev/" + schemaID

	var mu sync.Mutex
	var cur map[string]int
	e.onStatement = func(q string, _ []any) {
		mu.Lock()
		defer mu.Unlock()
		if cur != nil {
			cur[strings.Join(strings.Fields(q), " ")]++
		}
	}
	out := depthCounts{byQuery: map[string]map[string]int{}}
	count := func(what string, f func()) int {
		t.Helper()
		mu.Lock()
		cur = map[string]int{}
		mu.Unlock()
		f()
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, c := range cur {
			n += c
		}
		out.byQuery[what], cur = cur, nil
		return n
	}
	read := func(name string) {
		t.Helper()
		if h, err := e.ResourceHead(ctx, deep, name, cred); err != nil || h == nil {
			t.Fatalf("head of %s/%s: %v", deep, name, err)
		}
	}
	// Once unmeasured, so that what the engine keeps across requests
	// (parsed namespace documents, ids by name, prepared statements) is
	// there, as it is for all but a deployment's first requests.
	read("r0")
	put(deep, "w0", map[string]any{"k": 1.0})
	put(deep, "t0", typedDoc(schemaPath, 1))

	out.read = count("read", func() { read("r1") })
	out.create = count("create", func() { put(deep, "w1", map[string]any{"k": 1.0}) })
	out.typed = count("typed create", func() { put(deep, "t1", typedDoc(schemaPath, 1)) })
	return out
}

// A request in a branch of a branch of … costs as many statements at depth
// 8 as at depth 1: the chain of bases is read once per transaction, in one
// statement (and locked in one, on Postgres), whatever its length, and so
// is a name read through it (chain.go). On Postgres that holds on each
// path a write takes: checked inside its locks, checked outside and
// re-checked inside, and in a group commit.
func TestBranchDepthStatements(t *testing.T) {
	if pgtest.Spanner() {
		t.Skip("Spanner has no recursive queries: a chain is read a statement per level")
	}
	t.Parallel()
	paths := []depthPath{{name: "default"}}
	if pgtest.Enabled() {
		paths = append(paths, depthPath{name: "optimistic", optimistic: true}, depthPath{name: "grouped", grouped: true})
	}
	depths := []int{1, 4, 8}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			t.Parallel()
			got := map[int]depthCounts{}
			for _, d := range depths {
				got[d] = countDepth(t, d, path)
				t.Logf("depth %d: read %d, create %d, typed create %d statements", d, got[d].read, got[d].create, got[d].typed)
			}
			one := got[1]
			for _, d := range depths[1:] {
				g := got[d]
				if g.read > one.read || g.create > one.create || g.typed > one.typed {
					t.Errorf("depth %d: read %d, create %d, typed create %d statements; depth 1: %d, %d, %d",
						d, g.read, g.create, g.typed, one.read, one.create, one.typed)
				}
			}
			if !t.Failed() && !testing.Verbose() {
				return
			}
			// The statements that differ between depths 1 and 8.
			for _, what := range []string{"read", "create", "typed create"} {
				var qs []string
				for q := range got[8].byQuery[what] {
					qs = append(qs, q)
				}
				sort.Strings(qs)
				for _, q := range qs {
					if a, b := got[1].byQuery[what][q], got[8].byQuery[what][q]; a != b {
						t.Logf("%s: %d at depth 1, %d at depth 8: %.150s", what, a, b, q)
					}
				}
			}
		})
	}
}
