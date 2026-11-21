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

// checkCounts are the round trips of a resource write's check outside
// the lock (checkOutside, D.3) and of a revision read (resourceRev), once
// the engine's caches are warm: the statements, and on Postgres a read
// transaction's begin and rollback, two more (onReadTx). In SQLite none is
// a round trip, but the statements count alike.
type checkCounts struct {
	appendIfMatch, create, retry, revHead, revOld counted
	byQuery                                       map[string]map[string]int
}

type counted struct{ stmts, txs int }

// trips is the round trips on Postgres.
func (c counted) trips() int { return c.stmts + 2*c.txs }

func (c counted) String() string {
	return fmt.Sprintf("%d (%d statements, %d transactions)", c.trips(), c.stmts, c.txs)
}

// countCheck counts on an engine of its own, with authentication on and
// the rate-limit buckets in the engine (as with --local-rate-buckets); tx
// makes every read run in a transaction (noLone).
func countCheck(t *testing.T, tx bool) checkCounts {
	t.Helper()
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), OperatorKeys: ops, Limits: lim, Purger: discardPurger{},
		RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1, LocalRateBuckets: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	e.noLone = tx
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
	ctx := context.Background()
	if _, err := e.WriteConfig(ctx, Request{NS: "n", Cred: Credentials{Bearer: opG}},
		ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
		t.Fatal(err)
	}
	cred := Credentials{Bearer: mint(priv, map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"read", "create", "append"}})}
	req := Request{NS: "n", Cred: cred}
	appendItem := func(name, head string, k int) Item {
		return Item{Resource: name, IfMatch: head, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/k", "value": float64(k)}}}}}
	}
	write := func(it Item) string {
		t.Helper()
		res, err := e.WriteResource(ctx, req, it)
		if err != nil {
			t.Fatalf("write %s: %v", it.Resource, err)
		}
		return res.Items[0].IDs[0]
	}
	check := func(it Item) *WriteResult {
		t.Helper()
		plan, _, res, err := e.checkOutside(ctx, req, []Item{it}, nil, false, false)
		if err != nil || (plan == nil) == (res == nil) {
			t.Fatalf("check of %s: plan %v, result %v, %v", it.Resource, plan != nil, res, err)
		}
		return res
	}
	rev := func(name, id string) {
		t.Helper()
		r, err := e.ResourceRev(ctx, "n", name, id, cred)
		if err != nil || r.Status != 200 {
			t.Fatalf("rev %s/%s: %+v, %v", name, id, r, err)
		}
	}

	first := write(createItem("r", map[string]any{"k": 0.0}))
	head := write(appendItem("r", first, 1))
	// Once unmeasured, so that what the engine keeps across requests
	// (parsed namespace documents, ids by name, verified grants) is there.
	check(appendItem("r", head, 2))
	check(createItem("c0", map[string]any{"k": 0.0}))
	rev("r", first)

	// The warm-up's first reads, before the namespace's document was
	// cached, needed a transaction: the namespace backs off (readOne).
	e.lone.m.Delete("n")

	var mu sync.Mutex
	var cur map[string]int
	var txs int
	e.onStatement = func(q string, _ []any) {
		mu.Lock()
		defer mu.Unlock()
		if cur != nil {
			cur[strings.Join(strings.Fields(q), " ")]++
		}
	}
	e.onReadTx = func() {
		mu.Lock()
		defer mu.Unlock()
		txs++
	}
	out := checkCounts{byQuery: map[string]map[string]int{}}
	count := func(what string, f func()) counted {
		t.Helper()
		mu.Lock()
		cur, txs = map[string]int{}, 0
		mu.Unlock()
		f()
		mu.Lock()
		defer mu.Unlock()
		c := counted{txs: txs}
		for _, n := range cur {
			c.stmts += n
		}
		out.byQuery[what], cur = cur, nil
		return c
	}
	out.appendIfMatch = count("append", func() { check(appendItem("r", head, 3)) })
	out.create = count("create", func() { check(createItem("c1", map[string]any{"k": 0.0})) })
	// The same append again once written: an idempotent retry, answered
	// by the check.
	again := appendItem("r", head, 4)
	newHead := write(again)
	out.retry = count("retry", func() {
		if res := check(again); res == nil || !res.Replayed {
			t.Fatalf("retry not replayed: %+v", res)
		}
	})
	e.lone.m.Delete("n") // the retry needed a transaction
	h3 := write(appendItem("r", newHead, 5))
	// Revisions not read before, so not in the read cache: the head, and
	// one below it.
	out.revHead = count("rev head", func() { rev("r", h3) })
	out.revOld = count("rev old", func() { rev("r", head) })
	return out
}

// TestCheckStatements bounds the round trips of a write's check outside
// the lock and of a revision read: on Postgres each statement is one, and
// a read transaction two more. Before lookupResource and readOne an
// append's check took six (begin, the namespace, the resource, its head,
// the retry lookup, rollback), a create's four, a revision read five or,
// below the head, seven. Now each takes one statement, which on Postgres
// runs without a transaction. An idempotent retry still takes a few more:
// rare, it runs again in a transaction.
func TestCheckStatements(t *testing.T) {
	t.Parallel()
	for _, tx := range []bool{false, true} {
		t.Run(fmt.Sprintf("tx=%v", tx), func(t *testing.T) {
			t.Parallel()
			got := countCheck(t, tx)
			t.Logf("check: append %v, create %v, retry %v; rev: head %v, older %v",
				got.appendIfMatch, got.create, got.retry, got.revHead, got.revOld)
			for what, c := range map[string]counted{"append": got.appendIfMatch, "create": got.create, "rev head": got.revHead, "rev old": got.revOld} {
				want := counted{1, 0}
				if tx || !pgtest.Enabled() {
					want.txs = 1
				}
				// A document the engine's cache no longer holds is folded
				// from its stored rows (docBytesAt), and the read then
				// runs again in a transaction: not what is counted here,
				// but the cache keeps no promise (slow runs, -race).
				if folds := docStmts(got.byQuery[what]); folds > 0 {
					t.Logf("%s: %d statements folding its document, not counted", what, folds)
					c.stmts -= folds
					if !tx && pgtest.Enabled() {
						c.stmts-- // the first, abandoned, statement
						want.txs = 1
					}
				}
				if c != want {
					t.Errorf("%s: %v, want %v", what, c, want)
				}
			}
			if !t.Failed() && !testing.Verbose() {
				return
			}
			var whats []string
			for w := range got.byQuery {
				whats = append(whats, w)
			}
			sort.Strings(whats)
			for _, w := range whats {
				var qs []string
				for q, c := range got.byQuery[w] {
					qs = append(qs, fmt.Sprintf("%d× %.160s", c, q))
				}
				sort.Strings(qs)
				t.Logf("%s:\n  %s", w, strings.Join(qs, "\n  "))
			}
		})
	}
}

// docStmts counts the statements that fold a document from its stored
// rows (docBytesAt): its base from heads or snapshots, the revisions on
// top of it.
func docStmts(qs map[string]int) int {
	n := 0
	for q, c := range qs {
		if strings.HasPrefix(q, "SELECT res, doc FROM heads WHERE") || strings.HasPrefix(q, "SELECT res, doc FROM snapshots WHERE") ||
			strings.HasPrefix(q, "SELECT "+revCols+" FROM revisions WHERE seq = ?") {
			n += c
		}
	}
	return n
}
