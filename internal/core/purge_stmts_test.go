package core

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// purgeCounts are the statements of one purge of a document of a base with
// branches of one kind, by statement.
type purgeCounts struct {
	total   int
	byQuery map[string]int
}

// The kinds of branch a purge in their base meets (§8.3).
const (
	branchUnseeing = "created before the document"
	branchThrough  = "reading it through"
	branchOwn      = "with their own revision"
)

// countPurge builds a base with a document x and branches branches of one
// kind, on an engine of its own, and counts the statements of the purge of
// x in the base. Lock statements count too (Postgres).
func countPurge(t *testing.T, kind string, branches int) purgeCounts {
	t.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	lim.BranchesPerNamespace = 1 << 20
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, Limits: lim, Purger: discardPurger{},
		RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	create := func(ns, name string) string {
		t.Helper()
		id, err := put(e, ns, name, "", 1)
		if err != nil {
			t.Fatalf("create %s/%s: %v", ns, name, err)
		}
		return id
	}
	// Another document, purged first and unmeasured, so that what the
	// engine keeps across requests is there.
	warm := create("n", "warm")
	var head string
	if kind != branchUnseeing {
		head = create("n", "x")
	}
	for i := 0; i < branches; i++ {
		b := fmt.Sprintf("b%d", i)
		r := who
		r.NS = "n"
		if _, err := e.CreateBranch(ctx, r, BranchRequest{Name: b, IfNoneMatch: true}); err != nil {
			t.Fatalf("branch %s: %v", b, err)
		}
		if kind == branchOwn {
			if _, err := put(e, b, "x", head, 2); err != nil {
				t.Fatalf("write %s/x: %v", b, err)
			}
		}
	}
	if kind == branchUnseeing {
		head = create("n", "x")
	}
	r := who
	r.NS = "n"
	if _, err := e.Purge(ctx, r, "warm", warm, false); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	out := purgeCounts{byQuery: map[string]int{}}
	e.onStatement = func(q string, _ []any) {
		mu.Lock()
		defer mu.Unlock()
		out.total++
		out.byQuery[strings.Join(strings.Fields(q), " ")]++
	}
	_, err = e.Purge(ctx, r, "x", head, false)
	e.onStatement = nil
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	// What the purge must have done in each branch (§8.3).
	for i := 0; i < branches; i++ {
		b := fmt.Sprintf("b%d", i)
		h, err := e.ResourceHead(ctx, b, "x", who.Cred)
		if err != nil {
			t.Fatal(err)
		}
		want := Purged
		if kind == branchUnseeing {
			want = NotFound
		}
		if h.State != want {
			t.Fatalf("%s/x after the purge: state %v, want %v", b, h.State, want)
		}
	}
	return out
}

// A purge of a document costs no more statements with many branches that
// neither hold nor see it than with few (§8.3: such a branch is skipped,
// and purgePlan finds the others by name), and a few for each branch it
// does reach: none on Postgres, where a statement is a round trip and the
// branches' rows and entries go in a statement each; in SQLite the
// branch's log head, its entry and its head's update, and the purged row
// of a branch that read the name through. The purge asks for the branches
// level by level, so its statements grow with the depth of the tree below
// it, not with its width. Before the purge found its branches by name it
// spent, per branch of each kind, 8, 17 and 25 statements in SQLite and
// 11, 19 and 27 on Postgres, log locks included.
func TestPurgeStatements(t *testing.T) {
	if pgtest.Spanner() {
		t.Skip("statement counts of Postgres's holder search; Spanner searches level by level")
	}
	t.Parallel()
	few, many := 3, 23
	limit := map[string]int{branchUnseeing: 0, branchThrough: 4, branchOwn: 3}
	if pgtest.Enabled() {
		limit = map[string]int{branchUnseeing: 0, branchThrough: 0, branchOwn: 0}
	}
	for _, kind := range []string{branchUnseeing, branchThrough, branchOwn} {
		a, b := countPurge(t, kind, few), countPurge(t, kind, many)
		t.Logf("branches %s: %d statements with %d, %d with %d: %.1f per branch", kind, a.total, few, b.total, many, float64(b.total-a.total)/float64(many-few))
		if b.total-a.total > limit[kind]*(many-few) {
			t.Errorf("branches %s: %d statements with %d, %d with %d; want at most %d more per branch", kind, a.total, few, b.total, many, limit[kind])
		}
		if !t.Failed() && !testing.Verbose() {
			continue
		}
		var qs []string
		for q := range b.byQuery {
			qs = append(qs, q)
		}
		sort.Strings(qs)
		for _, q := range qs {
			if a.byQuery[q] != b.byQuery[q] {
				t.Logf("  %d with %d, %d with %d: %.130s", a.byQuery[q], few, b.byQuery[q], many, q)
			}
		}
	}
}

// A purge appends its entries branches first, siblings by name, whatever
// order the branches were made in and whether the purge visits a namespace
// between them or not (§8.3, purgePlan).
func TestPurgeOrder(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	branch := func(base, name string) {
		t.Helper()
		r := who
		r.NS = base
		if _, err := e.CreateBranch(ctx, r, BranchRequest{Name: name, IfNoneMatch: true}); err != nil {
			t.Fatalf("branch %s: %v", name, err)
		}
	}
	create := func(ns string) string {
		t.Helper()
		id, err := put(e, ns, "x", "", 1)
		if err != nil {
			t.Fatalf("create %s/x: %v", ns, err)
		}
		return id
	}
	// old and its branches are made before n's x: old sees none and is
	// skipped, its branches have their own.
	branch("n", "old")
	branch("old", "oldz")
	branch("old", "olda")
	create("oldz")
	create("olda")
	head := create("n")
	branch("n", "bb")
	branch("bb", "bb2")
	branch("bb", "bb1")
	branch("n", "ba")
	r := who
	r.NS = "n"
	if _, err := e.Purge(ctx, r, "x", head, false); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := e.read(ctx, func(t *tx) error {
		// Across namespaces Spanner's seqs are ordered by their time bits
		// (spWriteOrder).
		order := `l.seq`
		if t.e.spanner {
			order = fmt.Sprintf(`mod(l.seq, %d), l.seq`, spOrderMod)
		}
		rows, err := t.Query(`SELECT n.name FROM ns_log l JOIN namespaces n ON n.ns = l.ns WHERE l.kind = ? ORDER BY `+order, nsKindCode("purge"))
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var s string
			t.must(rows.Scan(&s))
			got = append(got, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if want := "ba bb1 bb2 bb olda oldz n"; strings.Join(got, " ") != want {
		t.Fatalf("purge entries in the order %v, want %s", got, want)
	}
	// Every log is still a chain, however its purge entry was appended
	// (on Postgres, with the other branches' in one statement): each
	// entry's id covers the one before it (§3.5), and the namespace's head
	// is its last.
	if err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT l.ns, l.seq, l.id, l.prev_seq, l.body, n.head_seq, n.head_id FROM ns_log l JOIN namespaces n ON n.ns = l.ns ORDER BY l.ns, l.seq`)
		t.must(err)
		defer rows.Close()
		var ns, lastSeq int64
		var last *ids.ID
		var headOK bool
		check := func() {
			if ns != 0 && !headOK {
				panic(fmt.Sprintf("namespace %d: its head isn't its log's last entry %d", ns, lastSeq))
			}
		}
		for rows.Next() {
			var n, seq int64
			var prev, headSeq sql.NullInt64
			var id, headID []byte
			var body string
			t.must(rows.Scan(&n, &seq, &id, &prev, &body, &headSeq, &headID))
			if n != ns {
				check()
				ns, last, lastSeq = n, nil, 0
			}
			if prev.Int64 != lastSeq || ids.Hash(last, []byte(body)) != ids.FromBytes(id) {
				panic(fmt.Sprintf("namespace %d: entry %d doesn't chain on %d", n, seq, lastSeq))
			}
			cur := ids.FromBytes(id)
			last, lastSeq = &cur, seq
			headOK = headSeq.Int64 == seq && bytes.Equal(headID, id)
		}
		check()
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
}
