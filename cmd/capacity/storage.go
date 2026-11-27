package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/client"
)

// The storage phase measures what each write leaves in the database once
// its patch set is pruned (§8.6): -storage-writes single-resource writes
// spread over -storage-resources resources of one namespace, all under one
// grant, then (once the retry window has passed, -storage-wait) a prune of
// every resource to its head, so every revision but
// the heads keeps only its skeleton (patches NULL). It reads the core's
// database itself (-storage-db, the core's --db), before the writes and
// after the prunes, and reports the difference per write for each table
// and index:
//
//   - SQLite: the database is copied with VACUUM INTO (so free pages left
//     by the prunes don't count) and each object's pages are summed from
//     the dbstat virtual table.
//   - Postgres: after VACUUM FULL ANALYZE, pg_relation_size of each table
//     (main fork), its TOAST table and each index.
//
// It is meant for a new, empty database per run, the core started with
// an --operator-key whose seed is -operator-seed (the grants profile), so
// that the entries carry a grant as most deployments' do.

// storageNS is the phase's namespace.
const storageNS = "cap-storage"

func (r *runner) storage() {
	if r.c.storageDB == "" {
		fail(fmt.Errorf("storage phase: set --storage-db to the core's --db"))
	}
	n, R := r.c.storageWrites, r.c.storageResources
	if R <= 0 || n < R {
		fail(fmt.Errorf("storage phase: --storage-writes must be at least --storage-resources (>0)"))
	}
	// The namespace: in the grants profile its key may do everything, so
	// a grant chained to it may prune where no archive is configured.
	c := r.pubs[r.urls[0]]
	doc := r.nsDoc()
	if r.op != nil {
		c = r.newClient(r.urls[0], r.mint(r.op, map[string]any{"kid": "operator", "sub": "op:capacity", "ns": []any{storageNS}, "can": []any{"config"}}))
		doc["keys"] = []any{map[string]any{"kid": keyKid, "alg": "ed25519", "pub": r.keyPub, "can": []any{"*"}}}
	}
	must(c.CreateNamespace(r.ctx, storageNS, doc))
	// One grant for every write and prune.
	w := r.pubs[r.urls[0]]
	if r.op != nil {
		w = r.newClient(r.urls[0], r.mint(r.key, map[string]any{"kid": keyKid, "sub": loaderSub, "ns": []any{storageNS},
			"can": []any{"read", "create", "append", "prune"}}))
	}
	before := r.storageSizes()

	names := make([]string, R)
	heads := make([]string, R)
	for i := range names {
		names[i] = fmt.Sprintf("s%05d", i)
	}
	t0 := time.Now()
	var done atomic.Int64
	workers := min(r.c.workers, R)
	var wg sync.WaitGroup
	for k := 0; k < workers; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each document names its resource, so no two resources' chains share
			// revision ids (they are per resource, §3.3) as identical documents
			// and patches would make them.
			// Worker k writes the resources i ≡ k (mod workers) in turn, so
			// no two writers race for one resource.
			count := n / R
			// The first n % R resources get one write more.
			for round := 0; ; round++ {
				wrote := false
				for i := k; i < R; i += workers {
					want := count
					if i < n%R {
						want++
					}
					if round >= want {
						continue
					}
					wrote = true
					var res *client.WriteResult
					var err error
					if round == 0 {
						res, err = retry(func() (*client.WriteResult, error) {
							return w.CreateDoc(r.ctx, storageNS, names[i], map[string]any{"name": names[i], "n": 0})
						})
					} else {
						h := heads[i]
						res, err = retry(func() (*client.WriteResult, error) {
							return w.Append(r.ctx, storageNS, names[i], h, []any{map[string]any{"op": "replace", "path": "/n", "value": round}})
						})
					}
					if err != nil {
						fail(fmt.Errorf("storage phase: writing %s: %w", names[i], err))
					}
					heads[i] = res.ID
					if d := done.Add(1); d%100_000 == 0 {
						r.logf("storage: %d writes (%.0f/s)", d, float64(d)/time.Since(t0).Seconds())
					}
				}
				if !wrote {
					return
				}
			}
		}()
	}
	wg.Wait()
	wrote := time.Since(t0)
	// A prune keeps what was written within the retry window (§8.6, at
	// least 5 minutes), so it waits that long after the last write.
	if r.c.storageWait > 0 {
		r.logf("storage: waiting %s for the retry window to pass", r.c.storageWait)
		time.Sleep(r.c.storageWait)
	}
	t1 := time.Now()
	for i, name := range names {
		if _, err := retry(func() (*client.PruneResult, error) {
			return w.Prune(r.ctx, storageNS, name, client.PruneRequest{Horizon: heads[i]})
		}); err != nil {
			fail(fmt.Errorf("storage phase: pruning %s: %w", name, err))
		}
	}
	pruned := time.Since(t1)
	after := r.storageSizes()

	objs := map[string]any{}
	tables := map[string]float64{}
	total := 0.0
	for name, a := range after.bytes {
		d := a - before.bytes[name]
		if d == 0 {
			continue
		}
		per := float64(d) / float64(n)
		objs[name] = map[string]any{"kind": after.kind[name], "table": after.table[name], "bytes": d, "bytes_per_write": round1(per)}
		tables[after.table[name]] += per
		total += per
	}
	for t, v := range tables {
		tables[t] = round1(v)
	}
	r.record("storage", map[string]any{
		"store":             after.store,
		"writes":            n,
		"resources":         R,
		"write_seconds":     wrote.Seconds(),
		"writes_per_second": float64(n) / wrote.Seconds(),
		"prune_seconds":     pruned.Seconds(),
		"bytes_per_write":   round1(total),
		"tables_per_write":  tables,
		"objects":           objs,
		"rows":              after.rows,
		"method":            after.method,
	})
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// sizes are a database's bytes by object (table, its TOAST table or
// index), and for each the table it belongs to.
type sizes struct {
	store, method string
	bytes         map[string]int64
	kind, table   map[string]string
	rows          map[string]int64
}

func (r *runner) storageSizes() sizes {
	if strings.HasPrefix(r.c.storageDB, "postgres") {
		return r.pgSizes()
	}
	return r.sqliteSizes()
}

// counted are the row counts reported with the sizes.
var counted = []string{"ns_log", "revisions", "head_history", "resources", "grants", "ns_config"}

func countRows(db *sql.DB, out map[string]int64) {
	for _, t := range counted {
		var c int64
		if db.QueryRow("SELECT COUNT(*) FROM "+t).Scan(&c) == nil {
			out[t] = c
		}
	}
	var c int64
	if db.QueryRow("SELECT COUNT(*) FROM revisions WHERE patches IS NULL").Scan(&c) == nil {
		out["revisions_patches_null"] = c
	}
}

func (r *runner) sqliteSizes() sizes {
	dir, err := os.MkdirTemp("", "capacity-storage")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(dir)
	src, err := sql.Open("sqlite", "file:"+r.c.storageDB+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		fail(err)
	}
	defer src.Close()
	cp := filepath.Join(dir, "copy.db")
	if _, err := src.Exec("VACUUM INTO ?", cp); err != nil {
		fail(fmt.Errorf("storage phase: VACUUM INTO: %w", err))
	}
	db, err := sql.Open("sqlite", "file:"+cp)
	if err != nil {
		fail(err)
	}
	defer db.Close()
	s := sizes{store: "sqlite", method: "VACUUM INTO a copy, then SUM(pgsize) FROM dbstat by object",
		bytes: map[string]int64{}, kind: map[string]string{}, table: map[string]string{}, rows: map[string]int64{}}
	rows, err := db.Query(`SELECT d.name, COALESCE(m.type, 'table'), COALESCE(m.tbl_name, d.name), SUM(d.pgsize)
		FROM dbstat d LEFT JOIN sqlite_master m ON m.name = d.name GROUP BY d.name`)
	if err != nil {
		fail(fmt.Errorf("storage phase: dbstat: %w", err))
	}
	defer rows.Close()
	for rows.Next() {
		var name, kind, table string
		var b int64
		if err := rows.Scan(&name, &kind, &table, &b); err != nil {
			fail(err)
		}
		if strings.HasPrefix(name, "sqlite_autoindex_") {
			kind = "index"
		}
		s.bytes[name], s.kind[name], s.table[name] = b, kind, table
	}
	countRows(db, s.rows)
	return s
}

func (r *runner) pgSizes() sizes {
	db, err := sql.Open("pgx", r.c.storageDB)
	if err != nil {
		fail(err)
	}
	defer db.Close()
	if _, err := db.Exec("VACUUM FULL ANALYZE"); err != nil {
		fail(fmt.Errorf("storage phase: VACUUM FULL: %w", err))
	}
	s := sizes{store: "postgres", method: "VACUUM FULL ANALYZE, then pg_relation_size of each table (main fork), its TOAST table and each index",
		bytes: map[string]int64{}, kind: map[string]string{}, table: map[string]string{}, rows: map[string]int64{}}
	rows, err := db.Query(`
		SELECT c.relname, 'table', c.relname, pg_relation_size(c.oid) FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relkind = 'r'
		UNION ALL
		SELECT c.relname || ' (toast)', 'toast', c.relname, pg_total_relation_size(c.reltoastrelid) FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.reltoastrelid <> 0
		UNION ALL
		SELECT i.relname, 'index', t.relname, pg_relation_size(i.oid) FROM pg_index x
		  JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class t ON t.oid = x.indrelid
		  JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = current_schema()`)
	if err != nil {
		fail(fmt.Errorf("storage phase: sizes: %w", err))
	}
	defer rows.Close()
	for rows.Next() {
		var name, kind, table string
		var b int64
		if err := rows.Scan(&name, &kind, &table, &b); err != nil {
			fail(err)
		}
		s.bytes[name], s.kind[name], s.table[name] = b, kind, table
	}
	countRows(db, s.rows)
	return s
}
