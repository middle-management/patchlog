package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
)

// The cliff phase measures how single-resource write latency follows the
// size of the indexes a write inserts into at a random place (those keyed
// by a hash id: ns_log (ns, id), revisions (res, id) and revisions (id)),
// against the memory the database has (docs/capacity/storage/README.md,
// "The memory cliff"). It runs in three steps, each its own invocation
// (--cliff-step), so the core can be stopped while the database is loaded
// and the database restarted cold before the paced load:
//
//   - setup: through the API, creates the namespace cap-cliff and
//     --cliff-resources resources in it, a create and an append each, under
//     one grant.
//   - preload: with the core stopped, inserts --cliff-writes more writes
//     straight into the database (--cliff-db): for each, the rows a
//     single-resource append leaves once pruned (a revisions row with its
//     patches NULL, its ns_log entry, its head_history row), round-robin
//     over the resources, each revision's parent the resource's previous
//     one and each entry's the namespace's previous one, as the API writes
//     them; the other columns are copied from the last rows the setup
//     wrote. Ids are the first 20 bytes of sha256(k, table): as random as
//     hashes, and the same in every run of a size, so the indexes of a run
//     before a schema change and one after hold the same keys. The
//     resources' and the namespace's heads and the identity sequences are
//     then moved past the loaded rows.
//   - paced: through the API, --cliff-rate appends a second for
//     --cliff-seconds, open loop (each starts at its scheduled time,
//     whatever the ones before took, and its latency counts from then), each
//     to a resource picked at random among those with no write in flight.
//     It reports the latency in all, after the first 30 seconds and per
//     10-second bucket, the size of
//     every index of the tables a write touches, and the reads the database
//     did during the load: on Postgres pg_statio_user_indexes / _tables
//     (blocks read, i.e. missed in shared_buffers, against hit), pg_stat_io
//     (reads and their time, which tells the OS page cache from the disk)
//     and the WAL written; on both, the host's block-device reads
//     (/proc/diskstats, --cliff-disk) and, with --cliff-cgroup, the page
//     cache and RSS of the database's container; each in all and for the
//     writes after the first 30 seconds (io_per_write_after_30s).

const cliffNS = "cap-cliff"

func (r *runner) cliffWriter() *client.Client {
	w := r.pubs[r.urls[0]]
	if r.op != nil {
		w = r.newClient(r.urls[0], r.mint(r.key, map[string]any{"kid": keyKid, "sub": loaderSub, "ns": []any{cliffNS},
			"can": []any{"read", "create", "append"}}))
	}
	return w
}

func cliffName(i int) string { return fmt.Sprintf("c%05d", i) }

func (r *runner) cliff() {
	switch r.c.cliffStep {
	case "setup":
		r.cliffSetup()
	case "preload":
		r.cliffPreload()
	case "paced":
		r.cliffPaced()
	default:
		fail(fmt.Errorf("cliff phase: --cliff-step must be setup, preload or paced"))
	}
}

func (r *runner) cliffSetup() {
	c := r.pubs[r.urls[0]]
	doc := r.nsDoc()
	if r.op != nil {
		c = r.newClient(r.urls[0], r.mint(r.op, map[string]any{"kid": "operator", "sub": "op:capacity", "ns": []any{cliffNS}, "can": []any{"config"}}))
		doc["keys"] = []any{map[string]any{"kid": keyKid, "alg": "ed25519", "pub": r.keyPub, "can": []any{"*"}}}
	}
	must(c.CreateNamespace(r.ctx, cliffNS, doc))
	w := r.cliffWriter()
	R := r.c.cliffResources
	jobs := make(chan int)
	var wg sync.WaitGroup
	for k := 0; k < r.c.workers; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				name := cliffName(i)
				res, err := retry(func() (*client.WriteResult, error) {
					return w.CreateDoc(r.ctx, cliffNS, name, map[string]any{"name": name, "n": 0})
				})
				if err != nil {
					fail(fmt.Errorf("cliff setup: creating %s: %w", name, err))
				}
				// An append, so the resource has a heads row (a genesis is its
				// own snapshot) and the template rows are an append's.
				if _, err := retry(func() (*client.WriteResult, error) {
					return w.Append(r.ctx, cliffNS, name, res.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 1}})
				}); err != nil {
					fail(fmt.Errorf("cliff setup: appending to %s: %w", name, err))
				}
			}
		}()
	}
	for i := 0; i < R; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	r.record("cliff_setup", map[string]any{"resources": R})
}

// cliffID is the id the preload gives write k's row of a table (1: ns_log,
// 2: revisions, 3: the revision's digest), as the Postgres preload's
// substr(sha256(int8send(k) || table), 1, n) does.
func cliffID(k int64, table byte, n int) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[:], uint64(k))
	b[8] = table
	s := sha256.Sum256(b[:])
	return s[:n]
}

func (r *runner) cliffPG() bool { return strings.HasPrefix(r.c.cliffDB, "postgres") }

func (r *runner) cliffOpen() *sql.DB {
	if r.c.cliffDB == "" {
		fail(fmt.Errorf("cliff phase: set --cliff-db to the core's --db"))
	}
	if r.cliffPG() {
		return must(sql.Open("pgx", r.c.cliffDB))
	}
	return must(sql.Open("sqlite", "file:"+r.c.cliffDB+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"))
}

// q rewrites ? placeholders as $n on Postgres.
func (r *runner) q(s string) string {
	if !r.cliffPG() {
		return s
	}
	var b strings.Builder
	n := 0
	for _, c := range s {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// cliffState is what the preload builds on: the namespace, its resources
// (res and head seq, by res) and the template rows (the last the setup
// wrote).
type cliffState struct {
	ns, nsHead, revTmpl int64
	res, heads          []int64
	revBase, logBase    int64
}

func (r *runner) cliffState(db *sql.Conn) cliffState {
	var s cliffState
	must(0, db.QueryRowContext(r.ctx, r.q(`SELECT ns, head_seq FROM namespaces WHERE name = ?`), cliffNS).Scan(&s.ns, &s.nsHead))
	rows := must(db.QueryContext(r.ctx, r.q(`SELECT res, head_seq FROM resources WHERE ns = ? ORDER BY res`), s.ns))
	for rows.Next() {
		var a, b int64
		must(0, rows.Scan(&a, &b))
		s.res, s.heads = append(s.res, a), append(s.heads, b)
	}
	must(0, rows.Err())
	rows.Close()
	must(0, db.QueryRowContext(r.ctx, r.q(`SELECT MAX(r.seq) FROM revisions r JOIN resources s ON s.res = r.res WHERE s.ns = ?`), s.ns).Scan(&s.revTmpl))
	must(0, db.QueryRowContext(r.ctx, `SELECT MAX(seq) FROM revisions`).Scan(&s.revBase))
	must(0, db.QueryRowContext(r.ctx, `SELECT MAX(seq) FROM ns_log`).Scan(&s.logBase))
	if len(s.res) == 0 {
		fail(errors.New("cliff preload: run --cliff-step setup first"))
	}
	return s
}

func (r *runner) cliffPreload() {
	db := r.cliffOpen()
	defer db.Close()
	N := int64(r.c.cliffWrites)
	t0 := time.Now()
	conn := must(db.Conn(r.ctx))
	defer conn.Close()
	s := r.cliffState(conn)
	if r.cliffPG() {
		r.cliffPreloadPG(conn, s, N, t0)
	} else {
		r.cliffPreloadSQLite(conn, s, N, t0)
	}
	r.record("cliff_preload", map[string]any{"writes": N, "resources": len(s.res), "seconds": time.Since(t0).Seconds()})
}

const cliffChunk = 250_000

func (r *runner) cliffPreloadPG(conn *sql.Conn, s cliffState, N int64, t0 time.Time) {
	R := int64(len(s.res))
	// As a replica applies rows: no foreign-key or trigger work, the keys
	// being right by construction.
	must(conn.ExecContext(r.ctx, `SET session_replication_role = replica`))
	resArr, headArr := pgArray(s.res), pgArray(s.heads)
	for a := int64(1); a <= N; a += cliffChunk {
		b := min(a+cliffChunk-1, N)
		tx := must(conn.BeginTx(r.ctx, nil))
		must(tx.Exec(`INSERT INTO revisions (seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules, grant_ref)
			SELECT $1 + k, ($2::bigint[])[(k - 1) % $4 + 1],
				substr(sha256(int8send(k) || '\x02'::bytea), 1, 20),
				CASE WHEN k <= $4 THEN ($3::bigint[])[(k - 1) % $4 + 1] ELSE $1 + k - $4 END,
				0, t.kind, NULL, t.author, t.via, t.grant_id, t.signature, t.schema_ref, t.created + k, t.gesture, t.undoes, t.size,
				sha256(int8send(k) || '\x03'::bytea), t.rules, t.grant_ref
			FROM generate_series($5::bigint, $6::bigint) k, (SELECT * FROM revisions WHERE seq = $7) t`,
			s.revBase, resArr, headArr, R, a, b, s.revTmpl))
		must(tx.Exec(`INSERT INTO ns_log (seq, ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id, no_auth, gestures, via, grant_ref)
			SELECT $1 + k, t.ns, substr(sha256(int8send(k) || '\x01'::bytea), 1, 20),
				CASE WHEN k = 1 THEN $3 ELSE $1 + k - 1 END,
				t.kind, ($4::bigint[])[(k - 1) % $5 + 1], $2 + k, t.body, t.config_seq, t.author, t.created, t.grant_id, t.no_auth, t.gestures, t.via, t.grant_ref
			FROM generate_series($6::bigint, $7::bigint) k, (SELECT * FROM ns_log WHERE seq = $8) t`,
			s.logBase, s.revBase, s.nsHead, resArr, R, a, b, s.nsHead))
		must(tx.Exec(`INSERT INTO head_history (res, ns_seq, target_seq)
			SELECT ($1::bigint[])[(k - 1) % $2 + 1], $3 + k, $4 + k FROM generate_series($5::bigint, $6::bigint) k`,
			resArr, R, s.logBase, s.revBase, a, b))
		must(0, tx.Commit())
		r.logf("cliff preload: %d writes (%.0f/s)", b, float64(b)/time.Since(t0).Seconds())
	}
	r.cliffFinish(conn, s, N)
	must(conn.ExecContext(r.ctx, `SET session_replication_role = origin`))
	must(conn.ExecContext(r.ctx, `SELECT setval(pg_get_serial_sequence('revisions', 'seq'), (SELECT MAX(seq) FROM revisions))`))
	must(conn.ExecContext(r.ctx, `SELECT setval(pg_get_serial_sequence('ns_log', 'seq'), (SELECT MAX(seq) FROM ns_log))`))
	// Vacuumed now, so autovacuum doesn't scan the new rows during the
	// paced load.
	must(conn.ExecContext(r.ctx, `VACUUM ANALYZE`))
	must(conn.ExecContext(r.ctx, `CHECKPOINT`))
}

func (r *runner) cliffPreloadSQLite(conn *sql.Conn, s cliffState, N int64, t0 time.Time) {
	R := int64(len(s.res))
	must(conn.ExecContext(r.ctx, `PRAGMA foreign_keys = OFF`))
	for a := int64(1); a <= N; a += cliffChunk {
		b := min(a+cliffChunk-1, N)
		tx := must(conn.BeginTx(r.ctx, nil))
		rev := must(tx.Prepare(`INSERT INTO revisions (seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules, grant_ref)
			SELECT ?, ?, ?, ?, 0, kind, NULL, author, via, grant_id, signature, schema_ref, created + ?, gesture, undoes, size, ?, rules, grant_ref FROM revisions WHERE seq = ?`))
		lg := must(tx.Prepare(`INSERT INTO ns_log (seq, ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id, no_auth, gestures, grant_ref)
			SELECT ?, ns, ?, ?, kind, ?, ?, body, config_seq, author, created, grant_id, no_auth, gestures, grant_ref FROM ns_log WHERE seq = ?`))
		hh := must(tx.Prepare(`INSERT INTO head_history (res, ns_seq, target_seq) VALUES (?, ?, ?)`))
		for k := a; k <= b; k++ {
			j := (k - 1) % R
			parent := s.revBase + k - R
			if k <= R {
				parent = s.heads[j]
			}
			prev := s.logBase + k - 1
			if k == 1 {
				prev = s.nsHead
			}
			must(rev.Exec(s.revBase+k, s.res[j], cliffID(k, 2, 20), parent, k, cliffID(k, 3, 32), s.revTmpl))
			must(lg.Exec(s.logBase+k, cliffID(k, 1, 20), prev, s.res[j], s.revBase+k, s.nsHead))
			must(hh.Exec(s.res[j], s.logBase+k, s.revBase+k))
		}
		must(0, tx.Commit())
		r.logf("cliff preload: %d writes (%.0f/s)", b, float64(b)/time.Since(t0).Seconds())
	}
	r.cliffFinish(conn, s, N)
	must(conn.ExecContext(r.ctx, `ANALYZE`))
	must(conn.ExecContext(r.ctx, `PRAGMA wal_checkpoint(TRUNCATE)`))
}

// cliffFinish moves the resources' and the namespace's heads to the last
// loaded rows and gives each new head revision the template's patches (a
// head keeps them; the rest are pruned).
func (r *runner) cliffFinish(conn *sql.Conn, s cliffState, N int64) {
	R := int64(len(s.res))
	tx := must(conn.BeginTx(r.ctx, nil))
	for j := int64(0); j < R && j+1 <= N; j++ {
		k := j + 1 + R*((N-(j+1))/R) // the last write to resource j
		seq := s.revBase + k
		must(tx.Exec(r.q(`UPDATE revisions SET patches = (SELECT patches FROM revisions WHERE seq = ?) WHERE seq = ?`), s.revTmpl, seq))
		must(tx.Exec(r.q(`UPDATE resources SET head_seq = ? WHERE res = ?`), seq, s.res[j]))
		must(tx.Exec(r.q(`UPDATE heads SET seq = ? WHERE res = ?`), seq, s.res[j]))
	}
	must(tx.Exec(r.q(`UPDATE namespaces SET head_seq = ?, head_id = (SELECT id FROM ns_log WHERE seq = ?) WHERE ns = ?`), s.logBase+N, s.logBase+N, s.ns))
	must(0, tx.Commit())
}

func pgArray(v []int64) string {
	b := make([]string, len(v))
	for i, x := range v {
		b[i] = strconv.FormatInt(x, 10)
	}
	return "{" + strings.Join(b, ",") + "}"
}

// --- paced ---------------------------------------------------------------

type cliffStats map[string]float64

func (r *runner) cliffSnapshot(db *sql.DB) cliffStats {
	st := cliffStats{}
	add := func(k string, v float64) { st[k] += v }
	if f, err := os.ReadFile("/proc/diskstats"); err == nil {
		for _, l := range strings.Split(string(f), "\n") {
			x := strings.Fields(l)
			if len(x) > 9 && x[2] == r.c.cliffDisk {
				n := func(i int) float64 { v, _ := strconv.ParseFloat(x[i], 64); return v }
				add("disk_reads", n(3))
				add("disk_read_bytes", n(5)*512)
				add("disk_read_ms", n(6))
				add("disk_writes", n(7))
				add("disk_write_bytes", n(9)*512)
			}
		}
	}
	if r.c.cliffCgroup != "" {
		if f, err := os.ReadFile(r.c.cliffCgroup + "/memory.stat"); err == nil {
			for _, l := range strings.Split(string(f), "\n") {
				x := strings.Fields(l)
				if len(x) == 2 && (x[0] == "total_cache" || x[0] == "total_rss") {
					v, _ := strconv.ParseFloat(x[1], 64)
					st["cgroup_"+x[0]+"_mb"] = v / (1 << 20)
				}
			}
		}
	}
	if !r.cliffPG() {
		return st
	}
	rows := must(db.QueryContext(r.ctx, `SELECT relname, indexrelname, COALESCE(idx_blks_read, 0), COALESCE(idx_blks_hit, 0)
		FROM pg_statio_user_indexes WHERE relname IN ('ns_log', 'revisions', 'head_history', 'resources', 'heads')`))
	for rows.Next() {
		var t, i string
		var rd, hit float64
		must(0, rows.Scan(&t, &i, &rd, &hit))
		add("idx_blks_read:"+i, rd)
		add("idx_blks_hit:"+i, hit)
	}
	rows.Close()
	rows = must(db.QueryContext(r.ctx, `SELECT relname, COALESCE(heap_blks_read, 0), COALESCE(heap_blks_hit, 0)
		FROM pg_statio_user_tables WHERE relname IN ('ns_log', 'revisions', 'head_history', 'resources', 'heads')`))
	for rows.Next() {
		var t string
		var rd, hit float64
		must(0, rows.Scan(&t, &rd, &hit))
		add("heap_blks_read:"+t, rd)
		add("heap_blks_hit:"+t, hit)
	}
	rows.Close()
	rows = must(db.QueryContext(r.ctx, `SELECT backend_type, COALESCE(SUM(reads), 0), COALESCE(SUM(read_time), 0), COALESCE(SUM(writes), 0),
		COALESCE(SUM(write_time), 0), COALESCE(SUM(extends), 0), COALESCE(SUM(hits), 0), COALESCE(SUM(evictions), 0)
		FROM pg_stat_io WHERE object = 'relation' GROUP BY backend_type`))
	for rows.Next() {
		var bt string
		var v [7]float64
		must(0, rows.Scan(&bt, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]))
		for i, k := range []string{"reads", "read_ms", "writes", "write_ms", "extends", "hits", "evictions"} {
			add("io:"+bt+":"+k, v[i])
		}
	}
	rows.Close()
	var wal float64
	must(0, db.QueryRowContext(r.ctx, `SELECT (pg_current_wal_lsn() - '0/0'::pg_lsn)::float8`).Scan(&wal))
	st["wal_bytes"] = wal
	return st
}

func (r *runner) cliffSizes(db *sql.DB) map[string]int64 {
	out := map[string]int64{}
	var q string
	if r.cliffPG() {
		q = `SELECT i.relname, pg_relation_size(i.oid) FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class t ON t.oid = x.indrelid
			WHERE t.relname IN ('ns_log', 'revisions', 'head_history')
			UNION ALL SELECT relname, pg_relation_size(oid) FROM pg_class WHERE relname IN ('ns_log', 'revisions', 'head_history') AND relkind = 'r'
			UNION ALL SELECT 'database', pg_database_size(current_database())`
	} else {
		q = `SELECT d.name, SUM(d.pgsize) FROM dbstat d LEFT JOIN sqlite_master m ON m.name = d.name
			WHERE COALESCE(m.tbl_name, d.name) IN ('ns_log', 'revisions', 'head_history') GROUP BY d.name
			UNION ALL SELECT 'database', page_count * page_size FROM pragma_page_count, pragma_page_size`
	}
	rows := must(db.QueryContext(r.ctx, q))
	defer rows.Close()
	for rows.Next() {
		var n string
		var b int64
		must(0, rows.Scan(&n, &b))
		out[n] = b
	}
	return out
}

func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	i := int(p/100*float64(len(v)) + 0.5)
	if i >= len(v) {
		i = len(v) - 1
	}
	return secMS(v[i])
}

// secMS is a duration in seconds in milliseconds, to two places.
func secMS(v float64) float64 { return float64(int64(v*1e5+0.5)) / 100 }

func latSummary(v []float64) map[string]any {
	sort.Float64s(v)
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	out := map[string]any{"n": len(v)}
	if len(v) > 0 {
		out["mean_ms"] = secMS(sum / float64(len(v)))
		out["p50_ms"], out["p95_ms"], out["p99_ms"] = pct(v, 50), pct(v, 95), pct(v, 99)
		out["max_ms"] = secMS(v[len(v)-1])
	}
	return out
}

func (r *runner) cliffPaced() {
	db := r.cliffOpen()
	defer db.Close()
	var nsID int64
	must(0, db.QueryRowContext(r.ctx, r.q(`SELECT ns FROM namespaces WHERE name = ?`), cliffNS).Scan(&nsID))
	rows := must(db.QueryContext(r.ctx, r.q(`SELECT s.name, r.id FROM resources s JOIN revisions r ON r.seq = s.head_seq WHERE s.ns = ? ORDER BY s.name`), nsID))
	var names, heads []string
	for rows.Next() {
		var n string
		var id []byte
		must(0, rows.Scan(&n, &id))
		names, heads = append(names, n), append(heads, ids.FromBytes(id).String())
	}
	rows.Close()
	var sizes map[string]int64
	if r.cliffPG() {
		sizes = r.cliffSizes(db) // the catalog only: no data pages read
	}
	w := r.cliffWriter()
	busy := make([]atomic.Bool, len(names))
	rate, secs := r.c.cliffRate, r.c.cliffSeconds
	total := int(rate * float64(secs))
	lat := make([]float64, total)
	ok := make([]bool, total)
	var errs sync.Map
	var skipped atomic.Int64
	before := r.cliffSnapshot(db)
	// The counters again once the first 30 seconds' writes are scheduled,
	// for the reads of the rest (a cold start's are in the first).
	warmup := min(int(30*rate), total)
	var mid cliffStats
	midDone := make(chan struct{})
	t0 := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		if i == warmup {
			go func() { mid = r.cliffSnapshot(db); close(midDone) }()
		}
		at := t0.Add(time.Duration(float64(i) / rate * float64(time.Second)))
		if d := time.Until(at); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func(i int, at time.Time) {
			defer wg.Done()
			j := -1
			for try := 0; try < 50; try++ {
				c := rand.IntN(len(names))
				if busy[c].CompareAndSwap(false, true) {
					j = c
					break
				}
			}
			if j < 0 {
				skipped.Add(1)
				return
			}
			defer busy[j].Store(false)
			res, err := w.Append(r.ctx, cliffNS, names[j], heads[j], []any{map[string]any{"op": "replace", "path": "/n", "value": i + 1}})
			lat[i] = time.Since(at).Seconds()
			if err != nil {
				k := err.Error()
				var ae *client.APIError
				if errors.As(err, &ae) {
					k = fmt.Sprint(ae.Status, " ", ae.Code)
				}
				v, _ := errs.LoadOrStore(k, new(atomic.Int64))
				v.(*atomic.Int64).Add(1)
				return
			}
			heads[j], ok[i] = res.ID, true
		}(i, at)
	}
	wg.Wait()
	wall := time.Since(t0)
	if warmup < total {
		<-midDone
	} else {
		mid = before
	}
	// Backends report their I/O counters when idle, at most every second
	// and at least every ten.
	time.Sleep(12 * time.Second)
	after := r.cliffSnapshot(db)
	diff := func(from cliffStats) map[string]float64 {
		delta := map[string]float64{}
		for k, v := range after {
			if strings.HasPrefix(k, "cgroup_") {
				delta[k] = round1(v)
				continue
			}
			if d := v - from[k]; d != 0 {
				delta[k] = d
			}
		}
		return delta
	}
	delta, warmDelta := diff(before), diff(mid)
	if !r.cliffPG() {
		sizes = r.cliffSizes(db)
	}
	// Counted last: a count reads the tables, which would have filled the
	// cache the load measures.
	var counts struct{ revs, entries int64 }
	must(0, db.QueryRowContext(r.ctx, `SELECT COUNT(*) FROM revisions`).Scan(&counts.revs))
	must(0, db.QueryRowContext(r.ctx, `SELECT COUNT(*) FROM ns_log`).Scan(&counts.entries))
	var all, warm []float64
	buckets := []any{}
	per := map[int][]float64{}
	for i := 0; i < total; i++ {
		if !ok[i] {
			continue
		}
		all = append(all, lat[i])
		sec := float64(i) / rate
		if sec >= 30 {
			warm = append(warm, lat[i])
		}
		per[int(sec/10)] = append(per[int(sec/10)], lat[i])
	}
	for b := 0; b*10 < secs; b++ {
		s := latSummary(per[b])
		s["from_s"] = b * 10
		buckets = append(buckets, s)
	}
	errOut := map[string]int64{}
	errs.Range(func(k, v any) bool { errOut[k.(string)] = v.(*atomic.Int64).Load(); return true })
	written := len(all)
	per1 := func(delta map[string]float64, n float64) map[string]float64 {
		out := map[string]float64{}
		for k, v := range delta {
			if strings.HasPrefix(k, "cgroup_") || n == 0 {
				continue
			}
			out[k] = round1(v/n*1000) / 1000
		}
		return out
	}
	r.record("cliff", map[string]any{
		"store":                  map[bool]string{true: "postgres", false: "sqlite"}[r.cliffPG()],
		"label":                  r.c.cliffLabel,
		"revisions":              counts.revs,
		"ns_log_entries":         counts.entries,
		"resources":              len(names),
		"rate":                   rate,
		"seconds":                secs,
		"wall_seconds":           wall.Seconds(),
		"written":                written,
		"skipped":                skipped.Load(),
		"errors":                 errOut,
		"latency":                latSummary(all),
		"latency_after_30s":      latSummary(warm),
		"buckets":                buckets,
		"sizes":                  sizes,
		"io":                     delta,
		"io_per_write":           per1(delta, float64(written)),
		"io_after_30s":           warmDelta,
		"io_per_write_after_30s": per1(warmDelta, float64(len(warm))),
	})
}
