package core

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/middle-management/patchlog/internal/ids"
)

// Spanner's PostgreSQL interface, through PGAdapter (docs/SPANNER.md).
//
// The engine runs there as on Postgres (e.pg), with e.spanner set where
// Spanner differs. What differs, and where it is handled:
//
//   - write serialisation. Spanner's read-write transactions are
//     serializable, and lock what they read (shared) and write
//     (exclusive) until they commit; a deadlock aborts one of them, which
//     runs again (retryable). So no advisory lock is taken (tx.locking):
//     reading a namespace's row in a write transaction holds it as
//     pg_advisory_xact_lock_shared held the namespace, and a write that
//     changes the namespace reads its row FOR UPDATE (nsForWrite), as the
//     exclusive lock. The log lock is the namespace's row read FOR UPDATE
//     just before the append (logHeadOf), which orders appends to one
//     chain as the log lock did; namespace rows a write transaction read
//     stay as read until it commits (snapshotRows). Nothing is only tried,
//     so errRelock never happens;
//   - ids. Spanner's identities are bit-reversed, so they don't grow, and
//     the seqs of revisions, ns_log, ns_config and archives must grow
//     along their chains (§3.5, D.8): they come from blocks of id_blocks
//     (idBlocks), each above the chain's head;
//   - the tailer reads ns_log by commit timestamp, not xid (tailer.go);
//   - the leader of the background loops holds a lease row, not a session
//     lock (leaderLease);
//   - statements Spanner refuses (UPDATE … FROM, data-modifying CTEs,
//     unnest of several arrays, LATERAL, recursive CTEs, window
//     functions, ON CONFLICT on a secondary index) have Spanner forms
//     where they are written; multi-row VALUES (spValues) and arrays
//     subscripted by an unnest of ordinals (bulk.go) stand in for unnest;
//   - constraint violations name the index, not the table (isConflict);
//   - the shared rate buckets are drawn by statements in Go
//     (drawsSpanner), not by rate_draws, a function.

// idBlockSize is how many ids an instance takes from id_blocks at once per
// table: one short transaction on the counter's row each time.
const idBlockSize = 1024

// idBlocks hands out the chain-ordered ids of an engine on Spanner. Every
// id comes from a block taken from id_blocks, whose next only grows: a
// block is above every id handed out before it was taken, by any instance.
// An id must be above the head of its chain (above); one from the block
// in hand that isn't, because another instance's later block appended the
// head, is skipped by taking a new block, which is above the head since
// the head's id was handed out before it.
//
// Blocks are taken between transactions, never inside one: inside, the
// counter's row would stay locked until it commits, serialising every
// writer of the deployment, and the emulator, which runs one read-write
// transaction at a time, would wait forever for the one open. So a write
// transaction takes ids from the blocks in hand only (take), and one that
// needs more, or one above a head a later block appended, rolls back
// (errIDBlock), takes a new block (refill) and runs again (update1).
// Before each write transaction, blocks running low are refilled
// (topUp), so that is rare.
type idBlocks struct {
	db     *sql.DB
	mu     sync.Mutex
	blocks map[string]*idBlock
}

type idBlock struct{ next, end int64 }

// idTables are the tables whose ids idBlocks hands out (id_blocks' rows,
// seeded by migrations/seed/spanner.sql).
var idTables = []string{"revisions", "ns_log", "ns_config", "archives"}

func openIDBlocks(url string) (*idBlocks, error) {
	url, _, err := parsePGPool(url)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(10 * time.Second)
	return &idBlocks{db: db, blocks: map[string]*idBlock{}}, nil
}

func (b *idBlocks) close() {
	if b != nil {
		b.db.Close()
	}
}

// errIDBlock rolls back a write transaction on Spanner that needs n ids of
// table, above above, that the block in hand doesn't have (idBlocks).
type errIDBlock struct {
	table string
	above int64
	n     int
}

func (e *errIDBlock) Error() string {
	return fmt.Sprintf("%d %s ids above %d are not in hand", e.n, e.table, e.above)
}

// take returns n ascending ids of table, each above above (0: any), from
// the block in hand, or panics with errIDBlock.
func (b *idBlocks) take(table string, above int64, n int) []int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := b.blocks[table]
	if k == nil || k.end-k.next < int64(n) || k.next <= above {
		panic(&errIDBlock{table: table, above: above, n: n})
	}
	out := make([]int64, n)
	for i := range out {
		out[i] = k.next
		k.next++
	}
	return out
}

// refill takes a new block of table's ids, of at least n, which is above
// every id handed out before, above included.
func (b *idBlocks) refill(ctx context.Context, table string, above int64, n int) error {
	size := int64(max(idBlockSize, n))
	var end int64
	err := b.db.QueryRowContext(context.WithoutCancel(ctx), `UPDATE id_blocks SET next = next + $1 WHERE name = $2 RETURNING next`, size, table).Scan(&end)
	if err != nil {
		return fmt.Errorf("taking a block of %s ids: %w", table, err)
	}
	if end-size <= above {
		return fmt.Errorf("a block of %s ids from %d is not above the head %d", table, end-size, above)
	}
	b.mu.Lock()
	b.blocks[table] = &idBlock{next: end - size, end: end}
	b.mu.Unlock()
	return nil
}

// topUp refills the blocks less than a quarter full, before a write
// transaction begins.
func (b *idBlocks) topUp(ctx context.Context) error {
	for _, table := range idTables {
		b.mu.Lock()
		k := b.blocks[table]
		low := k == nil || k.end-k.next < idBlockSize/4
		b.mu.Unlock()
		if low {
			if err := b.refill(ctx, table, 0, idBlockSize); err != nil {
				return err
			}
		}
	}
	return nil
}

// spIDs returns n ascending ids of table above above, for a write
// transaction's inserts (idBlocks).
func (t *tx) spIDs(table string, above int64, n int) []int64 {
	return t.e.spIDs.take(table, above, n)
}

// spannerBackoff pauses before the attempt after attempt of a write
// transaction Spanner aborted: a random time up to 10 ms × 2^attempt, at
// most a second.
func spannerBackoff(ctx context.Context, attempt int) {
	d := min(10*time.Millisecond<<attempt, time.Second)
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(mrand.Int64N(int64(d)))):
	}
}

// spID is spIDs for one id.
func (t *tx) spID(table string, above int64) int64 { return t.spIDs(table, above, 1)[0] }

// spExpr is a value of spValues written into the statement as SQL rather
// than passed as an argument: spanner.pending_commit_timestamp(), which
// Spanner takes only as a value in INSERT or UPDATE.
type spExpr string

const spCommitTS spExpr = `spanner.pending_commit_timestamp()`

// spMaxArgs bounds the arguments of one statement spValues runs: the
// rows are split into statements of at most this many.
const spMaxArgs = 900

// spValues runs head, an INSERT up to VALUES, over rows as one multi-row
// VALUES list followed by tail (ON CONFLICT …, RETURNING …), in as few
// statements as spMaxArgs allows, calling scan for every row returned
// (nil: none are).
func (t *tx) spValues(head string, rows [][]any, tail string, scan func(*sql.Rows)) {
	if len(rows) == 0 {
		return
	}
	t.wrote()
	per := max(1, spMaxArgs/len(rows[0]))
	for len(rows) > 0 {
		chunk := rows[:min(per, len(rows))]
		rows = rows[len(chunk):]
		var b strings.Builder
		var args []any
		b.WriteString(head)
		b.WriteString(` VALUES `)
		for i, row := range chunk {
			if i > 0 {
				b.WriteString(`, `)
			}
			b.WriteByte('(')
			for j, v := range row {
				if j > 0 {
					b.WriteByte(',')
				}
				if x, ok := v.(spExpr); ok {
					b.WriteString(string(x))
					continue
				}
				args = append(args, v)
				b.WriteByte('$')
				b.WriteString(strconv.Itoa(len(args)))
			}
			b.WriteByte(')')
		}
		if tail != "" {
			b.WriteByte(' ')
			b.WriteString(tail)
		}
		q := b.String()
		t.counted(q)
		if scan == nil {
			_, err := t.Tx.Exec(q, pgArgs(args)...)
			t.must(err)
			continue
		}
		rs, err := t.Tx.Query(q, pgArgs(args)...)
		t.must(err)
		for rs.Next() {
			scan(rs)
		}
		t.must(rs.Err())
		rs.Close()
	}
}

// spConflictIndexes are the unique indexes of the Spanner schema whose
// violations mean a concurrent writer won the race of a resource chain or
// a namespace chain (isConflict; conflictTables on Postgres): Spanner's
// errors name the index, or a primary key's table, but carry no table
// name of their own.
var spConflictIndexes = []string{
	"revisions_res_id_key", "revisions_res_parent_seq_key", "one_first",
	"resources_ns_name_key", "ns_log_ns_id_key", "ns_log_ns_prev_seq_key", "one_ns_first",
	// Primary keys, as Spanner reports them ("Row [..] in table heads
	// already exists").
	"in table head_history", "in table heads",
}

// spannerConflict is isConflict for an error from Spanner.
func spannerConflict(pe *pgconn.PgError) bool {
	if pe.Code != "23505" {
		return false
	}
	for _, s := range spConflictIndexes {
		if strings.Contains(pe.Message, s) {
			return true
		}
	}
	return false
}

// --- leader lease ---------------------------------------------------------------

// leaseTTL is how long the leader's lease lasts unless renewed: each
// background loop's tick and each step of a leader's job renews it
// (leaderSpanner, holdsLeaderSpanner). An instance that stops renewing it
// loses it that long after, and another takes over at its next tick, as
// when a Postgres leader loses its connection.
const leaseTTL = 60 * time.Second

// leaseHolder names this engine in leader_lease.
func newLeaseHolder() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// leaderSpanner is leader on Spanner: the instance holding the lease row,
// taken when it has expired, renewed while held. Leases are timed by each
// instance's clock, so clocks must agree to well within leaseTTL.
func (e *Engine) leaderSpanner(ctx context.Context) bool {
	now := time.Now().UnixMilli()
	if _, err := e.db.ExecContext(ctx, `INSERT INTO leader_lease (id, holder, expires) VALUES (1, $1, $2) ON CONFLICT (id) DO NOTHING`, e.leaseHolder, now+leaseTTL.Milliseconds()); err != nil {
		return false
	}
	r, err := e.db.ExecContext(ctx, `UPDATE leader_lease SET holder = $1, expires = $2 WHERE id = 1 AND (holder = $1 OR expires < $3)`,
		e.leaseHolder, now+leaseTTL.Milliseconds(), now)
	if err != nil {
		return false
	}
	n, err := r.RowsAffected()
	return err == nil && n == 1
}

// holdsLeaderSpanner is holdsLeader on Spanner: the lease is still this
// instance's, renewed.
func (e *Engine) holdsLeaderSpanner(ctx context.Context) bool {
	now := time.Now().UnixMilli()
	r, err := e.db.ExecContext(ctx, `UPDATE leader_lease SET expires = $1 WHERE id = 1 AND holder = $2 AND expires >= $3`,
		now+leaseTTL.Milliseconds(), e.leaseHolder, now)
	if err != nil {
		return false
	}
	n, err := r.RowsAffected()
	return err == nil && n == 1
}

// resignSpanner gives the lease up (Close).
func (e *Engine) resignSpanner() {
	e.db.ExecContext(context.Background(), `UPDATE leader_lease SET expires = 0 WHERE id = 1 AND holder = $1`, e.leaseHolder)
}

// --- read timestamps -------------------------------------------------------------

// spReadTimestamp is the read timestamp of the last read-only
// transaction or query on conn (PGAdapter's spanner.read_timestamp), in
// Unix microseconds: every transaction that committed before it began is
// visible to it, every later one commits after it (Spanner's external
// consistency). Microseconds truncate Spanner's nanoseconds, which only
// moves it earlier.
func spReadTimestamp(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int64, error) {
	var s sql.NullString
	// PGAdapter answers SHOW in the simple protocol only.
	if err := q.QueryRowContext(ctx, `SHOW spanner.read_timestamp`, pgx.QueryExecModeSimpleProtocol).Scan(&s); err != nil {
		return 0, err
	}
	if !s.Valid || s.String == "" {
		return 0, errors.New("no read timestamp")
	}
	ts, err := parseSpannerTime(s.String)
	if err != nil {
		return 0, err
	}
	return ts.UnixMicro(), nil
}

// parseSpannerTime parses a timestamp as PGAdapter shows it
// (2026-11-24 10:07:09.441867+00) or as RFC 3339.
func parseSpannerTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", s)
}

// --- the namespace chain ---------------------------------------------------------

// spLogRow is an ns_log entry for appendSpanner: appendNS's columns.
type spLogRow struct {
	id                             []byte
	kind                           int
	res, target                    any
	body                           string
	author                         int64
	grantID, noAuth, gestures, via any
	hist                           []histRow
}

// appendSpanner appends rows to n's chain, after its head prevSeq (nil
// for an empty chain) read under the row's lock (logHeadOf), with the
// namespace's new head id and configuration, and records the resource
// heads they move: appendNS's and appendNSMany's single statement, as
// three, since Spanner has no data-modifying CTEs. The entries' seqs are
// taken above the head, ascending (idBlocks), and each records its
// transaction's commit timestamp, which the tailer reads by. It returns
// their seqs.
func (t *tx) appendSpanner(n *nsRow, prevSeq any, configSeq int64, headID ids.ID, rows []spLogRow) []int64 {
	var above int64
	if p, ok := prevSeq.(int64); ok {
		above = p
	}
	seqs := t.spIDs("ns_log", above, len(rows))
	vals := make([][]any, len(rows))
	var hist [][]any
	prev := prevSeq
	for i, r := range rows {
		vals[i] = []any{seqs[i], n.id, r.id, prev, r.kind, r.res, r.target, r.body, configSeq, r.author, t.now.UnixMilli(), r.grantID, r.noAuth, r.gestures, r.via, spCommitTS}
		prev = seqs[i]
		for _, h := range r.hist {
			hist = append(hist, []any{h.res, seqs[i], h.target})
		}
	}
	t.spValues(`INSERT INTO ns_log (seq, ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id, no_auth, gestures, via, committed)`, vals, "", nil)
	_, err := t.Exec(`UPDATE namespaces SET head_seq = ?, head_id = ?, config_seq = ? WHERE ns = ?`, seqs[len(seqs)-1], headID[:], configSeq, n.id)
	t.must(err)
	t.spValues(`INSERT INTO head_history (res, ns_seq, target_seq)`, hist, "", nil)
	return seqs
}

// nilBytes is a nullable bytea argument: NULL for nil.
func nilBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// nullPtr is a nullable text argument: NULL for nil.
func nullPtr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// --- rate buckets ---------------------------------------------------------------

// aborted reports an error after which Spanner expects the transaction to
// run again (40001: aborted, a deadlock broken or a lock lost).
func aborted(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "40001"
}

// failedTx reports a statement refused because an earlier one failed the
// transaction (25P02). Some reads take an error for an answer (no such
// row: authorID, for one); on Spanner that error may have been an abort,
// so a write transaction refused so runs again (update1).
func failedTx(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "25P02"
}

// drawsSpanner is drawsOnce on Spanner: rate_draws (migration
// 031_rate_draws_batched), which Spanner can't hold as a function, as
// statements of one read-write transaction. It adds the buckets never
// drawn on, full as of the first request that draws on each; reads every
// bucket of the batch FOR UPDATE; then judges the requests in queue order
// as rate_draws does, each after the ones before it; and writes each
// changed row once, in one statement. A deadlock between batches aborts
// one, which runs again (drawBatch). Every row is read after it is
// inserted, in the transaction, so the batch is always complete.
func (s *bucketStore) drawsSpanner(ctx context.Context, b []*drawReq) ([]drawRes, bool, error) {
	type bucket struct {
		tokens        float64
		last          int64
		rate, burst   float64
		changed, read bool
	}
	buckets := map[string]*bucket{}
	var keys [][]byte
	var ins [][]any
	for _, r := range b {
		for _, d := range r.ds {
			if _, ok := buckets[d.key]; ok {
				continue
			}
			buckets[d.key] = &bucket{}
			keys = append(keys, []byte(d.key))
			ins = append(ins, []any{[]byte(d.key), d.rate.Burst, r.now.UnixMicro(), d.rate.Rate, d.rate.Burst})
		}
	}
	res := make([]drawRes, len(b))
	err := func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for len(ins) > 0 {
			chunk := ins[:min(len(ins), spMaxArgs/5)]
			ins = ins[len(chunk):]
			var q strings.Builder
			var args []any
			q.WriteString(`INSERT INTO rate_buckets (key, tokens, last, rate, burst) VALUES `)
			for i, row := range chunk {
				if i > 0 {
					q.WriteString(`, `)
				}
				fmt.Fprintf(&q, `($%d, $%d, $%d, $%d, $%d)`, len(args)+1, len(args)+2, len(args)+3, len(args)+4, len(args)+5)
				args = append(args, row...)
			}
			q.WriteString(` ON CONFLICT (key) DO NOTHING`)
			if _, err := tx.ExecContext(ctx, q.String(), args...); err != nil {
				return err
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT key, tokens, last, rate, burst FROM rate_buckets WHERE key = ANY($1::bytea[]) FOR UPDATE`, keys)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k []byte
			var x bucket
			if err := rows.Scan(&k, &x.tokens, &x.last, &x.rate, &x.burst); err != nil {
				rows.Close()
				return err
			}
			if p := buckets[string(k)]; p != nil {
				*p = x
				p.read = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for k, p := range buckets {
			if !p.read {
				return fmt.Errorf("rate buckets: bucket %q not read", k)
			}
		}
		for i, r := range b {
			now := r.now.UnixMicro()
			cur := make([]float64, len(r.ds))
			ok := true
			for j, d := range r.ds {
				p := buckets[d.key]
				c := p.tokens
				if now > p.last {
					c = min(d.rate.Burst, c+float64(now-p.last)*d.rate.Rate/1e6)
				}
				cur[j] = c
				if c < 1 {
					ok = false
				}
			}
			ok = ok || r.force
			res[i] = drawRes{tokens: make(map[string]float64, len(r.ds)), ok: ok}
			for j, d := range r.ds {
				res[i].tokens[d.key] = cur[j]
				if ok {
					p := buckets[d.key]
					p.tokens, p.last, p.rate, p.burst, p.changed = cur[j]-d.cost, max(p.last, now), d.rate.Rate, d.rate.Burst, true
				}
			}
		}
		var up [][]any
		for _, k := range keys {
			if p := buckets[string(k)]; p.changed {
				up = append(up, []any{k, p.tokens, p.last, p.rate, p.burst})
			}
		}
		for len(up) > 0 {
			chunk := up[:min(len(up), spMaxArgs/5)]
			up = up[len(chunk):]
			var q strings.Builder
			var args []any
			q.WriteString(`INSERT INTO rate_buckets (key, tokens, last, rate, burst) VALUES `)
			for i, row := range chunk {
				if i > 0 {
					q.WriteString(`, `)
				}
				fmt.Fprintf(&q, `($%d, $%d, $%d, $%d, $%d)`, len(args)+1, len(args)+2, len(args)+3, len(args)+4, len(args)+5)
				args = append(args, row...)
			}
			q.WriteString(` ON CONFLICT (key) DO UPDATE SET tokens = excluded.tokens, last = excluded.last, rate = excluded.rate, burst = excluded.burst`)
			if _, err := tx.ExecContext(ctx, q.String(), args...); err != nil {
				return err
			}
		}
		return tx.Commit()
	}()
	if err != nil {
		return nil, false, err
	}
	return res, true, nil
}
