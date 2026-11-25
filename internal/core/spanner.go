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
	_ "unsafe" // go:linkname (spResetForRetry)

	"cloud.google.com/go/spanner"
	spannerdriver "github.com/googleapis/go-sql-spanner"

	"github.com/middle-management/patchlog/internal/spannerurl"

	"github.com/middle-management/patchlog/internal/ids"
)

// Spanner's PostgreSQL dialect (docs/SPANNER.md).
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

// Chain-ordered ids on Spanner (seqGen): the seqs of revisions, ns_log,
// ns_config and archives must grow along their chains (§3.5, D.8), and
// Spanner's identities are bit-reversed, so they don't. Taken from one
// counter, as Postgres's sequences hand them out, every insert of the
// deployment would land at the end of each table's key range, on one
// split: Spanner's classic hotspot. So an id is
//
//	bucket (8 bits) | milliseconds since spEpoch (41 bits) | count (14 bits)
//
// where the bucket is the top 8 bits of the key of the chain's first row's
// (the resource for revisions and archives, the namespace for ns_log and
// ns_config), which the rest of the chain keeps: those keys are
// bit-reversed identities, whose top bits are spread evenly, so the
// inserts spread over 256 points of each table's key range, one per
// bucket, and Spanner splits the load between them. Within a bucket ids
// grow with time, and an instance's count, one for all buckets, orders
// those it takes in one millisecond, starting at a random point, so the low
// bits order an instance's ids across chains too (spWriteOrder). An id is
// also always above its chain's head, read under the row's lock
// (logHeadOf), so ids grow along a chain whatever the clocks of the
// instances that append to it. Two instances can take one id in the same
// bucket and millisecond, rarely: the second to commit fails on the
// table's primary key, a unique violation of no chain (isConflict), and
// runs again (retryable) with a new one. Ids are not dense, nor ordered
// across chains by their seqs: the least needn't be the deployment's first
// entry, which is read by commit timestamp instead (operatorkeys.go,
// archive.go).
const (
	spBucketBits = 8
	spCountBits  = 14
	spLowBits    = 63 - spBucketBits
	spLowMask    = 1<<spLowBits - 1
)

// spEpoch is the zero of the ids' milliseconds: 41 bits of them last until
// 2095.
var spEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()

// seqGen hands out an engine's chain-ordered ids on Spanner (above).
type seqGen struct {
	mu   sync.Mutex
	last int64 // the low bits of the last id taken, in any bucket
}

// spOrderMod is 2^55: an id modulo it is its low bits (spWriteOrder).
const spOrderMod = int64(1) << spLowBits

// spWriteOrder is the order in which an id was taken across chains: its
// low bits, the time and the count. Ids of one chain share a bucket, so it
// orders them as their seqs do; across chains, it orders them by the
// millisecond they were taken in, which seqs don't. (Ties across chains
// are ordered by seq.) Only for an order the deployment's writes must keep
// across resources (Gestures).
func spWriteOrder(seq int64) int64 { return seq & spLowMask }

// spBucket is the bucket of a chain's key: its top 8 bits of 63.
func spBucket(chain int64) int64 { return int64(uint64(chain)>>spLowBits) & (1<<spBucketBits - 1) }

// take returns n ascending ids for chain, each above above (its head; 0 for
// none). They are in the bucket of the head, or of chain's key for a chain
// with none: a branch's chain goes on from its base's (a revision of the
// base's resource, an entry of the base's log), whose bucket it keeps.
func (g *seqGen) take(chain, above int64, n int) []int64 {
	b := spBucket(chain)
	if above > 0 {
		b = spBucket(above)
	}
	g.mu.Lock()
	low := (time.Now().UnixMilli() - spEpoch) << spCountBits
	if g.last >= low {
		low = g.last + 1
	} else {
		low += mrand.Int64N(1 << (spCountBits - 1))
	}
	v := b<<spLowBits | low
	if v <= above {
		v = above + 1
	}
	if spBucket(v+int64(n)-1) != b {
		g.mu.Unlock()
		panic(fmt.Errorf("no ids left above %d in bucket %d", above, b))
	}
	g.last = max(g.last, (v+int64(n)-1)&spLowMask)
	g.mu.Unlock()
	out := make([]int64, n)
	for i := range out {
		out[i] = v + int64(i)
	}
	return out
}

// spIDs returns n ascending ids for a row of chain's, above its head above
// (seqGen).
func (t *tx) spIDs(chain, above int64, n int) []int64 {
	return t.e.spSeqs.take(chain, above, n)
}

// spID is spIDs for one id.
func (t *tx) spID(chain, above int64) int64 { return t.spIDs(chain, above, 1)[0] }

// spWrite is the connection and transaction update1Spanner runs a write
// on, across its attempts. kept is set when an attempt left the
// transaction open, aborted by Spanner (spAborted), for update1Spanner to
// run again; duringCommit when its commit was aborted.
type spWrite struct {
	conn               *sql.Conn
	tx                 *sql.Tx
	kept, duringCommit bool
}

// spResetForRetry is go-sql-spanner's resetTransactionForRetry, which
// RunTransaction calls after Spanner aborted its transaction: the same
// transaction runs again, on the session it ran on, as one that inherits
// the aborted one's priority among the transactions that lock the same
// rows (wound-wait). A new transaction instead would be younger than every
// transaction it waited for, and lose to them again; on the emulator,
// which runs one transaction at a time, every write that overlapped
// another then aborted until it gave up. The driver exports the loop only
// (RunTransaction), which takes a function of a *sql.Tx, while the engine's
// writes need the connection too (spBuffer), so its step is linked to
// here; a driver without it fails to link.
//
//go:linkname spResetForRetry github.com/googleapis/go-sql-spanner.resetTransactionForRetry
func spResetForRetry(ctx context.Context, conn *sql.Conn, errDuringCommit bool) error

// spAborted reports an error after which Spanner expects the transaction to
// run again: aborted (40001), or refused after a statement that failed for
// an abort (25P02, failedTx).
func spAborted(err error) bool { return aborted(err) || failedTx(err) }

// update1Spanner is update1 on Spanner: f in a write transaction on a
// connection of its own (for its mutations and DML batches, spBuffer and
// spDMLBatch), run again after Spanner aborts it, as the same transaction
// (spResetForRetry), after a pause (spannerBackoff), and after any other
// error retryable reports, as a new one; at most spMaxWriteAttempts times.
// The driver's own retries are off on the connection while it runs: it
// would replay the statements and give up if any read differently, where
// f reads anew. On the emulator they stay on: it runs one read-write
// transaction at a time and aborts any other, and a write that draws rate
// tokens (drawsSpanner, a transaction of its own) while its own is open is
// aborted by the draw, so run again it would draw again, and be aborted
// again, forever; the driver's replay runs its statements again without
// the draw.
func (e *Engine) update1Spanner(ctx context.Context, f func(t *tx) error) (rotate []string, err error) {
	db := e.db
	if c := e.commits; c != nil && committingGroup(ctx) && c.take() {
		// A group commit's, on the commit pool (updateOnce).
		db = c.db
		defer c.give()
	}
	conn, err := db.Conn(ctx)
	if err != nil && db != e.db {
		conn, err = e.db.Conn(ctx)
	}
	if err != nil {
		return nil, err
	}
	defer spEndWrite(conn)
	if !spannerurl.Emulator() {
		if err := spSetRetries(conn, false); err != nil {
			return nil, err
		}
	}
	w := &spWrite{conn: conn}
	for attempt := 1; ; attempt++ {
		if w.tx == nil {
			if w.tx, err = conn.BeginTx(ctx, nil); err != nil {
				return nil, err
			}
		}
		rotate, err = e.updateOnce(ctx, f, nil, nil, w)
		if err == nil {
			return rotate, nil
		}
		again := attempt < spMaxWriteAttempts && ctx.Err() == nil && (retryable(err) || failedTx(err))
		if !again {
			if w.kept && !w.duringCommit {
				w.tx.Rollback()
			}
			return nil, err
		}
		// Spanner aborted it (40001), for a lock it lost: it runs again
		// after a pause, as Spanner asks, longer each time, so that
		// transactions aborting each other don't retry in step.
		spannerBackoff(ctx, attempt)
		// On the emulator, the driver's retries ran first, and a reset
		// transaction would keep the mutations they replay, which f
		// buffers again: it runs as a new one.
		if w.kept && !spannerurl.Emulator() {
			if spResetForRetry(ctx, conn, w.duringCommit) == nil {
				if w.duringCommit {
					// database/sql took the transaction as ended at its
					// commit: BeginTx gives the reset one back.
					w.tx = nil
				}
				continue
			}
		}
		if w.kept && !w.duringCommit {
			w.tx.Rollback()
		}
		w.tx = nil
	}
}

// spEndWrite turns the driver's retries back on for c and returns it to
// its pool, once its transaction has ended.
func spEndWrite(c *sql.Conn) {
	spSetRetries(c, true)
	c.Close()
}

// spSetRetries turns the driver's retries of aborted transactions on c on
// or off.
func spSetRetries(c *sql.Conn, on bool) error {
	return c.Raw(func(dc any) error {
		sc, err := spannerurl.Conn(dc)
		if err != nil {
			return err
		}
		return sc.SetRetryAbortsInternally(on)
	})
}

// spMaxWriteAttempts bounds the runs of a write transaction on Spanner
// (update1). Spanner aborts a transaction to break a deadlock or for an
// older one that needs its locks (wound-wait), and expects it to run again,
// as its client library does until the context ends; the emulator aborts
// any that overlaps another. So aborts are retried far more often than
// maxWriteAttempts allows, after spannerBackoff's pauses: 64 runs wait up
// to about a minute in all.
const spMaxWriteAttempts = 64

// spannerBackoff pauses before the attempt after attempt of a write
// transaction Spanner aborted: a random time up to 10 ms × 2^attempt, at
// most a second.
func spannerBackoff(ctx context.Context, attempt int) {
	d := min(10*time.Millisecond<<min(attempt, 7), time.Second)
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(mrand.Int64N(int64(d)))):
	}
}

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
			_, err := t.Tx.Exec(q, pgArgs(args, t.e.spanner)...)
			t.must(err)
			continue
		}
		rs, err := t.Tx.Query(q, pgArgs(args, t.e.spanner)...)
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

// spannerConflict is isConflict for a unique violation from Spanner.
func spannerConflict(err error) bool {
	var se *spanner.Error
	if !errors.As(err, &se) {
		return false
	}
	for _, s := range spConflictIndexes {
		if strings.Contains(se.Error(), s) {
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

// spReadTimestamp is the read timestamp of the read-only transaction open
// on c, once it has read, in Unix microseconds: every transaction that committed
// before it is visible to it, every later one commits after it (Spanner's
// external consistency). Microseconds truncate Spanner's nanoseconds,
// which only moves it earlier.
func spReadTimestamp(c *sql.Conn) (int64, error) {
	var ts time.Time
	err := c.Raw(func(dc any) error {
		sc, err := spannerurl.Conn(dc)
		if err != nil {
			return err
		}
		ts, err = sc.ReadOnlyTransactionTimestamp()
		return err
	})
	if err != nil {
		return 0, err
	}
	return ts.UnixMicro(), nil
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
// one, since Spanner has no data-modifying CTEs. The entries' seqs are
// taken above the head, ascending (seqGen). It returns their seqs.
//
// The entries and their head_history rows are mutations, buffered and sent
// with the commit (spBuffer), each entry's committed set to the commit's
// timestamp there, which the tailer reads by: no round trip of their own,
// and no statement of the transaction writes a pending commit timestamp,
// after which Spanner refuses reads of the table in the same transaction.
// Mutations are not read back by the transaction's own statements, so
// nothing reads these rows before the commit: the namespace's new head is
// what the transaction reads of its chain from here on (logHeadOf keeps
// it), and the namespace's row, which other reads of it take, is updated
// by a statement.
func (t *tx) appendSpanner(n *nsRow, prevSeq any, configSeq int64, headID ids.ID, rows []spLogRow) []int64 {
	var above int64
	if p, ok := prevSeq.(int64); ok {
		above = p
	}
	seqs := t.spIDs(n.id, above, len(rows))
	ms := make([]*spanner.Mutation, 0, len(rows))
	prev := spNullInt(prevSeq)
	for i, r := range rows {
		ms = append(ms, spanner.Insert("ns_log", spLogCols, []any{
			seqs[i], n.id, r.id, prev, int64(r.kind), spNullInt(r.res), spNullInt(r.target), r.body, configSeq, r.author, t.now.UnixMilli(),
			spNullBytes(r.grantID), spNullInt(r.noAuth), spNullString(r.gestures), spNullString(r.via), spanner.CommitTimestamp, spShard(n.id)}))
		prev = spanner.NullInt64{Int64: seqs[i], Valid: true}
		for _, h := range r.hist {
			ms = append(ms, spanner.Insert("head_history", spHistCols, []any{h.res, seqs[i], h.target}))
		}
	}
	t.wrote()
	t.spBuffer(ms)
	_, err := t.Exec(`UPDATE namespaces SET head_seq = ?, head_id = ?, config_seq = ? WHERE ns = ?`, seqs[len(seqs)-1], headID[:], configSeq, n.id)
	t.must(err)
	return seqs
}

// The columns of appendSpanner's mutations.
var (
	spLogCols  = []string{"seq", "ns", "id", "prev_seq", "kind", "res", "target_seq", "body", "config_seq", "author", "created", "grant_id", "no_auth", "gestures", "via", "committed", "shard"}
	spHistCols = []string{"res", "ns_seq", "target_seq"}
)

// spShards is how many shards ns_log_committed_by_shard, the tailer's
// index, is split into: every append writes at the tail of its entries'
// shard, by commit timestamp, so the appends of the deployment spread
// over this many points of the index rather than one (tailPollSpanner
// reads each).
const spShards = 32

// spShardList lists every shard, for the tailer's IN.
var spShardList = func() string {
	var b strings.Builder
	for i := range spShards {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(i))
	}
	return b.String()
}()

// spShard is a namespace's shard of the tailer's index: the top bits of
// its key, a bit-reversed identity, spread evenly.
func spShard(ns int64) int64 { return int64(uint64(ns) >> (63 - 5)) }

// spBuffer buffers mutations in the write transaction, sent with its
// commit (beginWrite's connection).
func (t *tx) spBuffer(ms []*spanner.Mutation) {
	if len(ms) == 0 {
		return
	}
	if t.sp == nil {
		panic(errors.New("mutations outside a write transaction"))
	}
	t.must(t.sp.Raw(func(dc any) error {
		return dc.(spannerdriver.SpannerConn).BufferWrite(ms)
	}))
}

// spDMLBatch runs q, a statement with ? placeholders, once per row of
// args, all sent to Spanner as one batch of DML (ExecuteBatchDml): one
// round trip, where a statement per row would take one each. It returns
// the rows they affected in all.
func (t *tx) spDMLBatch(q string, args [][]any) int64 {
	t.wrote()
	q = rebind(q)
	t.counted(q)
	t.must(t.sp.Raw(func(dc any) error { return dc.(spannerdriver.SpannerConn).StartBatchDML() }))
	ok := false
	defer func() {
		if !ok {
			t.sp.Raw(func(dc any) error { return dc.(spannerdriver.SpannerConn).AbortBatch() })
		}
	}()
	for _, a := range args {
		_, err := t.Tx.Exec(q, pgArgs(a, true)...)
		t.must(err)
	}
	var n int64
	t.must(t.sp.Raw(func(dc any) error {
		r, err := dc.(spannerdriver.SpannerConn).RunDmlBatch(t.ctx)
		if err != nil {
			return err
		}
		n, err = r.RowsAffected()
		return err
	}))
	ok = true
	return n
}

// spMoveHeads is moveHeads on Spanner, whose UPDATE … FROM it lacks: one
// UPDATE for the rows (up to spMaxArgs's worth), each column a CASE on the
// row's key. A batch of DML (spDMLBatch) of an UPDATE per row was one round
// trip, but Spanner runs a batch's statements one after another: 50 rows
// took 157 ms, most of a group commit's transaction (docs/SPANNER.md, the
// bench). Each row of rows is moveHeads's: head, state, snap_revs,
// snap_bytes, res, old (the head the precondition matched, 0 for none). It
// returns the rows updated.
func (t *tx) spMoveHeads(rows [][]any) int64 {
	if len(rows) == 0 {
		return 0
	}
	t.wrote()
	per := spMaxArgs / 6
	var n int64
	for len(rows) > 0 {
		chunk := rows[:min(per, len(rows))]
		rows = rows[len(chunk):]
		var args []any
		arg := func(v any) string {
			args = append(args, v)
			return "$" + strconv.Itoa(len(args))
		}
		keys := make([]string, len(chunk))
		for i, r := range chunk {
			keys[i] = arg(r[4])
		}
		cases := func(col int) string {
			var b strings.Builder
			b.WriteString("CASE res")
			for i, r := range chunk {
				b.WriteString(" WHEN " + keys[i] + " THEN " + arg(r[col]))
			}
			b.WriteString(" END")
			return b.String()
		}
		q := `UPDATE resources SET head_seq = ` + cases(0) + `, state = ` + cases(1) + `, snap_revs = ` + cases(2) + `, snap_bytes = ` + cases(3) +
			` WHERE res IN (` + strings.Join(keys, ", ") + `) AND COALESCE(head_seq, 0) = ` + cases(5)
		t.counted(q)
		r, err := t.Tx.Exec(q, pgArgs(args, true)...)
		t.must(err)
		k, err := r.RowsAffected()
		t.must(err)
		n += k
	}
	return n
}

// spNullInt, spNullBytes and spNullString are a nullable argument (nil, or
// a value) as a mutation's column value.
func spNullInt(v any) spanner.NullInt64 {
	switch x := v.(type) {
	case int64:
		return spanner.NullInt64{Int64: x, Valid: true}
	case int:
		return spanner.NullInt64{Int64: int64(x), Valid: true}
	case nil:
		return spanner.NullInt64{}
	case spanner.NullInt64:
		return x
	}
	panic(fmt.Errorf("not an integer: %T", v))
}

func spNullBytes(v any) []byte {
	switch x := v.(type) {
	case []byte:
		return x
	case nil:
		return nil
	}
	panic(fmt.Errorf("not bytes: %T", v))
}

func spNullString(v any) spanner.NullString {
	switch x := v.(type) {
	case string:
		return spanner.NullString{StringVal: x, Valid: true}
	case nil:
		return spanner.NullString{}
	}
	panic(fmt.Errorf("not a string: %T", v))
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
func aborted(err error) bool { return sqlState(err) == "40001" }

// failedTx reports a statement refused because an earlier one failed the
// transaction (25P02). Some reads take an error for an answer (no such
// row: authorID, for one); on Spanner that error may have been an abort,
// so a write transaction refused so runs again (update1).
func failedTx(err error) bool { return sqlState(err) == "25P02" }

// drawsSpanner is drawsOnce on Spanner: rate_draws (migration
// 031_rate_draws_batched), which Spanner can't hold as a function, as one
// read-write transaction. It reads every bucket of the batch FOR UPDATE,
// which locks a key whether or not its row exists (Spanner's transactions
// are serializable): a bucket never drawn on is full, as of the first
// request that draws on it. Then it judges the requests in queue order as
// rate_draws does, each after the ones before it, and writes each changed
// row once, as a mutation sent with the commit. So a batch is one read and
// the commit. A deadlock between batches aborts one, which runs again
// (drawBatch).
func (s *bucketStore) drawsSpanner(ctx context.Context, b []*drawReq) ([]drawRes, bool, error) {
	type bucket struct {
		tokens      float64
		last        int64
		rate, burst float64
		changed     bool
	}
	buckets := map[string]*bucket{}
	var keys [][]byte
	for _, r := range b {
		for _, d := range r.ds {
			if _, ok := buckets[d.key]; ok {
				continue
			}
			// Full, as of the first request that draws on it, unless read.
			buckets[d.key] = &bucket{tokens: d.rate.Burst, last: r.now.UnixMicro(), rate: d.rate.Rate, burst: d.rate.Burst}
			keys = append(keys, []byte(d.key))
		}
	}
	res := make([]drawRes, len(b))
	err := func() error {
		conn, err := s.db.Conn(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
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
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
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
		var ms []*spanner.Mutation
		for _, k := range keys {
			if p := buckets[string(k)]; p.changed {
				ms = append(ms, spanner.InsertOrUpdate("rate_buckets", []string{"key", "tokens", "last", "rate", "burst"}, []any{k, p.tokens, p.last, p.rate, p.burst}))
			}
		}
		if len(ms) > 0 {
			if err := conn.Raw(func(dc any) error {
				sc, err := spannerurl.Conn(dc)
				if err != nil {
					return err
				}
				return sc.BufferWrite(ms)
			}); err != nil {
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
