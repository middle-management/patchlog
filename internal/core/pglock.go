package core

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"math"
	"sort"

	"github.com/jackc/pgx/v5/pgconn"
)

// Write serialisation on Postgres (Addendum D.8).
//
// SQLite has one writer at a time: Engine.mu and BEGIN IMMEDIATE. On
// Postgres several instances share the database, writers of different
// namespaces run in parallel, and so do writers of different resources of
// one namespace. Every write transaction holds transaction-scoped advisory
// locks, pg_advisory_xact_lock(lockClass, ns):
//
//   - exclusive on every namespace whose configuration or rows beyond its
//     resources' chains it changes: a config write, a purge, a prune, a
//     branch or freeze, the base that receives a branch entry, every
//     branch and remote shadow a purge propagates to, a blob upload;
//   - shared on the namespace a resource write or batch (without a config
//     change) appends to (nsForResources), and on every other namespace
//     whose state a decision read (nsByName, nsByID): the bases whose keys
//     and revocations a branch write re-checks (§C.4), the namespaces its
//     $schema and $ref resolve into (§6.1), a requireAt's or a batch
//     source's namespace. A schema purge, a base revocation, a config
//     change, a frozen or purged flag therefore can't commit between a
//     write's check and its insert, and READ COMMITTED is enough: every
//     read of a namespace happens after its lock is held.
//
// What a shared lock leaves to the writers of one namespace to settle
// among themselves:
//
//   - their resources' chains. Two writers of one resource may both pass
//     their check; the first to insert wins. The other fails on the
//     chain's unique constraints (revisions (res, parent_seq) and (res,
//     id), the one first revision, resources (ns, name)), waiting for the
//     winner to commit, or on the head it moves from (insertItem updates
//     the resources row only from the head its precondition matched:
//     errChainRace). Either is a conflict (isConflict): the check runs
//     again and answers 412 with the new head, or the idempotent retry,
//     as on the D.3 path (recheck.go).
//   - the namespace chain. Its entry is appended last (appendNS), at the
//     head read with SELECT … FOR NO KEY UPDATE on the namespace row,
//     which waits for a concurrent appender's commit and then reads its
//     head; entry, head and head_history go in one statement. The row
//     lock is held until commit, so entries commit in chain order (the
//     tailer's xid window and readers' snapshots never see a gap) and
//     ns_log.seq grows along the chain. It is taken after every advisory
//     lock, and its holder waits for nothing but its commit, so it adds
//     no deadlock; FOR NO KEY UPDATE doesn't block the foreign-key checks
//     of other writers' inserts.
//
// The namespace's lock is thus held shared for a write's whole check and
// insert, and serialisation per namespace is reduced to two statements and
// the commit (README "Postgres").
//
// Locks are taken in ascending key order, whatever their mode, so writers
// never deadlock on them. A resource write or batch knows its namespaces
// from its check phase (writeDeps) and takes them all before its re-check
// (recheck.go), or checks inside them, taking them as it reads. The rarer
// writes run their whole gate in the transaction and lock as they go: the
// target namespace exclusively first (nsForWrite), then each namespace as
// they read or change it. A lock whose key is above every key held is
// waited for; one below is only tried, and if it is busy the transaction
// rolls back and runs again with every lock it needed taken up front, in
// order (errRelock). A write therefore waits only for keys above the ones
// it holds.
//
// The few rows shared by all namespaces (authors, grants, the grants data
// key, blob bytes) are inserted with ON CONFLICT or retried: a unique
// violation, a deadlock between such row locks and a lock wait, or a
// serialization failure rolls the transaction back and runs it again
// (update1).

// lockClass is the class id of the namespace and schema locks, the first
// argument of the two-argument pg_advisory_*lock forms (D.8), so they never
// collide with other advisory locks in a shared database ("PL" in ASCII).
// leaderClass is the class of the leader lock of the background loops.
const (
	lockClass   = 0x504c
	leaderClass = 0x504d
)

// lockSchema is the key, in lockClass, held while creating or migrating
// the schema. Namespace keys are positive.
const lockSchema = 0

type lockMode int8

const (
	lockShared lockMode = iota + 1
	lockExclusive
)

// maxWriteAttempts bounds how often update1 runs a write transaction that
// rolled back to take its locks in order, or on a deadlock or unique
// violation.
const maxWriteAttempts = 8

// lockKey is a namespace's key in lockClass. The two-argument advisory lock
// functions take int4 keys; ids beyond that range share keys, which only
// serialises more.
func lockKey(ns int64) int32 {
	if ns >= 0 && ns <= math.MaxInt32 {
		return int32(ns)
	}
	return int32((ns^(ns>>31))&math.MaxInt32) | 1
}

// errRelock rolls back a write transaction that needs a lock below one it
// holds and found it busy: it runs again with want taken up front.
type errRelock struct{ want map[int32]lockMode }

func (e *errRelock) Error() string { return fmt.Sprintf("advisory locks out of order: %v", e.want) }

// locking reports whether this transaction takes advisory locks.
func (t *tx) locking() bool { return t.e.pg && t.write && t.noLock == 0 }

// lockNS takes ns's advisory lock in at least mode (see above).
func (t *tx) lockNS(ns int64, mode lockMode) {
	if !t.locking() {
		return
	}
	t.lock(lockKey(ns), mode)
}

func (t *tx) lock(k int32, mode lockMode) {
	if t.locks[k] >= mode {
		return
	}
	if len(t.locks) == 0 || k > t.maxKey {
		t.acquire(k, mode)
		return
	}
	fn := `SELECT pg_try_advisory_xact_lock($1, $2)`
	if mode == lockShared {
		fn = `SELECT pg_try_advisory_xact_lock_shared($1, $2)`
	}
	var ok bool
	t.must(t.Tx.QueryRow(fn, lockClass, k).Scan(&ok))
	if !ok {
		want := map[int32]lockMode{k: mode}
		for k2, m := range t.locks {
			want[k2] = max(want[k2], m)
		}
		panic(&errRelock{want: want})
	}
	t.held(k, mode)
}

// acquire waits for a lock.
func (t *tx) acquire(k int32, mode lockMode) {
	fn := `SELECT pg_advisory_xact_lock($1, $2)`
	if mode == lockShared {
		fn = `SELECT pg_advisory_xact_lock_shared($1, $2)`
	}
	_, err := t.Tx.Exec(fn, lockClass, k)
	t.must(err)
	t.held(k, mode)
}

func (t *tx) held(k int32, mode lockMode) {
	if t.locks == nil {
		t.locks = map[int32]lockMode{}
	}
	t.locks[k] = max(t.locks[k], mode)
	t.maxKey = max(t.maxKey, k)
	t.forget()
}

// lockAll takes several locks in ascending order: all waited for at the
// start of a transaction, or tried as lockNS does below keys already held.
func (t *tx) lockAll(want map[int32]lockMode) {
	if !t.locking() {
		return
	}
	keys := make([]int32, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		t.lock(k, want[k])
	}
}

// lockDeps takes a resource write's or batch's locks before its re-check:
// every namespace its check read shared, its own included (sharedNS).
func (t *tx) lockDeps(target int64, d *writeDeps) {
	want := map[int32]lockMode{lockKey(target): lockShared}
	for id := range d.ns {
		want[lockKey(id)] = lockShared
	}
	t.lockAll(want)
	if t.locking() {
		t.sharedNS = target
	}
}

// retryable reports an error after which a write transaction runs again:
// it needs its locks in order, or Postgres rolled it back for a deadlock or
// a serialization failure, or a unique violation of a row shared by all
// namespaces (a namespace name, an author, the grants data key) that the
// next run finds taken. A lost race of a chain (isConflict) is the caller's
// to handle (D.3).
func retryable(err error) bool {
	var rl *errRelock
	if errors.As(err, &rl) {
		return true
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return false
	}
	switch pe.Code {
	case "40P01", "40001":
		return true
	case "23505":
		return !isConflict(err)
	}
	return false
}

// --- leader -------------------------------------------------------------------

// leader reports whether this instance runs the background loops that must
// run once per deployment (retention, epoch rotation, following remote
// bases): on Postgres, the instance holding the session-level advisory
// lock (leaderClass, 0) on a connection it keeps; on SQLite, always. An
// instance that loses its connection loses the lock, and another one
// takes over at its next tick.
func (e *Engine) leader(ctx context.Context) bool {
	if !e.pg {
		return true
	}
	e.leaderMu.Lock()
	defer e.leaderMu.Unlock()
	if e.leaderConn != nil {
		if err := e.leaderConn.PingContext(ctx); err == nil {
			return true
		}
		log.Printf("background loops: lost the leader connection; another instance may take over")
		e.leaderConn.Raw(func(any) error { return driver.ErrBadConn }) // discards it
		e.leaderConn.Close()
		e.leaderConn = nil
	}
	c, err := e.db.Conn(ctx)
	if err != nil {
		return false
	}
	var ok bool
	if err := c.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1, 0)`, leaderClass).Scan(&ok); err != nil || !ok {
		c.Close()
		return false
	}
	e.leaderConn = c
	return true
}

// resign releases the leader lock (Close).
func (e *Engine) resign() {
	e.leaderMu.Lock()
	defer e.leaderMu.Unlock()
	if e.leaderConn == nil {
		return
	}
	// The connection goes back to the pool: unlock explicitly.
	e.leaderConn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1, 0)`, leaderClass)
	e.leaderConn.Close()
	e.leaderConn = nil
}

// leaderJobKey marks the context of a background job that runs because
// this instance is the leader.
type leaderJobKey struct{}

// leaderJob marks ctx as a leader's background job's: jobStep checks
// before each step that the leader lock is still held.
func leaderJob(ctx context.Context) context.Context {
	return context.WithValue(ctx, leaderJobKey{}, true)
}

// errLostLeader stops a background job whose instance no longer holds the
// leader lock.
var errLostLeader = errors.New("background job: this instance no longer holds the leader lock")

// jobStep is checked before each step of a background job (D.8): a leader
// that lost its session, and so its lock, stops, since another instance
// may already run the job. Steps are idempotent, so one still under way
// when that happens does no harm. Calls outside a leader's job (an
// operator's, or a test's) always proceed, as on SQLite.
func (e *Engine) jobStep(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.pg || ctx.Value(leaderJobKey{}) == nil {
		return nil
	}
	if e.holdsLeader(ctx) {
		return nil
	}
	return errLostLeader
}

// holdsLeader reports whether this instance's leader connection still
// holds the leader lock.
func (e *Engine) holdsLeader(ctx context.Context) bool {
	e.leaderMu.Lock()
	defer e.leaderMu.Unlock()
	if e.leaderConn == nil {
		return false
	}
	var ok bool
	err := e.leaderConn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory'
		AND classid = ($1::bigint)::oid AND objid = 0 AND objsubid = 2 AND pid = pg_backend_pid() AND granted)`, leaderClass).Scan(&ok)
	return err == nil && ok
}
