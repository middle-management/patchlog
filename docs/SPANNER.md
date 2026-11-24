# Spanner (PostgreSQL interface)

The core can store in a Google Cloud Spanner database of the PostgreSQL dialect, reached
through [PGAdapter](https://github.com/GoogleCloudPlatform/pgadapter), which speaks the
Postgres wire protocol. This is the first phase: `patchlog serve` runs on it, migrations apply,
writes and reads work, and part of the Postgres test suite passes, all against the **Spanner
emulator**, which checks semantics only: its locking is not Spanner's, and it says
nothing about performance. Nothing here has run on a real Spanner instance yet.

It is the Postgres backend of Addendum D.8 with the differences below; read this beside D.8
(README "Postgres (D.8)", `internal/core/pglock.go`, `tailer.go`, `groupcommit.go`).

## Using it

```sh
# The emulator with PGAdapter in front of it, on 127.0.0.1:5432; any database name is
# created on first connect.
docker run -d --name pgspanner --network host gcr.io/cloud-spanner-pg-adapter/pgadapter-emulator

./patchlog serve --dev --blob-dir ./blobs \
  --db 'spanner+postgres://x@127.0.0.1:5432/patchlog?sslmode=disable'

# Tests: the Postgres-family tests, each in a database of a pool on the emulator.
PATCHLOG_TEST_SPANNER='postgres://x@127.0.0.1:5432/x?sslmode=disable' make test-spanner
```

- **The URL.** PGAdapter is indistinguishable from Postgres on the wire, so the scheme says it:
  `spanner+postgres://` is a Postgres URL (pgx gets `postgres://`), with `e.spanner` set beside
  `e.pg`. The pool parameters (`pool_max_conns`, `pool_max_conn_idle_time`) work as on Postgres.
- **Blobs** need `--blob-dir`: a Spanner cell holds at most 10 MiB, less than `maxBlobSize`.
- **Rate buckets** are shared, as on Postgres, but drawn by statements from Go
  (`drawsSpanner`), since Spanner has no functions for `rate_draws`.

## How each Postgres mechanism maps

| Postgres (D.8) | Spanner | Where |
| --- | --- | --- |
| Schema, `migrations/postgres` through mmmigrate, transactional DDL under an advisory lock | `migrations/spanner`, one baseline equal to Postgres after 031, applied by `dbmigrate.MigrateSpanner`: DDL batched (`START BATCH DDL`) outside transactions, every statement `IF NOT EXISTS` so a half-applied migration runs again, recorded in `mmmigrate_applied`; no lock (instances starting together both run it, harmlessly) | `internal/dbmigrate/spanner.go` |
| `smallint` flags and codes | `bigint` (no `int2`); still compared with 0 and 1 | baseline |
| `UNIQUE` constraints | unique indexes; on nullable columns `WHERE col IS NOT NULL`, since Spanner's unique indexes count NULLs equal | baseline |
| Partial unique indexes `one_first`, `one_ns_first`, `one_config_genesis` | a stored generated column holding the chain's key on its first row only (`CASE WHEN first = 1 THEN res END`), under a null-filtered unique index: Spanner filters partial indexes on `IS NOT NULL` alone | baseline |
| `COLLATE "C"` indexes and comparisons | dropped: Spanner orders text by UTF-8 bytes, the order they exist for (§7.4) | `reads.go`, `nslist.go`, `nsconfig.go` |
| Identity keys | bit-reversed identities (`BIT_REVERSED_POSITIVE`) for keys whose order means nothing (namespaces, resources, authors, cdn_repurge); explicit ids for the chain-ordered tables (below) | baseline, `spanner.go` |
| `ns_log.seq`, `revisions.seq`, `ns_config.seq`, `archives.seq` grow along their chains (identities assigned under the log lock) | taken from per-table blocks of `id_blocks`, 1024 at a time, between transactions; each id above its chain's head; a transaction whose block can't give one rolls back (`errIDBlock`), takes a new block and runs again | `idBlocks` |
| `pg_advisory_xact_lock_shared(ns)`: a resource write's namespace, every namespace a decision read | nothing taken: reading the namespace's row in the read-write transaction holds a shared lock on it until commit | `tx.locking` |
| `pg_advisory_xact_lock(ns)`: config writes, purges, prunes, branches | the namespace's row read `FOR UPDATE` (`spLockRow`, `nsForWrite`) | `pglock.go` |
| The log lock `pg_advisory_xact_lock(logClass, ns)`, taken last, held through commit | the head read `SELECT head_seq, head_id … FOR UPDATE` just before the append (`logHeadOf`); entries of one chain are appended one transaction at a time, in chain order | `engine.go` |
| Try-locks below held keys and `errRelock` restarts | none: nothing is tried, so no restart; deadlocks are Spanner's to break (wound-wait aborts the younger), and an aborted transaction runs again (`retryable`, SQLSTATE 40001) after a random pause doubling per attempt (`spannerBackoff`). A transaction refused with 25P02 runs again too: a few reads take an error for "no such row", which on Spanner may have been an abort | `pglock.go`, `engine.go` |
| `READ COMMITTED` writes, every namespace read after its lock | `SERIALIZABLE`, Spanner's only isolation for writes: a read sees the latest commit and keeps it locked, so namespace rows a write read stay as read (`snapshotRows`) | `chain.go` |
| `REPEATABLE READ READ ONLY` reads | read-only transactions: one strong snapshot | `engine.go` |
| Tailer: `xid >= from AND xid < pg_snapshot_xmin(pg_current_snapshot())` | `ns_log.committed`, the transaction's `spanner.pending_commit_timestamp()`; a poll reads `committed > from` in a read-only transaction and moves `from` to that transaction's read timestamp | `tailer.go` |
| `SyncTail`: `pg_snapshot_xmax` | the read timestamp of a strong read made now | `tailer.go` |
| `cache_gen` | the same row, read in the poll's snapshot | |
| Leader: session lock `pg_try_advisory_lock(leaderClass, 0)` on a kept connection | a lease row, `leader_lease`, taken when expired, renewed at each tick and each job step; 60 s | `leaderSpanner` |
| Shared rate buckets, `rate_draws` (a plpgsql function) | the same algorithm in Go, in one read-write transaction per batch: missing buckets inserted, all read `FOR UPDATE`, requests judged in queue order, changed rows upserted in one statement; an aborted batch runs again. The sweep of full buckets has no `SKIP LOCKED`: it deletes in a transaction of its own, and a draw it meets aborts one of them | `drawsSpanner`, `ratebuckets.go` |
| Group commit | unchanged: one transaction appends a group's entries, and the log heads it appended stay known under the row's lock | `groupcommit.go` |
| Bulk statements: `unnest` of one array per column | each column's array subscripted by an `unnest` of ordinals, `($1::bigint[])[u.i] … FROM unnest($k::bigint[]) AS u(i)` (no `unnest` of several arrays); `UPDATE … FROM` (`moveHeads`) runs once per row | `bulk.go` |
| Data-modifying CTEs (`appendNS`'s one statement) | three statements: the entries (multi-row `VALUES`, the commit timestamp only allowed there), the namespace's head, head_history | `appendSpanner` |
| `LATERAL`, `WITH RECURSIVE`, window functions, `generate_series` | correlated scalar subqueries; a chain of bases read a statement per level; a purge's candidates searched level by level (`purgeLevels`), never from the name's holders; the Postgres-only multi-namespace purge append isn't used | `resolve.go`, `chain.go`, `nspurge.go` |
| `ON CONFLICT DO NOTHING` without a target | the primary key named (shared with the other dialects); on a secondary index, Spanner refuses a conflict target, so a plain insert, whose race aborts or fails the transaction, which runs again | `engine.go` authors, `blobs.go`, `repurge.go` |
| `DO UPDATE SET key = excluded.key` row touches | Spanner updates no key column: a non-key column set to itself, or an insert then `FOR UPDATE` | `blobs.go` |
| `octet_length(bytea)` | `length(bytea)` | `octetLength` |
| Unique violations carry the table (`isConflict`) | 23505 without a table: the index named in the message (`spConflictIndexes`) | `dialect.go` |
| Planner settings (`set_config`) | none | `nspurge.go` |

### Why the locks are enough

Spanner's read-write transactions are serializable, and lock what they read (shared) and write
(exclusive) until they commit. D.8's advisory locks exist because `READ COMMITTED` is not: they
make every read of a namespace happen under its lock. Here every read in a write transaction is
already under a lock, so the invariants D.8 argues from locks hold by serializability: a
schema purge, a base revocation, a config change, a frozen or purged flag can't commit between a
write's check and its insert, since the write read the rows they change. What the explicit locks
add is order, to wait rather than abort: `FOR UPDATE` takes the exclusive lock when the row is
read, so a config write, purge or appender waits for the writers that hold the row shared,
instead of all taking it shared and aborting one another when they write it.

Two writers of one resource still settle it on insert, as on Postgres: the chain's unique
indexes, or the head moving only from the one the precondition matched (`errChainRace`), or an
abort, after which the transaction runs again and the re-check answers 412 or the idempotent
retry (D.3).

### Why the tailer misses nothing

Spanner's commits are externally consistent: a strong read at timestamp T sees every transaction
that committed at or before T and none after, and a transaction that commits after the read
began gets a timestamp after T, however long it ran. So the commits after one poll's read and up
to the next's are exactly those whose `committed` is in (from, T], and moving `from` to T skips
none. Commit timestamps are read in microseconds, Spanner's nanoseconds truncated: that only
moves `from` earlier, so a poll may see the previous poll's last commits again, which wakes
readers twice (a wake-up is a hint) and flushes caches once more.

### Why the ids grow along their chains

`id_blocks.next` only grows, so a block is above every id handed out before it was taken, by any
instance. A chain's head was handed out before the transaction that appends after it read it
(under the row's lock), so a block taken after that read is above it. An id is taken from the
block in hand only if it is above the head; otherwise, or if the block is short, the transaction
rolls back and takes a new block first. Blocks are never taken inside a write transaction:
there the counter's row would stay locked to commit, serialising every writer (and on the
emulator a block taken beside an open write transaction waited for it forever). Ids are not
dense, and the least `seq` needn't be the deployment's first entry, which is read by commit
timestamp instead (`operatorkeys.go`, `archive.go`).

## What the emulator showed

- Migrations apply to an empty database, and again to a migrated one (`TestMigrateSpanner`).
- `serve --dev` starts. Over HTTP and with the `patchlog` CLI: namespace create and list,
  resource put, patch, get, log, ls, delete and restore, a batch, a branch and a write in it, a
  blob upload and download, a purge, and `watch`, on one instance and across two sharing the
  database (a write on one wakes a long-poll and a watch on the other: the tailer).
- `internal/core` (293 top-level tests, each run on its own, 45–400 s timeout): 233 pass,
  52 skip, 4 fail, 4 time out. Of the skips, 10 skip on Postgres too (store compression, lz4,
  the oracle); the rest test Postgres mechanisms Spanner replaces (advisory locks and their
  order, `rate_draws` and its row locks, the leader's session lock, plpgsql and trigger
  injections, `pg_locks`, plans and statement counts of recursive queries, databases an
  earlier version left). The failures and time-outs are all concurrent: writers that the
  emulator stalls (`TestPGGroupCommitStress`, `…NoDeadlockWithSingleWrite`, `TestPGNoLostUpdates`,
  `TestV073P17SharedBucketsAcrossInstances`, `TestV087FilteredOracle`), and two that expect one
  transaction to wait for another's lock (`TestPGParallelNamespaces`'s config write,
  `TestPGPurgeSkipsBranchPurgedMeanwhile`), where the emulator lets the second go on and aborts
  the first, which runs again. The fourth failure, `TestPGDrawAfterCheck`, fails on Postgres
  too.
- `internal/server`, every sixth of its 594 tests (99): 97 pass; `TestResourceLongPollIsolated`
  fails on its timing (a long-poll reaches its boundary on the slow emulator) and
  `TestV034ConcurrentUploadsPending` (concurrent) times out.
- `internal/dbmigrate` and `internal/pgtest` pass.

## Untested

- **Anything concurrent, on real Spanner.** The emulator does run read-write transactions at
  once, and aborts one of two that conflict (a shared lock upgraded by both, for instance), but
  with a dozen writers of one namespace it stalls them all for minutes: its lock manager is not
  Spanner's. Lock waits, wound-wait aborts, `FOR UPDATE` ordering, and PGAdapter's own retry of
  aborted transactions (which replays the statements and gives up with 40001 if results
  differ) are untested.
- Real Spanner's limits the emulator may not enforce: statement parameters (`spValues` splits at
  900), mutations per commit (a batch of 1,000 items with history is far below 80,000), and
  reading a table in the transaction that wrote a pending commit timestamp into it (the emulator
  allows it; group commit and purges read `ns_log` after appending). If Spanner refuses that,
  the commit timestamp moves to a table of its own that no write transaction reads.
- Instances sharing a database at scale: the leader lease is timed by each instance's clock;
  two instances migrating at once.
- `internal/server` ran in part only; no other package uses the database.

## What is left

- **Hotspots**, before any capacity number means anything. `ns_log_committed` is an index on a
  commit timestamp, written at its tail by every append of the deployment; the chain-ordered
  primary keys come from a counter, so each instance inserts at the end of a key range. Both are
  Spanner's classic hotspots. Likely shapes: shard `ns_log_committed` (a hash of `ns` first, the
  tailer reading every shard), and key the chain tables by their chain (`(res, seq)`,
  `(ns, seq)`) with seq dense per chain, which also retires `id_blocks`.
- **The rate-bucket sweep** scans `rate_buckets` whole (no `SKIP LOCKED`, and no index on
  fullness); fine for a test, a hot table at scale.
- **Purge holder search** (`purgeHolders`) without recursive queries: the purge now reads every
  branch below the purged namespace, level by level, which is fine for few branches only.
- **Round trips**: `moveHeads` runs once per row and an append is three statements; PGAdapter's
  `START BATCH DML` could send them together.
- **Migration concurrency**: a lease, as for the leader, if instances must not both migrate.
- The concurrency above, on a real instance.

## A capacity bench on real Spanner would need

- an instance (regional, a few nodes or 1,000+ processing units to start), a PGAdapter beside
  each core instance (sidecar), and the cores in the same region;
- the hotspot changes above, or the bench measures the counter and the timestamp index;
- `cmd/capacity` pointed at `spanner+postgres://`, and the D.8 contention runs (one namespace,
  many namespaces, group sizes) for Postgres comparison in `docs/CAPACITY.md`;
- Spanner's lock-wait and abort metrics (Query/Transaction/Lock statistics tables), and
  PGAdapter's retry counts, beside patchlog's own group-commit metrics.
