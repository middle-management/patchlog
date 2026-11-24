# Spanner (PostgreSQL dialect)

The core can store in a Google Cloud Spanner database of the PostgreSQL dialect. It talks to
Spanner with Spanner's own Go driver, [go-sql-spanner](https://github.com/googleapis/go-sql-spanner),
through `database/sql` for the statements it shares with Postgres, and through the driver's
Spanner connection where Spanner offers more: mutations sent with the commit, DML batches, the
commit and read timestamps. `patchlog serve` runs on it, migrations apply, writes and reads work,
and most of the Postgres test suite passes, all against the **Spanner emulator**, which checks
semantics only: it runs one read-write transaction at a time, and says nothing about
performance. Nothing here has run on a real Spanner instance yet; `deploy/gcp-spanner.sh` is
the bench that will.

It is the Postgres backend of Addendum D.8 with the differences below; read this beside D.8
(README "Postgres (D.8)", `internal/core/pglock.go`, `tailer.go`, `groupcommit.go`).

## Using it

```sh
# The emulator, its gRPC on localhost:9010 (this image also runs PGAdapter on
# 5432, which the core no longer uses). Any database named is created on the
# first connection, of the PostgreSQL dialect.
docker run -d --name spanner --network host gcr.io/cloud-spanner-pg-adapter/pgadapter-emulator
export SPANNER_EMULATOR_HOST=localhost:9010

./patchlog serve --dev --blob-dir ./blobs \
  --db 'spanner://projects/emulator-project/instances/test-instance/databases/patchlog'

# Tests: the Postgres-family tests, each in a database of a pool on the instance.
PATCHLOG_TEST_SPANNER=spanner://projects/emulator-project/instances/test-instance make test-spanner
```

- **The URL** is `spanner://projects/P/instances/I/databases/D` (`internal/spannerurl`). Its
  query parameters go to the driver as connection properties, but for the engine's own pool
  parameters (`pool_max_conns`, `pool_max_conn_idle_time`), which work as on Postgres. With
  `SPANNER_EMULATOR_HOST` set, the driver connects to the emulator and creates the instance and
  the database if they don't exist. Off the emulator it authenticates with Application Default
  Credentials and needs `roles/spanner.databaseUser`.
- **Blobs** need `--blob-dir`: a Spanner cell holds at most 10 MiB, less than `maxBlobSize`.
- **Rate buckets** are shared, as on Postgres, but drawn by Go (`drawsSpanner`), since Spanner
  has no functions for `rate_draws`.
- **The driver** is wrapped (`spannerurl.Open`) so that a NULL `bytea` reads as NULL: go-sql-spanner
  gives it as a nil `[]byte`, which `database/sql` takes for an empty value. Arguments are named
  for their placeholders (`p1` for `$1`, `pgArgs`): the driver gives unnamed arguments to the
  placeholders in the order they appear in the statement, whatever their numbers.

## How each Postgres mechanism maps

| Postgres (D.8) | Spanner | Where |
| --- | --- | --- |
| Schema, `migrations/postgres` through mmmigrate, transactional DDL under an advisory lock | `migrations/spanner`, one baseline equal to Postgres after 031 and 002 for the hotspots, applied by `dbmigrate.MigrateSpanner`: DDL batched (`START BATCH DDL`) outside transactions, every statement `IF NOT EXISTS` so a half-applied migration runs again, recorded in `mmmigrate_applied`; no lock (instances starting together both run it, harmlessly) | `internal/dbmigrate/spanner.go` |
| `smallint` flags and codes | `bigint` (no `int2`); still compared with 0 and 1 | baseline |
| `UNIQUE` constraints | unique indexes; on nullable columns `WHERE col IS NOT NULL`, since Spanner's unique indexes count NULLs equal | baseline |
| Partial unique indexes `one_first`, `one_ns_first`, `one_config_genesis` | a stored generated column holding the chain's key on its first row only (`CASE WHEN first = 1 THEN res END`), under a null-filtered unique index: Spanner filters partial indexes on `IS NOT NULL` alone | baseline |
| `COLLATE "C"` indexes and comparisons | dropped: Spanner orders text by UTF-8 bytes, the order they exist for (§7.4) | `reads.go`, `nslist.go`, `nsconfig.go` |
| Identity keys | bit-reversed identities (`BIT_REVERSED_POSITIVE`) for keys whose order means nothing (namespaces, resources, authors, cdn_repurge); explicit ids for the chain-ordered tables (below) | baseline, `spanner.go` |
| `ns_log.seq`, `revisions.seq`, `ns_config.seq`, `archives.seq` grow along their chains (identities assigned under the log lock) | made in Go, no table (`seqGen`): `bucket (8 bits) | ms (41) | count (14)`, the bucket the top bits of the chain's first key, so inserts spread over 256 points of each table instead of its end; each id above its chain's head, read under the row's lock | `seqGen` |
| Ids in insertion order across chains (the gesture listing, §7.4) | the ids' low bits, time then an instance's count (`spWriteOrder`) | `gestures.go` |
| `pg_advisory_xact_lock_shared(ns)`: a resource write's namespace, every namespace a decision read | nothing taken: reading the namespace's row in the read-write transaction holds a shared lock on it until commit | `tx.locking` |
| `pg_advisory_xact_lock(ns)`: config writes, purges, prunes, branches | the namespace's row read `FOR UPDATE` (`spLockRow`, `nsForWrite`) | `pglock.go` |
| The log lock `pg_advisory_xact_lock(logClass, ns)`, taken last, held through commit | the head read `SELECT head_seq, head_id … FOR UPDATE` just before the append (`logHeadOf`); entries of one chain are appended one transaction at a time, in chain order | `engine.go` |
| Try-locks below held keys and `errRelock` restarts | none: nothing is tried, so no restart; deadlocks are Spanner's to break (wound-wait aborts the younger) | `pglock.go` |
| A write rolled back on a deadlock or serialization failure runs again, at most 8 times | an aborted write (40001, or 25P02 after one) runs again on its own connection as the **same transaction**, reset by the driver's `resetTransactionForRetry`, which keeps its lock priority (wound-wait), after a random pause doubling up to a second, at most 64 times (`update1Spanner`); the driver's own retries, which replay the statements, are off for it. On the emulator they stay on, and a write aborted past them runs as a new transaction (below) | `spanner.go` |
| `READ COMMITTED` writes, every namespace read after its lock | `SERIALIZABLE`, Spanner's only isolation for writes: a read sees the latest commit and keeps it locked, so namespace rows a write read stay as read (`snapshotRows`) | `chain.go` |
| `REPEATABLE READ READ ONLY` reads | read-only transactions: one strong snapshot | `engine.go` |
| The append: one statement (a data-modifying CTE) for the entries, the namespace's head and head_history | the entries and head_history rows as **mutations** buffered in the transaction and sent with its commit, each entry's `committed` the commit's timestamp; the namespace's head one `UPDATE` | `appendSpanner` |
| Tailer: `xid >= from AND xid < pg_snapshot_xmin(pg_current_snapshot())` | `ns_log.committed`, the commit timestamp; a poll reads `committed > from` from each of the 32 shards of `ns_log_committed_by_shard` (`shard`, the top bits of `ns`) in a read-only transaction and moves `from` to its read timestamp | `tailer.go` |
| `SyncTail`: `pg_snapshot_xmax` | the read timestamp of a strong read made now | `tailer.go` |
| `cache_gen` | the same row, read in the poll's snapshot | |
| Leader: session lock `pg_try_advisory_lock(leaderClass, 0)` on a kept connection | a lease row, `leader_lease`, taken when expired, renewed at each tick and each job step; 60 s | `leaderSpanner` |
| Shared rate buckets, `rate_draws` (a plpgsql function) | the same algorithm in Go, in one read-write transaction per batch: all buckets read `FOR UPDATE` (which locks a missing key too: a missing bucket is full), requests judged in queue order, changed rows written as `InsertOrUpdate` mutations with the commit: one read and the commit; an aborted batch runs again. The sweep of full buckets has no `SKIP LOCKED`: it deletes in a transaction of its own, and a draw it meets aborts one of them | `drawsSpanner`, `ratebuckets.go` |
| Group commit | unchanged: one transaction appends a group's entries (mutations), and the log heads it appended stay known under the row's lock | `groupcommit.go` |
| Bulk statements: `unnest` of one array per column | each column's array subscripted by an `unnest` of ordinals, `($1::bigint[])[u.i] … FROM unnest($k::bigint[]) AS u(i)` (no `unnest` of several arrays); a statement without that form (`moveHeads`, `UPDATE … FROM`) runs once per row, its rows sent as **one batch of DML** (one round trip) | `bulk.go`, `spDMLBatch` |
| `LATERAL`, `WITH RECURSIVE`, window functions, `generate_series` | correlated scalar subqueries, or arrays subscripted by ordinals; a chain of bases read a statement per level; a purge's holders found by name as on Postgres (`purgeHolders`: sealed copies and sealings by `DISTINCT` over their `(name, ns)` index, the holders' chains a level per statement), and level by level from the purged namespace past `purgeHoldersMax` holders (`purgeLevels`); the Postgres-only multi-namespace purge append isn't used | `resolve.go`, `chain.go`, `nspurge.go` |
| `ON CONFLICT DO NOTHING` without a target | the primary key named (shared with the other dialects); on a secondary index, Spanner refuses a conflict target, so a plain insert, whose race aborts or fails the transaction, which runs again | `engine.go` authors, `blobs.go`, `repurge.go` |
| `DO UPDATE SET key = excluded.key` row touches | Spanner updates no key column: a non-key column set to itself, or an insert then `FOR UPDATE` | `blobs.go` |
| `octet_length(bytea)` | `length(bytea)` | `octetLength` |
| Unique violations carry the table (`isConflict`) | 23505 (the driver's SQLSTATE for `AlreadyExists`) without a table: the index named in the message (`spConflictIndexes`) | `dialect.go` |
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

### Why an aborted write runs again as the same transaction

Spanner breaks lock conflicts by age (wound-wait): an older transaction that needs a lock a
younger one holds aborts it, and a younger one waits for an older. A transaction run again as a
new one is younger than every transaction it lost to, and under steady contention can lose to
them again and again. The driver's `resetTransactionForRetry` (what its `RunTransaction` calls
between attempts) starts the next attempt on the same session as one that inherits the aborted
one's priority. The engine runs its function again on it, reading anew; the driver's own
retries, which would replay the statements and give up when a read differs (after a contended
abort, the head the write read has moved), are off. The driver exports only the loop, which
takes a function of a `*sql.Tx`, while the engine's writes need the connection too (mutations),
so the step is linked to by `go:linkname` (`spResetForRetry`): a driver version without it fails
to link, not to run.

On the emulator this can't work: it runs one read-write transaction at a time and aborts any
other, and a write that draws rate tokens while its transaction is open (the draw is a
transaction of its own) is aborted by the draw; run again, it draws again, and is aborted again.
There the driver's replay stays on (it runs the statements again without the draw), as PGAdapter's
did, and a write the replay can't save runs as a new transaction.

### Why the tailer misses nothing

Spanner's commits are externally consistent: a strong read at timestamp T sees every transaction
that committed at or before T and none after, and a transaction that commits after the read
began gets a timestamp after T, however long it ran. So the commits after one poll's read and up
to the next's are exactly those whose `committed` is in (from, T], and moving `from` to T skips
none. Commit timestamps are read in microseconds, Spanner's nanoseconds truncated: that only
moves `from` earlier, so a poll may see the previous poll's last commits again, which wakes
readers twice (a wake-up is a hint) and flushes caches once more. The entries are written as
mutations, so no statement writes a pending commit timestamp, after which Spanner refuses reads
of the table in the same transaction.

### Why the ids grow along their chains, and spread

`seqGen` makes an id of a bucket, the milliseconds since 2026 and a count. A chain keeps the
bucket of its first row's key (a branch's chain goes on from its base's, so it keeps the base's),
and an id is taken above the chain's head, read under the row's lock, so ids grow along a chain
whatever the clocks of the instances appending to it. The keys the buckets come from are
bit-reversed identities, whose top bits are spread evenly, so each table's inserts land at 256
points of its key range rather than at its end. An instance's count is one for all buckets, so
its ids also order its writes across chains (`spWriteOrder`). Two instances can make the same id
in one bucket and millisecond, rarely: the second to commit fails on the primary key, a unique
violation of no chain, and runs again. Ids are not dense, and the least `seq` needn't be the
deployment's first entry, which is read by commit timestamp instead (`operatorkeys.go`,
`archive.go`).

This keeps the shared SQL, which uses a seq as a row's identity everywhere. Keying the chain
tables by `(res, seq)` and `(ns, seq)` with dense per-chain seqs, the other way to spread them,
would change most of it.

## What the emulator showed

- Migrations apply to an empty database, and again to a migrated one (`TestMigrateSpanner`), in
  half a second (PGAdapter: several).
- `serve --dev` starts. Over HTTP and with the `patchlog` CLI: namespace create and list,
  resource put, patch, get, log, ls, delete and restore, a batch, a branch and a write in it, a
  blob upload and download, a purge, and `watch`, on one instance and across two sharing the
  database (a write on one wakes a long-poll and a watch on the other: the tailer).
- `internal/core` (310 top-level tests, each run on its own, 280 s timeout): 297 pass or skip
  (at least 46 skip: Postgres mechanisms Spanner replaces, or skipped on Postgres too), 10 fail
  and 3 time out. Rerun on the final code, six of those pass or skip as they should (the
  gesture and purge-order listings, two tests' orderings by a bit-reversed key, a Postgres-only
  `pg_settings` test, and one flake). Left, all concurrent: writers the emulator stalls
  (`TestPGGroupCommitStress`, `TestPGNoLostUpdates`, `TestV087FilteredOracle` time out), and
  tests that expect one transaction to wait for another's lock, where the emulator aborts one
  (`TestPGParallelNamespaces`, `TestPGPurgeSkipsBranchPurgedMeanwhile`,
  `TestPGGroupCommitNoDeadlockWithSingleWrite`); and `TestPGDrawAfterCheck`, which fails on
  Postgres too. `TestV073P17SharedBucketsAcrossInstances`, which timed out through PGAdapter,
  passes.
- `internal/server`, every sixth test (100): 95 pass or skip. Three more failed on tests that
  opened the database with pgx themselves, or wrote an untyped literal Spanner can't type in a
  `SELECT` list; fixed (`pgtest.Driver`), they pass. Left, as through PGAdapter:
  `TestResourceLongPollIsolated` fails on its timing (a long-poll reaches its boundary on the
  slow emulator), and `TestV034ConcurrentUploadsPending` (concurrent) times out.
- `internal/dbmigrate` and `internal/pgtest` pass.

## Untested

- **Anything concurrent, on real Spanner.** The emulator runs one read-write transaction at a
  time: lock waits, wound-wait aborts, `FOR UPDATE` ordering, the same-transaction retry
  (`spResetForRetry`) under contention, and two instances making one id are untested.
- Real Spanner's limits the emulator may not enforce: statement parameters (`spValues` splits at
  900), mutations per commit (a batch of 1,000 items with history is far below 80,000).
- Instances sharing a database at scale: the leader lease is timed by each instance's clock;
  two instances migrating at once.
- `internal/server` ran in part only (every sixth test); no other package uses the database.

## What is left

- **A run of `deploy/gcp-spanner.sh`**, and what it finds.
- **The rate-bucket sweep** scans `rate_buckets` whole (no `SKIP LOCKED`, and no index on
  fullness); fine for a test, a hot table at scale.
- **Round trips** left in a write: the namespace's head `UPDATE` (a mutation would hide the new
  head from the transaction's own later reads), and a chain of bases read a statement per level.
- **Migration concurrency**: a lease, as for the leader, if instances must not both migrate.
- **mmmigrate**: a Spanner driver there would replace `dbmigrate.MigrateSpanner`.

## The capacity bench on real Spanner

`deploy/gcp-spanner.sh` (header: settings, what it makes, `cleanup`) runs the D.8 comparison on
Google Cloud: a regional Spanner instance (1,000 processing units by default), `SERVERS` cores on
Compute Engine in the same region (2 × `c3-standard-8`, `pool_max_conns=48`, `--group-commit 128`,
as the best Postgres run), and a loader running `cmd/capacity --only namespaces`: 1, 2, 4, 8, 16
and 32 busy namespaces of 100 documents, each written 10 times a second, closed loop, as doors'
`ec2-sources.sh` loads Postgres (without its consumers). After the run it saves Spanner's
statistics of the run's minutes (`spanner_sys.txn_stats_top_minute`, `lock_stats_top_minute`,
`query_stats_top_minute`, `txn_stats_total_minute`) and the instance's CPU beside the harness's
JSON. Compare with `docs/CAPACITY.md`, "Several namespaces on one database": 28,070 writes a
second on RDS `db.m7g.4xlarge`, 20,307 on Aurora Serverless v2, where commit latency to the
storage quorum bound each namespace's log. Spanner's commit latency (a Paxos round across the
region's zones) will bound it the same way, so group size per namespace is the lever to watch.
