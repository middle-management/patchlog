# What a write leaves behind

`cmd/capacity -only storage` measures the bytes each write leaves in the database once its
patch set has been pruned (§8.6): the skeleton of a `revisions` row, an `ns_log` row, a
`head_history` row and their index entries, which stay as long as the resource does.

The phase creates one namespace (`cap-storage`) and writes `--storage-writes` single-resource
writes spread evenly over `--storage-resources` resources, all under one grant (the grants
profile, so the rows record a grant as most deployments' do). Each document names its
resource, so no two resources' chains share revision ids. It then waits out the retry window
(`--storage-wait`, 5m10s: a prune keeps what the namespace's `retryWindow`, at least 5
minutes, protects) and prunes every resource to its head, which leaves every revision but the
heads without its patch set (`patches` NULL), as retention does.

It reads the core's database itself (`--storage-db`, the core's `--db`) before the writes and
after the prunes, and reports the difference divided by the number of writes, per table and
index (`objects`, `tables_per_write`) and in all (`bytes_per_write`):

- **SQLite**: the database is copied with `VACUUM INTO` (so pages the prunes freed don't count)
  and each object's pages are summed from the `dbstat` virtual table (`SUM(pgsize)`).
- **Postgres**: after `VACUUM FULL ANALYZE` (a plain `VACUUM` would keep the space the prunes'
  updates left in the files), `pg_relation_size` of each table's main fork, its TOAST table
  (`pg_total_relation_size` of it) and each index.

`rows` counts the rows of the tables a write touches after the run.

## Rerunning

From the repository root, with Go and (for Postgres) `psql`:

```sh
docs/capacity/storage/run.sh sqlite out-sqlite.json            # 1,000,000 writes over 1,000 resources
PG='postgres://postgres@localhost:5432/postgres?sslmode=disable' \
  docs/capacity/storage/run.sh pg out-pg.json 200000 1000      # writes, resources
```

`run.sh` builds the core and the harness, starts the core on a new database (a temporary
SQLite file, or a database `capstorage` it creates and drops on the server `PG` names) with an
operator key, the rate maximums raised and retention off, runs the phase and stops the core.
`PORT` (default 18181) is the core's port, so a SQLite and a Postgres run can go side by side.
A Postgres container as the tests use is enough:
`docker run -d -p 55495:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16`.

The memory cliff's points (below) are `cliff.sh`'s, one database each, as root (it drops the
host's page cache):

```sh
docker run -d --name plx-cliff --memory=256m --memory-swap=256m -p 55602:5432 \
  -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16 -c max_connections=300 -c shared_buffers=32MB \
  -c effective_cache_size=64MB -c max_wal_size=512MB -c track_io_timing=on
PG='postgres://postgres@localhost:55602/postgres?sslmode=disable' CONTAINER=plx-cliff MEM=256m \
  docs/capacity/storage/cliff.sh pg point-pg.json 1000000      # writes loaded before the load
MEM=256m docs/capacity/storage/cliff.sh sqlite point-sqlite.json 1000000
```

`BIN` names a directory with `patchlog` (built with `CGO_ENABLED=0`, for the alpine container
the SQLite core runs in) and `capacity` to use in place of building the working tree's, to
measure another commit's core with the same harness.

## Results

Taken on 2026-11-27 on a 4-vCPU host, the core, the harness and Postgres 16 (in Docker) on the
same machine, with **200,000 writes over 1,000 resources** (the default is 1,000,000; at about
1,000 writes a second on SQLite and 600 on Postgres over HTTP a million takes 15 to 30 minutes,
and the bytes per write don't depend on the count beyond the B-trees' fill).

| File | Code |
|---|---|
| `baseline-{sqlite,pg}.json` | the storage layout before this work (v0.34.0) |
| `after-item1-{sqlite,pg}.json` | derived `ns_log` bodies and created times, grants by number |
| `after-item2-{sqlite,pg}.json` | `ns_log_by_grant` and `ns_log_ns_config` replaced by rows written once |
| `after-idkey-{sqlite,pg}.json` | ids found by their first 8 bytes (taken 2026-11-28; "The memory cliff") |

| Run | Bytes per write | Tables | Indexes |
|---|---|---|---|
| SQLite baseline | 485 | 291 (`ns_log` 164, `revisions` 111, `head_history` 15) | 194 |
| SQLite after item 1 | 337 | 162 (`ns_log` 54, `revisions` 93, `head_history` 15) | 175 |
| SQLite after item 2 | 309 | 162 | 147 |
| Postgres baseline | 950 | 493 (`ns_log` 257, `revisions` 182, `head_history` 52) | 456 |
| Postgres after item 1 | 802 | 364 (`ns_log` 142, `revisions` 167, `head_history` 52) | 438 |
| Postgres after item 2 | 720 | 364 | 356 |
| SQLite, ids by key | 284 | 162 | 122 (the two id indexes 30 → 18, 32 → 20) |
| Postgres, ids by key | 683 | 364 | 320 (the two id indexes 50 → 32 each) |

The writes per second in the files are not comparable between runs: some ran beside test
suites on the same host.

## Query plans of the lookups item 2 moved

SQLite (`EXPLAIN QUERY PLAN`) before, on the baseline schema:

```
  SELECT seq FROM ns_log WHERE grant_id = x'00' AND ns = 1 ORDER BY seq LIMIT 1
    -> SEARCH ns_log USING COVERING INDEX ns_log_by_grant (grant_id=? AND ns=?)
  SELECT EXISTS (SELECT 1 FROM ns_log WHERE grant_id = x'00' AND ns = 1 AND seq <= 5)
    -> SCAN CONSTANT ROW
    -> SCALAR SUBQUERY 1
    -> SEARCH ns_log USING COVERING INDEX ns_log_by_grant (grant_id=? AND ns=? AND seq<?)
  SELECT seq, config_seq, created FROM ns_log WHERE grant_id = x'00' AND ns = 1 AND seq <= 5 ORDER BY seq LIMIT 1
    -> SEARCH ns_log USING INDEX ns_log_by_grant (grant_id=? AND ns=? AND seq<?)
  SELECT MIN(seq) FROM ns_log WHERE ns = 1 AND config_seq = 1
    -> SEARCH ns_log USING COVERING INDEX ns_log_ns_config (ns=? AND config_seq=?)
```

After (the statements `firstGrantEntry`, `firstUnder` and a log page send):

```
  SELECT (SELECT f.first_seq FROM ns_grants f WHERE f.grant_ref = (SELECT ref FROM grants WHERE id = x'00') AND f.ns = 1)
    -> SCAN CONSTANT ROW
    -> SCALAR SUBQUERY 2
    -> SEARCH f USING PRIMARY KEY (grant_ref=? AND ns=?)
    -> SCALAR SUBQUERY 1
    -> SEARCH grants USING INDEX sqlite_autoindex_grants_1 (id=?)
  SELECT (SELECT f.first_seq FROM ns_grants f WHERE f.grant_ref = (SELECT ref FROM grants WHERE id = x'00') AND f.ns = 1 AND f.first_seq <= 5)
    -> SCAN CONSTANT ROW
    -> SCALAR SUBQUERY 2
    -> SEARCH f USING PRIMARY KEY (grant_ref=? AND ns=?)
    -> SCALAR SUBQUERY 1
    -> SEARCH grants USING INDEX sqlite_autoindex_grants_1 (id=?)
  SELECT l.seq, l.config_seq, l.created FROM ns_log l WHERE l.seq = (SELECT f.first_seq FROM ns_grants f WHERE f.grant_ref = (SELECT ref FROM grants WHERE id = x'00') AND f.ns = 1 AND f.first_seq <= 5)
    -> SEARCH l USING INTEGER PRIMARY KEY (rowid=?)
    -> SCALAR SUBQUERY 2
    -> SEARCH f USING PRIMARY KEY (grant_ref=? AND ns=?)
    -> SCALAR SUBQUERY 1
    -> SEARCH grants USING INDEX sqlite_autoindex_grants_1 (id=?)
  SELECT first_seq FROM ns_config WHERE seq = 1 AND ns = 1
    -> SEARCH ns_config USING INTEGER PRIMARY KEY (rowid=?)
  SELECT l.seq, l.id, COALESCE(l.body, ''), l.kind, dr.name, dv.id, dv.created FROM ns_log l LEFT JOIN resources dr ON dr.res = l.res AND (l.body IS NULL OR l.body = '') LEFT JOIN revisions dv ON dv.seq = l.target_seq AND (l.body IS NULL OR l.body = '') WHERE l.ns = 1 AND l.seq > 0 AND l.seq <= 100 ORDER BY l.seq LIMIT 10
    -> SEARCH l USING INDEX ns_log_ns_seq (ns=? AND seq>? AND seq<?)
    -> SEARCH dr USING INTEGER PRIMARY KEY (rowid=?) LEFT-JOIN
    -> SEARCH dv USING INTEGER PRIMARY KEY (rowid=?) LEFT-JOIN
```

On Postgres the before plans used the same indexes (`ns_log_by_grant`, `ns_log_ns_config`);
after, `TestPGFirstsPlans` checks that both lookups take `ns_grants_pkey` and `ns_config_pkey`
and never read `ns_log`, and a log page over the 200,000 entries plans as

```
  SELECT l.seq, l.id, COALESCE(l.body, ''), l.kind, dr.name, dv.id, dv.created FROM ns_log l LEFT JOIN resources dr ON dr.res = l.res AND (l.body IS NULL OR l.body = '') LEFT JOIN revisions dv ON dv.seq = l.target_seq AND (l.body IS NULL OR l.body = '') WHERE l.ns = 1 AND l.seq > 0 AND l.seq <= 100000 ORDER BY l.seq LIMIT 1000
    Limit
      ->  Nested Loop Left Join
            Join Filter: ((l.body IS NULL) OR (l.body = ''::text))
            ->  Nested Loop Left Join
                  Join Filter: ((l.body IS NULL) OR (l.body = ''::text))
                  ->  Index Scan using ns_log_pkey on ns_log l
                        Index Cond: ((seq > 0) AND (seq <= 100000))
                        Filter: (ns = 1)
                  ->  Index Scan using resources_pkey on resources dr
                        Index Cond: (res = l.res)
            ->  Index Scan using revisions_pkey on revisions dv
                  Index Cond: (seq = l.target_seq)
```

## The memory cliff (ids found by their first 8 bytes)

**The worry.** At a sustained 100 writes a second (3.15e9 a year), two unique indexes keyed by
hash ids grow with every write: `ns_log (ns, id)` and `revisions (res, id)`, about 50 bytes a
write each on Postgres (the table above). Ids are hashes (20 bytes, the CHECK constraint), so an
insert lands on a random leaf page: once the indexes outgrow memory, every write should read
pages from disk, and write latency should climb, where a seq-keyed index only touches its tail.
`revisions_by_id (id)` (41 bytes a write) is random-keyed too, over every resource.

### Method

`cmd/capacity -only cliff` (`cliff.go`) with `docs/capacity/storage/cliff.sh`, one point of the
curve per run, on a new database each time:

1. **setup**, through the API: the namespace `cap-cliff` and 1,000 resources in it, a create and
   an append each, under one grant (the grants profile).
2. **preload**, with the core stopped, straight into the database: N more writes, each the rows a
   pruned single-resource append leaves (a `revisions` row with its patches NULL, its `ns_log`
   entry, its `head_history` row), round-robin over the resources, each revision's parent the
   resource's previous one and each entry's the namespace's previous one; the other columns are
   copied from the setup's last rows. Ids are `sha256(k, table)[:20]`: as random as the hashes
   the API makes, and the same keys in a run before and after a schema change. The heads, the
   namespace head and the identity sequences then move past the loaded rows, and Postgres gets
   `VACUUM ANALYZE` and a checkpoint (so autovacuum doesn't scan the new rows during the load).
3. **memory**: Postgres 16 runs in a container limited to **256 MB** (`--memory=256m
   --memory-swap=256m`, `shared_buffers=32MB`, `effective_cache_size=64MB`, `max_connections=300`,
   `track_io_timing=on`); the limit counts its page cache, so what the cache holds is what fits
   in 256 MB beside Postgres itself. For the load the container is restarted, the host's page
   cache dropped, then every table and every index read once (`pg_prewarm(…, 'read')`, tables
   first, largest first): the cache then holds what the memory allows, as on a server that has
   been running. On SQLite the core runs in an alpine container under the same 256 MB limit
   (page cache included; SQLite's own cache is the default `cache_size`, 2 MB a connection), and
   reads the database file once before the load.
4. **paced**, through the API: 100 appends a second for 150 s, open loop (each starts at its
   scheduled time and its latency counts from then, so a slow write doesn't hide the ones behind
   it), each to a resource picked at random among those with no write in flight. The latency is
   reported for the writes after the first 30 s (and per 10 s bucket in the files), and so are
   the reads: the host's block-device reads (`/proc/diskstats`, nothing else running), Postgres'
   `pg_stat_io` reads and their time for client backends, `pg_statio_user_indexes` blocks read
   (missed in `shared_buffers`, which may still be in the page cache) by index, and WAL bytes.

Writes spread over 1,000 resources of one namespace, picked at random: the worst case for both
indexes, which lead with `ns` and `res`. A write to a namespace or resource of its own lands in
its own small key range; many namespaces, or a few hot resources, would shrink what must stay in
memory.

The core and the harness run on the same 4-vCPU host as the database; its disk is a virtual one
whose random reads took 0.17–0.47 ms (0.2–0.35 in most runs).

### Results

Taken on 2026-11-28 (files `cliff-{before,after}-{pg,sqlite}.json`, each point's whole record:
latency per 10 s bucket, sizes of every index of the three tables, every counter). "Before" is
97aa259, "after" this change, the same harness and loads; latency and reads per write are those
of the 12,000 writes after the first 30 s. *Disk reads* are the host's block-device reads per
write; *read ms* Postgres client backends' read time per write (`pg_stat_io`, which includes
page-cache hits' copies), in SQLite the device's; *index blocks read* are `shared_buffers`
misses per write, mostly page-cache hits until the indexes outgrow the container.

Postgres (256 MB for Postgres and its page cache, `shared_buffers` 32 MB):

| Loaded | Schema | Database MB | Hash-keyed indexes MB (ns_log id + revisions (res, id) + revisions (id)) | p50 ms | p95 ms | p99 ms | Disk reads / write | Read ms / write | Index blocks read / write (ns_log id / revisions (res, id) / revisions (id) / revisions (res, seq)) | WAL KiB / write |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.25M | before | 196 | 16 + 15 + 13 = 44 | 8.1 | 10.3 | 13.8 | 0.03 | 0.03 | 0.72 / 0.72 / 0.50 / 0.50 | 3.4 |
| 0.25M | after | 184 | 10 + 10 + 13 = 32 | 7.6 | 9.9 | 13.0 | 0.04 | 0.02 | 0.43 / 0.43 / 0.55 / 0.55 | 3.0 |
| 1M | before | 767 | 63 + 60 + 50 = 174 | 7.9 | 10.2 | 12.8 | 2.05 | 0.39 | 0.94 / 0.94 / 0.87 / 0.55 | 8.5 |
| 1M | after | 721 | 39 + 39 + 50 = 128 | 8.0 | 10.8 | 17.6 | 1.23 | 0.32 | 0.86 / 0.85 / 0.89 / 0.60 | 6.7 |
| 2M | before | 1,530 | 125 + 122 + 101 = 348 | 8.3 | 10.6 | 14.6 | 2.48 | 0.65 | 0.98 / 0.98 / 0.95 / 0.59 | 12.1 |
| 2M | after | 1,438 | 78 + 77 + 101 = 256 | 8.6 | 11.0 | 13.8 | 2.27 | 0.53 | 0.94 / 0.94 / 0.96 / 0.62 | 10.4 |
| 3M | before | 2,286 | 183 + 185 + 149 = 517 | 8.1 | 10.6 | 15.2 | 2.80 | 1.25 | 1.00 / 1.01 / 0.97 / 0.63 | 14.8 |
| 3M | after | 2,156 | 120 + 119 + 149 = 387 | 8.5 | 11.6 | 24.7 | 2.67 | 0.82 | 0.97 / 0.97 / 0.98 / 0.66 | 12.9 |

SQLite (256 MB for the core and its page cache). The first "after" runs met a slower disk (0.47
and 0.38 ms a read against 0.17 and 0.20 for "before"); the 1M points were taken again, back to
back:

| Loaded | Schema | Database MB | Hash-keyed indexes MB | p50 ms | p95 ms | p99 ms | Disk reads / write | Disk read ms / write | Disk KiB written / write |
|---|---|---|---|---|---|---|---|---|---|
| 1M | before | 320 | 32 + 35 + 31 = 98 | 2.5 | 5.1 | 22.7 | 1.00 | 0.17 | 103 |
| 1M | after | 293 | 19 + 21 + 31 = 72 | 2.7 | 8.1 | 25.7 | 0.76 | 0.36 | 101 |
| 1M | before (repeat) | 320 | 32 + 35 + 31 = 98 | 2.7 | 5.6 | 23.0 | 1.15 | 0.20 | 102 |
| 1M | after (repeat) | 293 | 19 + 21 + 31 = 72 | 2.6 | 5.6 | 23.3 | 0.76 | 0.16 | 101 |
| 4M | before | 1,265 | 128 + 136 + 123 = 388 | 2.8 | 5.6 | 23.1 | 2.87 | 0.56 | 101 |
| 4M | after | 1,161 | 76 + 84 + 123 = 284 | 3.0 | 10.0 | 29.1 | 2.60 | 0.98 | 100 |

### What held and what didn't

**The hypothesis held for reads, not for latency.** On Postgres the reads a write makes go from
none to about two between 250,000 and 1,000,000 loaded writes, as the three hash-keyed indexes
go from 44 MB to 174 MB against the 256 MB the container has for Postgres and its cache (its
page cache held 170–200 MB during the loads), and to 2.8 at 3,000,000 (517 MB, twice the
memory). `pg_statio` blocks read show where they go: about one miss a write in each of the
three hash-keyed indexes once they are out of memory, against 0.5–0.65 for the seq-keyed control
`revisions (res, seq)`, whose 1,000 resources' tails don't stay in 32 MB of `shared_buffers`
either (most of those are page-cache hits: blocks read count `shared_buffers` misses, not disk
reads). The WAL a write makes grows with them, 3.4 to 14.8 KiB: the first change to a leaf after
each checkpoint logs the whole 8 KiB page, and random inserts touch a different leaf each time.

But the write latency hardly moves: p50 stays at 8 ms, p95 rises by half a millisecond, and p99
(the slowest 120 of each run's 12,000 writes) wanders between 13 and 25 ms run to run, before
and after alike. A write here is bound by its commit (WAL flush, fsync), and the host's disk answers a random
read in 0.2–0.35 ms, so 2.8 reads add about a millisecond of reading, part of it overlapped by
the 100 writes a second in flight. There is no cliff in latency at twice the memory; there is a
step in reads and WAL bytes per write, which a slower disk would turn into latency (2.8 serial
reads at 1–2 ms each, a network volume's, would add 3–6 ms) and a busier one into IOPS (280 a
second at 100 writes a second).

SQLite shows the same: 1.0 disk reads a write at 1,000,000 loaded writes (98 MB of hash-keyed
indexes beside a 320 MB file), 2.9 at 4,000,000 (388 MB), and p50 2.5 → 2.8 ms; a repeat of the
1,000,000 points gives the same p50 and p95 before and after (2.7 and 5.6 ms) — the first
"after" run's higher p95 came with a slower disk (0.47 ms a read against 0.17).

**The prefix indexes move the step, they don't remove it.** The two key indexes are 35–38%
smaller than the unique ones (39 MB where 63 MB, at 1,000,000 writes), but still random-keyed, and
`revisions_by_id (id)` is unchanged: the three together are 26% smaller (128 MB where 174), so
the reads start about 1.35 times later. Where the old indexes had just outgrown memory and the
new ones less so (1,000,000 writes), a write reads 1.2 pages where it read 2.05 and logs 6.7 KiB
where 8.5; at 2,000,000 and 3,000,000, where both are well outside, 5–8% fewer reads and 13–14%
less WAL. Latency didn't improve: p50 is 0.5 ms lower after at 250,000 but 0.1–0.4 ms higher
from 1,000,000 up, and p95 0.4–1.0 ms higher there (as in a discarded first series, with the
row-level triggers), which may be the triggers' cost, a PL/pgSQL call per insert statement, two
per write; the single-write benchmarks of the next paragraph show no difference. On SQLite
25–35% fewer reads at 1,000,000, 9% at 4,000,000.

**Kept for the bytes.** 36 bytes a write on Postgres (720 → 683, 5%) and 24 on SQLite (309 → 284,
8%), about 110 GB and 75 GB a year at 100 writes a second, and those are bytes of the indexes
every write inserts into at random, the ones that must fit in memory for writes not to read:
the step comes at a third more writes. The costs: a trigger per insert statement on Postgres
(`BenchmarkBatch1000`, 1,000 creates in one batch, on an idle host: before 179–211 ms, after
203–275 ms in alternating runs, and the same build with its triggers dropped 169–195 ms against
185–201 with them, so 5–25%; single writes the same, `BenchmarkAppendsOneNamespace` 1 and 8
writers 150–215 and 530–710 writes a second either way), one per row in SQLite (+6% on the
batch, single writes the same), and a migration that rewrites `ns_log` and `revisions` on
SQLite.

The next lever is `revisions_by_id (id)`, as big (41 bytes a write) and as random, over every
resource: the same key, `(key)` with the whole id compared, would cut it to about 22 bytes.
Removing the step altogether takes an index whose inserts don't land at random, which an id
that is a hash can't give: only fewer of them (one per write instead of three), or memory.

### The prefix indexes

`ns_log (ns, id)` and `revisions (res, id)` are no longer unique constraints on the whole id
but indexes on `(ns, key)` and `(res, key)`, the key the id's first 8 bytes (migrations
`034_ids_found_by_their_first_8_bytes` on SQLite, `036_…` on Postgres; `dialect.go` `idKeySQL`):

- **An expression, not a column.** On Postgres `('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)
  ::bigint`, the bytes as a big-endian two's-complement `bigint`; in SQLite `substr(id, 1, 8)`, an
  8-byte BLOB (SQLite has no blob-to-integer function, and a blob prefix sorts and compares as
  well). An expression index costs no heap bytes (a stored column would add 8 to each row of both
  tables), no insert sets it (`ns_log` and `revisions` are inserted in half a dozen places), and
  building it on an existing table is a `CREATE INDEX`, where adding a generated column would
  rewrite the table. A Postgres entry is 24
  bytes (8 of tuple header, `ns` or `res`, the key) where `(ns, id)` took 40 (the 21-byte `bytea`
  padded to 24); a `bytea` prefix would take 32.
- **Lookups compare the whole id** on the rows the key finds (`idIs`: `key = ? AND id = ?`), so
  two ids that share 8 bytes in one namespace or resource are told apart. Every lookup by id was
  changed: `nsLogSeq` (log paging and retries), `revByID` and the retry lookups of
  `lookupResource` (a write's idempotent-retry check, §7.2), `locate` (reads and as-of reads down
  an ancestry, branches' bases included), archive restores and gesture paging. In SQLite the
  whole id is compared as `+id`, which no index answers: with statistics the planner otherwise
  takes `revisions_by_id (id)`, as selective but over every resource's revisions, where the key
  index's page is the one the write then inserts into. `TestIDKeyPlans` checks every one of these
  statements, and the probes of SQLite's triggers and of the update triggers, on a resource of
  20,000 revisions and a namespace of 20,000 entries, before and after `ANALYZE`, on both
  stores: all take `revisions_res_id8` or `ns_log_ns_id8` (gesture paging may take the
  gesture's own partial indexes, as selective). `docRules` and `copyRows` (drafts, purge
  checks, schema reads) look revisions up by id across resources and keep `revisions_by_id`,
  which the test checks too. The Postgres insert triggers' join is left no plan but the index
  by its function's settings.
- **The whole id stays unique in its namespace and in its resource.** A trigger of each table
  checks it through the key index and fails as the constraint did: on Postgres an `AFTER INSERT …
  FOR EACH STATEMENT` trigger joins the statement's inserted rows (its transition table) to the
  table by key and id, one pass per statement (a batch's thousand revisions in one join), and
  raises `unique_violation` on the same table and constraint name (`revisions_res_id_key`,
  `ns_log_ns_id_key`), so `isConflict` tells a lost race as before; in SQLite a `BEFORE INSERT`
  trigger raises `UNIQUE constraint failed: revisions.res, revisions.id` as
  `SQLITE_CONSTRAINT_TRIGGER`, which `isConflict` now takes. Both check `UPDATE OF` the key
  columns too, which nothing does. A first version checked each row before it went in, in a
  row-level Postgres trigger: its function cached a plan made while the tables were small, a
  sequential scan, and kept it as they grew (a 1,000-item batch took 1–1.3 s instead of 0.2 s);
  the statement trigger's function allows the planner nothing but the index (`enable_seqscan`,
  `enable_hashjoin`, `enable_mergejoin` off for its one query).
- **Concurrency.** SQLite writes are serialised, so the check is exact. On Postgres a trigger
  can't see another transaction's uncommitted row, as a unique index's insert could. The engine
  never gives it one to miss: a namespace's entries are appended under its log lock
  (`pg_advisory_xact_lock`, pglock.go), held to the commit, so the next appender's check sees
  the last one's row; and every write of a resource either inserts the resource's row (unique
  `(ns, name)`) or moves its head from the one its precondition matched (`moveHeads`, `WHERE
  head_seq = old`), so two writes of one resource can't both commit, whatever ids they insert
  (the loser gets a unique violation or `errChainRace`, a lost race). An id being the hash of
  its parent's (§3.3, §3.5), two rows with one id in one chain would also have one parent, which
  `(res, parent_seq)` and `(ns, prev_seq)` refuse. Rows inserted by hand, outside a write, have
  only the trigger.
- **Collisions.** `TestIDKeyCollision` (both stores) puts decoy rows into a resource and a
  namespace, sharing the first 8 bytes of the revision and entry ids a write is about to make;
  the write succeeds with its own ids, its retry replays it, `revByID` and `nsLogSeq` find each
  row by its id and no id that isn't there; a second row with an id the resource or namespace
  holds, or two in one statement, is refused as a lost race; another resource may hold the same
  id. `TestIDKeyUpgrade` migrates a database written before (both stores) and checks every row
  is there, the foreign keys and integrity hold (SQLite), the two tables' indexes, constraints,
  triggers and columns are a fresh database's, an old write replays, old revisions and entries
  are found, and new writes chain on.
- **Upgrading.** Postgres builds the two indexes (one read of each table, holding writes off for
  as long) and drops the constraints. SQLite can't drop a table constraint's index, so its
  migration rebuilds `ns_log` and `revisions`: copied aside, dropped, created again, copied back
  with every seq, indexes and triggers, the foreign keys to them deferred to the commit (their
  child columns indexed meanwhile, so the checks are lookups): a rewrite of the two largest
  tables, once. A binary from before running on the new schema would find an entry by id by
  scanning its namespace's entries: stop old instances before migrating.

Nothing a client sees changes: entry ids, served bodies, wire bytes and vectors are the same.

## What was left

- **`revisions_by_id (id)`** (29 bytes per write on SQLite, 41 on Postgres). Two lookups use it.
  `docRules` asks only whether a Legacy-marked revision with an id exists in a few namespaces,
  which a partial index `(id) WHERE kind = 0 AND COALESCE(rules, 0) = 0`, nearly empty on new
  data, would answer exactly. But `copyRows` (drafts in branches, purge reference checks, schema
  reads) wants every live revision with an id and a resource name anywhere in the deployment:
  without the index it goes `resources_name` → `(res, id)`, one probe per resource of that name
  in every namespace, O(namespaces) for a common name. A table of schema revisions written at
  write time would have to take in every revision stored before it (SQL can't tell a stored
  schema document from its patch set) and would stop finding refs that name a revision whose
  document isn't a schema, which changes their error. Left for a decision. It is the third
  hash-keyed index every write inserts into at random (see "The memory cliff"), now the largest:
  an index on its first 8 bytes, the whole id compared, would serve both lookups at about 22
  bytes a write.
- **Postgres column types and order.** A table laid out 8 → 4 → 2 → varlena, with `ns`,
  `author` and `grant_ref` as `integer`, measured on 200,000 synthetic rows: `ns_log` 141 →
  126 bytes a row, `revisions` 126 → 109; the indexes don't shrink (an `integer` beside a
  `bigint` or a 21-byte `bytea` pads to the same 8 bytes). Changing the types in place saves
  nothing for the same padding, so it needs `ns_log` and `revisions` rebuilt (copied into new
  tables with every index, constraint, identity, trigger and foreign key from `head_history`,
  `snapshots`, `blobs`, … recreated) under an exclusive lock for the whole copy: about 32 bytes
  per write for downtime proportional to the database. Not done. `res` and the revision and
  entry seqs must stay `bigint` (one value per resource, revision or entry, burnt by rollbacks
  too); `ns`, `author` and `grant_ref` fit `integer`: a value per namespace, per distinct
  author (looked up before it is inserted, `actorID`) and per new grant (the grant statement
  draws a number only when it inserts), plus those rollbacks burn.
- **`head_history` from a partial index of `ns_log`.** Its 84 bytes per write on Postgres could
  become about 40 with `ns_log (res, seq) INCLUDE (target_seq) WHERE kind IN (head, tombstone)`
  and rows kept for batch items only, but a dozen statements read it (the head as of an entry,
  the first entry of a resource, entries by `target_seq`, the purge searches' lateral lookups),
  each of which would become a union of the two. Not done.

