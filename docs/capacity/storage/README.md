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

| Run | Bytes per write | Tables | Indexes |
|---|---|---|---|
| SQLite baseline | 485 | 291 (`ns_log` 164, `revisions` 111, `head_history` 15) | 194 |
| SQLite after item 1 | 337 | 162 (`ns_log` 54, `revisions` 93, `head_history` 15) | 175 |
| SQLite after item 2 | 309 | 162 | 147 |
| Postgres baseline | 950 | 493 (`ns_log` 257, `revisions` 182, `head_history` 52) | 456 |
| Postgres after item 1 | 802 | 364 (`ns_log` 142, `revisions` 167, `head_history` 52) | 438 |
| Postgres after item 2 | 720 | 364 | 356 |

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
  document isn't a schema, which changes their error. Left for a decision.
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

