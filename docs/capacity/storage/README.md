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

| Store | Bytes per write | Tables | Indexes |
|---|---|---|---|
| SQLite | 485 | 291 (`ns_log` 164, `revisions` 111, `head_history` 15) | 194 |
| Postgres | 950 | 493 (`ns_log` 257, `revisions` 182, `head_history` 52) | 456 |
