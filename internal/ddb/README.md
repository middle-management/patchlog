# ddb — the DynamoDB store

The DynamoDB backend of docs/DYNAMODB.md: the key design of §3, the
transactions of §4, wired into `internal/core` for phase 1 of §10's path
C (plain namespaces, one instance — the integration status is §13). It reuses the production id scheme (`internal/ids`), canonical JSON
(`internal/jsonv`) and patch engine (`internal/patch`), so the bytes it
hashes and folds are the production bytes.

The surface. Writes: `Commit` (commit.go) commits what core's write gate
decided — a write's or batch's items, each step a revision or tombstone
on the head the checks read (multi-step items included), an optional
config change, the namespace entry — conditioned on those heads and the
configuration in force, `ErrStale` when they moved; `CreateNamespace`
is its own transaction. The gate's reads (gatereads.go: `Namespace`,
`ConfigAt`, `ConfigByID`, `Resource`, `RevAt`, `ReadRevOf`, `DocAt`,
`EntryAt`, `EntryPos`, and grants.go's `Grant`, `RecordsGrant`) are
what core/ddbreads.go answers the gate with; `PutGrant` stores a write's
grant, `FirstEntryTime` dates the operator keys (§C.4); blobs.go's
`Attachment`, `Pending`, `PendingOf`, `UploaderVersion`, `Bytes` are the
blob reads, `PutBytes` and `PutPending` an upload's writes, `ScanBlobs`,
`DeletePending`, `DeleteBytes` the sweep's; schemas.go's `SchemaRefs`,
`Namespaces` and `RevsByID` answer schemaReads' referrer checks, from
`PutSchemaRefs`' markers, the `#NAMESPACES` registry `CreateNamespace`
writes, and GSI1. Pruning (prune.go): `Commit.Prune` moves a
resource's horizon, `PutSnapshots` writes the documents it keeps before
the commit, `PruneContent`, `EachDoc`, `EachSnapshot`, `Attachments`,
`EndAttachment` and `DonePruning` finish it, `Pruning` lists the
unfinished for the sweep; `PrunedBelow`, `FirstRevSince`,
`NthNewestRev` and `RetainedNames` are the retention and paging reads,
and `DocAt` answers a `*PrunedError` below a horizon.
Serving reads are core's, through the same reads: `EntriesBetween` and
`RevsBetween` (a log's or a chain's range), `HeadAt` (a head as of an
entry, from the history rows), `ListHeads`, `FoldResource` (crossing
tombstones: the restore applies to the last live document), `Ping`.
`Open` parses the `-db` URL
(`dynamodb://<table>?region=…&endpoint=…`); `CreateTable` makes the
table; errors carry the core's `{"code": …}` body shape. With
`GroupCommit` > 1, commits without a config change commit in groups per
namespace (`group.go`, docs/DYNAMODB.md §4).

## What it proves

- **The transaction design (§4).** A single-resource write commits as
  eight actions of one `TransactWriteItems`: put the revision (condition:
  the parent has no child yet), update the resource's head (condition: the
  head is what the checks read), upsert the head document and the history
  row, put the log entry, put the entry's marker (condition: it does not
  exist), move the log tip (condition: it is what the commit chained over
  — the log lock's replacement), and check `#META` (the configuration
  the checks ran under). commit_test.go pins the layout;
  `TestLocalConcurrentNamespace` hammers one namespace with concurrent
  commits (the log commits in chain order with no gaps);
  `TestLocalConcurrentResource` races one resource (exactly one commit
  wins, the rest are `ErrStale`, which core answers by checking them
  again — D.3); `TestLocalConfigPinned` proves the configuration pin.
- **Idempotent replay** is core's gate's (the retry lookup), over this
  store's reads: a revision records the entry that committed it
  (`logPos`), so a retry finds its entry wherever the head has gone.
- **The key design (§3).** Byte-ordered `/heads` (`begins_with(RES#)`),
  log paging with id cursors (the marker resolves a served id back to its
  position — `UNIQUE(ns, id)`), chain order by zero-padded positions.
- **Namespace creation** as one transaction: meta, config genesis, first
  log entry, tip, marker.

## Running

```sh
go test ./internal/ddb/            # the hermetic tests (keys, commit layouts)

docker run -d --name ddb-local -p 8000:8000 amazon/dynamodb-local
DDB_ENDPOINT=http://localhost:8000 go test ./internal/ddb/   # + the integration tests
DDB_ENDPOINT=http://localhost:8000 go test -run TestDDB ./internal/core/  # what the API suites can't reach
DDB_ENDPOINT=http://localhost:8000 go test -run XXX -bench BenchmarkDDB -benchtime 1x ./internal/ddb/
PATCHLOG_TEST_BACKEND=dynamodb DDB_ENDPOINT=http://localhost:8000 go test ./...   # the API suites on DynamoDB (internal/testenv)
```

The behaviour the spec defines is tested through the API, on every
backend alike: the server package's and the services' suites run on
DynamoDB with `PATCHLOG_TEST_BACKEND=dynamodb` (docs/DYNAMODB.md §13).
This package's own integration tests are what HTTP can't observe — the
transaction races, group commit, the store's history lookups — and
`internal/core`'s `TestDDB*` cover the few seam answers no API test that
runs on this backend reaches (frozen, the delete envelope, the 501s).

The integration tests skip without `DDB_ENDPOINT`. Each creates its own
table and deletes it on cleanup. Benchmark numbers and their reading are
in docs/DYNAMODB.md §11; the headline: a write is two round trips (one
batch read + one transaction), p50 ~4 ms locally, and concurrent writers
of one namespace need the group commit of §4 — optimistic retry on the
hot `#TIP` item degenerates (167/s at 8 writers down to 82/s at 32),
which is why Postgres uses a log lock instead. `group.go` is that group
commit: the `-grouped` benchmarks keep rising with writers instead.

## Simplifications (all deliberate)

- The scope is plain namespaces and local branches: no remote branches,
  sealed/e2e, or the S3 offload of large values. Purges (purge.go) commit their flags at once
  and their content after (`PurgeContent`, finished by the sweep from
  `PURGING#` markers when interrupted); second CDN purges queue in the
  commit (repurge.go). Blobs (blobs.go) keep attachments and
  pending entries as items of the namespace's partition and their bytes
  in `BYTES#<sha256>` items, inline (≤ `MaxInlineBytes`, which bounds
  `blobSize` without a blob directory) or as a file of `-blob-dir`; an
  attachment's `refPos` answers whether a chain references a blob up to
  a revision. Branches (branch.go) are a commit to the base that creates
  the branch in the same transaction; a branch's #META names its base,
  and a first revision its foreign parent. Grants are stored (grants.go): each
  once, before the commits that record it, outside their transactions (a
  group's commits may share one); a namespace marker per grant, written
  once per transaction, answers GET /ns/{ns}/grants/{gid}; LOG and REV
  items carry `grantId`, and LOG items `noAuth` for writes made with
  authentication disabled. What the scope doesn't
  cover is refused (501) by core's reads or seam, not silently dropped.
- A commit is bounded by the 100-action transaction budget, which lowers
  the deployment's `ItemsPerBatch` to `MaxBatchItems` (23) —
  docs/DYNAMODB.md §10's lowered maximum; multi-step items draw it down
  by a revision a step.
- A retried `CreateNamespace` with the *same patches* answers the original
  ids (its marker covers them); with *different* patches it is 412 naming
  the current config id — production's answer.
- `kind` and `author` are stored as names, not the SQL schema's ints;
  revision/log/head metadata (`size`, `digest`, `created`, gestures) rides
  as plain attributes, and LOG items denormalize `cfgPos` like
  `ns_log.config_seq`.
- A commit re-chains over a moving tip at most `maxWriteAttempts = 8`
  times, and core checks a stale write again at most 8 times, like the
  SQL backends' bounds.
- Group commit queues commits without a config change. A config change
  commits on its own under the namespace's commit lock, which the group
  worker holds through each group; across instances (phase 3) they race
  on `#TIP` and re-chain.

## What the spike learned (fed back into docs/DYNAMODB.md)

1. **Entry ids are unique per namespace, not globally.** Two namespaces
   created with identical genesis patches produce identical config ids and
   first-entry ids. The idempotency marker's key therefore carries the
   namespace (`NSID#<ns>#<id>`) — and no GSI is needed for it: it is a
   plain item read by its key. GSI1 of §3 shrinks to revision-by-id (which
   *is* a global lookup, and non-unique — genesis twins share an id — so a
   GSI, not a marker).
2. **One sort-key condition per query.** Log paging and `/heads` paging
   can't combine `begins_with` with `>` on the cursor. The spike's
   pattern: first page with `begins_with`, later pages with `SK > cursor`,
   stopping the scan at the prefix boundary (RES# can run into REV#,
   LOG# into anything sorting after it).
3. **A condition's target and the values written must both be explicit.**
   The first version of the tip move `SET` the old values back (the
   condition pinned them correctly), so the tip never advanced and every
   later write collided on the same `LOG#` item. Caught by the
   concurrency test; `TestBuildCommitCreate` now pins the written values.
4. **Replay needs the request's parent, not the stored head.** Computing
   the revision id over the current head can never replay: the retry's id
   covers the id in the request's precondition (`If-Match`), which is the
   head of the first attempt. The 412/replay order matters: replay first,
   then stale.
5. DynamoDB Local needs `ResponseChecksumValidation` unset in the SDK
   config, and supports transactions and consistent reads as documented.
