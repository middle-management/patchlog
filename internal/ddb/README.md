# ddb — the DynamoDB store

The DynamoDB backend of docs/DYNAMODB.md: the key design of §3, the
transactions of §4, wired into `internal/core` for phase 1 of §10's path
C (plain namespaces, `-dev`, one instance — the integration status is
§13). It reuses the production id scheme (`internal/ids`), canonical JSON
(`internal/jsonv`) and patch engine (`internal/patch`), so the bytes it
hashes and folds are the production bytes.

The surface, beyond the spike's writes: `CreateNamespace`, `WriteResource`
(restores included: a write on a tombstone root-replaces, its parent the
tombstone id), `DeleteResource` (§8.1's tombstones: the deterministic
`ids.Tombstone` id, replay, the last-live markers for `Head.Last`), and
`WriteConfig` — the three writes with a check hook that runs the caller's
gate inside the retry loop, after planning (D.3's recheck shape);
`ReadHead`, `ReadLog` (paged, id cursors, upper bounds), `ReadRevByID`
(GSI1), `FoldResource` (crossing tombstones: the document dies, the
restore root-replaces), `ResourceLogEntries`, `ListHeads`, `ReadConfig`,
`ReadDocAtEntry` (the `ns_log ⨯ ns_config` join), `ReadNSInfo`,
`KnownEntry`, `Ping`. `Open` parses the `-db` URL
(`dynamodb://<table>?region=…&endpoint=…`); errors carry the core's
`{"code": …}` body shape.

## What it proves

- **The transaction design (§4).** A single-resource write commits as
  seven actions of one `TransactWriteItems`: put the revision (condition:
  the parent has no child yet), update the resource's head (condition: the
  head is what the check phase read), upsert the head document and the
  history row, put the log entry, move the log tip (condition: it is what
  the check phase read — the log lock's replacement), put the entry's
  idempotency marker (condition: it does not exist).
  `TestLocalConcurrentNamespace` hammers one namespace with concurrent
  writers: the log commits in chain order with no gaps.
  `TestLocalConcurrentResource` races one resource: exactly one writer
  wins, the rest get the 412 with the winner's head — D.3's conflict path.
- **Idempotent replay.** A retried write recomputes its first attempt's
  revision id (the id covers the precondition's parent, not whatever the
  head has become), finds it already the head, and answers with the
  original entry id — read from the resource item, since the entry's own
  id chains over a tip that has moved past it. `TestPlanWriteReplay`,
  `TestLocalStaleAndReplay`.
- **The key design (§3).** Byte-ordered `/heads` (`begins_with(RES#)`),
  log paging with id cursors (the marker resolves a served id back to its
  position — `UNIQUE(ns, id)`), chain order by zero-padded positions.
- **Namespace creation** as one transaction: meta, config genesis, first
  log entry, tip, marker.

## Running

```sh
go test ./internal/ddb/            # the hermetic tests (keys, plans, tx shapes)

docker run -d --name ddb-local -p 8000:8000 amazon/dynamodb-local
DDB_ENDPOINT=http://localhost:8000 go test ./internal/ddb/   # + the integration tests
DDB_ENDPOINT=http://localhost:8000 go test -run TestDDB ./internal/core/  # the engine's phase-1 surface
DDB_ENDPOINT=http://localhost:8000 go test -run XXX -bench BenchmarkDDB -benchtime 1x ./internal/ddb/
```

The integration tests skip without `DDB_ENDPOINT`. Each creates its own
table and deletes it on cleanup. Benchmark numbers and their reading are
in docs/DYNAMODB.md §11; the headline: a write is two round trips (one
batch read + one transaction), p50 ~4 ms locally, and concurrent writers
of one namespace need the group commit of §4 — optimistic retry on the
hot `#TIP` item degenerates (167/s at 8 writers down to 82/s at 32),
which is why Postgres uses a log lock instead.

## Simplifications (all deliberate)

- The scope is plain namespaces: no grants, blobs, branches, purges,
  batches, sealed/e2e, or the S3 offload of large values. What the scope
  doesn't cover is refused by core's seam (501), not silently dropped;
  limits and namespace rules are the gate's, evaluated in the check hook.
- `WriteResource` is one patch-set step (create-or-append, `ifMatch`
  optional); multi-step items are phase 2's batch work.
- A retried `CreateNamespace` with the *same patches* answers the original
  ids (its marker covers them); with *different* patches it is 412 naming
  the current config id — production's answer.
- `kind` and `author` are stored as names, not the SQL schema's ints;
  revision/log/head metadata (`size`, `digest`, `created`, gestures) rides
  as plain attributes, and LOG items denormalize `cfgPos` like
  `ns_log.config_seq`.
- Read-modify loops (the tip retry) are bounded by `maxWriteAttempts = 8`,
  like the SQL backends'. Group commit (docs/DYNAMODB.md §4, §11) is
  phase 2.

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
   concurrency test; `TestBuildWriteTx` now pins the written values.
4. **Replay needs the request's parent, not the stored head.** Computing
   the revision id over the current head can never replay: the retry's id
   covers the id in the request's precondition (`If-Match`), which is the
   head of the first attempt. The 412/replay order matters: replay first,
   then stale.
5. DynamoDB Local needs `ResponseChecksumValidation` unset in the SDK
   config, and supports transactions and consistent reads as documented.
