# A DynamoDB backend — design exploration

Status: exploration on branch `dynamodb`, off `main` (v0.22.x). Phase 1 is
spiked and green in [internal/ddb](../internal/ddb) (keys, namespace
create, the single-resource write transaction, head and log reads, against
DynamoDB Local); its findings are folded into §3, §11 and §12 and listed
in its README. The rest of this document stands as written: it maps what a
DynamoDB storage backend for the core (`internal/core`) would have to do,
proposes a concrete table and key design, and names the hard problems
before any code commits to them.

References are to the code on this branch: `internal/core/db.go` (SQLite
schema, Addendum D.2), `internal/core/pgschema.go` and `pglock.go` (D.8),
`dialect.go` (the two-dialect seam), `write.go`, `recheck.go`, `reads.go`,
`resolve.go`, `groupcommit.go`, `tailer.go`, `live.go`, `repurge.go`.

## 1. The seam today

SQLite and Postgres are one storage layer with two dialects, not two backends:

- One schema, written twice (`schemaSQL`, `schemaPG`): ~20 tables, integer
  identity keys, 20-byte BLOB ids, canonical JSON in TEXT columns.
- One query corpus, written once: constant SQL strings with `?` placeholders,
  rewritten to `$1..$n` for Postgres (`dialect.go` rebind), executed through
  the `tx` wrapper (`stmts.go`). What differs per dialect is small: `blobArg`,
  `inArray`/`arrayArg`, bool coercion, `isConflict`.
- Write serialisation differs by deployment shape: an in-process mutex and
  `BEGIN IMMEDIATE` on SQLite; per-namespace advisory locks, a per-namespace
  log lock, and group commit on Postgres (`pglock.go`, `groupcommit.go`).
- Cross-instance invalidation exists only on Postgres: the tailer polls
  `ns_log` by transaction id and `cache_gen` (`tailer.go`) to wake live
  readers and move the read caches of every instance.

There is **no storage interface above SQL**. The `tx` type wraps `*sql.Tx`
and is threaded through everything: ~115 `Engine` methods, and the whole of
the write gate, reads, folding, sealing, e2e, blobs, branches and retention
(`write.go` is 2,300 lines alone). The SQL corpus *is* the interface.

Consequence: DynamoDB is not a third dialect next to `sqlite` and `pg`. It has
no SQL, no joins, no multi-statement transactions, no sequences, and a fixed
set of primitives (GetItem, Query, Put/Update/Delete with conditions,
TransactWriteItems, Streams). §10 weighs the three ways to get there; the
design in §3–§9 is written against the access patterns, not against the SQL,
so it survives whichever path is taken.

## 2. What the store must do — access patterns

Grouped from the query corpus:

**Namespace registry.** By unique name (`nsByName`); by integer id
(`nsByID`); branches of a base; frozen/purged flags; head and config chain
tips denormalised onto the row.

**Resource registry.** By `(ns, name)`, unique; paged by name in byte order
(`/heads`, `reads.go`); state (live/tombstoned/purged), horizon, kept ids,
snapshot counters.

**Revision chains.** Append-only per resource: unique `(res, id)` and
`(res, parent_seq)`, one genesis. Read: whole chain in order (fold,
`resolve.go`), ranges in order (resource log pages), by id (draft schema
revisions, §6.1), sparse by `gesture` and `undoes` (§7.4).

**Documents.** Head snapshot per resource (`heads`), intermediate snapshots
every 100 revisions / 64 KiB (D.4), kept documents below a horizon (§8.6).
Values up to `documentSize`: 1 MiB default, 4 MiB deployment maximum
(`MaxDocumentSize`).

**Namespace log.** Append-only per namespace, chain-linked by
`(prev_seq, id)`; unique `(ns, id)` for idempotent retry (§7.1); paged in
order (`X-Log-Next`, `logPageSize`/`logPageBytes`); entries by grant
(§C.3.1); the first entry of a configuration (retry of config writes).
Bodies carry a batch's items inline — up to `batchSize` (16 MiB default).

**Namespace config chain.** Same chain shape as revisions; the resulting
document stored on each row.

**Head history.** `(res, ns_seq) → target_seq`, for `?at=` resolution
(`resolve.go`) and replay (`recheck.go`).

**Grants.** By 20-byte id; immutable once stored; root sub/kid readable in
plaintext (§7.4).

**Encryption.** Data keys per resource (E.1), epoch keys per `(ns, epoch)`
(E.2), sealed responses per `(ns, kind, key)`, e2e epoch registry and
client-sealed snapshots (E.3).

**Blobs (§7.8).** Attachments per `(res, bid)`; pending uploads per
`(res, bid, uploader)`, swept by age; reference intervals per revision range;
bytes keyed by `(owner, hash)` — already offloaded to files under `-blob-dir`
via the `blobStore` interface; sealed forms per epoch.

**Background jobs.** Second CDN purges due at a time (`cdn_repurge`);
retention (§8.6); blob sweep; epoch rotation.

**Federation (G.3).** Registered remote branches per base; shadow namespaces
and their follow state; purge notices.

**Cross-cutting.** Idempotent retry (unique entry ids + replay); authors
(name → id compression only); rate-limit buckets (in-process on SQLite; a
multi-instance deployment must share them); schema/data migrations
(`migrations` table).

## 3. Table and key design

One table, `patchlog`, with generic `PK`/`SK` (string keys), one stream
(NEW_IMAGE), and two GSIs. Single-table because the write path's transactions
are confined to one namespace's items, one stream then feeds all
cross-instance invalidation (§6), and GSIs are shared by every entity.
Multi-table is viable (DynamoDB transactions span tables) and is noted where
it changes a decision.

The relational layer's integer keys are dropped: ids (20-byte content hashes,
served base32) and names (§3.6 grammar, ASCII-safe) are the natural keys.
Chain positions are decimal, zero-padded to 12 digits (`000000000042`) so
sort order is chain order; `seq`-only identity (a global integer) becomes
the tuple `(ns, resource, pos)` plus the revision's id.

```text
PK                          SK                                  entity
NS#<ns>                     #META                               namespace: frozen, purged, base, baseAt, configPos/Id, level
NS#<ns>                     #TIP                                namespace log tip: headPos, headId   (own item: every write
                                                                  conditions on it; config reads must not contend with it)
NS#<ns>                     CFG#<pos12>                         config chain entry: id, parentPos, patches, doc|docRef, firstLogPos
NS#<ns>                     LOG#<pos12>                         ns_log entry: id, prevPos, kind, res?, body|bodyRef, cfgPos,
                                                                author, created, grantId, noAuth, gestures
NS#<ns>                     RES#<name>                          resource: headPos, headId, state, horizonPos, keep, snapRevs/Bytes
NS#<ns>                     REV#<name>#<pos12>                  revision: id, parent (pos | {ns,name,pos} foreign), kind, first,
                                                                patches|patchesRef, author, created, grantId, schemaRef,
                                                                gesture?, undoes?, size?, digest?, epoch?
NS#<ns>                     DOC#<name>#HEAD                     head snapshot: revPos, doc|docRef
NS#<ns>                     DOC#<name>#SNAP#<pos12>             intermediate / kept snapshot (D.4, §8.6)
NS#<ns>                     HIST#<name>#<logPos12>              head_history row: revPos
NS#<ns>                     BLOB#<name>#<bid>                   blob attachment: type, nonce, size, hash, owner, refPos, pruned
NS#<ns>                     BREF#<name>#<bid>#<fromPos12>       blob reference interval: toPos?
NS#<ns>                     PEND#<bid>#<uploader>               pending blob upload (GSI2 on created for the sweep)
NS#<ns>                     EPOCH#<n>                           sealed epoch key (wrapped)
NS#<ns>                     SEALED#<kind>#<key>                 sealed response (JWE)
NS#<ns>                     E2E#<n>                             e2e epoch registry row
NS#<ns>                     E2ESNAP#<name>#<pos12>              e2e sealed snapshot (JWE)
NS#<ns>                     BLOBEPOCH#<name>#<bid>#<n>          sealed blob form per epoch (pointer)
NS#<ns>                     ARCH#<name>#<fromPos12>             pruning archive record (§8.6)
NS#<ns>                     REMOTE#<origin>#<branch>            registered remote branch (source side)
NS#<shadow>                 #FOLLOW                             remote base follow state (branch side)
NS#<shadow>                 NOTICE#<nsId>                       purge notice
GRANT#<id32>                #                                   grant: blocks, rootSub, rootKid
DEK#<ns>#<name|0>           #                                   data key (wrapped, keystore, created)
BLOB#<owner>#<hash64>       #                                   blob bytes pointer: S3 key (or inline ≤ ~350 KB)
BUCKET#<hash>               #                                   shared rate bucket (multi-instance)
JOB#REPURGE#<logId>         #                                    second CDN purge: tags, due (GSI2 on due)
META#<name>                 #                                   schema version, migrations, deployment meta
```

GSIs (both on the one table):

- **GSI1** `G1PK` — global id lookups, sparse: revision by id
  (`REVID#<id32>`; §6.1 drafts), config entry by id (`CFGID#<id32>`),
  branches of a base (`BASE#<ns>`). The spike refined the ns-entry lookup:
  entry ids are unique *per namespace*, not globally (identical genesis
  patches in two namespaces hash identically), so the idempotency marker
  and the `since` resolver are plain items keyed `NSID#<ns>#<id32>` — no
  GSI, and `attribute_not_exists` on the marker is the retry dedup.
  Revision ids are equally non-unique (genesis twins), which is why
  revision-by-id stays a GSI rather than becoming marker items.
- **GSI2** `G2PK`+`G2SK` — sparse lookups, some time-ordered: pending blobs
  (`PEND#`, SK `created`) and repurge jobs (`REPURGE#`, SK `due`) for the
  sweeps; gesture and undoes lookups (`GEST#<g>`, `UND#<g>`; the §7.4 partial
  indexes).

Why this shape for the SQL reader:

- `/heads` in byte order: `Query(PK=NS#demo, begins_with(SK,"RES#"), SK > cursor)` —
  DynamoDB sorts SK by bytes; §3.6 names are ASCII, so this is the byte order
  of `reads.go`. Revisions sort under `REV#`, never interleaved.
- A resource's chain, in order: `Query(PK, begins_with(SK,"REV#<name>#"))`.
  Same partition as the resource, its snapshots, history and blobs: one
  partition key holds everything a fold, purge or prune touches.
- A namespace log page: `Query(PK, SK BETWEEN LOG#a AND LOG#b)` — one page
  per 1 MiB of DynamoDB read, chained exactly like `X-Log-Next`.
- The grants/authors tables lose their raison d'être: grants key by id
  directly; author names denormalise onto revisions and log entries (they are
  metadata, not hashed — §3.5 — so duplicating them is free of identity
  concerns).

Large values (`doc`, `patches`, `body`) up to 4–16 MiB vs the 400 KiB item
limit: values over ~350 KiB are stored in S3, keyed by content hash, and the
item carries `<attr>Ref: {s3, sha256, size}`. This is the pattern
`blobstore.go` already uses for blob bytes (`file` vs `data`); it extends it
to documents and log bodies. Inline-below / S3-above keeps small writes
single-item cheap. (Chunking into segment items was considered; S3 is
simpler, cheaper per MiB, and the read paths already stream.)

## 4. The write path

D.3's shape survives: check (steps 1–6) outside any serialisation, then one
atomic commit that re-checks and inserts. On DynamoDB the commit is a
`TransactWriteItems`, and the database's guarantees replace the lock and the
unique constraints:

- **Resource chain race** (was `UNIQUE(res,parent_seq)`, `isConflict`): the
  transaction's `Update` on `RES#<name>` has
  `ConditionExpression: headPos = :checked`. Two writers both pass the gate;
  the first commit wins; the loser's whole transaction cancels with
  `ConditionalCheckFailed` → the same recheck/412/idempotent-replay path
  (`recheck.go`). A genesis conditions on `attribute_not_exists` of the
  resource item.
- **Namespace chain serialisation** (was `pg_advisory_xact_lock(logClass)`):
  the log entry `Put` at `LOG#<prev+1>` plus an `Update` of `#TIP` with
  `ConditionExpression: headPos = :prev AND headId = :prevId` — optimistic
  concurrency on one item. Entries commit in chain order with no gaps,
  because a tip that moved fails the condition. This also replaces the
  in-process mutex on the single-instance path.
- **Idempotent retry** (was `UNIQUE(ns,id)`): a `Put` of the GSI1
  `NSID#<id>` marker item with `ConditionExpression: attribute_not_exists`,
  in the same transaction (the marker records the log position, so the retry
  finds its entry through GSI1); a cancelled transaction reads the existing
  entry and replays, as today.
- **Group commit** (`groupcommit.go`): the equivalent is collecting checked
  writes of one namespace into one transaction — several `LOG#` entries at
  consecutive positions, the `#TIP` moving by n. The spike's benchmarks
  (§12) show this is **required, not optional**: optimistic retry on a hot
  `#TIP` degenerates under concurrency (Postgres queues writers on the log
  lock; DynamoDB collides them), while a grouped transaction amortises one
  tip move over up to ~13 single-resource writes (the 100-action cap ÷ 7).

A single-resource write is ~6 actions: put revision, update resource
(condition), put head snapshot (upsert), put history row, put log entry,
update tip (condition). Occasional extras: snapshot, grant (once, condition
`attribute_not_exists`), blob-ref closes, dek/epoch rows. DynamoDB forbids
two actions on the same item in one transaction, which this shape respects
by construction: each condition rides on its target's single `Update`, and
no item is written twice.

**The batch problem.** `ItemsPerBatch` defaults to **1000**; a batch commits
as *one* transaction today (§7.5). `TransactWriteItems` caps at **100
actions**, and the items one transaction writes may not exceed **4 MB** in
aggregate (against a 16 MiB default `batchSize`), so even a modest batch
cannot always map one-to-one. The S3 offload of §3 relieves the aggregate —
an offloaded patch set writes a pointer, not its bytes — but the 100-action
cap stands: a batch of more than ~15 resources cannot be one transaction.
Two honest answers:

1. **Lower the deployment maximum** (`Maximums.ItemsPerBatch`, e.g. 25) on
   DynamoDB deployments. Limits are deployment-set under §6.6; a namespace
   learns them from its document and `422 limit` names them. Simple,
   spec-clean, and batches stay atomic. Recommended for any first version.
2. **Saga batches**: commit the batch's `LOG#` entry (the entry is the
   atomic fact; it carries its items inline) with a `pending` marker, then
   apply per-resource transactions, with reads treating unapplied entries as
   invisible until applied. This preserves 1000-item batches at the price of
   read-path complexity (every read must join log truth against applied
   state) and a crash-recovery sweeper. A real design of its own; not
   recommended before option 1 proves insufficient.

Multi-step items (several patch sets to one resource in one batch) cost one
revision put per step, so they draw down the same 100-action budget.

Purge and prune (§8.1–§8.6) delete or blank many items of a resource or
namespace — unbounded, so never one transaction. These become **durable job
items** (the `cdn_repurge` pattern of `repurge.go`, generalised): a
`JOB#PURGE#…` item records progress (last position processed); a worker loop
advances it in ≤100-action transactions until done; the namespace's state
flags (`purged`, horizon) move in the *first* transaction so reads refuse
correctly from then on. Propagation to branches (§8.3) fans out as one job
per namespace. Crash anywhere: the job resumes.

## 5. The read path

Reads hold no locks on any backend today (WAL snapshots / REPEATABLE READ);
DynamoDB reads are per-request consistent. The difference that matters is
**cross-request snapshot consistency**: a fold (`resolve.go`) reads the
resource, then its snapshots, then walks revisions across many queries; a
concurrent purge could remove items mid-fold. On SQL the snapshot makes this
impossible; on DynamoDB the fold must treat a missing item as a lost race
and answer `410`/retry — the same shape as `purgerace_test.go` already
exercises. Every read loop needs that audit; it is the main correctness work
of the read path, not the queries themselves.

Everything else maps directly: head reads are 1–2 point reads; revision by id
is GSI1; log pages and chain walks are ordered Queries (1 MiB pages, so a
16 MiB `logPageBytes` page is ~16 chained reads — already paged by design);
`?at=` is a descending `HIST#` query, limit 1.

The read cache, document cache and grant cache are in-process and unchanged.
Their Postgres-only freshness source is the subject of §6.

## 6. Several instances: Streams, buckets, leader

- **The tailer → DynamoDB Streams.** The table's stream delivers every item
  change, ordered per partition key, at-least-once, for 24 h. Each instance
  polls the shards (a few lines of iterator polling; no KCL needed) and does
  what `tailPoll` does: `LOG#` records wake the namespace's live readers
  (long-poll/SSE, `live.go` unchanged); records of the meta kinds (config,
  purge, purge-ns, prune, branch, tip moves) move the read cache and flush
  the document/DEK/epoch caches. No `cache_gen` counterpart is needed — the
  stream *is* the change feed. The freshness bound (`freshFor`) becomes
  "the stream poller's lag", measured from record timestamps; while polling
  fails, the read cache stops serving, as on Postgres. Typical stream latency
  (~1 s) is far inside the 20 s long-poll interval.
- **Rate buckets.** Single-instance deployments keep in-process buckets (as
  SQLite today). Multi-instance: a `BUCKET#` item per bucket, token bucket by
  optimistic concurrency — read, compute refill, conditional write on the old
  `last`; retry on race. Draws are per request, so this is one extra read and
  a conditional write on the write path only; hot principals' buckets
  serialise on one item, which the per-principal rate limit makes
  self-limiting.
- **Leader** (retention, sweeps, repurge, rotation — the `leaderClass`
  advisory lock): a `META#leader` item with a lease, taken and renewed by
  conditional write; standard, no new machinery.

## 7. Encryption and blobs

Addendum E is application-level and untouched: DEKs, epoch keys, sealed JWEs
and e2e ciphertext are items keyed as in §3; `KeyStore` stays the wrapping
abstraction (an AWS deployment would add a KMS adapter — the noted "KMS
adapters to come" — but that is orthogonal). Blob bytes go to S3 behind the
existing `blobStore` interface, which already assumes an external byte store;
`s3://` archives (§8.6, "archives other than file://") land naturally in the
same bucket setup.

## 8. Cost and throughput notes

- Writes are billed per KiB: a 256 KiB patch set (`patchSetSize` default)
  costs ~256 WCU plus its companions. The defaults are survivable; namespaces
  that raise `patchSetSize`/`documentSize` raise their bill linearly. S3
  offload caps item sizes at ~350 KiB regardless.
- The `#TIP` item serialises a namespace's writes by condition contention.
  At the default `ratePerNamespace` (500/s, burst 1000) this is inside one
  partition's write budget; contention failures fold into the existing
  retry/recheck path. A namespace pushed past that would throttle — the same
  ceiling the log lock imposes on Postgres, arrived at differently.
- On-demand capacity fits the spiky profile; the GSIs are sparse and cheap.

## 9. What does not port

- **`secure_delete` semantics** (SQLite) and VACUUM notes (Postgres): a purge
  on DynamoDB deletes items, and S3 offloaded values are deleted objects, but
  neither is a cryptographic guarantee. Addendum E.1 remains the answer where
  purges must be final — unchanged from Postgres.
- **`ON CONFLICT`/upsert idioms** become conditional puts; `INSERT …
  RETURNING` disappears (keys are computed, not assigned).
- **Data migrations** (`migrations` table, `migrateData`): the pattern ports
  to `META#` items and job sweeps; the schema-migration machinery
  (`ALTER TABLE`) vanishes — a DynamoDB table has no schema to alter, only
  item formats to version.

## 10. How to get there — three paths

**A. A `database/sql/driver` shim over DynamoDB.** Seductive because the
query corpus is constant strings (`stmts.go` prepares only known texts): map
each known statement to DynamoDB calls, buffer a transaction's writes, apply
at Commit. It dies on semantics, not syntax: transactions re-read their own
and others' rows under snapshot isolation, joins and `json_each` bulk queries
would need a mini query engine, `pg_advisory_xact_lock` is `SELECT`-ed, and
`isConflict` inspects driver-specific errors. One would end up reimplementing
a database to avoid designing one. **Rejected**, except possibly as a
throwaway spike to count the corpus.

**B. Extract a storage port from `internal/core`, then implement it for
DynamoDB.** The principled end state: a Go interface at the granularity of
the entities in §2, with SQL and DynamoDB implementations side by side, and
the spec suite (`spec_test.go`, the test vectors of docs/TESTVECTORS.md,
`multi_test.go`, `groupcommit_test.go`) running against both. The cost is the refactor: the
`tx` wrapper is threaded through ~7k lines of write/read logic and every
feature file. Done as one big bang it is the riskiest change the project
could take; done incrementally (entity by entity behind an interface the SQL
side implements first) it is a programme, not a branch.

**C. A parallel store package behind a new, narrow seam, grown feature by
feature.** Introduce no interface up front. Instead, build
`internal/core/ddb` (DynamoDB client, key codecs, transactions, job loop,
stream poller) and a small number of *new* entry points in `core` that
delegate whole operations to a store-specific implementation — starting with
engine open/close, namespace create, resource write (single item), and the
reads that serve them — selected by the `-db` URL scheme
(`dynamodb://…?table=…&region=…`, next to file paths and `postgres://`).
Each operation lands as: shared check logic produces a plan, a per-store
"commit plan/read plan" executes it. The plan types are the seam; they start
narrow (plain namespaces: no sealed/e2e/blobs/remote) and widen per feature,
refusing unimplemented features at Open or at namespace-config time (422),
exactly as a missing `KeyStore` refuses encryption today. The spec suite runs
against it subset by subset. B is where this ends if it succeeds; C is how it
gets there without a flag day.

**Recommended: C, in phases.**

0. This document; DynamoDB Local in the compose stack for dev and tests.
1. Keys and items; namespace create; single-resource write with its log
   entry, tip condition and idempotent replay; head and log reads. The test
   vectors and the plain-namespace spec tests pass. Lowered `ItemsPerBatch`
   maximum.
2. Batches (≤ the cap), tombstone/restore, branches (foreign parents are
   cross-partition parent references), pruning with S3 archives. Group
   commit (§4, §11): the per-namespace write queue that turns `#TIP`
   collisions into one transaction of up to ~13 writes.
3. Multi-instance: stream invalidation, shared buckets, leader lease,
   repurge jobs.
4. Sealed/e2e, blobs on S3, remote branches; purge/prune job sweeps.

Phase 1 is a real milestone: it proves the transaction design (§4) and the
read-race audit (§5) against the normative vectors, which is where this
design lives or dies.

## 11. Performance expectations (spike measurements)

Measured on the spike against DynamoDB Local (same host, no network RTT,
no partitions), storage path only — no HTTP, grants, rules or validation,
which are core CPU and unchanged by the backend. The SQL column is
docs/CAPACITY.md (2 vCPU core + 2 vCPU Postgres 16, full stack over HTTP
with grants; a write there is ~13 statements).

| | spike, DynamoDB Local | CAPACITY.md, Postgres |
|---|---|---|
| write, 1 writer, one ns | 242/s, p50 3.8 ms (2 RTs) | 125/s, p50 7.5 ms |
| write, 8 writers, one ns | 167/s, p50 9.9 ms — `#TIP` contention | 310/s |
| write, 32 writers, one ns | 82/s, p50 156 ms — contention degenerates | 590/s, p50 52 ms (group commit) |
| write, 32 writers, 64 ns | 266/s (collisions where writers met) | 420/s over 1,000 ns |
| write, 8 writers, one ns, grouped | 289/s, p50 27 ms, ~3 writes a group (vs 80/s ungrouped, same run) | 310/s |
| write, 32 writers, one ns, grouped | 346/s, p50 94 ms, ~12 a group (vs 49/s ungrouped, same run) | 590/s, p50 52 ms (group commit) |
| append, 1 writer, 1 doc | 261/s, p50 3.7 ms | — |
| read head, 8 readers | ~2,000/s, p50 2 ms (1 RT) | 1,000–1,600/s, p50 4.6–6.6 ms |
| log pages of 100 | 302 pages/s ≈ 30k entries/s | catch-up ≈ 28k entries/s |

The grouped rows are phase 2's `group.go` (§13), measured on a slower
host than the spike's rows (one writer there: 164/s, p50 5.9 ms), with
the ungrouped figures of the same run alongside: grouping removes the
collapse and the errors, and the ceiling it then meets is DynamoDB
Local's per-action transaction cost, not `#TIP`.

Read the DynamoDB column as *round-trip structure*, not AWS projection:
real in-region latency adds ~1–3 ms per RT. What it establishes:

- **Single-writer latency is at least as good as Postgres**: 2 RTs vs ~13
  statements, p50 ~4 ms vs 7.5 ms measured. In-region AWS should land in
  the same band.
- **Single-namespace throughput has the same shape of ceiling as
  Postgres, and needs group commit to reach it.** Optimistic concurrency
  on `#TIP` cannot queue writers; grouping them into one transaction both
  queues them (in-process, like groupcommit.go) and amortises the tip
  move: ~13 writes per transaction at ~5–8 ms each → an estimated
  1,000–1,600/s per namespace, against Postgres's measured 590/s. The
  other ceiling is the per-partition write budget (~1,000 WCU/s): ~7–15
  WCU a small write, so ~70–140/s ungrouped, and large patch sets count
  per KiB (a 256 KiB patch set is ~256 WCU).
- **Many-namespace writes are DynamoDB's structural win**: partitions
  scale horizontally where one Postgres primary does not; per-writer
  latency stays ~4 ms, so aggregate throughput is
  writers × ~250/s until account limits.
- **Reads are the other win**: one batch read, ~2 ms locally, scaling
  with RCU and instances rather than bottlenecking one primary.
- **Log catch-up is on par** (~30k entries/s both), paged as designed.

Cost shape (on-demand): ~7–15 WCU per small write, ~2 RCU per consistent
head read, plus storage per GB; S3 offload bounds the per-KiB exposure of
large patch sets and documents (§3).

## 12. Open questions

- Exact per-feature action counts vs the 100-action cap (batch composition,
  multi-step items) — measure on the phase-2 prototype before fixing the
  lowered batch maximum. (The spike's single write is 7 actions, as
  estimated.)
- Whether log bodies and head documents offload to S3 always or only above
  the threshold (read amplification vs cost); the `blobstore.go` precedent
  says threshold.
- GSI1 write amplification on hot namespaces (every revision writes one GSI
  entry) — likely fine; confirm with the capacity numbers of
  `docs/CAPACITY.md`. The spike already removed the ns-entry markers from
  it (§3).
- Whether `#TIP` contention ever binds before `ratePerNamespace` does at
  raised limits — the spike's 8-way race resolves cleanly by retry; a
  load-test question for phase 3.
- ~~One sort-key condition per query for paged listings~~ — answered by
  the spike: first page `begins_with`, later pages `SK > cursor` stopping
  at the prefix boundary.

## 13. Status: phase 1 integrated

Phase 1 of §10's path C is implemented and wired in, behind the `-db`
URL scheme:

```sh
patchlog -dev -db 'dynamodb://patchlog?region=eu-west-1'          # AWS
patchlog -dev -db 'dynamodb://spike?region=us-east-1&endpoint=http://localhost:8000'
```

The table is pre-created (PAY_PER_REQUEST is fine) with the key schema of
§3 and GSI1 (`G1PK`, project ALL); phase 1 does not create it for you.

What landed, beyond the spike:

- **`internal/core/ddb.go`, the seam.** `core.Open` branches on
  `ddb.IsURL(opt.Path)`; the Engine keeps a `*ddbBackend` and every
  phase-1 method delegates: `WriteResource` (single patch-set step, and
  DELETE's tombstone step — §8.1 works end to end: the deterministic
  tombstone id, replay, restore as §6.2's verb, the 410 serving paths
  with `Last` and `$successor`), `WriteConfig` (creates and changes),
  `Batch` (§7.5: single-step items, per-item failure lists, dry runs, an
  optional config change gating the items under its result, the
  100-action budget lowering ItemsPerBatch to ~24), `ResourceHead/Raw/
  Rev/Log`, `NamespaceHead/Rev/Log/Heads`, `NamespaceLiveLog`, `Wait`,
  `Ping`, `Close`. Everything else the server can reach answers **501
  "unsupported"** rather than falling through to SQL: multi-step items,
  branches, purges and pruning, blobs (batch sources with them),
  sealed/e2e, grants (`Grant`, `Principal`, `Keys`, `IssueEdgeGrants`),
  gestures listing, event streams, author signatures.
- **The thin gate (§6.2 subset).** The store's check hook runs *after*
  planning, inside the retry loop, so limits (step 2) and namespace rules
  (step 6, against the §6.4.1 envelope — `doc` always, `patches` when a
  rule reads them, `principal: null` in `-dev`) evaluate the document the
  transaction will actually commit, re-done on every attempt (D.3's
  recheck shape). Refused configurations (`encryption`, `nonce:
  required`, `base`, `successor`, `$schema` documents) are 501 at
  create/change/write time, as §10 prescribes ("refuse at Open or at
  namespace-config time").
- **Reads as items.** Revision-by-id is GSI1; `…/rev/{id}` folds from the
  genesis (snapshots are a later phase); `…/rev/{nsID}` joins the entry's
  denormalized `cfgPos` (the `ns_log.config_seq` of the SQL schema);
  `/heads` serves `created`/`size`/`digest` off the RES item's head
  metadata; log entries serve `grant: null` in `-dev`, with gestures
  merged in unhashed (§7.4).
- **Errors in the core's body shape** (`{"code": …}`), so the HTTP layer
  serves either backend alike.
- **Group commit (§4, phase 2).** `internal/ddb/group.go`, on with
  `-group-commit` (default 32) as on Postgres: each resource write or
  delete runs its check phase alone, then queues; a worker per namespace
  takes the queued writes that fit one transaction (distinct resources,
  one configuration, ≤ 100 actions: six a write, five a delete, two
  shared, so ≤ 16 writes) and re-chains their entries over the tip at
  consecutive positions — an entry's id covers the one before it, not
  anything the write's gate read. The transaction pins every write's head
  as ungrouped, moves `#TIP` once, and carries a `ConditionCheck` that
  `#META`'s `configPos` is still the one the writes were checked under,
  so a write's gate holds at commit though the tip it read moved on. A
  write whose head moved is answered alone (412, or its replay); a moved
  tip (another instance) is re-read and the group re-chained; a changed
  configuration or an unknown outcome sends each write back round its own
  loop. Batches and config writes don't queue: they hold a per-namespace
  commit lock, shared with the worker, from their reads to their commit.
  §11 has the measurements.

Requirements and limits, by design: `-dev` (writes need authentication
disabled; reads of non-`public` namespaces are 501), one instance (no
stream invalidation — §6 is phase 3), no background loops (retention,
sweeps, rotation, remote follow don't start).

Tests: the API-level suites are backend-agnostic. Every test server —
the server package's HTTP harness, and `clienttest`'s, which the client,
bundle, dav, tree, merge and other service suites start — takes its
database from `internal/testenv`, so

```sh
PATCHLOG_TEST_BACKEND=dynamodb DDB_ENDPOINT=http://localhost:8000 go test ./...
```

runs them on DynamoDB Local, a fresh table each, as `PATCHLOG_TEST_PG`
runs them on Postgres; CI's `dynamodb` job does. What the backend hasn't
built skips without per-test annotations: `core.Open` refusing an option
with `core.ErrUnsupported` (authentication, encryption at rest, blobs,
archives, the SQL write path's hooks), or a `501 {"code":"unsupported"}`
answer on the test's own goroutine. Tests that run and answer
differently are its **known divergences**,
`internal/testenv/known_dynamodb.txt`, each with the failure seen,
skipped until fixed (`PATCHLOG_TEST_KNOWN=run` runs them) — the
backend's to-do list. At the time of writing, of the suites' 1,009
top-level tests: 277 pass on DynamoDB, 579 skip as unsupported (232 for
authentication, 114 encryption at rest, 67 `$schema`, 67 branches, 32
blobs, …) and 153 skip as known divergences. The list has 156 entries
(a few name tests that now skip earlier as unsupported): 40 where the
backend answers differently (rate limits, `If-Match` on appends, retries
answered 412, creates without a root replace, namespace limits…) and 116
that meet an unsupported feature inside a service (mostly the dav
gateway's principal lookup), where no skip can reach.

`internal/ddb`'s and `internal/core/ddb_test.go`'s own tests (the store's
transactions, races and group commit; the engine seam) stay gated on
`DDB_ENDPOINT`, and the full suite passes with and without it — the SQL
backends are untouched when `e.ddb` is nil.
