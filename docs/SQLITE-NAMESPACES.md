# SQLite: a file per namespace

A design, not an implementation: how the core would keep each namespace in a SQLite file of its
own, so that writes to different namespaces stop sharing one writer, and how that compares with
group commit on the single file. Written against `main` at `772ac38b` (2026-11-24). The SQLite
write path it describes (`db.go`, `recheck.go`, `groupcommit.go`) is unchanged since
`b13be98a`, the tree the EC2 bench below ran. References: § to [SPEC.md](SPEC.md), D.x to the
prototype's Addendum D as the README uses them, files to `internal/core/` unless named.

## Recommendation

**Do both, group commit first.** Enabling the existing per-namespace group commit
(`groupcommit.go`) on SQLite is a small change that roughly doubles what the one writer
commits when a namespace has many writers: measured here at 1.6–2.7 times with 16–32 writers,
with a third of the disk bytes per write. It carries over unchanged to the per-namespace layout. Then build the
file-per-namespace layout behind a new `--db DIR` form, keeping the single file as the default
and as one configuration of the same code. That is what gives namespaces independent writers,
cores to scale on and a quiet namespace its own latency. Its cost is a routing refactor of about
340 query sites, a catalog file, and three cross-file protocols with recovery on open. The
estimates and their basis are in [Group commit for SQLite as the
alternative](#group-commit-for-sqlite-as-the-alternative).

Cross-namespace atomicity is never asked of SQLite. Writes that only *depend* on other
namespaces (a branch's base keys, a `$schema` in another namespace, a batch source) stay
single-file. Invariant 6 holds for them through per-namespace locks, as on Postgres. The three
writes that *change* several namespaces (branch creation, namespace creation, purge
propagation) record an intent in the catalog first and roll forward on open. While they commit,
a reader that spans those files waits at a per-namespace gate. Derived state in the catalog
(mirrored flags, the deployment-wide schema indexes) is written before the namespace commit it
covers, as a superset, so a crash leaves at worst a stale entry. Nothing here uses a shared
rollback-journal file: [why not](#choosing-how-to-keep-multi-file-writes-atomic).

## The problem, measured

The EC2 bench (doors `apps/ouroboros/bench/aws/ec2-sources.sh`, `DB_ENGINE=sqlite`): a
`c7g.2xlarge` store, its SQLite file on gp3 (6,000 IOPS), patchlog `b13be98a`, each namespace
asked for 1,000 writes a second:

| namespaces | written/s | per namespace | write p50 / p99 ms |
| ---: | ---: | ---: | ---: |
| 1 | 999 | 999 | 3 / 21 |
| 2 | 1,010 | 505 | 196 / 261 |
| 8 | 1,011 | 126 | 753 / 909 |
| 32 | 723 | 22 | 4,538 / 4,887 |

The store used 12–20% of 8 vCPUs (about one core) with 0–7% iowait. After the run the file was
175 MB and the WAL about 5 MB. A quiet namespace beside 31 busy ones got 19 of its 100 writes a
second. On Postgres a namespace takes about 1,000 a second, and two stores on a
`db.m7g.4xlarge` reached 28,070 across 32 namespaces ([CAPACITY.md](CAPACITY.md)).

**Why (verified in the code).** `Engine.update1` (`engine.go`) takes `Engine.mu` for every
SQLite write transaction, and the DSN (`openSQLite`, `db.go`) sets `_txlock=immediate`, WAL and
`synchronous(NORMAL)`. So every write transaction in the deployment runs alone, as its own
`BEGIN IMMEDIATE … COMMIT`. Group commit is Postgres-only: `grouping()` is `e.pg &&
e.opt.GroupCommit > 1` (`groupcommit.go`), and `appendNSMany` (`engine.go`) is Postgres SQL
(`unnest`, `nextval`). The D.3 split (`writeOptimistic`, `recheck.go`) already moves steps 1–6
out of the lock. What stays inside is the re-check, the inserts and the commit. Every query goes to
the one database, and the D.2 schema keeps every namespace's rows in shared tables with global
integer keys.

**What the serialised work is (measured here).** One 4-vCPU host (Intel Xeon at 2.1 GHz,
15 GB, ext4 on virtio), Go toolchain 1.26.1, `main` at `772ac38b`. These are small appends
(`benchWrite` documents) on a SQLite file (`benchFileEngine`). Phases were timed with the
engine's own hooks (`BeforeWriteLock`, `afterWriteLock`, `BeforeCommit`) and, separately, with
timers around `sqlTx.Commit` in a temporary patch:

| phase, one write alone | µs |
| --- | ---: |
| check outside the lock (`checkOutside`) | 68–72 (`BenchmarkCheckAppend`: 54) |
| mutex and `BEGIN IMMEDIATE` | 7 |
| re-check and inserts | 133–135 |
| `COMMIT` (WAL frames, plus the autocheckpoint when due) | 185–213 |
| held under `Engine.mu` | 330–352 |

Batches of *k* small appends in one transaction held the lock for 352, 194, 164 and 160 µs per
item at *k* = 1, 4, 16 and 64. So about **130–190 µs of a write is per transaction**, and
**about 160 µs is per write**: roughly half of each. With `wal_autocheckpoint(0)` the commit
phase fell from 239 to 132 µs for one write, and from 1,443 to 481 µs for 16. Checkpoints run
inside `COMMIT`, under the mutex, and they are about half of it. `/proc/self/io` counted 72–76 KiB
of disk writes per small write (WAL frames plus checkpoint backfill), which is about 17 pages.

The EC2 figure of about 1 ms per serialised write is about three times this host's. That
difference is assumed to be Graviton versus Xeon, plus checkpoint fsyncs on gp3 inside the lock.
It was not measured: Phase 0 profiles it.

## Layout

`--db /data/pl` naming a directory (or a new directory) selects the layout. `--db file.db`
keeps the single file:

```
/data/pl/catalog.db               the shared file
/data/pl/ns/{hh}/{ns}.db          one per namespace, by catalog id (hh = ns mod 256, hex)
/data/pl/ns/{hh}/{ns}.db-wal|-shm
/data/pl/blobs/{ns}/…             blob bytes, per namespace (see Lifecycle)
/data/pl/LOCK                     flock: one process per directory
```

Files are named by id, never by name. Names are long (§3.6), and a namespace is never renamed
or deleted. `chain.go`: "no namespace row is ever deleted". `purgeNSNow` only marks one
purged. An old binary given the directory fails to open it, so the catalog can never be
migrated as a single-file database by mistake.

### What each table becomes

Every table of `migrations/sqlite` as applied (29 migrations; dumped from a fresh database):

| table | goes to | why |
| --- | --- | --- |
| `namespaces` | **both** | Catalog: `ns`, `name` (unique), `base`, `base_at`, `base_config_seq`, which are immutable once inserted (`chain.go`, `nsLink`), plus `block`, `state` (`creating`/`live`), `created` (the first entry's, for `GET /ns`, `nslist.go`, and `operatorkeys.go`'s first entry), and mirrors (below). Namespace file: its own row only, with the mutable `head_seq`, `head_id`, `config_seq`, `frozen`, `purged`, which every write moves (`appendNSMeta`). The `base` foreign key is dropped there: the base's row isn't in the file. |
| `resources`, `revisions`, `heads`, `snapshots`, `head_history`, `ns_log`, `ns_config` | namespace | The chains. Every query names its namespace or a key of a row in it. `revisions` gains `parent_ns` for a foreign parent (§7.6), which `ancestry` (`resolve.go`) finds today by a global `WHERE seq = ?`. |
| `authors` | namespace | Today the first write of a new name inserts one (`authorID`, `engine.go`). Shared, that is a shared write on the hot path. Ids are block-unique (below), so `idCache.authorNames` stays keyed by id; `idCache.authors` becomes keyed by (namespace, name). |
| `grants` | namespace | `storeGrantBlocks` (`crypt.go`) upserts on each transaction that uses a grant. Shared, that is a shared write per write. A grant then lives in every namespace it wrote in. Its id is content-addressed, so copies are harmless, and each is encrypted at its own namespace's level. Lookups by id (`grantref.go`, `crypt.go`) are made while serving or writing one namespace's entries, so they go to its file; those by entry (`grants.go`, `archive.go`) already name the namespace. |
| `deks` | namespace | One per resource row (`crypt.go`). The grants key (`grantsDEK = 0`) becomes one per file, still `res` 0. Its AAD is unchanged, so migrated rows decrypt as they are. |
| `epoch_keys`, `rev_epochs`, `sealed`, `seal_counts`, `e2e_epochs`, `e2e_snapshots` | namespace | Keyed by `ns`, `res` or a revision `seq`. |
| `blobs`, `blob_pending`, `blob_refs`, `blob_bytes`, `blob_epochs` | namespace | See blob storage under Lifecycle: owner-0 bytes are no longer shared across namespaces. |
| `archives` | namespace | Per resource. `archive.go`'s scan joining `namespaces` becomes per file. |
| `cdn_repurge` | namespace | Queued in the write's own transaction, "durable with the commit" (`queueRepurge`, `updateOnce`). `ns_seq` stays unique per file. The loop is in Lifecycle. |
| `rotations_due` | namespace + mirror | Written in the config write that revokes (`sealed.go`). The rotation loop finds namespaces by a catalog mirror flag. |
| `purge_follows`, `purge_follow_names`, `purge_follow_waiting` | namespace + mirror | Keyed by `ns` (`purgefollow.go`). The follow loop finds them by a catalog flag. |
| `filtered_views`, `filtered_view_exps` | namespace | Keyed by namespace name (`recordFilteredView`). The sweep (`filtered_state.go`) runs per open file. |
| `read_judged` | namespace | A cache of per-revision read answers written after reads (`flushJudged`, `filtered_visible.go`). Each row goes to the file of the namespace read, so `judgedRow` gains it. |
| `rate_buckets` | neither | Postgres only. SQLite keeps buckets in memory (`rateLimiter`, `auth.go`; `ratebuckets.go`). |
| `mmmigrate_applied`, `mmmigrate_current`, `sqlite_sequence` | each file | Each file is migrated on its own (Lifecycle). Each file's `sqlite_sequence` is seeded with its block. |
| *new* `schema_refs (schema_ref, ns)` | catalog | Replaces the deployment-wide use of `revisions_schema_ref`: `possiblyReferenced` and `usesWalkOf`'s `holds` (`drafts.go`). A superset (below). |
| *new* `schema_copies (id, name, ns)` | catalog | Replaces `revisions_by_id` for `copyRows` (`drafts.go`), and only for revisions whose document is a schema (`schema.IsSchemaDoc`). Those are the only ids `copyRows` is asked for. |
| *new* `intents` | catalog | The multi-file operations in flight (below). |

**Mirrors.** `frozen`, `purged`, the encryption level, "has retention rules", "rotation due"
and "has purge follows" are copied into the catalog row. Several scans read them across the
deployment: `liveBranchesCount` (`nsconfig.go`), the purge walk (`nspurge.go`: `purged = 0`,
`base_at >= lo`), `retention.go`, `RotateDue`, `purgefollow.go` and `GET /ns`. Opening every
file for those would cost about 1 ms each (measured below). A decision that needs the committed
truth reads the namespace's own file under its lock, never the mirror. That covers
`successorOK`, which takes the successor's state lock and reads its `purged` there. Mirrors
serve listings, candidate enumeration and counts that err on the safe side. Updating a mirror
follows the pending protocol below.

### Integer keys

`resources.res`, `revisions.seq`, `ns_log.seq`, `ns_config.seq`, `authors.author` and
`archives.seq` are referenced across namespaces today. A branch's first revision names its
base's revision as `parent_seq`. A branch reads its base's rows through `resolve`, whose `view`
holds a base's `resRow` and `revRow`. A base's `branch` entry has the branch's `ns_config` seq
as `target_seq` (`createBranch`). `base_at` and `base_config_seq` are the base's seqs. In
memory they key `memo.rev`, `cfgCache`, `deks` and `knowRevID`. So they must stay unique
across files.

**Blocks.** The catalog gives each namespace a block of 2³² ids at creation. Each table of its
file is `AUTOINCREMENT`, with `sqlite_sequence` seeded to `block << 32`. A file that exhausts a
block gets a new, higher one, so seqs keep growing along each chain (pglock.go relies on that
ordering on Postgres; here only within a file). 2³¹ blocks fit in a signed 64-bit key. Block 0 is
the single file's ids, kept as they are when a database is converted (Lifecycle).

**Routing is by origin, not arithmetic.** Rows carry the namespace they were read from
(`resRow.ns` already does; `revRow` gains it). `config(seq)` becomes `config(ns, seq)`. A
foreign parent is found through `revisions.parent_ns`. So nothing derives a file from an id,
and block-0 ids from a converted database need no lookup table. A fixed split (ns in the high
24 bits) was rejected: it limits namespaces to 16.7M over the deployment's life, branches
included.

## Locks

Postgres already proves what can be independent per namespace (`pglock.go`). The per-file
layout keeps its rules and swaps the primitive. The lock manager is in-process: one
`nsLocks` entry per namespace id, created on demand and reference-counted.

| Postgres (`pglock.go`) | per-file SQLite |
| --- | --- |
| `pg_advisory_xact_lock(lockClass, ns)`, shared or exclusive | `state`, a `sync.RWMutex`: the same holders in the same modes (`nsForWrite` exclusive, `nsForResources` and every namespace a decision reads shared) |
| the log lock (`logClass`), taken last, held through commit | `writer`, a `sync.Mutex`, plus `BEGIN IMMEDIATE` on the file, taken after every state lock, held through `COMMIT`. SQLite has one writer per file, so it covers the whole write transaction, not just the append |
| a lock below the highest held is only tried; busy → `errRelock` and run again with all of them up front | the same, with `TryLock`/`TryRLock` |
| (MVCC snapshots) | `cut`, a `sync.RWMutex`: readers take it shared while they open their snapshots of several files; a multi-file write holds it exclusive while it commits (Cross-namespace operations) |
| leader lock (`leader`) | `LOCK` (flock) for the directory, held for the process's life |
| — | `catalogMu`, the catalog file's writer: a leaf, held only for short catalog transactions |

**Order.**

1. State locks, in ascending id, as `lockAll` takes them. One below the highest held is only
   tried, and if it is busy the transaction rolls back and runs again with every lock it needed
   taken up front (`errRelock`, `relockAll`).
2. Then the `writer` of the file being written. A transaction holds more than one `writer` only
   while it holds all of their namespaces' state locks exclusive (the multi-file writes below),
   and takes them in ascending id.
3. A multi-file write takes the `cut` locks of its files exclusively, ascending, after all its
   state locks, before its first commit.
4. `catalogMu` is a leaf. It may be taken while holding any of the above, and its holder waits
   for nothing else.

A holder of `writer` waits for no state lock: it only tries one, as a holder of a log lock does
(`lock` in `pglock.go`). A holder of another namespace's `writer` either holds that namespace's
state lock exclusive or is a writer that waits for nothing, such as the read caches'
`flushJudged`. So the only way to wait for a `writer` held by another transaction is behind a
transaction that will finish without waiting for you. Readers take only `cut` shared,
ascending, and hold nothing else while waiting. Every wait is therefore for a lock above all
those held, or for a holder that waits on nothing, and no cycle can form. Go's `RWMutex` blocks
new readers once a writer waits, so config writes don't starve behind streams of resource
writes. The cost: a transaction must never take a lock it holds a second time (it would
deadlock behind a waiting writer). `t.locks` already records what is held, as `lock` does.

**`writeOptimistic` maps over as it is** (`recheck.go`, `writeAlone`):

- *Check*, outside any lock: read transactions on the target's file and on the files it reads
  (the base chain under `cut`, schema and source namespaces as they are found). It records
  `writeDeps` as now. Before taking any lock it makes the catalog's schema supersets cover the
  plan (below), in a catalog transaction of its own.
- *Lock*: `lockDeps`, so the target and every dependency shared in ascending order, then the
  target's `writer`, then `BEGIN IMMEDIATE`.
- *Re-check*: `recheckIn` reads the target in its transaction, and each dependency's row from
  its own file in a read transaction begun after its lock is held. That is Postgres's rule:
  "every read of a namespace happens after its lock is held". `sameNS` ignores the head, as it
  must: another namespace's head moves under a shared lock.
- *Insert and commit*, then release `writer` and the state locks.
- After `optimisticAttempts` (3) rounds, `writeLocked` runs the whole gate in the target's write
  transaction. There a dependency found late is only tried, and `errRelock` restarts with it up
  front, exactly as `lock` does under a held log lock.

Checking inside the lock (Postgres's `LockedCheckBytes` path) is not taken. Here `writer` is
exclusive per namespace, so checking inside it would serialise the check too.

**Invariant 6** (§4 "Configuration in force", D.3). Everything a write's decision rests on is
held at least shared from the re-check through the commit: its namespace's configuration,
frozen and purged flags, every base whose keys and revocations apply (§C.4), the namespaces its
`$schema` and `$ref` resolve into (§6.1) and a batch source's. Everything that changes those
takes them exclusive: config writes, freezes, purges, prunes, branch creation on the base,
namespace purges and encryption changes. The heads it checked are its own namespace's,
serialised by `writer` and compared in the transaction (`sameView`). Each dependency is read in
a snapshot begun after its lock. So a write is inserted against exactly the configuration,
heads and revocations it was checked against, and a re-check that fails redoes the check, as
now. A branch's read-through is as of `base_at` (immutable rows, invariant 7) except purges and
prunes in the base, which take the base exclusive.

**What changes besides.** `snapshotRows` (`chain.go`) returns true for every SQLite
transaction: "In SQLite a write transaction is the only writer". With several files that holds
only for the file it writes. It becomes Postgres's rule: a kept row of another namespace is
valid only under that namespace's lock (`held`, `keepLocked`). `memo.schemaNS` (`memo.go`)
relies on the same claim and follows. `locking()` is true on SQLite too. `update` is told its
target before `BEGIN`: `e.update(ctx, f)` becomes `e.updateIn(ctx, ns, mode, f)`, because
`nsForWrite` is called inside the transaction today and SQLite must know which file to begin.

**One process.** §5 asks for the invariants "under concurrent writers and multiple processes".
Today `BEGIN IMMEDIATE` serialises processes sharing the file. In-process locks can't. The
directory's `LOCK` makes a second `serve` (or any tool that opens the store, such as `archive
restore`) fail fast. Several processes remain Postgres's job. The single file today has no
tailer either, so a second process on it never woke live readers or invalidated caches
(`tailer.go` is Postgres-only).

## Cross-namespace operations

Found by reading every statement on `namespaces` (60 in core), every statement over several
namespaces' rows (`inArray("ns", …)`, recursive chains, joins with `resources` by name or id)
and every caller of `nsByName`/`nsByID` for a namespace other than the target.

| operation | where | writes | how it stays correct |
| --- | --- | --- | --- |
| branch read-through, foreign parents | `resolve`, `base`, `seedResources`, `ancestry`, `findInAncestry` | — | Reads the chain's files in one cut (Reads). Base rows are as of `base_at`. |
| base keys and revocations re-checked (§C.4) | `authenticate` (`auth.go`), `grants.go`, `recheckIn` | — | Bases shared-locked (Locks). |
| `$schema`/`$ref` into another namespace, drafts (§6.1, §F.9) | `loadSchema`, `copiesIn`, `docRules`, `schemaNS` | catalog supersets | Shared locks on schema and draft namespaces. Supersets below. |
| batch source, `Blob-From` (§7.5, §7.8) | `checkSource` (`source.go`), `blobs.go` | target only | Source shared-locked. Bytes hard-linked into the target's blob directory before its row commits. |
| `successor` (§7.4) | `successorOK` | — | Successor shared-locked, read from its file. |
| `branchesPerNamespace`, dependents (§6.6, §8.5) | `liveBranches`, `branchDependents` | — | Catalog mirrors. A mirror pending is read as its old value, the state before the commit in flight. Every such decision then errs towards refusing. |
| `in_use` of schema purges and `drafts.for` (§6.1) | `refsInUse`, `brokenEach`, `touchedPaths`, `usesWalkOf` | — | Catalog `schema_refs`/`schema_copies` give the candidate namespaces. Each candidate's file gives the exact answer, read under its lock where `brokenReferences` locks today. |
| **branch creation** (§7.6, invariant 5) | `createBranch` | base + new file + catalog | Intent: creating row, then the file, then the base entry as commit point. |
| **namespace creation** | `createNamespace`, `insertNamespace` | new file + catalog | Intent: creating row, then the file renamed in as commit point. |
| **purge propagation** (§8.3) | `Purge` → `purgePlan`, `purgeApply`, `appendPurges` | n + every branch reached | Intent and roll forward, leaves first, n last. |
| namespace purge (§8.5) | `PurgeNamespace`, `purgeNSNow` | one file + mirror | Refused with dependents, so single-file. Mirror protocol for `purged`. |
| config writes, freezes (§7.4, §8.4) | `WriteConfig`, `insertConfig`, `encryptNamespace` | one file + mirrors | Mirror protocol. Base config changes never write branches: branches re-check base keys on their own writes (`keepsStarKeys` reads only). |
| imports, followed purges (§G.4, §G.1) | bundle import over the API; `purgefollow.go` | via Purge | Imports are namespace creations and batches over the API. A followed purge is a Purge. |
| edge-grant exchange (§C.5) | `POST /edge-grants` | — | Each namespace judged in its own file. A grant naming several is judged per namespace, as per request today. |
| retention, epoch rotation, repurge, view sweep | `ApplyRetention`, `RotateDue`, `Repurge`, `filtered_state.go` | one file each | Each prune or rotation is already its own transaction. Candidates come from catalog flags. |
| `GET /ns` | `pageNamespaces` (`nslist.go`) | — | Catalog only: name, created, base, frozen, purged. |

### Choosing how to keep multi-file writes atomic

- **Avoiding cross-file atomicity** is chosen for everything a write *reads* across namespaces
  (every row above but the three in bold): locks give the decision, and only one file is
  written, besides the catalog's derived state.
- **Ordered writes with recovery on open** is chosen for the three writes that change several
  namespaces. All three are rare, and each can be made idempotent.
- **A shared rollback-journal file** is rejected. SQLite's super-journal makes a transaction
  across attached files atomic only when no file is in WAL. Readers would then block writers,
  and each commit costs several fsyncs. That is the contention this design removes.
- **ATTACH** is rejected as the mechanism. In WAL it is atomic per file only, and attaching is
  per connection, limited to 10 (125 at most), and not allowed inside a transaction. Every
  cross-file statement found above is a loop over a handful of files, or over the catalog.
- **A file per branch tree** (a root namespace and all its branches in one file) would make
  branch creation and purge propagation single-file and give the read-through one snapshot.
  Branches of one namespace would then share a writer again, and a session is a branch: Doors
  runs shared editing sessions as branches. Rejected as the default. It is the fallback if the
  intent protocol proves too costly to keep right.

Three mechanisms cover the rest. "FULL" means a commit under `synchronous=FULL` (an fsync of the
file's WAL). All other commits stay `NORMAL`.

**Catalog-first supersets** (`schema_refs`, `schema_copies`). Before a write in namespace X
commits a revision whose `$schema` is path P, the pair (P, X) is in the catalog, committed FULL.
Likewise (id, name, X) for a schema document. The engine keeps each open file's set in memory,
read once by `SELECT DISTINCT schema_ref FROM revisions` on its local index. So the catalog is
written only on a namespace's first use of a path, or a schema revision's first copy in it.
Concurrent inserts of this kind share a catalog transaction.

- *Crash after the catalog commit, before X's:* the pair names nothing. That is harmless: every
  reader goes on to X's file for the exact answer. A periodic rebuild drops stale pairs.
- *Correctness:* a purge of a copy in S holds S exclusive. A write that resolved into S holds S
  shared until X commits, and its pair committed before that. So a purge sees every committed
  reference, as `schemaUses` argues for Postgres ("a write that makes a schema referenced holds the
  lock of the namespace it resolved it in shared, and purges hold that lock exclusively").
- *Copies in the namespaces a change touches* (`touchedPaths`) are read from those files, which
  the change holds exclusive, never from the index. A missing or stale `schema_copies` row
  elsewhere can then only make a copy look like the last one, which refuses (`409`) a purge that
  would have been allowed, never the reverse.

**Mirror protocol** (frozen, purged, level, flags). The writer holds the namespace's state lock
exclusive:

1. Set the catalog row's `pending` to the new values (FULL).
2. Commit the namespace's file.
3. Apply the values and clear `pending`.

- *Crash between 1 and 3:* recovery reads the file and fixes the row. A pending row is read as
  its old values (see the table).

**Intents** (branch creation, namespace creation, purge propagation). An `intents` row,
committed FULL, records everything needed to finish without deciding anything again: the kind,
the namespaces in apply order, the name, the author, `forced`, and the transaction's clock (the
entries' `created`). The writer holds every involved namespace's state lock exclusive from the
check until the end, and takes their `cut` locks exclusive from its first commit to its last.
Recovery runs at open, before the first request, and finishes every intent: forward where the
commit point was reached, back otherwise. At that moment no request has run since the crash, so
the decision made under the locks still stands. Each step is idempotent. A namespace entry the
server writes for an intent records the intent id in a new unhashed `ns_log.intent` column, as
`gestures` is stored beside the hash. A step finds its own earlier run there.

### Branch creation (invariant 5)

§4: "Creating a branch writes its `branch` entry in the base's chain, atomically with the first
`config` entry of the branch's own chain." Under the base's state lock (exclusive, as
`nsForWrite`) and its `writer`, the gate runs in the base's write transaction T, unchanged
(`createBranch`, steps 1–6, `liveBranches`, `keepsStarKeys`). Then:

1. Catalog (FULL): a new id and block, the row with `state = creating`, and the intent. The
   name is now taken.
2. The branch's file is built from the template at a temporary path, holding its namespaces row,
   genesis `ns_config`, `config` entry and epoch keys (`sealedConfigWritten`). It is committed
   FULL, fsynced, renamed into `ns/{hh}/`, and the directory is fsynced.
3. Under `cut` for the base and the branch: append the `branch` entry in T, with `target_seq` the
   branch's `ns_config` seq, and commit T FULL. **The commit point.**
4. Catalog: `state = live`, the mirrors, and the intent deleted.

Crash cases:

| crash after | recovery finds | does |
| --- | --- | --- |
| 1 | `creating`, no file | deletes the row and the intent (the id is never reused): no branch, and the client's retry creates it (§7.2) |
| 2 | `creating`, a file, no entry in the base | deletes the file, the row and the intent: no branch |
| 3 | `creating`, the entry in the base (`kind = branch`, `target_seq` in the block) | sets `live`: the branch exists, and a retry is answered by `branchRetry` |
| 4 | — | nothing |

While a row is `creating`, `nsByName` treats the name as taken for a second creation (which
waits for the first and then decides, as Postgres's unique index makes it wait). Reads treat it
as absent. The `branch` entry becomes visible to readers of the base only at step 3. They see it
under `cut`, with step 4 following before the cut is released, so in one process no reader sees
the entry without the branch.

### Namespace creation

Catalog row `creating` (FULL), then the file built and renamed in with its genesis entry (the
commit point: rename plus directory fsync), then `live`. Recovery: a file means `live` (the
retry gets `200`, §7.2); no file means the row is deleted.

### Purge propagation (§8.3)

`Purge` runs as now in n's write transaction T up to the plan. `purgePlan` locks n and every
branch reached exclusive (found by walking the catalog's branches, `purgeLevels`; see the
risks), then come `refsInUse` and the rules. All of it is
decided before anything is written. Then:

1. The intent (FULL): n, the name, the author, `forced`, the clock, and the candidates
   leaves-first.
2. `cut` exclusive on n and the candidates.
3. For each candidate b, its own transaction on b's file: the effects of `purgeApply` for b, and
   its server-written `purge` entry carrying the intent, committed FULL. Candidates are
   independent files, so these may run in parallel goroutines.
4. n's own effects and entry in T, committed FULL. **The point after which the purge is
   reported.**
5. Release the cuts and delete the intent.

| crash after | recovery |
| --- | --- |
| 1, or *k* of *N* candidates done | applies the candidates without an entry for the intent, then n, then deletes the intent |
| 4 | deletes the intent |

Roll forward is the only possible direction. Steps already committed destroyed content:
`secure_delete`, keys gone with `deleteDEKs`, files dropped. A purge whose answer was lost in a
crash is reported as done, which is what a Postgres commit whose answer was lost looks like.
The client's retry gets the purged resource's `410` (§8.3).

**Why leaves first.** A branch that reads the name through resolves into n's rows. If n's purge
committed first, such a branch would briefly read a purged base revision through a resource
row of its own that isn't purged yet. Leaves first, a purged b answers `410` from its own row,
and when n commits every branch already has. A reader that reads b and then n in two requests
can see b purged while n is not yet. That is an ordering Postgres never shows, but it reveals
nothing: the content is gone from b first. It is documented as allowed.

### Writes in flight and readers

A writer of an involved namespace waits at its state lock. A reader of one file sees each file
before or after its step. A reader of several files (a branch with its bases) opens its
snapshots under `cut` shared, so it sees the whole operation or none of it. Files a read
reaches later (schemas, drafts, a source) are opened without the cut. What a read takes from
those is decided by that namespace alone, a schema revision's availability, and such a
namespace is never a branch (§6.1 "Never into a branch"). The case left open is a draft read
from a branch while its own purge propagates. It is listed under risks.

## Reads, live followers and caches

**A read.** The catalog lookup is from memory (`idCache.nss` and the immutable catalog
columns, never invalidated, since nothing in them changes). Then the namespace's database from
the file manager (below), then a read transaction. A branch's read takes `cut` shared on its
chain in ascending id, begins a read transaction on each file and forces the snapshot with the
namespaces-row read it needs anyway, then releases the cuts. The chain is at most `BranchDepth`
deep (8 by default, `config.go`). `seedResources` and `readChain` become one primary-key lookup
per file instead of one statement.

**Long-polls, event streams, heads, the namespace log.** The engine still sees all its own
commits, since one process writes every file. `updateOnce` calls `invalidate` after each file's
commit, which publishes to the `hub` (`reads.go`) per namespace, as now. Waiters hold no
transaction while they wait (`Engine.Wait`, `WaitResource`), so a followed but idle namespace
needs no open file. A woken waiter reopens it (about 1 ms, below) if it was evicted. Shared
long-poll reads (`liveReads`, `liveDone`, `quiet`, `live.go`) are per namespace already. `/heads`
and logs of a branch read the chain as above. The namespace log is its own file only (a base's
`branch` entries are in the base's file).

**Caches** stay engine-wide. `docs` are keyed by revision id (§3.3), `cfgCache` by `ns_config`
seq (block-unique), `deks` by `res`, `ekeys` by (ns, epoch), and grants and `grantRoots` by
grant id. The read cache's `meta` counter stays global: a config write anywhere still stops
serving cached answers everywhere until they are read again, as today. Per-namespace meta is a
later refinement, not a requirement.

**The file manager.** It keeps an LRU of open namespace databases, each a `*sql.DB` of its own,
because queries name unqualified tables:

- *Connections:* 1 writer plus 2 readers to start, growing for hot namespaces, with a global
  cap on open connections (a semaphore). Idle connections close after 30 s.
- *Handles:* a WAL connection holds about three descriptors (db, `-wal`, `-shm`). The LRU's size
  defaults to what `RLIMIT_NOFILE` allows: (limit − 256) / (3 × connections). Go raises the
  soft limit to the hard one at start on Linux. A file with a transaction, waiter or queued
  write is never evicted.
- *Memory:* SQLite's default `cache_size` is 2 MB a connection, so 1,000 files × 3 connections
  could hold 6 GB. Namespace files set `cache_size` to a few hundred KiB and rely on the OS page
  cache, and the catalog keeps the default.
- *Prepared statements:* `stmtCache` becomes per database, capped at the hot statements (about
  64 of today's 512), and goes with the database when it is evicted.
- *Checkpoints:* every file sets `wal_autocheckpoint(0)`. A checkpointer runs `PASSIVE` off the
  writer's path when a WAL passes 1,000 frames, and `TRUNCATE` when a file is evicted, so cold
  files keep no WAL. That also takes the checkpoint out of `COMMIT`, which is half of it today
  (above). It is Phase 0 below, for the single file too.
- *Cost of an open:* measured here, opening a migrated file, checking its migrations
  (`dbmigrate.Migrate`) and running one query took **1.07 ms**. A freshly migrated empty file is
  **389,120 bytes**: one page per table and index of the 29 migrations, plus the pages that the
  dropped tables freed.

## Lifecycle

**Creating and deleting.** A new file is a copy of a template: an empty database at the
current schema, `VACUUM`ed, `auto_vacuum=INCREMENTAL` and `secure_delete` set. It is built at
start when its version changed. The copy then follows the steps above: temporary name, fsync,
rename, directory fsync. A namespace is never deleted (`purgeNSNow` marks it, and §5 keeps the
log and ids of a purged one), so a file goes only when a creation is undone, or by an operator
after a namespace purge if §5's retained parts are moved into a tombstone file. That is not
proposed now.

**Migrations.** There are two sets, `migrations/sqlite-catalog` and `migrations/sqlite-ns`,
applied by `dbmigrate.Migrate` per file. `current.sql` exists in each, and `make migration`
commits both.

- *Applied lazily on open*, the only way any code reaches a file, so no query ever meets an
  old schema. The catalog records each file's version.
- *A background task* then migrates the rest at a bounded rate, and `patchlog migrate --all`
  does it offline.
- Because versions coexist for a while, a migration that changes what other namespaces read
  of a file is split expand-then-contract across two releases.
- Data migrations, like the core's 008–010, run per file in order with the schema's.

**Backup and restore.**

- *Recommended:* a filesystem snapshot (EBS, LVM, ZFS) of the whole directory. That is a crash,
  and recovery on open handles it.
- *`patchlog backup DIR`* (new) holds an intent gate exclusive: multi-file writes in flight
  finish, new ones (creations, propagating purges) wait, and single-file writes and all reads
  go on. It runs `VACUUM INTO` for each namespace
  file, then the catalog last, then copies the blob directory, as the README's "database first
  and then the directory" says. With the catalog last, every reference a copied file holds has
  its superset row in the copy.
- *A restore rebuilds* every mirror and superset from the files before serving (`patchlog
  catalog rebuild`, also usable after a doubtful recovery).

**Background loops.** Retention (`ApplyRetention`), epoch rotation (`RotateDue`,
`rotations_due`), followed purges (`purgefollow.go`) and the views' sweep find their namespaces
by catalog flags and open only those files. The repurge loop (`Repurge`) and the blob sweep
(`SweepBlobFiles`) run per open file. So that a crash doesn't strand the second CDN purges of a
file nobody opens again, the catalog keeps an `active` set: the namespaces written since the
last clean shutdown, recorded in one batched catalog transaction a second. Recovery opens those
files and runs what is due. A namespace first written in the second before a crash, and not
recorded yet, sends its due second purges when it is next opened.

**Purge, prune, vacuum.** These stay per file, except propagation (above). A purged
namespace's file is `VACUUM`ed in the background. Smaller files make that possible at all: a
175 MB single file can't be vacuumed without stopping every writer. `secure_delete` stays on,
as in `openSQLite`.

**Encryption at rest** (`crypt.go`, §E.1). Resource keys live in their namespace's file, and
`purgeNSNow`'s `deleteDEKs` destroys them as now. The grants key becomes per file. A purge
destroys nothing more than today: grants are not purged (§5 keeps the log's references).

**Compression** (`compress.go`). The `store_compression` marker goes in each file, since that
is what an older binary would open. The decision stays per namespace.

**Blob storage** (`blobstore.go`, `blobs.go`). Bytes move to `blobs/{ns}/{owner}/{hh}/…`.
Owner-0 plaintext is shared within a namespace only. A copy across namespaces (a branch
attaching its base's blob, a batch source) is a hard link into the target's directory before
its row commits, or a copy where links aren't possible. Collection (`gcBytes`) and the sweep
(`SweepBlobFiles`) then need nothing outside one file and its directory. The cost: one directory
entry per namespace per shared blob, and no deduplication across trees.

**Converting a single-file database** (`patchlog convert --from file.db --to DIR`, offline).
For each namespace in id order (bases before branches):

1. Create its file and copy its rows with their ids, in block 0. Then seed `sqlite_sequence` to
   a fresh block.
2. Copy the authors, grants and keys it references. Owner-0 blob bytes are hard-linked per
   namespace and their rows renamed.
3. Fill `parent_ns` from the foreign parents' resources.
4. Build the catalog: its rows, the mirrors from each file, `schema_refs` from each file's
   distinct `schema_ref`, and `schema_copies`.
5. Verify every resource and namespace chain with `internal/verify` against the source.

Encrypted rows move as they are, since their AAD (`be64(res)`, the revision id) doesn't change.

**Both layouts stay.** Every query goes through the router. The single file is the
configuration in which every namespace routes to the one database, which is also the catalog.
There one transaction spans everything, intents are skipped, and `cut` and `writer` collapse
into `Engine.mu`. `:memory:` stays single-file (its one connection,
`openSQLite`). So the routing refactor ships first with no change of behaviour, the test suite
runs on both, and small deployments keep one file.

## Group commit for SQLite as the alternative

"Several waiting writes in one transaction under the mutex." The code exists for Postgres
(`groupcommit.go`). The prototype needed only `grouping()` and a SQLite form of `appendNSMany`
(one `INSERT` per entry, one `UPDATE namespaces`): `lockAll`, `lockLog` and `commitPool` are
no-ops or nil on SQLite. That temporary patch, not committed and not run against the group
commit tests, measured on the same host:

| writers in one namespace | today, writes/s | grouped, writes/s | writes/group | disk KiB/write (today → grouped) | CPU µs/write (today → grouped) |
| ---: | ---: | ---: | ---: | --- | --- |
| 1 | 2,291–2,669 | 2,602–2,801 | — | 73 → 73 | 406 → 381 |
| 8 | 1,832–2,386 | 2,964–3,480 | 4.0 | 75 → 44 | 524 → 462 |
| 16 | 1,955–2,251 | 3,633–4,120 | 7.9–8.1 | — | — |
| 32 | 1,998–2,325 | 4,232–5,380 | 15.7–16.0 | 75 → 25 | 539 → 352 |

With 2 and 4 writers nothing groups (`soloWrites` is 4), and with one writer per namespace
across many namespaces nothing groups either: groups are per namespace. Measured: 1–16
namespaces with one writer each, grouped or not, all 2,000–2,900 a second.

**Separate files, measured as a ceiling.** One engine and file per namespace, one writer each,
in one process. That is the storage side of this design without its locks or catalog:

| namespaces | one file, writes/s | a file each, writes/s | a file each, p99 ms | disk KiB/write (one file → a file each) |
| ---: | ---: | ---: | ---: | --- |
| 1 | 2,302–2,928 | 2,423–2,847 | 6.7–7.5 | 72 → 72 |
| 2 | 1,988–2,217 | 2,297–3,498 | 10.7–13.8 | 74 → 69 |
| 4 | 2,101–2,306 | 3,399–4,096 | 17.9–22.9 | 75 → 68 |
| 8 | 2,166–2,521 | 4,443–4,914 | 26.8–39.1 | 75 → 66 |
| 16 | 2,320–2,464 | 4,187–5,235 | 58–86 | 76 → 64 |

On 4 vCPUs it about doubles and stops, at 430–490 µs of process CPU a write. That is about
half of what the CPU allows, and the p99 grows with the number of files. The cause is not
known; checkpoints running inside `COMMIT` in every file at once are the first suspect, and
Phase 3 profiles it.

**Estimates for the EC2 bench.** These are extrapolations, not measurements. About 1 ms of
serialised work a write, and the local split puts half of it per transaction.

- *Group commit (per namespace, Phase 1):* the bench's namespaces each have 100 closed-loop
  writers, so groups fill (16–32). The serialised time per write falls to about 0.45–0.5 ms, so
  **about 2,000–2,200 written/s in all** however many namespaces, against 1,011, at a cost of
  roughly a hundred lines plus making the Postgres group tests run on SQLite. It does not fix
  isolation. A quiet namespace's write still queues on `Engine.mu` behind up to 31 group
  commits of about 15 ms each, so on the order of 0.5 s instead of 4.5 s.
- *A file per namespace with group commit:* the store's CPU, about 1–1.6 ms a write across 8
  vCPUs, bounds it at 5,000–8,000 a second. The local ceiling reached about 55% of its CPU
  bound, and group commit cut CPU per write by a third. **About 3,000–7,000 written/s in all**
  at 8–32 namespaces is the range to expect, with a quiet namespace's latency independent of the
  others' queue (CPU and disk contention aside).
- *Disk:* at 70 KiB a write, 500 MB/s of gp3 throughput (`SQLITE_THROUGHPUT`'s default) caps
  ungrouped writes near 7,000 a second. Grouped (25 KiB) it is past 20,000. Checkpoint backfill
  is random 4 KiB writes against 6,000 IOPS, which this host couldn't show.
- *The cost of the layout:* the refactor (every query site routed, about 340 in core), the
  catalog, three intent protocols with recovery, the file manager, conversion, and a third
  configuration in the test matrix. Months, not weeks.

Postgres remains the answer past one machine. Per-file SQLite targets one store with
independent namespaces, not the 28,070 a second of two stores on a `db.m7g.4xlarge`.

**Order.**

- **Phase 0** (checkpoints off the writer) and **Phase 1** (group commit) first: little code,
  about twice the throughput, both kept by the layout.
- **The layout next**, if the Phase-1 bench still shows namespaces starving each other, or if
  totals beyond about 2,000 a second are needed on SQLite.
- Cross-namespace grouping under the single mutex (one transaction for writes of many
  namespaces) was considered for one writer per namespace. It would be discarded by the
  layout, and the bench's shape doesn't need it. Not proposed.

## Rollout

| phase | work | measurable result |
| --- | --- | --- |
| 0 | `wal_autocheckpoint(0)` on the pool and a checkpointer (`PASSIVE` past 1,000 frames, `TRUNCATE` when idle) | Locally, the commit phase of one write from 185–239 to about 130 µs. On EC2, the store's CPU and block profiles (`PROFILE=1`) show what the 1 ms is. Two namespaces above 1,010 written/s. |
| 1 | Group commit on SQLite: `grouping()`, `appendNSMany`'s SQLite form, the `TestPGGroupCommit*` tests on both dialects | `BenchmarkAppendsOneNamespace` writers=32 at least twice today's. EC2 32 namespaces at least 1,800 written/s with p50 halved. |
| 2 | Routing in single-file mode: `tx.in(ns)`, rows carrying their namespace, `config(ns, seq)`, `revisions.parent_ns`, `updateIn`, the in-process lock manager behind `locking()`, the Postgres rule for kept rows | No behaviour change. The suite passes, statement-count tests (`*_stmts_test.go`) unchanged, benches within 5%. |
| 3 | The layout: catalog, file manager, blocks, intents and recovery, mirrors, supersets, per-namespace blob directories, two migration sets, template, `LOCK` | The suite passes on it. The local one-writer-per-namespace bench reaches the separate-engines ceiling above within 15%. EC2 32 namespaces at least 3,000 written/s, and the quiet namespace at least 95 of its 100/s. |
| 4 | `convert`, `backup`, `catalog rebuild`, README layout and CAPACITY sections | The bench's 175 MB database converted and verified. A backup restored and served. |

**Tests to add.**

- *Crash and recovery.* Each multi-file operation gets a hook between every step: after the
  catalog row, after the file, after the base entry, after *k* of *N* candidates, and between a
  mirror's pending and its apply. A subprocess runs it (the `os.Args[0] -test.run=Helper`
  pattern), is killed with SIGKILL at the hook, and is reopened. Then check:
  - all-or-nothing as seen by reads: a branch exists iff its base has its entry, and a purge is
    in every candidate or none;
  - every chain verifies (`internal/verify`);
  - no intent or pending row remains;
  - an idempotent retry is answered as §7.2 says.
- *Power loss.* Run the same under a filesystem that drops unsynced writes (LazyFS), or at least
  a test that counts fsyncs and checks one at every ordering point.
- *Concurrency across namespaces.* `TestPGParallelNamespaces`, `TestPGLockOrder` and the
  `TestPGGroupCommit*` set run on per-file SQLite. New tests:
  - a branch write against its base's revocation, key removal, purge and freeze, each landing
    between check and lock with the `BeforeWriteLock` hook;
  - a schema write against the schema's purge across files;
  - branch creation against a base config write;
  - a reader of a deep branch during purge propagation that must never see the base purged
    and the branch not;
  - LRU eviction under readers, long-polls and queued writes;
  - a descriptor limit with a tiny LRU;
  - lazily migrated files of mixed versions.
- *Oracles.* `PATCHLOG_TEST_VALIDATE_BOTH` (`brokenByEveryDocument`, `drafts.go`) on the
  per-file layout checks the catalog supersets against every document.

**Existing coverage.**

- `internal/server/concurrency_test.go` runs on SQLite and Postgres (`bothDBs`) and gains the
  layout: `TestRaceConfigChange`, `TestRaceRevocationAndKeys`, `TestRaceSchemaPurge`,
  `TestRaceFallbackUnderLock` and `TestConcurrentWritersStress` are invariant 6 across files.
- In core:
  - `readone_test.go` (`TestRecheckAfterHeadMove`, `TestRecheckSeesMovedHead`) for the
    re-check;
  - `purge_search_test.go` (`TestPurgeSearch`) for which branches a purge reaches;
  - `livebranches_test.go` for the `frozen` column the mirror replaces;
  - `groupcommit_test.go`, `multi_test.go`, `loglock_test.go` and `purgerace_test.go`, today
    Postgres-only, for the lock rules;
  - `sqlitepath_test.go` for paths.
- `internal/server/blob_test.go` (`TestBlobPurgeRacesUpload`, `TestBlobRecheck`) for blob
  copies.
- `internal/server/purge_refscan_test.go` for `in_use` scans.
- `internal/dbmigrate`'s `TestMigrations` for the two migration sets.
- `PATCHLOG_TEST_LOG_PAGE_SIZE=2` for paged reads across a chain.
- A test-environment knob (`internal/testenv`, like `PATCHLOG_TEST_LOG_PAGE_SIZE`) selects the
  layout for the whole suite.

**Benches.**

- *Locally:*
  - `go test ./internal/core -run '^$' -bench 'AppendsOneNamespace|CheckAppend' -benchtime
    3000x`;
  - a new `BenchmarkNamespacesParallel`: 1–32 namespaces with one writer each and with 32
    each, on a file, reporting writes/s, p50/p99, `cpu-ns/op` (`processCPU`) and disk bytes per
    write from `/proc/self/io`, as the measurements above did.
- *On EC2, from doors `apps/ouroboros`:*

  ```sh
  PATCHLOG_DIR=/path/to/patchlog DB_ENGINE=sqlite STORE_TYPE=c7g.2xlarge \
    MODE=namespaces NAMESPACES=1,2,8,32 FETCHES=1 PROFILE=1 ./bench/aws/ec2-sources.sh -y
  ```

  Keep the defaults `SQLITE_IOPS=6000` and `SQLITE_THROUGHPUT=500`. Add `STORE_ARGS` for the
  phase's flags. Read the store volume's `VolumeWriteBytes` and `VolumeWriteOps` from
  CloudWatch for the same window. The script's metrics helper is RDS's. Record the quiet
  namespace row (`sourcesNamespaces.ts`, `--quiet-rate`).

## Open questions and risks

- **Size per namespace.** 389 KB for an empty file, so 3.9 GB for 10,000 namespaces before any
  content. A `VACUUM`ed template, fewer indexes in namespace files and lazily created
  encryption tables are the levers. Measure the template.
- **Memory and descriptors with thousands of open files.** Page caches, statements and
  connections per file. Measure RSS at 1,000 open files.
- **Purge propagation over thousands of branches.** Today `purgeHolders` finds the branches
  holding a name through `resources_name`, `sealed_by_name` and `blob_epochs_name` across the
  deployment (`nspurge.go`). A shared index of names would cost a catalog write per created
  resource, so the per-file layout walks the catalog's branches (`purgeLevels`) and probes each
  file. That means one open and a key lookup per branch, and readers of those branches wait at
  `cut` while the steps commit. It is rare, but seconds where Postgres takes milliseconds.
- **Bursts of catalog writes.** A new schema revision rolled out to thousands of namespaces
  makes each one's next write insert a superset row, with one fsync each. The catalog writer
  must group them, or the catalog becomes the shared writer again.
- **Ordering under power loss.** Every ordering point relies on a FULL commit, a file fsync and
  a directory fsync. SQLite's own fsync of a new `-wal`'s directory entry is assumed, not
  verified: fsync the directory after a file's first write.
- **Reads that open files late** (schemas, drafts in branches, sources) see each file at its own
  moment. This was argued safe above for schema namespaces. The `PATCHLOG_TEST_VALIDATE_BOTH`
  oracle and the new purge-reader test must confirm it for drafts.
- **Two layouts to maintain**, plus Postgres: a third configuration for every test and bench.
- **The separate-files ceiling stopped at half the CPU locally**, for a reason not yet known.
  If it is contention in the driver rather than checkpoints, the EC2 estimate is high.
- **One process per directory** narrows §5's "multiple processes" for SQLite, documented as
  Postgres's job.
- **The block size** (2³² ids) and `AUTOINCREMENT`'s extra `sqlite_sequence` write per insert,
  one hot page, were not measured.
- **Whether `mmmigrate` refuses a database newer than it knows** was not checked. The directory
  form of `--db` sidesteps it.

## What was verified, measured and assumed

- **Verified in the code** at `772ac38b`, files and functions as cited:
  - SQLite's single writer (`update1`, the DSN) and Postgres-only group commit (`grouping`,
    `appendNSMany`);
  - the D.3 path (`writeOptimistic`, `checkOutside`, `recheckIn`, `writeLocked`) and the lock
    rules (`pglock.go`);
  - the table list and which tables are read across namespaces, and the integer keys shared
    across namespaces (`resolve.go`, `nsbranch.go`, `chain.go`);
  - the operations that write several namespaces (`createBranch`, `createNamespace`,
    `purgeApply`) and those that only read others;
  - the index-driven `in_use` path (`possiblyReferenced`, `copyRows`, `usesWalkOf`), whose
    full scan (`schemaUses`) is the test oracle;
  - `snapshotRows`' single-writer assumption, the blob layout and ownership, the grants key, and
    that the hub's waiters hold no transaction.
- **Measured here**, on one 4-vCPU host, never on EC2: the phase split, the batch split, the
  checkpoint share, the group-commit prototype, the separate-files ceiling, disk bytes and CPU
  per write, and the open cost and empty-file size. The prototypes were temporary patches and
  test files, removed again: nothing in this commit changes code.
- **Assumed or estimated:**
  - the EC2 split of the 1 ms and its estimates;
  - SQLite's behaviour under power loss at the ordering points;
  - Go's `RWMutex` fairness as documented;
  - the size of the refactor (counted as query call sites, not reviewed one by one);
  - the cost of purge propagation by walking files;
  - memory per open file.
