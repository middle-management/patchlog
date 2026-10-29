# Capacity

What one deployment of this implementation handles, measured. For each limit it found, this
document says whether the limit is **by design** (the spec's model; changing it means changing
how data is laid out), a **gap** (this implementation; fixable without changing the spec) or
**deployment** (hardware and configuration; buy or tune your way past it).

The numbers come from `cmd/capacity` (see [Rerunning](#rerunning)) at spec 0.52, measured on
2026-10-15. They are taken over HTTP, from a load generator on the same host, so they include
the HTTP stack and are conservative. The raw results are in [`capacity/`](capacity/).

## The envelope

**Server X:** the core at **2 vCPU / 4 GB**, Postgres 16 at **2 vCPU / 4 GB**, each in its own
container on one 4-vCPU host, which also ran the load generator. Grants on: private
(`read: grant`) namespaces, and every request carries a signed grant.

**Data:** 1,000 small namespaces (10 documents each) and one large namespace of
**1,000,000 documents** and **5,000,000 revisions**: 1M creates (in 1,000-item batches) and
4M single appends of a small patch, about 500-byte documents. 6.2 GB in Postgres; the same data
is 3.1 GB in SQLite.

At that size, server X answers, at the origin (before any CDN):

| | |
|---|---|
| Reads of a document or head pointer | 1,000–1,600/s at 8 concurrent, p50 4.6–6.6 ms, p99 ≤ 27 ms |
| Cold reads of old revisions (folds) | 470/s, p50 15 ms |
| Single writes to one namespace | 125/s from one writer (p50 7.5 ms), 310/s from 8, **590/s from 32** (p50 52 ms, p99 91 ms) |
| Single writes spread over 1,000 namespaces | 420/s from 32 writers (p50 66 ms, p99 210 ms) |
| A batch of 1,000 appends | 1.4 s |
| Appends to a large document | p50 7 ms at 16 KiB, 15 ms at 1 MiB, 25 ms at 3.5 MiB |
| A consumer's full catch-up of the large namespace | log: 4M entries in 2.4 min; `/heads`: 1M in 37 s; fetching 1M documents 8 at a time: ~10 min |
| Long-poll followers of one **private** namespace | 5,000 followers: 0.3–1 s of core CPU and 0.35–0.7 s to deliver each write, the waiters sharing one read at the origin (no CDN collapse, see below; 3.7–4.1 s of CPU before) |
| Long-poll followers of one **public** namespace, behind the CDN | 5,000 followers: 0.01 s of core CPU, all delivered in 0.25 s (0.4 s on SQLite) |

What the data size costs and what it doesn't: none of the per-request numbers above depends on
the namespace's size (pages and reads use indexes; see the fixes under Unreleased in the CHANGELOG), so a
namespace of 1M documents and 5M revisions answers like a small one. What grows with size is
storage (about 1.2 KB a revision on Postgres, 620 B on SQLite, for these small documents), full
scans (catch-up, bootstrap, bundle export), and memory (below).

### What limits server X

The same data measured again (grants unless noted; reads from 8 concurrent clients, writes to
the large namespace from 32):

| Core | Reads, uncached grants | Reads, cached grants | Writes, one namespace | Writes, 1,000 namespaces | Bootstrap fetches |
|---|---|---|---|---|---|
| 2 vCPU, authentication off | 1,840/s, p50 3.9 ms | — | 750/s, p50 41 ms | 460/s | 1,920/s |
| 2 vCPU | 1,030/s, p50 6.6 ms | 1,630/s, p50 4.6 ms | 590/s, p50 52 ms | 420/s | 1,620/s |
| 1 vCPU | 1,130/s, p50 5.3 ms | 2,070/s, p50 3.3 ms | 790/s, p50 40 ms | 400/s | 1,220/s |
| 2 × 1 vCPU, writes routed by namespace | 1,110/s, p50 6.4 ms | 1,510/s, p50 4.8 ms | 700/s, p50 45 ms | 380/s | 1,440/s |

- **The core isn't server X's bottleneck; Postgres is.** Halving the core changes little, and a
  second instance adds nothing: the 2-vCPU Postgres (at ~1.3 vCPU and 3.4 GB under these loads)
  and its round trips set the pace. On server X, give Postgres the CPU first; core instances pay
  off once the core's own CPU is the limit (grant checks at fleet scale, large documents,
  uncollapsed followers that are CPU-bound rather than database-bound).
- **Grants cost ~40% of read throughput when the grant isn't cached** (1,030/s against 1,840/s
  without authentication), mostly verification: with grants in the core's bearer cache reads
  are within ~10% of unauthenticated ones.
- Write throughput into one namespace doesn't depend on the core's size here: the namespace's
  log (one append at a time, grouped) and Postgres set it.

## Three backends on AWS

`deploy/ec2-bench.sh` runs `deploy/bench.sh` against each backend from one EC2 instance in the
backend's region, measured on 2026-10-28 and 29 in eu-north-1:

- **The machine:** the core and the load generator (oha) on one **c7g.2xlarge** (8 vCPU arm64,
  16 GB): SQLite on its own gp3 disk, Postgres on RDS **db.m7g.large** (2 vCPU, 8 GB, gp3,
  single-AZ), DynamoDB an on-demand table pre-warmed to 15,000 write and 20,000 read units a
  second.
- **The load:** for 30 s, open-loop at fixed rates (oha's latency correction: a slow server shows
  as latency, not as a lower rate), over **8 namespaces**: creates of small documents (`-dev`, no
  grants), each of 16–64 authors its own content; reads of resources' heads at the write rate;
  followers reading each namespace's log since a recent entry at half the write rate. One run
  each, 10% of requests traced.

Writes answered a second, and latency at the client (ms, p50 / p95 / p99):

| Asked | | SQLite | Postgres (RDS) | DynamoDB |
|---|---|---|---|---|
| 600/s | writes | 600/s · 1 / 12 / 16 | 600/s · 43 / 208 / 578 | 594/s · 45 / 574 / 677 |
| | head reads | 0 / 1 / 1 | 9 / 56 / 324 | 6 / 9 / 24 |
| | log reads | 1 / 3 / 4 | 31 / 70 / 80 | 13 / 21 / 24 |
| 1,200/s | writes | **942/s** · 937 / 6,277 / 6,860 | **795/s** · 7,947 / 10,153 / 10,571 | **1,154/s** · 42 / 1,053 / 1,404 |
| | head reads | 0 / 1 / 2 | 380 / 1,830 / 2,214 | 6 / 9 / 16 |
| | log reads | 1 / 3 / 5 | 193 / 454 / 617 (562/s) | 13 / 19 / 22 |
| 2,400/s | writes | **885/s** · 7,073 / 18,793 / 19,842 | **819/s** · 11,067 / 19,671 / 20,458 | — |
| | head reads | 0 / 1 / 4 | 6,270 / 9,358 / 9,878 (1,664/s) | — |
| | log reads | 1 / 4 / 6 | 250 / 572 / 799 (1,017/s) | — |

Where a backend answers fewer writes than asked, the rest queue: their latency is the queue's.

- **SQLite: ~900 writes a second, reads untouched.** One writer at a time, whatever the
  namespaces; past it writes queue, and reads, beside the write-ahead log, stay under 4 ms at
  p99 with 2,400 reads and 1,200 log reads a second. Lowest latency below its ceiling, one
  machine.
- **Postgres on a 2-vCPU RDS instance: ~800 writes a second, and reads fall with it.** At its
  write ceiling head reads go from 9 ms to 380 ms (p50), then seconds: the database instance is
  the limit for both, as on server X; a larger instance class raises it.
- **DynamoDB: as far as the table's capacity.** 1,154 writes a second with head reads at 6 ms,
  writes ~40 ms (a transaction, ~22 ms, and the wait for a group commit). Its limits are
  different in kind:
  - **~11 write units a write** (five items in one transaction, at two units each, and a GSI
    entry), so the table's capacity: 1,200 writes a second is ~13,000 units, and this run's
    bursts reached 21,000 against the 15,000 pre-warmed, throttled (a 503 with `Retry-After`
    when it outlasts the retries) and retried. A new on-demand table starts at 4,000 write units
    a second and grows with use; pre-warming (`update-table --warm-throughput`) is a one-time
    charge.
  - **~150 writes a second a namespace.** A namespace's log entries and resource items share its
    partition key, which DynamoDB holds to ~1,000 write units a second (docs/DYNAMODB.md §3):
    one namespace measured 147/s at 300 asked. Throughput grows with namespaces, not within one.
  - Physical partitions split under sustained load, so a young table's first runs throttle more
    than later ones.

On the same machine, then: SQLite for one machine below ~900 writes a second; Postgres for
heavy writes into few namespaces, sized by its instance; DynamoDB for many namespaces and
instances with no database server to run, sized by the table's capacity and paid by the request.

## Long-poll followers and the CDN

Many followers (devices, not consumer services) are meant to long-poll (§7.7) through the CDN:
every follower of a namespace asks for the same URL (`since` the head, the same interval
`cursor`), the CDN collapses identical misses into one origin request, and the answer is cached
for the interval. The origin's cost is then one request per namespace, interval and CDN node,
whatever the number of followers. Measured with the repository's Varnish configuration
(`deploy/varnish/default.vcl`): 1,100 followers made 4 origin requests.

That holds for **public** namespaces only. A private namespace's long-poll answers are
`CDN-Cache-Control: no-store` unless the CDN verifies edge grants (§C.5, `-edge-secret`), and
no edge that does is included (only the checks, in Go: `edge.Cookies.Check`). Without one,
every follower is an origin request, and every write wakes all of them.

**Origin-side collapse.** The origin shares those reads (`internal/core/live.go`): a waiter's
first read is checked as any read is, and while that decision holds (no configuration change,
purge or other change to what reads may return since, the grant not expired, no rule reading
`/now`) its later reads skip the check and are shared with every waiter woken by the same commit:
one log read per namespace, `since` and commit, whatever the number of waiters. Before it, each
woken waiter read the log in a transaction of its own.

| Followers of one namespace | public, via CDN | private, direct, before | private, direct, origin collapse | private, via Varnish, origin collapse |
|---|---|---|---|---|
| 100 | 7 ms, ~0 CPU-s | 0.3–0.4 s, 0.06–0.07 CPU-s | 0.03–0.5 s, 0.02–0.03 CPU-s | 0.24–0.41 s, 0.02–0.03 CPU-s |
| 1,000 | 46 ms, ~0 CPU-s | 0.63–0.71 s, 0.7–0.8 CPU-s | **0.08 s, 0.10–0.12 CPU-s** | 0.53–0.60 s, 0.08–0.11 CPU-s |
| 5,000 | 0.25–0.39 s, 0.01 CPU-s | 3.1 s, 3.7–4.1 CPU-s | **0.35–0.69 s, 0.33–0.98 CPU-s** | 2.8–3.0 s, 1.25–2.2 CPU-s |

Private columns: server X (Postgres, the core at 2 vCPU), grants, two runs each, the core idle
before the write; the time is until every follower had the write, CPU-s the core's CPU time for
it. The public column is SQLite and server X. With the collapse, a write costs about **0.1–0.2 ms
of core CPU per private follower** (1 ms before: a transaction and a log query each), so server
X delivers roughly 5,000–15,000 follower-writes a second, against ~1,000 before. Through
Varnish, the rest is Varnish passing 5,000 private connections on the same host. The
repository's VCL no longer queues a long-poll with credentials behind an identical one in flight
(`hash_ignore_busy`): it held them until the next write and then sent them to the origin a few
at a time, as new requests that share nothing.

Planning rule for private followers without a verifying edge: `followers × writes/s` up to
~5,000/s on server X; and every follower is a connection the origin holds open (the CDN in front
holds them when it verifies edge grants).

## Limits, by kind

### By design

| Limit | Measured | Lever |
|---|---|---|
| **One log per namespace.** Every write appends to its namespace's hash chain (§3.5), so writes to one namespace commit one at a time (on Postgres, one group of up to 32 at a time). | One namespace: ~590 single writes/s on server X from 32 writers; 700–1,000/s on SQLite (4 vCPU). | Spread write-heavy data over namespaces: writes to different namespaces run in parallel, across instances too. A sign-in storm writing per-user items belongs in many namespaces, not one. |
| **§6.6 size limits**: documents 1 MiB by default (4 MiB a namespace may set, the deployment maximum; §6.6 says 4 MiB), patch sets 256 KiB, 1,000 ops a set, 1,000 items and 16 MiB a batch, 1,000 entries a log page. The other deployment maximums equal the defaults. | | Large documents are slow to write (next row); batches are imports, not interactive writes. `serve -max-document-size` raises the document maximum. |
| **Whole-document work on every write**: the result is canonicalised, checked against the limits and validated against its `$schema` in full; a small patch to a large document costs the document's size. | Append p50: 7 ms at 16 KiB, 15 ms at 1 MiB, 25 ms at 3.5 MiB (server X); 1.7 / 7 / 19 ms on SQLite. | Keep frequently edited documents small: split large aggregates into resources. |
| **Default rates** (§6.6): 50 items/s a principal (burst 100), 500 items/s a namespace (burst 1,000), 10/s a resource (burst 20); since v0.73 the instances of a Postgres deployment share the buckets (`rate_buckets`, about +1.2 ms a write), per instance only with `serve -local-rate-buckets`. | 500/s a namespace is ~85% of server X's single-namespace ceiling. | Allowances (§6.6) replace a principal's and its namespace's buckets, for loaders and importers. The per-resource rate always applies. |
| **Followers are cheapest through the CDN** (§7.7, §9): there they cost the origin nothing per follower; at the origin, a connection each and a shared read per write. SSE streams (§7.3) are collapsed neither at the CDN nor at the origin. | See the table above. | Devices long-poll; services that need every entry use the log and checkpoints (§10). |
| **Consumers read over HTTP**: a consumer catches up from the log and fetches each changed document (§10). | Catch-up of 4M entries: 2.4 min; bootstrap of 1M documents: ~11 min on server X. | Consumer throughput is the consumer's (gaps below); the origin side scales with instances. |

### Gaps in this implementation

| Gap | Effect | Fix |
|---|---|---|
| **No edge that verifies edge grants** is included. | Private long-polls don't collapse at the CDN: every follower is an origin connection and request; the origin shares their reads (above), ~0.1–0.2 ms of core CPU per follower per write. | An edge (Varnish VMOD, Fastly or Cloudflare worker) with `edge.Cookies.Check`'s checks; the origin already issues the cookies. |
| **No read replicas, and one `-db` for everything** (the core runs migrations, the tailer and leader jobs, so it can't run on a read-only database). | Consumers' scans and private reads load the primary. | Route bulk reads (catch-up, bootstrap, export) and private reads to a replica, with misses of new revisions falling back to the primary; decisions stay on the primary. |
| **Consumers** (index, tree): one SQLite writer per process, 8 document fetches at a time (the tree service: one), no sharding but by namespace lists. | Bootstrap of 1M documents: ~11 min on server X (fetches at 1,600/s); 2.6 min on SQLite. | More fetch concurrency, pipelining pages; split namespaces over processes. |
| **A namespace purge is one transaction.** | Long lock and transaction for large namespaces. | Purge in chunks. |
| **No profiling endpoint; the core sets no memory limit.** | Peak RSS 1.5–1.8 GB on the instance that served the full scans of the large namespace (steady 0.5–0.8 GB); the second instance, which didn't, peaked at 0.2 GB. | Run with `GOMEMLIMIT` under container limits; profile the scans (an opt-in pprof listener would help). |

Fixed in this branch, and so not limits any more: namespace log pages bounded entries but not
items, so a page of 1,000 batch entries of 1,000 items held a million (now at most the page size
in resource entries too, a batch counting as its items); the bearer grant cache held 1,024 grants and
emptied itself when full, so a fleet of 5,000 devices with grants of their own verified on
nearly every request (now 65,536, least recently used out first: the warm fleet's reads went
from 1,490/s, p50 4.9 ms, to 1,710–1,770/s, p50 3.2–4.4 ms on server X, where Postgres rather
than verification is the bottleneck); the document cache was bounded by count (4,096 documents,
up to 16 GiB of 4 MiB ones; now 256 MiB) and the read cache emptied itself when full (now evicts
a quarter); rate-limit buckets, one per (namespace, resource, principal) written, were never
dropped (now swept once full again, which is the same as new), and compiled schemas and their
documents were kept forever (now the 512 and 2,048 most recently used); long-polls of a namespace each read the log
on their own when woken (now shared, above); namespace log pages scanned and sorted the
whole namespace, and the config-retry lookup the whole log (now indexed; CHANGELOG, Unreleased);
a consumer's snapshot bootstrap held the whole `/heads` listing in memory and one transaction
(now paged and resumable).

### Deployment

| Resource | Measured | Notes |
|---|---|---|
| **Core CPU** | Grant checks, canonicalisation, validation, folds and page serialisation are core CPU. On server X a 1-vCPU core kept up with everything measured. | Scales with instances once it is the limit (it wasn't on server X). |
| **Postgres round trips** | A single write is ~13 statements; on server X one writer did 125 writes/s (7.5 ms each), neither container saturated. | Keep the core near Postgres (sub-millisecond); concurrency, not speed, is what instances add. |
| **Postgres CPU and memory** | ~1.3 of 2 vCPU and 3.4 of 4 GB under the read measurements; the limit on server X. | Size Postgres first; a read replica takes bulk reads and private followers' log reads (the gap above). |
| **Storage** | 6.2 GB on Postgres, 3.1 GB on SQLite for 5M revisions of ~500-byte documents. | Linear in revisions; pruning (§8.6) bounds it. |
| **Memory** | Core: 0.5–0.8 GB steady, 1.5–1.8 GB peak during full scans. The caches are bounded: up to 256 MiB of documents, 64 MiB of read-cache revisions and 65,536 grants (a few hundred MB at most) by default. | Give containers `GOMEMLIMIT`, 2 GB+ for an instance that serves catch-ups; size the caches with `serve -doc-cache-size`, `-read-cache-size` and `-grant-cache`. |
| **Upgrades** | Schema migrations run in a transaction at start (README "Schema migrations"); one that builds an index on a large table blocks writes to it while the index builds. | Create the index `CONCURRENTLY` beforehand under the same name: migrations are written with `IF NOT EXISTS`, so they then find it. |

## Recommended changes to limits

- **Bearer cache: done.** 65,536 grants, at most 32 MiB of tokens, least recently used out first
  (`serve -grant-cache`).
- **Document and read caches: done.** 256 MiB and 64 MiB, evicting gradually
  (`serve -doc-cache-size`, `-read-cache-size`).
- **Log pages**: bound items or bytes as well as entries.
- **`documentSize`: done.** 1 MiB by default, 4 MiB a namespace may set (`serve -document-size`,
  `-max-document-size`). Appends at 3.5 MiB are 3–4× slower than at 16 KiB, and every revision of
  a large document weighs on the caches.
- **Keep**: the rates (500/s a namespace is just under one namespace's ceiling on server X),
  `itemsPerBatch` 1,000 (imports; give importers allowances), the snapshot cadence, the
  long-poll interval and the log page size.

## Rerunning

```sh
go build -o patchlog ./cmd/patchlog && go build -o capacity ./cmd/capacity
./patchlog serve -dev -addr :9080 -db cap.db -origin http://localhost:8080 -max-rate-per-namespace 1e9,1e9 &
./capacity -url http://127.0.0.1:9080 -pid $! -json result.json   # 1M docs, 5M revisions: about 1-1.5 h to seed
```

- **Allowance**: the harness's namespaces give its loader an allowance of 1e9 writes a second
  and burst, and an allowance's bucket never exceeds the deployment maximum of
  `ratePerNamespace` (§6.6), so the core needs `-max-rate-per-namespace` raised to it; without
  it, creating them is `422` (`limit: "ratePerNamespace"`).

- **Grants**: run the core with `-operator-key <public>` (from `patchlog keygen`) and pass the
  private seed as `-operator-seed`; the namespaces are then private and every request carries a
  grant, readers 5,000 distinct ones (`-readers`).
- **A CDN**: put Varnish with `deploy/varnish/default.vcl` (backends pointed at the core) in front
  and pass its URL as `-live-url` for the long-poll measurement.
- **Several instances**: `-url` takes a comma-separated list; a namespace's writes go to one by a
  hash of its name, reads and followers to each in turn.
- **Once seeded**, `-only scans,reads,writes,bootstrap,large,live` measures again without seeding,
  e.g. after resizing the core.
- Sizes: `-docs`, `-revs`, `-namespaces`, `-doc-size`, `-append-batch`; `-help` lists the rest.

The comparison of [Three backends on AWS](#three-backends-on-aws), from a checkout with the AWS
CLI, Go and AWS's session-manager-plugin (the script says what it makes, and asks):

```sh
BACKEND=postgres NAMESPACES=8 TYPE=c7g.2xlarge ./deploy/ec2-bench.sh 1200 30   # RDS, made on first use
BACKEND=sqlite   NAMESPACES=8 TYPE=c7g.2xlarge ./deploy/ec2-bench.sh 1200 30
TABLE=patchlog   NAMESPACES=8 TYPE=c7g.2xlarge ./deploy/ec2-bench.sh 1200 30   # DynamoDB
./deploy/ec2-bench.sh cleanup   # the RDS instance (billed by the hour), the IAM role
```
