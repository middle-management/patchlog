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
| Long-poll followers of one **private** namespace | 5,000 followers: ~5 s of core CPU and ~5 s to deliver each write (no CDN collapse, see below) |
| Long-poll followers of one **public** namespace, behind the CDN | 5,000 followers: 0.01 s of core CPU, all delivered in 0.4 s (measured on SQLite; collapse doesn't depend on the backend) |

What the data size costs and what it doesn't: none of the per-request numbers above depends on
the namespace's size (pages and reads use indexes; see the fixes under Unreleased in the CHANGELOG), so a
namespace of 1M documents and 5M revisions answers like a small one. What grows with size is
storage (about 1.2 KB a revision on Postgres, 620 B on SQLite, for these small documents), full
scans (catch-up, bootstrap, bundle export), and memory (below).

<!-- comparison -->

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
every follower is an origin request, and every write wakes all of them, each of which reads the
log again:

| Followers of one namespace | public, via CDN | public, direct (SQLite, 4 vCPU) | private, via CDN or direct (Postgres, server X) |
|---|---|---|---|
| 100 | 7 ms to deliver, ~0 CPU | 35 ms, 0.07 CPU-s | 0.1–0.2 s, 0.1 CPU-s |
| 1,000 | 46 ms, ~0 CPU | 0.18 s, 0.5 CPU-s | 0.7–0.8 s, 0.8 CPU-s |
| 5,000 | 0.39 s, 0.01 CPU-s | 0.69 s, 2.0 CPU-s | 4.4–5.2 s, 5–6.5 CPU-s |

CPU-s is the core's CPU time per write delivered. Uncollapsed, a write costs about **1 ms of
core CPU per private follower** on server X (0.4 ms per public follower on SQLite), plus a log
query per follower in Postgres. So 5,000 private followers of a namespace saturate server X's
core at about **0.4 writes/s** to that namespace. Planning rule without a verifying edge:
`followers × writes/s × 1 ms ≤ the core's CPU`.

## Limits, by kind

### By design

| Limit | Measured | Lever |
|---|---|---|
| **One log per namespace.** Every write appends to its namespace's hash chain (§3.5), so writes to one namespace commit one at a time (on Postgres, one group of up to 32 at a time). | One namespace: ~590 single writes/s on server X from 32 writers; 700–1,000/s on SQLite (4 vCPU). | Spread write-heavy data over namespaces: writes to different namespaces run in parallel, across instances too. A sign-in storm writing per-user items belongs in many namespaces, not one. |
| **§6.6 size limits**: documents 4 MiB, patch sets 256 KiB, 1,000 ops a set, 1,000 items and 16 MiB a batch, 1,000 entries a log page. The deployment maximums equal the defaults; namespaces can only lower them. | | Documents near the limit are slow to write (next row); batches are imports, not interactive writes. |
| **Whole-document work on every write**: the result is canonicalised, checked against the limits and validated against its `$schema` in full; a small patch to a large document costs the document's size. | Append p50: 7 ms at 16 KiB, 15 ms at 1 MiB, 25 ms at 3.5 MiB (server X); 1.7 / 7 / 19 ms on SQLite. | Keep frequently edited documents small: split large aggregates into resources. |
| **Default rates** (§6.6), per instance: 50 items/s a principal (burst 100), 500 items/s a namespace (burst 1,000), 10/s a resource (burst 20). | 500/s a namespace is ~85% of server X's single-namespace ceiling. | Allowances (§6.6) replace a principal's and its namespace's buckets, for loaders and importers. The per-resource rate always applies. |
| **Followers are cheap only through the CDN** (§7.7, §9). SSE streams (§7.3) can't be collapsed. | See the table above. | Devices long-poll; services that need every entry use the log and checkpoints (§10). |
| **Consumers read over HTTP**: a consumer catches up from the log and fetches each changed document (§10). | Catch-up of 4M entries: 2.4 min; bootstrap of 1M documents: ~11 min on server X. | Consumer throughput is the consumer's (gaps below); the origin side scales with instances. |

### Gaps in this implementation

| Gap | Effect | Fix |
|---|---|---|
| **Bearer cache of 1,024 grants** per instance (`maxGrantCacheEntries`), emptied when full. | A fleet with more than 1,024 active tokens verifies its grant (Biscuit decode, Ed25519) on every request: reads p50 6.6 ms against 4.6 ms with cached grants, 1,030/s against 1,630/s. | A larger, byte-bounded cache (tens of thousands of grants), evicting gradually. |
| **No edge that verifies edge grants** is included. | Private long-polls don't collapse at the CDN: ~1 ms of core CPU per follower per write. | An edge (Varnish VMOD, Fastly or Cloudflare worker) with `edge.Cookies.Check`'s checks; the origin already issues the cookies. |
| **Log pages bound entries, not items.** A batch entry carries its items inline. | A page of 1,000 batch entries of 1,000 items holds 1M items. | Bound pages by resource entries or bytes too. |
| **Rate-limit buckets are never evicted**: one per (namespace, resource, principal) written, per instance. | Memory grows with distinct resources written until restart. | Drop buckets that are full again (idle longer than burst / rate). |
| **The document cache is bounded by count** (4,096 documents), not bytes; the 64 MiB read cache empties itself when full. | Up to 16 GiB of 4 MiB documents; hit rates collapse past 64 MiB. | Byte budgets and gradual eviction. |
| **The compiled-schema cache is never evicted.** | Memory grows with distinct schema revisions used. | Bound it. |
| **No read replicas, and one `-db` for everything** (the core runs migrations, the tailer and leader jobs, so it can't run on a read-only database). | Consumers' scans and private reads load the primary. | Route bulk reads (catch-up, bootstrap, export) and private reads to a replica, with misses of new revisions falling back to the primary; decisions stay on the primary. |
| **Consumers** (index, tree): one SQLite writer per process, 8 document fetches at a time (the tree service: one), no sharding but by namespace lists. | Bootstrap of 1M documents: ~11 min on server X (fetches at 1,600/s); 2.6 min on SQLite. | More fetch concurrency, pipelining pages; split namespaces over processes. |
| **A namespace purge is one transaction.** | Long lock and transaction for large namespaces. | Purge in chunks. |
| **No profiling endpoint; the core sets no memory limit.** | Peak RSS 1.7–1.8 GB in these runs (steady 0.8 GB), unexplained without a profile. | Run with `GOMEMLIMIT` under container limits; add an opt-in pprof listener. |

Fixed in this branch, and so not limits any more: namespace log pages scanned and sorted the
whole namespace, and the config-retry lookup the whole log (now indexed; CHANGELOG, Unreleased);
a consumer's snapshot bootstrap held the whole `/heads` listing in memory and one transaction
(now paged and resumable).

### Deployment

| Resource | Measured | Notes |
|---|---|---|
| **Core CPU** | Grant checks, canonicalisation, validation, folds, page serialisation and uncollapsed followers are core CPU. | Scales with instances (see the comparison above). |
| **Postgres round trips** | A single write is ~13 statements; on server X one writer did 125 writes/s (7.5 ms each), neither container saturated. | Keep the core near Postgres (sub-millisecond); concurrency, not speed, is what instances add. |
| **Postgres CPU and memory** | ~1.3 of 2 vCPU and 3.4 of 4 GB under the read measurements. | The busier side on server X. |
| **Storage** | 6.2 GB on Postgres, 3.1 GB on SQLite for 5M revisions of ~500-byte documents. | Linear in revisions; pruning (§8.6) bounds it. |
| **Memory** | Core: 0.8 GB steady, 1.7–1.8 GB peak. | Give containers `GOMEMLIMIT`. |
| **Upgrades** | The new namespace-log indexes build in the migration, blocking writes a few seconds per 5M log entries. | `CREATE INDEX CONCURRENTLY` beforehand (README). |

## Recommended changes to limits

- **Bearer cache**: 1,024 → a byte budget of tens of thousands of grants (gap above).
- **Document and read caches**: byte budgets with gradual eviction.
- **Log pages**: bound items or bytes as well as entries.
- **`documentSize`**: a default of 1 MiB, with a deployment flag allowing up to 4 MiB. Appends at
  3.5 MiB are 3–4× slower than at 16 KiB, and every revision of a large document weighs on the
  caches; today the default is also the maximum.
- **Keep**: the rates (500/s a namespace is just under one namespace's ceiling on server X),
  `itemsPerBatch` 1,000 (imports; give importers allowances), the snapshot cadence, the
  long-poll interval and the log page size.

## Rerunning

```sh
go build -o patchlog ./cmd/patchlog && go build -o capacity ./cmd/capacity
./patchlog serve -dev -addr :9080 -db cap.db -origin http://localhost:8080 &
./capacity -url http://127.0.0.1:9080 -pid $! -json result.json   # 1M docs, 5M revisions: about 1-1.5 h to seed
```

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
