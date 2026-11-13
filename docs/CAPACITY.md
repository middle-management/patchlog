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
| **Whole-document work on every write**: the result is canonicalised, checked against the limits and validated against its `$schema` in full; a small patch to a large document costs the document's size. | Append p50: 7 ms at 16 KiB, 15 ms at 1 MiB, 25 ms at 3.5 MiB (server X); 1.7 / 7 / 19 ms on SQLite. Those are documents of long strings without a `$schema`; many small values cost 3–5× more, and a schema that types them about 3× more again ([below](#large-documents-by-shape-and-schema)). | Keep frequently edited documents small: split large aggregates into resources. |
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

## Large documents, by shape and schema

Measured on 2026-11-12 at spec 0.82 with `cmd/capacity -only large,single`, on a 4-vCPU / 15 GB
host that also ran the load generator, `-dev`, the core unconstrained: SQLite, and Postgres 16 on
the same host with default settings. This is **not server X**, so compare the columns with each
other, not with the envelope above. Each figure is the median of 60 appends of
`[{"op":"replace","path":"/n","value":i}]`, one after another, to one document.

Three documents per size:

- **strings**: `{ n, items }` with `items` an array of 1,000-character strings, no `$schema`.
  This is the shape the envelope's numbers used.
- **structured**: `{ n, items }` with `items` an array of objects of about 110 bytes
  (`{ id, name, score, tags: [..], at, ok }`), no `$schema`: about 9,500 objects a MiB.
- **schema**: the structured document with `$schema` pinned to a schema revision in the same
  namespace that types every member: `type` and `required` throughout, closed item objects
  (`additionalProperties: false`), a `pattern` on `name`, `minimum`/`maximum`, `maxItems` and
  `maxLength`, and `format: date-time` on `at`.

| Append p50 | 16 KiB | 256 KiB | 1 MiB | 3.5 MiB |
|---|---|---|---|---|
| SQLite, strings | 1.2 ms | 2.0 ms | 5.0 ms | 14 ms |
| SQLite, structured | 1.4 ms | 6.5 ms | 22 ms | 73 ms |
| SQLite, schema | 2.5 ms | 17 ms | 58 ms | 225 ms |
| Postgres, strings | 4.8 ms | 5.5 ms | 9.1 ms | 17 ms |
| Postgres, structured | 4.9 ms | 11 ms | 27 ms | 75 ms |
| Postgres, schema | 5.9 ms | 21 ms | 68 ms | 220 ms |

- **The shape matters more than the bytes.** The same bytes as many small values cost 3–5× a
  document of long strings: parsing, applying and canonicalising work per value.
- **Validation roughly triples it again**: about 40 ms a MiB of small typed objects on top of
  about 20 ms a MiB without a schema. At the 1 MiB default a typed document of this shape takes
  ~60 ms an append, at 3.5 MiB ~220 ms, p99 ~300 ms.
- The database adds a constant (3–4 ms on this Postgres); the rest is the core's CPU, which is
  why the two databases agree at the large sizes.
- Creating the document costs about what two appends do (190 ms at 1 MiB, 530 ms at 3.5 MiB
  with the schema).

The advice under [By design](#by-design) stands, with a number: keep a frequently edited typed
document well under 100 KiB if its appends should stay under 10 ms.

## Writes to one document

Same host and day, a document of about 500 bytes. Each writer is a principal of its own that
appends in a loop for 15 seconds without pausing, with `If-Match` on the head it last saw, and
shares nothing with the others. Two ways of retrying:

- **at once**: after a `412` read the head again and retry; after a `429` wait 100 ms.
- **backoff**: the client's `AppendLatest`: after a `412` take the head from the refusal's body
  and wait a random time under a ceiling that doubles with each loss in a row (2 ms to 16 ms);
  after a `429` wait its `Retry-After` and read the head again.

**At the default limits** the per-resource rate is the ceiling: §6.6 allows 10 writes a second
(burst 20) per resource and principal, and an allowance doesn't lift it.

| Writers | Retry | Appends/s (SQLite / Postgres) | Attempts `412` | Attempts `429` | Fewest and most appends by one writer (SQLite) |
|---|---|---|---|---|---|
| 1 | | 11 / 11 | 0 | 46% | |
| 8 | at once | 12 / 12 | 46% | 46% | 8 and 47 |
| 8 | backoff | 16 / 13 | 43% | 46% | 24 and 46 |
| 32 | at once | 14 / 14 | 51% | 46% | 0 and 40 |
| 32 | backoff | 28 / 19 | 49% | 46% | 4 and 36 |

- **The document takes about one writer's rate however many write it.** Each principal has a
  bucket of its own, but a write refused with `412` has still drawn its tokens (the buckets are
  drawn before the precondition is compared), and a writer that waited for a token usually
  holds a stale head by then. So 8 writers together do 12 a second, and 32 do 14.
- The backoff helps a little (up to twice the appends at 32 writers) and spreads them more
  evenly, but about half the attempts are still `412`s: the rate, not the retry policy, decides.

**With the rate lifted** (`serve -max-rate-per-resource 1e6,1e6 -max-rate-per-principal 1e6,1e6`
and a namespace whose `limits` set both that high; `capacity -single-rate 1000000`) nothing is
rate limited and the core and the database set the pace:

| Writers | Retry | Appends/s (SQLite / Postgres) | Attempts `412` (SQLite / Postgres) | One write, retries included, p50 / p95 / p99 (SQLite) | Fewest and most appends by one writer (SQLite / Postgres) |
|---|---|---|---|---|---|
| 1 | | 1,130 / 295 | 0 | 0.7 / 1.1 / 9.7 ms | |
| 8 | at once | 600 / 175 | 84% / 86% | 1.7 / 72 / 128 ms | 1,025 and 1,244 / 231 and 447 |
| 8 | backoff | 1,000 / 284 | 44% / 70% | 0.8 / 1.4 / 227 ms | 1,517 and 2,299 / 0 and 1,591 |
| 32 | at once | 236 / 87 | 95% / 96% | 19 / 580 / 947 ms | 62 and 152 / 19 and 59 |
| 32 | backoff | 764 / 128 | 81% / 95% | 1.0 / 3.5 ms / 1.4 s | 105 and 630 / 0 and 175 |

- **One writer in a loop does about 1,100 appends a second on SQLite and 300 on Postgres** to a
  small document, about a hundred times the default rate on SQLite.
- **More writers make it slower, not faster.** Every append needs the head the last one made, so
  the writers queue behind one another whatever the server does. Retrying at once, 8 writers
  get half of what one does and 32 a fifth, with 84–96% of their requests wasted.
- **Backing off recovers most of the throughput**: on SQLite 8 writers do 1,000 a second with
  44% of attempts lost, and 32 do 764. It doesn't make the document fair: the writer that just
  won holds the newest head and waits for nothing, so it tends to win again, and on Postgres,
  where a write takes longer than the backoff's ceiling spreads the losers, some writers got no
  append in at all in 15 seconds. A longer ceiling loses fewer requests and is less fair still
  (at 250 ms one of 8 writers did more than half the appends and another none).
- These writers never pause, the worst case. Writers with time between their writes collide
  less in proportion.

What the retry policy can't change is that a lost race costs a whole request. The remedies are
structural: one writer per document (or a queue in front of it), a writer's changes collected
into batch steps (below), or an append the server may rebase when the writes in between don't
overlap its own, which the next section measures.

### An experimental rebase

**Not in the spec** (docs/SPEC-FEEDBACK.md, v0.82 Open 91); off unless the core runs with
`-experimental-rebase`. A `PATCH` with `X-Experimental-Rebase: 1` whose `If-Match` is no longer
the head is applied to the head, in place of a `412`, when `If-Match` names an ancestor at most
64 revisions back and nothing written since overlaps the paths the patch set touches (its ops'
paths, a copy's or move's `from` and its tests; a path through an array counts as the whole
outermost array, as in §F.3, except that two sides that only append to the same array don't
conflict). It then passes every later check as an append on that head. A delete, a signed write
and an end-to-end namespace are never rebased.

Same setup with the rate lifted, on two workloads where writers don't conflict in substance:
**member** (each writer replaces a member of its own, `/members/wK`) and **append** (every
writer does `add /list/-`; 5 seconds, since the document grows). Appends a second, then the
share of attempts answered `412`:

| Workload, writers | At once | Backoff | Rebase (with the backoff as fallback) |
|---|---|---|---|
| SQLite, member, 8 | 562, 84% | 943, 45% | 827, 0% |
| SQLite, member, 32 | 219, 95% | 737, 82% | 552, 0% |
| SQLite, append, 8 | 529, 83% | 664, 54% | 503, 0% |
| SQLite, append, 32 | 260, 95% | 575, 85% | 380, 0% |
| Postgres, member, 8 | 170, 86% | 268, 71% | 257, 0% |
| Postgres, member, 32 | 81, 96% | 116, 95% | 150, 0% |
| Postgres, append, 8 | 175, 86% | 256, 72% | 220, 0% |
| Postgres, append, 32 | 80, 96% | 124, 95% | 133, 0% |

| SQLite, member | Fewest and most appends by one writer | One write, retries included: p50 / p99 / max |
|---|---|---|
| 8 writers, backoff | 1,125 and 2,515 | 0.8 ms / 208 ms / 3.2 s |
| 8 writers, rebase | 1,530 and 1,580 | 8.5 / 27 / 50 ms |
| 32 writers, backoff | 64 and 577 | 1.0 ms / 1.3 s / 9.7 s |
| 32 writers, rebase | 256 and 262 | 58 / 82 / 99 ms |

- **No request is wasted and every writer gets the same share.** With the backoff some Postgres
  writers got nothing in 15 seconds; rebased, the fewest and the most by one writer were 471
  and 496 of 8, and 65 and 76 of 32.
- **The tail goes from seconds to tens of milliseconds**: every write is served in turn, so
  the median is higher than the backoff's (whose median is the winner's) and the worst case far
  lower.
- **Total throughput is the single writer's or somewhat under it**, and falls as writers are
  added (1,010 a second for one writer, 827 for 8, 552 for 32 on SQLite): a rebase reads the
  patch sets written since its base and folds them to know what they wrote, so each write
  costs more the further behind it is. The backoff's higher totals on SQLite are one or two
  writers doing most of the work.
- One writer pays nothing for asking (1,010 against 1,060 a second on SQLite, within the run's
  noise).
- Writers that do conflict (the **same** workload, every writer replacing `/n`) get `412` as
  before: there the fallback is all there is.
- That was the first prototype, which folded the patch sets since the base on every rebase
  and committed each write on its own. Two changes since, measured the same way (member
  workload, 10 seconds):

  | Appends/s, 8 and 32 writers | SQLite | Postgres |
  |---|---|---|
  | One writer, for scale (it varied this much between the runs) | 1,060–1,290 | 330–385 |
  | First prototype | 830–890 and 550–620 | 250–260 and 146–150 |
  | Remembering what each revision touched | 936 and 681 | 261 and 148 |
  | And writing the waiting writes of a document in one transaction (`-experimental-combine`) | 2,870 and 2,380 | 399 and 243 |
  | And reading nothing twice in that transaction | 3,610 and 3,620 | 609 and 674 |
  | And, on Postgres, inserting the group's rows together | 3,440 and 3,670 (unchanged: not used on SQLite) | 917 and 1,334 |

  - **Remembering what revisions touched** (by revision id, in memory, with the parent's id,
    so a known chain is walked without the database) helps a little: the fold wasn't the main
    cost.
  - **One transaction for the writes that wait together**: each write still goes through the
    whole gate on the result of the one before it; a refused one is answered with its refusal
    and the others land; they commit once. On SQLite that alone gave 2.7 times one writer's
    rate. On Postgres it gave little, and timing the transaction showed why: the commit a
    group shares costs 0.4–0.7 ms, while each write's own statements cost 1.9–2.7 ms. A single
    append is about 15 statements, each a round trip: a rate draw, reads of the namespace, the
    resource's row, its head revision (twice), its head document and its blob references, the
    inserts of the revision and the head document, the head's move, and the log's head and
    append.
  - **Reading nothing twice**: in such a transaction the resource's row, its head revision and
    its document are what the write before just made, so they are kept in memory, and the
    log's head is the entry appended last. Postgres then does 609 appends a second from 8
    writers and 674 from 32, twice one writer's 365–385, and no longer falls as writers are
    added; SQLite does 3,600 from 8 and from 32, three times one writer's.
  - Shares stay even (4,502 and 4,534 appends by the least and the most served of 8 on
    SQLite, 1,125 and 1,138 of 32; 210 and 211 of 32 on Postgres), and the worst write of 32
    writers took 44 ms on SQLite and 77 ms on Postgres.
  - **Inserting the group's rows together** (Postgres): the revisions, the heads' moves, the
    heads documents and the namespace entries of a group are held in memory and written at its
    end, one statement per table, with the revisions' sequence numbers drawn beforehand so a
    child can name its parent before either is inserted. Any other statement the transaction
    runs first writes what is held back, but for a short list that can't be affected by it, so
    a write that does something unforeseen costs a flush, not a wrong answer. Postgres then
    does 917 appends a second from 8 writers and 1,334 from 32, against 340–460 for one
    writer: more writers now means more throughput, since a larger group shares the same few
    statements. Shares stay even (1,145 and 1,147 by the least and the most served of 8, 417
    and 418 of 32) and the worst write of 32 writers took 45 ms.
  - **Finding what forced the rows out early** took three rounds of measuring: the retry
    lookup (§7.2) asked the database for every write's own id, then reads of committed
    revisions by sequence number, then the namespace's row and the head's blob references,
    each now answered from memory or exempt where the rows held back can't change the answer.
  - **Still per write on Postgres**: the rate draw, and a read or two of rows committed before
    the group. A snapshot (every so many revisions) writes at once.
  - **How it was tested.** `PATCHLOG_TEST_COMBINE_ALL=1` sends every single resource write of
    the test suites through this transaction, a group of one included, with its ordinary
    meaning, and on Postgres with its rows held back as above. The core, server, client,
    merge and bundle suites pass that way on SQLite and on Postgres, and the core suite under
    the race detector. The first runs found three faults, since fixed: patch sets weren't compressed on
    this path, a cancelled request's write wasn't rolled back, and losing a race to a writer
    on another instance surfaced as a database error in place of a `412`.
- **A repeated rebased write is applied again** unless it carries a retry key: §7.2 recognises a
  retry by its parent, which the server chose here. The prototype takes
  `X-Experimental-Producer: {id};{epoch};{seq}`, after the Durable Streams protocol's idempotent
  producers, and writes each `seq` once: with every third answer lost, 12 appends left 16 items
  without it and 12 with it. The record (per resource, author and producer id: the last epoch
  and seq, and the revision that write made) is a row of `write_producers`, written in the
  write's own transaction, so a repeat is recognised at any instance and after a restart. It
  costs a read per write: 754 and 933 appends a second from 8 and 32 writers on Postgres
  against 876 and 1,242 without the key (`_rebase_producer` in the two-instance results).
- **Several instances.** What the prototype keeps in memory is either the transaction's own (the
  rows it holds back, checked against the database when they are written), a cache keyed by
  revision id, which can't go stale, or a queue per instance. So two instances that both take
  writes of one document each form their own groups, and the group that writes second finds
  the head moved, rolls back and sends its writes on alone. Nothing is lost or written twice,
  but work is wasted. Two instances on one Postgres, the member workload for 10 seconds:

  | Appends/s, 8 and 32 writers | A document's writes at one instance | Spread over both |
  |---|---|---|
  | Rebased | 876 and 1,242 | 392 and 910 |
  | Fewest and most by one writer | 1,095 and 1,096; 388 and 389 | 458 and 522; 23 and 546 |
  | Worst write | 31 ms; 56 ms | 73 ms; 261 ms |

  Route a namespace's writes to one instance, as the envelope's two-instance run did
  ("writes routed by namespace"): then two instances behave as one. Spread, throughput
  halves with 8 writers, a few writers get most of the turns with 32, and 1% of attempts are
  `412`.
- **Tests for that** (`internal/core/rebase_multi_test.go`, on Postgres): writers on both
  instances rebasing onto one document, each repeating every third write at the other instance
  (120 writes, 40 repeats: each lands once and every repeat is answered with the first
  attempt's revision); the other instance committing a write of the document while a group's
  rows are held back (the group rolls back and its writes land on their own, over the
  other's); and a producer's record recognised at the other instance and after a restart, a
  gap refused, another author's producer of the same name its own.
- A rebased write is validated on the head it lands on, so it can be `422` where it was valid on
  its base (two writers each adding the last item a schema's `maxItems` allows), and a
  dependency between members that the schema doesn't hold is only protected by a `test` op on
  it. SPEC-FEEDBACK note 91 has both cases; the tests are in
  `internal/client/rebase_experimental_test.go`.

**A batch writes many steps to one document at once** (§7.5: one item, many steps, one token):

| One item of | SQLite | Postgres |
|---|---|---|
| 100 steps | 4–5 ms | 18 ms (152 ms as the first batch on a cold connection) |
| 1,000 steps | 36–44 ms (23,000–28,000 steps/s) | 146–205 ms (4,900–6,800 steps/s) |

**A long history doesn't slow a document down.** One document grown to 100,000 revisions:

| Revisions | Append p50 (SQLite / Postgres) | Head read | Document at head | Document at its first revision |
|---|---|---|---|---|
| 1,000 | 0.9 / 3.3 ms | 0.2 ms | 0.2–0.3 ms | 0.2 ms |
| 10,000 | 1.1 / 4.4 ms | 0.2 ms | 0.2 ms | 0.2 ms |
| 100,000 | 1.4 / 4.1 ms | 0.2 ms | 0.2–0.4 ms | 0.2 ms |

The reads were made right after the writes, from warm caches, 20 samples each: they show that
nothing scans the history, not what a cold read of an old revision costs (the envelope's "cold
reads of old revisions" row does).

So a document that many parties write often (a counter, a shared list, a presence record) is the
wrong shape: at the default limits it takes about 10 writes a second in all, and at any limits
several writers waste most of their attempts. Give each writer a document of its own, or collect
a writer's changes into batch steps. Where one writer does need more than 10 writes a second on
a small document, raise the deployment maximum (`serve -max-rate-per-resource`) and set
`ratePerResource` in that namespace's `limits`; leave it at the default where documents are
large, since a typed 1 MiB document already costs ~60 ms of CPU an append (above). Clients that
do share a document should retry with `AppendLatest` or its like, not at once.

## Recommended changes to limits

- **Bearer cache: done.** 65,536 grants, at most 32 MiB of tokens, least recently used out first
  (`serve -grant-cache`).
- **Document and read caches: done.** 256 MiB and 64 MiB, evicting gradually
  (`serve -doc-cache-size`, `-read-cache-size`).
- **Log pages**: bound items or bytes as well as entries.
- **`documentSize`: done.** 1 MiB by default, 4 MiB a namespace may set (`serve -document-size`,
  `-max-document-size`). Appends at 3.5 MiB are 3–4× slower than at 16 KiB, and every revision of
  a large document weighs on the caches.
- **Per-resource and per-principal maximums: done.** `serve -max-rate-per-resource` and
  `-max-rate-per-principal` let a namespace set its own above the defaults (10/s and 50/s), for
  small documents one writer writes often. The defaults stay.
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
- **Large documents and one hot document**: `-only large,single` needs no seeding (it makes
  namespaces of its own) and takes about two minutes; `-single-seconds` sets how long each
  single-document measurement runs, and `-single-rate N` runs them in a namespace that allows N
  writes a second per resource and principal (the core then needs `-max-rate-per-resource N,N
  -max-rate-per-principal N,N`).
- Sizes: `-docs`, `-revs`, `-namespaces`, `-doc-size`, `-append-batch`; `-help` lists the rest.
