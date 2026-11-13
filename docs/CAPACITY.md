# Capacity

What one deployment of this implementation handles, measured. For each limit it found, this
document says whether the limit is **by design** (the spec's model; changing it means changing
how data is laid out), a **gap** (this implementation; fixable without changing the spec) or
**deployment** (hardware and configuration; buy or tune your way past it).

## At a glance

- **A small server handles about 1,000–1,600 reads a second and 590 single writes a second into
  one namespace** (from 32 writers). The server is "server X": a 2 vCPU / 4 GB core and a
  2 vCPU / 4 GB Postgres. See [The envelope](#the-envelope).
- **Data size doesn't slow requests.** A namespace of 1,000,000 documents and 5,000,000
  revisions answers like a small one. Size costs storage, full scans and memory. See
  [What data size costs](#what-data-size-costs).
- **Postgres, not the core, limits server X.** Give Postgres the CPU first. See
  [What limits server X](#what-limits-server-x).
- **Followers are cheapest through the CDN.** 5,000 followers of a public namespace cost the
  origin 0.01 s of CPU a write. Private followers cost about 0.1–0.2 ms of core CPU each per
  write. See [Long-poll followers and the CDN](#long-poll-followers-and-the-cdn).
- **Large typed documents are slow to write**: up to about 225 ms an append at 3.5 MiB, ~60 ms
  at the 1 MiB default. Keep a frequently edited typed document well under 100 KiB. See
  [Large documents, by shape and schema](#large-documents-by-shape-and-schema).
- **One document takes about 10 writes a second in all by default**, however many writers share
  it, and the writers collide: 8 writers together got 12 a second, 32 got 14. See
  [Writes to one document](#writes-to-one-document).
- **Make each list entry a resource of its own**: 1,930 writes a second from 32 writers on
  Postgres, where the shared document did 88. Nothing collides. See
  [One resource per item](#one-resource-per-item).
- **A shared document is not fair between writers.** With a backoff some writers got no write in
  at all. With a resource per item the shares differ by 2% at most. See
  [Fairness between writers](#fairness-between-writers).
- **One writer with many changes should batch them**: 1,000 steps to one document take 36–44 ms
  on SQLite and 146–205 ms on Postgres. See [Batches](#batches).
- **A long history doesn't slow a document down**, measured up to 100,000 revisions. See
  [Long histories](#long-histories).

## Contents

- [What was measured, and on what](#what-was-measured-and-on-what)
- [The envelope](#the-envelope)
- [What limits server X](#what-limits-server-x)
- [Long-poll followers and the CDN](#long-poll-followers-and-the-cdn)
- [Large documents, by shape and schema](#large-documents-by-shape-and-schema)
- [Many writers](#many-writers)
  - [Writes to one document](#writes-to-one-document)
  - [One resource per item](#one-resource-per-item)
  - [Fairness between writers](#fairness-between-writers)
  - [Batches](#batches)
  - [Long histories](#long-histories)
  - [A prototype that was set aside](#a-prototype-that-was-set-aside)
- [Limits, by kind](#limits-by-kind)
- [Recommended settings](#recommended-settings)
- [Rerunning](#rerunning)

## What was measured, and on what

The numbers come from `cmd/capacity` (see [Rerunning](#rerunning)). They are taken over HTTP,
from a load generator on the same host as the server, so they include the HTTP stack and are
conservative.

There are two test setups. **Numbers from one are not comparable with numbers from the other.**

### Server X (2026-10-15, spec 0.52)

Used for [the envelope](#the-envelope), [what limits server X](#what-limits-server-x) and
[followers](#long-poll-followers-and-the-cdn). The raw results are in [`capacity/`](capacity/).

- **Hardware:** the core at **2 vCPU / 4 GB**, Postgres 16 at **2 vCPU / 4 GB**, each in its own
  container on one 4-vCPU host, which also ran the load generator.
- **Grants on:** the namespaces are private (`read: grant`), and every request carries a signed
  grant.
- **Data:** 1,000 small namespaces (10 documents each) and one large namespace of
  **1,000,000 documents** and **5,000,000 revisions**. The large namespace was made by 1M
  creates (in 1,000-item batches) and 4M single appends of a small patch. Its documents are
  about 500 bytes.
- **Size on disk:** 6.2 GB in Postgres. The same data is 3.1 GB in SQLite.

Some rows quote SQLite figures next to server X's; they say so.

### Host B (2026-11-12, spec 0.82)

Used for [large documents](#large-documents-by-shape-and-schema) and [many writers](#many-writers).
This is **not server X**. The large-document runs and the first runs of writes to one document
are from 2026-11-12. The resource-per-item and fairness runs, and the runs with two instances,
are from 2026-11-13 on the same host. The raw results of all of them are in
[`capacity/`](capacity/) too, listed in its README.

- **Hardware:** a 4-vCPU / 15 GB host that also ran the load generator.
- **Core:** run with `-dev`, unconstrained.
- **Databases:** SQLite, and Postgres 16 on the same host with default settings.

Within these sections, compare SQLite with Postgres and one row with another. Do not compare
them with the envelope.

## The envelope

At the data size above, server X answers as follows. These are origin numbers, before any CDN.

| Operation | Result on server X |
|---|---|
| Reads of a document or head pointer | 1,000–1,600/s at 8 concurrent, p50 4.6–6.6 ms, p99 ≤ 27 ms |
| Cold reads of old revisions (folds) | 470/s, p50 15 ms |
| Single writes to one namespace | 125/s from one writer (p50 7.5 ms), 310/s from 8, **590/s from 32** (p50 52 ms, p99 91 ms) |
| Single writes spread over 1,000 namespaces | 420/s from 32 writers (p50 66 ms, p99 210 ms) |
| A batch of 1,000 appends | 1.4 s |
| Appends to a large document | p50 7 ms at 16 KiB, 15 ms at 1 MiB, 25 ms at 3.5 MiB |
| A consumer's full catch-up of the large namespace | log: 4M entries in 2.4 min; `/heads`: 1M in 37 s; fetching 1M documents 8 at a time: ~10 min |
| Long-poll followers of one **private** namespace | 5,000 followers: 0.3–1 s of core CPU and 0.35–0.7 s to deliver each write. The waiters share one read at the origin; there is no CDN collapse ([see below](#long-poll-followers-and-the-cdn)). Before the origin shared the read it was 3.7–4.1 s of CPU. |
| Long-poll followers of one **public** namespace, behind the CDN | 5,000 followers: 0.01 s of core CPU, all delivered in 0.25 s (0.4 s on SQLite) |

The large-document row is for documents of long strings without a `$schema`. Other shapes cost
more: see [Large documents, by shape and schema](#large-documents-by-shape-and-schema).

### What data size costs

**None of the per-request numbers above depends on the namespace's size.** Pages and reads use
indexes (see the fixes under Unreleased in the CHANGELOG). So a namespace of 1M documents and
5M revisions answers like a small one.

What does grow with size:

- **Storage:** about 1.2 KB a revision on Postgres and 620 B on SQLite, for these small
  documents.
- **Full scans:** catch-up, bootstrap and bundle export.
- **Memory:** see [Deployment](#deployment).

## What limits server X

**The core isn't server X's bottleneck; Postgres is.**

The same data was measured again with different cores. Grants are on unless noted. Reads come
from 8 concurrent clients. Writes go to the large namespace from 32 writers.

| Core | Reads, uncached grants | Reads, cached grants | Writes, one namespace | Writes, 1,000 namespaces | Bootstrap fetches |
|---|---|---|---|---|---|
| 2 vCPU, authentication off | 1,840/s, p50 3.9 ms | — | 750/s, p50 41 ms | 460/s | 1,920/s |
| 2 vCPU | 1,030/s, p50 6.6 ms | 1,630/s, p50 4.6 ms | 590/s, p50 52 ms | 420/s | 1,620/s |
| 1 vCPU | 1,130/s, p50 5.3 ms | 2,070/s, p50 3.3 ms | 790/s, p50 40 ms | 400/s | 1,220/s |
| 2 × 1 vCPU, writes routed by namespace | 1,110/s, p50 6.4 ms | 1,510/s, p50 4.8 ms | 700/s, p50 45 ms | 380/s | 1,440/s |

What the table shows:

- **Halving the core changes little, and a second instance adds nothing.** The 2-vCPU Postgres
  (at ~1.3 vCPU and 3.4 GB under these loads) and its round trips set the pace.
- **On server X, give Postgres the CPU first.** More core instances pay off once the core's own
  CPU is the limit. That happens with grant checks at fleet scale, with large documents, and
  with uncollapsed followers that are CPU-bound rather than database-bound.
- **Grants cost ~40% of read throughput when the grant isn't cached** (1,030/s against 1,840/s
  without authentication). Most of that is verification. With grants in the core's bearer cache,
  reads are within ~10% of unauthenticated ones.
- **Write throughput into one namespace doesn't depend on the core's size here.** The
  namespace's log (one append at a time, grouped) and Postgres set it.

## Long-poll followers and the CDN

**Followers of a public namespace cost the origin almost nothing behind the CDN. Followers of a
private namespace each cost an origin connection, and about 0.1–0.2 ms of core CPU per write.**

### Public namespaces: the CDN collapses followers

Many followers (devices, not consumer services) are meant to long-poll (§7.7) through the CDN.
It works like this:

- Every follower of a namespace asks for the same URL: `since` the head, with the same interval
  `cursor`.
- The CDN collapses identical misses into one origin request.
- The answer is cached for the interval.

The origin's cost is then one request per namespace, interval and CDN node, whatever the number
of followers. Measured with the repository's Varnish configuration
(`deploy/varnish/default.vcl`): 1,100 followers made 4 origin requests.

### Private namespaces: no collapse at the CDN

The CDN collapse holds for **public** namespaces only. A private namespace's long-poll answers
are `CDN-Cache-Control: no-store` unless the CDN verifies edge grants (§C.5, `-edge-secret`).
No edge that verifies them is included. Only the checks are, in Go: `edge.Cookies.Check`.

Without such an edge, every follower is an origin request, and every write wakes all of them.

### Origin-side collapse

The origin shares the reads of the followers it wakes (`internal/core/live.go`):

- A waiter's first read is checked as any read is.
- While that decision holds, the waiter's later reads skip the check and are shared with every
  waiter woken by the same commit. That is one log read per namespace, `since` and commit,
  whatever the number of waiters.
- The decision holds as long as there has been no configuration change, purge or other change to
  what reads may return since, the grant has not expired, and no rule reads `/now`.

Before this, each woken waiter read the log in a transaction of its own.

### Measured

Each cell is the time until every follower had the write, and the core's CPU time for it
(CPU-s).

| Followers of one namespace | public, via CDN | private, direct, before | private, direct, origin collapse | private, via Varnish, origin collapse |
|---|---|---|---|---|
| 100 | 7 ms, ~0 CPU-s | 0.3–0.4 s, 0.06–0.07 CPU-s | 0.03–0.5 s, 0.02–0.03 CPU-s | 0.24–0.41 s, 0.02–0.03 CPU-s |
| 1,000 | 46 ms, ~0 CPU-s | 0.63–0.71 s, 0.7–0.8 CPU-s | **0.08 s, 0.10–0.12 CPU-s** | 0.53–0.60 s, 0.08–0.11 CPU-s |
| 5,000 | 0.25–0.39 s, 0.01 CPU-s | 3.1 s, 3.7–4.1 CPU-s | **0.35–0.69 s, 0.33–0.98 CPU-s** | 2.8–3.0 s, 1.25–2.2 CPU-s |

- **Private columns:** server X (Postgres, the core at 2 vCPU), grants, two runs each, the core
  idle before the write.
- **Public column:** SQLite and server X.

What the table shows:

- **With the collapse, a write costs about 0.1–0.2 ms of core CPU per private follower.** Before
  it cost 1 ms: a transaction and a log query each.
- **Server X therefore delivers roughly 5,000–15,000 follower-writes a second**, against ~1,000
  before.
- **Through Varnish, the rest of the time is Varnish** passing 5,000 private connections on the
  same host.

The repository's VCL no longer queues a long-poll with credentials behind an identical one in
flight (`hash_ignore_busy`). It used to hold them until the next write and then send them to the
origin a few at a time, as new requests that share nothing.

### Planning rule

For private followers without a verifying edge:

- Plan for `followers × writes/s` up to ~5,000/s on server X.
- Every follower is a connection the origin holds open. (A CDN in front holds them instead when
  it verifies edge grants.)

## Large documents, by shape and schema

**Every write works on the whole document, so a small patch to a large document costs the
document's size. The shape matters more than the bytes: many small values cost 3–5× a document
of long strings, and a schema that types them about 3× more again.** Keep a frequently edited
typed document well under 100 KiB if its appends should stay under 10 ms.

Measured on [host B](#host-b-2026-11-12-spec-082) on 2026-11-12 at spec 0.82, with
`cmd/capacity -only large,single`. Each figure is the median of 60 appends of
`[{"op":"replace","path":"/n","value":i}]`, one after another, to one document.

Three documents were measured at each size:

- **strings**: `{ n, items }` with `items` an array of 1,000-character strings, no `$schema`.
  This is the shape the envelope's numbers used.
- **structured**: `{ n, items }` with `items` an array of objects of about 110 bytes
  (`{ id, name, score, tags: [..], at, ok }`), no `$schema`. That is about 9,500 objects a MiB.
- **schema**: the structured document with `$schema` pinned to a schema revision in the same
  namespace. The schema types every member: `type` and `required` throughout, closed item
  objects (`additionalProperties: false`), a `pattern` on `name`, `minimum`/`maximum`,
  `maxItems` and `maxLength`, and `format: date-time` on `at`.

| Append p50 | 16 KiB | 256 KiB | 1 MiB | 3.5 MiB |
|---|---|---|---|---|
| SQLite, strings | 1.2 ms | 2.0 ms | 5.0 ms | 14 ms |
| SQLite, structured | 1.4 ms | 6.5 ms | 22 ms | 73 ms |
| SQLite, schema | 2.5 ms | 17 ms | 58 ms | 225 ms |
| Postgres, strings | 4.8 ms | 5.5 ms | 9.1 ms | 17 ms |
| Postgres, structured | 4.9 ms | 11 ms | 27 ms | 75 ms |
| Postgres, schema | 5.9 ms | 21 ms | 68 ms | 220 ms |

What the table shows:

- **The shape matters more than the bytes.** The same bytes as many small values cost 3–5× a
  document of long strings. Parsing, applying and canonicalising all work per value.
- **Validation roughly triples it again.** It adds about 40 ms a MiB of small typed objects on
  top of about 20 ms a MiB without a schema. At the 1 MiB default a typed document of this shape
  takes ~60 ms an append. At 3.5 MiB it takes ~220 ms, p99 ~300 ms.
- **The database adds a constant** (3–4 ms on this Postgres). The rest is the core's CPU, which
  is why the two databases agree at the large sizes.
- **Creating the document costs about what two appends do**: 190 ms at 1 MiB and 530 ms at
  3.5 MiB with the schema.

## Many writers

**A document that many parties write often (a shared list, a feed, a presence record) is the
wrong shape.** At the default limits it takes about 10 writes a second in all. At any limits,
several writers waste most of their attempts.

What to do instead:

- **Make each item a resource of its own** ([One resource per item](#one-resource-per-item)).
- Or give each writer a document of its own.
- Or keep one writer per document, or put a queue in front of it.
- Or collect one writer's changes into batch steps ([Batches](#batches)).
- **Where one writer does need more than 10 writes a second on a small document**, raise the
  deployment maximum (`serve -max-rate-per-resource`) and set `ratePerResource` in that
  namespace's `limits`. Leave it at the default where documents are large: a typed 1 MiB
  document already costs ~60 ms of CPU an append
  ([above](#large-documents-by-shape-and-schema)).
- **Clients that do share a document** should retry with `AppendLatest` or its like, not at once.

The runs in this section are from [host B](#host-b-2026-11-12-spec-082). The tables under
[Writes to one document](#writes-to-one-document) are 15-second runs of 2026-11-12. The tables
under [One resource per item](#one-resource-per-item) and
[Fairness between writers](#fairness-between-writers) are 10-second runs of 2026-11-13, which
measured the shared document again beside the resource per item. That is why the shared
document's figures differ a little between them (588 and 600 writes a second for 8 writers on
SQLite, for instance): they are two runs, and they vary this much.

Terms used below:

- **Principal:** the identity a request's grant names. Here every writer is a principal of its
  own.
- **`412`:** the write was refused because the document's head had moved since the writer read
  it (the `If-Match` precondition failed). The writer lost a race and must retry.
- **`429`:** the write was refused by a rate limit.

### Writes to one document

**At the default limits a shared document takes about one writer's rate, however many writers
share it. With the rate lifted, more writers make it slower than one writer, not faster.**

Same host and day as the large documents (2026-11-12), with a document of about 500 bytes. Each
writer is a principal of its own. It appends in a loop for 15 seconds without pausing, with
`If-Match` on the head it last saw, and shares nothing with the others.

Two ways of retrying were measured:

- **at once**: after a `412`, read the head again and retry. After a `429`, wait 100 ms.
- **backoff**: the client's `AppendLatest`. After a `412`, take the head from the refusal's body
  and wait a random time under a ceiling that doubles with each loss in a row (2 ms to 16 ms).
  After a `429`, wait its `Retry-After` and read the head again.

These writers never pause, which is the worst case. Writers with time between their writes
collide less in proportion.

#### At the default limits

The per-resource rate is the ceiling. §6.6 allows 10 writes a second (burst 20) per resource and
principal, and an allowance doesn't lift it.

| Writers | Retry | Appends/s (SQLite / Postgres) | Attempts `412` | Attempts `429` | Fewest and most appends by one writer (SQLite) |
|---|---|---|---|---|---|
| 1 | | 11 / 11 | 0 | 46% | |
| 8 | at once | 12 / 12 | 46% | 46% | 8 and 47 |
| 8 | backoff | 16 / 13 | 43% | 46% | 24 and 46 |
| 32 | at once | 14 / 14 | 51% | 46% | 0 and 40 |
| 32 | backoff | 28 / 19 | 49% | 46% | 4 and 36 |

- **The document takes about one writer's rate however many write it.** So 8 writers together do
  12 a second, and 32 do 14. Two things cause this:
  - Each principal has a bucket of its own, but a write refused with `412` has still drawn its
    tokens. (The buckets are drawn before the precondition is compared.)
  - A writer that waited for a token usually holds a stale head by then.
- **The backoff helps a little**: up to twice the appends at 32 writers, spread more evenly. But
  about half the attempts are still `412`s. The rate, not the retry policy, decides.

#### With the rate lifted

Here nothing is rate limited, and the core and the database set the pace. The settings:

- the core run with `serve -max-rate-per-resource 1e6,1e6 -max-rate-per-principal 1e6,1e6`;
- a namespace whose `limits` set both that high;
- `capacity -single-rate 1000000`.

| Writers | Retry | Appends/s (SQLite / Postgres) | Attempts `412` (SQLite / Postgres) | One write, retries included, p50 / p95 / p99 (SQLite) | Fewest and most appends by one writer (SQLite / Postgres) |
|---|---|---|---|---|---|
| 1 | | 1,130 / 295 | 0 | 0.7 / 1.1 / 9.7 ms | |
| 8 | at once | 600 / 175 | 84% / 86% | 1.7 / 72 / 128 ms | 1,025 and 1,244 / 231 and 447 |
| 8 | backoff | 1,000 / 284 | 44% / 70% | 0.8 / 1.4 / 227 ms | 1,517 and 2,299 / 0 and 1,591 |
| 32 | at once | 236 / 87 | 95% / 96% | 19 / 580 / 947 ms | 62 and 152 / 19 and 59 |
| 32 | backoff | 764 / 128 | 81% / 95% | 1.0 / 3.5 ms / 1.4 s | 105 and 630 / 0 and 175 |

- **One writer in a loop does about 1,100 appends a second on SQLite and 300 on Postgres** to a
  small document. On SQLite that is about a hundred times the default rate.
- **More writers make it slower, not faster.** Every append needs the head the last one made, so
  the writers queue behind one another whatever the server does. Retrying at once, 8 writers
  get half of what one does and 32 a fifth, with 84–96% of their requests wasted.
- **Backing off recovers most of the throughput.** On SQLite 8 writers do 1,000 a second with
  44% of attempts lost, and 32 do 764.
- **Backing off doesn't make the document fair.** The writer that just won holds the newest head
  and waits for nothing, so it tends to win again. On Postgres a write takes longer than the
  backoff's ceiling spreads the losers, and some writers got no append in at all in 15 seconds.
- **A longer ceiling loses fewer requests and is less fair still.** At 250 ms one of 8 writers
  did more than half the appends and another none.

What the retry policy can't change is that a lost race costs a whole request. The remedies are
structural, and are listed at the top of [Many writers](#many-writers).

### One resource per item

**When each writer creates resources of its own, nothing collides, every writer gets the same
share, and throughput grows with the number of writers.**

The same writers as above. Each now creates resources of its own in the namespace
(`If-None-Match: *`, a name the client chose, a 450-byte document) where before they appended to
one shared document. No experimental code. The rate is lifted as above. Each run is 10 seconds.

| Writers | Creates/s (SQLite / Postgres) | Attempts `412` | Fewest and most by one writer (Postgres) | One write p50 / p99 / max (Postgres) |
|---|---|---|---|---|
| 1 | 1,254 / 369 | 0 | | 2.6 / 4.2 / 36 ms |
| 8 | 2,121 / 1,074 | 0 | 1,340 and 1,345 | 7.2 / 13 / 33 ms |
| 32 | 2,200 / 1,930 | 0 | 599 and 608 | 16 / 31 / 49 ms |

- **Nothing collides.** Creates of different resources share no head, so there is no `412` to
  lose a request to, and every writer gets the same share. The worst write of 32 writers took
  49 ms, against seconds on the shared document.
- **It scales with writers.** On Postgres 32 writers do five times what one does. The reason is
  group commit (D.8): the core writes the resources of several requests in one transaction. On
  SQLite 32 writers do 1.8 times one writer's.
- **A repeat is safe as it is.** The same create sent again is §7.2's retry, answered with the
  first attempt's revision.
- **Each item is still checked and ordered.** Each item is validated on its own (`$schema`,
  rules, limits), and the namespace's log gives the items one order.
- **What is given up is the aggregate.** A constraint across items (a maximum count, uniqueness)
  isn't the server's to check. The list is read as the namespace's heads under a prefix, or from
  an index, not as one document.

### Fairness between writers

**A resource per item is fair without trying. On a shared document the retry policy trades
fairness for throughput, and with the backoff some writers get nothing.**

Whether every writer gets its share matters as much as the total: a document that takes 1,000
writes a second is of little use to the writer who gets none of them.

Fairness is measured as the writes the least-served and the most-served writer got in one run.
Every writer sends as fast as it can, so an even split is the fair outcome. These tables are
from the same run as the [One resource per item](#one-resource-per-item) table: the rate lifted,
10 seconds.

| 8 writers | Writes/s | Fewest and most by one writer | Most ÷ fewest | Worst write |
|---|---|---|---|---|
| SQLite, shared document, retry at once | 588 | 660 and 828 | 1.3 | 0.3 s |
| SQLite, shared document, backoff | 986 | 674 and 1,667 | 2.5 | 2.9 s |
| SQLite, a resource per item | 2,121 | 2,626 and 2,681 | 1.02 | 39 ms |
| Postgres, shared document, retry at once | 177 | 170 and 285 | 1.7 | 1.2 s |
| Postgres, shared document, backoff | 320 | 0 and 1,823 | one writer got nothing | 5.4 s |
| Postgres, a resource per item | 1,074 | 1,340 and 1,345 | 1.004 | 33 ms |

| 32 writers | Writes/s | Fewest and most by one writer | Most ÷ fewest | Worst write |
|---|---|---|---|---|
| SQLite, shared document, retry at once | 263 | 46 and 114 | 2.5 | 1.5 s |
| SQLite, shared document, backoff | 958 | 2 and 660 | 330 | 8.0 s |
| SQLite, a resource per item | 2,200 | 683 and 697 | 1.02 | 47 ms |
| Postgres, shared document, retry at once | 88 | 14 and 42 | 3 | 4.2 s |
| Postgres, shared document, backoff | 137 | 0 and 213 | some writers got nothing | 9.4 s |
| Postgres, a resource per item | 1,930 | 599 and 608 | 1.02 | 49 ms |

- **On a shared document the retry policy trades fairness for throughput.**
  - Retrying at once wastes most requests but spreads what gets through within a factor of 1.3
    to 3.
  - The backoff gets far more through, to fewer writers. Whoever just won holds the newest head
    and waits for nothing, while each loser waits longer after each loss.
  - In these runs one of 8 writers on Postgres made no write at all in 10 seconds, and on SQLite
    one of 32 made two.
- **A resource per item is fair without trying.** Nobody's write depends on anybody else's, so
  the shares differ by 2% at most and the worst write is under 50 ms.
- **At the default limits the shared document is unfair either way**, since a lost race has
  still spent a token. These figures are from the earlier 15-second run
  ([At the default limits](#at-the-default-limits)), on SQLite:
  - 8 writers retrying at once: 8 and 47 writes by the least and the most served. With the
    backoff: 24 and 46.
  - 32 writers retrying at once: 0 and 40. With the backoff: 4 and 36.

**What these runs don't show:**

- Every writer here asks for as much as it can get. Nothing in the write path shares turns
  between writers. A resource per item and the namespace's log serve requests as they arrive,
  so a writer that sends twice as often gets twice the writes.
- What caps a greedy writer is its own rate (`ratePerPrincipal`, 50 a second by default) and the
  namespace's (`ratePerNamespace`). This run lifted both, and the per-resource rate with them.
- Writers that pause between writes collide less on a shared document, so its unfairness shrinks
  with load. These runs are the worst case.

### Batches

**A batch writes many steps to one document at once** (§7.5: one item, many steps, one token).
This is the way for one writer to make many changes to one document.

| One item of | SQLite | Postgres |
|---|---|---|
| 100 steps | 4–5 ms | 18 ms (152 ms as the first batch on a cold connection) |
| 1,000 steps | 36–44 ms (23,000–28,000 steps/s) | 146–205 ms (4,900–6,800 steps/s) |

### Long histories

**A long history doesn't slow a document down.** One document was grown to 100,000 revisions:

| Revisions | Append p50 (SQLite / Postgres) | Head read | Document at head | Document at its first revision |
|---|---|---|---|---|
| 1,000 | 0.9 / 3.3 ms | 0.2 ms | 0.2–0.3 ms | 0.2 ms |
| 10,000 | 1.1 / 4.4 ms | 0.2 ms | 0.2 ms | 0.2 ms |
| 100,000 | 1.4 / 4.1 ms | 0.2 ms | 0.2–0.4 ms | 0.2 ms |

The reads were made right after the writes, from warm caches, 20 samples each. They show that
nothing scans the history. They do not show what a cold read of an old revision costs; the
"cold reads of old revisions" row of [the envelope](#the-envelope) does.

### A prototype that was set aside

**An experimental alternative was built, measured and set aside. It is not in this code.**

The prototype is on branch `capacity-schema-single`. docs/SPEC-FEEDBACK.md, v0.82 Open 91, has
the rules and what it left open. It let the server:

- apply a stale append to the current head when nothing written since overlapped it;
- write the waiting appends of a document in one transaction;
- recognise repeats by a producer key.

What it showed on the shared document:

- **It removed the `412`s and shared the document evenly.** 3,440 and 3,670 appends a second
  from 8 and 32 writers on SQLite, 917 and 1,334 on Postgres. That is more than a resource per
  item on SQLite and less on Postgres.
- **It was fair**, as long as the document's writes went to one instance: 417 and 418 appends by
  the least and the most served of 32 writers on Postgres. Spread over two instances: 23 and 546.
- **Throughput halved again** when a document's writers were spread over two instances.
- **It cost** about 900 lines in the write path, a table and a change to §7.2's contract.

A resource per item needs none of that, so the prototype is not in this code.

## Limits, by kind

Each limit is one of three kinds:

- [By design](#by-design): the spec's model.
- [Gaps in this implementation](#gaps-in-this-implementation): fixable without changing the
  spec. Some are already [fixed in this branch](#fixed-in-this-branch).
- [Deployment](#deployment): hardware and configuration.

### By design

**One log per namespace.**

- *Limit:* every write appends to its namespace's hash chain (§3.5). So writes to one namespace
  commit one at a time. On Postgres they commit one group of up to 32 at a time.
- *Measured:* one namespace takes ~590 single writes/s on server X from 32 writers, and
  700–1,000/s on SQLite (4 vCPU).
- *Lever:* spread write-heavy data over namespaces. Writes to different namespaces run in
  parallel, across instances too. A sign-in storm writing per-user items belongs in many
  namespaces, not one.

**§6.6 size limits.**

- *Limit:*
  - documents: 1 MiB by default. A namespace may set 4 MiB, the deployment maximum. (§6.6 says
    4 MiB.)
  - patch sets: 256 KiB, and 1,000 ops a set;
  - batches: 1,000 items and 16 MiB;
  - log pages: 1,000 entries.
  - The other deployment maximums equal the defaults.
- *Lever:* `serve -max-document-size` raises the document maximum. Large documents are slow to
  write (next limit). Batches are imports, not interactive writes.

**Whole-document work on every write.**

- *Limit:* the result of a write is canonicalised, checked against the limits and validated
  against its `$schema` in full. A small patch to a large document costs the document's size.
- *Measured:* append p50 is 7 ms at 16 KiB, 15 ms at 1 MiB and 25 ms at 3.5 MiB on server X, and
  1.7 / 7 / 19 ms on SQLite. Those are documents of long strings without a `$schema`. Many small
  values cost 3–5× more, and a schema that types them about 3× more again
  ([Large documents, by shape and schema](#large-documents-by-shape-and-schema)).
- *Lever:* keep frequently edited documents small. Split large aggregates into resources. Keep a
  frequently edited typed document well under 100 KiB if its appends should stay under 10 ms.

**Default rates** (§6.6).

- *Limit:*
  - 50 items/s a principal (burst 100);
  - 500 items/s a namespace (burst 1,000);
  - 10/s a resource (burst 20).
  - Since v0.73 the instances of a Postgres deployment share the buckets (`rate_buckets`, about
    +1.2 ms a write). They are per instance only with `serve -local-rate-buckets`.
- *Measured:* 500/s a namespace is ~85% of server X's single-namespace ceiling.
- *Lever:* allowances (§6.6) replace a principal's and its namespace's buckets, for loaders and
  importers. The per-resource rate always applies.

**Followers are cheapest through the CDN** (§7.7, §9).

- *Limit:* through the CDN, followers cost the origin nothing per follower. At the origin they
  cost a connection each and a shared read per write. SSE streams (§7.3) are collapsed neither
  at the CDN nor at the origin.
- *Measured:* see the table under [Long-poll followers and the CDN](#measured).
- *Lever:* devices long-poll. Services that need every entry use the log and checkpoints (§10).

**Consumers read over HTTP.**

- *Limit:* a consumer catches up from the log and fetches each changed document (§10).
- *Measured:* catch-up of 4M entries takes 2.4 min. Bootstrap of 1M documents takes ~11 min on
  server X.
- *Lever:* consumer throughput is the consumer's (see the gaps below). The origin side scales
  with instances.

### Gaps in this implementation

| Gap | Effect | Fix |
|---|---|---|
| **No edge that verifies edge grants** is included. | Private long-polls don't collapse at the CDN: every follower is an origin connection and request. The origin shares their reads ([Origin-side collapse](#origin-side-collapse)), at ~0.1–0.2 ms of core CPU per follower per write. | An edge (Varnish VMOD, Fastly or Cloudflare worker) with `edge.Cookies.Check`'s checks; the origin already issues the cookies. |
| **No read replicas, and one `-db` for everything.** The core runs migrations, the tailer and leader jobs, so it can't run on a read-only database. | Consumers' scans and private reads load the primary. | Route bulk reads (catch-up, bootstrap, export) and private reads to a replica, with misses of new revisions falling back to the primary; decisions stay on the primary. |
| **Consumers** (index, tree): one SQLite writer per process, 8 document fetches at a time (the tree service: one), no sharding but by namespace lists. | Bootstrap of 1M documents: ~11 min on server X (fetches at 1,600/s); 2.6 min on SQLite. | More fetch concurrency, pipelining pages; split namespaces over processes. |
| **A namespace purge is one transaction.** | Long lock and transaction for large namespaces. | Purge in chunks. |
| **No profiling endpoint; the core sets no memory limit.** | Peak RSS 1.5–1.8 GB on the instance that served the full scans of the large namespace (steady 0.5–0.8 GB); the second instance, which didn't, peaked at 0.2 GB. | Run with `GOMEMLIMIT` under container limits; profile the scans (an opt-in pprof listener would help). |

### Fixed in this branch

These were limits and are not any more:

- **Namespace log pages** bounded entries but not items, so a page of 1,000 batch entries of
  1,000 items held a million. Now a page holds at most the page size in resource entries too, a
  batch counting as its items.
- **The bearer grant cache** held 1,024 grants and emptied itself when full. So a fleet of 5,000
  devices with grants of their own verified on nearly every request. Now it holds 65,536, least
  recently used out first. The warm fleet's reads went from 1,490/s, p50 4.9 ms, to
  1,710–1,770/s, p50 3.2–4.4 ms on server X, where Postgres rather than verification is the
  bottleneck.
- **The document cache** was bounded by count: 4,096 documents, which is up to 16 GiB of 4 MiB
  ones. Now it is bounded at 256 MiB.
- **The read cache** emptied itself when full. Now it evicts a quarter.
- **Rate-limit buckets**, one per (namespace, resource, principal) written, were never dropped.
  Now they are swept once full again, which is the same as new.
- **Compiled schemas and their documents** were kept forever. Now the 512 and 2,048 most
  recently used are kept.
- **Long-polls of a namespace** each read the log on their own when woken. Now the read is
  shared ([Origin-side collapse](#origin-side-collapse)).
- **Namespace log pages** scanned and sorted the whole namespace, and the config-retry lookup
  scanned the whole log. Now both are indexed (CHANGELOG, Unreleased).
- **A consumer's snapshot bootstrap** held the whole `/heads` listing in memory and one
  transaction. Now it is paged and resumable.

### Deployment

| Resource | Measured | Notes |
|---|---|---|
| **Core CPU** | Grant checks, canonicalisation, validation, folds and page serialisation are core CPU. On server X a 1-vCPU core kept up with everything measured. | Scales with instances once it is the limit (it wasn't on server X). |
| **Postgres round trips** | A single write is ~13 statements; on server X one writer did 125 writes/s (7.5 ms each), neither container saturated. | Keep the core near Postgres (sub-millisecond); concurrency, not speed, is what instances add. |
| **Postgres CPU and memory** | ~1.3 of 2 vCPU and 3.4 of 4 GB under the read measurements; the limit on server X. | Size Postgres first; a read replica takes bulk reads and private followers' log reads (a gap, above). |
| **Storage** | 6.2 GB on Postgres, 3.1 GB on SQLite for 5M revisions of ~500-byte documents. | Linear in revisions; pruning (§8.6) bounds it. |
| **Memory** | Core: 0.5–0.8 GB steady, 1.5–1.8 GB peak during full scans. The caches are bounded: up to 256 MiB of documents, 64 MiB of read-cache revisions and 65,536 grants (a few hundred MB at most) by default. | Give containers `GOMEMLIMIT`, 2 GB+ for an instance that serves catch-ups; size the caches with `serve -doc-cache-size`, `-read-cache-size` and `-grant-cache`. |
| **Upgrades** | Schema migrations run in a transaction at start (README "Schema migrations"); one that builds an index on a large table blocks writes to it while the index builds. | Create the index `CONCURRENTLY` beforehand under the same name: migrations are written with `IF NOT EXISTS`, so they then find it. |

## Recommended settings

Changes to limits that these measurements recommend. Most are done.

| Setting | Status | Detail |
|---|---|---|
| **Bearer cache** | Done | 65,536 grants, at most 32 MiB of tokens, least recently used out first (`serve -grant-cache`). |
| **Document and read caches** | Done | 256 MiB and 64 MiB, evicting gradually (`serve -doc-cache-size`, `-read-cache-size`). |
| **`documentSize`** | Done | 1 MiB by default, 4 MiB a namespace may set (`serve -document-size`, `-max-document-size`). Appends at 3.5 MiB are 3–4× slower than at 16 KiB for documents of long strings on server X, and far more for typed documents of small values ([above](#large-documents-by-shape-and-schema)); every revision of a large document weighs on the caches. |
| **Per-resource and per-principal maximums** | Done | `serve -max-rate-per-resource` and `-max-rate-per-principal` let a namespace set its own above the defaults (10/s and 50/s), for small documents one writer writes often. The defaults stay. |
| **Log pages** | Recommended | Bound items or bytes as well as entries. |
| **The rates** | Keep | 500/s a namespace is just under one namespace's ceiling on server X. |
| **`itemsPerBatch`** | Keep | 1,000. Batches are for imports; give importers allowances. |
| **The snapshot cadence, the long-poll interval and the log page size** | Keep | |

## Rerunning

```sh
go build -o patchlog ./cmd/patchlog && go build -o capacity ./cmd/capacity
./patchlog serve -dev -addr :9080 -db cap.db -origin http://localhost:8080 -max-rate-per-namespace 1e9,1e9 &
./capacity -url http://127.0.0.1:9080 -pid $! -json result.json   # 1M docs, 5M revisions: about 1-1.5 h to seed
```

Why `-max-rate-per-namespace 1e9,1e9` is needed:

- The harness's namespaces give its loader an allowance of 1e9 writes a second and burst.
- An allowance's bucket never exceeds the deployment maximum of `ratePerNamespace` (§6.6), so
  the core needs `-max-rate-per-namespace` raised to it.
- Without it, creating the namespaces is `422` (`limit: "ratePerNamespace"`).

Options:

- **Grants**: run the core with `-operator-key <public>` (from `patchlog keygen`) and pass the
  private seed as `-operator-seed`. The namespaces are then private and every
  request carries a grant. Readers carry 5,000 distinct ones (`-readers`).
- **A CDN**: put Varnish with `deploy/varnish/default.vcl` (backends pointed at the core) in
  front, and pass its URL as `-live-url` for the long-poll measurement.
- **Several instances**: `-url` takes a comma-separated list. A namespace's writes go to one
  instance by a hash of its name, and reads and followers go to each in turn.
- **Measuring again without seeding**: once seeded,
  `-only scans,reads,writes,bootstrap,large,live` measures again without seeding, e.g. after
  resizing the core.
- **Large documents and one hot document**: `-only large,single` needs no seeding (it makes
  namespaces of its own) and takes about two minutes.
  - `-single-seconds` sets how long each single-document measurement runs.
  - `-single-rate N` runs them in a namespace that allows N writes a second per resource and
    principal. The core then needs `-max-rate-per-resource N,N -max-rate-per-principal N,N`.
  - `-only single` also measures the writers each creating resources of their own
    (`single_ns_items_writers_N`).
- **Sizes**: `-docs`, `-revs`, `-namespaces`, `-doc-size`, `-append-batch`. `-help` lists the
  rest.
