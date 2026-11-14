# Capacity

What one deployment of this implementation handles, measured. For each limit it found, this
document says whether the limit is **by design** (the spec's model; changing it means changing
how data is laid out), a **gap** (this implementation; fixable without changing the spec) or
**deployment** (hardware and configuration; buy or tune your way past it).

Every figure here is from one set of runs on one host on 2026-11-13, at spec 0.82, except those
under [Earlier measurements](#earlier-measurements) and
[A recursive union schema](#a-recursive-union-schema), and the dated notes. See
[What was measured, and on what](#what-was-measured-and-on-what).

## At a glance

- **A small server handles about 2,500–3,600 reads a second and about 1,000 single writes a
  second into one namespace** (from 32 writers). The server is "server X": a 2 vCPU / 4 GB core
  and a 2 vCPU / 4 GB Postgres. See [The envelope](#the-envelope).
- **Data size doesn't slow requests.** A namespace of 1,000,000 documents and 5,000,000
  revisions answers like a small one. Size costs storage, full scans and memory. See
  [What data size costs](#what-data-size-costs).
- **The core isn't what limits server X.** Halving it made nothing slower. See [What limits server X](#what-limits-server-x).
- **Followers are cheapest through the CDN.** 5,000 followers of a public namespace cost the
  origin no measurable CPU a write. Followers that reach the origin cost about 0.03–0.04 ms of
  core CPU each per write. See [Long-poll followers and the CDN](#long-poll-followers-and-the-cdn).
- **Large documents of many small values are slow to write**: about 24 ms an append at the
  1 MiB default and 70 ms at 3.5 MiB, with or without a schema. Keep a frequently edited one
  under about 250 KiB. See
  [Large documents, by shape and schema](#large-documents-by-shape-and-schema).
- **One document takes about 10 writes a second in all by default**, however many writers share
  it, and the writers collide: 8 writers together got 12 a second, 32 got 12–16 (up to 70 with a
  backoff). See
  [Writes to one document](#writes-to-one-document).
- **Make each list entry a resource of its own**: 620–1,420 writes a second from 32 writers on
  server X, where the shared document did 64. Nothing collides. See
  [One resource per item](#one-resource-per-item).
- **A shared document is not fair between writers.** With a backoff some writers got no write in
  at all. With a resource per item the shares differ by 3% at most. See
  [Fairness between writers](#fairness-between-writers).
- **One writer with many changes should batch them**: 1,000 steps to one document take 70–74 ms
  on SQLite and 150–220 ms on server X. See [Batches](#batches).
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
- [Earlier measurements](#earlier-measurements)
- [Rerunning](#rerunning)

## What was measured, and on what

The numbers come from `cmd/capacity` (see [Rerunning](#rerunning)). They are taken over HTTP,
so they include the HTTP stack. The raw results are in [`capacity/`](capacity/).

**One host, one day, one version.** Everything was run on 2026-11-13 at spec 0.82 on one
4-vCPU / 15 GB host. Two databases were measured on it:

- **Server X** (the "Postgres" or "server X" figures):
  - the core in a container limited to **2 vCPU / 4 GB**;
  - Postgres 16 in a container limited to **2 vCPU / 4 GB** (`max_connections=300`, otherwise
    default settings);
  - **grants on**: the namespaces are private (`read: grant`), and every request carries a
    signed grant. Rows that say "authentication off" ran the same core with `-dev`.
- **SQLite** (the "SQLite" figures): the core with `-dev` and a SQLite file, in a container
  with **no limit**, so it had the host's 4 vCPU. Its namespaces are public.

So the two columns differ in more than the database: SQLite also had twice the CPU and no grant
checks. Read the SQLite column as "one unconstrained instance on local disk", not as a
like-for-like comparison of databases.

**The data.** 1,000 small namespaces (10 documents each) and one large namespace of
**1,000,000 documents** and **5,000,000 revisions**. The large namespace was made by 1M creates
(in 1,000-item batches) and 4M single appends of a small patch. Its documents are about 500
bytes. Seeding took 45 minutes on server X and 39 on SQLite. On disk it is 6.8 GB in Postgres
and 3.7 GB in SQLite.

**What makes the numbers conservative, and what makes them vary:**

- The load generator ran on the same host, and so did Varnish. With the two server X containers
  that is more work than the host has CPUs for, so the server X figures are a floor.
- Requests went straight to the containers' addresses, not through a published port.
- The measurements were taken twice on server X, about 25 minutes apart on the same data. Where the two
  differ, both are given as a range. Most agree within 10–15%; writes spread over many
  namespaces and creates from 32 writers varied more.

## The envelope

At the data size above, the two setups answer as follows. These are origin numbers, before any
CDN. Reads come from 8 concurrent clients.

| Operation | Server X (Postgres, grants) | SQLite (4 vCPU, no grants) |
|---|---|---|
| Reads of a document, the grant not cached | 2,540–2,860/s, p50 2.6–2.8 ms, p99 6–8 ms | 13,300/s, p50 0.5 ms, p99 2 ms |
| Reads of a document, the grant cached | 3,200–3,650/s, p50 2.0 ms, p99 6–8 ms | — |
| Reads of a head pointer | 4,300–6,200/s, p50 1.2–1.7 ms | 16,600/s, p50 0.4 ms |
| Cold reads of old revisions (folds) | 970–1,170/s, p50 6–7 ms | 3,560/s, p50 2.1 ms |
| Single writes to one namespace, 1 writer | 200–240/s, p50 4 ms | 910/s, p50 0.8 ms |
| Single writes to one namespace, 8 writers | 550–710/s, p50 10–14 ms | 1,440/s, p50 3.3 ms |
| Single writes to one namespace, 32 writers | **930–1,000/s**, p50 26–33 ms, p99 55–97 ms | **1,500/s**, p50 25 ms, p99 35 ms |
| Single writes spread over 1,000 namespaces, 32 writers | 610–920/s, p50 30–44 ms, p99 97–150 ms | 1,570/s, p50 22 ms, p99 40 ms |
| A batch of 1,000 appends | 0.56–0.63 s | 0.38 s |
| Appends to a large document | p50 4 ms at 16 KiB, 7 ms at 1 MiB, 16 ms at 3.5 MiB | 1.1 / 5.6 / 13 ms |
| A page of 1,000 log entries, at a random place | 175–200/s, p50 39–46 ms | 360/s, p50 17 ms |
| A consumer's full catch-up of the large namespace | log: 4M entries in 1.7 min; `/heads`: 1M in 18 s; fetching 1M documents 8 at a time: 6–7 min | log: 32 s; `/heads`: 14 s; documents: 1.3 min |
| Long-poll followers | see [Long-poll followers and the CDN](#long-poll-followers-and-the-cdn) | |

The large-document row is for documents of long strings without a `$schema`. Other shapes cost
more: see [Large documents, by shape and schema](#large-documents-by-shape-and-schema).

**Right after a restart the first minutes are slower.** One pass was taken minutes after
Postgres had been restarted, before its cache had filled: the first read measurement did
260 reads a second with a p99 of 0.57 s, and writes from 32 writers 440 a second. The
measurements later in that same pass were back to the figures above. That pass is kept as
`pg-grants-serverX-cold-start.json` and is not otherwise used here, except where a range says
"three runs".

### What data size costs

**None of the per-request numbers above depends on the namespace's size.** Pages and reads use
indexes (see the fixes under Unreleased in the CHANGELOG). So a namespace of 1M documents and
5M revisions answers like a small one.

What does grow with size:

- **Storage:** about 1.4 KB a revision on Postgres and 750 B on SQLite, for these small
  documents.
- **Full scans:** catch-up, bootstrap and bundle export.
- **Memory:** see [Deployment](#deployment).

## What limits server X

**The core isn't server X's bottleneck.**

The same data was measured again with different cores. Grants are on unless noted. Reads come
from 8 concurrent clients. Writes go to the large namespace from 32 writers.

| Core | Reads, grant not cached | Reads, grant cached | Writes, one namespace | Writes, 1,000 namespaces | Bootstrap fetches |
|---|---|---|---|---|---|
| 2 vCPU, authentication off | 3,640/s, p50 1.5 ms | — | 910/s, p50 33 ms | 740/s | 2,840/s |
| 2 vCPU (two runs) | 2,540–2,860/s, p50 2.6–2.8 ms | 3,200–3,650/s, p50 2.0 ms | 930–1,000/s, p50 26–33 ms | 610–920/s | 2,430–2,830/s |
| 1 vCPU | 2,470/s, p50 2.4 ms | 3,340/s, p50 1.9 ms | 1,220/s, p50 25 ms | 660/s | 3,830/s |
| 2 × 1 vCPU, writes routed by namespace | 2,570/s, p50 2.6 ms | 3,010/s, p50 2.3 ms | 860/s, p50 29 ms | 660/s | 2,700/s |

What the table shows:

- **Halving the core made nothing slower, and a second instance adds nothing.** So the core's
  CPU is not what sets these numbers.
- **The 1-vCPU core was faster at writes and bootstrap fetches** (1,220 against 930–1,000, and
  3,830 against 2,430–2,830). A smaller core leaves more of the shared 4-vCPU host to Postgres
  and the load generator. That points at the rest of the host, not the core, as the limit in
  this test.
- **These runs do not show that Postgres is the limit.** Its CPU was not recorded. The earlier
  measurements did record it (about 1.3 of its 2 vCPU under the read measurements), and that is
  why the advice has been to size Postgres first.
- **More core instances pay off once the core's own CPU is the limit.** That happens with grant
  checks at fleet scale, with large documents, and with followers that reach the origin.
- **Grants cost 20–30% of read throughput when the grant isn't cached** (2,540–2,860/s against
  3,640/s without authentication). Most of that is verification. With grants in the core's
  bearer cache, reads are within about 10% of unauthenticated ones.
- **Write throughput into one namespace doesn't depend on the core's size here.** The
  namespace's log (one append at a time, grouped) and Postgres set it.

Postgres's container held 3.3 of its 4 GB when the runs ended.

## Long-poll followers and the CDN

**Followers of a public namespace cost the origin almost nothing behind the CDN. Followers that
reach the origin (those of a private namespace, or any without a CDN) each cost an origin
connection, and about 0.03–0.04 ms of core CPU per write.**

### Public namespaces: the CDN collapses followers

Many followers (devices, not consumer services) are meant to long-poll (§7.7) through the CDN.
It works like this:

- Every follower of a namespace asks for the same URL: `since` the head, with the same interval
  `cursor`.
- The CDN collapses identical misses into one origin request.
- The answer is cached for the interval.

The origin's cost is then one request per namespace, interval and CDN node, whatever the number
of followers.

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

### Measured

Each cell is the time until every follower had the write, and the core's CPU time for it
(CPU-s). The CDN is the repository's Varnish configuration (`deploy/varnish/default.vcl`) in a
container on the same host. Server X, except where SQLite is named.

| Followers of one namespace | public, via the CDN | straight to the origin (public or private) | private, via Varnish (not collapsed there) |
|---|---|---|---|
| 100 | 9–18 ms, ~0 CPU-s (SQLite: 5 ms) | 15–21 ms, 0.01 CPU-s | 22–27 ms, 0.01 CPU-s |
| 1,000 | 44–48 ms, ~0 CPU-s (SQLite: 48 ms) | 24–31 ms, 0.03–0.04 CPU-s | 0.11–0.13 s, 0.05 CPU-s |
| 5,000 | **0.18–0.28 s, ~0 CPU-s** (SQLite: 0.21 s, 0.02 CPU-s) | **0.09–0.14 s, 0.16–0.18 CPU-s** | 1.5–1.6 s, 0.6–0.7 CPU-s |

- **Via the CDN:** two runs on server X with authentication off and a public namespace, and one
  on SQLite.
- **Straight to the origin:** a private namespace with grants, a public one without, and SQLite.
  They agree at 5,000 followers, so they share a column. (At 100 and 1,000 SQLite was faster:
  4 ms and 21 ms.)
- The public namespaces of the first two columns were made in a new, empty database, not the
  seeded one.
- **Private, via Varnish:** two runs with grants.

What the table shows:

- **Through the CDN, followers of a public namespace cost the origin nothing that the
  measurement can see.**
- **At the origin, a write costs about 0.03–0.04 ms of core CPU per follower** (0.17 CPU-s for
  5,000), and all 5,000 have it in about 0.1 s.
- **Through Varnish, private followers take longer and cost the core more** (0.12–0.14 ms each).
  Varnish passes 5,000 private connections one by one, on the same host. It adds nothing for
  private followers until an edge verifies their grants.

The repository's VCL does not queue a long-poll with credentials behind an identical one in
flight (`hash_ignore_busy`).

### Planning rule

For followers that reach the origin:

- **Straight to the core**, plan for `followers × writes/s` up to ~25,000/s on server X. That is
  half of what the CPU figure above allows a 2-vCPU core that does nothing else, and it is
  extrapolated from single writes to an idle core.
- **Through Varnish without a verifying edge**, plan for a quarter of that, and for delivery to
  take over a second at 5,000 followers: each follower costs the core 0.12–0.14 ms a write
  there.
- Every follower is a connection the origin holds open. (A CDN in front holds them instead when
  it verifies edge grants.)

## Large documents, by shape and schema

**Every write works on the whole document, so a small patch to a large document costs the
document's size. The shape matters more than the bytes: many small values cost 3–4× a document
of long strings. A schema that types them adds little: nothing measurable for a patch to one
member, and about a quarter when the patch changes a large array.** Keep a frequently edited
document of many small values under about 250 KiB if its appends should stay near 10 ms.

This section was measured again on 2026-11-14, on the same host and containers as the rest,
after the server got its own schema validator (`internal/jsv`). Each figure is the median of 60
appends, one after another, to one document.

Three documents were measured at each size:

- **strings**: `{ n, items }` with `items` an array of 1,000-character strings, no `$schema`.
  This is the shape the envelope's row used.
- **structured**: `{ n, items }` with `items` an array of objects of about 110 bytes
  (`{ id, name, score, tags: [..], at, ok }`), no `$schema`. That is about 9,500 objects a MiB.
- **schema**: the structured document with `$schema` pinned to a schema revision in the same
  namespace. The schema types every member: `type` and `required` throughout, closed item
  objects (`additionalProperties: false`), a `pattern` on `name`, `minimum`/`maximum`,
  `maxItems` and `maxLength`, and `format: date-time` on `at`.

And three patches to the schema document:

- **one member**: `[{"op":"replace","path":"/n","value":i}]`, as for the other two documents.
  The server validates a patch where it changes the document, so this checks `/n` alone.
- **the array**: an item added at the end of `items` and one removed at its start. The array
  itself changed, so all of it is validated again.
- **in full**: the one-member patch with the core run with `-full-validation`, which validates
  the whole document on every write.

| Append p50 | 16 KiB | 256 KiB | 1 MiB | 3.5 MiB |
|---|---|---|---|---|
| SQLite, strings | 1.3 ms | 2.0 ms | 5.3 ms | 13 ms |
| SQLite, structured | 1.6 ms | 6.1 ms | 21 ms | 66 ms |
| SQLite, schema, one member | 1.7 ms | 6.1 ms | 20 ms | 69 ms |
| SQLite, schema, the array | 1.8 ms | 8.3 ms | 24 ms | 81 ms |
| SQLite, schema, in full | 1.8 ms | 7.8 ms | 27 ms | 82 ms |
| Server X, strings | 5.1 ms | 6.1 ms | 8.8 ms | 16 ms |
| Server X, structured | 5.0 ms | 11 ms | 24 ms | 69 ms |
| Server X, schema, one member | 6.0 ms | 10 ms | 24 ms | 70 ms |
| Server X, schema, the array | 5.5 ms | 13 ms | 31 ms | 90 ms |
| Server X, schema, in full | 5.6 ms | 12 ms | 29 ms | 88 ms |

What the table shows:

- **The shape matters more than the bytes.** The same bytes as many small values cost 3–4× a
  document of long strings at 1 MiB and above. Parsing, applying and canonicalising all work
  per value.
- **A patch to one member of a typed document costs what it does without a schema.** Only what
  the patch changed is validated, and the constraints of the objects and arrays above it.
- **Validating in full adds about a quarter**: 5–6 ms a MiB of small typed objects on top of
  about 20 ms a MiB without a schema. That is what a patch that changes the large array pays,
  and what every append pays under `-full-validation`.
- **The database adds a constant** (3–4 ms on server X). The rest is the core's CPU, which is
  why the two agree at the large sizes even though one core has half the CPU: an append uses one
  thread.
- **Creating the document costs four to five appends, typed or not**: 100–130 ms at 1 MiB and
  340–420 ms at 3.5 MiB with the schema, against 100–190 ms and 280–350 ms without.
- **What is left is the work every write does on the whole document**: parsing the stored head
  (about 35–40% of an append in a profile) and serialising and measuring the result (about
  40%).

**Before the server had its own validator** (the runs of 2026-11-13, with a third-party
library and the whole document validated on every write), the one-member append to the schema
document took 19 / 55 / 187 ms at 256 KiB / 1 MiB / 3.5 MiB on server X, and 14 / 52 / 172 ms
on SQLite. Those results are `pg-grants-serverX.json` and `sqlite-public-4vcpu.json`; the new
ones are the `*-large-change.json` and `*-large-full.json` files.

### A recursive union schema

**A schema whose `oneOf` branches each recurse no longer costs exponential time, and validation
work is bounded.** The third-party validator the server used until 2026-11-14 checked every branch in
full, children included, even where the branch's discriminator had already failed, so a node at
depth *d* was validated once per branch per level above it. The server now validates with its
own validator (`internal/jsv`), which stops a branch at its first failure and checks a value's
own keywords and scalar members before its objects and arrays.

Measured on 2026-11-14 on a development machine, in the validator alone, not through the
server: a binary tree whose nodes are one of 4 kinds, against a `oneOf` of 4 node schemas, each
with `children`.

| | Before | Now |
|---|---|---|
| Tree of depth 10 (1,023 nodes) | 4.2 s (7.3 s when first measured, on another machine) | 0.39 ms, 14,833 steps |
| The 1 MiB **schema** document of [the section above](#large-documents-by-shape-and-schema) (9,500 typed objects) | 43 ms | 4.2 ms, 85,503 steps |

- **Validation is bounded by steps**, a step being one schema applied to one value: 5,000,000
  for a document unless `serve -max-validation-steps` says otherwise. A write that needs more is
  refused `422`, `limit: "validationSteps"`. The `core.schema.validate` span carries the count
  (README, "Telemetry").
- Keeping the recursion out of the union (declaring `children` once on the node schema, with
  only the discriminator and each kind's own members in the branches) is still the cheaper
  schema, but no longer needed to stay out of trouble.


## Many writers

**A document that many parties write often (a shared list, a feed, a presence record) is the
wrong shape.** At the default limits it takes 11–16 writes a second in all when the writers
retry at once, and 13–70 with a backoff. At any limits,
several writers waste most of their attempts.

What to do instead:

- **Make each item a resource of its own** ([One resource per item](#one-resource-per-item)).
- Or give each writer a document of its own.
- Or keep one writer per document, or put a queue in front of it.
- Or collect one writer's changes into batch steps ([Batches](#batches)).
- **Where one writer does need more than 10 writes a second on a small document**, raise the
  deployment maximum (`serve -max-rate-per-resource`) and set `ratePerResource` in that
  namespace's `limits`. Leave it at the default where documents are large: a 1 MiB
  document of small values already costs ~24 ms of CPU an append
  ([above](#large-documents-by-shape-and-schema)).
- **Clients that do share a document** should retry with `AppendLatest` or its like, not at once.

Every run in this section lasts 15 seconds, on a document (or items) of about 500 bytes.

Terms used below:

- **Principal:** the identity a request's grant names. Here every writer is a principal of its
  own.
- **`412`:** the write was refused because the document's head had moved since the writer read
  it (the `If-Match` precondition failed). The writer lost a race and must retry.
- **`429`:** the write was refused by a rate limit.

### Writes to one document

**At the default limits a shared document takes about one writer's rate, however many writers
share it. With the rate lifted, more writers make it slower than one writer, not faster.**

Each writer is a principal of its own. It appends in a loop without pausing, with `If-Match` on
the head it last saw, and shares nothing with the others.

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

| Writers | Retry | Appends/s (SQLite / server X) | Attempts `412` | Attempts `429` | Fewest and most appends by one writer (SQLite / server X) |
|---|---|---|---|---|---|
| 1 | | 11 / 11 | 0 | 46% | |
| 8 | at once | 12 / 12 | 47% | 45% | 10 and 30 / 0 and 71 |
| 8 | backoff | 16 / 13 | 45% | 47% | 24 and 38 / 8 and 46 |
| 32 | at once | 12 / 16 | 52% | 45% | 0 and 41 / 0 and 18 |
| 32 | backoff | 21 / 26–70 | 43–50% | 46% | 2 and 25 / 2 and 143 |

- **The document takes about one writer's rate however many write it.** So 8 writers together do
  12 a second, and 32 do 12–16. Two things cause this:
  - Each principal has a bucket of its own, but a write refused with `412` has still drawn its
    tokens. (The buckets are drawn before the precondition is compared.)
  - A writer that waited for a token usually holds a stale head by then.
- **The backoff helps, unevenly**: 8 writers gained little (13–16 a second), while 32 did 21 a
  second on SQLite and 26, 60 and 70 on server X in three runs. About half the attempts are
  still `412`s, and the least-served writer still got 2 writes in 15 seconds.

#### With the rate lifted

Here nothing is rate limited, and the core and the database set the pace. The settings:

- the core run with `serve -max-rate-per-resource 1e6,1e6 -max-rate-per-principal 1e6,1e6`;
- a namespace whose `limits` set both that high;
- `capacity -single-rate 1000000`.

| Writers | Retry | Appends/s (SQLite / server X) | Attempts `412` (SQLite / server X) | One write, retries included, p50 / p95 / p99 (SQLite) | Fewest and most appends by one writer (SQLite / server X) |
|---|---|---|---|---|---|
| 1 | | 1,150 / 330 | 0 | 0.7 / 1.0 / 10 ms | |
| 8 | at once | 526 / 155 | 85% / 87% | 2.0 / 82 / 153 ms | 908 and 1,073 / 181 and 463 |
| 8 | backoff | 1,029 / 281 | 44% / 70% | 0.8 / 1.4 / 175 ms | 1,349 and 2,699 / 0 and 2,674 |
| 32 | at once | 177 / 64 | 96% / 96% | 6.8 / 870 ms / 1.7 s | 46 and 119 / 14 and 45 |
| 32 | backoff | 752 / 84 | 82% / 96% | 1.0 / 3.3 ms / 1.2 s | 104 and 798 / 0 and 131 |

- **One writer in a loop does about 1,150 appends a second on SQLite and 330 on server X** to a
  small document. On SQLite that is about a hundred times the default rate.
- **More writers make it slower, not faster.** Every append needs the head the last one made, so
  the writers queue behind one another whatever the server does. Retrying at once, 8 writers
  get half of what one does and 32 a fifth or less, with 85–96% of their requests wasted.
- **Backing off recovers most of the throughput where a write is fast.** On SQLite 8 writers do
  1,030 a second with 44% of attempts lost, and 32 do 750. On server X, where a write takes
  3 ms, 8 writers get back to 280 and 32 only to 84.
- **Backing off doesn't make the document fair.** The writer that just won holds the newest head
  and waits for nothing, so it tends to win again. On server X a write takes longer than the
  backoff's ceiling spreads the losers, and some writers got no append in at all in 15 seconds.

What the retry policy can't change is that a lost race costs a whole request. The remedies are
structural, and are listed at the top of [Many writers](#many-writers).

### One resource per item

**When each writer creates resources of its own, nothing collides, every writer gets the same
share, and throughput grows with the number of writers.**

The same writers as above. Each now creates resources of its own in the namespace
(`If-None-Match: *`, a name the client chose, a 450-byte document) where before they appended to
one shared document. No experimental code. The rate is lifted as above.

| Writers | Creates/s (SQLite / server X) | Attempts `412` | Fewest and most by one writer (server X) | One write p50 / p99 / max (server X) |
|---|---|---|---|---|
| 1 | 1,120 / 300 | 0 | | 3.2 / 5.9 / 29 ms |
| 8 | 1,830 / 940 | 0 | 1,768 and 1,774 | 7.8 / 15 / 626 ms |
| 32 | 1,970 / 1,420 | 0 | 660 and 670 | 20 / 50 / 98 ms |

- **Nothing collides.** Creates of different resources share no head, so there is no `412` to
  lose a request to, and every writer gets the same share. The worst write of 32 writers took
  98 ms, against seconds on the shared document.
- **It scales with writers.** On server X 32 writers do almost five times what one does. The
  reason is group commit (D.8): the core writes the resources of several requests in one
  transaction. On SQLite 32 writers do 1.8 times one writer's.
- **It varies between runs on server X.** A second run, with authentication off, did 290, 740
  and 620 creates a second from 1, 8 and 32 writers. Even that is ten times the shared
  document's 64.
- **A repeat is safe as it is.** The same create sent again is §7.2's retry, answered with the
  first attempt's revision.
- **Each item is still checked and ordered.** Each item is validated on its own (`$schema`,
  rules, limits), and the namespace's log gives the items one order.
- **What is given up is the aggregate.** A constraint across items (a maximum count, uniqueness)
  isn't the server's to check. The list is read as the namespace's heads under a prefix, or from
  an index, not as one document.

**At the default limits the principal's and the namespace's rates cap it, not collisions.** One
writer did 56 creates a second (`ratePerPrincipal` is 50), 8 writers 440, and 32 writers
410–560 (`ratePerNamespace` is 500). Refusals are `429`s with a `Retry-After`, never `412`s.

### Fairness between writers

**A resource per item is fair without trying. On a shared document the retry policy trades
fairness for throughput, and with the backoff some writers get nothing.**

Whether every writer gets its share matters as much as the total: a document that takes 1,000
writes a second is of little use to the writer who gets none of them.

Fairness is measured as the writes the least-served and the most-served writer got in one run.
Every writer sends as fast as it can, so an even split is the fair outcome. These are the runs
of the two tables above (the rate lifted, 15 seconds), set side by side.

| 8 writers | Writes/s | Fewest and most by one writer | Most ÷ fewest | Worst write |
|---|---|---|---|---|
| SQLite, shared document, retry at once | 526 | 908 and 1,073 | 1.2 | 0.4 s |
| SQLite, shared document, backoff | 1,029 | 1,349 and 2,699 | 2.0 | 2.7 s |
| SQLite, a resource per item | 1,830 | 3,407 and 3,454 | 1.01 | 57 ms |
| Server X, shared document, retry at once | 155 | 181 and 463 | 2.6 | 3.6 s |
| Server X, shared document, backoff | 281 | 0 and 2,674 | one writer got nothing | 12.9 s |
| Server X, a resource per item | 940 | 1,768 and 1,774 | 1.003 | 0.6 s (p99 15 ms) |

| 32 writers | Writes/s | Fewest and most by one writer | Most ÷ fewest | Worst write |
|---|---|---|---|---|
| SQLite, shared document, retry at once | 177 | 46 and 119 | 2.6 | 2.9 s |
| SQLite, shared document, backoff | 752 | 104 and 798 | 7.7 | 9.5 s |
| SQLite, a resource per item | 1,970 | 911 and 938 | 1.03 | 45 ms |
| Server X, shared document, retry at once | 64 | 14 and 45 | 3.2 | 7.8 s |
| Server X, shared document, backoff | 84 | 0 and 131 | some writers got nothing | 12.0 s |
| Server X, a resource per item | 1,420 | 660 and 670 | 1.02 | 98 ms |

- **On a shared document the retry policy trades fairness for throughput.**
  - Retrying at once wastes most requests but spreads what gets through within a factor of 1.2
    to 3.2.
  - The backoff gets more through, to fewer writers. Whoever just won holds the newest head
    and waits for nothing, while each loser waits longer after each loss.
  - In these runs one of 8 writers on server X made no write at all in 15 seconds while another
    made 2,674.
- **A resource per item is fair without trying.** Nobody's write depends on anybody else's, so
  the shares differ by 3% at most.
- **At the default limits the shared document is unfair either way**, since a lost race has
  still spent a token. The last column of the table under
  [At the default limits](#at-the-default-limits) has the figures: retrying at once, one of 8
  writers on server X got nothing while another got 71.

**What these runs don't show:**

- Every writer here asks for as much as it can get. Nothing in the write path shares turns
  between writers. A resource per item and the namespace's log serve requests as they arrive,
  so a writer that sends twice as often gets twice the writes.
- What caps a greedy writer is its own rate (`ratePerPrincipal`, 50 a second by default) and the
  namespace's (`ratePerNamespace`). These runs lifted both, and the per-resource rate with them.
- Writers that pause between writes collide less on a shared document, so its unfairness shrinks
  with load. These runs are the worst case.

### Batches

**A batch writes many steps to one document at once** (§7.5: one item, many steps, one token).
This is the way for one writer to make many changes to one document.

| One item of | SQLite | Server X |
|---|---|---|
| 100 steps | 5 ms | 20–28 ms |
| 1,000 steps | 70–74 ms (13,600–14,400 steps/s) | 150–220 ms (4,600–6,700 steps/s) |

Four runs on server X and two on SQLite. As the first batch after a restart, 100 steps took
115 ms on server X.

### Long histories

**A long history doesn't slow a document down.** One document was grown to 100,000 revisions:

| Revisions | Append p50 (SQLite / server X) | Head read, document at head, document at its first revision (SQLite / server X) |
|---|---|---|
| 1,000 | 0.7–0.8 / 3.0–7.6 ms | 0.15–0.19 / 0.46–0.60 ms |
| 10,000 | 0.7–1.5 / 2.9–7.8 ms | 0.15–0.23 / 0.42–0.61 ms |
| 100,000 | 0.6–1.1 / 3.2–3.8 ms | 0.13–0.20 / 0.48–0.54 ms |

The ranges are over two runs each. The reads were made right after the writes, from warm
caches, 20 samples each. They show that nothing scans the history. They do not show what a cold
read of an old revision costs; the "cold reads of old revisions" row of
[the envelope](#the-envelope) does.

### A prototype that was set aside

**An experimental alternative was built, measured and set aside. It is not in this code.**

The prototype is on branch `capacity-schema-single`. docs/SPEC-FEEDBACK.md, v0.82 Open 91, has
the rules and what it left open. It let the server:

- apply a stale append to the current head when nothing written since overlapped it;
- write the waiting appends of a document in one transaction;
- recognise repeats by a producer key.

It was measured on the same host and containers as everything else here, in a new, empty
database, each writer replacing a member of its own in the shared document. What it showed:

- **It removed the `412`s and shared the document evenly.** 3,270 and 3,450 appends a second
  from 8 and 32 writers on SQLite, 450 and 410 on server X. That is more than a resource per
  item on SQLite (1,830 and 1,970) and less on server X (940 and 1,420). On server X it did not
  grow from 8 writers to 32. (An earlier run with an unconstrained core and Postgres, without
  grants, did 917 and 1,334; that is the figure in the prototype's pull request.)
- **It was fair**: 192 and 193 appends by the least and the most served of 32 writers on
  server X.
- **It needed a document's writes to go to one instance.** An earlier measurement on another
  setup (in the prototype's pull request) had throughput halve and the shares come apart when a
  document's writers were spread over two instances. That was not measured again here.
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
- *Measured:* one namespace takes 930–1,000 single writes/s on server X from 32 writers, and
  1,500/s on SQLite (4 vCPU).
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

- *Limit:* the head is parsed and the result of a write is canonicalised and checked against
  the limits in full; only validation against its `$schema` follows the patch. A small patch to
  a large document costs the document's size.
- *Measured:* append p50 is 5 ms at 16 KiB, 9 ms at 1 MiB and 16 ms at 3.5 MiB on server X, and
  1.3 / 5.3 / 13 ms on SQLite. Those are documents of long strings. Many small values cost
  3–4× more, with or without a schema
  ([Large documents, by shape and schema](#large-documents-by-shape-and-schema)).
- *Lever:* keep frequently edited documents small. Split large aggregates into resources. Keep a
  frequently edited document of many small values under about 250 KiB if its appends should
  stay near 10 ms.

**Default rates** (§6.6).

- *Limit:*
  - 50 items/s a principal (burst 100);
  - 500 items/s a namespace (burst 1,000);
  - 10/s a resource (burst 20).
  - Since v0.73 the instances of a Postgres deployment share the buckets (`rate_buckets`, about
    +1.2 ms a write). They are per instance only with `serve -local-rate-buckets`.
- *Measured:* 500/s a namespace is about half of server X's single-namespace ceiling.
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
- *Measured:* catch-up of 4M entries takes 1.7 min. Bootstrap of 1M documents takes 6–7 min on
  server X.
- *Lever:* consumer throughput is the consumer's (see the gaps below). The origin side scales
  with instances.

### Gaps in this implementation

| Gap | Effect | Fix |
|---|---|---|
| **No edge that verifies edge grants** is included. | Private long-polls don't collapse at the CDN: every follower is an origin connection and request. The origin shares their reads ([Origin-side collapse](#origin-side-collapse)), at ~0.03–0.04 ms of core CPU per follower per write (0.12–0.14 ms through Varnish). | An edge (Varnish VMOD, Fastly or Cloudflare worker) with `edge.Cookies.Check`'s checks; the origin already issues the cookies. |
| **No read replicas, and one `-db` for everything.** The core runs migrations, the tailer and leader jobs, so it can't run on a read-only database. | Consumers' scans and private reads load the primary. | Route bulk reads (catch-up, bootstrap, export) and private reads to a replica, with misses of new revisions falling back to the primary; decisions stay on the primary. |
| **Consumers** (index, tree): one SQLite writer per process, 8 document fetches at a time (the tree service: one), no sharding but by namespace lists. | Bootstrap of 1M documents: 6–7 min on server X (fetches at 2,400–2,800/s); 1.3 min on SQLite. | More fetch concurrency, pipelining pages; split namespaces over processes. |
| **Rule `test`s with a `schema` and annotation walks are not counted** against `validationSteps`, and listing an invalid document's failures gets the budget anew. | A rule's schema fragment, or a schema's annotations, can still be made expensive to evaluate; an invalid document can cost twice the limit. | Count them against the same budget. |
| **A namespace purge is one transaction.** | Long lock and transaction for large namespaces. | Purge in chunks. |
| **No profiling endpoint; the core sets no memory limit.** | Peak RSS 1.0 GB on server X and 1.4 GB on SQLite over a whole run. Scans, reads and small writes alone peaked at 0.2–0.3 GB; the rest came with 3.5 MiB documents and 5,000 followers. | Run with `GOMEMLIMIT` under container limits; profile the large-document path (an opt-in pprof listener would help). |

### Fixed in this branch

These were limits and are not any more:

- **Namespace log pages** bounded entries but not items, so a page of 1,000 batch entries of
  1,000 items held a million. Now a page holds at most the page size in resource entries too, a
  batch counting as its items.
- **The bearer grant cache** held 1,024 grants and emptied itself when full. So a fleet of 5,000
  devices with grants of their own verified on nearly every request. Now it holds 65,536, least
  recently used out first. ([Earlier measurements](#earlier-measurements) has the before and
  after.)
- **The document cache** was bounded by count: 4,096 documents, which is up to 16 GiB of 4 MiB
  ones. Now it is bounded at 256 MiB.
- **The read cache** emptied itself when full. Now it evicts a quarter.
- **Rate-limit buckets**, one per (namespace, resource, principal) written, were never dropped.
  Now they are swept once full again, which is the same as new.
- **Nothing bounded schema validation time**, and the validator evaluated every `oneOf`/`anyOf`
  branch in full, so a recursive union schema took seconds on a document of a thousand nodes.
  Now validation stops a branch at its first failure and is bounded by steps
  ([A recursive union schema](#a-recursive-union-schema)).
- **Compiled schemas and their documents** were kept forever. Now the 512 and 2,048 most
  recently used are kept.
- **Long-polls of a namespace** each read the log on their own when woken. Now the read is
  shared ([Origin-side collapse](#origin-side-collapse);
  [Earlier measurements](#earlier-measurements) has the before and after).
- **Namespace log pages** scanned and sorted the whole namespace, and the config-retry lookup
  scanned the whole log. Now both are indexed (CHANGELOG, Unreleased).
- **A consumer's snapshot bootstrap** held the whole `/heads` listing in memory and one
  transaction. Now it is paged and resumable.

### Deployment

| Resource | Measured | Notes |
|---|---|---|
| **Core CPU** | Grant checks, canonicalisation, validation, folds and page serialisation are core CPU. On server X a 1-vCPU core kept up with the reads, writes and scans measured. | Scales with instances once it is the limit (it wasn't on server X). |
| **Postgres round trips** | A single write is ~13 statements; on server X one writer did 200–240 writes/s (about 4 ms each). | Keep the core near Postgres (sub-millisecond); concurrency, not speed, is what instances add. |
| **Postgres CPU and memory** | 3.3 of 4 GB at the end of the runs; CPU not recorded in them. In the earlier measurements it was the limit (~1.3 of 2 vCPU under reads), and here a smaller core was no slower. | Size Postgres first; a read replica takes bulk reads and private followers' log reads (a gap, above). |
| **Storage** | 6.8 GB on Postgres, 3.7 GB on SQLite for 5M revisions of ~500-byte documents. | Linear in revisions; pruning (§8.6) bounds it. |
| **Memory** | Core: 0.2–0.3 GB through scans, reads and small writes, 0.4–0.6 GB after a whole run, 1.0 GB peak (1.4 GB on SQLite) with 3.5 MiB documents and 5,000 followers. The caches are bounded: up to 256 MiB of documents, 64 MiB of read-cache revisions and 65,536 grants (a few hundred MB at most) by default. | Give containers `GOMEMLIMIT`, 2 GB+ for an instance that serves large documents or many followers; size the caches with `serve -doc-cache-size`, `-read-cache-size` and `-grant-cache`. |
| **Upgrades** | Schema migrations run in a transaction at start (README "Schema migrations"); one that builds an index on a large table blocks writes to it while the index builds. | Create the index `CONCURRENTLY` beforehand under the same name: migrations are written with `IF NOT EXISTS`, so they then find it. |

## Recommended settings

Changes to limits that these measurements recommend. Most are done.

| Setting | Status | Detail |
|---|---|---|
| **Bearer cache** | Done | 65,536 grants, at most 32 MiB of tokens, least recently used out first (`serve -grant-cache`). |
| **Document and read caches** | Done | 256 MiB and 64 MiB, evicting gradually (`serve -doc-cache-size`, `-read-cache-size`). |
| **`documentSize`** | Done | 1 MiB by default, 4 MiB a namespace may set (`serve -document-size`, `-max-document-size`). Appends at 3.5 MiB are 4× slower than at 16 KiB for documents of long strings on server X, and 14× for documents of many small values ([above](#large-documents-by-shape-and-schema)); every revision of a large document weighs on the caches. |
| **Per-resource and per-principal maximums** | Done | `serve -max-rate-per-resource` and `-max-rate-per-principal` let a namespace set its own above the defaults (10/s and 50/s), for small documents one writer writes often. The defaults stay. |
| **Log pages** | Recommended | Bound items or bytes as well as entries. |
| **The rates** | Keep | 500/s a namespace is about half of one namespace's ceiling on server X, which leaves room for reads. |
| **`itemsPerBatch`** | Keep | 1,000. Batches are for imports; give importers allowances. |
| **The snapshot cadence, the long-poll interval and the log page size** | Keep | |

## Earlier measurements

The first measurements were taken on 2026-10-15 at spec 0.52, on another host, with the same
data and the same container sizes. Their raw results are in
[`capacity/2026-10-15/`](capacity/2026-10-15/).

**Their absolute figures are not comparable with this document's.** They were about half of
today's (1,000–1,600 reads a second and 590 writes a second into one namespace). The host, the
network path (a published port then, container addresses now) and thirty spec versions all
differ, and nothing here separates their effects.

What they are still good for is before and after, since each pair was taken on that one host
on that one day:

- **Sharing the followers' read at the origin**: a write to 5,000 private followers went from
  3.7–4.1 s of core CPU and 3.1 s to deliver, to 0.3–1 s of CPU and 0.35–0.7 s. That is from
  about 1 ms of CPU per follower to 0.1–0.2 ms. (Today's 0.03–0.04 ms is on the faster host.)
- **The bearer grant cache**: a warm fleet of 5,000 readers went from 1,490 reads a second,
  p50 4.9 ms, to 1,710–1,770, p50 3.2–4.4 ms.
- **The CDN collapse, counted**: 1,100 followers of a public namespace made 4 origin requests.

## Rerunning

```sh
go build -o patchlog ./cmd/patchlog && go build -o capacity ./cmd/capacity
./patchlog serve -dev -addr :9080 -db cap.db -origin http://localhost:8080 -max-rate-per-namespace 1e9,1e9 &
./capacity -url http://127.0.0.1:9080 -pid $! -json result.json   # 1M docs, 5M revisions: about 40 min to seed
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
- **Server X**: run the core and Postgres in containers with `--cpus 2 --memory 4g` each
  (Postgres with `-c max_connections=300`), the core with `-operator-key`, and point `-url` at
  the core container's address. `-pid` takes the core's process id on the host
  (`docker inspect -f '{{.State.Pid}}'`), which is where the CPU and memory figures come from.
- **A public namespace's followers** need a namespace made without grants: run the core with
  `-dev` and give `-ns` a name not used before, since `-only live` reuses `<ns>-live` if it
  exists.
- **Sizes**: `-docs`, `-revs`, `-namespaces`, `-doc-size`, `-append-batch`. `-help` lists the
  rest.
