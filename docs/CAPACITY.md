# Capacity

What this implementation is known to handle, as of 2026-11-20: what was measured, on what, and
what limits it. Each limit is **by design** (the spec's model; changing it means changing how
data is laid out), a **gap** (this implementation; fixable without changing the spec) or
**deployment** (hardware and configuration; buy or tune your way past it).

Each section names the setup its figures come from:
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
- **Waiting devices cost the database nothing.** Each long-polling its own resource, 120,000
  devices on three `c7g.xlarge` cores and a 2-vCPU RDS were answered from memory, with
  delivery and database CPU the same as at 15,000. See [Resource followers](#resource-followers).
- **Namespaces share the database.** On an RDS `db.m7g.large` the writes of all namespaces
  together top out at about 1,600 a second, on a `db.m7g.2xlarge` at about 2,900. One namespace
  alone takes about 1,000, and a quiet namespace slows down with the busy ones once the
  database is near its limit. See
  [Several namespaces on one database](#several-namespaces-on-one-database).

## Contents

- [What was measured, and on what](#what-was-measured-and-on-what)
- [The envelope](#the-envelope)
- [What limits server X](#what-limits-server-x)
- [Long-poll followers and the CDN](#long-poll-followers-and-the-cdn)
  - [Resource followers](#resource-followers)
- [Large documents, by shape and schema](#large-documents-by-shape-and-schema)
- [Many writers](#many-writers)
  - [Writes to one document](#writes-to-one-document)
  - [One resource per item](#one-resource-per-item)
  - [Fairness between writers](#fairness-between-writers)
  - [Batches](#batches)
  - [Long histories](#long-histories)
  - [Several namespaces on one database](#several-namespaces-on-one-database)
- [Limits, by kind](#limits-by-kind)
- [Settings](#settings)
- [Rerunning](#rerunning)

## What was measured, and on what

The numbers come from `cmd/capacity`, `cmd/devicebench`, `deploy/ec2-devices.sh` and doors'
`apps/ouroboros/bench/aws/ec2-sources.sh` (see [Rerunning](#rerunning)). They are taken over
HTTP, so they include the HTTP stack. The raw results are in [`capacity/`](capacity/), whose
README says which run each file is.

Four setups were measured:

- **One 4-vCPU / 15 GB host** (2026-11-13 and 14, spec 0.82): server X and SQLite, below. All
  sections but the two on resource followers.
- **The same host without containers** (2026-11-19): `serve --dev` on SQLite or on a Postgres 16
  sharing the host, with resource followers ([Resource followers](#resource-followers)).
- **AWS** (2026-11-19, eu-west-1): three `c7g.xlarge` cores on an RDS `db.m7g.large`, with load
  generators of their own ([Resource followers](#resource-followers)).
- **AWS, namespaces on one database** (2026-11-20, eu-west-1): one `c7g.xlarge` core on an RDS
  `db.m7g.large` or `db.m7g.2xlarge`, writers on a `c7g.2xlarge`, consumers on a `c7g.xlarge`
  ([Several namespaces on one database](#several-namespaces-on-one-database)).

On the host, two databases were measured:

- **Server X** (the "Postgres" or "server X" figures):
  - the core in a container limited to **2 vCPU / 4 GB**;
  - Postgres 16 in a container limited to **2 vCPU / 4 GB** (`max_connections=300`, otherwise
    default settings);
  - **grants on**: the namespaces are private (`read: grant`), and every request carries a
    signed grant. Rows that say "authentication off" ran the same core with `--dev`.
- **SQLite** (the "SQLite" figures): the core with `--dev` and a SQLite file, in a container
  with **no limit**, so it had the host's 4 vCPU. Its namespaces are public.

So the two columns differ in more than the database: SQLite also had twice the CPU and no grant
checks. Read the SQLite column as "one unconstrained instance on local disk", not as a
like-for-like comparison of databases.

**The data.** 1,000 small namespaces (10 documents each) and one large namespace of
**1,000,000 documents** and **5,000,000 revisions**. The large namespace was made by 1M creates
(in 1,000-item batches) and 4M single appends of a small patch. Its documents are about 500
bytes. Seeding took 45 minutes on server X and 39 on SQLite. On disk it is 6.8 GB in Postgres
and 3.7 GB in SQLite.

**What makes the host's numbers conservative, and what makes them vary:**

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
indexes, so a namespace of 1M documents and 5M revisions answers like a small one.

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
- **These runs don't show whether Postgres is the limit:** its CPU wasn't recorded. On AWS a
  2-vCPU RDS ran at 68–70% for 450 writes a second ([Resource followers](#resource-followers)),
  so size Postgres for the writes first. With writes spread over several namespaces a
  `db.m7g.large` ran at 70–86% for about 1,600 writes a second
  ([Several namespaces on one database](#several-namespaces-on-one-database)).
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
are `CDN-Cache-Control: no-store` unless the CDN verifies edge grants (§C.5, `--edge-secret`).
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

### Resource followers

**A device that long-polls its own resource (§7.7), as one waits for the result of a workflow
run it started, costs the database nothing while the resource is quiet, and about 60 KB of a
core's memory.** As of 2026-11-19, three cores sharing a 2-vCPU Postgres held 120,000 such
devices with delivery and database CPU the same as at 15,000. That was the largest load
measured, not a limit.

What a follower costs:

- **Writes to other resources don't touch it.** A resource long-poll or event stream is woken
  only by commits naming its resource (a write, a batch item, a purge, a prune) and by those
  that concern the whole namespace (a configuration change, a branch, a namespace purge)
  (`Engine.WaitResource`; on Postgres the tailer wakes by resource too).
- **Its re-polls are answered from memory.** A follower asks again at each interval boundary,
  devices ÷ 20 requests a second. A long-poll from its resource's head is answered without a
  transaction while nothing that could change the answer has happened
  (`Engine.ResourceLiveLog`; README, "Long-poll reads are shared"). Only its first request,
  and a write to its resource, read the database.
- **Boundaries are spread out.** Each log's long-poll intervals have a phase of their own
  (§7.7), so followers of different resources don't all ask at once.

**On AWS** (`deploy/ec2-devices.sh`, eu-west-1):

- **Setup:** three `c7g.xlarge` cores (4 vCPU, 8 GB) sharing an RDS `db.m7g.large` (2 vCPU),
  and three load generators of their own.
- **Load:** devices were added 15,000 a step, each long-polling a resource of its own. Each
  step had 90 s of 150 completions a second (writes to random devices' resources) and a
  background writer of up to 300 writes a second to the same namespace.

| Devices | Completions/s, delivered | Delivery p50 / p99 | Long-polls/s: memory / read / stale | Cores' CPU | Cores' memory | RDS CPU |
|---|---|---|---|---|---|---|
| 15,000 | 145.7, 99.9% | 81 / 189 ms | 887 / 202 / 0 | 0.36 + 0.07 + 0.07 | 351–366 MB | 68% |
| 30,000 | 145.8, 99.9% | 87 / 189 ms | 1,644 / 194 / 0 | 0.40 + 0.11 + 0.11 | 662–710 MB | 70% |
| 60,000 | 147.2, 100% | 81 / 189 ms | 3,145 / 196 / 0 | 0.47 + 0.16 + 0.16 | 1.2–1.3 GB | 68% |
| 90,000 | 145.5, 100% | 87 / 204 ms | 4,643 / 194 / 0 | 0.53 + 0.22 + 0.22 | 1.8–2.1 GB | 70% |
| 120,000 | 146.9, 100% | 81 / 189 ms | 6,144 / 196 / 0 | 0.60 + 0.28 + 0.28 | 2.3–2.6 GB | 68% |

- **The figures are the run's `summary.txt`** (`deploy/devices-summary.py`).
- **The database's load is the writes'.** RDS stayed at 68–70% at every step.
  - Long-polls were answered from memory: 6,144 a second at 120,000 devices.
  - Reads stayed at about 196 a second, the completions' wake-ups. A completion is read twice
    on the core that wrote it, whose tailer wakes its own commits' followers again.
  - None was stale (read because the tailer was behind).
- **A waiting device costs a core about 60 KB and little CPU.** The first core also took every
  write. The other two used 0.28 of 4 vCPUs at 40,000 devices each.
- **Delivery** from a completion's write to its device took 81 ms at p50 and 189 ms at p99,
  including the hop from the writing core to the others through the tailer.

**On one host** (`cmd/capacity -only resource-live`, 4 vCPU, the harness on the same host,
`serve --dev`): N followers each long-poll a resource of their own while 16 writers append to
16 other resources of the namespace as fast as they can, for 20 s. SQLite was a file; Postgres
16 shared the host (`fsync=off`).

| Followers | Writes/s | Write p50 / p99 | Worst write | Core CPU |
|---|---|---|---|---|
| SQLite, 0 | 1,921 | 6.2 / 20 ms | 44 ms | 1.45 cores |
| SQLite, 1,024 | 1,746 | 6.5 / 24 ms | — | 1.4 cores |
| SQLite, 12,288 | 1,669 | 6.6–7.0 / 24–26 ms | 51 ms | — |
| Postgres, 1,024 | 1,277 | 11.8 / 22 ms | — | 0.8 cores |

- **Followers don't slow writes.** The 16 writers alone reach 1,921 a second, the ceiling of
  a host they share with the core.
- **A write to a follower's own resource** reaches it in 1–15 ms.
- **15,000 waiting devices with no writes** (`cmd/devicebench`, one core on Postgres) cost
  Postgres no CPU and the core 0.16 cores.

**Limits:**

- **Memory.** About 60 KB a waiting device, so a core with 8 GB holds about 100,000 (estimated,
  not measured). More devices need more cores, not a larger database.
- **Open files.** A core holds one socket a follower: give it a `nofile` limit above its
  followers. `deploy/ec2-devices.sh` raises it to 1,048,576.
- **Not reached:** a core's own limit, connections past 40,000 a core, and the database's
  share of more than three cores' wake-ups.

The files are in `docs/capacity/devices-aws-2026-11-19-fresh/` (AWS) and
`docs/capacity/resource-live-sqlite-after-*.json`, `resource-live-pg-after-1024.json` and
`resource-live-sqlite-phase.json` (one host).

## Large documents, by shape and schema

**Every write works on the whole document, so a small patch to a large document costs the
document's size. The shape matters more than the bytes: many small values cost 3–4× a document
of long strings. A schema that types them adds little: nothing measurable for a patch to one
member, and about a quarter when the patch changes a large array.** Keep a frequently edited
document of many small values under about 250 KiB if its appends should stay near 10 ms.

Measured on 2026-11-14, on the host and containers of the rest, with the server's own schema
validator (`internal/jsv`). Each figure is the median of 60 appends, one after another, to one
document.

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
- **in full**: the one-member patch with the core run with `--full-validation`, which validates
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
  and what every append pays under `--full-validation`.
- **The database adds a constant** (3–4 ms on server X). The rest is the core's CPU, which is
  why the two agree at the large sizes even though one core has half the CPU: an append uses one
  thread.
- **Creating the document costs four to five appends, typed or not**: 100–130 ms at 1 MiB and
  340–420 ms at 3.5 MiB with the schema, against 100–190 ms and 280–350 ms without.
- **What is left is the work every write does on the whole document**: parsing the stored head
  (about 35–40% of an append in a profile) and serialising and measuring the result (about
  40%).

The results are the `*-large-change.json` and `*-large-full.json` files.

### A recursive union schema

**A schema whose `oneOf` branches each recurse costs time in proportion to the document, and
validation work is bounded.** The validator (`internal/jsv`) stops a branch at its first failure
and checks a value's own keywords and scalar members before its objects and arrays, so a
branch whose discriminator fails doesn't descend into the children.

Measured on 2026-11-14 on a development machine, in the validator alone, not through the
server: a binary tree whose nodes are one of 4 kinds, against a `oneOf` of 4 node schemas, each
with `children`.

| Document | Validation | Steps |
|---|---|---|
| Tree of depth 10 (1,023 nodes) | 0.39 ms | 14,833 |
| The 1 MiB **schema** document of [the section above](#large-documents-by-shape-and-schema) (9,500 typed objects) | 4.2 ms | 85,503 |

- **Validation is bounded by steps** (`validationSteps`, §6.6 since v0.85), a step being one
  schema or subschema applied to one value: 5,000,000 for a write unless
  `serve --max-validation-steps` says otherwise. The limit covers validating the resulting
  document and the `schema` tests of the rules evaluated for the write, together, and each
  step of each batch item has it to itself, so a batch of 1,000 documents like the 1 MiB one
  above is far within it. A write that needs more is refused `422`, `limit: "validationSteps"`.
  The `core.schema.validate` span carries the validation's own count (README, "Telemetry").
- **A rule's schema fragment can be as costly as a document's schema**, and on any value: a
  fragment whose n levels each apply the next twice takes 2^n steps on a one-word string, and
  twelve levels fit in a kilobyte of a grant. Counted against the same limit, it is refused
  as a document over it is. That holds for writes only; see the gaps below.
- Keeping the recursion out of the union (declaring `children` once on the node schema, with
  only the discriminator and each kind's own members in the branches) is the cheaper schema.


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
  deployment maximum (`serve --max-rate-per-resource`) and set `ratePerResource` in that
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

- the core run with `serve --max-rate-per-resource 1e6,1e6 --max-rate-per-principal 1e6,1e6`;
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

The same writers as above, but each creates resources of its own in the namespace
(`If-None-Match: *`, a name the client chose, a 450-byte document) instead of appending to one
shared document. The rate is lifted as above.

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

### Several namespaces on one database

**On an RDS `db.m7g.large`, the writes of all namespaces together top out at about 1,600 a
second; on a `db.m7g.2xlarge`, at about 2,900. One namespace alone takes about 1,000. Once their writes
reach that total, namespaces share it evenly, and each one's write latency rises in proportion.** On the
`large` the limit is RDS CPU, not the core. Size Postgres for the total write rate of all
namespaces.

**Setup** (`apps/ouroboros/bench/aws/ec2-sources.sh` in doors, eu-west-1, 2026-11-20, patchlog
`0b017f31`, the v0.33.0 release tree plus later main):

- **Core:** one `c7g.xlarge` on an RDS Postgres `db.m7g.large` (2 vCPU, 8 GiB, single-AZ gp3)
  or `db.m7g.2xlarge` (8 vCPU, 32 GiB).
- **Writers and followers:** a `c7g.2xlarge`. **Consumers:** a `c7g.xlarge`, one namespace
  follower for each data namespace, reading each changed document back from the core.
- **Load:** each namespace has 100 small documents (about 80 bytes of JSON), each written 10
  times a second, so 1,000 writes a second are asked of each. One principal writes. Each write
  is a single-document JSON Patch with `If-Match` (an append). A writer waits for a write's
  acknowledgement before the next write to that document (a closed loop). 30 s a row.
- **Limits:** `ratePerResource`, `ratePerPrincipal` and `ratePerNamespace` raised in the
  namespaces, and the deployment maximums with `--max-rate-per-*`.

| Busy namespaces | Written/s, consumers read 1 at a time | Write p50 / p99 | Written/s, consumers read 8 at a time | Write p50 / p99 |
|---|---|---|---|---|
| 1 | 993 | 33 / 131 ms | 987 | 40 / 144 ms |
| 2 | 1,634 | 109 / 261 ms | 1,467 | 123 / 279 ms |
| 4 | 1,638 | 224 / 595 ms | 1,533 | 243 / 601 ms |
| 8 | 1,618 | 452 / 1,255 ms | 1,420 | 505 / 1,438 ms |
| 16 | 1,609 | 886 / 2,655 ms | 1,466 | 991 / 2,757 ms |

- **One namespace takes about 1,000 writes a second.** Its writers are closed-loop and every
  write extends the namespace's chain. That agrees with the host's 930–1,000 a second on server
  X (see "One log per namespace" under [By design](#by-design)).
- **Two namespaces reach the limit.** More share it out evenly: about 800 a namespace at 2,
  400 at 4, 200 at 8 and 100 at 16, with write latency rising in proportion. No write failed.
- **RDS CPU is the limit** (CloudWatch, 1-minute averages): 70–86% while namespaces were busy.
  The core's instance was at 14–23% CPU throughout, the consumers' at most 13% and the writers'
  at most 5%.

**On a `db.m7g.2xlarge`** (8 vCPU, 32 GiB; the same setup, 2026-11-20, consumers reading 8 at a
time only): the consumers read the revision each namespace entry names
(`GET /r/{ns}/{name}/rev/{id}`), one request instead of a redirect and the revision.

| Busy namespaces | Written/s | Write p50 / p99 | Per namespace, least–most | Changes applied by consumers/s |
|---|---|---|---|---|
| 1 | 999 | 17 / 24 ms | 999 | 999 |
| 2 | 1,996 | 23 / 79 ms | 998 | 1,993 |
| 4 | 2,851 | 122 / 303 ms | 695–723 | 1,012 |
| 8 | 2,914 | 248 / 696 ms | 352–390 | 906 |
| 16 | 2,917 | 491 / 1,460 ms | 166–207 | 911 |

- **About 2,900 writes a second across namespaces, against 1,600 on the `large`.** So on the
  `large` RDS CPU was the limit. No write failed.
- **Two namespaces each kept their full 1,000 a second** with no interference. From four on they
  share about 2,900, with write latency rising in proportion.
- **Nothing is CPU-bound at 2,900.** RDS was at 25–39% (CloudWatch, 1-minute averages while
  namespaces were busy), the core's instance at most 38%, the consumers' at most 38% and the
  writers' at most 18%.
- **Nor is storage.** RDS wrote 150–206 IOPS of the 3,000 gp3 gives 20 GiB, at 1–3 ms, its disk
  queue under 0.4 (CloudWatch, 1-minute averages).
- **Nor is the writers' principal's rate bucket**, one row of `rate_buckets` (`rate_draw`) that
  every write of a principal locks, across namespaces (§6.6): with a writer principal per
  namespace, writes stopped at 2,962–3,037 a second, as with one (3,000–3,055).
- **The limit is the core's main pool, 16 connections.** It is 4 per GOMAXPROCS by default
  (`internal/core/pgpool.go`), and `pool_max_conns` could then only lower it, so a run with
  `pool_max_conns=64` kept 16 (it now sets the pool's size: "Since these runs", below). Profiled
  (net/http/pprof) at 16 namespaces, the core had up to 700 requests waiting in `database/sql`
  for a connection, while Postgres had about 11 sessions not idle, most of them idle in a
  transaction waiting for the core's next statement (`pg_stat_activity`). Each write's check
  (D.3) takes a connection for five round trips, and the group commit workers wait in the same
  queue: each spent about 90% of its time waiting for a connection, so groups of about 30 writes
  (of `--group-commit` 32) committed about 100 times a second in all, about 3,000 writes.
  Postgres did little: about 2.5 ms of statements per group.
- **A pool of 64 raised the limit to about 4,600 writes a second.** With GOMAXPROCS 16 on the
  core (`pool_max_conns` couldn't raise the pool then), four namespaces wrote their full 3,992 a
  second, and eight and sixteen 4,611 and 4,602 (write p99 376 and 861 ms); a quiet namespace
  beside three busy ones stayed at p99 45 ms. RDS CPU peaked at 75%, the core's at 71%.
- **The next limit is the rate-limit draw.** A write's check (D.3) draws its tokens (`rateLimit`,
  `bucketStore.draw`) inside its read transaction, so it holds a main-pool connection, idle in a
  transaction, while it waits for one of the bucket pool's 16 and then for its buckets' rows.
  With one writer principal every draw locks the same row: `rate_draw`'s mean rose from 0.4 to
  1.9 ms, and Postgres showed row-lock waits (`Lock:tuple`, `Lock:transactionid`). Drawing
  outside the check's transaction would free the connection; a principal writing across many
  namespaces still serialises on its row.
- **A writer principal per namespace added 15–19%** on the pool of 64: 5,242 and 5,523 writes a
  second at eight and sixteen namespaces, against 4,547 and 4,649 with one in the same run, and
  the row-lock waits went. The pool was full again (430–580 requests waiting for a connection),
  with about 40 sessions idle in a check's transaction, and the core's instance at 79% CPU, much
  of it garbage collection. So past a larger pool and the draw moved out of the check, the
  core's CPU is next on a 4-vCPU instance; more instances share the work (D.8).
- **Changed after those runs** (93149318, measured below):
  - `pool_max_conns=N` sets the main pool to `N` connections, above 4 per GOMAXPROCS too, and
    the bucket pool to a quarter of `N`.
  - A write's draw is made after its check's read transaction, so it holds no main-pool
    connection while it waits for the bucket pool or its rows. The draw comes before the write
    is admitted, and its 429 answers as before.
  - Group commits take a connection from a pool of their own (a quarter of the main pool's
    size) when one is free, so a group of about 30 writes no longer queues behind every
    write's check.
- **With those (93149318), the draws are the limit.** On a pool of 64 and one writer principal,
  4, 8 and 16 namespaces wrote 3,923, 3,933 and 2,181 a second; with a principal per namespace
  3,960, 5,214 and 4,550. Up to 1,340 writes waited for one of the bucket pool's 16 connections,
  with 13–16 draws running, and with one principal they queued on its row (`rate_draw` 1.7 ms,
  `Lock:tuple` waits). Writes reached the group commit queue so slowly that groups shrank to
  about 2. `rate_draw` took more of Postgres's time than every other statement together. With
  `--local-rate-buckets` the same run wrote 7,733 and 8,134 a second at 8 and 16 namespaces (p99
  171 and 675 ms), so a draw per write is what costs: a draw for many writes at once, as group
  commit does for their rows, would take each bucket row's lock once. There the pool of 64 was
  full again, 1,400 requests waiting, most of them for checks' read transactions (five round
  trips each), and the core's instance at 82% CPU.
- **Past that, the core's CPU is the limit on 4 vCPUs.** A pool of 128 wrote less than 64 (6,544
  and 7,451 a second at 8 and 16 namespaces): the core used 3.4 of its 4 vCPUs (pprof), and the
  extra connections only waited on it (up to 91 sessions idle in a transaction). A write's check
  took 31–36% of the core's CPU, about a fifth of it in pgx: six round trips (begin, the
  namespace, resource and head reads, the retry lookup of §7.2, rollback), each a statement
  through pgx and TLS (TLS writes 8–9% in all). Followers' revision reads took 10–15%, group
  commits 9%, garbage collection 11%. Fewer round trips in the check would save the most.
- **On an 8-vCPU core (`c7g.2xlarge`), pool 64, buckets in memory**, 8 and 16 namespaces wrote
  7,777 and 10,462 a second at 3.5–4.5 vCPUs busy, the pool full again (1,000–1,250 requests
  waiting). A pool of 128 wrote less (7,757 at 16): Postgres slowed with more sessions (group
  commit's insert 2.5 ms against 1.6, the log lock 0.49 ms against 0.12) while RDS was at 67%
  CPU, so about 64 connections is the most that helps a `db.m7g.2xlarge`.
- **With batched draws and one-statement checks (cce94746, below), buckets in Postgres again**,
  8-vCPU core, pool 64: one writer principal wrote 7,819 and 11,621 a second at 8 and 16
  namespaces (p99 179 and 255 ms), more than with buckets in memory before; a principal per
  namespace 7,978 and 9,874 (a batch then locks a row per namespace). No request waited for a
  connection: writes waited in their namespaces' group commit queues, the core at 58% CPU, RDS
  at 76% with write latency up to 7.9 ms and a disk queue of 3.3. `rate_draw` and `rate_draws`
  took most of Postgres's statement time, and about two in five draws still ran alone. Next
  are Postgres's CPU and its volume (20 GiB of gp3: 125 MiB/s, of which up to 74 MB/s here).
- **Since these runs** (cce94746, measured above):
  - A write's check is one round trip, not six: its namespace, resource, head and the retry
    lookup of §7.2 are one statement (the lookup returns no row almost always), and a check
    that needs only that statement runs without a transaction (no begin, no rollback), so its
    connection is held for the statement alone, not idle in a transaction while the core works
    on the check. A check that needs more (a branch's bases, a document or schema not cached,
    an idempotent retry) runs again in a read transaction. The same holds for followers'
    revision reads (`resourceRev`): one round trip instead of five, or seven below the head.
    `purgedItems` and the rest of step 2 repeated no statements (the transaction kept the
    rows) but resolved each item again; they now share one view. On a local Postgres 16, a
    check took about 175 µs of the core's CPU instead of 270, a revision read about 150 instead
    of 240 (`BenchmarkCheckAppend`, `BenchmarkRevUncached`, `cpu-ns/op` at `-cpu 1`); over TLS
    to RDS the saved round trips cost more.
  - Concurrent rate-limit draws batch, as group commit's writes do (`bucketStore.draw`,
    `rate_draws`). Up to one draw statement runs on each of the bucket pool's connections, and
    the draws queued meanwhile go in the next one, which locks each bucket's row once for all
    of them and judges them in turn. A principal writing to every namespace locked its row
    once per write before; now once per batch, and no draw waits for a connection of the
    bucket pool. To measure it again: doors' `ec2-sources.sh` with `MODE=namespaces
    DB_CLASS=db.m7g.2xlarge FETCHES=8 STORE_POOL_CONNS=64 PRINCIPALS="one namespace"
    PROFILE=1`, without `--local-rate-buckets`.
  - Draws on the same bucket share a batch. Measured with batched draws (16 namespaces, a
    `c7g.2xlarge` core with `pool_max_conns=64`), the core wrote 11,621 a second with one writer
    principal and 9,874 with one per namespace. Still, `rate_draw` ran 1.12M times beside
    222k `rate_draws` (5.25M draws), so about two in five draws ran alone. The draws took more
    Postgres time than every other statement together, and one principal's batches waited on
    its row (`Lock:tuple`, `Lock:transactionid`). A draw that found a connection free started a
    batch of its own, only to wait for the row the batch before it held. Now at most one batch
    runs on any bucket: a draw on a bucket a batch draws on queues for the next batch on it,
    and draws on buckets no batch holds start a batch at once. At most 4 batches run at once
    (`drawBatches`), not one per connection of the bucket pool. A lone draw on an idle
    instance still starts at once, and requests on one bucket are still judged in queue order.
    On a local Postgres 16 (`BenchmarkDrawContended`, 64 goroutines, a bucket pool of 16),
    the one-principal case drew 17,900 a second instead of 6,400, 32 draws a statement instead
    of 2.3, with almost no draw alone (28% before). A principal per namespace drew 25,000 a
    second instead of 11,300, 7.5 draws a statement instead of 2.5, with 2% of draws alone
    (32% before). To measure it again, use the same `ec2-sources.sh` run as above
    (`STORE_TYPE=c7g.2xlarge`).
- **Followers that read each change's own revision applied everything at one and two
  namespaces** (999 and 1,993 a second). From four namespaces on they applied about 900–1,000 a
  second in all.

**Namespace followers that read documents back** (consumers, one for each data namespace) go to
the same database as the writes:

- **Reading one changed document at a time** (`GET /r/{ns}/{name}`, a redirect to the head
  revision, then that revision), one consumer applied 129 changes a second of the 993 written in
  its namespace. Each read waits on a round trip through the core to RDS (about 8 ms).
- **Reading 8 at once** it applied 741 of 987. With several busy namespaces each consumer
  applied fewer (348, 269, 230 and 252 a second in all at 2, 4, 8 and 16 namespaces), because
  its reads queue at the saturated RDS too.
- **Reading 8 at once cost 6–12% of the writes at saturation**: 1,634 against 1,467 at 2
  namespaces, 1,638 against 1,533 at 4, 1,618 against 1,420 at 8 and 1,609 against 1,466 at 16.
  Read in parallel, as patchlog's own index consumer does, and expect 6–12% of write
  capacity to go to followers at saturation.

**Nothing isolates namespaces from each other once the database is saturated.** One quiet
namespace (100 documents, each written once a second, so 100 writes a second) was run beside
busy ones:

| Busy namespaces beside it | Busy written/s (read 1 / read 8) | Quiet write p50 / p99, read 1 | Quiet write p50 / p99, read 8 |
|---|---|---|---|
| 0 | 0 / 0 | 8 / 18 ms | 8 / 19 ms |
| 1 | 986 / 967 | 18 / 102 ms | 32 / 143 ms |
| 3 | 1,479 / 1,316 | 128 / 371 ms | 151 / 419 ms |
| 7 | 1,584 / 1,329 | 357 / 1,086 ms | 371 / 980 ms |
| 15 | 1,595 / 1,385 | 725 / 2,569 ms | 875 / 2,847 ms |

- **On the `large`, a quiet namespace's write latency follows the busy ones'**: p99 18 ms alone,
  2.6 s beside fifteen busy namespaces. Beside fifteen, it wrote 87 a second of its 100 (77 with
  8 reads at a time).
- **On the `2xlarge` it is unaffected beside one busy namespace** (p99 12 ms, against 102 ms on
  the `large`) and follows the busy ones beyond that:

  | Busy namespaces beside it | Busy written/s | Quiet write p50 / p99 |
  |---|---|---|
  | 0 | 0 | 8 / 9 ms |
  | 1 | 999 | 9 / 12 ms |
  | 3 | 2,535 | 69 / 200 ms |
  | 7 | 2,710 | 202 / 609 ms |
  | 15 | 2,770 | 416 / 1,278 ms |
- **The lever today is the per-namespace rate limit** (`ratePerNamespace`, §6.6): keep the total
  of all namespaces under what the database takes. Nothing yet gives a quiet namespace a share.

The files are in `docs/capacity/sources-aws-2026-11-20/` (`large`) and
`docs/capacity/sources-aws-2026-11-20-rds2x/` (`2xlarge`).

## Limits, by kind

Each limit is one of three kinds:

- [By design](#by-design): the spec's model.
- [Gaps in this implementation](#gaps-in-this-implementation): fixable without changing the
  spec.
- [Deployment](#deployment): hardware and configuration.

### By design

**One log per namespace.**

- *Limit:* every write appends to its namespace's hash chain (§3.5). So writes to one namespace
  commit one at a time. On Postgres they commit one group of up to 32 at a time.
- *Measured:* one namespace takes 930–1,000 single writes/s on server X from 32 writers, and
  1,500/s on SQLite (4 vCPU). On an RDS `db.m7g.large` one namespace took about 993 a second,
  and all namespaces together about 1,600 (about 2,900 on a `db.m7g.2xlarge`)
  ([Several namespaces on one database](#several-namespaces-on-one-database)).
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
- *Lever:* `serve --max-document-size` raises the document maximum. Large documents are slow to
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
  - The instances of a Postgres deployment share the buckets (`rate_buckets`, about +1.2 ms a
    write). They are per instance only with `serve --local-rate-buckets`.
- *Measured:* 500/s a namespace is about half of server X's single-namespace ceiling.
- *Lever:* allowances (§6.6) replace a principal's and its namespace's buckets, for loaders and
  importers. The per-resource rate always applies.

**Followers are cheapest through the CDN** (§7.7, §9).

- *Limit:* through the CDN, followers of a namespace cost the origin nothing per follower. At
  the origin they cost a connection each and a shared read per write. A follower of its own
  resource costs a connection and about 60 KB of a core's memory, and nothing while its
  resource is quiet. SSE streams (§7.3) are collapsed neither at the CDN nor at the origin.
- *Measured:* see the table under [Long-poll followers and the CDN](#measured).
- *Lever:* devices long-poll. Services that need every entry use the log and checkpoints (§10).

**Consumers read over HTTP.**

- *Limit:* a consumer catches up from the log and fetches each changed document (§10).
- *Measured:* catch-up of 4M entries takes 1.7 min. Bootstrap of 1M documents takes 6–7 min on
  server X.
- *Read-back:* a namespace follower that reads each changed document back is limited by its
  reads: 129 changes a second of 993 reading one at a time, 741 reading 8 at a time, each read
  about 8 ms through the core to RDS. Reading 8 at a time cost 6–12% of the writes at
  saturation ([Several namespaces on one database](#several-namespaces-on-one-database)).
- *Lever:* consumer throughput is the consumer's (see the gaps below). The origin side scales
  with instances.

### Gaps in this implementation

| Gap | Effect | Fix |
|---|---|---|
| **No edge that verifies edge grants** is included. | Private long-polls don't collapse at the CDN: every follower is an origin connection and request. The origin shares their reads ([Origin-side collapse](#origin-side-collapse)), at ~0.03–0.04 ms of core CPU per follower per write (0.12–0.14 ms through Varnish). | An edge (Varnish VMOD, Fastly or Cloudflare worker) with `edge.Cookies.Check`'s checks; the origin already issues the cookies. |
| **No read replicas, and one `--db` for everything.** The core runs migrations, the tailer and leader jobs, so it can't run on a read-only database. | Consumers' scans and private reads load the primary. | Route bulk reads (catch-up, bootstrap, export) and private reads to a replica, with misses of new revisions falling back to the primary; decisions stay on the primary. |
| **Consumers** (the index): one SQLite writer per process, 8 document fetches at a time, no sharding but by namespace lists. | Bootstrap of 1M documents: 6–7 min on server X (fetches at 2,400–2,800/s); 1.3 min on SQLite. | More fetch concurrency, pipelining pages; split namespaces over processes. |
| **Rule `test`s with a `schema` are not counted on reads, and annotation walks never.** A write's rule tests draw on its `validationSteps` with its validation (v0.85), and listing an invalid document's failures takes what is left of it. | A grant narrowed with a rule whose schema fragment is expensive to evaluate still costs that on every read, exchange and key request it is presented for; the spec bounds writes only (docs/SPEC-FEEDBACK.md, v0.85 Open 52). A schema's annotations can still be made expensive to walk. | Bound rule tests on reads too, once the spec says what a read that runs out answers; count annotation walks. |
| **A namespace purge is one transaction.** | Long lock and transaction for large namespaces. | Purge in chunks. |
| **No profiling endpoint; the core sets no memory limit.** | Peak RSS 1.0 GB on server X and 1.4 GB on SQLite over a whole run. Scans, reads and small writes alone peaked at 0.2–0.3 GB; the rest came with 3.5 MiB documents and 5,000 followers. | Run with `GOMEMLIMIT` under container limits; profile the large-document path (an opt-in pprof listener would help). |

### Deployment

| Resource | Measured | Notes |
|---|---|---|
| **Core CPU** | Grant checks, canonicalisation, validation, folds and page serialisation are core CPU. On server X a 1-vCPU core kept up with the reads, writes and scans measured. | Scales with instances once it is the limit (it wasn't on server X). |
| **Postgres round trips** | A single write is ~13 statements; on server X one writer did 200–240 writes/s (about 4 ms each). | Keep the core near Postgres (sub-millisecond); concurrency, not speed, is what instances add. |
| **Postgres CPU and memory** | Server X: 3.3 of 4 GB at the end of the runs, CPU not recorded, and a smaller core was no slower. AWS, devices run: a 2-vCPU RDS at 68–70% for 450 writes a second, unmoved by 120,000 waiting followers. AWS, namespaces run: a `db.m7g.large` at 70–86% for about 1,600 writes a second of small documents across several namespaces, with the core at 14–23%. A `db.m7g.2xlarge` (8 vCPU) at 25–39% for about 2,900 writes a second in the same setup, with the core at most 38%. | Size Postgres for the writes first; a read replica takes bulk reads and private followers' log reads (a gap, above). |
| **Storage** | 6.8 GB on Postgres, 3.7 GB on SQLite for 5M revisions of ~500-byte documents. | Linear in revisions; pruning (§8.6) bounds it. |
| **Memory** | Core: 0.2–0.3 GB through scans, reads and small writes, 0.4–0.6 GB after a whole run, 1.0 GB peak (1.4 GB on SQLite) with 3.5 MiB documents and 5,000 followers; about 60 KB more a waiting resource follower (2.3–2.6 GB at 40,000). The caches are bounded: up to 256 MiB of documents, 64 MiB of read-cache revisions and 65,536 grants (a few hundred MB at most) by default. | Give containers `GOMEMLIMIT`, 2 GB+ for an instance that serves large documents or many followers; size the caches with `serve --doc-cache-size`, `--read-cache-size` and `--grant-cache`. |
| **Open files** | One socket a follower. | A `nofile` limit above the followers a core holds. |
| **Upgrades** | Schema migrations run in a transaction at start (README "Schema migrations"); one that builds an index on a large table blocks writes to it while the index builds. | Create the index `CONCURRENTLY` beforehand under the same name: migrations are written with `IF NOT EXISTS`, so they then find it. |

## Settings

The defaults, and when to change them.

| Setting | Default | Change it when |
|---|---|---|
| **Bearer cache** (`serve --grant-cache`) | 65,536 grants, at most 32 MiB of tokens, least recently used out first | More distinct grants than that read often: every request whose grant isn't kept verifies it. |
| **Document and read caches** (`serve --doc-cache-size`, `--read-cache-size`) | 256 MiB and 64 MiB | Large documents or a large working set of revisions. |
| **`documentSize`** (`serve --document-size`, `--max-document-size`) | 1 MiB; a namespace may set up to 4 MiB | Rarely: appends at 3.5 MiB cost 4× those at 16 KiB for documents of long strings, and 14× for many small values ([Large documents](#large-documents-by-shape-and-schema)). |
| **Per-resource and per-principal rates** (`serve --max-rate-per-resource`, `--max-rate-per-principal`, and the namespace's `limits`) | 10/s and 50/s | One writer writes a small document often. |
| **`ratePerNamespace`** | 500/s | Leave it: about half of one namespace's ceiling on server X, which leaves room for reads. Give importers and loaders allowances. |
| **`itemsPerBatch`** | 1,000 | Leave it: batches are for imports; give importers allowances. |
| **Postgres pools** (`pool_max_conns` in the URL) | 4 × GOMAXPROCS connections; a quarter of that, at least 2, for rate draws and for group commits each | Writes queue for connections while Postgres is mostly idle: a database a millisecond away wants more than the CPUs give, e.g. 64 on a `c7g.xlarge` ([Several namespaces on one database](#several-namespaces-on-one-database)). Keep every instance's pools together under `max_connections`. |
| **The snapshot cadence, the long-poll interval and the log page size** | as shipped | — |

## Rerunning

```sh
go build -o patchlog ./cmd/patchlog && go build -o capacity ./cmd/capacity
./patchlog serve --dev --addr :9080 --db cap.db --origin http://localhost:8080 --max-rate-per-namespace 1e9,1e9 &
./capacity -url http://127.0.0.1:9080 -pid $! -json result.json   # 1M docs, 5M revisions: about 40 min to seed
```

Why `--max-rate-per-namespace 1e9,1e9` is needed:

- The harness's namespaces give its loader an allowance of 1e9 writes a second and burst.
- An allowance's bucket never exceeds the deployment maximum of `ratePerNamespace` (§6.6), so
  the core needs `--max-rate-per-namespace` raised to it.
- Without it, creating the namespaces is `422` (`limit: "ratePerNamespace"`).

Options:

- **Grants**: run the core with `--operator-key <public>` (from `patchlog keygen`) and pass the
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
    principal. The core then needs `--max-rate-per-resource N,N --max-rate-per-principal N,N`.
  - `-only single` also measures the writers each creating resources of their own
    (`single_ns_items_writers_N`).
- **Server X**: run the core and Postgres in containers with `--cpus 2 --memory 4g` each
  (Postgres with `-c max_connections=300`), the core with `--operator-key`, and point `-url` at
  the core container's address. `-pid` takes the core's process id on the host
  (`docker inspect -f '{{.State.Pid}}'`), which is where the CPU and memory figures come from.
- **A public namespace's followers** need a namespace made without grants: run the core with
  `--dev` and give `--ns` a name not used before, since `-only live` reuses `<ns>-live` if it
  exists.
- **Resource followers**: `-only resource-live` needs no seeding. It makes a namespace of its
  own and needs the core run with `--max-rate-per-namespace`, `--max-rate-per-resource` and
  `--max-rate-per-principal` all at `1e9,1e9`. `--resource-waiters`, `--resource-writers` and
  `--resource-seconds` size it.
- **Devices waiting on resources of their own, across machines**: `deploy/ec2-devices.sh` runs
  `cmd/devicebench` on EC2 load generators of their own against `SERVERS` cores sharing an RDS
  Postgres (or one on SQLite). Each step connects more devices, each long-polling its own
  resource, and measures how long a write to a device's resource takes to reach it.
  `deploy/devices-summary.py` prints a row per step, with the cores' and RDS's CPU, and names the
  first step that looks broken. The script's header lists its settings and what it makes;
  `./deploy/ec2-devices.sh cleanup` deletes the RDS instance and the IAM role. `devicebench`
  also runs on its own against any core (`-help`).
- **Several namespaces on one database, across machines**: doors'
  `apps/ouroboros/bench/aws/ec2-sources.sh` (doors-live/doors) runs its source-consumer benches
  with the core, the database, the writers and the consumers each on their own instance. The
  run in [Several namespaces on one database](#several-namespaces-on-one-database) used
  `NAMESPACES 1,2,4,8,16 RATE 10 DURATION 30000 FETCHES 1 8`. The `2xlarge` run used
  `DB_CLASS=db.m7g.2xlarge FETCHES=8`; add `STORE_POOL_CONNS=64` to set the core's
  `pool_max_conns`.
- **Sizes**: `-docs`, `-revs`, `-namespaces`, `-doc-size`, `-append-batch`. `-help` lists the
  rest.
