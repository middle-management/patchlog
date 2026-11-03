# Costs

What this implementation would cost to run on Cloudflare, by scenario, per month.
`bench/cost.mjs` computes it; change its scenarios or units and rerun.

**Inputs.** Prices are Workers Paid (Standard) as published on 2026-11-03. Unit costs
come from the deployments measured on 2026-11-03 (`bench/RESULTS.md`), read from
Cloudflare's GraphQL analytics, except storage per write, which was measured on local
SQLite. These are estimates. Real traffic will differ: request mix, document sizes, and
how many namespaces are busy at once all move the numbers.

## Prices

| | Included per month | Then |
|---|---|---|
| Workers Paid | | $5 per account |
| Worker requests | 10M | $0.30 per million |
| Worker CPU | 30M ms | $0.02 per million ms |
| Durable Object requests | 1M | $0.15 per million |
| Durable Object duration | 400,000 GB-s | $12.50 per million GB-s, at 128 MB per object |
| SQLite rows read | 25 billion | $0.001 per million |
| SQLite rows written | 50M | $1.00 per million |
| SQLite storage | 5 GB | $0.20 per GB-month |

Durable Objects are billed for duration, not CPU. A request served from the Cache API
inside a Worker is still a Worker request: on Workers, the Worker runs before the cache.

## Units, measured

| | Per | Measured |
|---|---|---|
| Worker requests | API request | 1 |
| Worker CPU | API request | p50 0.9–1.0 ms, p99 3.6 ms |
| Durable Object requests | write, uncached read, long-poll | 1 |
| Rows written | append | 4 (6.0–7.7 as first built) |
| Rows read | append | ~4 |
| Storage | small append (0.5 KiB document) | ~512 bytes (local SQLite) |
| Active time | write to a quiet namespace | ~15–25 ms |
| Active time | request to a busy namespace (requests overlap) | ~2.5 ms |
| Long-poll polls | idle follower | one per 20-second interval (100 followers: 300 a minute), each a Worker request |
| Active time, waits **inside** the object (first design) | namespace with a waiting follower | **the whole time**: 59.8 s of every minute, 7.66 GB-s a minute, for 100 idle followers |
| Active time, waits on **hibernating WebSockets** (as built) | namespace with 100 idle followers | **0.35 s a minute** (0.045 GB-s), about 170× less |
| Durable Object invocations, hibernating | idle poll | 2: the socket's connect and its close event (counted here as full requests; a close may be billed at 1/20 as an incoming WebSocket message) |

## Scenarios

The scenarios are illustrations, not requirements from the spec. The **device fleet** is a
mostly idle, read-only fleet:

- 100,000 devices, each long-polling one of 10 public namespaces (about 10,000 followers a
  namespace);
- 100 writes a day across those namespaces, so nearly every poll ends in a `204`;
- one poll per device every 20 seconds, the spec's default interval (§7.7): 3 a minute, about
  13 billion a month;
- about 500 bytes per answer, about 6.5 TB a month.

| Scenario | Per month | Main cost |
|---|---|---|
| **Small team CMS**: 50 namespaces, 10,000 saves and 100,000 reads a day (half cached), 2 GB | **$5** | Within the included usage |
| **Collaborative SaaS**: 5,000 namespaces, 1M saves and 10M reads a day (half cached), 2,000 open documents with 5 followers each, 50 GB | **~$1,060** | Worker and Durable Object requests, $945 |
| The same behind Workers Cache | **~$710** | Worker requests, $507; a document's followers share one miss |
| The same, with waits inside the object, as first built | ~$9,200 | Durable Object duration, $8,300: each followed namespace is active all month |
| **Device fleet through the Worker**: 100,000 devices long-polling 10 public namespaces, 100 writes a day | **~$6,200** | Requests: 13 billion polls a month, $5,880 |
| The same fleet behind Workers Cache (measured collapse) | **~$3,900** | Worker requests, $3,890: cache hits are billed as requests |
| The same fleet behind Fastly (collapse measured; prices third-party, unconfirmed) | ~$10,500 | Fastly's requests, ~$9,700 at ~$0.75 per million |
| **The same fleet behind Bunny** (collapse measured; no request fees) | **~$70** | ~6.5 TB of `204`s at $0.01/GB |
| **Write-heavy ingest**: 1,000 namespaces, 10M writes a day, 150 GB added a month | **~$1,300** | Rows written, $1,150 |
| The same at 7 rows per append, as first built | ~$2,200 | Rows written, $2,050 |

## What the costs say about the design

1. **Long-poll waits must not keep the object awake.** As first built, a long-poll (§7.7)
   waited inside the namespace's Durable Object, which kept the object active and
   billed: about $4.14 per followed namespace per month, $8,300 of the collaborative
   scenario's $9,200. Now the front Worker holds the client's poll (a Worker isn't billed
   while it waits) on a WebSocket to the object, which the object accepts with the
   hibernation API and answers after the next write; the Worker answers `204` at the
   interval's end. Measured with 100 idle followers, the object's active time fell from
   59.8 s to 0.35 s a minute. Each poll now wakes the object twice (connect and close)
   instead of once, so past about 200 waiters on one namespace, where an always-awake
   object becomes cheaper, further polls wait in the object again.
2. **Turn on Workers Cache; for fleets, pick a CDN by its request price.** §7.7's long-poll
   URLs are built to be collapsed by a cache, and both Workers Cache and Fastly do it:
   measured, hundreds of followers of one URL cost one request to the Worker. What remains
   is the price of each poll, and a 100,000-device fleet polling every 20 s makes about 13
   billion a month: Workers Cache bills each hit as a Worker request ($0.30 per million,
   ~$3,900 a month), Fastly charges more per request (~$0.75 per million, ~$10,500), and
   Bunny, which charges only for bandwidth, ~$70 (measured: the Worker ran about once
   per interval for 100 idle followers). A longer interval divides all of
   these. Any CDN in front must cache the long-poll `204` (§9) and wait longer than the
   interval for the origin, and Bunny must be told to key its cache on the query string
   (`RESULTS.md` has both CDNs' settings).
3. **Rows written are the cost of writes.** Every row and index entry counts. An append
   writes 4 (it wrote 7 as first built, before the `resources` table and an index went), at
   $1 per million: $4 per million writes, still more than everything else a write costs put
   together (Worker and Durable Object requests $0.45 per million, CPU $0.02).
4. **Small deployments cost the $5 base.** The included usage covers 10 million Worker
   requests, 1 million Durable Object requests and the rows of 12.5 million appends a
   month. Past that, a million writes cost about $4.50.
5. **Storage is cheap but grows.** About 0.5 KB per small append, $0.20 per GB-month.
   Pruning (§8.6), not implemented, bounds it.
