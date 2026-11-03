# Results

Measured on 2026-11-03 on one 4-vCPU Intel Xeon (2.8 GHz) VM, with workerd 2026-11-02
(`bench/workerd.capnp`). The load generator ran on the same machine.

**What these numbers are.** Locally, workerd runs the front Worker and every Durable
Object in one process, on local disk, with no replication and no network. So:

- **Server CPU per request** carries over to Cloudflare as an estimate. It includes the
  runtime's own work (HTTP, dispatch to the object, SQLite), which Cloudflare doesn't bill
  as Worker CPU time.
- **Throughput and latency** are this machine's, and so a floor. On Cloudflare each
  namespace's object can run on its own machine, and the network adds latency (below).

## CPU of the patchlog logic

`crates/bench`: the write path minus storage (read the body, hash the id, apply the patch
to the cached head document, check the limits, and every 16th write serialise a snapshot),
and the read path (serialise the document; SHA-256 for `Repr-Digest`). The patch is a
single `replace`. "wasm" is the same code under Node's WASI, on V8, the engine workerd uses.
Runs on this shared VM vary by about ±30%.

| Document | Write, wasm | Write, native | Serialise, wasm |
|---|---|---|---|
| 0.5 KiB | 9–15 µs | 5–8 µs | 3 µs |
| 16 KiB | 52–125 µs | 56–76 µs | 82 µs |
| 256 KiB | 0.75–1.5 ms | 0.7–1.2 ms | 1.3 ms |
| 1 MiB | 3.1–7.4 ms | 3.7–6.6 ms | 6.4 ms |
| 1.5 MiB | 4.6–9.7 ms | 6.3–8.4 ms | 9.7 ms |

Wasm on V8 runs within about 1–2× of native. A write's cost grows with the document,
not the patch: §6.6 holds the *resulting* document to `documentSize`, `valueSize`,
`pathSize` and `nestingDepth`, and this implementation re-measures the whole document on
every write. SHA-256 in wasm runs at about 90 µs per 16 KiB, more than serialising, so the
Worker hashes with WebCrypto instead.

## Server CPU per request (workerd)

`bench/overhead.mjs` and `bench/load.mjs --pid`. Durable Object requests include the front
Worker's hop to the object.

| Request | Server CPU |
|---|---|
| `GET /` (front Worker only: the floor for any request) | 0.36–0.40 ms |
| `GET /ns/{ns}` (the object answers from memory) | 0.58–0.65 ms |
| `GET /r/{ns}/{name}` (head `302`, from memory) | 0.58–0.70 ms |
| `GET /r/{ns}/{name}/rev/{id}` (folds or uses the cache, serialises, hashes) | 1.3–1.6 ms |
| Append to a 0.5 KiB document, one writer | 2.1–2.3 ms |
| Append, 32 concurrent writers to one namespace | 1.4 ms |
| Append to a 16 KiB / 256 KiB / 1 MiB document | 2.6 / 4.9 / 9.7 ms |
| Long-poll delivery, per follower per write (100 / 1,000 / 3,000 followers) | 0.30 / 0.36 / 0.53 ms |

**Where an append's CPU goes.** A JavaScript Durable Object that issues an append's SQL
and nothing else (`bench/baseline`) costs 2.04 ms per request: 0.62 ms for a no-op round
trip to the object and about 1.4 ms for the SQLite reads and the three inserts committed
together. The Rust object was 2.59 ms before its head caches and 2.27 ms after (it no
longer issues SQL reads on a hot append). The patchlog logic is about 0.01 ms of that.
For small documents the cost is the runtime and the durable SQLite commit, not this code.
Locally the commit is a write to disk; in production it is a replicated commit, whose CPU
cost these numbers don't show.

## Throughput and latency on this machine

`bench/load.mjs`, writers each appending to their own 0.5 KiB document, 8 s per scenario:

| Scenario | Rate | p50 | p99 |
|---|---|---|---|
| Writes, one namespace, 1 writer | 241/s | 3.9 ms | 9 ms |
| Writes, one namespace, 8 writers | 511/s | 14 ms | 48 ms |
| Writes, one namespace, 32 writers | 550/s | 57 ms | 183 ms |
| Writes over 100 namespaces, 32 writers | 439/s | 66 ms | 253 ms |
| Appends to a 16 KiB / 256 KiB / 1 MiB document, 1 writer | 206 / 131 / 75/s | 4.5 / 6.4 / 12.8 ms | 10 / 17 / 43 ms |
| Head reads (`302`), 8 readers | 1,352/s | 4.7 ms | 23 ms |
| Revision reads from the object, 8 readers | 640–790/s | 8–11 ms | 63–71 ms |
| Long-poll: one write reaches 100 / 1,000 / 3,000 followers | all in 0.08 / 0.66 / 2.0 s | | |

The one process is saturated in each of these. Spreading writes over 100 namespaces is no
faster here, because every object shares that process. Cloudflare can spread namespaces
over machines; one namespace stays on one object, which runs one event at a time.

Through `wrangler dev`, every request costs about 7 ms more (its dev proxy), so its numbers
are not useful for this.

## What it suggests for Cloudflare

These are estimates from the numbers above, not measurements on Cloudflare.

- **One namespace.** The object's single thread runs at about 1.4–2.3 ms of CPU per small
  append, so roughly 450–700 appends/s per namespace, and fewer for large documents
  (about 100/s at 1 MiB). That is near the spec's default `ratePerNamespace` of 500/s and
  the Go server's 590/s on Postgres (`main`'s `docs/CAPACITY.md`). Cloudflare's soft limit
  of 1,000 requests/s per object is above it.
- **Many namespaces** add up, because each namespace is its own object.
- **Write latency** adds the network: the client to its nearest Cloudflare location, and
  that location to the object's location, which is fixed where the namespace was first
  used. The replicated commit adds a few ms. Expect tens of ms in the same region and
  100–250 ms from another continent.
- **Followers.** One object delivers a write to about 1,500 long-poll followers a
  second. Beyond about a thousand followers per namespace, either collapse them at the
  edge (public namespaces, §7.7) or fan out through relay objects.
- **Cached reads** cost only the front Worker (about 0.4 ms here) and never reach the
  object. The Cache API is per data center, so each location misses once.

## Rerunning

```sh
cargo run --release -p patchlog-bench
cargo build --release -p patchlog-bench --target wasm32-wasip1 && node bench/wasi.mjs
npm run build && npm run workerd &
PID=$(pgrep -f '^workerd serve bench')
node bench/overhead.mjs http://127.0.0.1:8788 "$PID"
node bench/load.mjs http://127.0.0.1:8788 --pid "$PID"
```
