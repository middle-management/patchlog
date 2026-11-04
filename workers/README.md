# patchlog on Cloudflare Workers

A from-scratch implementation of [docs/SPEC.md](../docs/SPEC.md) (draft v0.74) for Cloudflare
Workers and Durable Objects, in Rust. It shares no code with the Go implementation in the
rest of this repository: it was written from the spec alone, to find out whether the spec
fits Workers and what it costs there. [bench/RESULTS.md](bench/RESULTS.md) has the measurements, locally and on
Cloudflare, and [bench/COSTS.md](bench/COSTS.md) what they cost by scenario.

**Status: a skeleton.** It implements the core write and read path for one namespace,
with authentication disabled (§1, `"auth": "disabled"`). Everything else is listed under
[Not yet](#not-yet).

## Layout

| Path | What |
|---|---|
| `crates/core` | Platform-neutral Rust, with no I/O: I-JSON input and canonical JSON (§3.1), ids (§3.2–§3.5, §3.7), names (§3.6), JSON Patch with the `writes` of §6.4.1, the limits of §6.6, and the storage-free steps of a write (§6.2). It builds natively for tests and to wasm for the Worker. |
| `crates/worker` | The Worker ([workers-rs](https://github.com/cloudflare/workers-rs)). `lib.rs` is the front Worker: `GET /`, URL checks (§7), the Cache API for immutable reads, and routing to the Durable Object of the namespace named in the URL. `ns.rs` is that Durable Object: one per namespace, on SQLite storage. |
| `crates/bench` | Measures the CPU cost of the write and read paths, natively and as wasm on V8. |
| `bench/` | `smoke.mjs` (end-to-end checks), `load.mjs` and `overhead.mjs` (load and CPU per request), `workerd.capnp` (runs the build on plain workerd), `baseline/` (a JavaScript Durable Object doing the same SQL, for comparison). |

## Design

- **One Durable Object per namespace.** The object owns the namespace chain, the namespace
  document chain and every resource log in its namespace. It runs one event at a time, and
  each write's checks and inserts run with no `await` between them, inside
  `transactionSync`. That gives §5 its atomicity (invariants 2, 5 and 6) and the single
  linear namespace chain of §3.5 without locks.
- **Storage** is the object's SQLite: `ns_log` (the namespace chain), `ns_config` (the
  namespace document chain), `res_log` (resource log entries holding canonical patch sets,
  clustered by resource, so a log range or a head is one range of its key) and
  `res_snapshots` (a canonical document every 16 entries of a resource, so any revision is a
  fold of at most 15 patch sets). A resource entry takes the sequence number of the
  namespace entry that records it, and a resource's head is its newest entry. Every row and
  index entry written is billed, and an append writes 4: two tables, one index each.
- **Memory.** The namespace head, every resource's head and the head documents (up to
  32 MiB, parsed) stay in the object's memory. A hot append issues no SQL reads, only its
  two inserts.
- **`documentSize` is capped at 1.5 MiB** (the default is 1 MiB, as in §12.2). A SQLite
  value in a Durable Object can't exceed 2 MB, and a 4 MiB maximum would need snapshots
  split across rows.
- **Long-poll (§7.7)** waits in the front Worker, not in the namespace's object, which would
  keep the object awake and billed. The Worker opens a WebSocket to the object; the object
  answers at once when it can, and otherwise accepts the socket with the hibernation API
  and can sleep until the next write, when it sends the answer down every waiting socket.
  The Worker answers `204` at the interval's end. Past 200 waiters on a namespace, further
  polls wait in the object itself, which is cheaper there (`bench/COSTS.md`).
- **Typed documents (§6.1, §6.2 step 5)** are validated with the `jsonschema` crate
  (draft 2020-12, formats asserted) against the schema revision and its `$ref` closure, which
  may live in other namespaces: a write whose closure isn't in the object's memory or its
  own storage stops before its checks commit to anything, fetches the revisions from the
  other namespaces' objects, and runs again from the start, so the write itself still has no
  `await`. Revisions are immutable, so schema documents and compiled validators are cached
  for good. Schema documents get §6.1's checks: no `$id`, `$schema` only at the root, no
  unknown keywords but `x-*`, only defined formats, `$ref` to fragments or revision paths,
  references that resolve. Regular expressions follow RE2 (§6.6, Addendum I.11): patterns
  are translated for the `regex` crate, which shares RE2's semantics but spells `\uXXXX`,
  surrogate pairs, `\Q…\E` and the ASCII classes `\d \w \s \b` differently. It adds about
  1.2 MB to the gzipped bundle (1.5 MB in all; startup 5 ms).
- **Namespace rules (§6.4)** are enforced on resource writes (step 6 of §6.2) against the
  change envelope of §6.4.1, compiled once per namespace-document revision; a failure is
  `422 rule` with `rule` and `path`. With authentication disabled, config writes skip them
  (§1). `catalog`, `catalogs`, `allowances` and Addendum F's `merge`, `merged`, `cleanup`
  and `abandoned` are accepted in namespace documents and checked for shape (§12.3);
  allowances change nothing while authentication is disabled.
- **Caching (§9)**: responses carry the spec's `Cache-Control` and `Cache-Tag`. The front
  Worker serves immutable public responses from the Cache API and answers
  `If-None-Match` itself. Private namespaces are `CDN-Cache-Control: no-store`, since
  there are no edge grants yet.
- **`Repr-Digest`** is hashed by WebCrypto, because SHA-256 in wasm costs more than
  serialising the document.

## Running

Needs Rust with the `wasm32-unknown-unknown` target, `cargo install worker-build`, and
Node 22. Commands run from this directory.

```sh
npm install
cargo test -p patchlog-core               # unit tests and the vectors of Addendum I.1–I.3
npm run dev                               # wrangler dev on :8787 with auth off (builds first)
node bench/smoke.mjs                      # end-to-end checks against it
cargo build -p patchlog-grant && npm run dev:grants   # grants and edge grants on, with development keys, on :8788
node bench/auth-smoke.mjs http://127.0.0.1:8788      # grant checks against it

npm run build && npm run workerd          # plain workerd on :8788, without wrangler's proxy
node bench/load.mjs http://127.0.0.1:8788 --pid "$(pgrep -f '^workerd serve bench')"
```

Workers Cache is on (`[cache]` in `wrangler.toml`): responses are cached by their
`Cache-Control` (§9) in front of the Worker, and concurrent long-polls on one URL
collapse into one miss. Deploy to a custom domain with
`npx wrangler deploy --domain patchlog.example.com`.

`npm run deploy` deploys with wrangler (`npx wrangler login --device` signs in from a
headless machine). The Cache API works only on a custom domain, not on `workers.dev`.
On the Workers free plan, Durable Objects may write 100,000 SQLite rows a day, and an
append writes 4: past that, writes answer `503` with `Retry-After` until 00:00 UTC.

## Implemented

- `GET /`; URL and query-parameter checks (§7); `400`, `404`, `405`, `410`, `412`, `413`, `415`, `422` and `428` with §12.1 bodies.
- Namespaces: creation and config writes (`PATCH /ns/{ns}`) with idempotent retries; `GET /ns/{ns}`, `/rev/{ns_id}`, `/rev/{ns_id}/log`, and `/log` with `live=long-poll`. Namespace documents accept `read`, `frozen`, the six patch-set and document `limits` and `x-` members, and check the Values rule of §6.6. Other members are `422`.
- Resources: create, append, restore and delete with preconditions, idempotent retries (§7.2), `Gesture`/`Undoes`, the frozen check, JSON Patch, the `writes` of §6.4.1, the limits of §6.6, typed documents (§6.1) and namespace rules (§6.4). `GET`/`HEAD` of heads (`302`, or `410` once tombstoned), revisions (`ETag`, `Last-Modified`, `Repr-Digest`, `304`), log ranges with paging, and `/r/{ns}/{name}/log` (the redirect to its range, and long-poll, §7.7).
- `GET /ns/{ns}/rev/{ns_id}/heads` (§7.4) and the gesture listing `GET /ns/{ns}/gestures/{gesture}`.
- Batches (`POST /ns/{ns}/batch`, §7.5): items with several steps (patch sets, `"delete"`, restores), an optional `config` change, `source`, per-step gestures, idempotent retries and dry runs. Every step is checked as §6.2 says (schemas written by earlier items resolve for later ones), and the batch commits all or nothing as one `batch` entry. A batch's resource entries each take their own sequence number, and the `batch` entry the last of them.
- Blobs (§7.8) on R2 (`BLOBS`, bucket `patchlog-blobs`), stored once per id under `b/{id}`: uploads checked against the id over the body, pending entries per uploader (`blobPending`, `blobGrace` of 24 h), attachment by the write that references them (in single writes and batches), `Blob-From` copies within a namespace, reads of attached blobs with ranges, `nosniff` and `sandbox`, and `GET …/raw` redirecting raw documents to their blob. Uploads are held in memory while hashed, so `blobSize` is 32 MiB here.
- Branches (§7.6): `POST /ns/{base}/branches` (the branch's document, the base's rules on a `branch` envelope, `branchDepth`, `branchesPerNamespace`, retries, taken names) and `GET /ns/{ns}/branches`. A branch reads resources without entries of its own through its base as of `at`, recursively: heads, revisions, `/raw`, blobs, `/heads` pages and resource logs, which cross the foreign parent. First writes, deletes and batch steps take the base's head as their foreign parent. A batch with a local `source` may reference the source's blobs, so merges carry them. Each namespace is its own Durable Object, so a branch asks its base's object over internal requests (`/internal/…`, never forwarded by the front Worker) and keeps the answers, which never change.
- Grants (Addendum C), with `AUTH = "grants"` (see Authentication below):
  - **Tokens:** Biscuit v3 grants are verified per §C.8 against all the Addendum I.14 vectors (`crates/core/src/grant.rs`, Ed25519 verified strictly).
  - **The order of §7 and §C.2:** `grantSize` and `rulesPerGrant`, then the `ns` check (`403`), then verification against the namespace's `keys` or the deployment's operator keys. Verification covers times, `revoked` and the key scope (`can`, `maxTtl`, `sub`, `groups`, `roles`, `attrs`, `rules`, `readScope`).
  - **Writes:** verbs are checked at gate step 1, with candidate verbs for `PATCH`, batch items and blob uploads. All key, block and role rules are checked at step 6, before the namespace rules.
  - **The `*`-key guard** applies to config writes and to a branch's `patches`. Namespace rules also judge config writes made without a `*` key.
  - **Reads of a namespace that isn't public:** `/ns/…` needs unrestricted `read`; a resource is `404` without `read`. Reads of public namespaces ignore grants.
  - **Creating a namespace** takes an operator grant.
  - **Log entries** record `grant: { id, sub, kid }` and `via`. Retries must come from the same `sub` and `kid`.
  - **Endpoints:** `GET /ns/{ns}/grants/{gid}` and `GET /ns/{ns}/principal`. Operator keys are published at `/.well-known/patchlog-keys` and named by `GET /`.
  - **Namespace documents** accept `keys`, `roles` and `revoked`.
- Edge grants (§C.5.2–§C.5.4): `POST /edge-grants` exchanges grants for cookies, one per smallest edge prefix the grant allows. The cookies are in §C.5.3's default format, HMAC-SHA256 with `EDGE_KEYS`, and match the Addendum I.5 vector. The origin verifies them on `GET` and `HEAD` without `Authorization`, long-polls included. `DELETE /edge-grants` withdraws them.
- CORS (§7, browsers): origins in `CREDENTIALED_ORIGINS` are named, with `Access-Control-Allow-Credentials: true` and `Vary: Origin`. Every other origin gets `*`, except that `/edge-grants` preflights are allowed only for listed origins. Preflights answer from the front Worker with the methods and headers §7 lists and `Access-Control-Max-Age`; every response, errors and cache hits included, carries `Access-Control-Allow-Origin: *` and the exposed headers.
- The vectors of Addendum I.1 (canonical JSON), I.2 (ids) and I.3 (blob ids).

## Authentication

The deployment in `wrangler.toml` runs with `AUTH = "grants"` and one operator key, `operator-1`, whose seed its owner keeps. With `AUTH` anything else, authentication is off (§1) and writes name their author in `X-Author`. A deployment turns it on by setting `AUTH = "grants"` and giving the deployment's operator public keys in `OPERATOR_JWKS`, a JWK Set (§C.4: OKP Ed25519 keys with `kid`, `use: "sig"` and `patchlog: { from, until? }`). Only public keys are configured. Namespaces are then created with an operator grant whose genesis document lists the namespace's own `keys`, and everything else uses grants signed by those.

Edge grants need `EDGE_KEYS`, a secret JSON array `[{ "kid", "key" }]` of HMAC keys in hex, newest last (`npx wrangler secret put EDGE_KEYS`). Pages that send cookies need their origin in `CREDENTIALED_ORIGINS`, a JSON array. With origins listed, cookies are `SameSite=None; Partitioned` (CHIPS), since a page on another site sends them as third-party cookies. Without keys, `/edge-grants` answers `404 not_offered`.

**A verifying edge** (§C.5.3, §9) lets a CDN cache private namespaces. `edge/bunny/middleware.ts` is one for Bunny, an Edge Scripting middleware:
- It checks the edge-grant cookie on every request, cache hits included.
- It gives verified reads a cache key of their own.
- On a miss, it forwards them with `X-Edge-Verified` (the secret it shares with the origin, `EDGE_VERIFY_SECRET`) and `X-Edge-Prefix`.

The origin answers such reads with the public lifetimes in `CDN-Cache-Control`. Clients still see `private`, and Cloudflare's own cache gets `no-store`. Without `EDGE_VERIFY_SECRET`, no read counts as verified. `node edge/bunny/test.mjs` tests the script against `npm run dev:grants`.

Behind a CDN that ignores `Vary: Origin`, as Bunny does, a cached public response keeps the CORS headers of the request that filled it. Pages on credentialed origins should read public namespaces without credentials, or the CDN's cache key should include `Origin`. The CDN must also forward `Cookie` and pass `Set-Cookie` through.

`crates/grant` is a command-line tool for development and issuers:
- `patchlog-grant keygen` makes a key pair;
- `patchlog-grant mint --seed … --root '<json>' [--block '<json>']` signs a grant;
- `patchlog-grant attenuate` adds a narrowing block;
- `patchlog-grant inspect` shows a token's blocks, grant id and revocation ids.

`bench/auth-smoke.mjs` runs the grant checks against a local deployment with fixed development keys (its header has the command).

## Client

`client/patchlog.mjs` is a small `fetch`-based client (browsers and Node) with `load`, `loadRevision` and `save`. `save` does the rebase of §11: on `412` it takes the head the server names and resends the same patch set, then reads the result by its pinned revision URL. Head pointers may be up to a second stale behind a CDN (§9), so an editor that saves with `If-Match` on a head it just read will sometimes get `412` right after someone else's write; the rebase turns that into one extra round trip. Revision URLs are immutable, so no cache can serve a stale one. Start a patch set with `test` ops of the values it relies on, and a rebase onto changed data fails with `422` instead of overwriting.

## Not yet

Roughly in order of how much they change the design:

- **Grants beyond the core:**
  - author signatures and `signatures: "required"` (§C.3.1);
  - a verifying edge (§C.5.3, §9): private reads are `no-store` at CDNs, and edge-grant cookies are checked by the origin;
  - the `exchangeRate` limit on `POST /edge-grants`;
  - `requireAt` and `maxLag` (keys with `requireAt` are refused);
  - rate limits and `allowances` (§6.6);
  - keys and revocations that follow a branch's base (§C.4): a branch has the keys copied at its creation;
  - the per-resource filtering of the gesture listing (it needs unrestricted `read`);
  - grants recorded by a branch's bases in `/grants/{gid}`;
  - read permission on schema revisions in other namespaces (§6.1).
- **Schemas, beyond the core** (§6.1): `schemaReads`, drafts in branches, read permission on schema revisions (with authentication off, every revision is readable), and the `in_use` refusals (there is no purge yet). `idn-hostname` and `idn-email` are checked as the `jsonschema` crate does, which may differ from RFC 5890 without UTS 46 mapping in edge cases.
- Purge (§8.3, §8.5) and pruning (§8.6), and so removing unreferenced blob bytes from R2; SSE (§7.3), `/principal`, credentialed CORS (edge grants, §C.5.2).
- Branches beyond the local core: remote branches (§G.3), `drafts`, checking that `successor` names a namespace and the branch limit on unfreezing. Creating a branch writes in two objects; a retry completes one that failed half-way.
- Blobs beyond the core: copies across namespaces, `blobRate`, uploads above 32 MiB.
- Addenda A, B, E, F, G and H.
