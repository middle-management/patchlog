# patchlog

This is the **reference implementation** of the **Patch Log** specification. The
canonical text of the specification is maintained outside this repository;
[docs/SPEC.md](docs/SPEC.md) mirrors it, and deltas the reference takes that the
text doesn't yet describe are collected for its writer in
[docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) — when the two disagree, the
reference and this README are what implementations are measured against, and the
mirror follows.

Each resource is an append-only log of content-addressed JSON Patch sets. The server
validates documents that opt in with `$schema`, enforces namespace rules and grants,
and serves immutable, CDN-cacheable revisions.

## What's implemented

| Area | Spec | Status |
|---|---|---|
| I-JSON input, JCS canonical form, base32 ids (`1…`) | §3 | ✅ |
| Revisions, tombstones, namespace chain, names grammar, canonical URLs | §3.3–§3.6 | ✅ |
| Opt-in `$schema` validation (JSON Schema 2020-12, format assertions, strict refs, unknown keywords rejected, a schema document's top-level fresh `$nonce` aside); `schema import` brings in external schemas (e.g. schemastore) with refs pinned | §6.1–§6.3, §6.5 | ✅ |
| Draft schema revisions in branches (`drafts.for`, repeated `Source-Authorization`), `in_use` by last available copy | §6.1, §7.4 | ✅ |
| Releases across namespaces: release documents, the four-step release merge (plan, approve, resume), release rebases, release previews, janitor ordering; catalog merge grants | §F.9, §F.8, §B.5 | ✅ (`patchlog merge release`, `tree -release`, `POST /merge-grants`; see [Releases across namespaces](#releases-across-namespaces-f9)) |
| Change envelopes, rule engine (`test`, `writes`, `compare`, `all`/`any`/`not`/`if`) | §6.4 | ✅ |
| Limits (configurable, deployment maximums) and token-bucket rate limits | §6.6 | ✅ |
| Reads, writes, gate order, `412`/`428`, idempotent retry, paged log ranges (`X-Log-Next`) | §6.2, §7.1–§7.2 | ✅ (`serve -log-page-size`; see [Design notes](#design-notes)) |
| SSE events, long-poll with cursors | §7.3, §7.7 | ✅ |
| Namespace documents (the spec's members validated strictly, others must start with `x-`), log, `/heads` (byte order of name), `/branches` | §7.4 | ✅ |
| Atomic batches (multi-step items, config changes, dry run, retry) | §7.5 | ✅ |
| Gestures for undo and redo: `Gesture`/`Undoes` on writes and batch steps, in logs, `GET /ns/{ns}/gestures/{gesture}`, carried by merges and bundles | §7.2, §7.4, §7.5, §F.3, §G.4.1 | ✅ (server, tooling, client library, and the undo/redo procedure of §11.2 in the client and the playground; see [Undo and redo](#undo-and-redo-112)) |
| Local branches: read-through, foreign parents, keys follow the base (the base's current keys work in its branches) | §7.6, §C.4 | ✅ |
| `schemaReads`: schemas follow their documents into listed namespaces | §6.1 | ✅ |
| Edge grants as cookies: `POST /edge-grants`, withdrawn with `DELETE /edge-grants`, verified by the origin without an edge | §C.5, §9 | ✅ |
| Required nonces: `"nonce": "required"`, `422 nonce` at gate step 3 (sealed namespaces too), kept by branches and remote branches, required by a base only once its branches require them (`409 in_use`), added by undo, merges, imports, schema import and release tools, and by writers that can't read the setting in private namespaces | §C.7 | ✅ |
| Tombstone, restore, purge (with propagation), freeze, namespace purge | §8.1–§8.5 | ✅ |
| Pruning with horizons, protected revisions, kept documents, archives and retention | §8.6 | ✅ (file:// archives) |
| Blobs: uploads, copies (`Blob-From`, `Source-Authorization`), pending entries and `blobGrace`, availability (bases, batch sources), attach at write, ranges, purge and pruning (`410`, archived as blob lines, back on restore), bundle blob lines, mirrored by remote branches | §7.8, §G.3, §G.4.1 | ✅ (bytes in files under `-blob-dir`, encrypted per resource at rest; sealed and e2e specifics to come) |
| Cache-Control classes and cache tags | §9 | ✅ (tag purges over HTTP with `-purge-url`, default: log; a local Varnish CDN in the compose stack; private content cached at the edge only with `-edge-secret`) |
| Grants (Biscuit v3, §C.8), narrowing, sealing, roles, attributes, key scopes, revocation | Addendum C | ✅ |
| Remote branches: registration (`export`), mirroring with verification, schema mirroring, purge notices, bases that are branches, sealed and e2e bases | §G.3, §G.5.2 | ✅ (mirrored up front) |
| Bundles: history and snapshot export and import, sealed bundles, access levels, e2e ciphertext | §G.4, §G.5.1 | ✅ (`patchlog export/import`) |
| Storage layout | Addendum D.2 | ✅ SQLite (pure Go, `modernc.org/sqlite`) |
| Encryption at rest, cryptographic purge | Addendum E.1 | ✅ (local master key file; KMS adapters to come) |
| Sealed for delivery: epoch keys, JWE responses, `POST /ns/{ns}/keys`, rotation, `$nonce` | Addendum E.2 | ✅ (client library decrypts; other consumers don't re-seal yet) |
| End-to-end: sealed patch sets, header checks, blind rules, fold reads, keyring relay, sealed prune snapshots | Addendum E.3 | ✅ (client library seals, folds, validates and administers keyrings; merge refuses; export and remote branches carry ciphertext) |

### Not implemented

- **Addendum B:** preview access computed from a catalog branch by the catalog service itself
  (§F.8; a release preview, `tree -release`, serves branch listings without roles), a `groups`
  namespace, signed manifests and `x-tree-label` titles.
- **§F.7 merge service** (scheduled merges, web status): not built. Its logic is in
  `internal/merge` and the CLI.
- **Addendum E.3 gaps:** merging or rebasing e2e branches (§F.8: decrypt and re-encrypt in a
  client holding both keyrings) and snapshot bundles of e2e namespaces (§G.5.1: a sealed
  genesis by a key holder) are refused; retention for e2e
  namespaces needs a key-holding janitor, which isn't built (the server skips them); no
  size-bucket padding (§E.4).
- **Addendum E.2 gaps:** consumers that re-publish (search index, tree and catalog services)
  don't seal what they serve yet (§E.2.5), so don't point them at sealed namespaces unless
  their own output is private; importing plaintext into an e2e target (sealing each patch set
  with the target's keys, §G.5.1) isn't done; no size-bucket padding (§E.4).
- **Addendum G** (federation): lazy read-through, mirroring pinned `x-ref` targets, and
  remote branches of a base that is itself a remote branch (§G.3). Bundles (§G.4) are implemented
  as `patchlog export/import`; merging a remote branch back is a bundle or merge-tool task.
- **Archives other than `file://`** (§8.6), e.g. object storage.
- **Blob gaps** (§7.8): bytes live in files on a local or shared filesystem (`-blob-dir`, see
  [Blob storage](#blob-storage)), not in object storage (D.2, D.8); importing a private or
  sealed source into an e2e target, which re-encrypts each blob and rewrites its references to
  the new ids (a MAY of §G.5.1, for a client holding the target's keys), isn't implemented; no
  resumable uploads. Ranges of sealed blobs are served over the sealed bytes (§E.2.2), so a
  download resumes, but a range can't be opened on its own. A branch keeps its stored sealings
  of a base's blobs after the base prunes them (it stops serving them; deleting them is a MAY
  of §E.2.2 not done).
- A CDN edge that verifies edge grants (§C.5): none is included. The origin issues them as
  cookies and verifies them itself, and checks grants on every read. Both §9 deployments are
  supported: behind a grant-verifying edge (`-edge-secret`) private content gets edge
  lifetimes, otherwise it is `no-store` for shared caches (see
  [Private namespaces and the edge](#private-namespaces-and-the-edge)).
- Author signatures (§C.3.1): a signature whose kid the grant's root `signers` lists is
  verified at the gate (`422 signature`); others are stored unverified. See
  [Author signatures](#author-signatures).

## Releases and images

CI (`.github/workflows/ci.yml`) runs gofmt, vet, the tests and a Docker build on every push and PR.
`.github/workflows/release.yml` publishes:

- **On a tag `vX.Y.Z`**: a GitHub Release with binaries for linux, macOS and windows (amd64 and
  arm64) and a checksum file, and the image `ghcr.io/middle-management/patchlog:X.Y.Z`, `:X.Y` and
  `:latest`. A tag with a `-` (`v0.2.0-rc.1`) is a prerelease: no `:latest` or `:X.Y`.
- **On every push to main**: `ghcr.io/middle-management/patchlog:edge` and `:sha-<commit>`.

The image holds the one `patchlog` binary (entrypoint), runs as a non-root user with its data in
`/data`, and serves on 8080. As a backend for another project:

```sh
docker run -p 8080:8080 -v patchlog-data:/data ghcr.io/middle-management/patchlog:edge \
  serve -dev -addr=:8080 -db=/data/patchlog.db -origin=http://localhost:8080
```

```yaml
# compose.yaml in the other project
services:
  patchlog:
    image: ghcr.io/middle-management/patchlog:edge   # or a released :X.Y.Z
    command: [serve, -dev, -addr=:8080, -db=/data/patchlog.db, -origin=http://localhost:8080]
    ports: ["8080:8080"]
    volumes: [patchlog-data:/data]
volumes:
  patchlog-data:
```

`-dev` turns authentication off (`X-Author` names the author), for development only: every
request then counts as holding a `*` key, so config guards and forced purges are open and
config writes skip namespace rules (resource writes are still checked), and namespace entries
record `"grant": null` (§1, Conformance). `GET /` says which mode a deployment runs in
(`"auth": "disabled"` or `"grants"`), and the merge tools and the janitor read it from there.
Without it, give `-operator-key` and use grants (Addendum C). `patchlog version` prints the build's version.
While the package is private, pulling needs `docker login ghcr.io` with a token that can read
packages.

## Running the whole stack

```sh
make up        # or: docker compose up --build -d
```

On hosts where Docker can't create network namespaces (a Fly.io sprite, some VMs and CI runners;
`bind-mount /proc/…/ns/net …: permission denied`), use `make up-host`, which layers
`compose.host.yaml` over it: host networking, the same ports, and no `docker exec` healthchecks.
On a sprite the stack's URL (`https://{sprite}-{org}.sprites.app`) routes to the CDN on 8080; pass
`PATCHLOG_ORIGIN` with that URL so generated links point there.

This starts the core server in dev mode, seeds a few demo namespaces and documents, and runs the
search index, the tree service and the branch janitor, all behind a local CDN (Varnish, see
[The local CDN](#the-local-cdn-9)):

| URL | What |
|---|---|
| http://localhost:8080 | core API |
| http://localhost:8080/playground/ | web playground |
| http://localhost:8081/demo?q=derby | search index (Addendum A) |
| http://localhost:8082/cat/roots | tree service (Addendum B): the catalog `cat`, a tree |
| http://localhost:8082/topics/roots | the same service: the catalog `topics`, a DAG |
| http://localhost:8080/playground/tree/cat/roots | the same, through the core's read-only proxy (`-tree-url`) |
| http://localhost:8080/playground/index/demo?q=derby | the search index, through the core's read-only proxy (`-index-url`) |
| http://localhost:9080, :9081, :9082 | the core, search and tree origins directly, bypassing the CDN |

The seed creates `schemas`, `demo` (a few matches, with catalog roles), two catalogs of `demo`,
`private` (sealed, E2) and `vault` (end-to-end, E3: create its keyring from the playground's Keys
tab). The catalogs:

- `cat`, `mode: tree` (one parent per node, §B.6): folders, placements, `$access`, an embargoed
  folder with `inherit: false`, and one dangling placement.
- `topics`, `mode: dag` (the §B.6 rules without `maxItems: 1`): a `derbies` folder under both
  `stockholm` and `rivalries` (a diamond from the root), another diamond `competitions` →
  `league` | `cup` → `big-games`, items placed under several folders, ordering keys, and
  `$access` that differs by path, so an item's effective roles are the union over its paths
  (§B.11.2). `/r/demo/derby` is under `derbies` and the embargoed `editorial` (`inherit: false`):
  `group:catalog-admins`' desk on the root reaches it only around `editorial`. `loop-a` and
  `loop-b` are each other's parents: the tree service flags that cycle under
  `/topics/problems` and lists neither. [deploy/seed.sh](deploy/seed.sh) draws the whole DAG.

One tree service serves both (`-catalog=cat -catalog=topics`), each at `/{catalog}/…` with its own
database.

Spec v0.46 additions to the catalog and tree services:

- **Item titles (§B.5).** `catalog.title` is a JSON Pointer (the core rejects anything else); the
  service copies the string at that pointer in each item's head into listings as `title`, for
  items of namespaces that are neither sealed nor end-to-end. A placement's own `title` wins;
  changing the pointer re-reads every head.
- **`?min` on `POST /grants` and `POST /read-grants` (§B.11.4).** `?min={ns}:{ns_id}`, repeatable:
  the grant is decided at a checkpoint at or past every `min`, else `503` with `Retry-After`.
- **`$access.inheritPowers: true` (§B.11.2).** Tree powers (`move`, `place`) collected on the walk
  up apply at that folder too; moves stay bounded by no widening.
- **Read grants** are core grants fixed to one resource (`/resource` tested, read only, one
  namespace), so the origin's `POST /edge-grants` (§C.5) can exchange them for cookies.

- `make logs` follows the logs.
- `make seed` re-runs the seed, which is safe to repeat.
- `make down` stops the stack and keeps its data; `docker compose down -v` wipes it.
- Data lives in the `data` volume: databases, pruning archives, and the at-rest master key,
  which is created on first start.
- Ports and the origin can be changed with `PATCHLOG_PORT`, `INDEX_PORT`, `TREE_PORT` (the
  CDN's), `CORE_DIRECT_PORT`, `INDEX_DIRECT_PORT`, `TREE_DIRECT_PORT` (the origins') and
  `PATCHLOG_ORIGIN`.
- Without Docker, `make dev` runs just the core server, and `make check` runs vet, the tests and
  a gofmt check.

### The local CDN (§9)

The design is CDN-first, so the stack runs one: Varnish (`cdn` in compose.yaml, configured by
[deploy/varnish/default.vcl](deploy/varnish/default.vcl)). One `varnishd` listens on 8080, 8081
and 8082 and picks the core, search or tree origin by listener. Reads and writes both go
through it; writes are passed. `make cdn-check` shows it working against the running stack:
an immutable revision MISS then HIT, a head pointer micro-cached across an append, five
long-poll followers collapsed onto one origin request, and a resource purge evicting its
cached revision.

**What is cached, and for how long.** Whatever the origin allows, for as long as it allows:

- The edge lifetime comes from `CDN-Cache-Control` (RFC 9213) when the origin sends it, else from
  `Cache-Control` (`s-maxage`, then `max-age`). `no-store`, `no-cache`, `ttl 0`, error statuses and
  responses without any `Cache-Control` aren't cached. `Vary` is honoured.
- So, per §9: immutable revisions, logs, search results and tree listings for a year; head
  pointers (`302`) for 1 s; unknown-id `404`s for 5 s; long-poll answers for their interval
  (`200`) or 2 s (`204`).
- Grace, the time a stale copy is served while it is refetched (or while the origin is down), is
  the response's `stale-while-revalidate` and nothing else: 5 s for head pointers, none for the
  rest. §9 grants no `stale-if-error`, and a stale long-poll answer would end a wait early.
- Identical concurrent misses wait for one origin request (Varnish's waiting list): this is what
  collapses long-poll followers (§7.7). Event streams (`…/events`) are passed and streamed.
  Backend timeouts are 75 s, above the long-poll interval (20 s) and the SSE keep-alive (30 s).

**Headers.** Clients get `Cache-Control` exactly as the origin sent it (so browsers keep
immutable content a day, not a year), plus `X-Cache: HIT | MISS | PASS` and `Age`.
`CDN-Cache-Control`, `Cache-Tag` and `Surrogate-Key` are stripped. With the request header
`X-Cache-Debug: 1` they are kept, and `X-Cache-TTL`, `X-Cache-Grace`, `X-Cache-Hits` and (for
uncached responses) `X-Cache-Reason` are added:

```sh
curl -sI -H 'X-Cache-Debug: 1' http://localhost:8080/r/demo/derby -L | grep -i -E '^(x-cache|cache-tag|age)'
```

**Purging.** `patchlog serve`, `index` and `tree` take `-purge-url URL` (repeatable; compose
passes `http://cdn:8080/`). Without it purges are only logged, as before. With it, each tag purge
(resource purge `r:{ns}/{name}`, namespace purge `ns:{ns}`, the services' `idx:{ns}` and listing
tags) becomes

```
PURGE / HTTP/1.1
X-Purge-Tags: r:demo/derby ns:demo
```

sent asynchronously by [internal/cdnpurge](internal/cdnpurge): tags are queued (bounded),
coalesced, batched (64 tags or 2 KiB per request), retried with backoff and flushed on shutdown
for up to 5 s. The write path never waits for the CDN; a purge the CDN never takes is logged.
The VCL accepts `PURGE` or `BAN` from loopback and private (Docker) addresses only. That
includes the host through the published port, and machines on a private LAN, since compose
publishes on all interfaces: fine for development, not for exposure. It bans every object whose `Cache-Tag` lists any
of the tags as a whole token (`ns:dem` doesn't purge `ns:demo`; tags are matched literally).
By hand:

```sh
curl -X PURGE -H 'X-Purge-Tags: r:demo/derby' http://localhost:8080/
```

A config write that makes a namespace's content non-public-cacheable (`read` from `public` to
`grant`, unless the namespace is sealed or e2e, which stay publicly cacheable) purges `ns:{ns}`
after it commits (§9), so no public copy outlives the change at the edge.

#### Private namespaces and the edge

§9 caches private (non-public, non-sealed) content at the edge only behind an edge that
verifies grants, and the origin must know which deployment it is in:

- **Without a verifying edge** (the default, and the compose stack: Varnish verifies nothing),
  private responses carry `Cache-Control: private, …` plus `CDN-Cache-Control: no-store` and
  `Surrogate-Control: no-store`, so no shared cache stores them. The origin checks the grant on
  every request. Public and sealed responses are unchanged.
- **With a verifying edge**, give `patchlog serve` the secret the edge sends once it has verified
  a request: `-edge-secret FILE` (the file's content, surrounding whitespace ignored), in the
  header `-edge-header` (default `X-Edge-Verified`). Private reads that don't carry it are
  refused with `403 {"code":"edge_required"}` (`no-store`); the secret is compared in constant
  time. Verified private responses get the §9 edge lifetimes in `CDN-Cache-Control`. The edge
  must strip the header from client requests and set it itself.

  What is gated: every cacheable read of a private namespace (resource and namespace heads,
  revisions, logs, heads pages, branch lists, unknown-id `404`s, `410`s, long-polls, which are
  refused before they wait). Not gated, because no shared cache ever stores them (`no-store`)
  and the origin checks their grants itself: writes, batches, config writes, purges, `POST
  /ns/{ns}/keys`, event streams (SSE), error answers such as `401`/`403`, and schema revisions
  read under `schemaReads` by a reader of a referrer (§6.1). Those carry the grant in
  `Authorization`, or none for a revision a public referrer pins (v0.49), so an edge that
  knows only prefixes forwards them undecided, and they are served `private, max-age=300` and
  `no-store` for shared caches. Public and sealed reads never need the header.

  `patchlog index` and `patchlog tree` take the same two flags for their private listings
  (§A.4, §B.11.5): without `-edge-secret` those are `no-store` at the edge, with it they need the
  header and get their edge lifetime. Their private head pointers depend on the caller's grant
  and stay `no-store` either way.

```sh
head -c 32 /dev/urandom | base64 > edge.secret   # shared with the edge's configuration
patchlog serve -edge-secret edge.secret           # the edge sends X-Edge-Verified: <secret>
```

**Edge grants as cookies** (§C.5). `POST /edge-grants` with a grant in `Authorization` answers
`{ "prefixes": [...], "exp" }` (`no-store`) and sets one cookie per prefix: `/r/{ns}` and
`/ns/{ns}` per namespace the grant names, or `/r/{ns}/{name}` when its read rules fix
`/resource`. `"*"` and a grant without `read` are `403`, and so is one whose blocks or key
scope refer to `/resource` without fixing it, or to `/now`, since the edge evaluates no rules.
A grant with roles needs one role that lists `read` and qualifies: none of its rules refers to
`/resource` or `/now`, and they pass now for the principal. Roles are alternatives, so one is
enough, with the blocks and key scope on top; a role that tests `/resource` never qualifies,
even next to blocks that fix it. The answer is all or nothing: if any namespace the grant names
doesn't exist, is purged or refuses it, no cookie is set, and the request is `401` if any
namespace's answer is, else `403`. A purged namespace is decided last, once the grant verifies
and may read there, so the answer is `410 purged`, with the `head` of the first one the grant
names, only if every refusal is a purge (v0.49). While authentication is disabled (`-dev`),
issuance is `404 not_offered`. Cookies are
`Secure`, `HttpOnly`, named `__Secure-pl-eg-…` per prefix, with `Path` the prefix, which covers
what lies below it by whole segments (`/ns/{ns}` covers the namespace URL itself and
`/ns/{ns}/…`, not `/ns/{ns}-x`), and last until the grant's `exp` or 15 minutes, whichever is
sooner. A read under one checks its expiry, so an event stream opened under a cookie ends
there. One authorises `GET` and `HEAD` under its prefix only, on requests without
`Authorization`; never writes, `/edge-grants` or the services. The origin verifies them itself
(an HMAC over prefix, namespace, resource, subject and expiry), so they work without a verifying
edge; behind one, reads still need `-edge-header`, and the key is derived from `-edge-secret` so
the edge can verify the same cookies. `-edge-grant-key FILE` sets the key otherwise (default:
random per process). Pages on another origin call it with `credentials: "include"`: list them
with `-cors-credentials-origin` (repeatable), which names the origin from that list with
`Access-Control-Allow-Credentials: true` and `Vary: Origin`, even when `-cors-origin` is `*`, and
makes the cookies `SameSite=None` (otherwise `Lax`). `DELETE /edge-grants?prefix=…` (v0.48;
`prefix` repeatable, as `prefixes` returned them) withdraws them at sign-out: `204`,
`no-store`, an expired cookie of the same name and attributes per prefix (a repeated one once),
no grant needed, and the same with authentication disabled, so sign-out works either way. No
`prefix`, or one of another form, is `400 bad_input`; `prefix` is the core's one repeatable
parameter (§7). Only credentialed origins may preflight it, so another site can't sign a reader
out. It clears the browser's copies only; a copied cookie lasts until it expires.

**Bypassing it.** The origins answer directly on 9080 (core), 9081 (search) and 9082 (tree).
`make cdn-restart` restarts Varnish, which reloads the VCL and empties the cache.

**Limitations.**

- **No edge grants (§C.5).** A real deployment's edge verifies an edge grant on every request to
  a non-public namespace and serves the cached copy to anyone who holds one. This CDN verifies
  nothing, so compose runs the origins without `-edge-secret`: private responses come with
  `CDN-Cache-Control: no-store` and pass (`X-Cache: PASS`). The VCL also refuses to cache
  responses marked `Cache-Control: private` whatever `CDN-Cache-Control` says (belt and braces;
  the only exception is a response that also says `Vary: Authorization`, which is cached per
  credential). Private namespaces therefore work through the CDN but get no caching and no
  long-poll collapsing. Public and sealed (E2) namespaces are cached fully: a public namespace
  answers a request carrying a grant exactly as one without (§7), so such requests are looked
  up in the cache too.
- Head pointers can lag a write by up to 6 s (1 s TTL plus 5 s of stale-while-revalidate), as §9
  intends; clients that need their own write read the revision from `Location` or pass
  `?min=` to the services.
- Varnish resolves the origins' host names when it loads the VCL. If an origin container is
  recreated with a new address, restart the CDN.
- Purges are best effort: if Varnish is down longer than the retries last, the tags are
  dropped (and logged), and copies stay cached until their TTL.

## Running

```sh
go build -tags grpcnotrace -o patchlog ./cmd/patchlog   # the tag only trims the binary (~3.8 MB)

# Development: no authentication; X-Author names the author.
./patchlog serve -dev -db dev.db

# With authentication: create an operator key for bootstrapping namespaces (§C.4).
./patchlog keygen                     # prints a public and a private key
./patchlog serve -db prod.db -origin https://cms.example -operator-key <PUBLIC>
```

### Postgres (Addendum D.8)

SQLite is the default. Give `-db` a Postgres URL instead of a file (or set `PATCHLOG_DB`, which
keeps the password out of the process arguments), and the core stores everything there:

```sh
PATCHLOG_DB='postgres://patchlog:secret@db.internal:5432/patchlog?sslmode=require' \
  ./patchlog serve -origin https://cms.example -operator-key <PUBLIC>
make up-pg     # the compose stack with a postgres:16 container (compose.postgres.yaml)
```

- **Schema.** Created on first start (and migrated by later versions) under an advisory lock, in
  whatever schema the URL's user defaults to (add `search_path=…` to the URL for another). It
  mirrors the SQLite layout (`internal/core/pgschema.go`): bigint identity keys, 20-byte
  `bytea` ids, canonical JSON in `text` (never `jsonb`, which would change the bytes ids are
  computed over), integer millisecond timestamps. Patch sets, head and intermediate snapshots
  and grants are `bytea`, because encryption at rest stores binary rows there.
- **Reads** run in `REPEATABLE READ READ ONLY` transactions (one snapshot, as in SQLite's WAL
  mode); writes in `READ COMMITTED`, serialised as described below.
- **Purged content.** There is no `secure_delete`: a purge deletes or nulls rows, but the old
  tuples stay in the table files until `VACUUM` reclaims them (autovacuum does, eventually; run
  `VACUUM` on `revisions`, `heads`, `snapshots`, `sealed` and `deks` after a purge that must be
  gone from disk now), and in WAL archives and backups until they expire. With encryption at
  rest (Addendum E.1) a purge also destroys the data keys, which makes those leftovers
  unreadable: use it where purges must be final. Blob files are deleted, not erased (see
  [Blob storage](#blob-storage)).
- **Blob files** need `-blob-dir` (or `PATCHLOG_BLOB_DIR`), a directory every instance mounts
  (a shared volume, NFS, …). Without it the core logs so at startup and keeps blob bytes in
  the database (`bytea`), as before; mixing is possible (rows say where their bytes are), but
  an instance without the directory can't serve bytes stored in files.
- **Several instances** can share the database (rolling deploys, horizontal scaling). Writes
  take transaction-scoped advisory locks per namespace, `pg_advisory_xact_lock(0x504c, ns)`,
  in ascending order. Writes that change a namespace's configuration or state (config writes,
  purges, prunes, branch operations, freezing, the pending-blob sweep) take them exclusive on
  every namespace they change (the written one; a branch's base, which receives the `branch`
  entry; every branch and remote shadow a purge reaches). Resource writes, batches and blob
  uploads take their own namespace's lock **shared**, like every namespace a decision read
  (bases whose keys and revocations a branch write re-checks, the namespaces `$schema` and
  `$ref` resolve into, a batch source), so writers of different resources of one namespace
  check and insert in parallel, and a namespace's configuration, frozen and purged flags can't
  change under them. Two writers of the same resource settle it on insert: the chain's unique
  constraints, and the resource's head moving only from the one the precondition matched, make
  the loser re-check and answer `412` with the new head (or the idempotent retry), as on
  SQLite. The namespace entry is appended last, under a separate advisory **log lock**,
  `pg_advisory_xact_lock(0x504e, ns)`, taken after every other lock, in ascending order when a
  write appends to several logs (purge propagation, branch creation), and held through commit,
  so entries commit, and their sequence numbers grow, in chain order. A transaction holding a
  log lock never waits for a namespace lock (it tries, and restarts with the lock taken up
  front if that fails). An uploader's pending blob total (§7.8) is ordered by a row of its
  own (`blob_uploaders`), so concurrent uploads can't together exceed `blobPending`. Details in
  `internal/core/pglock.go`.
- **Group commit per namespace** (D.8 "Contention"). Holding the log lock through commit means
  one append and one WAL flush per write per namespace, and writers queueing on the lock add a
  hand-over each, so without more, throughput in one namespace peaks and then falls as writers
  are added. So each instance queues the checked resource writes and batches of a namespace (never
  config writes, purges, prunes, branch operations, or batches that change the configuration),
  and one transaction appends up to `-group-commit` of them (default 32) and commits once:
  - A write is checked first on its own, outside any lock (D.3), and queued. The namespace's
    worker takes the queue, waiting at most `-group-commit-wait` (default 200µs) for writes still
    being checked, takes the shared locks of every namespace the group's checks read, and
    re-checks each write. The writes that pass and write distinct resources go in together, one
    statement per table with rows in resource order, as a batch's items do; only then is the log
    lock taken and their entries appended in queue order, in one statement, each computed from
    the one before it (§3.5). So a group, like any writer, never waits for another writer's rows
    while holding the log lock, and takes part in no deadlock a batch doesn't.
  - A write whose resource's head moved (another instance's write), or that writes a resource an
    earlier write of the group writes, is left out and answered alone after the commit: from the
    idempotent-retry lookup if the same write committed (§7.2), otherwise `412` with the new head.
    One that finds the configuration changed is checked again, as on its own (D.3). The rest of
    the group is unaffected. If inserting the group loses a race to another instance's writer,
    the transaction runs again and the re-checks leave out the writes that lost. An error that
    aborts the whole transaction (a deadlock, `40P01`, a serialization failure) retries the whole
    group; one that persists answers every write alone. A group is cancelled, even while it
    waits for a lock, only once all of its requests are.
  - Every write is answered after the group's commit; caches, live readers and CDN purges hear of
    its writes only then.
  - While no group of a namespace is queued or committing, up to four of its writes take the
    path they take without group commit (checked inside the lock, fewer round trips), so groups
    form only once writers contend. `-group-commit 1` turns it off: every write then commits on
    its own, exactly as before. SQLite has a single writer and doesn't group. Details in
    `internal/core/groupcommit.go`.
- **One writer per namespace.** Groups are per instance: two instances writing one namespace
  each form their own groups, which then contend for the same log lock. With several instances,
  route each namespace's writes to one of them, e.g. by hashing the namespace name in the load
  balancer: it is the second path segment of every write (`/r/{ns}/…`, `/ns/{ns}/…`), so extract
  it with a regex and hash it consistently (nginx `map` plus `hash $ns consistent`, HAProxy
  `balance hdr()` on a header set from the path, Envoy's ring hash). Reads can go anywhere. That instance
  then enforces the namespace's and its resources' whole rate limits (§6.6) rather than a share;
  per-principal limits span namespaces and stay split between instances. Routing is an
  optimisation, not a requirement: writes from any instance stay correct.
- **Round trips.** Each statement is one, so a write costs what its statements cost: about
  13 for a small append (begin, lock, namespace, resource, head, retry lookup, insert, head,
  heads, chain, commit) and 10 for a create, about 3 ms on a local `postgres:16` with `fsync` on,
  against 0.3 ms on SQLite (`go test ./internal/core -run '^$' -bench .` with `PATCHLOG_TEST_PG`
  set). A write on its own is checked inside its namespace's shared lock (`LockedCheckBytes`),
  skipping the separate check transaction of D.3; one that joins a group (below) is checked
  first, outside it. What writers of one namespace still do one at a time is the chain append:
  two statements and the commit's flush, or per group about a dozen statements and one flush. A
  batch inserts its items with one statement per table (over arrays, `unnest`), so 1,000
  creates cost about as many round trips as one.
- **Throughput** (`-bench 'CreatesOneNamespace|Batch1000'`, 20–70 KiB documents to distinct
  resources of one namespace, on 4 vCPUs shared by the benchmark and `postgres:16`): 160
  writes/s from one writer, 440–500 from 8, ~350 from 32 and 64 (where the CPU is saturated),
  against ~160 at every concurrency before writers shared the namespace's lock; p99 at 64
  writers 0.8 s, from 1.1 s. A batch of 1,000 creates takes about 330 ms (1.5 s before), on
  SQLite 250 ms. Writes to different namespaces run in parallel too. Small appends from
  concurrent writers to distinct resources of one namespace (`-bench AppendsOneNamespace`,
  medians of three interleaved runs) show what group commit changes: without it about 250
  writes/s from one writer, 490 from 2, 715 from 4, then falling to 590 from 8, 575 from 16 and
  615 from 32 (p99 165 ms); with it the same up to 4 writers (groups don't form), then 805 from
  8, 1,030 from 16 and 1,650 from 32 (groups of about half the writers; p99 31 ms). Large
  creates are bound by the CPU, where it changes little but the tail (p99 at 64 writers
  0.2–0.45 s, from 0.55–1.7 s).
- **A tailer per instance** polls `ns_log` by transaction id every 100 ms
  (`ns_log.xid xid8 DEFAULT pg_current_xact_id()`, `pg_snapshot_xmin`) and wakes long-polls and
  SSE streams for writes of every instance, and moves the read cache's generations. Commits
  that change what reads may return (configuration, purges, prunes, restores, key
  destruction) also increment a one-row `cache_gen` counter that every poll reads. The
  transaction-free read cache serves only while the tailer's last successful poll is recent,
  so another instance's purge, revocation or configuration change stops being served from
  this instance's memory at most **300 ms** (three poll intervals) after it commits, and head
  pointers are micro-cached for at most that long. A wake-up for another instance's write can
  be later while an older write transaction is still running (the tailer never skips one).
- **Background loops** that must run once per deployment (the retention applier, epoch
  rotation, following and registering remote bases, the blob sweeps, second CDN purges) run on
  the instance holding a session-level advisory lock (class `0x504d`); another one takes over
  when it goes away. Before each step of a job (a resource pruned, a namespace swept, a base
  followed, a purge resent) the leader checks on its connection that it still holds the lock,
  so a leader that lost its session stops; steps are idempotent.
- **Second CDN purge** (D.8). A stale instance, a lagging replica or a response already under
  way may hand the CDN content just purged. So the transaction that commits a CDN tag purge
  (§8.3: resource and namespace purges, a switch to private or sealed, a restore from an
  archive, a remote base's purges) also queues it in `cdn_repurge`, keyed on its namespace
  entry, and the leader sends it again once `RepurgeDelay` has passed (default three tail
  intervals plus two minutes, covering the cache staleness bound, replica lag and the response
  deadline), then deletes the row. SQLite deployments do the same.
- **Keep transactions short.** The tailer can't move past the oldest running transaction in the
  database (its `xmin`), so one left open holds back every instance's wake-ups: set
  `idle_in_transaction_session_timeout` (e.g. `ALTER ROLE patchlog SET
  idle_in_transaction_session_timeout = '60s'`).
- **Per instance:** rate-limit buckets (§6.6), so each instance enforces the limits on what it
  serves (D.8), and the in-memory caches above.
- **Clocks.** Long-poll cursors are interval numbers counted from each instance's own clock
  (§7.7), so keep the instances' clocks synchronised (NTP) to well within the long-poll interval
  (20 s by default), e.g. under a second. Skew never repeats a URL (the `204` rule), but
  waiters near an interval boundary split between two cursors and stop collapsing at the CDN.
  Entry and revision `created` times come from the instance that wrote them, too.
- **The services keep SQLite.** The search index and tree service (`-db index.db`,
  `-db tree.db`) store derived state they rebuild from the core's API; only the core runs on
  Postgres.
- **Tests.** `PATCHLOG_TEST_PG=postgres://postgres@localhost:5432/postgres make test-pg` runs
  the storage-dependent tests with a fresh database per test (`internal/pgtest`); CI does the
  same against a `postgres:16` service container.

### Blob storage

Blob bytes (§7.8) are files under the blob directory; their rows in `blob_bytes` (and stored
sealings' rows in `blob_epochs`, §E.2.2) stay in the database and decide which bytes exist
(`internal/core/blobstore.go`).

- **Where.** `-blob-dir DIR` (or `PATCHLOG_BLOB_DIR`); by default `<db>.blobs` next to a SQLite
  file. `:memory:` keeps bytes in the database, and so does Postgres unless `-blob-dir` is given
  (see above). `patchlog archive restore` takes the same flag. A directory belongs to one
  database: the sweep deletes whatever that database doesn't name.
- **Layout.** `{owner}/{hh}/{sha256}.{random}`: owner `0` for plaintext shared by every resource
  that names the same bytes, else the resource row whose data key encrypts them (encryption at
  rest), `hh` the hash's first two hex digits. Sealings are `e/{ns}/{hh}/{bid}.{epoch}.{random}`.
  The random suffix makes each stored copy its own file, so deleting a collected one never
  races a new upload of the same bytes on another instance.
- **Writes** go to a temporary file in the target directory, are synced, renamed into place
  and the directory synced, before the transaction inserting the row commits; a transaction
  that rolls back deletes what it wrote. **Deletes** (the grace sweep, pruning, purges, a lost
  race for a sealing) happen after the deleting transaction commits. A crash in between
  leaves only orphan files: on the leader, the blob sweep (every ten minutes) also deletes
  files older than an hour that no row names, and stray temporary files.
- **Reads** of plaintext are served from the file, ranges reading only what they ask for;
  bytes encrypted at rest are decrypted whole, sealings are served from their file.
- **Purges.** With encryption at rest a purge destroys the resource's data key, so its files
  are unreadable even before they are deleted. Plaintext files are deleted once the purge
  commits, but deleting a file is not erasing it: its blocks stay on disk (and in snapshots and
  backups) until overwritten, as with Postgres tuples before `VACUUM`. Use encryption at rest
  where purges must be final.
- **Backups** take the database and the directory together: one filesystem snapshot, or the
  database first and then the directory. Files the restored database doesn't name are swept;
  a blob collected between the two copies answers `500` after a restore.
- **Databases from before blob files** need nothing: their rows keep the bytes in the table
  (`file` is NULL) and are served, copied and collected from there; new bytes go to files. To
  move old bytes out, re-upload them, or leave them until they are collected.

### HTTP/2

`serve`, `index` and `tree` speak HTTP/2 without TLS (h2c, prior knowledge) as well as HTTP/1.1.
A page following several logs by long-poll then shares one connection instead of using up the
browser's six per host (§7.7). Browsers only use HTTP/2 over TLS, so put a TLS terminator or
CDN that speaks HTTP/2 in front; it can reach the servers over h2c or HTTP/1.1.

### CORS

Browser pages on other origins (a demo app, a frontend on another port) can call `serve`, `index`
and `tree` once those allow their origin. This is a deployment setting, not part of the spec:

```sh
./patchlog serve -cors-origin http://localhost:5173 -cors-origin https://demo.example
PATCHLOG_CORS_ORIGINS='*' make up     # compose passes it to every server
```

- Preflights (`OPTIONS` with `Access-Control-Request-Method`) are answered by the server. The
  request headers the API reads are allowed (`Authorization`, `Content-Type`, `If-Match`,
  `If-None-Match`, `If-Range`, `Range`, `Signature`, `Source-Authorization`, `Gesture`, `Undoes`,
  `Blob-From`, `Blob-Nonce`, `Last-Event-ID`, and `X-Author`, which names the author under `serve -dev`), and the response headers it sets are exposed (`ETag`, `Location`,
  `Retry-After`, `Content-Range`, `Gesture`, `Undoes`, `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`,
  `X-Cursor`, `X-Log-Next`, …), as §7 "Browsers" lists them; without `X-Log-Next` a page couldn't
  follow a paged log range, and without `Gesture` it couldn't see what a retried write recorded. `-cors-max-age` (default 10m) sets `Access-Control-Max-Age`, how long
  browsers cache a preflight.
- Grants travel in `Authorization`, which a page sets itself, so cross-origin calls need no
  cookies. `-cors-credentials` adds `Access-Control-Allow-Credentials` for pages that do send
  them; it needs explicit origins. `-cors-credentials-origin` lists origins allowed credentials
  on their own, for edge-grant cookies (§C.5); an origin that isn't listed is never echoed with
  credentials. Only credentialed origins (these, or `-cors-origin` ones with
  `-cors-credentials`) may preflight `DELETE /edge-grants`, which withdraws the cookies.
- With `*`, every response allows `*` and exposes the headers, whether or not the request sends
  `Origin`, so responses are the same for every origin and the CDN keeps one copy: one cached
  from a request without `Origin` (curl, a service, a same-origin page) serves cross-origin
  pages too. With a list, the matching origin is echoed and every response says `Vary: Origin`,
  so the CDN keeps one copy per origin and never serves one origin's allowance to another. (The
  library echoes the origin, with `Vary: Origin`, for `*` with credentials too; `serve` refuses
  that combination.)
- The playground's tree and index proxies drop the services' own CORS headers; the core's apply.

### Health checks and graceful shutdown

`serve`, `index` and `tree` answer two paths ahead of their own routes. Both are
`Cache-Control: no-store` and `CDN-Cache-Control: no-store`, and the compose CDN passes them, so
a probe always reaches the origin itself:

| Path | Answer |
| --- | --- |
| `GET /_health` | Liveness and drain state: `200 {"status":"ok"}` while serving, `503 {"status":"draining"}` from the moment shutdown starts. It touches no database, so frequent probes are cheap. Use it for load-balancer and CDN probes and container healthchecks. |
| `GET /_ready` | Readiness: `503 {"status":"draining"}` while draining, `503 {"status":"unavailable","error":…}` when the core can't reach its database (a ping with a 2 s timeout), else `200 {"status":"ok"}`. The index and tree keep local SQLite databases they opened at start, so for them it is the drain state alone. |

The paths start with `_`, which no namespace or catalog name can (§3.6), so they never shadow
the index's `/{ns}` or the tree's `/{catalog}`; they sit beside the services' `/_status`.
`patchlog health [URL]` (default `http://localhost:8080/_health`; `:8081` is short for
`http://localhost:8081/_health`) exits 0 on a 200 and 1 otherwise, so the image needs no curl or
wget for healthchecks.

On SIGTERM or SIGINT a server shuts down in phases:

1. **Drain.** `/_health` and `/_ready` answer 503 and keep-alives are turned off (responses say
   `Connection: close`), so load balancers take the instance out of rotation and clients
   reconnect elsewhere. Requests are still served normally.
2. **Delay.** That goes on for `-shutdown-delay` (default 0): the time a load balancer needs to
   see the 503s, typically a probe interval or two.
3. **Stop.** The listener closes. Long-polls (§7.7) answer at once with their normal "no change"
   `204` and a fresh `X-Cursor`, so clients just poll again; event streams (§7.3, §7.4) end, and
   EventSource reconnects with `Last-Event-ID`; the index's and tree's `?min=` waits answer as if
   their wait had run out. Every other request in flight, writes included, is waited for, up to
   `-shutdown-timeout` (default 30s).
4. **Cancel**, only if that timeout expires: the remaining requests' contexts are cancelled, so
   their transactions roll back (nothing of a cancelled write is stored, and the chains stay
   intact), and their handlers get 2 s more to return.
5. **Close.** Only then does the core stop its background jobs (retention, remote follows,
   epoch rotation), resign leadership and close the database, and the CDN purger flush its queue
   (up to 5 s); the index and tree stop following and close their databases. The database is
   never closed under a running handler.

Each phase is logged, with the requests waited for or cancelled (method, path, age). A second
signal exits at once (exit status 1). Give the process manager's grace period more than
`-shutdown-delay` + `-shutdown-timeout` + about 10 s; compose uses `-shutdown-timeout=20s` with
`stop_grace_period: 30s`. On Kubernetes:

```yaml
spec:
  terminationGracePeriodSeconds: 45     # > delay (5s) + timeout (25s) + ~10s
  containers:
    - name: patchlog
      image: ghcr.io/middle-management/patchlog:X.Y.Z
      args: [serve, -shutdown-delay=5s, -shutdown-timeout=25s, ...]
      ports: [{containerPort: 8080}]
      readinessProbe:
        httpGet: {path: /_ready, port: 8080}
        periodSeconds: 2
        failureThreshold: 1
      livenessProbe:
        exec: {command: [patchlog, health, "http://localhost:8080/_health"]}
        periodSeconds: 10
        failureThreshold: 3
```

Kubernetes sends SIGTERM and removes the pod from its Service endpoints at the same time, so
`-shutdown-delay` keeps the pod serving while kube-proxy and ingress controllers catch up; no
`preStop` sleep is needed (a `preStop: sleep 5` with `-shutdown-delay=0` is equivalent, but its
time also counts against the grace period). Point readiness at `/_ready`; liveness at `/_health`
should tolerate the drain (it answers 503 then), hence the higher threshold.

### Observability (OpenTelemetry)

Every command that talks HTTP or serves it (`serve`, `index`, `tree`, `janitor`, `merge`,
`rebase`, `export`/`import`/`bundle`, `archive`, `schema`) exports OpenTelemetry traces and
metrics when the standard `OTEL_*` environment variables ask for it. **It is off by default:**
with no exporter configured nothing is installed, the HTTP handlers and transports are not
wrapped, and instrumented code costs an atomic load (a cached read measures the same with and
without this support, allocations included). There are no flags.

| Variable | Effect |
| --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns on OTLP export of traces and metrics, e.g. `http://collector:4318` (HTTP) or `http://collector:4317` (gRPC). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Per signal; either alone turns on that signal (a full URL for HTTP, e.g. `…:4318/v1/traces`). |
| `OTEL_EXPORTER_OTLP_PROTOCOL` (and `_TRACES_`/`_METRICS_PROTOCOL`) | `http/protobuf` (default) or `grpc`. `http/json` is not supported. |
| `OTEL_EXPORTER_OTLP_HEADERS`, `_TIMEOUT`, `_COMPRESSION`, `_CERTIFICATE`, `_INSECURE` | As the OTLP exporter specification has them (also per signal). |
| `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER` | `otlp`, `console` (JSON on stderr, for a quick look) or `none`. Set, they decide alone: `otlp` with no endpoint sends to `localhost`; `none` turns a signal off while the other is exported. |
| `OTEL_SERVICE_NAME` | Default `patchlog-<command>`: `patchlog-serve`, `patchlog-index`, `patchlog-tree`, `patchlog-janitor`, … |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, e.g. `deployment.environment.name=prod`. `service.version` is the build's version (`-X main.version`, as release builds and the image set it); host, OS, process id and Go runtime are detected. The command line is not recorded (flags such as `-bearer` carry grants). |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Default `parentbased_always_on`; e.g. `parentbased_traceidratio` with `0.1`. |
| `OTEL_BSP_*`, `OTEL_METRIC_EXPORT_INTERVAL` | Span batching; metric export interval (default 60 s). |
| `OTEL_SDK_DISABLED=true` | Everything off, whatever else is set. |

Context propagates as W3C `traceparent`/`tracestate` and `baggage`, in and out. Spans and metrics
are flushed (up to 5 s) when the command returns, for the servers after their graceful shutdown
(above), so the last requests' spans are not lost; `/_health` and `/_ready` are not traced.

What is instrumented:

- **HTTP servers** (`serve` with its playground and proxies, `index`, `tree`/catalog): a server
  span per request named `{method} {route}`, with the route the matched pattern, never the
  path's ids or names: `GET /r/{ns}/{name}/rev/{id}`, `POST /ns/{ns}/batch`, the index's
  `GET /{ns}`, `GET /g/{gs}/{ns}/at/{at}`, the tree's `GET /{catalog}/at/{at}/children`, the
  catalog's `POST /grants`, `GET /playground/`; requests without one (a CORS preflight, a 404)
  are named by the method alone. Attributes are the HTTP semantic conventions (`http.route`,
  `http.response.status_code`, `url.path`, `client.address`, …) and `patchlog.ns` on the core's
  routes; request and response bodies, the query, `Authorization`, `Source-Authorization`
  and other headers are not recorded. Metrics: `http.server.request.duration`,
  `http.server.request.body.size`, `http.server.response.body.size` by method, route and
  status. Long-polls and event streams count with their real duration (they are long by design;
  read their routes' histograms accordingly).
- **HTTP clients**: `internal/client` (the index, tree, janitor, merge tools and bundles),
  remote branches following other deployments, the CDN purger, the playground's proxies to the
  index and tree, schema fetches and catalog grant requests: a client span per request (named by
  the method), `http.client.request.duration`, and the trace context sent along, so a trace runs
  from the index or tree into the core.
- **Engine writes**, as children of the server span: `core.WriteResource`, `core.Batch`,
  `core.WriteConfig`, `core.CreateBranch`, `core.RegisterRemoteBranch`, `core.Purge`,
  `core.PurgeNamespace`, `core.Prune`, `core.UploadBlob`, with `patchlog.ns`,
  `patchlog.write.kind` (`resource`, `delete`, `batch`, `config`, `branch`,
  `remote_registration`, `purge`, `purge_ns`, `prune`, `blob`), `patchlog.outcome` (`created`,
  `ok`, `replayed`, `dry_run`, or the error code: `stale`, `forbidden`, …), `patchlog.status`
  and for batches `patchlog.batch.items`, `patchlog.dry_run`. A refusal (4xx) is an outcome,
  not a span error. Metrics `patchlog.writes` (count) and `patchlog.write.duration` (s), by kind
  and outcome; the namespace is never a metric attribute.
- **Database transactions**: `core.db.read` and `core.db.update` (with `db.system.name`) inside
  a trace, so a read served from the read cache has none, and Postgres write retries show in
  one `core.db.update`. Background jobs (the tailer, retention, remote follows) are not traced.
  Statement-level SQL spans are not recorded.
- **Postgres**: `patchlog.groupcommit.size` (writes per group commit transaction, D.8) and
  `patchlog.db.lock.wait` (s, by `patchlog.lock` = `ns` or `log`: time waiting for advisory
  locks).
- **Consumers** (index, tree, catalog): `patchlog.follow.units` (units applied, by
  `patchlog.follow.snapshot`) and `patchlog.follow.lag` (s: from the newest applied entry's
  `created` to its application, so catching up shows as large values).

Logs are not exported: the commands log with the standard `log` package, without trace ids.

A local look at traces with the compose stack's `otel` profile (Jaeger, which takes traces but
not metrics):

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318 OTEL_METRICS_EXPORTER=none \
  docker compose --profile otel up --build
# then open http://localhost:16686 (services patchlog-serve, patchlog-index, patchlog-tree, …)
```

For metrics too, point the endpoint at an OpenTelemetry Collector (e.g. `otel/opentelemetry-collector`
with an `otlp` receiver and `prometheus`/`otlp` exporters). For a binary on its own,
`OTEL_TRACES_EXPORTER=console OTEL_METRICS_EXPORTER=none patchlog serve -dev` prints spans to
stderr.

### Playground

`serve` also hosts a web playground at **`/playground/`** (turn it off with `-playground=false`).
It is plain HTML/JS embedded in the binary and talks to the same-origin API. It has:

- a request inspector with every request's preconditions, status, response headers and error body, plus "copy as curl";
- namespace, resource, history, batch and branch editors;
- live SSE feeds;
- scripted examples: conflict and rebase, schema validation, rules, batch delete+restore, branch read-through;
- a **Catalog** tab (Addendum B): the folder tree of a catalog namespace with its placed items
  (linked to the Resource tab), effective roles per subject derived in the browser from `$access`
  (§B.11.2, `inherit: false`, tree powers, `includes` from the content namespace), the listing's
  checkpoint (`at`) and problems (dangling items, orphans, cycles). A picker lists the namespaces
  with a `catalog` config it finds (the tree service's catalogs, the proxy's mappings, namespaces
  used before). In a DAG, a node is listed under each parent, marked shared with the others named
  (a shared folder's children are expanded once and folded elsewhere), a selected node shows every
  path to a root with the roles that path collects (and where `inherit: false` stops it), and
  folders on a cycle are reported, not traversed. It creates folders and places,
  moves, reorders and removes nodes as ordinary writes to the catalog namespace (`If-None-Match`,
  `If-Match`, fresh `$nonce` on placements), then re-reads the tree with `?min=` (read-your-writes):
  tree listings go through the browser's HTTP cache, and `?min={ns}:{ns_id}` from the page's last
  write to the catalog and to each namespace it trusts (`X-Namespace-Revision`) makes a new URL that
  the service answers once caught up (§B.5), instead of `no-store`;
- blobs (§7.8): a document's `$blob` references show as chips (type, size, Open, Download, inline preview
  of images and small text), including sealed (E2) blobs, opened with the epoch's key and an older epoch if
  that is all the reader holds, and E3 blobs, decrypted with the key inside the reference. "Attach file" on
  the Resource tab uploads a blob (with a `Blob-Nonce` in sealed namespaces, encrypted in the browser in E3
  ones) and inserts its reference into the patch set; E3 writes declare their `blobs`, and the fold flags a
  revision whose list is wrong. Only inert types open in a tab; the rest download;
- gestures (§7.2): every save from the Resource editor (and every batch without its own `gesture`) sends a
  fresh `Gesture`, or the last save's again while "same gesture as the last save" is checked; history and
  the namespace log show each entry's gesture and `undoes`, and an **Undo / redo** card on the Namespace tab
  rebuilds the author's stack from the namespace log and undoes or redoes with the procedure of §11.2 (see
  [Undo and redo](#undo-and-redo-112));
- a **Keys** tab (Addendum E): an X25519 identity kept in localStorage (its public JWK goes in a
  grant's `enc`, or into an E3 keyring), the keys held, E3 keyring administration (init, add a
  reader, rotate), a JWE decrypter and a self-test of the page's crypto against vectors made by
  the Go implementation (`selftest.json`).

With keys, the playground decrypts sealed (E2, `application/jose`) documents, namespace documents
and logs, fetching them with `POST /ns/{ns}/keys` (unwrapping HPKE-wrapped keys with the identity)
and checking `kid` and `pl` against the request; the inspector shows the plaintext next to the JWE.
In E3 namespaces it reads the keyring, folds the sealed log in the browser (checking ids, chain and
bindings; revisions that don't open, apply or validate against their `$schema` are flagged, using a
JSON Schema subset) and seals writes client-side with a fresh `$nonce` (padded when the namespace
sets `pad`). All of it is WebCrypto only: HPKE (RFC 9180) is built on X25519, HKDF and AES-GCM in
`internal/playground/static/seal.js`; `go test ./internal/playground` checks it against
`internal/seal` (with node on `PATH`, both ways).

The tree service is another origin, and the playground's CSP allows `connect-src 'self'` only, so
`serve -tree-url http://tree:8082` mounts a read-only reverse proxy at `/playground/tree/`: `GET`
and `HEAD` only (other methods are `405`), `Authorization` forwarded, the service's redirects
rewritten under the prefix, `502` while it is unreachable. compose passes it. `-tree-url` is
repeatable: `CATALOG=URL` sends `/playground/tree/{CATALOG}/…` (and `_status?catalog=CATALOG`) to
a tree service of its own, e.g. a catalog service (`-access`, one catalog each), and a plain URL
takes every other catalog. Without it, the
Catalog tab reads the catalog's documents straight from the core API and says that computed
listings need the tree service. Sealed listings (§E.2.6), whole or per entry, are decrypted when
keys are at hand and shown by name otherwise.

The **Search** tab does the same for the search index (Addendum A): `serve -index-url
http://index:8081` mounts the same kind of read-only proxy (`GET`/`HEAD` only, `Authorization`
forwarded, cookies and the service's CORS headers dropped, redirects rewritten under the prefix,
`502` while unreachable) at `/playground/index/`. One index serves several namespaces, so there is
one URL; it waits up to two minutes for an answer, since a `?min=` query waits for the index to
catch up. The tab picks a namespace (the ones the index's `/_status` lists, or any name), takes `q`
and, under "Filters", the `schema`, facet and range filters (`/league=cup`, `/kickoff>=2026-10-10`,
or the raw `facet[/league]=cup`), `sort`, `counts` and `limit`, and shows each hit's resource,
`$schema`, score, facets and revision, with the checkpoint (`at`) the index redirected the query to
(the browser follows that redirect through the proxy). A resource name opens in the Resource tab;
a facet chip or count adds a filter; "More results" follows `next` (for a `ref=` query without `q`
or `sort`, the result's `at` URL with `after` set to it). "Wait for my last write" sends
`min=` with the `X-Namespace-Revision` of the last write the page made to that namespace, so the
results include it (§A.5). Sealed results (§E.2.6), whole or per hit, are decrypted with the keys the
playground holds; an end-to-end namespace has no server index, and the tab says so. Without
`-index-url` it says that search needs the index service.

The **Schemas** tab imports external JSON Schemas from the browser (see
[Importing external schemas](#importing-external-schemas-61)). Pick a namespace, give URLs and/or
files (a file picker, a drop zone, or a pasted schema with a file name; `$ref`s between the files
are resolved by file name), optionally a root name, and press **Plan**: the core fetches,
converts and compiles as `patchlog schema import` does and answers with the plan, which the
tab shows as a table (source, resource, action, revision path) with the warnings, the cycles that
were merged, and the rewritten schema of each resource. **Import** then writes the plan from the
browser through the normal API, with the grant or author in the page's connection bar: the
plan's items in one `POST /ns/{ns}/batch` (chunked, one batch after another, when beyond the
namespace's limits), `If-None-Match: *` for a create and `If-Match: head` for an append. It
checks that the server assigned the predicted revision ids (and warns if not) and shows the
root's pinned `$schema` path with a copy button and a button that starts a new document with it
in the Resource editor. A second Plan shows every row `unchanged`. Plain (not sealed)
namespaces only.

The plan endpoint, `POST /playground/schema-import/plan`, takes `{ns, sources: [url…], files:
[{name, content}…], name?}` and writes nothing. It reads the current heads in process through the
API handler with the request's own headers (`Authorization`, `X-Author`, an edge secret), so a
caller plans against what their grant may read; a caller who can't read the namespace gets the
API's own refusal before anything is fetched. It answers `entries`, `resources` (with the
converted `content`), `bundled`, `warnings` and `batches` (`items` in the batch wire format, and
the `ids` they are predicted to get); `GET /playground/schema-import/` says whether fetching is on.

**Fetching URLs is off by default**, since it makes the core request what callers name:

| Flag | Effect |
|---|---|
| `serve -schema-fetch` | the endpoint fetches http(s) URLs (and what they `$ref`); without it, uploaded files only (a URL is `403 fetch_disabled`, and the tab says so) |
| `-schema-fetch-hosts a,b` | only these hosts (a name, an IP or `host:port`), redirects and references included; they are trusted with private addresses too, which is how a local schema server is allowed |

Without a host list any public host may be fetched, but a host with an address that is loopback,
private (RFC 1918, `fc00::/7`, CGNAT), link-local (cloud metadata), multicast or unspecified is
refused after DNS resolution, checking every address the name has and connecting to the one
checked. The environment's proxy settings are ignored (the check has to see the address dialled).
The size, document-count (100) and per-fetch timeout (30 s) limits of the CLI apply; a request
body is capped at 16 MiB and 50 files. The demo composes pass
`-schema-fetch -schema-fetch-hosts=www.schemastore.org,json.schemastore.org,raw.githubusercontent.com`.

Run it with `./patchlog serve -dev` and open `http://localhost:8080/playground/`. Sealed and e2e
namespaces need `-master-key FILE -master-key-create`.

### Undo and redo (§11.2)

A client sends a `Gesture` with every write a user action produces (`client.NewGesture`,
`client.WithGesture`, `Step.WithGesture`, `BatchRequest.Gesture`). `internal/client/undo.go` undoes
one from the log, so undo works after a reload, from another device and from a history view:

```go
plan, err := c.PlanUndo(ctx, "docs", g)        // the inverse and the conflicts; writes nothing
res, err := c.Undo(ctx, "docs", g)              // writes it: one batch, Gesture res.Gesture, Undoes g
res, err  = c.Redo(ctx, "docs", g)              // undoes the latest undo of g
st, err  := c.UndoStack(ctx, "docs", "alice")   // st.Done / st.Undone, each item's Target to pass to Undo
```

- **Finding it.** `GET /ns/{ns}/gestures/{gesture}` where offered, also to grants limited to
  some resources; otherwise (sealed and e2e namespaces, older deployments, or `UndoScanLog()`)
  the namespace log, which needs unrestricted read (§C.5), so a grant limited to some resources
  can't undo in sealed and e2e namespaces. The log is read all of it page by page or after
  `UndoSince(nsID)`, for entries with the gesture by the same author (`UndoAuthor`, by default
  the author of its first revision found). Each resource's log is
  read from its head just before the gesture in that log (or its head as of `UndoSince`), else from
  genesis, and from the pruning horizon when that is later.
- **The inverse**, per resource, the gesture's own entries newest first: a revision becomes the patch
  set that sets the paths it wrote back to its parent's values (writes to array elements widened to
  the whole array, as merges do; a revision of moves only is moved back when both ends are unchanged);
  a tombstone a restore with `[]`; a restore the inverse of its patches, then `"delete"`; a genesis
  `"delete"`. Edits others made to other paths, also between the gesture's saves, are kept. `$nonce`
  is never restored: each patch set gets a fresh one in sealed namespaces, in namespaces that
  require nonces (§C.7; a tombstone's inverse is then a restore with a lone fresh `$nonce`), and
  where the document has one, each only on a patch set whose resulting document is an object.
  Whether nonces are required is read from the namespace document, which needs unrestricted
  read: a grant limited to some resources can't read it, so in a private namespace it adds a
  fresh `$nonce` to every patch set (§C.7, v0.49, `client.NeedsNonce`), and the namespace's
  encryption level counts as unknown.
  The sets are joined and split again within the namespace's `opsPerSet` and `patchSetSize`.
- **The guard.** The log after the gesture's last entry in each resource: a write overlapping the
  gesture's paths, a delete, a restore or an undo of the gesture is a conflict, returned as
  `*client.ConflictError` (`Conflicts`: resource, entry, author, kind, paths) and listed in
  `plan.Conflicts`. The batch names the checked heads in `ifMatch`; a `412` re-plans, up to
  `UndoRetries(n)` times (3).
- **Impossible** (`*client.ImpossibleError`, `Reason`): a revision the inverse needs is below a
  pruning horizon (`pruned`), a blob is gone (`blob`, `422 blob`), the old values don't validate any
  more (`invalid`, `422 invalid` or `schema_unavailable`), or the resource was purged.
- **Redo** undoes the undo. **The stack** is the author's gestures minus those the same author undid
  and didn't redo; others' undos are listed in `UndoneBy`, not counted, and an `Undoes` naming a gesture
  that isn't in the log (or another author's) is ignored.
- **Encryption.** Plaintext and sealed (E2, with `client.WithKeys`) namespaces work as they are; e2e
  ones (E3) need `UndoE2E(x)`: logs are opened and folded through the E2E view, the guard compares
  decrypted entries, every resulting document is validated, and each step is sealed bound to the id of
  the step before. Without it an e2e namespace is refused.

The playground's **Undo / redo** card (Namespace tab) does the same in the browser for plaintext and
sealed namespaces: it rebuilds the stack of the author in the connection bar (or another one typed in)
from the namespace log, offers Undo/Redo for the last actions (and for any gesture id, or "Undo this
gesture" in History), and shows conflicts (red, with the later entries and paths; nothing written)
apart from "undo impossible" (pruned, blob, invalid). It refuses to write undos in e2e namespaces and
points to the Go client.

### Search index (Addendum A)

`patchlog index -ns matches` follows namespaces and serves a search API on its own origin
(default `:8081`). It indexes fields that schemas mark with `x-index: "text" | "facet" | "sort"`,
or an array of them such as `["facet", "sort"]`:

```sh
curl -L 'localhost:8081/matches?q=derby*&facet[/league]=allsvenskan&sort=-/kickoff'
```

- `GET /{ns}?…` runs the query at the current checkpoint and redirects to `/{ns}/at/{checkpoint}`,
  which stays correct forever. Every result computed or served is kept, in memory for about a
  minute (at most 64 MiB per index process, the oldest out first), and an `at` URL answers `200`
  while its result is kept, however far the checkpoint has moved; otherwise it redirects to the
  current checkpoint. So a query takes one redirect from the head pointer, and at most two from
  an older `at`, at any write rate. A purge drops the kept results that show what it purged.
- `?min={ns_id}` waits for your own write to be indexed, and answers 503 if it isn't in time.
  With it, an older `at` redirects to the current checkpoint even while its result is kept.
- `?ref=` answers "who uses this?" (§A.4): the documents of `{ns}` that reference a resource through
  a schema's `x-ref`, found by walking each typed document with the schema revision it pins, with
  no `x-index` needed. `?ref=/r/logic/route-3` matches any form, `/r/logic/route-3/rev/{id}` only
  references pinned to that revision, and `/r/logic/route-3%23t-42` only those naming that entry. It
  combines with the other filters, and each hit lists `refs: [{path, ref}]`. Untyped documents, and
  paths that merely appear in prose or embedded copies, are not references. Delete guards built on
  it are advisory (use `?min=` and expect races). A database from before this version is rebuilt
  from the logs on start. In a branch's preview index targets match as written.
  A document that references itself is a hit of its own query with `"self": true`, so a delete
  guard can leave it out. A `ref` query without `q` or `sort` pages by resource name (v0.49):
  `after` is a name, any string serving as the bound, and `next` is the `after` of the following
  page, to set on the `at` URL; other queries page by offset, with `next` the next page's URL.
- `GET /_refs?to=/r/logic/route-3` (v0.48) asks every namespace the index follows that the reader
  may read, branch previews included, `to` in any form `?ref=` takes. It redirects to
  `/_refs/at/{at}/g/{gs}?to=…`, where `at` is a combined checkpoint over only the namespaces the
  answer covers, which the body's `namespaces` lists, so writes elsewhere don't move it.
  - `gs` keys what the answer depends on, over markers alone (v0.49): `reads:{ns}` for each
    private namespace the grant reads unrestricted (one read role without `/resource` rules is
    enough), and `reads:{ns}:scope:{digest}` for one it reads in part, the digest covering the
    rules that limit it there and the `/principal` values they refer to; rules on `/now` there
    make the namespace unreadable. Readers with no marker, anonymous ones included, share the
    empty set's `gs`.
  - It leaves out namespaces the index hasn't reached yet, purged ones, and sealed or e2e ones
    whose keys it doesn't hold. `min` takes `{ns}:{ns_id}`, repeatable, and is `400` for a
    namespace the answer doesn't cover; on an `at` URL, a kept answer whose `at` already
    includes every `min` is `200`, otherwise it waits and redirects (`503` if not in time).
    Only a reader who may see none of the namespaces gets `401` or `403`. A namespace document
    the index can't read is `502` for a namespace the grant names; any other is left out, as a
    private one.
  - Hits are `?ref=` hits with their `ns`, filtered per resource, in byte order of namespace,
    then resource name. A page holds `limit` hits after `after`, given as `{ns}/{name}`, and
    `next` is the following page's `after`, to set on the `at` URL. Hits from sealed and e2e
    namespaces are sealed per entry, and such answers are served only at their canonical URL.
    Answers are kept as above. Delete guards built on it remain advisory.
- Schema documents (whose `$schema` is a dialect URL) are indexed too: `?schema=https://json-schema.org/draft/2020-12/schema`
  lists them, and the revision paths of `$ref` keywords at schema positions (fragment dropped; not
  those inside `const`, `enum`, `default` or `examples`) count as references, so
  `?ref=/r/schemas/address` lists the schemas that `$ref` it.
- Hits carry their facet and sort values under the field's path (always a list; sort values as
  written), and `?fields=/name,/title` adds those indexed fields, `text` ones included, so a list
  renders without fetching every document. A path is checked against the `x-index` marks of the
  schemas the namespace's documents use (an `x-index` reachable from a schema's root along the
  path, through `$ref`, `$dynamicRef`, the object and array keywords and every branch of
  `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, never through `not`, `propertyNames` or
  `unevaluated*`, array items at their array's path; §A.4), not against the data, so whether a
  query fails never depends on it: a marked path no document has values at is accepted and left
  out of hits, an unmarked one is `400`, and a schema that can't be read for now is `502`. In
  sealed namespaces they are sealed with the rest of the hit. A database from before this
  version is rebuilt from the logs on start.
- In private namespaces the reader's grant is checked locally. Results are routed under
  `/g/{subject-set}/…` and filtered to the resources the grant can read.

### Merge, rebase and cleanup (Addendum F)

```sh
patchlog merge status -branch release-7          # per resource: ahead, behind, clean, conflicting
patchlog merge plan   -branch release-7          # the batch, plus a dry run
patchlog merge apply  -branch release-7 -freeze  # one batch into the base, then freeze with "merged"
patchlog rebase -branch release-7 -new release-7-b -switch
patchlog janitor -ns matches                     # purge merged/superseded/abandoned branches after `cleanup`
```

- Resources are classified by ancestry, using ids only (§F.3). A fast-forward reproduces the
  branch's ids exactly. A replay reports overlapping `writes` under the array rule, and the
  delete-versus-change cases always go to a person.
- Fast-forwarded and replayed steps carry each branch revision's `gesture` and `undoes` (§F.3,
  step objects of §7.5), so history views and undo keep their grouping in the base; rebases do
  the same, and `-squash` loses them.
- `-resolve name=file.json` replaces a conflicting item's steps with a resolution. A `"keep"`
  resolution is still recorded in the batch with an empty step `[]` (in a sealed namespace or
  one that requires nonces, a patch set that only adds a fresh `$nonce`), so the batch holds the
  resource's pair, but only when the base's head is live. On a tombstone or an absent resource it
  gets no item, stays unmerged, and is offered again by the next merge. In such namespaces
  resolution and squash sets get a fresh `$nonce` too, and squash diffs leave `$nonce` out.
- The batch's `source.at` is the branch revision the plan was classified from. A `412` retry
  re-classifies against the base's new head but keeps that revision; work the branch got
  meanwhile waits for the next merge.
- Earlier merge batches from the same branch count as common ancestors, so a second merge after
  a replay only picks up what is new. Per resource, the pair comes from the most recent such
  batch with an entry for it. Only batches without `origin`, whose `source.ns` is the branch,
  whose `source.at` is in the branch's chain (checked by the tool itself, since the server
  checks it only for writers who can read the branch, §7.5) and whose recorded grant (root
  `sub` and `kid` of the entry's `grant`, §7.4) is listed in the base's `merge.authors` count.
  Entries written with authentication disabled record `"grant": null` (§1). The merger reads
  the deployment's mode from `GET /` (`client.AuthDisabled`, asked on every plan): while it
  says `"auth": "disabled"`, such entries match on `author` alone, whether or not the merger
  sends a bearer the server ignores; under `"grants"` they count for no one, so nothing
  written without authentication is trusted once the database is served with authentication
  on. Entries without `grant` at all (the server's own, or from before v0.37) always count for
  no one. (v0.37's `client.WithAuthDisabled` and the tools' `-dev` declaration are gone: an
  operator override could only make a production deployment trust unauthenticated entries.
  `-dev` is still accepted, and ignored, so scripts keep working.) Without `merge.authors` there
  are no such common ancestors: a second merge after a replay conflicts, and the tool suggests
  rebasing (§F.5). `status` and `plan` show per resource which batch and author its pair came
  from, and print a hint when the base has no `merge.authors` or the merger (`-bearer`'s root
  `sub`/`kid`, or `-author`) isn't listed.
- The janitor checks `merged`, `successor` and `abandoned` claims before purging (§F.6).
  A `merged` claim needs a merge batch whose recorded grant's root `sub` and `kid` are in the
  base's `merge.authors`; the successor's batch for `superseded` needs no such author, as §F.6
  states; `"abandoned": true` counts only if the config write that set it records a grant whose
  root key is a `*` key of the branch (its own or a base's), so only its administrators can
  give up everyone's unmerged work. An entry with `"grant": null` counts, on its author alone
  for `merged` and as a `*`-key write for `abandoned`, only while `GET /` says
  `"auth": "disabled"` (asked on each check, so a janitor notices a restart with grants);
  entries without `grant` count for no one. Cleanup is opt-in: a branch is
  purged only once a `cleanup` period (`"cleanup": { "merged": …, "superseded": …,
  "abandoned": … }`), from the branch's or the base's document, has passed.

### Draft schemas in branches (§6.1, §7.4, §F.9)

A schema path never names a branch (`422 schema_ref`), but a release can draft its schemas in a
branch of the schema namespace and its documents keep naming the base path:

```sh
# schemas-r7 drafts /r/schemas/team/rev/X; matches-r7 may use it
POST /ns/schemas/branches  {"name": "schemas-r7", "patches": [{"op": "add", "path": "/drafts", "value": {"for": ["matches-r7"]}}]}
PATCH /r/matches-r7/derby  {"$schema": "/r/schemas/team/rev/X", …}
  Source-Authorization: Bearer <grant reading schemas-r7>   # repeatable
```

- **Where drafts resolve.** Only in a write to a branch, and only for a path its namespace `N`
  can't resolve for the writer, because `N` lacks the revision or the writer can't read it
  there: the server then looks the id up (index `revisions_by_id`) among the local, non-e2e
  branches of `N`, branches of branches included, counting only revisions a branch wrote
  itself. A candidate serves itself and its own branches, and the namespaces its own
  `drafts.for` lists (names, prefixes ending in `*`, or a bare `"*"` for every namespace) with
  their branches; branches of a candidate don't inherit it (branch creation drops `drafts`,
  `merged` and `abandoned`). `drafts` is `422` outside a local branch that isn't e2e (remote
  branches and their branches included). In a namespace that isn't a branch, paths resolve
  only in `N`, so documents using drafts can be merged into a base only after their schemas
  (fast-forward the schema branch first: the same patches give the same ids).
- **Reading other namespaces** (§7.5) follows one rule, for batch sources, blob copies, drafts
  and the schema's own namespace alike: the request's grant or any grant of
  `Source-Authorization` (repeatable, or comma-joined) that names the namespace, verifies under
  its keys and allows the read; a public namespace needs none. So the writer needs `read` on
  the schema resource where it resolves: a grant naming only the namespace written no longer
  reads schemas in another private namespace. A blob copy's source is read with the request's
  grant as well as the header's (before, a `Source-Authorization` header replaced it). A
  draft the writer can't read is reported like an unknown one (`422 schema_unavailable`). The
  client library sends several grants with `client.WithSourceAuthorization`,
  `client.WithSourceGrants` (one write), `BatchRequest.SourceAuthorizations` and `CopyBlobWith`.
- **`schemaReads`** (§6.1). A namespace that isn't a branch may set
  `"schemaReads": { "for": ["content", "site-*"] }` (names, or prefixes ending in `*`, matched as
  `drafts.for`; the namespace itself always counts). Its schema revisions (resources whose own
  `$schema` is the dialect URL) then resolve for writes to a listed namespace, or a local branch
  of one, without the writer's read on it, through `$schema` and the `$ref` closure; and a grant
  that may read a resource of a listed namespace whose current document (head, or last live
  document if tombstoned) pins the revision through `$schema` and its `$ref` closure may `GET`
  that revision by path, `/r/{N}/{name}/rev/{id}`, even if it doesn't name `N` (cached
  `private`). Nothing else opens: not the head, log or other revisions, not a document that
  isn't a schema, not a draft in a branch. Only the listed namespace's own resources count as
  referrers. A referrer in a listed namespace that is public, and neither sealed nor e2e,
  opens the revision to every request, with or without a grant, which is then ignored (v0.49);
  any other counts only for a grant that names its namespace, verifies there and may read it.
  Whether a revision is open is kept per revision path until a write to an open listed
  namespace or a change of configuration or namespaces, so anonymous reads don't scan those
  namespaces each time. Setting it needs a `*` key; it is `422` in sealed and e2e namespaces,
  and branch creation drops it.
- **`in_use`.** A reference (every revision a branch wrote counts, not only its head; tombstoned
  documents too) is satisfied by any available copy: in `N`, or for a branch in a candidate
  serving it. A resource or namespace purge that would remove the last such copy, in any
  namespace it reaches, is `409 in_use` with `referencing`: the referencing namespaces in which
  the caller may read anything, by the rule above (one readable resource suffices). So are
  narrowing `drafts.for` and raising a draft branch to `e2e`. `?force=1` overrides a purge
  (`POST /r/{ns}/{name}/purge`, `POST /ns/{ns}/purge`) with a grant chained to a deployment
  operator key (`serve -operator-key`; the namespace's rules don't apply to it), or, for a
  purge of a branch or of a resource in one, to a `*` key of that branch, its own or inherited.
  A `*` key of a namespace that isn't a branch no longer forces. Every entry a forced purge
  writes, propagated ones included, carries `"forced": true`, part of the hashed entry
  (verified by `internal/verify`, `client.NSEntry.Forced`); a purge nothing refused isn't
  marked, `?force=1` or not. Dependents can't be forced. On Postgres a purge takes the other
  copy holders' locks shared, so two purges can't each remove one of the last two copies.
- **Consumers** find drafts the same way (`client.ResolveSchema`, `client.SchemaResolver`):
  `N` first, then its branches via `GET /ns/{N}/branches`, which shows each branch's `drafts`,
  preferred branches first. With `ResolveOptions.For` (the namespace of the document) the
  resolver skips candidates whose visible `drafts.for` doesn't serve it; this is best effort,
  and only the server's check decides a write. Resolved schemas may be cached by path across
  namespaces. The search index does this for documents of branches, and an e2e merge
  validates as the target's gate would (drafts only into a branch). `patchlog export` refuses
  a document whose schema exists only in a branch (`bundle.ErrSchemaUnavailable`) unless that
  schema's namespace is declared `-external`, and a remote branch whose documents use drafts
  is `422 schema_unavailable` (§G.3): merge the schemas first.

### Releases across namespaces (§F.9)

A release spans several namespaces: new documents in `matches`, their placements in the catalog
`cat-season`, a draft schema in `schemas`. Each is branched, and a **release document** lists the
branches (package `internal/release`):

```json
// /r/releases/release-7
{ "name": "release-7",
  "branches": { "matches":    { "ns": "matches-r7",    "at": "1k…" },
                "cat-season": { "ns": "cat-season-r7", "at": "1m…" },
                "schemas":    { "ns": "schemas-r7",    "at": "1d…" } },
  "on": "/r/releases/release-6/rev/1x…",
  "owners": ["user:anna"] }
```

Keys are the namespaces paths name; `at` (top level, a combined checkpoint) and `on` are optional.
Each branch's own `at` is authoritative; the top-level one is dropped by a rebase.
The core never reads it; every tool checks for itself what it is about to do.

```sh
R=/r/releases/release-7
patchlog merge release plan    -api URL -bearer $ANNA -catalog-service cat-season=$CATSVC $R   # classify, report conflicts, store the plan and its digest
patchlog merge release approve -api URL -bearer $ANNA -digest $DIGEST $R                     # plan again, require the same digest, freeze every branch
patchlog merge release apply   -api URL -bearer $ANNA -merge-bearer $MERGESVC -catalog-service cat-season=$CATSVC $R  # the four steps; run again to resume
patchlog merge release abandon -api URL -bearer $ADMIN $R                                    # freeze every branch with abandoned: true
patchlog merge release status  -api URL -bearer $ANNA $R
patchlog merge release rebase  -api URL -bearer $ANNA -suffix -b $R                          # successors of every branch, new release revision
patchlog tree -catalog cat-season -release $R -bearer $PREVIEW                               # a release preview (§B.5), following $R's revisions
patchlog janitor -ns schemas,matches,cat-season -release $R                                  # drafts purged last, in_use retried
```

- **The steps** (one batch per branch and step, each classified again with a dry run right
  before it is submitted): (1) schema resources (documents whose `$schema` is the dialect URL) by
  fast-forward only, in `$ref` order; (2) catalog changes that narrow access, judged by the
  §B.11.4 test (for every subject, effective roles on every node afterwards a subset of those
  before, `includes` honoured) on the step-2 batch as a whole; a folder the release creates goes
  here, with its own `$access`, when a narrowing move needs it (an empty folder gives access to
  nothing but its title and its tree powers, so the test applies to the items moved into it);
  (3) the content branches; (4) the remaining catalog changes (placements, widening moves,
  `$access` edits), which publishes the release. Tombstoned schema resources still merge in
  step 1.
  A branch with schemas and content merges its schemas in step 1 and the rest in step 3.
- **Conflicts reported before anything is submitted** (`plan` exits 1): a schema resource the
  base changed (`schema_changed`: rebase the release, then migrate documents with
  `replace /$schema`); a catalog node that narrows for some subjects and widens for others
  (`narrows_and_widens`: give `-split KEY/NODE=narrow.json`, the node's document after step 2;
  the branch's document is reached in step 4; a split that doesn't narrow then widen is
  `bad_split`); a narrowing batch that widens as a whole (`step2_widens`); a content item step 3
  creates or restores that a placement in the catalog base already names (`placed_item`: fine if
  step 2 removes that placement; accept with `-accept-placement NS.NAME` if the release keeps it
  unchanged; any other change to it is a conflict); a pinned link
  (any string `/r/{ns}/{name}/rev/{id}` in a changed document but `$schema`/`$ref`, which covers
  `x-ref` pins and manifest entries) to a revision of a listed branch that the merge replays
  (`dangling_pin`); a `$schema` (or its `$ref` closure) resolving to a draft in a branch the
  release doesn't list (`foreign_draft`), found with `client.ResolveSchema` preferring the
  listed branches; one the merger can't resolve at all (`schema_unavailable`); every §F.3
  merge conflict of a content or catalog resource (`merge`; content ones take
  `-resolve KEY/NAME=file.json`). The pre-approval checks report `base_chain` (a branch whose
  base chain doesn't reach its listed base, or for a release with `on`, the earlier release's
  branch), `frozen` and `purged`.
- **The stored plan** is the resource `{release}.merge` in the release document's namespace (or
  `-state-ns`), with the release document's revision and the plan's **digest**
  (`merge.PlanDigest`): `text(trunc160(sha256(canonical(plan))))` over
  `{ "release": <revision>, "steps": [ { "step", "key", "items": [ { "resource", "ifMatch" |
  "ifNoneMatch" | "after", "steps" } ] } ] }`, items by resource name, steps as plaintext before
  any sealing with `$nonce` values left out, and the second half of a split node's
  precondition written as `"after": { "step": 2, "key", "item" }` instead of an id; each step
  also stores its own part's digest. `plan` prints the digest; `approve` (the approving
  person's grant) plans again with the stored splits, acceptances and resolutions, requires it
  clean, for the same revision and with the same digest (and the one given with `-digest`, if
  any), freezes every listed branch (§8.4) and records each branch's config id, step by step,
  so a stopped approval resumes. The whole plan, both halves of every split node included, is
  stored before step 2. `apply` refuses a plan without a digest or whose release document
  moved or whose branches' config ids changed (unfreezing invalidates the plan: plan and
  approve again; already merged steps then classify as merged), rebuilds each step right
  before submitting it and stops (`merge.ErrPlanChanged`) if its items differ from the
  approved ones, records each step's batch as it completes, resumes from there, never reverts,
  and has every branch record `merged` (config write `frozen` + `merged.at`) only after step
  4, with `at` the target's `ns_id` after the last batch into it (for the catalog, step 4's).
  A resumed step whose batch went in before the stop has nothing left to do (fast-forwards by
  id, replays through merge points, which need the merger in the base's `merge.authors`;
  halves by content); a split node's step-4 pair replaces its step-2 one (§F.3), and until then
  the stored plan decides what is left.
- **Catalog batches** (steps 2 and 4) are submitted by the merge service itself, under a grant
  the catalog service signs for it for exactly that batch: `POST {catalog service}/merge-grants`
  with `{ "batch": … }`, the merge service's own grant for the catalog as `Authorization`
  (`-merge-bearer`) and the approving person's in `Approver-Authorization` (`-bearer`). The
  catalog service (`tree -access -merge-key SEED -merge-kid KID -merge-service SUB`) issues
  merge grants only to that `sub`, signs them with the merge key, a key used for nothing else,
  and folds each item onto the revision its precondition names to check it, for the approver,
  as in §B.11.4: a new placement needs the content namespace's `catalogs.{catalog}.place` list
  and `place` on its folders; a new folder, `move` on its parents; a deleted node, `move` on
  its parents; a move, `move` on the parents left and added and, unless admin, no widening of
  nodes in the moved subtree; other edits, `move` on the node's parents. Tree powers on a
  folder created in the same batch come only from its own `$access` (an admin may enter one
  nobody holds them on yet). The grant's root is `{ "sub": <merge service>, "kid": <merge key>,
  "attrs": { "approvedBy": <approver> } }`, without groups, its rules allow exactly the
  batch's pairs of `/resource` and `/action`, and it expires within minutes (`-merge-ttl`,
  default 5m). A batch that changes `$access`, which needs `catalog-admins` and so no catalog
  key may assert, is checked the same way and answered `{ "admin": true }` without a grant: the
  merge service submits it under the approver's grant, which must be a catalog admin's,
  narrowed with a block carrying its own `via`, the catalog, the batch's actions and pairs, and
  a five-minute `exp`. So list `{ "sub": <merge service>, "kid": <merge key> }` and each such
  admin `{ "sub", "kid" }` in the catalog base's `merge.authors`. `503 behind` until the service
  has reached the batch's preconditions (the tool waits).
- **One release per catalog base at a time.** `apply` holds the lock resource
  `merge-lock.{catalog base}` in the state namespace, a document `{ "release": link }` naming its
  holder, taken with an append with `If-Match` when its `release` is null (or created with
  `If-None-Match: *` the first time) and released with an append that clears it, from its
  first step until every branch records `merged`; a merge resuming from a stored plan takes
  over the lock that plan holds. Another release's `apply` fails with `ErrLocked` meanwhile.
  Two runs of the same release serialise on the stored plan's `If-Match`.
- **Abandoning** (`abandon`, `merge.AbandonRelease`) freezes every listed branch with
  `"abandoned": true`, marks a stored plan `abandoned` and releases its catalog locks. Run it
  with a `*` key of the branches (an administrator's): the janitor accepts the claim only then
  and purges the branches after their `cleanup.abandoned` period. What step 1 merged stays in
  the schema namespace's history, unused.
- **Rebasing** (`rebase -suffix -b`) creates successors (§F.5) of every branch, schema branches
  first, each schema successor with `drafts.for` naming the other successors in its creation
  patches. A draft that has to be replayed gets a new id; a resource whose entries reference it
  is squashed (one resolution set against its new base, reaching the branch's document with
  `$schema` moved to the draft's new revision). Old branches are switched (`frozen`,
  `successor`), and the release document gets a new revision listing the successors (`at` is
  dropped unless given with `-at`). It stops on conflicts and resumes.
- **Previews** (`tree -release LINK`, `tree.Options.Branches`): the tree service follows the
  listed branches in place of their bases (their `/heads` at their first entry, then their logs).
  The graph keeps the bases' names, as documents do; checkpoints, the combined checkpoint, cache
  tags, `/_status` and read checks use the branches, and items carry `url` into the branch and
  `branch`. A viewer sees the catalog only with a grant reading the catalog's branch (`403`
  otherwise), and an item's head only with one reading the content branch: items in a content
  branch the viewer can't read are hidden, never shown from the base. A preview issues no grants (`-access` is
  refused), and covers one catalog. It follows the release document's namespace log (§10,
  `tree.OpenPreview`): a revision listing other branches, such as a rebase's successors, switches the
  preview to them without a restart (it rebuilds its database from the new branches, answering `503`
  `behind` until it has reached them); a revision with the same branches, an invalid one, or deleting
  the document leaves it as it is.
- **The janitor** (`-release LINK`, repeatable) purges a release's non-draft branches before its
  draft branches (those with `drafts`, or holding schema documents). A purge refused with
  `in_use` is retried at the end of the sweep and otherwise reported as `retry` for the next
  sweep; it never forces. A release document only orders the sweep, never authorises a purge.

### Pruning archives and retention (§8.6)

```sh
patchlog serve -archive file:///var/lib/patchlog/archive [-archive-root file:///other] [-retention-interval 1h]
patchlog archive restore -db patchlog.db [-from file:///moved/archive] [-ns NS] [-resource NAME]
```

- **Archive first.** Before a prune drops patch sets, it writes them as a full-history bundle
  (§G.4.1) to `{destination}/{ns}/{name}/{horizon}.jsonl`. A later prune writes an incremental
  bundle whose `requires` points at the previous one. Blobs whose attachments the prune ends
  go in as blob lines; `archive restore` brings them back once the horizon is cleared.
- **410s link to the archive.** Revisions below the horizon answer `410 pruned`, with the
  archive's URL in the body.
- **Who can prune.** With an archive configured, the `prune` verb is enough. Pruning without an
  archive, or below what `retention` keeps, needs a `*` key, except that applying a rule that
  says `"archive": false`, within what it keeps, needs only `prune`.
- **Destinations.** A `retention[].archive` destination must lie under an allowed root
  (`-archive` or `-archive-root`), otherwise the config write gets `422`.
- **Purge reaches archives.** Purging deletes the resource's archives too.
- **Retention runs in the background.** Every `-retention-interval`, as `system:retention`, it
  keeps the last `revisions` or everything newer than `age`, whichever keeps more. Protected
  revisions always stay. A rule without `archive` uses the `-archive` default; with no default,
  it applies only if it says `"archive": false` (it prunes irreversibly, without an archive).
  Otherwise the applier skips it and logs that once. `"archive": false` is `422` in an e2e
  namespace. `/retention` needs a `*` key, the same authority that may prune without an archive.
- **Restore is offline.** It re-inserts every archived patch set whose recomputed id matches the
  kept row, then clears the horizon.

### Remote branches (§G.3)

```sh
# B: reach A with a read grant (and export, to register); follow A's purges.
patchlog serve -origin https://b.example -operator-key <PUB> \
  -remote-bearer https://a.example=<GRANT> [-remote-url https://a.example=http://10.0.0.5:8080] \
  [-remote-register] [-remote-ignore-purges] [-remote-follow-interval 5m]
# Create it with the operator key; at is A's namespace head.
curl -X PATCH $B/ns/release-7 -H "$P" -H 'If-None-Match: *' -H "Authorization: Bearer $OP" \
  -d '[{"op":"add","path":"","value":{"read":"grant","keys":[…],"base":{"origin":"https://a.example","ns":"matches","at":"1k…"}}}]'
```

- **Source side (A).** `POST /ns/{ns}/branches` with `{ "remote": { "origin", "ns" }, "at" }`
  registers (`If-None-Match: *`) or renews (`If-Match` with the latest entry's `ns_id`, same
  `at`). It needs unrestricted `read` (§C.5), checked as gate step 1 checks verbs, in a public
  namespace too (v0.49), and `export`, is checked as an `export` envelope, is rate-limited,
  appends a remote `branch` entry, is listed in `/branches` while unexpired, and protects the
  head as of `at` from pruning for the registration lifetime (`limits.remoteRegistration`,
  default `P30D`). In a purged namespace it is `410 purged`, with `head` (§8.5).
- **Branch side (B): mirrored up front.** Before the write transaction, B fetches A's
  namespace log up to `at`, `/heads` as of `at`, every resource's log and the `$schema`/`$ref`
  closure, and verifies them all by recomputing ids; `/heads` must agree with the log. It then
  inserts, in one transaction, a hidden shadow namespace `~{branch}` holding A's chain up to
  `at` and A's revisions with identical ids. The remote branch is a local branch of its
  shadow: read-through, foreign parents and logs work unchanged. History A pruned is mirrored
  from the horizon, whose document is kept as a snapshot (only as trustworthy as the channel,
  §8.6). A failed fetch or verification is `502` with `code: "remote"`, and nothing is written.
- **A base that is itself a branch.** Its read-through heads aren't in its own log, so B
  follows its `base` and `at` (proved by the id of its configuration genesis) recursively,
  fetches each base's log up to that `at`, and verifies every read-through head and its
  resource log against the base that wrote it; `/heads` must agree with the combined view.
  Each level gets its own shadow (`~{branch}`, `~{branch}~1`, …), holding what the levels above
  read through or use as foreign parents, each a local branch of the next, so logs cross
  foreign parents as at A. The branch-depth limit counts every level. B needs read access to
  every base in A's chain: a base that answers `401`/`403`/`404` is `422`. A base that is a
  remote branch at A is refused (`422`).
- **Schemas** are mirrored under the same paths into a non-branch namespace of that name on B,
  created if missing with the branch's `read`, `keys` and `roles`. Such a namespace starts
  `optional` (§C.7), since its mirrored history keeps its ids, and takes its source's `nonce`
  setting at A with a config write by the creating operator once that history is in, so later
  writes there stay exportable; it stays `optional` if B can't read the source's namespace
  document. A path whose chain neither contains A's nor is a prefix of it is
  `409 name_conflict`; a prefix is extended.
- **Required nonces (§C.7).** A branch of a base whose current namespace document requires
  nonces when the branch is created must be created with `"nonce": "required"` (`422`
  otherwise), or merging it back would fail. A remote branch isn't a dependent at A, so A may
  start requiring nonces later; B's history must then be re-authored to merge.
- **Encryption (§G.5.2).** B refuses a branch less protected than A's namespace as B reads it: a
  private base needs a private or sealed branch, a sealed base a sealed one (it may be public),
  an e2e base an e2e one; a base whose namespace document B can't read is refused (`422`), since its level can't be told. For a sealed base, B fetches keys with its own grant, whose `enc` names
  B's key pair (`-remote-identity https://a.example=b.jwk`), mirrors the plaintext and seals
  what it serves under the branch's own epoch keys. For an e2e base, B mirrors the ciphertext
  and the `keyring` verbatim (ids verified over the ciphertext, nothing folded, no schema
  closure) and relays the wrapped keys of every keyring it mirrored (one per level of A's chain)
  under their own kids; `base.chain` records the namespaces B followed, and e2e readers accept
  read-through ciphertext bound to any of them; history A pruned can't be
  mirrored (`410 pruned`). A accepts registrations whatever its level: it can't check B.
- **What doesn't cross.** Keys and revocations are the branch's own (they stop at the shadow),
  A's rules don't apply, B's purges and namespace purge never contact A, and A's registrations
  never block A's own purges. A private base's branch can't be public (A's `read` at `at`, as
  served).
- **Purges.** B follows A's log (`-remote-follow-interval`, or `Engine.SyncRemotes`) and on
  `purge`/`purge-ns` applies §8.3 locally to the names concerned: its own chains, its own
  branches and cache tags. With `-remote-ignore-purges` they are recorded as notices only
  (`Engine.RemoteNotices`). A purge on B also removes the shadows' copies. When A's base is a
  branch, B follows only that branch's log: A's purges in its bases propagate to it as purge
  entries there.
- **Registration.** With `-remote-register`, B registers after creating the branch and renews
  seven days before expiry.
- **Origins.** Both deployments need canonical origins (`-origin`), in https. Plain http is
  accepted only for loopback hosts, so two local servers can try this out
  (`-origin http://localhost:8080` and `http://localhost:8081`).
- **Spec versions.** B reads A's `GET /` first: its origin must be the one the genesis names.
  B reads A's namespace documents (`read`, `encryption`, `base`) and ignores members it doesn't
  define, so it never refuses for an unknown member or for A's `spec` alone, and A may upgrade
  first (§7.4, §G.3). An `encryption.level` B doesn't know counts as the strictest.

### Encryption at rest (Addendum E.1)

```sh
patchlog serve -master-key /etc/patchlog/master.key [-master-key-create]   # 32 random bytes, mode 0600
curl -X PATCH $B/ns/matches -H "$P" -H 'If-Match: "{config_id}"' -H "Authorization: Bearer $STAR" \
  -d '[{"op":"add","path":"/encryption","value":{"level":"at-rest"}}]'
```

- **Keys.** A `KeyStore` (`core.Options.KeyStore`; `internal/keystore` keeps the master key in a
  file, refused if group or others can access it) wraps per-resource data keys, stored in `deks`.
  Grants use one deployment data key. Patch sets, head and intermediate snapshots and grants of
  an at-rest namespace are stored as `0x01 ‖ nonce ‖ AES-256-GCM` BLOBs whose associated data
  binds table, resource and revision id (or seq); plaintext namespaces keep canonical JSON TEXT.
  Ids, the protocol and caching are unchanged; the in-memory document cache holds plaintext.
- **Purge is cryptographic.** Resource and namespace purges (and their propagation) delete the
  data keys as well as nulling the rows. SQLite runs with `secure_delete`, so freed pages are
  zeroed once the WAL is checkpointed (Postgres has no equivalent: see above).
- **Archives** of an at-rest namespace are the usual bundle, encrypted as a chunked AES-GCM
  stream under `HKDF(data key, salt, "patchlog-archive-v1")` (format in
  `internal/core/crypt.go`). Restore decrypts them; after a purge, surviving copies are
  unreadable.
- **Turning it on** for an existing namespace (a `*` key, §7.4) encrypts its stored rows, its
  remote shadow's and its grants in the config write's transaction; reads handle mixed rows by
  the version byte. Lowering or removing the level is `422`, and so is a branch below its base
  (branches inherit the level); raising a base with lower branches is `409 in_use`. A remote
  branch's mirrored rows follow the branch's level; a remote base's served level binds it.
- **Failing closed.** `encryption` without a key store is `422`. A database with encrypted data
  opened with the wrong master key refuses to start; without a key store, encrypted content
  answers `500 encryption_unavailable` (reads and writes), while plaintext namespaces are served.
- **Not yet:** a resumable background job for encrypting large namespaces (it runs in one
  transaction), re-encrypting archives written before encryption was turned on, `-master-key`
  for `patchlog archive restore` (the library restore decrypts), key rotation, KMS adapters.

### Sealed namespaces (Addendum E.2)

```sh
patchlog serve -master-key /etc/patchlog/master.key [-rotate-epochs 24h] [-rotate-on-revoke]
curl -X PATCH $B/ns/matches -H "$P" -H 'If-Match: "{config_id}"' -H "Authorization: Bearer $STAR" \
  -d '[{"op":"add","path":"/encryption","value":{"level":"sealed"}}]'
curl -X POST $B/ns/matches/keys -H "Authorization: Bearer $READER" -d '{"epochs":[1]}'
```

- **What it is.** A sealed namespace keeps encryption at rest (E1) and serves every response
  that carries content as a JWE (`Content-Type: application/jose`, `alg: dir`, `enc: A256GCM`,
  protected header `{ kid: "{ns}#{e}", pl, zip? }`, `internal/seal`). The CDN then holds only
  ciphertext and caches it with the **public** classes of §9, whatever `read` says.
- **Wire shapes.**
  - `GET /r/{ns}/{name}/rev/{id}`: one JWE, `pl { ns, name, id, kind: "doc" }`.
  - `…/rev/{id}/log` and resource long-polls: a JSON array of per-entry JWE strings, `pl { ns,
    name, id, kind: "rev" | "tombstone" }`, each sealing the plaintext entry object.
  - `GET /ns/{ns}/rev/{ns_id}`: one JWE, `pl { ns, id: ns_id, kind: "config" }`.
  - `…/log?since=` ranges and namespace long-polls: **one** JWE per page, never compressed,
    `pl { ns, range: [since, last] }` (`since` `""` from the start), the bounds of the page
    actually served (§7.1: `last` is its `X-Log-Next`, or the range's id on its last page),
    sealing the JSON array. The long-poll page from a `since` is the same stored JWE.
  - Events: the SSE `data:` line is a JWE. Resource events carry the entry's JWE (the same
    bytes as in the log); namespace events, and `purge`/`prune` events on resource streams,
    carry the range `(prev, id]` of their one entry (the same bytes as
    `…/rev/{id}/log?since={prev}`), whose plaintext is a one-element array.
  - Clear: URLs, status codes, `ETag`, `X-Revision`, `X-Config-Revision`, `X-Namespace-Revision`,
    `X-Cursor`, error bodies (including `410` bodies with `tombstone`/`last`/`horizon`), and the
    metadata listings `/heads` and `/branches` (names and ids are in URLs anyway, §E.2.2).
    Write responses go only to the writer (`no-store`) and stay plaintext.
- **Keys.** Each (namespace, epoch) has a 256-bit random epoch key, wrapped by the key store in
  `epoch_keys`. `encryption.epoch` starts at 1 (absent means 1; a new namespace or branch may
  name any start) and a config write may only keep it or add exactly 1, which starts a new
  epoch; its start time is that write's time. Resource content is sealed under
  `K_r = HKDF(K_e, ns, name)`, namespace documents and ranges under `K_e`.
- **Which epoch.** A revision or tombstone is sealed under the epoch in force when it was
  written (recorded in `rev_epochs`); a namespace document or range under the epoch in force at
  that entry (at the range's end). Content with no such epoch — read through from a base, or
  written before the namespace became sealed — gets the serving namespace's epoch current at
  its first sealing, kept forever.
- **Stored once, served forever.** Sealed bytes are made lazily on first read and stored in
  `sealed` (per serving namespace); concurrent first readers `INSERT OR IGNORE` and re-read, so
  everyone gets identical bytes, and ETags, `304`s and CDN copies stay valid. Ranges are stored
  too, at most 4096 per namespace (the oldest are dropped and resealed with fresh bytes on
  demand; event streams and long-polls reuse them). Purges delete a resource's sealed rows,
  a namespace purge also the epoch keys (cryptographic), and prunes the rows of what they
  pruned (kept documents keep their bytes). Documents of 1 KiB or more are DEFLATE-compressed
  before sealing, each on its own; ranges never are.
- **`POST /ns/{ns}/keys`** `{ "epochs"?: [e…], "resources"?: [name…] }` → `{ "keys": [ { kid,
  resource?, key } ] }`, `Cache-Control: no-store`. It needs a verified grant with `read`
  (also for a `read: "public"` sealed namespace); with `-dev` anyone gets epoch keys. It
  refuses as other reads do (§7): `401` without a usable grant, `403` for a grant that doesn't
  name the namespace (ignored, so `401`, in a public one), `404` without `read`. A grant that
  reads the namespace unrestricted (§C.5; with roles, through one without `/resource` rules
  that passes) gets `K_e` (and `resources` is ignored); one restricted by rules on `/resource`
  or a key with `readScope: "resource"` gets `K_r` for each requested resource it may read.
  Unlike the other `/ns/{ns}` URLs, it serves such grants. Any other `read` grant, whose rules
  refuse an unrestricted read and that has no read role referring to `/resource`, is `403`
  (§E.2.3, v0.49). A purged namespace answers `410 purged`, with `head`, only after all of
  that (§8.5).
  Epochs run from the one in force at the root block's `nbf` (without `nbf`: the first), capped
  to the last `encryption.historyEpochs`, up to the current one, never one that started at or
  after the grant's effective `exp`; requested epochs outside that are omitted. A root block
  with `"enc": { "kty": "OKP", "crv": "X25519", "x" }` gets keys HPKE-wrapped to it
  (`{ kid, resource?, suite, wrapped }`, `seal.WrapKey`) and never raw ones; narrowing blocks
  can't carry `enc`.
- **`$nonce`.** Every create, append and restore patch set must end up setting `/$nonce` to 128
  fresh random bits (26 base32 characters, `seal.HasFreshNonce`) that differ from the previous
  document's, or it is `422` with `code: "nonce"` at gate step 3 (v0.49; it was `invalid`), the
  code a namespace that requires nonces gives (§C.7); a failed `test` or patch is still
  reported first, as `invalid`. Validation leaves the fresh top-level `$nonce` out (§6.2 step
  5), so closed schemas needn't declare it. A restore with `[]` is exempt: its id hashes the
  (public) tombstone id and `[]`, so it reveals nothing, and the document it brings back was
  written with a nonce. Not where the namespace also requires nonces (§C.7): there such a
  restore sends a lone fresh `$nonce`.
- **Rotation.** A config write incrementing `encryption.epoch` (a `*` key, §7.4) rotates;
  earlier revisions keep their epoch and bytes. `-rotate-epochs 24h` rotates every sealed,
  unfrozen namespace whose epoch is that old, as `system:rotate` (`Engine.RotateEpoch`,
  `Engine.RotateDue`). `-rotate-on-revoke` follows a committed config write that adds to
  `revoked` or removes or changes a key with a rotation of that namespace and its sealed
  branches.
- **Access and branches.** `read: "grant"` still decides who may fetch ciphertext (without it:
  `401`/`404`); a sealed namespace may also be `read: "public"`. A branch of a sealed namespace
  must be sealed (the level rule) and has its own epoch keys, sealing read-through content under
  them. As for any branch, a branch of a non-public base can't be `public`, sealed or not
  (§7.4: names, sizes and timing would become public). A namespace with public dependents that aren't sealed
  can't become sealed (`409 in_use` with `dependents`). Remote branches of sealed namespaces
  are sealed too (§G.5.2, see remote branches).
- **Client.** `client.WithKeys(client.NewKeys(recipientPriv))` makes `Doc`, `Log`, `NSDoc`,
  `NSLog`, `LongPoll`, `ResourceLongPoll`, `NSEvents` and `ResourceEvents` decrypt
  transparently, checking each JWE's kid and `pl` against the request (and that log entries
  chain); keys are fetched from `/keys` and cached by kid and resource. `client.Sealed(ns)`
  reports whether a namespace is sealed; without keys, sealed content is `client.ErrNoKeys`.
  The follower, merge, bundle and other client-based tools thus work over sealed namespaces
  when their client has keys.

### End-to-end namespaces (Addendum E.3)

```sh
curl -X PATCH $B/ns/vault -H "$P" -H 'If-None-Match: *' -H "Authorization: Bearer $OPERATOR" \
  -d '[{"op":"add","path":"","value":{"keys":[…],"encryption":{"level":"e2e"}}}]'
```

- **What it is.** The server never sees plaintext: it is an ordered, access-controlled log of
  opaque entries. Clients seal patch sets and fold documents themselves (`client.E2E`). E2E
  keeps E1 storage (rows are also encrypted at rest, needing a key store) and uses the public
  cache classes; E2's response sealing doesn't apply (content is already ciphertext; namespace
  documents and logs stay plaintext, §E.3.1). `encryption.level: "e2e"` is accepted only when a
  namespace is created, or for a branch of an e2e base (which must be e2e); making an existing
  namespace e2e is `422` (its ids and content are over plaintext), and levels are never lowered.
- **Writes.** A create, append or restore carries exactly `[{"op":"sealed","value":"<JWE>"}]`
  (or `[]` for a restore), else `422 invalid`. The JWE (`seal.SealPatchSet`: `alg dir`, `enc
  A256GCM`) binds `kid: "{ns}#{e}"` and `pl: { ns, name, parent }` (`parent` `""` for genesis, the
  `If-Match` id otherwise, the foreign parent for a branch's first write). The server checks the
  header without a key: `pl` exactly this write's, `kid` an epoch the namespace has begun and not
  after `encryption.epoch` (or `422`). That catches client bugs and cross-resource replays early;
  it is a consistency check, not a security boundary (a writer can always seal garbage; readers
  verify `pl` when they decrypt). Nothing is applied and schemas aren't validated; limits apply to
  the patch set. Ids are over ciphertext, so an idempotent retry must resend the same bytes (the
  client keeps them); no `$nonce` is needed (random IV, §C.7).
- **Blind rules (§6.2).** The envelope of a sealed write has `writes: []` and `doc: null`. Any
  namespace rule that reads `writes`, `/doc` or the whole envelope (`rules.Rule.Refs()`) fails
  every such write as a whole with `422 rule`; such a grant, key or role rule with `403` (a role
  with one doesn't allow it). Rules on `/action`, `/resource`, `/principal`, `/now` and
  `/patches` work. Deletes, config, branch and prune writes are checked as usual; a delete's
  `doc` is `null` here, so a delete rule that reads `/doc` refuses every delete.
- **No documents on the server.** No head documents, intermediate snapshots or document cache
  for e2e content; the `$schema` index (§6.1 `in_use`, prune protection) sees nothing, and a
  `$schema` into an e2e namespace is `schema_unavailable`.
- **Reads.** `GET /r/{ns}/{name}` redirects as usual. `GET /r/{ns}/{name}/rev/{id}` (other
  than a pruning horizon, below) answers `302` with `X-E2E: fold`, `ETag`/`X-Revision` and `Location:
  /r/{ns}/{name}/rev/{id}/log?since={s}`, where `s` is the latest client-supplied snapshot at or
  before `id` in its ancestry (omitted if none); cached with the long public class (a later
  prune leaves the old target correct; clients restart from the horizon on a `410 pruned`).
  Tombstones and purges answer `410` as usual. The log serves entries as stored (the patch sets
  are the sealed ones), and never a snapshot: a prune's sealed snapshot, the document at `s`
  sealed with `pl { ns, name, id: s, kind: "snapshot" }`, is served as `/rev/{s}` (§7.1 Paging,
  §8.6): `200` with the JWE as `application/jose`, `X-E2E: snapshot`, `ETag`/`X-Revision` and
  the immutable class (`If-None-Match` answers `304`). For a tombstone horizon the snapshot is
  the last live document, and `/rev/{s}` keeps the tombstone's `410`, with `X-E2E: snapshot` and
  `{ "code": "gone", "snapshot": "<JWE>" }`. The snapshot stays served after an archive restore
  clears the horizon, until a later prune or a purge. Every other revision keeps the fold
  redirect (what it should serve is §13's open question), so a key holder folding a revision
  after the horizon reads `/rev/{s}` and then the range after `s`.
- **The keyring.** The reserved resource `keyring` holds `seal.Keyring` in plaintext (wrapped
  epoch keys and public X25519 JWKs only). It is the only plaintext resource: written by key
  holders with ordinary writes, checked like any document plus `seal.ParseKeyring`, `ns` equal
  to the namespace and `current` not after `encryption.epoch`.
- **`POST /ns/{ns}/keys`** relays only wrapped keys: it needs a verified grant that may read
  the resource `keyring` and whose root block carries `enc` (else `422`; non-readers `404`), and
  returns `{ "keys": [ { kid, suite, wrapped } ] }` — that recipient's keyring entries (by
  `seal.RecipientID` of `enc`) for the epochs the grant is entitled to (the E2 rule: from the
  epoch in force at `nbf`, capped by `historyEpochs`, none begun at or after `exp`). Per-resource
  keys don't exist at E3 (`resources` is ignored). A branch without its own keyring relays its
  base's.
- **Epochs and rotation.** The server holds no key; `e2e_epochs` records when each epoch began.
  A key holder rotates by re-wrapping the keyring for the remaining readers and incrementing
  `encryption.epoch` (by exactly 1, a `*` key) in one batch; old revisions keep their epoch.
  Server-side rotation (`-rotate-epochs`, `-rotate-on-revoke`) doesn't touch e2e namespaces.
- **Prune (§8.6).** `POST /r/{ns}/{name}/prune` `{ horizon, snapshot }` needs `snapshot` (a JWE
  of the horizon's document, or for a tombstone the last live one, with
  `pl { ns, name, id: horizon, kind: "snapshot" }` and a known epoch's `kid`; it carries no
  declared blob list, since the server keeps every revision's, §E.3.1) and an archive
  destination, even with a `*` key (`422` otherwise). `keep` is refused (the server can't keep
  documents it can't compute). If protected revisions move the horizon down, the answer is `422`
  with the effective `horizon` to seal for. The snapshot is stored opaque as the horizon's kept
  document; the pruned patch sets go to the archive as stored. The retention applier skips e2e
  namespaces: a key-holding janitor must apply retention.
- **Branches.** A branch of an e2e base is e2e with its own epochs starting at the copied one;
  read-through content stays the base's ciphertext and keyring. Its writes bind the branch
  (`pl.ns`, `kid`), so a key holder writes the branch's own keyring first.
- **Client.** `c.E2E(recipientPriv)` (or `c.E2EKeys(map[kid]key)`): `CreateSealed`,
  `CreateDocSealed`, `AppendSealed`, `RestoreSealed` (nil restores with `[]`) seal under the
  current epoch with the right `pl` and resend identical bytes on retries (`SealPatches` exposes
  them); they validate the resulting document against its `$schema` first unless
  `WithoutValidation()`. `DocE2E`/`LoadE2E` follow the fold redirect, verify the chain, every id
  and every `kid`/`pl` (the namespace or one of its bases), fold from genesis or from the
  horizon's snapshot (fetched from `/rev/{since}`; at the horizon itself `/rev/{id}` is the
  snapshot, so no log is read),
  and validate each document with a `$schema`: a revision that doesn't open, apply or validate
  is **flagged** (`E2EDoc.Flagged`, with its author) and left out, so `Value` is the document of
  the last valid revision (`ValidID`). `PruneE2E` folds and seals the snapshot. `InitKeyring`,
  `AddReader` and `RotateEpoch` administer the keyring (always including the admin's own key);
  `RotateEpoch` writes the keyring and the epoch bump in one batch. Keys come from `/keys`,
  falling back to the keyring resource. `client.EncryptionLevel(ns)` reports a namespace's level.
- **Refusals.** The merge tool refuses e2e namespaces (§F.8: merges re-encrypt, never
  fast-forward); `patchlog export` refuses snapshots of them (full history carries the
  ciphertext, §G.5.1).
- **Metadata no level hides (§E.4):** names, ids and parent links, sizes, timing, authors and the
  namespace log's shape.

### Tree and catalog (Addendum B)

`patchlog tree -catalog cat` follows a catalog namespace and the content namespaces it trusts, and
serves folder listings (`children`, `ancestors`, `subtree`, `roots`, `orphans`, `problems`,
`where`, `manifest`) at URLs pinned to the catalog's `ns_id`. Cycles and depth over 64 show up
under `problems`. `-catalog` is repeatable (or comma-separated): each catalog gets its own
service and database (`-db` with `{catalog}` replaced, or `-{catalog}` added before the
extension) behind one origin, and `/_status` covers them all (`?catalog=` for one).

Listings are kept like the search index's results (§A.4, §B.5, v0.49): every listing computed,
the one at the `at` a redirect names included, is kept in memory for about a minute (at most
64 MiB per catalog), and an `at` URL answers `200` while its listing is kept, so one redirect
suffices at any write rate. They are keyed by their URL and by what the reader reads whole, so a
reader whose namespace-wide reads changed since (a public namespace turned private) isn't served
one kept from before; listings that depend on the individual reader aren't kept, and sealed ones
are served only at their canonical URL. A purge drops the kept listings that show what it purged.

With `-access -key SEED -kid KID` it also issues grants from the tree (§B.11):
- `POST /grants` with `{ "node", "want": ["create"], "to": [folders] }` creates a folder
  (§B.11.4): `move` on every folder in `to`; the grant fixes the name and parents and, unless
  the caller is an admin, refuses `$access`. Tree powers on the new folder come only from its
  own `$access`; until an admin gives it some, only admins may move or place into it.
- `POST /grants` for content verbs, `create` (genesis only; `409` for a taken name), `place`,
  `move` and unplace (pinned to the placement's current parents), with the no-widening rule. Effective
  roles on an item are collected only through subjects the catalog key in its content namespace may
  assert (its `groups` scope; the caller's `user:` subject always), for `/read-grants` and restores
  too (§B.11.4 Resolve). A move of a deleted item's placement is checked like any other, against the
  roles the item would have now (§B.11.7).
- `POST /grants` with `{ "item", "want": ["restore"] }` restores a deleted item where it is placed
  (§B.11.4): the roles come from the `effective` rows frozen when the service saw the item's
  tombstone (marked `tombstoned`, kept across restarts, no longer recomputed), so placing the deleted
  item or moving folders afterwards changes nothing; they stay those of its deletion even if it was
  unplaced and placed again, but it must still be placed. The grant carries `can: ["restore"]` only;
  used on an item that is live again, the write is an append and the core refuses it. The answers,
  in order: a name that never existed `404`; a purged item `410`; `403` for a caller without a role
  granting `read` on the item (in its frozen rows if deleted, its current ones if live), without one
  granting `restore`, whose item has no placement, or whose restore would widen: the roles the item
  would have after it, from its current placement, exceed its frozen rows for some subject, judged
  with `includes` as for moves (a catalog admin skips that check, as for moves); then a live item
  `409`. The catalog key's entry in content namespaces lists `restore` for this (§B.11.3):
  `"can": ["read", "create", "append", "restore"]`.
- `POST /read-grants` returns resource-scoped read grants, and the keys of catalog nodes (and of an
  item's placement) visible to the caller.

Listings are filtered by the caller's subject set (§B.11.5). A node is visible when the walk up
collects, through a subject the catalog key may assert, a role granting `read` without conditions:
for an item, a role its content namespace defines with `read` and the catalog key there may grant
(its `roles` and `groups` scope), without rules or with rules that pass as a read of the item would
evaluate them: `action` `read`, the item as `resource`, and `/principal` holding only the caller's
groups the key may assert; no `writes`, `doc` or `patches`, so `within` is true and `covers` and
`overlaps` are false. A rule that refers to `/now`, or to anything in `/principal` but
`/principal/groups` (or to the whole envelope), makes the role not count. So the spec's
`translator` (`writes within ["/i18n"]`) sees the items it may read. For a folder, only a role
without rules in some trusted content namespace counts. `children`, `subtree`, `roots`, `ancestors`
and `where` show visible nodes and only paths through visible folders, with no counts of hidden
ones; limits, cut markers and pagination count visible nodes. `/read-grants` uses the same test.
Visibility is decided per request from `effective` and the content namespaces' documents (roles,
their definitions and the catalog key) as of their `ns_id`s in the listing's combined checkpoint:
the service keeps each content namespace's document with its checkpoint (`meta` `config:{ns}`,
read at the checkpoint after a snapshot or an upgrade), never the grant checker's latest copy, so a
listing at a given `at` never changes when a `/roles` change lands later. `problems`, `orphans` and
`manifest` aren't filtered: they need namespace-wide `read` on the catalog and on the content
namespaces they cover (`403` otherwise), for a manifest those of the items it pins, for `problems`
and `orphans` every trusted one; a public namespace counts as read namespace-wide; in the plain
tree service too. A reader whose grant reads the catalog and every trusted content namespace as a
whole is served unfiltered listings under `/{catalog}/at/{at}/g/all/…`, shared by all such
readers, with a private `max-age` no longer than that grant's expiry. Reading only some of them as
a whole doesn't change the URL space (the listing is then the subject set's), but still admits
`problems`, `orphans` and manifests covering only those, served `private` with a `max-age` no
longer than the grants, `no-store` for shared caches, and never stored sealed. There are no CDN
edge grants: the service decides `all` per request.

Read-your-writes: after its own write, a client relists with `?min={ns}:{ns_id}` from the write's
`X-Namespace-Revision` (repeatable, the catalog or any content namespace it trusts), which is a new
URL past any cached head pointer and waits for the service to catch up (`503` with `Retry-After`
otherwise), instead of fetching with `no-store` (§B.5, §A.5).
- `POST /merge-grants` checks a catalog branch's merge batch for the approver and signs one grant
  covering exactly that batch with the merge key, for the merge service only (`-merge-key`,
  `-merge-kid`, `-merge-service`, `-merge-ttl`; without a merge key it is refused); see
  [Releases across namespaces](#releases-across-namespaces-f9) (§F.8).

With `-release /r/{ns}/{release}` (not with `-access`) it previews a release (§B.5), following the
release document's revisions.

Callers authenticate with an ordinary grant for the catalog namespace, and their groups come only
from that grant. Issued grants carry `at`; the service refuses to issue from a checkpoint that
lags the catalog by more than `maxLag`, since the core would refuse the grant.

Note: the §B.11.3 example key rule `not writes overlaps /$access` refuses every create, since a
genesis writes `""`. Scope it to non-create actions and require `/doc/$access` to be absent on
create.

### Bundles (§G.4)

```sh
patchlog export -ns matches -mode history -o matches.jsonl  # with schemas and x-ref targets
patchlog bundle verify -i matches.jsonl                      # recompute every id
patchlog import -ns matches -i matches.jsonl -dry-run -atomic
patchlog import -ns matches -i matches.jsonl -pace 0.5       # backfill: split and paced
```

- **History bundles** keep ids, so importing one reproduces the source's ids exactly.
- **Authors** (`-authors`, `"authors": true`) adds each history line's author, creation time,
  signature, and its `gesture` and `undoes` (§G.4.1). Imports write the gestures with the
  revisions (batch step objects, §7.5), so undo history survives the move; authors and times
  stay the importer's, as for any batch. Without authors a line carrying them is refused.
- **Signatures** (§C.3.1): with authors, a bundle carries one grant line per grant its history
  references, with the key it verified against at the source; history lines name their grant
  in a `grant` member. `patchlog bundle verify -signatures` reports each revision as verified,
  attested (the chain completes only through the exporter's `key`), failed, unsigned or
  unverifiable; `-source URL` checks `key` against the source's namespace log and operator
  key history, turning attested into verified. A grant line names the namespace whose entry
  first recorded the grant, and its `key` is left out when the exporter can't find one; a
  history line for a revision written in another namespace (one a branch reads through, or a
  remote branch's base) carries `written`, which verifiers put in the signing input. Sealed
  namespaces' grants are fetched sealed and opened with the epoch key (pass `-bearer`), and
  end-to-end ones in the clear. Pruning archives (§8.6) carry grant lines too.
  `patchlog import` and the merge tools sign their own steps with `-sign-key kid:seed` (or
  `$PATCHLOG_SIGN_KEY`); original signatures are never re-sent.
- **Snapshot bundles** go through `{ns}-upstream` namespaces. Pinned references between snapshot
  documents are rewritten to them, keeping any `#id` fragment.
- **`-atomic`** lands each namespace as one batch, which needs an allowance for large imports
  (§6.6), within the deployment maximums (1,000 items and 16 MiB unless raised with
  `serve -max-items-per-batch` and `-max-batch-size`). **`-pace`** splits batches to fit the
  limits and paces them for backfills, at that fraction of the lower of the namespace's rate
  and the importer's own (`ratePerPrincipal`), counting every draw: dry runs, submits, blob
  uploads and copies. Where the importer has an allowance, batches follow its limits and are paced at its
  bucket's full rate, which holds up no other writer, until a minute before the allowance's
  `until`. A chain cut between two batches is also paced at `ratePerResource`, which an
  allowance doesn't replace. A `429` is waited out by its body's `retryAfter`.
- **Concurrent batches.** Under an allowance a backfill submits up to `-concurrency` batches at
  once (default 4), in dependency order all the same: a namespace's batches start once those of
  the namespaces it depends on have committed, and within a namespace a batch waits for one in
  flight that it goes on with or whose documents it pins. Items and namespaces are ordered by
  what they pin (schemas included), not by live references. Each request waits at its
  namespace's gate until the allowance's bucket, as answered requests left it, holds a token
  more than the requests in flight draw. A namespace has no more batches in flight than the
  allowance's burst holds the draws of, nor, where the allowance ends, than its rate draws in
  half the minute before `until`. The first failure stops the rest. Without an allowance,
  batches go one at a time.
- **Re-runs.** An import into a target that already has the bundle reads what it can't predict
  only: an upstream head that is the genesis of the rewritten snapshot is taken as unchanged
  without reading it, and an upstream chain is read only for a fast-forward that needs it.
- **Dry runs.** A batch is atomic, and a dry run draws the tokens its submit does (§6.6), so an
  import dry-runs only the first batch of each existing target namespace, before anything is
  written, and submits the rest directly; a failed submit lists its items as a dry run does. In
  a namespace the import creates, it dry-runs the first item of the first batch once the
  namespace exists, so a server that would give the revisions other ids stops it before
  anything is written there. A later batch that moves heads the target had (a fast-forward, a
  resolved conflict, a restore; not a snapshot's diffs upstream, which no live reference sees)
  is dry-run before its submit, its blobs sent first, since a failure after it would leave
  those heads moved (§G.4.4, v0.49); fresh imports make no extra dry runs. `-dry-run`
  dry-runs each existing namespace's first batch and those later ones, but for one that goes
  on with a chain an earlier batch cut, reporting failures that only need earlier batches
  written as deferred; it uploads no blobs (they show as deferred `blob` failures) and writes
  nothing.
- **Timings.** The summary's `time` line, and `timings` in `-json`, show where the time went:
  planning, blobs, batch requests (mostly the server's time), paced waits and waits after
  `429`s.
- **Grants.** With authentication on, the import runs under one grant with read and write
  (create, append, …) in every target namespace, signed by a key each of them lists, and an
  allowance there for speed. An operator grant only creates namespaces (§C.4), so create
  missing ones first, listing the importer's key and allowance; a `401` or `403` on the first
  read of a target namespace says so.
- **Branches** export with the base's history included, or with `-foreign-parents` naming the base revisions in `requires`.
- **Blobs** (§G.4.1) travel as blob lines (unpadded base64url; padded is accepted), each
  before the first line that mentions it: a `$blob` member in any op's value (tests too), the
  value of an op at `…/$blob`, a snapshot's document or a declared list. Incremental bundles
  leave out what the history up to `requires` referenced. Import checks each id and uploads
  the blobs a batch's steps bring in before the batch (a snapshot's to its upstream resource
  and target), or copies them with `Blob-From` within one deployment; uploads are repeated
  when half of `blobGrace` has passed. Within the deployment the bundle came from, the batch's
  local `source` already makes them available, so nothing is copied; if a dry run or submit
  shows it doesn't (the importer can't read the source unrestricted, §7.5), they are copied or
  uploaded after all, and a submit that failed only for them is sent again. A dry-run-only
  import uploads nothing and reports blob failures as deferred. An e2e namespace's blob lines
  must have the sealed type and no nonce, or the import is refused before anything is
  uploaded.

#### Encryption (§G.5.1)

```sh
patchlog bundle keygen -o me.jwk                         # prints the public JWK
patchlog export -ns secret -recipient them.jwk -o s.plb  # a sealed bundle
patchlog import -ns secret -i s.plb -identity me.jwk -atomic
```

- **`access`** in the header records each namespace's protection: `public`, `private`, `sealed`
  or `e2e` (missing means `private`). Export refuses to write private or sealed content unsealed
  unless `-plaintext`; `-identity` unwraps a sealed source's keys when the grant's `enc` names it.
- **Sealed bundles** (`application/vnd.patchlog.sealed-bundle+jsonl`): an envelope line with a
  random id and the content key HPKE-wrapped per recipient (kid: RFC 7638 thumbprint), then one
  JWE per bundle line with `pl: {bundle, line}` and `last` on the final one. Reordered, spliced,
  truncated or extended bundles are rejected; `source.bundle` is the plaintext bundle's digest.
- **Import** refuses a target less protected than its source (private or sealed into a public
  one) unless `-allow-less-protected`, and creates missing targets as protected as their source
  (sealed ones sealed, with a fresh `$nonce` in the patch sets the importer makes). A snapshot
  import creates the upstream namespace with its target's `nonce` setting (§C.7), and where
  nonces are required its generated patch sets carry a fresh one too. A full-history import
  whose revisions lack nonces into a target that requires them is refused before anything is
  written: import a snapshot instead.
- **E3:** full history carries the ciphertext and the `keyring` verbatim; ids verify over it. It
  imports only into an e2e namespace of the same name (sealed patch sets bind `pl.ns`), which a
  missing target is created as, moved up to the bundle's epochs. Diverged e2e documents can only
  be skipped: comparing or rewriting them needs a client with the keys (§F.8).

### Importing external schemas (§6.1)

How do I use a schema from [schemastore.org](https://www.schemastore.org) (or any other URL, or
a local file)? A document's `$schema`, and a schema's `$ref`, can only name an immutable schema
revision on this deployment (`/r/{ns}/{name}/rev/{id}`, optionally `#/json/pointer`), so the
schema and everything it references must first be brought in as schema resources, with their
references rewritten. `patchlog schema import` does that:

```sh
patchlog schema import -api http://localhost:8080 -ns schemas -author me \
  https://www.schemastore.org/petstore-v1.0.json
# SOURCE                                          RESOURCE       ACTION  PATH
# https://www.schemastore.org/petstore-v1.0.json  petstore-v1.0  create  /r/schemas/petstore-v1.0/rev/1h7u…
```

The last row is the root: paste its path into a document's `$schema` (or another schema's `$ref`).

- **Fetching.** The given URLs or files and, transitively, every document they `$ref`, relative
  refs resolved per JSON Schema base-URI rules (`$id` in the document and its subschemas; `id` in
  draft-04). Only http(s) and local files, and a remote document may not reference a local one.
  `-max-docs` (100), `-max-bytes` (32 MiB in total) and `-timeout` (30 s per fetch) bound it.
- **Conversion** to draft 2020-12 as the server accepts it (§6.1, §6.5): `$schema` becomes the
  2020-12 dialect URL; `definitions` → `$defs`, array `items`/`additionalItems` →
  `prefixItems`/`items`, `dependencies` → `dependentSchemas`/`dependentRequired`, draft-04 boolean
  `exclusiveMaximum`/`exclusiveMinimum` → numbers; `$id` and `$anchor` are dropped, since every
  reference is resolved; unknown keywords (schemastore's `markdownDescription`, `tsType`, …)
  become `x-*` annotations, which don't change validation. Each kind of change is reported.
- **Closed schemas type documents as they are.** Validation leaves out a document's top-level
  `$schema`, and a top-level `$nonce` of the fresh-nonce form (§6.2 step 5, since spec v0.36),
  so a schema closed at the root (`additionalProperties: false`) needn't declare them, and the
  import leaves it unchanged. For servers before v0.36 (patchlog before v0.7.0),
  `-declare-schema` (`Options.DeclareSchema`) adds `"$schema": {"type": "string"}` to the
  `properties` of every subschema that applies at the instance root (the root and what it
  reaches through `$ref`, `allOf` and, conservatively, every branch of
  `anyOf`/`oneOf`/`if`/`then`/`else`/`dependentSchemas`) and is closed without already covering
  `$schema`, and reports the count; a patched subschema also used below the root permits a
  `$schema` key there too, and one with `maxProperties`, or a `propertyNames` that rejects
  `$schema`, is left alone with a warning.
- **The source is kept.** `$id` can't be (§6.1), so each imported resource's root gets
  `"x-source"` (the URL it was fetched from, or the upload's name) and, when the document
  declared another `$id` (draft-04 `id`), `"x-source-id"`; so does each document bundled under
  `$defs` for a cycle. This changes content and so revision ids: re-importing something imported
  with v0.4.0 appends new revisions.
- **References.** Every `$ref` becomes either a same-document pointer (`#/$defs/…`) or the
  revision path of its target plus a JSON Pointer. Plain-name fragments (`#foo`: `$anchor`,
  `$dynamicAnchor`, draft-07 `"$id": "#foo"`) are resolved to pointers, since §6.1 resolves none
  across revisions. A `$ref` to a JSON Schema meta-schema (accepted by no server in `$ref`) is
  dropped with a warning, kept as `x-meta-ref`; that subschema then accepts anything.
- **Names** come from the URL's last segment (`petstore-v1.0.json` → `petstore-v1.0`), sanitised
  to resource names (§3.6); `-name` names the root. Colliding names keep the base name for the
  root (else the smallest URL); the others get `-` and 8 hex digits of their URL's SHA-256.
- **Order and cycles.** A revision can only reference revisions that exist, so the schemas are
  written leaves first, each revision id predicted client-side (§3.3) and pinned by its
  dependents. Documents that reference each other in a cycle can't pin each other: each cycle
  is merged into one resource (the root, else the smallest URL), the others under `$defs`, and
  reported. Their rows show the bundled path, e.g. `/r/schemas/a/rev/1…#/$defs/b`.
- **Checked, then written atomically.** Every converted schema is compiled as the server will
  (regular expressions must be RE2, §6.6) before anything is written; a failure refuses the
  import with the schema and the reason. Then one batch (§7.5), or dependency-ordered batches
  when beyond the namespace's `itemsPerBatch`/`batchSize`.
- **Idempotent.** A resource whose head already holds the converted content is reused
  (`unchanged`), so a re-run with unchanged sources writes nothing. A changed source appends a
  revision (`If-Match` the head, `append`) to it and to every schema that pins it, which then
  pins the new revision; documents keep validating against the revision they name (§6.3).
- **`-dry-run`** fetches, converts, compiles and prints the plan without writing (without
  `-api`, every resource is planned as a create). **`-json`** prints `entries`
  (`source`, `resource`, `path`, `action`, `root`), `bundled` and `warnings`.
- **In the playground.** The same plan and write are available from the Schemas tab
  ([Playground](#playground)), with uploaded files as well as URLs; the core fetches URLs only
  with `serve -schema-fetch`, and then never from private addresses unless the host is in
  `-schema-fetch-hosts`.

### A short tour (dev mode)

```sh
B=http://localhost:8080; P='Content-Type: application/json-patch+json'

# Create a namespace (its document is the genesis patch set).
curl -X PATCH $B/ns/matches -H "$P" -H 'If-None-Match: *' \
  -d '[{"op":"add","path":"","value":{"read":"public"}}]'

# Create a resource, then append to it with the id from ETag.
curl -i -X PATCH $B/r/matches/derby -H "$P" -H 'If-None-Match: *' \
  -d '[{"op":"add","path":"","value":{"score":"0-0"}}]'
curl -i -X PATCH $B/r/matches/derby -H "$P" -H 'If-Match: "1…"' \
  -d '[{"op":"replace","path":"/score","value":"1-0"}]'

curl -i $B/r/matches/derby                  # 302 to /r/matches/derby/rev/{head}
curl -L $B/r/matches/derby                  # the document
curl -L "$B/ns/matches/log"                 # the namespace log
```

## Grants

Grants are Biscuit v3 tokens (§C.8), implemented directly on Biscuit's protobuf schema and
signature scheme in `internal/grant` (no Biscuit library dependency):

- The authority block carries the root block and each appended block one narrowing block. Every
  block holds exactly one fact, `grant_block("<canonical JSON>")`; the string must be I-JSON and
  equal to its canonical form. Anything else in a block (other facts, rules, checks, scopes,
  public keys, a non-empty context), a third-party block, or a key that isn't Ed25519 makes the
  token invalid (`401`). Biscuit's Datalog is never evaluated: the JSON blocks are checked as
  §C.2 says, validity times come from their `nbf`/`exp`.
- Signatures are Ed25519 throughout (the ephemeral next keys too), verified strictly (RFC 8032,
  `S < L`, as Go's `crypto/ed25519` does). New blocks use Biscuit's signature payload version 1;
  versions 0 and 1 are both verified. The root key is named by `kid` in the root block
  (`rootKeyId` is ignored).
- Sealed tokens are accepted, and `patchlog grant … -seal` / `patchlog grant seal` produces them:
  a sealed grant can't be narrowed any further.
- Transport: `Authorization: Bearer <token>`, Biscuit's URL-safe base64 (written padded, read with
  or without padding and with or without the `biscuit:` prefix). The grant size limit applies to
  the decoded bytes.
- The grant id is `trunc160(sha256(canonical(root block)))`; a block's revocation id is
  `text(trunc160(sha256(its Biscuit signature)))`, so revoking the authority block revokes every
  grant narrowed from it.
- The stored, non-bearer form (§C.3) is the same protobuf message without its proof: every block
  signature still checks, but it isn't a token.

Compatibility is checked in `internal/grant/biscuit_vectors_test.go` against the Biscuit
specification's sample tokens (made by the reference implementation, biscuit-rust: v0 and v1
signatures, sealing, third-party and P-256 blocks, revocation ids; our payloads re-signed with
the sample root key reproduce the reference signatures byte for byte) and against tokens built
with the official Go library, biscuit-go v2.2.0, which decode, verify and narrow here.
biscuit-go v2.2.0 parses our tokens but only knows signature version 0, so it can't verify them.

Status codes (§C.2, §7): a grant not naming the namespace in every block that carries `ns` is
`403` before anything is verified or looked up, whether or not the namespace exists; no usable
grant (missing, malformed, badly signed, unknown key, revoked, expired, not yet valid) is `401`;
a valid grant that doesn't allow the request is `403` (`404` on reads, which hide existence). A
namespace that doesn't exist answers like an existing non-public one: `401` without a usable
grant (a grant naming it can only be verified by an operator key, and only a forced purge then
gets `404`). Public namespaces ignore an unusable or unrelated grant on reads.

`/ns/{ns}` and every URL under it but the gestures listing and `POST /ns/{ns}/keys` (the
namespace document, its log, events and long-polls, `/heads`, `/branches`, `/grants/…`) need
**unrestricted** read (§C.5, v0.47): the key has no `readScope`, no rule in the grant's blocks or its key's scope refers to
`/resource`, and, with roles, one role listing `read` has no such rule. A grant that reads only
some resources gets `404` there, as for any read it may not make, so it can't list the names
and heads its reads hide; a resource's own URLs, its event stream included, need read on that
resource only. Branching, remote registration and a batch's source check need unrestricted
read too; branching and registration check it as gate step 1 checks verbs, in a public
namespace too (v0.49): the grant must allow `read`, read unrestricted and pass its rules on
`/action`, `/principal` and `/now` with `/action` `read`, rules on `/doc` left to step 6.

A purged namespace (§8.5, §12) answers `410` with `code: "purged"` and `head`, the `ns_id` of
its `purge-ns` entry, which is the log's last (v0.49), so a consumer needn't re-read
`/ns/{ns}`: on `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…` (sealed and e2e
namespaces included), `POST /ns/{ns}/keys` and `/heads` at any revision, after the read check,
the grant's rules included; and on every write, after authorisation and rate limits and before
any other check: resource writes, batches (one with a config change after its items'
authorisation), blob uploads and copies, purges, prunes, config writes, namespace purges,
branching from it and remote registration. `/ns/{ns}` and its log stay readable, and the log's
`purge-ns` entry says what happened. The name stays reserved: creating a namespace or branch
under it is `412`, also a retry of the request that created a branch since purged.

`requireAt`: `at` must have been the head of its namespace at some point within `maxLag` before
the grant was issued, issuance taken as `max(nbf, exp − maxTtl)` of the root block (`nbf` when
the key sets no `maxTtl`, the time of the check when there is neither). `maxLag` is the
namespace document's (default 60 seconds), or the key's when stricter. A grant issued in time
stays valid after the head moves on, until it expires.

```sh
# A root grant signed by a key listed in the namespace document (kid "ops-2026")…
./patchlog grant mint -key <SEED> -block \
  '{"kid":"ops-2026","sub":"user:bob","ns":["matches"],"can":["read","append"],"exp":"2026-12-31T00:00:00Z"}'
# …narrowed for a translation service.
./patchlog grant narrow -grant <TOKEN> -block \
  '{"via":"svc:translator","can":["append"],"rules":[{"op":"writes","within":["/i18n"]}]}'
```

Namespace keys look like `{ "kid", "alg": "ed25519", "pub": <base64url>, "can": [...], … }`
with the key-scope fields of §C.4. Operator keys (`-operator-key`) get kid `operator`
(then `operator-2`, …) and may create namespaces; a creating grant lists the new
namespace's name, which need not exist yet, or `"*"`, in `ns`. Only operator grants may use
`"*"`: a grant signed by a namespace key that names `"*"` is refused with `403` (it is valid, it
just doesn't apply). An operator grant authorises exactly three things (§C.4): creating a
namespace with its genesis document, creating a remote branch with the schema histories it
mirrors, and forcing a purge or namespace purge (`?force=1`). Anything else under one is `401`,
as for a key the namespace doesn't list, also for a namespace that doesn't exist (a forced purge
of one is `404`); reads of a public namespace ignore it. An operator who needs more adds a key
to the namespace document.

**Keys follow the base** (§C.4). A branch accepts its base's *current* keys as well as its own,
recursively through every local base: a key added to the base after branching works in the
branch, one removed or replaced there stops working in every branch. A kid both have is the
base's: only the base's entry (its `pub` and scope) is accepted. Keys added only to the branch
(with a base `*` key) are its own. Remote branches keep their own keys. Archives list the keys
the bases had at the recording entry as candidate keys too (§C.3.1).

### Author signatures

A root block may list the principal's signing keys, and a client signs each write over
§C.3's input (tombstones with `tombstone` in place of the patch set):

```sh
patchlog grant mint -key "$NSKEY" -block '{"kid":"editors","sub":"ann","ns":["docs"],
  "can":["append"],"exp":"…","signers":[{"kid":"ann-1","alg":"Ed25519","pub":"<43 chars>"}]}'
```

- The gate verifies a signature whose kid the grant lists (`422 signature`) at §6.2 step 2.3:
  after rate limits, the idempotent-retry lookup and settling the verb, so a retry is answered
  as first recorded and authorisation failures come first. The parent is the one the
  precondition names (the `If-Match` id, none for a create); a write without a usable
  precondition gets `428` or `400`. A malformed `Signature` is `400`, and so is the header on
  a batch: each step object carries its own `signature`.
- `"signatures": "required"` in the namespace document (a `*` key) makes every revision and
  tombstone need a valid signature by a signer of its grant. Narrowing blocks can't carry
  `signers`, so delegated grants can't write there.
- Resource logs serve each revision's `grant: { id, sub, kid }` and `signature`, and
  `GET /ns/{ns}/grants/{gid}` serves the stored grant (`{ id, root, stored }`) to readers with
  unrestricted `read`: sealed in sealed namespaces (`pl: { ns, grant }`, stored once), in the
  clear with `Cache-Control: private` in end-to-end ones, and `410` once the namespace is
  purged. An operator key authorises only within its `from`–`until` period.
- `GET /` gives `jwks_uri`, by default `/.well-known/patchlog-keys`: the operator key history
  as a JWK Set, each key with `"patchlog": { "from", "until"? }`. `serve
  -operator-key-history KID=PUB,FROM[,UNTIL]` records retired keys (published, but they
  authorise nothing); a configured operator key without a period is published from the
  deployment's first namespace log entry. `-jwks-uri` points it elsewhere.
- The Go client signs with `client.WithSigner(sig.Key)`.

## Design notes

- **A delete's `doc` (§6.4.1).** The envelope of a `delete` carries the document
  being deleted as `doc`: the resource's last live document as the namespace sees it (read
  through its bases in a branch, or produced by the item's earlier steps in a batch).
  `patches` is `[]` and `writes` is `[]`, as before. Rules can then decide deletes by content,
  e.g. only a document's owner may delete it:
  `{"if":[{"op":"test","path":"/action","value":"delete"}],"then":[{"op":"compare","path":"/doc/owner","eq":{"path":"/principal/id"}}]}`.
  At E3 the server can't see the document, so `doc` stays `null`. `purge` keeps `doc: null`.
  A batch item with two `"delete"` steps in a row is `422 invalid`. Unplace grants from the
  catalog service fix `/doc/parents` to the parents checked (§B.11.4).
- **Heavy work outside the write lock (D.3).** Resource writes and batches run steps 1–6 of
  the gate (§6.2: authorisation and rate limits, idempotent-retry lookup, frozen,
  precondition, apply, limits, schema validation, rules) in a read transaction, without the
  write lock. They then take the lock (an in-process mutex plus `BEGIN IMMEDIATE`, which also
  serialises other processes sharing the file) and re-check, inside that transaction, that
  everything the decision read is unchanged: every namespace consulted (the target, every
  base whose keys and revocations apply, §C.4, the namespaces of resolved schemas, of a
  `requireAt` and of a batch source) keeps its config revision, frozen and purged flags;
  every item's resource keeps its state and head (or its absence), read through bases in a
  branch; and every schema revision resolved from storage is still available to the writer
  (a schema referenced only by the pending write can be purged meanwhile). If so the write is
  inserted; the configuration, heads and revocations it was checked against are exactly those
  it is inserted against, so invariant 6 holds. If not, it rolls back and redoes the whole
  check, so a moved head is answered `412` with the new head, and an idempotent retry that
  landed meanwhile is answered `200`. After three rounds the gate runs entirely inside the
  lock, so a write always terminates. Rate-limit tokens are drawn once per request. Error
  precedence is unchanged: a refusal is decided on one consistent snapshot, in §6.2 order.
  `UNIQUE (res, parent_seq)` and `UNIQUE (ns, prev_seq)` remain the safety net: a violation
  is treated as a lost race and redone. Caches, CDN purges and live readers hear of a write
  only after it commits. Dry runs stay read transactions. Config writes, batches with a config
  change, branch creation, purges, prunes and remote-branch creation are rare and still run
  their whole gate inside one write transaction.
- **Additions to the D.2 layout**: `namespaces.head_seq/config_seq/base_config_seq`,
  `ns_log.body` (the canonical entry exactly as hashed) and `ns_log.config_seq`,
  `ns_config.doc`, `revisions.signature/schema_ref`, `resources.keep`, `heads.seq`, `deks`
  (wrapped data keys of encryption at rest, Addendum E.1), `epoch_keys`, `rev_epochs` and
  `sealed` (sealed namespaces, Addendum E.2); and
  for §G.3 `remote_branches` (registrations at the source: base, remote origin and name,
  `at`, latest and previous entry, expiry), `remote_bases` (per remote branch: its shadow,
  A's origin, namespace and `at`, the follow checkpoint and the registration at A) and
  `remote_notices` (purges seen in A's log, applied or not).
- **Documents are cached by revision id**, since an id determines its document everywhere
  (§3.3). Head snapshots are kept only for documents up to 16 KiB. An intermediate snapshot is
  written after every 100 revisions or 64 KiB of patch sets, so every read folds from the nearest
  snapshot and never folds more than that (D.4). A genesis that adds the whole document counts
  as its snapshot: the count starts after it, and a read there cuts the document from its
  canonical patch set.
- **Namespace-document members** (§7.4). A namespace document may hold only the members the
  spec defines: `read`, `keys`, `roles`, `revoked`, `rules`, `limits`, `allowances`,
  `retention`, `encryption`, `maxLag`, `base`, `frozen`, `successor`, `drafts`, `signatures`,
  `schemaReads` and `nonce`, Addendum B's `catalog` and `catalogs`, and Addendum F's `merge`,
  `merged`, `cleanup` and `abandoned`. Any
  other member must start with `x-` (`"x-title": "Docs"`) and is stored as data. Creating a
  namespace, a config write (in a batch too), creating a branch (the base's document plus the
  patches) and a remote branch's genesis answer anything else with `422`, `code: "invalid"` and
  `errors: [{ "pointer", "message" }]`, as for schema validation (`"pointer": "/title"`; the
  body's `message` repeats the error), saying other members must start with `x-`. The check
  runs before the `*`-key guard. Other invalid namespace documents (a malformed `read`, `keys`,
  …) answer the same way, with the pointer their message names. The addenda's members are
  checked in their shapes: `catalog: { trust?: [namespace names], mode?: "tree" | "dag" }`,
  `catalogs: { <catalog>: { place?: ["group:…" | "user:…"] } }`, `merge: { authors: [{ sub,
  kid }] }`, `merged: { at: ns_id }`, `cleanup: { merged?, superseded?, abandoned? }` (ISO
  8601 durations), `abandoned` a boolean; and `revoked` lists revocation ids. `catalog`, each
  `catalogs` entry, `merge`, `merged` and `cleanup` may also carry `x-` members (v0.38); the
  keys of `catalogs` are catalog names, so they are checked as names, never as `x-` members.
  Role entries keep their other fields (`move`, `place`, `includes`), which the core ignores
  (§C.1.1); key entries, `merge.authors` entries and the core's nested objects are strict
  (key entries hold only the fields of §C.4; `x-` fields too are refused). **Upgrading:**
  documents stored by an earlier version are served as they are. A config write keeps a member
  the namespace's current document holds, if the write leaves it unchanged, and likewise
  entries of `revoked` and `keys`, so such a namespace can still be frozen, rotated and merged,
  and a revocation added next to a malformed one; a write may remove it; one that adds or
  changes it gets the `422`, and a `{"op":"move","from":"/title","path":"/x-title"}` renames
  it. A branch is a new
  namespace: it keeps the base's members the spec defines as stored, but a member it would
  inherit that isn't one is refused (the message gives the `move` the branch's patches can
  rename it with). Bundles carry no namespace
  documents, so an import from an older deployment brings no such members (§G.4); a remote
  branch's shadow keeps only the `encryption` fields this version defines of an e2e base's.
- **Paged log ranges** (§7.1). `…/rev/{id}/log?since=` (resources and namespaces) answers at most
  the log page size of entries (§6.6, default 1,000, `serve -log-page-size`), oldest first; a
  range that goes on carries `X-Log-Next: {id}`, the page's last entry and the `since` of the
  next page, an immutable range up to the same id, so every page caches as immutable. Errors are
  the range's on every page: a range crossing a pruning horizon is `410` on all of them. A page
  costs its own rows, however long the range: a resource's chain is its rows in seq order, so a
  page is one `seq > ? … LIMIT` query per ancestry segment it reaches, after a query or two per
  segment to place `since` and look for pruned patch sets, which only exist at or below a
  resource's horizon (or in a purged one); a namespace page is one `LIMIT` query. The rows a
  page reads are checked to chain (each one's parent is the row before it), so a broken chain is
  a `500`, never a range with rows that aren't ancestors. Long-polls (§7.7) answer pages of the
  same size and shape, without `X-Log-Next` (their header names the next `since`), and `/heads`
  pages are as long. Event streams (§7.3) catch up a page per fetch too, before they go live, so
  a stream from far back never builds (or, sealed, seals) the whole history at once. In an e2e
  namespace, a range or page whose `since` is a pruning horizon holds only the entries after it:
  the horizon's sealed snapshot is served as `/rev/{H}`, never as a log entry, so a page whose
  `since` became the horizon between two reads (pruned at the previous page's end) is like any
  other, and every e2e fold (the client's `DocE2E`, and so merge and rebase, PruneE2E, derived
  views; the playground) fetches `/rev/{H}` when it starts at the horizon. Every reader follows pages and treats a page that stops short of the range's id without
  `X-Log-Next` as an error: `client.Log`, `NSLog` (one page each: `LogPage`, `NSLogPage`) and e2e
  folds, and so `follow` (catch-up delivers and checkpoints page by page, §10), the index (`?min`
  checks only the first page), tree and catalog, merge, rebase, release and janitor tooling,
  bundle export and import (whether `requires` is in the target's chain takes one page), remote
  branches mirroring and following their bases (§G.3), and the playground (namespace logs,
  histories and e2e folds; each sealed page is opened as its own range).
- **Allowances** (§6.6): `allowances: [{ sub, kid, bucket: { rate, burst }, itemsPerBatch,
  batchSize, until? }]` in a namespace document gives one principal its own bucket (replacing the
  principal and namespace buckets, and a key scope's lower rate) and batch limits, until the
  optional RFC 3339 `until`. They can go
  up to the deployment maximums, set with `serve -max-items-per-batch` and `-max-batch-size`
  (the flag accepts `64MiB`; the document takes bytes).
- **Limit names** in a namespace document's `limits` object, exactly as §6.6's table:
  `patchSetSize`, `opsPerSet`, `documentSize`, `valueSize`, `pathSize`, `nestingDepth`, `rulesPerNamespace`,
  `rulesPerGrant`, `grantSize`, `itemsPerBatch`, `batchSize`, `branchesPerNamespace`,
  `keepPerResource`, `blobsPerDocument`, `blobSize`, `blobPending` (integers, sizes in bytes,
  lower only), `ratePerResource`, `ratePerPrincipal`, `ratePerNamespace`, `blobRate`
  (`{ rate, burst }`, `blobRate` in bytes), `retryWindow`, `remoteRegistration` and `blobGrace`
  (ISO 8601 durations; `blobGrace` at least `retryWindow`). Sizes written with units (`"64 MiB"`), unknown or
  v0.20 names (`liveBranches`, `remoteBranchLife`) and the deployment-only `logPageSize` and
  `branchDepth` are `422`. Creates, and restores from scratch, may be as large as
  `documentSize`; `valueSize` and `pathSize` bound strings and pointers, and an e2e namespace
  needs `3 × (valueSize + pathSize) + 1 KiB + 36 B × blobsPerDocument ≤ patchSetSize`.
  `$blob` objects must be well-formed and name available blobs that match their type, size
  and nonce (`422`, `code: "blob"`). Allowances may also set `blobRate` and `blobPending`; the
  deployment maximums are set with `serve -max-blob-size` and `-max-blob-pending`.
- **Batch sources** (§7.5, §7.8): a local `source.at` is checked against `source.ns`'s chain
  (`422`, `code: "source"`) at step 4, before blob references, only when the caller may read
  `source.ns` unrestricted (with `Source-Authorization`, if given); then the blobs attached to
  the same resource there, or in a base it reads through, are available as `source.ns` sees it
  at `source.at`. Anyone else's source is recorded unchecked and makes no blobs available. A
  dry run reports an unavailable blob and runs the later steps anyway: the item reports
  `blob` with the ids it would produce, or a later step's failure with the blob failure under
  `blob`. A write referencing a blob ends every pending entry for it in that resource.
- **Batch limits after authentication** (§7.5): the server authenticates a batch before
  reading its body, and stops reading at the principal's `batchSize` (its allowance's, if any,
  plus room for the batch's own JSON) with `413`. Item counts and the patch-set total are
  checked at step 4.
- **Candidate verbs** (§6.2): a `PATCH` with `If-Match` (in a batch, an item whose first step
  is a patch set) passes step 1 with `append` or `restore`; step 2 settles the verb from the
  resource's state (a branch's view, read-through included) after the idempotent-retry lookup
  and before frozen and the precondition, so a grant that can't restore gets `403` on a
  tombstoned resource, whatever `If-Match` says.
- **Namespace log entries** are `{ …entry, id, prev?, author, grant?, gesture?, undoes?,
  gestures?, created }` (§7.4). `author`, `grant`, the gesture members (see Gestures) and
  `created` are stored alongside the hashed entry, not in it. `grant` is
  `{ "id", "sub", "kid" }`: the id (§C.3) of the grant the entry was written under, stored as
  `ns_log.grant_id` (D.2), and its root `sub` and `kid`, stored in plaintext next to the
  non-bearer grant (`grants.root_sub`, `root_kid`; neither is secret, the log serves both), so
  reading a log never needs the key store even when the grant itself is encrypted at rest
  for some at-rest namespace. Opening a database from before them fills them for grants
  stored in plaintext; grants an earlier version stored encrypted are still decrypted to
  serve them. Every kind of entry written on a request has one (`head`,
  `tombstone`, `purge`, `config`, `batch`, `branch` (local or remote), `purge-ns`, `prune`), in
  sealed namespaces inside the sealed ranges. Entries the server writes itself have none, though
  they keep an author: purges propagated to branches (the purger), the schema namespaces a
  remote branch mirrors (its creator), purges applied from a remote base, retention's prunes
  and epoch rotations. Entries written on a request with authentication disabled record
  `"grant": null` (`ns_log.no_auth`, v0.38), so tools can tell them from the server's own;
  references recorded while authentication was on are still served if the database is later
  served with `-dev`. Entries a development server wrote before v0.38 can't be told from the
  server's own (neither stored anything): opening such a database adds `no_auth` empty, so they
  keep serving no `grant` and count for no one, and an `"abandoned": true` or merge batch
  written that way in development must be written again to count. Merge tools and
  the janitor match the grant's root `sub` and `kid` against the base's
  `merge: { authors: [{ sub, kid }] }` (§F.3, §F.6), which the server validates and guards with
  a `*` key like `/keys`, and the janitor accepts `"abandoned": true` only from an entry whose
  grant's root key is a `*` key of the branch. Databases from before v0.37 recorded only the
  root `kid` (`ns_log.kid`, kept but no longer read): opening one adds `grant_id` and fills it
  for `head`, `tombstone` and `batch` entries from the revisions they record, which store the
  request's grant (in the same transaction as adding the column). Their other entries
  (`config`, `branch`, `purge`, `purge-ns`, `prune`) serve no `grant`: a kid alone can't make a
  §C.3 grant reference, which names the grant by id. Sealed log ranges stored before the
  upgrade are served as sealed then (§E.2.2: stored once, served forever), with `kid`, which
  the client no longer reads. The cost: tools count those entries for no one, so an
  `"abandoned": true` set before the upgrade must be set again, and a merge batch the backfill
  couldn't fill (only `[]` items, or config only) no longer counts as a common ancestor.
- **Gestures** (§7.2, §7.4, §7.5, v0.39). `Gesture` and `Undoes` on `PATCH`, `DELETE` and
  restores, each one gesture id (`^[a-z2-7]{26}$`, otherwise `400`; blob uploads, purges and
  prunes write no revision or tombstone and don't read them), are stored with the revision
  or tombstone (`revisions.gesture`, `undoes`, with partial indexes, D.2), outside its id and the
  change envelope, so ids don't depend on them and rules never see them; pruning keeps them
  (§8.6), purges keep them with the ids. Write responses carry `Gesture`/`Undoes` naming what the
  entry recorded, so an idempotent retry, answered with the entry as first recorded, says so
  whatever it sent. In a batch a step may be `{ "patches": [...] | "delete": true, "gesture"?,
  "undoes"? }`; an item's and the batch's `gesture`/`undoes` are defaults, a step's own values
  override each, and the older step forms (`[...]`, `"delete"`) still work. Resource log entries
  carry `gesture?`/`undoes?`; namespace entries of single writes `gesture?`/`undoes?`, and batch
  entries `gestures: { resource: [{ gesture?, undoes? }, …] }`, one object per step (`{}` for a
  step with neither) for every resource of the batch, the member left out when no step has one.
  None of them are hashed: namespace entries keep them beside the hashed body
  (`ns_log.gestures`) and merge them in when served, by ranges, long-polls and event streams
  alike; sealed namespaces seal them inside their entries (§E.4), e2e ones serve them in
  plaintext. Opening an older database adds the columns and indexes empty.
  `GET /ns/{ns}/gestures/{gesture}` (optional in the spec) lists `{ resource, id, kind,
  gesture?, undoes?, author, ns_id }` for every revision and tombstone written with the gesture
  or undoing it, in insertion order (a resource's chain order; across resources, the order of a
  client's successive saves), `no-store`. Pages are as long as log pages; `X-Log-Next` names the
  next page's `after`, `{resource}/{id}` of the page's last entry (ids repeat across resources),
  and the last page has none. It answers any reader, listing only entries of resources its
  grant may read (a cursor naming another resource is `404`; v0.46, before it needed
  unrestricted read), answers `404 not_offered` in sealed and e2e namespaces after
  authorisation (`410 purged` first in a purged one, v0.49), leaves out purged resources, and
  in a branch lists only the
  branch's own rows, not what it reads through from its base (ask the base). Merges carry each
  fast-forwarded or replayed revision's gestures in their steps (§F.3), and remote branches
  mirror them; squashes don't. The client library sends them with `client.WithGesture`,
  `WithUndoes` (writes, `Delete` included), `Step.Gesture`/`WithGesture` and
  `BatchItem`/`BatchRequest` defaults, reads them from `WriteResult`, `LogEntry`, `NSEntry`
  (`Gestures` for batches) and lists with `Gestures`/`GesturesPage`; `client.NewGesture` makes
  an id.
- **Query parameters** (§7): every core endpoint accepts only those the spec defines for it
  (`since`, `live`, `cursor`, `after`, `dry-run=1`, `force=1`, each on its own routes, and
  `prefix` on `DELETE /edge-grants`, the one that may repeat), and answers anything else, a
  repeated parameter or another flag value with `400 bad_input`, `no-store`, before
  authentication.
- **`GET /`** answers `{ "spec": "0.49", "auth": "grants" | "disabled", "origin", "jwks_uri" }` (§1, §7,
  §G.1): the spec version, dotted decimal, from one constant (`core.SpecVersion`), and whether
  authentication is on. `client.Root` reads all three; `client.AuthDisabled` asks again every
  time, for tools that decide on the mode. A remote branch reads its base's namespace
  documents and ignores members it doesn't define, so neither an unknown member nor the
  base's `spec` is a reason to refuse (§7.4, §G.3). Only a tool that copies a namespace
  document into a namespace would refuse unknown members that don't start with `x-`; this
  repository has none (bundle imports create namespaces from a fresh document, §G.4).
- **`PATCH /ns/{ns}`** answers `201` with `X-Config-Revision`, `X-Namespace-Revision` and
  `Location: /ns/{ns}/rev/{ns_id}`, naming the entry it wrote, and the body
  `{ "config", "ns_id" }` (§7.4); an idempotent retry answers `200` with the same, also when
  the config change was written by a batch. `client.PatchConfig` and `CreateNamespace` return
  both.
- **Retries and purges** (§6.2, §7.2): the idempotent-retry lookup never applies to a purged
  resource, so a write, or a batch with an item for one, answers `410` like every URL of the
  resource, before the frozen check (purges are allowed in frozen namespaces). A retried
  batch whose config change is stale by then answers `410` too, not the config's `412`, which
  would tell the client its change didn't apply when it did. Nor does it apply in a purged
  namespace, where every write is `410 purged`, with `head`, at that point (§8.5, v0.49).
- **Blobs before a restore** (§7.8): a tombstoned resource accepts uploads (only a purged one
  is `410`, and any upload to a purged namespace `410 purged`), so a restore can reference
  blobs uploaded after the delete, by a grant that may only restore.
- **A forced schema purge** (`POST …/purge?force=1`, §6.1) needs a deployment operator key, or in
  a branch a `*` key of the branch; its entries say `"forced": true`.

## Layout

```
cmd/patchlog        CLI: serve, keygen, grant mint/narrow
internal/playground web UI served at /playground/
internal/client      typed API client (+ clienttest: in-process server)
internal/follow      §10 consumer loop with transactional checkpoints
internal/verify      id and chain verification (§G.2)
internal/grantcheck  local grant checks for services
internal/annot       x-* annotations and x-ref references
internal/index       search index service (Addendum A)
internal/merge       merge, rebase, status, diff; release merges and rebases (Addendum F, §F.9)
internal/release     release documents (§F.9)
internal/janitor     branch cleanup with claim verification (§F.6)
internal/tree        tree service: folders, placements, links, manifests (§B.2–§B.9)
internal/catalog     tree-derived access and grant issuing (§B.11)
internal/bundle      bundle format, export and import (§G.4)
internal/archive     file:// archives for pruning and offline restore (§8.6)
internal/pgtest      a fresh Postgres database per test (PATCHLOG_TEST_PG)
internal/testenv     test-suite knobs: the log page size of test servers (PATCHLOG_TEST_LOG_PAGE_SIZE)
internal/keystore    master key file and key wrapping for encryption at rest (Addendum E.1)
internal/seal        JWE sealing, key derivation, HPKE wrapping, $nonce (Addendum E)
internal/jsonv      I-JSON parsing, JCS canonicalisation, equality
internal/ids        content-addressed ids (§3.2–§3.5)
internal/pointer    JSON Pointer
internal/patch      JSON Patch and the `writes` of §6.4.1
internal/rules      the rule language of §6.4.2
internal/schema     $schema resolution and JSON Schema validation
internal/schemaimport external JSON Schemas into a namespace, refs pinned (schema import)
internal/grant      grants, keys, roles and verification (Addendum C)
internal/core       storage and semantics (gate, batches, branches, purge, prune)
internal/server     HTTP API
internal/lifecycle  /_health and /_ready, phased graceful shutdown (serve, index, tree)
internal/cdnpurge   HTTP cache-tag purges to a CDN (-purge-url)
internal/edge       the verifying edge's secret, private edge directives and edge-grant cookies (§9, §C.5)
internal/telemetry  OpenTelemetry from OTEL_* (off by default), HTTP handler and transport
deploy/varnish      the compose stack's local CDN (Varnish VCL)
```

`go test ./...` runs the unit and HTTP integration tests. `PATCHLOG_TEST_LOG_PAGE_SIZE=2 go test
./...` starts the API consumers' test servers (`clienttest`, bundles) with log ranges paged after
two entries, so every multi-page path runs; each consumer package also has a `TestPagedFlows`
that runs some of its flows that way (`clienttest.Paged`), and the server package tests paging,
sealed page bounds and `/heads` byte order directly (with `PATCHLOG_TEST_PG`, also on a database
whose default collation isn't byte order).

## License

MIT, see [LICENSE](LICENSE).
