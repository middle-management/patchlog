# patchlog

This is the **reference implementation** of the **Patch Log** specification. The
canonical text of the specification is maintained outside this repository;
[docs/SPEC.md](docs/SPEC.md) mirrors it, with the spec's own change log in
[docs/SPEC-CHANGELOG.md](docs/SPEC-CHANGELOG.md), and deltas the reference takes that the
text doesn't yet describe are collected for its writer in
[docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) — when the two disagree, the
reference and this README are what implementations are measured against, and the
mirror follows. The test vectors are SPEC.md Addendum I (normative);
[internal/vectors/addendum_i_test.go](internal/vectors/addendum_i_test.go) reproduces I.1–I.10
through production code, and [docs/TESTVECTORS.md](docs/TESTVECTORS.md) only points there.
Companion draft for the spec writer: [docs/CONFORMANCE.md](docs/CONFORMANCE.md) (a requirement
index over the spec). References to D.x (storage layout, write path, snapshots, Postgres) are to
Addendum D of spec v0.49 and earlier, the Bun prototype's notes, which v0.50 moved out of the
spec into the prototype's `PROTOTYPE.md`; this implementation still follows them, as its own
choices under §5.

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
| Limits (configurable, deployment maximums) and token-bucket rate limits; a refusal names the limit (`limit`) and, for sizes and counts, `measured` and `max` | §6.6, §12 | ✅ (see [Limit refusals](#design-notes)) |
| `GET /ns/{ns}/principal`: what the grant in `Authorization` is in a namespace (principal, `kid`, the verifying key's thumbprint `key`, `operator`, verbs, roles, and a catalog namespace's `catalog` settings) and what a writer needs from the namespace document (frozen, successor, nonce, signatures, level, limits in force), to a grant limited to some resources or without `read` too | §7.4, §C.5, §C.7, §8.5 | ✅ (client `NSPrincipal`; see [Design notes](#design-notes)) |
| File trees: `catalog.files` in catalog namespace documents, file metadata (`file: { size, type, modified }`) on placements in tree listings, sealed per entry for items of sealed namespaces, and the rendering of a JSON file shared by tools (`internal/files`) | §7.4, §H.1–§H.3, §E.2.6 | ✅ (tree service; see [File trees](#file-trees-h2-h3)) |
| Reads, writes, gate order, `412`/`428`, idempotent retry, paged log ranges (`X-Log-Next`, bounded by entries and by `logPageBytes`) | §6.2, §7.1–§7.2 | ✅ (`serve -log-page-size`, `-log-page-bytes`; see [Design notes](#design-notes)) |
| SSE events, long-poll with cursors | §7.3, §7.7 | ✅ |
| Namespace documents (the spec's members validated strictly, others must start with `x-`), log, `/heads` (byte order of name), `/branches` | §7.4 | ✅ |
| Files and sync clients: `Last-Modified`, `Repr-Digest` and `If-Modified-Since` on `…/rev/{id}`, and `created`, `size` and `digest` on `/heads` entries, outside E2 and E3; raw documents at `…/raw`; moves recorded as `$successor`, named by the head's `410`; whole-document appends up to `documentSize` | §6.2, §6.6, §7.1, §7.4, §7.8, §8.1 | ✅ (see [Files and sync clients](#files-and-sync-clients-71-74-78-81)) |
| Atomic batches (multi-step items, config changes, dry run, retry) | §7.5 | ✅ |
| Gestures for undo and redo: `Gesture`/`Undoes` on writes and batch steps, in logs, `GET /ns/{ns}/gestures/{gesture}`, carried by merges and bundles | §7.2, §7.4, §7.5, §F.3, §G.4.1 | ✅ (server, tooling, client library, and the undo/redo procedure of §11.2 in the client and the playground; see [Undo and redo](#undo-and-redo-112)) |
| Local branches: read-through, foreign parents, keys follow the base (the base's current keys work in its branches) | §7.6, §C.4 | ✅ |
| `schemaReads`: schemas follow their documents into listed namespaces | §6.1 | ✅ |
| Edge grants as cookies in §C.5's default format (`kid`): `POST /edge-grants` for one grant or up to 50 (`{ "grants": [ … ] }`), fixed to finite sets of resources (`enum`, `compare` `in`), at most 100 distinct prefixes, drawing on each principal's `exchangeRate` bucket once a request, keys rotated (`-edge-grant-key KID=FILE`, repeatable), withdrawn with `DELETE /edge-grants`, verified by the origin with or without an edge, an edge's checks in Go (`edge.Cookies.Check`); the catalog service mints its own for its listings, bound to a subject set (`/{catalog}/g/{gs}`) | §C.5, §9, §B.11.5 | ✅ |
| Required nonces: `"nonce": "required"`, `422 nonce` at gate step 3 (sealed namespaces too), kept by branches and remote branches, required by a base only once its branches require them (`409 in_use`), added by undo, merges, imports, schema import and release tools, and by writers that can't read the setting in private namespaces (`GET /ns/{ns}/principal` tells one that asks) | §C.7, §7.4 | ✅ |
| Tombstone, restore, purge (with propagation), freeze, namespace purge (a sealed namespace's documents, log, long-polls and events then answer `410 purged` with `head`, which followers, services, the janitor and remote branches take as the purge) | §8.1–§8.5 | ✅ |
| Pruning with horizons, protected revisions, kept documents, archives and retention | §8.6 | ✅ (file:// archives) |
| Blobs: uploads, copies (`Blob-From`, `Source-Authorization`), pending entries and `blobGrace`, availability (bases, batch sources), attach at write, ranges, `nosniff` and `Content-Security-Policy: sandbox` on every blob response, purge and pruning (`410`, archived as blob lines, back on restore), bundle blob lines, mirrored by remote branches | §7.8, §G.3, §G.4.1 | ✅ (bytes in files under `-blob-dir`, encrypted per resource at rest; sealed and e2e specifics to come) |
| Cache-Control classes and cache tags | §9 | ✅ (tag purges over HTTP with `-purge-url`, default: log; a local Varnish CDN in the compose stack; private content cached at the edge only for reads a verifying edge vouches for, with `-edge-secret`) |
| Grants (Biscuit v3, §C.8), narrowing, sealing, roles, attributes, key scopes, revocation | Addendum C | ✅ |
| Remote branches: registration (`export`), mirroring with verification, schema mirroring, purge notices, bases that are branches, sealed and e2e bases | §G.3, §G.5.2 | ✅ (mirrored up front) |
| Bundles: history and snapshot export and import, sealed bundles, access levels, e2e ciphertext | §G.4, §G.5.1 | ✅ (`patchlog export/import`) |
| Storage layout | §5 (D.2) | ✅ SQLite (pure Go, `modernc.org/sqlite`) |
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
- A CDN edge that verifies edge grants (§C.5): none is included, though `edge.Cookies.Check`
  makes its checks in Go. The origin issues edge grants as cookies and verifies them itself,
  and checks grants on every read. Both §9 deployments are supported: behind a grant-verifying
  edge (`-edge-secret`) private reads it verified get edge lifetimes, and everything else
  private is `no-store` for shared caches (see
  [Private namespaces and the edge](#private-namespaces-and-the-edge), which also gives the
  cookie format and what such an edge must check).
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
record `"grant": null` (§1, Conformance). A write without `X-Author` is then `400 bad_input`
(§7.2; reads are unaffected), so the tools that write (`janitor`, `merge`, `rebase`, `import`,
`schema`, `dav`) need `-author` against a `-dev` server; compose starts the janitor with
`-author=janitor`, and the playground sends `X-Author: anonymous` until its author box is
filled. `GET /` says which mode a deployment runs in
(`"auth": "disabled"` or `"grants"`), and the merge tools and the janitor read it from there.
Without it, give `-operator-key` and use grants (Addendum C). `patchlog version` prints the build's version.
While the package is private, pulling needs `docker login ghcr.io` with a token that can read
packages.

## Running the whole stack

```sh
make up        # or: docker compose up --build -d
```

It needs Docker Compose 2.23.1 or newer (`docker compose version`): `compose.yaml` gives the
WebDAV gateway's password as a config with `content`, which older versions refuse, and with it
the whole file.

On hosts where Docker can't create network namespaces (a Fly.io sprite, some VMs and CI runners;
`bind-mount /proc/…/ns/net …: permission denied`), use `make up-host`, which layers
`compose.host.yaml` over it: host networking, the same ports, and no `docker exec` healthchecks.
On a sprite the stack's URL (`https://{sprite}-{org}.sprites.app`) routes to the CDN on 8080; pass
`PATCHLOG_ORIGIN` with that URL so generated links point there.

This starts the core server in dev mode, seeds a few demo namespaces and documents, and runs the
search index, the tree service and the branch janitor, all behind a local CDN (Varnish, see
[The local CDN](#the-local-cdn-9)), and the WebDAV gateway beside it:

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
| http://localhost:8090 | WebDAV gateway (`patchlog dav`): `demo` as a flat directory, `drive` as a file tree; any user name, password `patchlog-dev` (see [WebDAV in the stack](#webdav-in-the-stack)) |

The seed creates `schemas`, `demo` (a few matches, with catalog roles), two catalogs of `demo`,
`files` and `drive` (a file tree of `files`), `private` (sealed, E2) and `vault` (end-to-end, E3:
create its keyring from the playground's Keys tab). The catalogs:

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
- `drive`, a file tree (`catalog.files`, see [File trees](#file-trees-h2-h3)) whose items live in
  `files`: folders `Reports` and `Photos` under its root, and in them `Q3 summary.md` and
  `README.txt` as raw documents (a blob and a document whose root is its reference, §7.8),
  `logo.png`, a raw PNG, and `budget.json`, a JSON document. Its rules are `cat`'s, for `files`'
  items, and §H.2's titles. [deploy/seed.sh](deploy/seed.sh) draws it.

One tree service serves the three (`-catalog=cat -catalog=topics -catalog=drive`), each at
`/{catalog}/…` with its own database.

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
  CDN's), `CORE_DIRECT_PORT`, `INDEX_DIRECT_PORT`, `TREE_DIRECT_PORT` (the origins'), `DAV_PORT`
  (the WebDAV gateway's) and `PATCHLOG_ORIGIN`.
- Without Docker, `make dev` runs just the core server, and `make check` runs vet, the tests and
  a gofmt check.

### WebDAV in the stack

`dav` in compose.yaml is the WebDAV gateway (see [WebDAV](#webdav-prototype)) in local mode
against the dev core, so its writes carry `X-Author: dav`. Open http://localhost:8090/ with any
user name and the password `patchlog-dev`. It serves `demo` as a flat directory of its
documents, and `drive` as a file tree whose folders are listed by the tree service:

```
/demo/derby.json …                    demo's matches, as JSON files
/drive/README.txt                     the file tree drive (§H.2): a raw document, text/plain
/drive/Reports/Q3 summary.md          a raw document, text/markdown
/drive/Reports/budget.json            a JSON document
/drive/Photos/logo.png                a raw document, image/png
```

drive's items live in the namespace `files`, which the gateway doesn't serve as a flat directory:
there a rename is a copy and a delete (§H.2 "Flat view"), so renaming or deleting a file in it
would take the file out of `/drive/`, leaving its placement dangling. `/demo/` is such a flat
directory of `demo`, whose documents `cat` and `topics` place: renaming or deleting one there
leaves their placements of it dangling the same way (a rename's new name, in `$successor`, §8.1,
is not followed by them). Rename and move files in `/drive/`, which changes only their
placements.

The password is a compose config, `${DAV_PASSWORD:-patchlog-dev}`, which reaches the gateway as a
file only the container's user can read. It is read when the `dav` container is created (the
first `up`, or after `down`): on a running stack, `DAV_PASSWORD=… docker compose up -d
--force-recreate dav` changes it (a plain `up -d` keeps the old one). It is a development
password, published here, and the gateway speaks plain HTTP: keep port 8090 to your own
machine, as with the rest of the stack. The gateway keeps nothing but memory caches, so it
doesn't mount the `data` volume, which holds the core's databases and master key.

- **macOS Finder**: Go → Connect to Server (⌘K), `http://localhost:8090/`, then Connect as a
  Registered User with any name and `patchlog-dev`.
- **Windows**: File Explorer → This PC → Map network drive, folder `http://localhost:8090/`, or
  `net use Z: http://localhost:8090/ /user:me patchlog-dev`. Windows' WebClient sends Basic
  credentials over HTTPS only, by default. For this plain-HTTP gateway, set `BasicAuthLevel` to
  `2` under `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters` and restart the
  WebClient service, or serve the gateway over HTTPS (`-tls-cert`, `-tls-key`).
- **rclone**, a remote of vendor `other`:

  ```sh
  rclone config create pl-dev webdav url=http://localhost:8090/ vendor=other user=me \
    pass=patchlog-dev --obscure
  rclone ls pl-dev:drive
  rclone mount pl-dev: ~/pl --vfs-cache-mode writes --ignore-size \
    --dir-cache-time 1s --vfs-cache-max-age 5s --vfs-cache-poll-interval 5s

  # Or without a config, the :webdav: backend:
  rclone ls --webdav-url http://localhost:8090/ --webdav-vendor other --webdav-user me \
    --webdav-pass "$(rclone obscure patchlog-dev)" :webdav:drive
  ```

  Copies and syncs to it take `--ignore-size --ignore-times`; see **rclone** under
  [WebDAV](#webdav-prototype) for why, and for the mount's flags.
- **davfs2** (Linux): `sudo mount -t davfs http://localhost:8090/ /mnt/pl`, then any user name and
  `patchlog-dev` when asked (or put `http://localhost:8090/ me patchlog-dev` in
  `/etc/davfs2/secrets`).

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
(resource purge `r:{ns}/{name}` and `heads:{ns}`, namespace purge `ns:{ns}`, `ns:{ns}` too for
a config write that makes a public namespace private or raises one to sealed (§9), the services'
`idx:{ns}` and listing tags) becomes

```
PURGE / HTTP/1.1
X-Purge-Tags: r:demo/derby ns:demo
```

sent asynchronously by [internal/cdnpurge](internal/cdnpurge): tags are queued (bounded),
coalesced, batched (64 tags or 2 KiB per request), retried with backoff and flushed on shutdown
for up to 5 s. The write path never waits for the CDN; a purge the CDN never takes is logged.
Each purge is sent a second time, since a response that read before it may reach the CDN after
it, and would then keep what it removed for a year: the core queues it with the write that
commits it (see [Second CDN purge](#postgres-d8)), and so do the index and the tree and catalog
services, in their own databases (`cdn_repurge`), in the transaction that applies what needs it
(a resource purge or purge-ns, drift a start or a failed apply's reload fixes, a namespace the
catalog stops trusting). They send it again two minutes later (`RepurgeDelay` of
`index.Options` and `tree.Options`), once a response under way at the commit has reached the
CDN: the services set no response deadline of their own, and a CDN takes a response only within
its first-byte timeout (75 s in the compose stack's Varnish). A loop sends the due ones every
10 s (`RepurgeInterval`) until the service closes; a queued purge survives a restart, a crash
and `-rebuild`.
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

§9 caches private (non-public, non-sealed) content at the edge only for reads that an edge
verifying edge grants (§C.5) has verified itself, and the origin must know which deployment it
is in. Private reads are served either way: the origin checks the grant, or the edge-grant
cookie, on every request.

- **Without a verifying edge** (the default, and the compose stack: Varnish verifies nothing),
  private responses carry `Cache-Control: private, …` plus `CDN-Cache-Control: no-store` and
  `Surrogate-Control: no-store`, so no shared cache stores them. Public and sealed responses
  are unchanged.
- **With a verifying edge**, give `patchlog serve` the secret it shares with the edge:
  `-edge-secret FILE` (the file's content, surrounding whitespace ignored). Once the edge has
  checked a request's edge grant (below), it forwards it with the secret in `-edge-header`
  (default `X-Edge-Verified`) and the grant's prefix `p` in `-edge-prefix-header` (default
  `X-Edge-Prefix`), and it strips both headers from client requests. A private response gets
  the §9 edge lifetime in `CDN-Cache-Control`, and no `Surrogate-Control`, only when all of
  these hold (v0.50):
  - each header is exactly one line without a comma (v0.51): two lines, or a list in one, count
    as none, so the secret can't contain a comma (`-edge-secret` refuses one);
  - the secret matches, compared in constant time;
  - the prefix covers the URL by whole segments: the path is the prefix or starts with it
    followed by `/`;
  - the request carries no other credential: no `Authorization` and no
    `Source-Authorization` (the reference defines no signed-URL parameters).

  Every other private response is `no-store` for shared caches, as without an edge, and is
  served all the same: a read with a grant in `Authorization`, which the origin verifies itself
  and which belongs to one credential; a schema revision read under `schemaReads` by a reader of
  a referrer (§6.1), which depends on the referrer; a read the edge only relayed; and one sent
  around the edge. So a response fetched around the edge is never one the edge would cache, and
  a client works the same either way. The headers decide only the lifetimes: the origin
  authorises every read itself, from its cookie or grant (v0.51). (Up to v0.49 a private read
  without the secret was refused with `403 edge_required`, a long-poll before it waited.)
  Writes, event streams, error answers such as `401`/`403`, `POST /ns/{ns}/keys` and the
  gestures listing are `no-store` whatever the headers say. Public and sealed reads ignore them.

  `patchlog index` and `patchlog tree` take the same three flags for their private listings
  (§A.4, §B.11.5), under the same rules: a listing read with a grant in `Authorization` is
  `no-store` at the edge. The catalog service (`tree -access`) mints edge grants of its own for
  its listings (v0.51, [Tree and catalog](#tree-and-catalog-addendum-b)), so a listing read
  under one of its cookies, which the edge checked with the service's kid, gets edge lifetimes;
  the search index and the plain tree service mint none. Private head pointers stay `no-store`
  either way.

```sh
head -c 32 /dev/urandom | base64 > edge.secret       # shared with the edge's configuration
head -c 32 /dev/urandom | base64 > edge-grant.key    # the origin's cookie key, which the edge holds too
patchlog serve -edge-secret edge.secret -edge-grant-key edge-grant.key   # the edge sends X-Edge-Verified and X-Edge-Prefix
```

**Edge grants as cookies** (§C.5). `POST /edge-grants` with a grant in `Authorization`, or up
to 50 grants as `{ "grants": [ … ] }` in the body (v0.50; each the token as it would follow
`Bearer `, surrounding whitespace ignored), answers `{ "prefixes": [...], "exp" }`
(`no-store`) and sets one cookie per prefix: `/r/{ns}` and `/ns/{ns}` per namespace a grant
names, or `/r/{ns}/{name}`, one per name, when its read rules fix `/resource`. A body with
`Authorization`, an empty list or more than 50, anything but strings, or any other member is
`400 bad_input`; a body too large is `413 limit`. The body must be `application/json`
(`415 unsupported_type` otherwise; media types compare case-insensitively, and the only
parameter allowed is `charset=utf-8`), so that a page on another site needs a CORS preflight to
send one:
a `text/plain` form needs none, and could otherwise set cookies of its own grant in a reader's
browser. While authentication is disabled (`-dev`), issuance is `404 not_offered`, whatever
the request.

Rules **fix** `/resource` (v0.50) when a rule of the blocks or the key's scope, at top level or
inside `all`, tests it against one name (`test` with `value`, or `compare` with `eq` and a
literal) or a finite set (`test` with a `schema` of only `enum`, or `compare` with `in` and a
literal array). Several such rules fix it to the names all of them allow, so
`{"op":"test","path":"/resource","schema":{"enum":["a","b"]}}` gives `/r/{ns}/a` and `/r/{ns}/b`
in each namespace the grant names. An empty set, or any literal of a fixing rule that isn't a
name valid under §3.6, even one the intersection drops, is `403`. `"*"` in `ns` is `401`, an
operator grant's too (§C.4, §C.5.2); a grant without `read` is `403`, and so is one whose
blocks or key scope refer to `/resource` any other way, or to `/now`, since the edge evaluates
no rules. A grant with roles needs one role that lists `read` and qualifies: its rules don't
refer to `/now`, refer to `/resource` only where the grant fixes it, and pass now for the
principal, for every name fixed (§2.1 Qualifying role). Roles are alternatives, so one is enough, with the blocks and key scope on top; a
role that tests `/resource` never qualifies, even next to blocks that fix it. The answer is all
or nothing across every grant: if any namespace a grant names doesn't exist, is purged or
refuses it, no cookie is set, and the request is `401` if any namespace's answer is, else `403`.
A purged namespace is decided last, once the grant verifies and may read there, so the answer is
`410 purged` only if every refusal is a purge, with `ns` and `head` naming the first one refused
in the order of the grants and their root blocks (v0.50). Only then, once nothing is refused, is
an exchange that would issue more than 100 distinct prefixes `400 bad_input` (v0.51; up to
v0.50, more than 100 names were `403`): prefixes several grants give count once, and a
namespace-wide grant counts two per namespace, `/r/{ns}` and `/ns/{ns}`. That `400` is a
refusal too and draws no token: a `429` is decided only once every grant has verified, so a
token would save no work, and prefixes are counted only up to the cap, so an exchange over it
costs no more than verifying its grants. And only then does the
request draw one token, however many grants it carries, from the `exchangeRate` bucket (§6.6) of
each distinct principal among them, keyed as write buckets are (the root `sub` and the key that
signed the root block), and from no write bucket or allowance, so a reader's exchanges and
writes never spend each other's budget (v0.52; v0.50 drew one token per grant from the
principal's write bucket). It is admitted while each of those buckets holds a token, and `429`
otherwise, with `limit: "exchangeRate"`, `Retry-After` and `retryAfter`, drawing nothing.
`exchangeRate` is set by the deployment only: `serve -exchange-rate RATE,BURST` (default
`10,100`, so 10 a second with a burst of 100).

Cookies are `Secure`, `HttpOnly`, named `__Secure-pl-eg-…` per prefix, with `Path` the prefix,
which covers what lies below it by whole segments (`/ns/{ns}` covers the namespace URL itself
and `/ns/{ns}/…`, not `/ns/{ns}-x`), and last until the grant's `exp` or 15 minutes, whichever
is sooner. Prefixes come in the order the grants first give them; a prefix several grants give
gets one cookie, lasting as long as the longest, and the body's `exp` is the earliest of the
cookies'. A read under one checks its expiry, so an event stream opened under a cookie ends
there. One authorises `GET` and `HEAD` under its prefix only, on requests without
`Authorization`; never writes or `/edge-grants`, and the origin's cookies never cover a
service's URLs. The origin verifies them itself, making the checks an edge makes (below), so
they work without a verifying edge, `no-store` at the edge. A cookie names no principal, so the
origin attributes a read under one to `edge:` and its prefix. They are signed with the last
`-edge-grant-key [KID=]FILE` given, and cookies signed with any of them are accepted, so the key
rotates (below; v0.51 made the flag repeatable); a plain `FILE` is named by `-edge-grant-kid`
(default `origin`). An argument is `KID=FILE` only when no `/` comes before its first `=`, so a
path holding `=` is a plain `FILE` (give `edge=v2.key` in the working directory as
`./edge=v2.key`), and `FILE` `edge-secret` is the key derived from `-edge-secret` (a file of that
name is `./edge-secret`; see the warning below). Without one, they are signed with a random key per
process, named by `-edge-grant-kid`, so cookies don't survive a restart, reach another instance or
verify at an edge, which only the origin can then check: an edge that verifies cookies needs
`-edge-grant-key` key files, which it holds too. With `-edge-secret` and no `-edge-grant-key`,
`serve` logs a warning saying so. (Earlier releases signed with the key derived from the edge
secret by default. The catalog service and the search index hold that secret too, for their own
edge lifetimes, so either could derive the key and mint core cookies for any namespace.)
Pages on another origin call it with `credentials: "include"`: list them with
`-cors-credentials-origin` (repeatable), which names the origin from that list with
`Access-Control-Allow-Credentials: true` and `Vary: Origin`, even when `-cors-origin` is `*`,
and makes the cookies `SameSite=None` (otherwise `Lax`). `DELETE /edge-grants?prefix=…` (v0.48;
`prefix` repeatable, as `prefixes` returned them) withdraws them at sign-out: `204`, `no-store`,
an expired cookie of the same name and attributes per prefix (a repeated one once), no grant
needed, and the same with authentication disabled, so sign-out works either way. No `prefix`, or
one of another form, is `400 bad_input`; `prefix` is the core's one repeatable parameter (§7).
Only credentialed origins may preflight it, so another site can't sign a reader out. It clears
the browser's copies only; a copied cookie lasts until it expires.

A cookie carries no grant id, so revocation reaches it only when it expires, at most 15 minutes
after issue, at the edge and the origin alike: a revoked grant, a key removed from the
namespace's `keys` or a changed role doesn't end it sooner; only dropping the edge-grant key
that signed it does. A branch serves the revisions it reads through under its own URLs (§7.6),
so its cookies never need the base's. Cookies fixed to single resources add up, and browsers
keep about 150–180 per host, evicting the oldest: a reader of many documents is better served by
a namespace-wide grant, if it may read the whole namespace, or by a proxy (§C.6).

**Verifying edge grants at an edge.** §C.5 leaves the cookie's format to the deployment, but
gives a default so an edge can be written once. The reference issues exactly that
(`internal/edge/grants.go`):

- **Name:** `__Secure-pl-eg-` followed by the first 8 bytes of `sha256(p)` in lowercase hex
  (16 characters), where `p` is the cookie's path prefix.
- **Value:** `base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))`, without padding,
  where `c` is the canonical JSON (§3.1) of `{"exp":…,"kid":…,"p":…}`: exactly those three
  members, the expiry in seconds since the epoch, the key's name and the prefix. A value whose
  `c` has other members, or isn't canonical byte for byte, is ignored (v0.51). The MAC is over
  the first part's text as sent, so a verifier never re-encodes the claims.
- **Kid and key:** `kid` names the key, which the minter and the edges hold. Each key vouches
  only for its own prefixes: the origin's for `/r/{ns}/{name}`, `/r/{ns}` and `/ns/{ns}` with
  names valid under §3.6, a service's for prefixes under a root of its own. The origin's kids
  are the `KID`s of its `-edge-grant-key KID=FILE` flags, and `-edge-grant-kid` (default
  `origin`) for a plain `FILE`. Each key is its file's bytes with surrounding whitespace
  trimmed, used as they are, not decoded (at least 16; `head -c 32 /dev/urandom | base64 >
  edge-grant.key` makes one), and the edge then needs those files. Without `-edge-grant-key` the
  key is a random one of the origin process, which no edge holds and no other origin instance
  either: with several instances, a cookie one mints is refused by the others, so give every
  instance the same key files. The key derived from the edge
  secret, HMAC-SHA256 keyed with the edge secret (the `-edge-secret` file's content, trimmed the
  same way) over the ASCII text `patchlog edge grants v1`, is held only when named as `FILE`
  `edge-secret`, for migration (below).
  The catalog service's kids and keys are its own `-edge-grant-key [KID=]FILE` flags (a plain
  `FILE` named by its `-edge-grant-kid`, default `catalog-{catalog}`), which vouch only for
  `/{catalog}/g/{gs}`, `gs` an id or `all`, never the key derived from the edge secret (see
  [Tree and catalog](#tree-and-catalog-addendum-b)). An edge in front of both holds both keys,
  and makes the same checks with whichever kid a cookie names, so neither's cookies cover the
  other's URLs.

**Rotating the edge-grant key** (§C.5.3, v0.51). The origin and its edges hold several
keys at once, each named by its `kid`, and the origin mints with the newest, so a key is
rotated without making clients exchange again:

1. Make the next key and add it to every edge, next to the current one. Edges look a cookie's
   key up by its `kid`, so they now accept both, and cookies are still minted with the current.
2. Add it to the origin as the newest, after the current one; new cookies carry its `kid`, and
   those minted before still read:

   ```sh
   head -c 32 /dev/urandom | base64 > k2.key
   patchlog serve -edge-grant-key k1=k1.key -edge-grant-key k2=k2.key …
   ```

3. Once the last cookie under the old key has expired, 15 minutes after every origin instance
   took the next one, drop the old key from the origin (`-edge-grant-key k2=k2.key`), then from
   the edges.

A deployment on the key derived from `-edge-secret` (the default of earlier releases) moves to key files
the same way, naming the derived key `edge-secret` (with `-edge-secret` still given) so the origin
holds it next to the first file until its cookies expire. **That key is for migration only:** every
holder of the edge secret can derive it, the catalog service and the search index included, which
take `-edge-secret` for their own edge lifetimes, and so can mint cookies the origin accepts for
any namespace. `serve` logs a warning while it holds it; drop it once its cookies have expired:

```sh
patchlog serve -edge-secret edge.secret -edge-grant-key origin=edge-secret -edge-grant-key k1=k1.key …
patchlog serve -edge-secret edge.secret -edge-grant-key k1=k1.key …   # 15 minutes later
```

**Every edge must drop the derived key too.** An edge built on the earlier default derives the
`origin` key from the edge secret, and serves cached private `/r/` and `/ns/` responses to any
cookie that passes its checks without asking the origin, so while it holds that key, the catalog
service, the search index or anything else holding the edge secret can mint cookies it accepts
and read what it caches. Without the opt-in above the origin no longer mints under the derived
key, so edges drop it as soon as every origin instance runs this release (cookies minted under it
before are refused at the origin from then on); with the opt-in, edges drop it 15 minutes after
the origin does.

The edge secret itself still has one value, so replacing it makes clients exchange again. In Go,
`edge.Cookies` holds the keys: `edge.NewCookies` and then `AddKey` for each newer one; `Kid`
names the one it mints with and `Check` and `Verify` accept any. Every key one `edge.Cookies`
holds vouches for the same prefixes, the core ones unless `Vouches` is set, so one minter's keys
go in one `edge.Cookies`, and `AddKey` rotates that minter's keys: a service keeps its own, with
`Vouches` set to its prefixes. The catalog service rotates its key the same way (`tree
-edge-grant-key KID=FILE`, repeatable; see [Tree and catalog](#tree-and-catalog-addendum-b)).

On every request, cache hits included, before serving it or forwarding it as verified, an edge
MUST check (§C.5):

1. the method is `GET` or `HEAD`;
2. the path has no empty, `.` or `..` segment and no percent-escape (`400` otherwise), since
   the cache is keyed on the raw URL; core names never need one (§3.6);
3. a cookie whose name is derived from its own `p`, as above; others are ignored;
4. a `kid` it holds, that vouches for `p`, and a valid MAC;
5. `exp` is in the future;
6. `p` covers the path segment by segment: the path is `p` or starts with `p/`, so `/r/demo`
   covers neither `/r/demo-x/…` nor `/r/demox`.

A browser sends every cookie whose path covers the URL, so a request may carry several: one that
passes all six checks is enough. A request that passes is answered from the copy cached for
verified requests, or on a miss forwarded with `X-Edge-Verified` carrying the secret and
`X-Edge-Prefix` the `p` it checked, each as exactly one header line without a comma; the cookie
is never part of the cache key. A request that fails any check is forwarded without those
headers, and the origin answers it as it would without an edge, `no-store` at the edge if it is
private. An edge may answer a failure of check 2 itself; the origin answers `400 bad_input`
either way, for every method and credential, `/` itself excepted (§7 since v0.51; v0.50 extended
it from dot segments, `//` and `%` to a trailing `/`). The origin decides a request carrying
`Authorization` from that grant alone, ignoring its cookies, and never gives it an edge
lifetime. In Go, `edge.Cookies.Check` makes the six checks in this order and returns the `p` to
forward; it answers a request failing check 2 as one without a covering cookie, so an edge tests
`edge.CanonicalPath` first to answer `400`. The origin checks cookies with `Check`, and its URLs
with `CanonicalPath`.

For example (pinned by `TestCookieVector` in `internal/edge`), the edge secret
`example edge secret` gives the key
`3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708` (hex), and the edge grant
of kid `origin` on `/r/demo/derby` until 1790000900 (2026-09-21T14:28:20Z) is this cookie:

```
__Secure-pl-eg-4390e78526d94754=eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw
```

whose claims are `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}`.

**Bypassing the CDN.** The origins answer directly on 9080 (core), 9081 (search) and 9082 (tree).
`make cdn-restart` restarts Varnish, which reloads the VCL and empties the cache.

**Limitations.**

- **No edge grants (§C.5).** A real deployment's edge verifies an edge grant on every request to
  a non-public namespace and serves the cached copy to anyone who holds one. This CDN verifies
  nothing, so compose runs the origins without `-edge-secret`, and the VCL strips
  `X-Edge-Verified` and `X-Edge-Prefix` from requests: private responses come with
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

`-origin` is the deployment's canonical origin (§C.3), which `GET /` publishes and signatures,
batch sources and bundles carry: `scheme://host[:port]` in lowercase ASCII, an IDN host as its
A-label, without a default port, path or trailing slash. `serve` refuses any other form at
startup.

### Postgres (D.8)

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
  deadline), then deletes the row. SQLite deployments do the same, and so do the index and tree
  services for their own purges (see [Purging](#the-local-cdn-9)).
- **Upgrading adds indexes.** A start that finds `ns_log` without `ns_log_ns_seq (ns, seq)` or
  `ns_log_ns_config (ns, config_seq, seq)` builds them inside the schema migration, which blocks
  writes until it commits: a few seconds per 5 million namespace entries (about 4 s for the
  first on a local `postgres:16`). To build them without blocking, create them beforehand with
  `CREATE INDEX CONCURRENTLY` under the same names; the migration then finds them.
- **Upgrading adds columns** `revisions.size` and `revisions.digest` (`/heads` sizes and
  digests, §7.4, see [Files and sync clients](#files-and-sync-clients-71-74-78-81)), on SQLite and Postgres.
  They are nullable without a default, so adding them changes only the catalog, instantly
  whatever the table's size, though on Postgres the `ALTER TABLE` waits for transactions
  using `revisions` and holds back others while it does. Nothing is backfilled. From then on
  they take about 40 bytes (SQLite; 41 to 48 on Postgres) on each revision a write leaves as
  a head outside sealed and e2e namespaces: for small documents written one revision at a time
  that is nearly every revision, and grew the `revisions` table by about 40% (the whole
  database by 9%) in a test of 20,000 such writes. Instances of the previous release keep
  working against the migrated schema (they name their columns), so a rolling upgrade is
  safe, with two leftovers. Heads they write, like those from before, are listed without
  `size` and `digest` until written again. And a purge they run nulls only the patch sets: the
  purged resource's two columns stay (never listed, since a purged resource is listed as a
  purge, but in an encrypted-at-rest namespace a plaintext hash that destroying the data key
  doesn't remove), and cached `/heads` pages aren't purged (`heads:{ns}`). Once no older
  instance runs, clear the columns with `UPDATE revisions SET size = NULL, digest = NULL WHERE
  digest IS NOT NULL AND res IN (SELECT res FROM resources WHERE state = 2)` (2: purged).
  Responses cached before the upgrade, or served by an older instance during it, lack the
  v0.54 fields and headers: `/heads` pages lack them and revisions `Last-Modified` and
  `Repr-Digest` until those copies expire or are purged, so clients treat them all as optional,
  as §7.4 says.
- **Keep transactions short.** The tailer can't move past the oldest running transaction in the
  database (its `xmin`), so one left open holds back every instance's wake-ups: set
  `idle_in_transaction_session_timeout` (e.g. `ALTER ROLE patchlog SET
  idle_in_transaction_session_timeout = '60s'`).
- **Rate-limit buckets are shared** (§6.6 Cost, v0.73): instances on one database draw on the
  same buckets, rows of `rate_buckets`, created at startup with the function `rate_draw`. A
  request's draw is one atomic statement that locks its buckets in key order and commits on its
  own before the write it admits can, so the instances together admit no more than a bucket's
  burst; an admitted write's deduction is never lost, and a request refused after admission
  keeps it. Each instance deletes full buckets once a minute. It costs a round trip per write
  (about +1.2 ms for one writer, and about 25% of the peak throughput of 32 writers on one
  namespace, a hot bucket's row lock, measured with `cmd/capacity`). A deployment of one instance
  may keep its buckets in memory, as SQLite does, with `serve -local-rate-buckets`
  (`Options.LocalRateBuckets`); before v0.73 every instance enforced the limits on what it
  served.
- **Per instance:** the in-memory caches above.
- **Edge-grant keys.** Without `-edge-grant-key`, each instance signs edge-grant cookies with a
  random key of its own, so a cookie one instance mints is refused by the others: behind a load
  balancer, give every instance the same `-edge-grant-key` files (see
  [Private namespaces and the edge](#private-namespaces-and-the-edge)).
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

`serve`, `index`, `tree` and `dav` answer two paths ahead of their own routes. Both are
`Cache-Control: no-store` and `CDN-Cache-Control: no-store`, and the compose CDN passes them, so
a probe always reaches the origin itself:

| Path | Answer |
| --- | --- |
| `GET /_health` | Liveness and drain state: `200 {"status":"ok"}` while serving, `503 {"status":"draining"}` from the moment shutdown starts. It touches no database, so frequent probes are cheap. Use it for load-balancer and CDN probes and container healthchecks. |
| `GET /_ready` | Readiness: `503 {"status":"draining"}` while draining, `503 {"status":"unavailable","error":…}` when the core can't reach its database (a ping with a 2 s timeout), else `200 {"status":"ok"}`. The index and tree keep local SQLite databases they opened at start, and `dav` keeps none, so for them it is the drain state alone. |

The paths start with `_`, which no namespace or catalog name can (§3.6), so they never shadow
the index's `/{ns}`, the tree's `/{catalog}` or a `dav` directory; they sit beside the services' `/_status`.
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
   their transactions roll back (nothing of a write cancelled before its commit is stored, and
   the chains stay intact; one cancelled while it commits may still be stored, and a client
   retrying it unchanged finds it, §7.2), and their handlers get 2 s more to return.
5. **Close.** Only then does the core stop its background jobs (retention, remote follows,
   epoch rotation), resign leadership and close the database, and the CDN purger flush its queue
   (up to 5 s); the index and tree stop following and resending purges (those not yet due are
   sent after the next start) and close their databases. The database is never closed under a
   running handler.

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
  `GET /{ns}`, `GET /{ns}/g/{gs}/at/{at}`, the tree's `GET /{catalog}/at/{at}/children`, the
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
It is plain HTML/JS embedded in the binary and talks to the same-origin API; against a `-dev`
server its writes carry the author box's name as `X-Author`, or `anonymous` until it is filled,
since a write without one is `400` (§7.2). It has:

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
or the raw `facet[/league]=cup`), `sort` and `counts` (paths comma-separated, each sent as one
parameter) and `limit`, and shows each hit's resource,
`$schema`, score, facets and revision, with the checkpoint (`at`) the index redirected the query to
(the browser follows that redirect through the proxy). A resource name opens in the Resource tab;
a facet chip or count adds a filter; "More results" sets `next` as `after` on the result's `at`
URL (§A.4). A `404` for a namespace the index follows but lacks the keys of says so, with the
reason `/_status` gives. "Wait for my last write" sends
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
API handler with the request's own headers (`Authorization`, `X-Author`), so a
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
  the namespace log. The log is read all of it page by page or after
  `UndoSince(nsID)`, for entries with the gesture by the same author (`UndoAuthor`, by default
  the author of its first revision found). Each resource's log is
  read from its head just before the gesture in that log (or its head as of `UndoSince`), else from
  genesis, and from the pruning horizon when that is later.
- **Writers limited to some resources** (v0.50) can't read the namespace log (§C.5). Where no
  listing answers them either (sealed and e2e namespaces), they name the documents they know the
  action touched, `UndoResources("a", "b")`, whose logs are read whole (from the pruning horizon
  when there is one) and scanned for the gesture (`plan.Source == "resources"`); without it the
  undo is `client.ErrNeedResources` rather than a raw `403` (a `401`, an unusable grant, stays
  one). `UndoSince` is dropped for them, since `/heads` needs unrestricted read. `Redo` and
  `UndoStack` take it the same way (the stack is then ordered by `created` across those logs).
  Revisions of the gesture in documents not named are left out, and a gesture a merge carried in
  counts for the merger who wrote it there, since only the namespace log shows the merge (§F.3).
  Without markers, the undo is impossible (`pruned`) rather than done in part when the
  gesture's oldest entry in a named document lies at or before the oldest entry it can read
  after a pruning horizon (§11.2, v0.51): the gesture's first entry read is that one, so it may
  continue below, or the gesture is found in no named document, by anyone, and one has a
  horizon, so it may lie wholly below. That covers a gesture never in those documents too,
  such as a mistyped id, since nothing tells them apart. A named document with a horizon and no
  entry of a gesture found in another is left out, as one the gesture didn't touch, so the
  `UndoStack`-then-`Undo` flow over every document followed keeps working after retention
  prunes one; a gesture lying wholly below the horizon there is then undone in the others only.
  A log read from genesis has nothing before it, so a genesis read from there is undone (the
  reference's reading of §11.2). The level comes from `POST /ns/{ns}/keys` (`plan.Level`;
  `404 not_offered` is a namespace that isn't sealed), and at E3 the current epoch and pad
  sealing the inverse needs, so such a writer undoes there with `UndoE2E` (§E.2.3, v0.51).
  Where `/keys` refuses (`403`, `404`, or `422` for a grant without `enc` at E3) or names no
  level, as a deployment before v0.51, the level is learned from what is read: entries whose
  patch set is one `sealed` op are e2e, else a resource log delivered as JWEs is sealed; an
  e2e undo is then refused (`client.ErrUndoE2ELimited`). Other `/keys` errors are returned.
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
  fresh `$nonce` to every patch set (§C.7, v0.49, `client.NeedsNonce`), and learns the
  namespace's encryption level from the resource logs it reads (see above).
  The sets are joined and split again within the namespace's `opsPerSet` and `patchSetSize`.
- **The guard.** The log after the gesture's last entry in each resource: a write overlapping the
  gesture's paths, a delete, a restore or an undo of the gesture is a conflict, returned as
  `*client.ConflictError` (`Conflicts`: resource, entry, author, kind, paths) and listed in
  `plan.Conflicts`. The batch names the checked heads in `ifMatch`; a `412`, or a `410 gone`
  naming a tombstone as `head` (a resource deleted meanwhile, as cores answer it from v0.73,
  §7.2), re-plans, up to `UndoRetries(n)` times (3).
- **Impossible** (`*client.ImpossibleError`, `Reason`): a revision the inverse needs is below a
  pruning horizon (`pruned`), a blob is gone (`blob`, `422 blob`), the old values don't validate any
  more (`invalid`, `422 invalid` or `schema_unavailable`), or the resource was purged.
- **Redo** undoes the undo. **The stack** is the author's gestures minus those the same author undid
  and didn't redo; others' undos are listed in `UndoneBy`, not counted, and an `Undoes` naming a gesture
  that isn't in the log (or another author's) is ignored.
- **Encryption.** Plaintext and sealed (E2, with `client.WithKeys`) namespaces work as they are; e2e
  ones (E3) need `UndoE2E(x)`: logs are opened and folded through the E2E view, the guard compares
  decrypted entries, every resulting document is validated, and each step is sealed bound to the id of
  the step before. Without it an e2e namespace is refused, and so is a writer that can't read the
  namespace document.

The playground's **Undo / redo** card (Namespace tab) does the same in the browser for plaintext and
sealed namespaces: it rebuilds the stack of the author in the connection bar (or another one typed in)
from the namespace log, offers Undo/Redo for the last actions (and for any gesture id, or "Undo this
gesture" in History), and shows conflicts (red, with the later entries and paths; nothing written)
apart from "undo impossible" (pruned, blob, invalid). It refuses to write undos in e2e namespaces and
points to the Go client, which undoes there for grants limited to some resources too. For a grant
that can't read the namespace log, undo and redo scan the log of the open resource instead,
asking `/keys` whether the namespace is sealed (learning it from the log where `/keys` doesn't
say), and refuse as impossible a gesture whose first entry read follows a pruning horizon, or
that is found in none of them while one has a horizon.

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
  It always redirects (v0.50, §A.5), so a `200` never carries `min`: an `at` URL whose result
  already includes every `min` (the current one, or a kept one whose `at` the log places at or
  after them) to itself without `min`, anything else, once `min` is reached, to the current
  checkpoint. A bare `?min={ns_id}` is given at most once (identical values count once, `min`
  being a set). A `min` naming another namespace, which a result of `{ns}` never includes, goes
  straight to the current checkpoint once reached, in one hop, if the index follows it and the
  reader may see it (it is public, or the reader's grant reads it) (v0.51, §A.5; kept pending
  F-I1, the strict `400` sits behind `strictMins`); any other is `400`. A `400` for refused
  `min`s lists every one refused, as given and in order, malformed ones too, in its body's
  `min` (`{ code: "bad_input", message, min: [...] }`, `no-store`), with one message whether
  the namespace is hidden or unfollowed (§A.5, §12.1). A `min` naming a followed namespace
  whose keys the index can't fetch for now is `503 behind` at once, to a reader who may see
  it, on single-namespace queries and on `/_refs` alike. For a purged sealed namespace, whose
  namespace documents are `410` (§8.5), the core makes that read check, as for the
  namespace's own queries; it is never a `502`.
- Redirects give the query in one canonical form (v0.50, §A.5): parameters sorted by name, then
  value, as UTF-8 bytes, and every byte but letters, digits and `-._~` percent-encoded in
  uppercase hex (a space is `%20`, never `+`). An `at` URL is answered `200` only in that form,
  and redirected to it otherwise. Repeatable parameters (`min`,
  `facet[…]`, range filters) are sets (v0.51): sorted, a value given twice kept once.
  A parameter that may not repeat, given twice, is `400`, and a multi-key sort is one parameter
  with comma-separated keys, `sort=-/kickoff,/title`, as `counts=/league,/round` and `fields`
  are (F-I2 default: a JSON Pointer token with a comma can't be named there).
- `?ref=` answers "who uses this?" (§A.4): the documents of `{ns}` that reference a resource through
  a schema's `x-ref`, found by walking each typed document with the schema revision it pins, with
  no `x-index` needed. `?ref=/r/logic/route-3` matches any form, `/r/logic/route-3/rev/{id}` only
  references pinned to that revision, and `/r/logic/route-3%23t-42` only those naming that entry. It
  combines with the other filters, and each hit lists `refs: [{path, ref}]`. Untyped documents, and
  paths that merely appear in prose or embedded copies, are not references. Delete guards built on
  it are advisory (use `?min=` and expect races). A database from before this version is rebuilt
  from the logs on start. In a branch's preview index targets match as written.
  A document that references itself is a hit of its own query with `"self": true`, so a delete
  guard can leave it out.
- Every query pages as `/_refs` does (§A.4): `next` is the `after` of the following page, to set
  on the `at` URL, and is absent on the last page. Without `q` or `sort`, `after` is a resource
  name, any string serving as the bound; with either, an opaque position `next` gives (a hit
  offset: after a redirect to a newer checkpoint it may skip or repeat, §13).
- `counts=/a,/b` (one parameter; a repeated `counts` is `400`) answers
  `counts: { "<path>": { "<value>": <hits> } }` over every hit, values counted by their string
  form, so `"1"` and `1` count together (§A.2, §A.4). Hits go by the sort keys, then resource
  name; with `q` and no `sort`, by score. A document sorts by its least value at a path, in
  either direction (F-I6 default): numbers, then strings by UTF-8 bytes (no date-time
  normalisation), then booleans, missing last; hits show every value at a sort path. The
  `gt`/`ge`/`lt`/`le` range extensions, which the spec doesn't define, need a `sort` mark and
  compare the least value, strings as bytes. `schema=` matches an exact `$schema`, or
  `/r/{ns}/{name}` for its revisions; no other prefix matches.
- A sealed or end-to-end namespace whose keys the index lacks is `404`, like one it doesn't
  follow, and a `min` naming it is `400`; one whose keys it can't fetch yet is `503 behind`
  (`no-store`, `Retry-After`) once the grant verifies (§A.4, §E.2.6; F-I3 default for what
  lacking keys covers). A document whose pinned schema revision answers `403`, `404` or `410`,
  or can't be opened for want of keys, is indexed as one without `$schema`. Results are sealed
  whole only for a private sealed namespace read whole; a public sealed or e2e namespace's are
  JSON with each hit sealed per entry under `K_r`, and `counts` there is `400` (§E.2.6, v0.73);
  opening the index drops results earlier releases stored sealed whole at a public URL.
- A hit's `score` depends on its document alone (§A.4, v0.73): each word counts
  `tf·2.2/(tf+1.2)`, BM25's term weight with a fixed idf, so scores no longer change with other
  namespaces or hidden documents, and differ from before. A word of one token takes its term
  frequency from the FTS5 index (`fts5vocab`), a phrase is counted with `highlight()` in the
  queried namespace's rows only.
- Any resource purge purges `idx:{ns}` (CDN, second purge, kept and stored sealed results,
  `/_refs` answers), so every cached result of the namespace goes; `idx:{ns}:counts` is gone. A
  followed namespace that turns private, or is raised to sealed or e2e, purges `idx:{ns}` and
  drops its kept and stored sealed results, and each private or sealed namespace gets one such
  purge when the index first applies its document after the upgrade (§A.1, §9).
- `GET /_refs?to=/r/logic/route-3` (v0.48) asks every namespace the index follows that the reader
  may read, branch previews included, `to` in any form `?ref=` takes. It redirects to
  `/_refs/g/{gs}/at/{at}?to=…` (the subject set first since v0.51; the old
  `/_refs/at/{at}/g/{gs}` is moved there with a `301`), where `at` is a combined checkpoint over
  only the namespaces the answer covers, which the body's `namespaces` lists, so writes
  elsewhere don't move it.
  - `gs` keys what the answer depends on, over markers alone (v0.49): `reads:{ns}` for each
    private namespace the grant reads unrestricted (one read role without `/resource` rules is
    enough), and `reads:{ns}:scope:{digest}` for one it reads in part, the digest covering the
    rules that limit it there and the `/principal` values they refer to; rules on `/now` there
    make the namespace unreadable. Readers with no marker, anonymous ones included, share the
    empty set's `gs`.
  - It leaves out namespaces the index hasn't reached yet, purged ones, and sealed or e2e ones
    whose keys it doesn't hold. `min` takes `{ns}:{ns_id}`, repeatable, and is `400` for a
    namespace the answer doesn't cover. It always redirects (v0.50): on an `at` URL whose
    kept answer already includes every `min`, to that URL without `min`; otherwise it waits
    (`503` if not in time) and redirects to the current `at`.
    Only a reader who may see none of the namespaces gets `401` or `403`. A namespace document
    the index can't read is `502` for a namespace the grant names; any other is left out, as
    one the reader can't see.
  - Hits are `?ref=` hits with their `ns`, filtered per resource, in byte order of namespace,
    then resource name. A page holds `limit` hits after `after`, given as `{ns}/{name}`, and
    `next` is the following page's `after`, to set on the `at` URL. Hits from sealed and e2e
    namespaces are sealed per entry. Answers, like every result, are served only at their
    canonical URL, so `after` set on an `at` URL takes one redirect unless the client builds
    the canonical form itself. Answers are kept as above. Delete guards built on it remain
    advisory.
- Schema documents (whose `$schema` is a dialect URL) are indexed too: `?schema=https://json-schema.org/draft/2020-12/schema`
  lists them, and the revision paths of `$ref` keywords at schema positions (fragment dropped; not
  those inside `const`, `enum`, `default` or `examples`) count as references, so
  `?ref=/r/schemas/address` lists the schemas that `$ref` it.
- Hits carry their facet and sort values under the field's path (always a list; sort values as
  written), and `?fields=/name,/title` adds those indexed fields, `text` ones included, so a list
  renders without fetching every document. A path is checked against the `x-index` marks of the
  schemas used by the namespace's documents the reader may see (§A.4 Private namespaces),
  by kind: `facet[…]` and `counts` paths must be marked `facet`, `sort` and range paths `sort`,
  `fields` paths with any kind, else `400` naming the parameter (an `x-index` reachable from a schema's root along the
  path, through `$ref`, `$dynamicRef`, the object and array keywords and every branch of
  `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, never through `not`, `propertyNames` or
  `unevaluated*`, array items at their array's path; §A.4), not against the data, so whether a
  query fails never depends on it: a marked path no document has values at is accepted and left
  out of hits, an unmarked one is `400`, and a schema that can't be read for now is `502`.
  Values are collected by the same static walk, whatever the document's validity: only strings,
  numbers and booleans, an array's scalars at the array's path, and for `text` strings only
  (F-I5 default). In sealed namespaces they are sealed with the rest of the hit. A database from
  before this version is rebuilt from the logs on start (the format is kept in SQLite's
  `user_version`).
- In private namespaces the reader's grant is checked locally. Results are routed to
  `/{ns}/g/{gs}/at/{ns_id}?…`, the subject set before the checkpoint (v0.51, §A.4), and
  filtered to the resources the grant can read. Since v0.73 `gs` is `SubjectSetID([marker])`, as
  `/_refs` computes it: `reads:{ns}` for a grant that would get a namespace-wide edge grant,
  else `reads:{ns}:scope:{digest}`, so readers of a whole namespace share one `gs` whatever
  their groups (**private result URLs change once**). A grant whose block, key-scope or read-role
  rules refer to `/now` finds the namespace unreadable (`403`; `/_refs` leaves it out). A grant
  at another `gs`'s `at` URL is `403 forbidden`, `no-store`, never redirected; `/_refs` there
  without a grant the service verifies is `401`. Only the head pointer and `at` URLs without
  `/g/{gs}` redirect into the reader's `gs`, and redirects a grant decides are `Cache-Control:
  private, no-store`. A grant over `grantSize` or `rulesPerGrant` is `413 limit`, naming the
  limit, wherever the grant isn't ignored, as the origin answers it (§C.8, §C.6). The URLs
  before v0.51, `/g/{subject-set}/{ns}[/at/{ns_id}]`, are moved permanently (`301`) to the new
  ones.

### Merge, rebase and cleanup (Addendum F)

```sh
patchlog merge status -branch release-7          # per resource: ahead, behind, clean, conflicting
patchlog merge plan   -branch release-7          # the batch, plus a dry run
patchlog merge apply  -branch release-7 -freeze  # one batch into the base, then freeze with "merged"
patchlog rebase -branch release-7 -new release-7-b -switch
patchlog janitor -ns matches                     # purge merged/superseded/abandoned branches after `cleanup`
```

- `rebase -onto` may name a namespace further up the branch's base chain (§7.4, §F.5), with
  `-switch` too: the core takes as `successor` a branch of the same base or of a namespace
  further up the base chain, checked only by the write that sets or changes it (v0.73). An e2e
  branch's successor wraps its key for each `-reader pub.jwk` (repeatable), for the view's own
  key (`-identity`) and for the old branch's readers whose keys the view knows;
  `RebaseResult.DroppedReaders` lists by thumbprint the readers of the old branch's newest epoch
  the successor's keyring lacks, and with `-switch` the rebase stops before replaying
  (`merge.ErrReadersDropped`), the old branch still in use, until it is run again with them
  named (§F.8.1, §E.3.2). A branch whose own keyring is still in the format before v0.63 is
  refused, naming the namespace to migrate (`patchlog e2e migrate-keyring`).

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
  base's `merge.authors`; a successor's batch counts for `superseded` only if its grant's root
  `sub` and `kid` are in the base's current `merge.authors`, or it is signed by the key that is
  the old branch's current `*` key under its kid (the stored grant, `GET /ns/{ns}/grants/{gid}`,
  verified under it; local bases only); `"abandoned": true` counts only if the config write
  that set it was signed so, so only the branch's administrators can give up everyone's
  unmerged work, and a key removed, or replaced under the same kid, withdraws what it claimed.
  In the `merged` and `superseded` checks every resource the branch changed up to `source.at`
  must have an entry in a counting batch since its last change, or a head there that equals or
  descends from the branch's revision (the closing rule); the decision names the first one
  that hasn't. The successor may be a branch of any namespace up the old branch's local base
  chain (§F.5), which the core accepts (§7.4); one purged after the freeze is verified from
  its log. A purged namespace's `/branches` is `410` (§7.4, §8.5): the janitor and namespace
  followers take it as having no branches. An entry with `"grant": null`
  counts, on its author alone for `merged` and `superseded` and as a `*`-key write for
  `abandoned`, only while `GET /` says `"auth": "disabled"` (asked on each check, so a janitor
  notices a restart with grants); entries without `grant` count for no one. Cleanup is opt-in:
  a branch is purged as a state only once the period its own document's `cleanup` gives that
  state (`"cleanup": { "merged": …, "superseded": …, "abandoned": … }`) has passed, counted
  from the last config write that froze it or set or changed the claim; the base's `cleanup`
  only sets minimums, since `cleanup` isn't copied into branches (§7.6). Against a `-dev`
  server the janitor needs `-author`.

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
  (`merge.PlanDigest`): `text(trunc160(sha256(canonical(plan))))` over the spec's plan,
  `{ "release": <revision>, "batches": [ { "ns", "source": { "ns", "at" }, "items": [ {
  "resource", "ifMatch" | "ifNoneMatch", "steps" } ] } ] }` (`merge.PlanObject`, v0.63), the
  batches in the order they are submitted, one per step with items, steps as plaintext before
  any sealing, without gesture, undoes, signatures or a fresh `$nonce` (F-F1 defaults), and the
  second half of a split node's precondition written as `"ifMatch": { "batch", "item" }`
  (indices from 0) instead of an id; `source.at` is each branch's `ns_id` before the approval's
  freeze, and each branch's `base` must be the namespace it is keyed by, or the earlier
  release's branch for that key. Each step also stores its own part's digest. Plans stored or
  approved by a version before v0.73 are planned and approved again, but a merge one started
  resumes under the step digests it was approved with. Each half of a `-split` must change the
  node (`bad_split` otherwise). `plan` prints the digest; `approve` (the approving
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
  `merge-lock.{catalog base}` in the release document's own namespace (`-state-ns` no longer
  moves it), `{ "holder": <sub>, "plan"? }` while held and `{}` while free (§F.9, v0.56's
  takeover rule), taken with an append with `If-Match` when free (or created with
  `If-None-Match: *` the first time) and released with an append of `{}`, from its first step
  until every branch records `merged`; a merge resuming from a stored plan takes over the lock
  that plan holds. Another release's `apply` fails with `ErrLocked` meanwhile. A
  `{ "release": link }` lock an earlier version took is taken over by the resumed merge it
  names; any other is released by a person appending `{}`. `release status` shows the locks.
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
  -d '[{"op":"add","path":"","value":{"read":"grant","keys":[…],"base":{"origin":"https://a.example","ns":"matches","at":"1k…","chain":["matches"]}}}]'
```

- **Source side (A).** `POST /ns/{ns}/branches` with `{ "remote": { "origin", "ns" }, "at" }`
  registers (`If-None-Match: *`) or renews (`If-Match` with the latest entry's `ns_id`, same
  `at`). It needs unrestricted `read` (§2.1), checked as gate step 1 checks verbs, in a public
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
  §8.6). The genesis must give `base.chain`, A's namespace, then its base, and so on, as of
  `at` (`422` at `/base/chain` before anything is fetched), and is stored as sent. No answer
  from A, a `5xx`, or a fetch that fails verification is `502` with `code: "upstream"` and
  `origin` (§12.1); what A answers for its own URLs (`401`, `403`, `404`, another `4xx`), and
  keys B can't get, are `422 invalid`, as a base B can't read. Nothing is written either way.
  B judges the base by its current namespace document (read, level, nonce); where it is e2e
  now, an `at` before its raise to e2e, and a `chain` naming the branch itself, are `422`. The
  operator grant that creates the branch must allow `config`, which covers the schema
  namespaces it mirrors (`403`).
  A base that is purged at A, or has a purged base in its chain, is `410 purged` instead, with
  `origin`, `ns` and `head` naming the purged namespace at A and its `purge-ns` entry (the
  first one found, A before its bases; v0.50), for any `at`, as for a local branch, once B's
  grant passes A's read check there: B reads A's `/heads` first. A purged schema namespace B
  would mirror isn't in the chain: `422 schema_unavailable` with `ref`.
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
  created if missing as exactly `{ "read": "public" }` when its source at A is public and
  `{ "read": "grant" }` otherwise (§G.3, F-F8; nothing of the branch's is copied), and given its
  source's `nonce` setting with a config write by the creating operator once that history is
  in, so later writes there stay exportable. A mirror, created or existing, that ranks below its
  source is `422` (§2.1), and so is an end-to-end one the history would have to be written
  into; a frozen one refuses the history with `409 frozen`, a purged one with `410 purged`, and
  a path holding the base's history purged with `410 gone`. A path whose chain neither contains
  A's nor is a prefix of it, or a branch, is `409 name_conflict`; a prefix is extended. A schema
  namespace answering `401`/`403` at A is `422 schema_unavailable`.
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
  branches and cache tags. A sealed base's purge arrives instead as the `410 purged` of its log,
  applied as its `purge-ns` entry at the `410`'s `head` (§8.5). With `-remote-ignore-purges`
  they are recorded as notices only (`Engine.RemoteNotices`). A purge on B also removes the
  shadows' copies. When A's base is a branch, B follows only that branch's log: A's purges in
  its bases propagate to it as purge entries there.
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
curl -X POST $B/ns/matches/keys -H "Authorization: Bearer $READER" -H 'Content-Type: application/json' \
  -d '{"epochs":[1]}'
```

- **What it is.** A sealed namespace keeps encryption at rest (E1) and serves every response
  that carries content as a JWE (`Content-Type: application/jose`, `alg: dir`, `enc: A256GCM`,
  protected header `{ kid: "{ns}#{e}", pl }`, `internal/seal`; never compressed, so no `zip`:
  bytes an earlier version stored with `zip: "DEF"` are still served and open, §E.2.2 v0.65).
  The CDN then holds only
  ciphertext, cached by read mode (§E.2.5, §9, v0.73): with `read: "public"` in the public
  classes, with `read: "grant"` privately, edge lifetimes only on reads a verifying edge
  verified, as for private plaintext. Earlier versions cached both publicly: the first start
  after upgrading queues a purge of the `ns:{ns}` tags of sealed and e2e namespaces with read
  `grant`, which the leader sends with its second purges (purge them by hand where the second
  purge is turned off, `RepurgeDelay` < 0).
- **Wire shapes.**
  - `GET /r/{ns}/{name}/rev/{id}`: one JWE, `pl { ns, name, id, kind: "doc" }`.
  - `…/rev/{id}/log` and resource long-polls: a JSON array of per-entry JWE strings, `pl { ns,
    name, id, kind: "rev" | "tombstone" }`, each sealing the plaintext entry object.
  - `GET /ns/{ns}/rev/{ns_id}`: one JWE, `pl { ns, id: ns_id, kind: "doc" }` (v0.63; readers
    still accept `kind: "config"` in bytes sealed before).
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
    Write responses go only to the writer (`no-store`) and stay plaintext. A sealed `200` of
    `/r/{ns}/{name}/rev/{id}` or `/ns/{ns}/rev/{ns_id}` has `ETag: "{id}.{e}"`, `e` the epoch of
    the stored sealing, and `If-None-Match` is compared with that tag, so `"{id}"` alone gets no
    `304`; head pointers keep `"{id}"`, and write preconditions take the bare id (§7.1, §7.4,
    §E.2.2, v0.73).
  - Not sent at all (§7.1, §7.4, §E.2.2): revisions' `Last-Modified` and `Repr-Digest`, and
    `/heads` entries' `created`, `size` and `digest`, which would show the exact created times
    the logs seal and the lengths padding hides; `If-Modified-Since` is ignored, so `304`s can't
    be probed for them (`If-None-Match` still gives one). A tombstoned head's `410` names no
    `successor` (§8.1): a client reads `$successor` from the document at `last`
    (`client.Moved`). `…/raw` is `404 not_offered`. A namespace raised to sealed lists none of
    the three on any of its pages from then on, earlier ones included, and the raise purges
    `ns:{ns}` (§9), whatever its `read`.
- **Keys.** Each (namespace, epoch) has a 256-bit random epoch key, wrapped by the key store in
  `epoch_keys`. `encryption.epoch` starts at 1 (absent means 1, not §12.3's 0, since existing
  sealed namespaces' epoch keys are numbered from 1; a new namespace or branch, or one becoming
  sealed, may name any start), and a config write to a namespace already sealed or e2e may only
  keep it or add exactly 1, which starts a new epoch; its start time is that write's time.
  Resource content is sealed under `K_r = HKDF(K_e, ns, name)`, namespace documents and ranges
  under `K_e`.
- **Which epoch.** A revision or tombstone is sealed under the epoch in force when it was
  written (recorded in `rev_epochs`); a namespace document under the epoch in force at that
  entry, and a log range under the epoch current when it is first sealed (§E.2.2, v0.73; ranges
  stored before keep their bytes). Content with no such epoch — read through from a base, or
  written before the namespace became sealed — gets the serving namespace's epoch current at
  its first sealing, kept forever.
- **Stored once, served forever.** Sealed bytes are made lazily on first read and stored in
  `sealed` (per serving namespace); concurrent first readers `INSERT OR IGNORE` and re-read, so
  everyone gets identical bytes, and ETags, `304`s and CDN copies stay valid. Ranges are stored
  too, at most 4096 per namespace (the oldest are dropped and resealed with fresh bytes on
  demand; event streams and long-polls reuse them). Purges delete a resource's sealed rows,
  a namespace purge also the epoch keys (cryptographic), and prunes the rows of what they
  pruned (kept documents keep their bytes). Nothing is compressed before sealing (§E.2.2,
  v0.65): a document holds content from several authors, and compressed lengths would leak it
  (the CRIME/BREACH class of attack).
- **`POST /ns/{ns}/keys`** `{ "epochs"?: [e…], "resources"?: [name…] }` → `{ "keys": [ { kid,
  name?, key } ], "epoch", "level", "pad" }`, `Cache-Control: no-store`: the current epoch,
  the level (`sealed` or `e2e`) and `pad` are what a writer limited to some resources needs to
  seal and can't read in the namespace document (§E.2.3, §C.5; v0.51). It needs a verified grant
  with `read` (also for a `read: "public"` sealed namespace); with `-dev` anyone gets every
  epoch's keys. It refuses as other reads do (§7), but doesn't ignore the grant in a public
  namespace (v0.73): `401` without a usable grant, `403` for a grant that doesn't name the
  namespace or that its key's scope refuses, `404` without `read`. A grant that reads the
  namespace unrestricted (§2.1; with roles, through one without `/resource` rules that passes)
  gets `K_e`. Only a grant whose rules fix `/resource` (§2.1) gets `K_r` (`name` names the
  resource), by default for every name it fixes; a requested name it doesn't fix or may not read
  is `403`, and `"resources": []` asks for none (§E.2.3, v0.73). Any other `read` grant, such as
  one whose role rules merely refer to `/resource` without an unrestricted role that passes, is
  `403`. A purged namespace answers `410 purged`, with `head`, only after all of that (§8.5),
  and a namespace that isn't sealed `404 not_offered`, which tells a limited writer there's
  nothing to seal (v0.51; it was `422`). Epochs run from the one in force at the latest `nbf`
  among all the grant's blocks, a narrowing block's included (without any `nbf`, the current
  epoch only: a grant that needs older epochs needs an `nbf`), up to the current one;
  `encryption.historyEpochs: h` gives the current epoch and the `h` before it (0: the current
  only); epochs begun after the grant's `exp` are no longer left out (v0.73). Requested epochs
  outside that are omitted. A request answered with keys draws one token from the principal's
  `exchangeRate` bucket (`429`, `limit: "exchangeRate"`); a refused one draws none. A root block
  with `"enc": { "kty": "OKP", "crv": "X25519", "x" }` gets keys HPKE-wrapped to it
  (`{ kid, name?, wrapped }`, `seal.WrapKey`, under the info `"patchlog-key-v1"` LF kid LF
  resource name, empty for `K_e`; §E.2.3, v0.63) and never raw ones; narrowing blocks can't
  carry `enc`. Entries before v0.73 named the resource `resource` and carried `suite`; clients
  read both forms.
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
  branches, recorded as due in the revocation's own transaction (`rotations_due`) and retried
  every minute until a new epoch begins, any new epoch clearing it, so neither a crash nor a
  failed rotation loses it (v0.73).
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
  header without a key: `pl` exactly this write's, no `zip`, and `kid` the epoch in force, for a
  batch item the one the batch's config change produces (`422 invalid` otherwise; a declared
  blob with a nonce is `422 blob`, §E.3.1, v0.73). That catches client bugs and cross-resource
  replays early; it is a consistency check, not a security boundary (a writer can always seal
  garbage; readers verify `pl` when they decrypt). Nothing is applied and schemas aren't
  validated; limits apply to
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
  sealed with `pl { ns, name, id: s }` (v0.63; snapshots stored with `kind: "snapshot"` still
  open), is served as `/rev/{s}` (§7.1 Paging,
  §8.6): `200` with the JWE as `application/jose`, `X-E2E: snapshot`, `ETag`/`X-Revision` and
  the immutable class (`If-None-Match` answers `304`). For a tombstone horizon the snapshot is
  the last live document, and `/rev/{s}` keeps the tombstone's `410`, with `X-E2E: snapshot` and
  `{ "code": "gone", "snapshot": "<JWE>" }`. The snapshot stays served after an archive restore
  clears the horizon, until a later prune or a purge. Every other revision keeps the fold
  redirect (what it should serve is §13's open question), so a key holder folding a revision
  after the horizon reads `/rev/{s}` and then the range after `s`. As at E2, no revision read,
  the keyring's and snapshots included, carries `Last-Modified` or `Repr-Digest`
  (`If-Modified-Since` is ignored), `/heads` entries carry no `created`, `size` or `digest`,
  a tombstoned head's `410` names no `successor` (`client.E2E.Moved` folds the document at
  `last` for its `$successor`, and ignores one a `410` names), and `…/raw` is `404
  not_offered` (§7.1, §7.4, §8.1).
- **The keyring.** The reserved resource `keyring` holds the §E.3.2 keyring document in
  plaintext, `{ "keys": [ { "kid", "to", "from", "wrapped" } ], "$nonce"? }` (`seal.KeyringV2`):
  each entry an epoch key wrapped in HPKE auth mode under the admin's X25519 key (`from`) to a
  recipient (`to`), both named by RFC 7638 thumbprint (`seal.Thumbprint`), under the info
  `"patchlog-key-v1"` LF kid LF name (v0.63). It is the only plaintext resource, written by key
  holders with ordinary writes; nothing else but `$nonce`, entries of exactly those members, no
  two for one `kid` and `to`, kids of this namespace and no epoch after `encryption.epoch`.
  Anything else, a keyring in the format before v0.63 (`seal.Keyring`) included, is `422
  invalid` (v0.73). An auth-mode entry opens only with its sender's public key, so a reader must
  know the admin's: `client.E2E.WithSenders(adminPub…)` or
  `client.WithKeyringSenders(adminPub…)`
  (services: the client given to `derived.Keys`; their flags come in wave 3); a view always
  knows its own key, and the playground its identity and the keys remembered with its
  "Remember key" button. A keyring stored in the old format is still relayed as stored until a
  key holder migrates it: `patchlog e2e migrate-keyring -api URL -ns NS -identity admin.jwk
  -reader pub.jwk… [-current-reader pub.jwk…]` (`client.E2E.MigrateKeyring`) wraps each epoch
  again only for the readers given (`-current-reader`: the newest epoch only), never the stored
  lists; `AddReader(ctx, ns, reader, true)`, the remedy before, no longer applies. A holder that
  can't open every epoch, such as one added at a later epoch, migrates those it can with
  `-skip-unopenable` (`MigrateKeyringOpenable`; it must open the newest), which reports those
  left out, and can then rotate, so revocation works again. A left-out epoch's key is in the
  keyring's history only, and `/keys` doesn't relay it, until a holder of it runs
  `migrate-keyring` again, which puts it back from the keyring's last revision in the old
  format. Entries of an old-format keyring wrapped under the info before v0.63
  (`"patchlog-keys-v1"` LF kid) still open: clients try it when the current one fails
  (`seal.UnwrapKeyLegacy`).
- **`POST /ns/{ns}/keys`** relays only wrapped keys: it needs a verified grant with `read`
  whose root block carries `enc` (else `422`; non-readers, and grants whose rules refuse every
  read, `404`). A grant limited to some resources gets its own entries too, without reading the
  keyring: a key holder chose to wrap them to its `enc`, and it needs them to seal (§E.2.3,
  §E.3.2, v0.51; before, the relay needed a read of `keyring`, which §E.3.2 doesn't say). It
  returns `{ "keys": [ { kid, from, wrapped } ], "epoch", "level": "e2e", "pad" }` — that
  recipient's keyring entries (by thumbprint of `enc`), with their sender as `from` (an
  old-format keyring's relayed as stored, without), for the epochs the grant is entitled to (the
  E2 rule above). A refused request (`422`: no `enc`) draws no `exchangeRate` token.
  Per-resource keys don't exist at E3 (`resources` is ignored). A branch relays its own keyring
  and each local base's as of its `at`, even after it wrote its own, for the base's epochs up to
  `at` (without `nbf`: the base's current epoch, while it is still its epoch at `at`) (§E.2.3,
  §F.8.1, v0.73).
- **Epochs and rotation.** The server holds no key; `e2e_epochs` records when each epoch began.
  A key holder rotates by re-wrapping the keyring for the remaining readers and incrementing
  `encryption.epoch` (by exactly 1, a `*` key) in one batch; old revisions keep their epoch.
  Server-side rotation (`-rotate-epochs`, `-rotate-on-revoke`) doesn't touch e2e namespaces.
- **Prune (§8.6).** `POST /r/{ns}/{name}/prune` `{ horizon, snapshot }` needs `snapshot` (a JWE
  of the horizon's document, or for a tombstone the last live one, with
  `pl { ns, name, id: horizon }` and a known epoch's `kid`, the pre-v0.63 `kind: "snapshot"`
  being `422 invalid`; it carries no
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
  `AddReader` and `RotateEpoch` administer the keyring, writing the keyring document under the
  view's own recipient key as its sender (always including the admin's own key);
  `RotateEpoch` writes the keyring and the epoch bump in one batch, and `MigrateKeyring` and
  `MigrateKeyringOpenable` migrate one stored in the old format. Keys come from `/keys`,
  falling back to the keyring resource. `client.EncryptionLevel(ns)` reports a namespace's level.
  A writer limited to some resources, which can't read the namespace document (§C.5), seals
  under the epoch and `pad` `/keys` names (`client.FetchKeysAnswer`); its grant needs `enc`. The
  server is outside the trust boundary at E3, so the epoch is raised to the newest one relayed
  to the grant: a server can't make it seal under an epoch older than one it holds a key for,
  though it can withhold a newer one. It then can't tell which configuration older revisions
  were written under, so its folds flag nothing for padding.
- **Refusals.** The merge tool refuses e2e namespaces (§F.8: merges re-encrypt, never
  fast-forward); `patchlog export` refuses snapshots of them (full history carries the
  ciphertext, §G.5.1).
- **Metadata no level hides (§E.4):** names, ids and parent links, sizes, timing, authors and the
  namespace log's shape.

### Tree and catalog (Addendum B)

`patchlog tree -catalog cat` follows a catalog namespace and the content namespaces it trusts, and
serves folder listings (`children`, `ancestors`, `subtree`, `roots`, `orphans`, `problems`,
`where`, `manifest`) at URLs pinned to its combined checkpoint: `/{catalog}/at/{at}/…`,
unfiltered and to everyone (a grant is ignored), while the catalog and every namespace in the
combined checkpoint are public; any other listing only under `/{catalog}/g/{gs}/at/{at}/…`, the
subject set before the checkpoint (v0.51, §B.11.5), where a request with neither a grant nor a
cookie the service verifies is `401` (v0.73: the anonymous filtered listing of a public catalog
that trusts a private namespace is gone). A grant in `Authorization` reads only at its own `gs`,
or at `all` where it qualifies; at another `gs` it is `403`, never redirected. URLs without
`/g/{gs}` redirect into the reader's, `Cache-Control: private, no-store`, and
`/{catalog}/g/{gs}/{op}` is a head pointer under an edge grant's prefix, redirecting to
`/{catalog}/g/{gs}/at/{cur}/{op}` (`403` at another reader's `gs`). The old
`/{catalog}/at/{at}/g/{gs}/…` is moved to the new form with a `301`. A grant over `grantSize` or
`rulesPerGrant` is `413 limit`, naming the limit, on listings, `/read-grants` and the exchange
(it was `401`; §C.8, §C.6). Cycles and depth over 64 show up under `problems`. `-catalog` is
repeatable (or comma-separated): each catalog gets its own
service and database (`-db` with `{catalog}` replaced, or `-{catalog}` added before the
extension) behind one origin, and `/_status` covers them all (`?catalog=` for one). Listings
are `503 behind`, with `Retry-After`, until the service has caught up with the catalog and with
every namespace it trusts (started with a fresh database, rebuilt, or trusting one lately), to
the head each one's follower read when it started, not just a first log page, rather than show
every placement of a namespace not yet followed as missing; once caught up, a restart on the
same database doesn't wait again. One it can't follow (purged, skipped for its keys as
configured, refused or absent at the core) isn't waited for until the core serves it again, and a
`?min=` naming it is `400`; one whose epoch key can't be fetched for the moment (the core
unreachable, a `5xx`, a `429`), sealed or end-to-end (its relay's keys and its keyring both),
is skipped but still waited for. A namespace the catalog stops
trusting loses its catch-up, also one its follower reports after that (once stopped, also after
it is trusted again), and one recorded before a stop, so trusted again it is waited for again.

Listings are kept like the search index's results (§A.4, §B.5, v0.49): every listing computed,
the one at the `at` a redirect names included, is kept in memory for about a minute (at most
64 MiB per catalog), and an `at` URL answers `200` while its listing is kept, so one redirect
suffices at any write rate. They are keyed by their URL and by what the reader reads whole, so a
reader whose namespace-wide reads changed since (a public namespace turned private) isn't served
one kept from before; listings that depend on the individual reader aren't kept. Every listing is
served only at its canonical URL, the query in the search index's canonical form (v0.50, §A.5),
and other forms are redirected to it; a `children` listing's `next` is in that form. `min` is a
set (v0.51), and a parameter other than `min` given more than once is `400`. A purge drops the
kept listings that show what it purged.

Listing shapes (§B.5, v0.73). `children` carries `total`, the number of visible children, and
pages as `/_refs` does: `next` is still the following page's query, its `after` an opaque
position (`{pos}~{at}~{last}`) whose pages are kept at the first page's `at` (up to 10 000
children), a `next` sent back as `after` continues, and a malformed position or a `limit` above
1000 is `400`; the v0.55 `after={order}` cursor, with `name` or `unordered`, is accepted for
this release. Every node carries `born`, the `created` of its document's first revision, sealed
per entry with the title in sealed and end-to-end catalogs; an implicit placement's (§B.9) is
shown only with its item, and never for items of sealed or end-to-end namespaces; it is left out
where a prune cut the chain. Sibling `order` keys compare by UTF-8 bytes (§B.2), and an explicit
placement wins over `$parents` whether live, deleted or purged (§B.9). A visible node whose
parents are all hidden is a root for that subject set: `roots` lists it, and `ancestors` and
`where` paths end at it (§B.11.5); `where?item=` naming an item that isn't in the catalog, or
whose placement is hidden, is `404`. `…/lookup?path={titles}` resolves a `/`-joined path of
titles from a file tree's `root`, or from the reader's roots where `root` is hidden, comparing
after NFC and simple case folding (`files.TitleKey`); numbered and escaped display names don't
resolve, siblings sharing a title answer the earliest `born`, then node name, and the answer is
`{ at, path, node }`. A path that doesn't resolve is `404`; catalogs without `files`, and sealed
or end-to-end ones, answer `404 not_offered`. A refused `min` is `400`, its body's `min` listing
the refused values (malformed ones too), and a `min` naming a namespace this service or another
catalog's behind the same origin holds as purged counts as reached (§A.5). The `503` while a
sealed namespace's keys can't be fetched yet has code `behind`, with `Retry-After` (§12.1); a
catalog whose keys the service lacks is `404 not_found` (the code `skipped` is gone). A `503
behind` has a generic message, and its `ns` member names the awaited namespace only to readers
with unrestricted read of the catalog (§B.5, v0.73). In a
file tree, `file` says why it is absent: `{ "absent": "e2e" }` or `{ "absent": "pending" }`
(§H.3). A database from before this version gains the new columns and records on its first
start, and `born` is filled in beside the followers, a few logs at a time.

With `-access -key SEED -kid KID` it also issues grants from the tree (§B.11):
- `POST /grants` with `{ "node", "want": ["create"], "to": [folders] }` creates a folder
  (§B.11.4): `move` on every folder in `to`; the grant fixes the name and parents and, unless
  the caller is an admin, refuses `$access`. Tree powers on the new folder come only from its
  own `$access`; until an admin gives it some, only admins may move or place into it.
- `POST /grants` for content verbs, `create` (genesis only; `409` for a taken name), `place`,
  `move` and unplace (pinned to the placement's current parents), with the no-widening rule. Effective
  roles on an item are collected only through subjects the catalog key in its content namespace may
  assert (its `groups` scope, and its `sub` scope for the caller's sub), for `/read-grants` and
  restores too (§B.11.4 Resolve). Tree powers count only at live folders off any cycle, through
  subjects the catalog's key in the catalog may assert, and the same subject's role must hold the
  power at every parent; a missing, tombstoned, purged, cyclic or non-folder parent gives none, a
  folder without `$access` gives each role the powers it has at all its parents, and
  `catalog-admins` need no tree power. Folders' roles compare by name in the no-widening checks.
  A deleted placement's rows are kept until it is placed again or purged (§B.11.7), so a
  non-admin re-place that would widen them is `403`; one deleted before this version has none,
  and only `catalog-admins` can re-place it. A move of a deleted item's placement is checked like any other, against the
  roles the item would have now (§B.11.7).
- **Organising requests** (Place, Move, Create a folder, Unplace and delete; §B.11.4, §B.11.5,
  v0.73) answer in the spec's order: malformed `400` (a Place, Move or Create a folder without
  `to` included); a node that isn't an untombstoned node of the catalog, or a `to` entry that
  isn't a live folder, `404`, and so is either one hidden from a caller not in
  `catalog-admins`, with the same answer and checkpoint as a missing one; failed requirements
  (place list, powers, an untrusted item namespace) `403`; then `409`. The `422` codes
  `not_folder`, `untrusted` and `not_placement` are gone. A dangling placement is judged as if
  its item were live, and cyclic nodes are hidden; a non-admin can't move, unplace or delete a
  node with a parent hidden from it (`403`, naming nothing hidden), and a widening refusal at a
  hidden node names only the moved node. Roots and an empty `to` need `catalog-admins`, who may
  give `to: []` for Place, Move and Create a folder (the grant then fixes `/doc/parents` to
  none). A Place of an item whose placement was purged is `410 gone`, without `checkpoint`; a
  live placement is still `409`. A Move whose `to` names the node or one below it is `403`.
  **A Move grant** may change the node's other members, `$access` excepted (a non-admin's refuses
  writes to it, and a non-admin's Place grant a placement with `$access`), a rename being a move
  to the current parents; unless the caller is in `catalog-admins` it requires the patch set to
  begin with `{ "op": "test", "path": "/parents", "value": <answer.parents> }`, and it expires at
  most the catalog's `maxLag` (60 s by default) after its decision. The answer carries
  `parents` for a Move grant that pins them and `head` (the node's head as decided) for Move and
  Unplace or delete, beside `ns`, `resource`, `can`, `roles`, `exp` and `at`. `want: ["delete"]`
  deletes folders too: it needs move on every parent, and the grant fixes `/doc/parents` to them
  by `href`; a tombstoned folder is `404`, and so is a request to restore a catalog node (`409`
  when live). An end-to-end catalog gets no organising grants (`404 not_offered`). `checkpoint`
  names every namespace the decision read: a non-admin move's, and any decision judging a
  folder's visibility, names every trusted namespace, as does a catalog folder's entry in
  `POST /read-grants`.
- `POST /grants` with `{ "item", "want": ["restore"] }` restores a deleted item where it is placed
  (§B.11.4): the roles come from the `effective` rows frozen when the service saw the item's
  tombstone (marked `tombstoned`, kept across restarts, no longer recomputed), so placing the deleted
  item or moving folders afterwards changes nothing; they stay those of its deletion even if it was
  unplaced and placed again, but it must still be placed. The grant carries `can: ["restore"]` only;
  used on an item that is live again, the write is an append and the core refuses it. The answers,
  in order: a name that never existed `404`; a purged item `410`, as is any name of a purged
  namespace, which the core answers `410 purged` for too (§8.5), even one the service never saw,
  such as when it started after the purge; `403` for a caller without a role
  granting `read` on the item (in its frozen rows if deleted, its current ones if live), without one
  granting `restore`, whose item has no placement, or whose restore would widen: the roles the item
  would have after it, from its current placement, exceed its frozen rows for some subject, judged
  with `includes` as for moves (a catalog admin skips that check, as for moves); then a live item
  `409`. The catalog key's entry in content namespaces lists `restore` for this (§B.11.3):
  `"can": ["read", "create", "append", "restore"]`.
- `POST /read-grants` returns resource-scoped read grants, and the keys of catalog nodes (and of an
  item's placement) visible to the caller: `{ "grants": [...] }`, one entry per item in request
  order, each with `grant` and `exp`, `public: true` (an item in a public namespace: no grant
  needed; a sealed one also gets its keys), or `error` (`{ status, code, message }`), and its `checkpoint`
  (below); a sealed item also gets its keys, and a catalog node keys and no grant. It decides
  every item at one combined checkpoint: if the checkpoint moved while it decided, it decides
  again, up to three times, then answers `503 behind` with `Retry-After`. So "may this reader
  read all of these?" is one call (v0.51, §B.11.5): it may iff every item comes back with a
  grant, as `public: true`, or, for a sealed item or a catalog node, with its keys, that is if
  no entry has `error`; it may not if an entry's error is a refusal (a `4xx` status); an entry
  whose error is a `5xx` (`503 behind` when the catalog lags its `maxLag`, `503 keys`,
  `502 upstream`) is undecided, and the client asks again. It takes 1 to 100 items (`400`
  otherwise).
- Decisions carry `checkpoint`, `{ ns: ns_id, … }`: the `ns_id`s of the catalog and of each named
  item's namespace they were decided at, which are all a decision depends on (v0.51, §B.11.4), so
  a client that caches a decision keys it by them, and a write to another namespace the catalog
  trusts doesn't drop it. It goes beside each grant, never inside it: in the answers of
  `POST /grants` and `POST /merge-grants` (for a merge batch, the namespaces of the items its
  placements name), in each entry of `POST /read-grants` (for a catalog node, the catalog's, and
  for a placement node also its item's namespace's), and in the bodies of refusals that are
  decisions (`403`, `404`, `409`, `410`: `{ code, message, checkpoint }`). One map per entry,
  rather than one for a whole `/read-grants` answer, keys each item by only its own namespaces
  and leaves out the entries that have none. A refusal decided from state the checkpoint doesn't
  pin carries none: a `409` for a name the core has but the service hasn't seen yet, a `403`
  because the catalog key is missing at the head, a merge batch's stale precondition, a `5xx`;
  so does a public item of a namespace the catalog doesn't follow, read at the head. It isn't
  listings' combined `at`, and the grants' own `at` stays the catalog's `ns_id`, which
  `requireAt` can check. What a decision reads is as of that checkpoint, as for listings: the
  roles, their definitions, the catalog key, includes and place lists, and for `/read-grants`
  whether a namespace is public and its encryption. So a `/roles` or `read` change the service
  hasn't reached yet doesn't change a decision.

Listings are filtered by the caller's subject set (§B.11.2, §B.11.5): its sub if it starts with
`user:` (any other sub is no subject), and `group:{g}` for each of its groups, only the exact
admin group counting as `catalog-admins`. A node is visible when the walk up collects, through a
subject the catalog key may assert, a role granting `read` without conditions: for an item, a
role its content namespace defines with `read` and the catalog key there may grant (its
`roles`, `groups` and `sub` scope), whose rules, and the key's scope `rules`, pass as a read of
the item would evaluate them: `action` `read`, the item as `resource`, and `/principal` holding
only the caller's groups the key may assert and, as `roles`, that role; no `writes`, `doc` or
`patches`, so `within` is true and `covers` and `overlaps` are false. A rule that refers to
`/now`, or to anything in `/principal` but `/principal/groups` and `/principal/roles` (or to the
whole envelope), makes the role not count. So the spec's `translator` (`writes within
["/i18n"]`) sees the items it may read. For a folder, a role counts whose rules don't refer to
`/resource`, through a key whose scope rules refer only to `/principal/groups` and
`/principal/roles`. A `sub` scope on the catalog's key in any trusted namespace adds the caller's
`user:` subject to its listings' subject set (`gs`); a subject set without one sees nothing
through sub-scoped keys. `children`, `subtree`, `roots`, `ancestors`
and `where` show visible nodes and only paths through visible folders, with no counts of hidden
ones; limits, cut markers and pagination count visible nodes. `/read-grants` uses the same test.
Visibility is decided per request from `effective` and the content namespaces' documents (roles,
their definitions and the catalog key) as of their `ns_id`s in the listing's combined checkpoint:
the service keeps each content namespace's document with its checkpoint (`meta` `config:{ns}`,
read at the checkpoint after a snapshot or an upgrade), never the grant checker's latest copy, so a
listing at a given `at` never changes when a `/roles` change lands later. `problems`, `orphans` and
`manifest` aren't filtered: they need §2.1 unrestricted read, judged per request, of the
catalog and of the content namespaces they cover (`403` otherwise; under a subject set's cookie
always `403`), for a manifest those of the items it pins, for `problems` and `orphans` the
trusted namespaces in the combined checkpoint; a public namespace counts as read namespace-wide.
A reader whose grants would be issued namespace-wide edge grants (§C.5.2) for every namespace in
the combined checkpoint that isn't public, the catalog among them unless it is public, is served
unfiltered listings under `/{catalog}/g/all/at/{at}/…`, shared by all such readers, with a
private `max-age` no longer than that grant's expiry; a block, key or role rule on `/now`
disqualifies a grant even while it passes, and with a public catalog the grant needn't name the
catalog (v0.73). Reading only some of them as a whole doesn't change the URL space (the listing
is then the subject set's), but still admits `problems`, `orphans` and manifests covering only
those, served `private` with a `max-age` no longer than the grants, `no-store` for shared caches,
and never stored sealed. Without edge grants, the service decides `all` per request. A tree
service without §B.11 (no `-access`), release previews included, serves only `g/all`, to readers
who qualify for it; other grants are `403` (§B.11.5, F-T6), and a gateway relays that `403`. A
sealed catalog's listing is sealed whole only for `g/all` of a catalog that isn't public, per
entry otherwise; whole listings earlier releases stored elsewhere are dropped at start
(§E.2.6).

**Edge grants for listings** (v0.51, §B.11.5, §C.5). A listing read with a grant in
`Authorization` belongs to one credential, so it is never cached at the edge; the catalog
service mints cookies of its own, bound to a subject set, so an edge can cache a listing for
everyone who shares it. `POST /edge-grants` on the service's origin follows the core's issuance:
the grant in `Authorization`, or 1 to 50 as `{ "grants": [ … ] }` in an `application/json` body
(`415` otherwise; `400` with `Authorization` too, an empty list or another member), all or
nothing (`401` if any grant is, else `403`), answering `{ "prefixes": [...], "exp" }`
(`no-store`) with one `Secure`, `HttpOnly` cookie per prefix, named and formatted as the core's.
Once nothing is refused, an exchange draws one token, however many grants it carries, from the
`exchangeRate` bucket of each distinct principal among them (keyed by principal and kid, as the
core keys write buckets), and is `429` (`code: "rate"`, `limit: "exchangeRate"`, `Retry-After`)
while any is empty (v0.52, §6.6). The buckets, 10/s with a burst of 100 by default, set with
`-exchange-rate RATE,BURST` as `serve` takes it, are shared by every instance on one `-db`, each
draw an atomic check-and-draw (v0.73). Like the core's, it takes no query parameters (`400`). A
body with a Unicode noncharacter is `400`, and one larger than 50 grants of `grantSize` can be is
`400 bad_input` before it is parsed (§3.1, §C.5.2; it was `413`).
Each grant is resolved as a listing resolves its reader: its prefix is `/{catalog}/g/{gs}`, the
subject set its listings are served under, lasting until that grant's `exp` or 15 minutes,
whichever is sooner; or `/{catalog}/g/all` for a reader with namespace-wide read on the catalog
and every content namespace it trusts, lasting until the earliest of those grants. A prefix
several grants give gets one cookie, lasting as long as the longest, and `exp` is the earliest.
While the core runs with authentication disabled it is `404 not_offered`, before the body is
read; so is it on the plain tree service, whose listings depend on more than a subject set.
`DELETE /edge-grants?prefix=…` withdraws them, as the core's does for its own prefixes (`prefix`
repeatable, each `/{catalog}/g/{gs}`, `400` otherwise; `204` with expired cookies, no grant
needed). Credentialed CORS is the core's: pages listed with `-cors-credentials-origin` call it
with `credentials: "include"`, the cookies are then `SameSite=None` (otherwise `Lax`), and only
those origins may preflight the `DELETE`. Cookies are signed with the last
`-edge-grant-key [KID=]FILE` given, a key of the service's own that the origin never holds
(refused if it is the key derived from `-edge-secret`, or `FILE` `edge-secret`; without the flag,
a random key per process, so cookies don't survive a restart), and accepted under any of them, so
the service's key rotates as the origin's does: add the next key to the edges, then to the
service as the last flag, and drop the old one 15 minutes later. The flag takes the arguments
`serve`'s does; a plain `FILE` is named `-edge-grant-kid` (default `catalog-{catalog}`). No kid of
the service's may be one of the origin's, which `-origin-edge-grant-kid` lists (repeatable or
comma-separated, default `origin`): every `KID` of the origin's `-edge-grant-key` flags and its
`-edge-grant-kid`. Keep that list in step with the origin's rotation, adding a kid when the origin
takes it, since an edge looks keys up by kid. The edge-grant flags and `-exchange-rate` need
`-access`. A catalog named `r` or `ns` mints none, since its prefixes would overlap the core's (the
service still runs; naming a key or kid for it is an error).

A `GET` or `HEAD` without `Authorization` that carries one of these cookies, covering its path
and passing the six checks an edge makes (see
[Private namespaces and the edge](#private-namespaces-and-the-edge), with the service's kid),
is read as that subject set, with no grant. The cookie covers
the subject set's listings at every `at`, not the head pointer: a reader follows the pointer with
its grant once, or starts from any `at` under the prefix, which redirects to the current one. A
read under a cookie gets edge lifetimes only when a verifying edge (`-edge-secret`) checked it
and says so, with the prefix in `-edge-prefix-header`, exactly as for the core's private reads;
otherwise it is `no-store` at the edge, and so is everything else private. Namespace-wide reads
don't come with a subject set's cookie, so its `problems`, `orphans` and manifests are `403`
unless the namespaces they cover are public. A cookie carries only `kid`, `p` and `exp`, so the
service keeps the subjects behind each `gs` it minted a cookie for (`edge_subjects`, across
restarts and `-rebuild`, until the last such cookie expires); a `gs` it doesn't know, such as
one another instance with its own database minted, is `401`, and the reader exchanges again
there. A user's direct `$access` entries count as they were at the exchange.

A `g/all` cookie was checked against the content namespaces the catalog trusted when it was
issued, and covers every later `at`, so the service answers `403` at an `at` that includes a
namespace trusted since, until the reader exchanges again (a kept listing from before is still
served). The service records when it came to trust each namespace (`meta` `trusted:{ns}`; a new
or rebuilt database records its start). A cookie carries only `kid`, `p` and `exp`, so every
`g/all` cookie with one `exp` is the same bytes, and when one was issued can be known only where
nothing else holds the key: with a random key (no `-edge-grant-key`), the service records when
it first issued a `g/all` cookie with each `exp` and refuses a namespace trusted no earlier than
that (an exchange that would repeat a cookie issued before a namespace became trusted gets an
`exp` a second earlier). With `-edge-grant-key`, which a restart or another instance shares, it
is conservative: a cookie counts as issued at its `exp` less 15 minutes, so for 15 minutes after
a namespace becomes trusted (or a new database starts) only cookies lasting the full 15 minutes
read an `at` including it. A namespace that was public when a `g/all` cookie was issued and has
turned private since is still read whole under it until it expires, as under a grant revoked
since: the cookie's lifetime is the revocation latency (§C.5). A purged content namespace has no
live items, so every reader reads it whole, sealed or not (a sealed one's documents are `410` once
it is purged, so no grant could be checked against them): it doesn't take `g/all` away for good.
With edge grants, though, an edge may still hold `g/all` listings from before the purge, showing
its last items, until the purge of `ns:{ns}` lands, and serves them to every `g/all` cookie; so
the service counts it as read whole only once those copies have surely expired, a `g/all`
listing's edge lifetime (below) after it applied the purge (`meta` `purged:{ns}`). Until then
each reader's grant is checked as before: on an unsealed namespace, read whole or not; a sealed
one is read whole by nobody, so for those 16 minutes nobody gets `g/all` from it. Once the
catalog itself is purged, an exchange is `410 purged` with `head` after the read check, which the
core makes for a sealed catalog, as its listings are, and a read under a cookie minted before the
purge is `410 purged` too: with `head` under a `g/all` cookie, whose exchange read the catalog,
and without under a subject set's, which a grant without read on the catalog may have got.

An edge can't make that check: it serves a listing it holds to every `g/all` cookie that passes
its six checks. So a `g/all` listing at an `at` including a recently trusted namespace is
`no-store` at the edge, whoever reads it, while a `g/all` cookie issued before that namespace was
trusted may be live: with a random key, while one the service issued is; with a key file, for 15
minutes after. Either way a minute more is allowed for edges' clocks.

Untrusting works the other way round: a `g/all` cookie issued after the catalog stops trusting a
namespace isn't checked against it, but an edge would serve it the `g/all` listings it holds that
show that namespace's items. So when the trust list loses a namespace the service purges
`ns:{catalog}` through `-purge-url`, the tag of every listing of the catalog (the namespace's own
`ns:{ns}` would evict everything every service caches of it), and refuses such a cookie at those
`at`s itself. Should a purge be lost, or race an edge filling its cache, a `g/all` listing's edge
lifetime (`CDN-Cache-Control`) is no longer than a `g/all` cookie lives, 15 minutes, and a minute
for edges' clocks: an untrusted namespace leaves the edge's `g/all` listings within the revocation
latency of a cookie. That cap holds for listings an edge cached from this release on: earlier
releases gave `g/all` listings a year, so after upgrading the catalog service, purge
`ns:{catalog}` at the edge once. A start that finds its derived rows drifted, such as placements
of a purged namespace's names that an earlier release held as missing, purges `ns:{catalog}` too,
stored sealed listings with it, as its listings then change at an unchanged `at`. Without
`-purge-url` purges are only logged, and the cap alone bounds them.

```sh
head -c 32 /dev/urandom | base64 > catalog-edge-grant.key   # the edge holds it too, under catalog-cat
patchlog tree -catalog cat -access -key SEED -kid catalog-01 \
  -edge-grant-key catalog-edge-grant.key -origin-edge-grant-kid k1,k2 \
  -edge-secret edge.secret -purge-url http://cdn/purge -cors-credentials-origin https://app.example
```

Read-your-writes: after its own write, a client relists with `?min={ns}:{ns_id}` from the write's
`X-Namespace-Revision` (repeatable, the catalog or any content namespace it trusts), which is a new
URL past any cached head pointer and waits for the service to catch up (`503` with `Retry-After`
otherwise), instead of fetching with `no-store` (§B.5, §A.5). As in the search index, `min`
always redirects (v0.50): an `at` URL whose listing already includes every `min` (the current
`at`, or a kept one whose checkpoints show it) to itself without `min`, anything else to the
current `at`. A bare `{ns_id}` never counts as included in an older `at`. Every namespace a
catalog's service follows is in its `at`. A tree service serving several catalogs keeps an `at`
per catalog, so a `min` naming a namespace that only another of its catalogs follows, and that
the reader may see (public, or its grant reads it; the core's read check decides for a purged
sealed namespace, whose documents are `410`), is waited for there and redirects to the
current `at` in one hop (§A.5); a `min` naming a namespace no catalog of the service follows, or
one the reader can't see, is `400`, with one message for both. `POST /grants` and
`POST /read-grants` take `?min` the same way; a decision on an item also depends on its content
namespace (whether the item exists), so after creating a document it placed, or restoring one, a
client passes `min` for both (§B.11.4).
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

### File trees (§H.2, §H.3)

Spec v0.55's Addendum H stores files in namespaces so that tools showing them as files, such as
WebDAV gateways and mounts, share them. A catalog whose namespace document says
`"catalog": { "trust": ["files"], "mode": "tree", "files": { "ns": "files", "root": "root" } }`
is a file tree: folders are folder nodes and files placements, named by their `title`s. The
tree service then gives every placement entry with a head, in `children`, `subtree`, `roots`,
`ancestors` and `where`, the file metadata of that head:

```json
{ "name": "files.k3x9…", "kind": "item", "title": "notes.json", "head": "1…", "url": "…",
  "file": { "size": 1234, "type": "application/json", "modified": "2026-10-18T09:12:44.512Z" } }
```

- **`size` and `type`**: for a raw file, a document whose root is a blob reference (§7.8), the
  reference's; for a JSON file, the length of its rendering and `application/json`. The
  rendering (§H.1, `files.Rendering`) is the canonical text of the document without a top-level
  fresh `$nonce` or `$successor` of §8.1's form, laid out as `JSON.stringify(v, null, 2)` lays it
  out, with JCS's tokens and member order (keys that look like array indices stay where JCS puts
  them), and a final LF. `files.MetaOf` computes both; the WebDAV gateway renders and lists
  files with the same code (`files.Show`, `files.Bare`).
- **`modified`** is the head's `created` as the namespace log gives it (a batch entry's for a
  batch, a `/heads` row's for a snapshot bootstrap), else its `Last-Modified`; it is left out
  where neither is known (a snapshot of a sealed namespace, rows written before v0.54).
- **Reads.** The service reads each head once, as it applies the entry that made it the head,
  for every item of every trusted namespace (not only `files.ns`, implicit placements too), and
  keeps the metadata with the item (`items.created`, `items.file`), so a folder lists in one
  request. A sealed (E2) namespace is read with keys; an e2e one isn't, and its items get no
  `file`. When `catalog.files` appears, every live item's head is read for it, and when it goes
  the metadata goes, both moving listings to the new checkpoint; a database from before this, or
  one a release that ignored `catalog.files` kept, is filled in on start (meta `filed`, purging
  the catalog's cached listings, `ns:{catalog}`). A head that can't be read for the moment (not
  gone, nor unreadable content) is read again: the catalog's change is applied again by its
  follower, and a start's fill-in is retried beside the followers until it succeeds.
- **Sealed items** (§E.2.6). For an item of a sealed namespace the entry carries
  `"file": { "sealed": "<JWE>" }` instead, the JWE of `{ "file": { … } }` under the item's own
  `K_r` (kid its namespace's current epoch, padded as that namespace pads), with `pl { ns, name,
  view }` naming the item and the listing's `at` URL, whatever the catalog's level: a reader
  given `K_r` by `/read-grants` opens it, and in a sealed catalog read whole, the catalog's JWE
  holds it still sealed, so the catalog's keys open no content-derived value. A listing holding
  one is stored and served unchanged, as a sealed catalog's listings are, keyed like kept ones
  by its URL and what the reader reads whole. While a sealed namespace's key can't be had for
  the moment, listings are `503`, `no-store`, with `Retry-After`, as when the catalog's own key
  can't, rather than kept at their `at` without it. Only sealed namespaces' keys are asked for.
  The service stores the metadata in the clear, as it does titles. This form, and its nesting
  inside a sealed catalog's JWE, are provisional: §E.2.6 defines a per-entry `"sealed"` member
  for values of one source and none yet for values another namespace's resource gives.

### WebDAV (prototype)

`patchlog dav` serves namespaces as a network drive, for file managers and editors, following
Addendum H (files): a file other than a JSON file is a raw document, its bytes a blob (§7.8), and a
JSON file is a document, read as its rendering. A namespace (`-ns`) is a flat directory of its
resources; a catalog (`-catalog`) is a file tree, whose files and folders are named by their
nodes' titles. It is an API consumer like the index and tree services: it reads and writes the
core only through its public API, and keeps nothing but memory caches.

```sh
# Local mode: one grant for every request; WebDAV clients log in with any user name and the password.
./patchlog dav -api http://localhost:8080 -ns docs,matches -catalog cat-season \
  -bearer-file editor.grant -password-file dav.password      # http://127.0.0.1:8090/

# Gateway mode: each request's Basic password is the user's own grant, sent upstream; the
# tree's folders listed by its tree service (§H.3).
./patchlog dav -api https://cms.example -ns docs -catalog cat-season -gateway \
  -tree-url http://tree:8082 -addr :8443 -tls-cert dav.crt -tls-key dav.key
```

- **Local mode** (the default) sends `-bearer` (or `-bearer-file`) with every request to the core,
  or `-author NAME` to a `-dev` one. WebDAV clients log in with HTTP Basic: any user name, and the
  password of `-password-file` or a random one logged at start, compared in constant time. It is
  meant for one person on their own machine: the default `-addr` is `127.0.0.1:8090`, and plain
  HTTP on any other address logs a warning. Every program and device that logs in is one user
  to the server (§H.7: one bearer for everyone): what it keeps per user below is shared between
  them.
- **Gateway mode** (`-gateway`) has no grant of its own: a request's Basic password is the grant,
  sent upstream as `Authorization: Bearer` (the user name is ignored), so the core decides what
  each user may read and write, and the revisions are the grant's subject's. Nothing is kept for
  a grant before the core has accepted it: `GET /ns/{ns}/principal` (§7.4) in a served namespace
  the grant names until one accepts it: first the one that accepted this token before (kept past
  the token, for the 256 tokens of each user verified last, 16384 in all, the verifying
  namespace keeping the most giving way, then its key (`kid`) keeping the most, so one user's
  logins with thousands of narrowings, or one key holder's for thousands of `sub`s or with
  thousands of keys added to its namespace, push out only their own), then those that accepted a grant of its root `kid` and
  `sub` (every served namespace that did, in the order they did, so later ones never push out the
  first), then at most three of the rest, sorted, so a namespace created or given the key later,
  or another namespace's key with the same `kid`, doesn't make the same person someone else. It checks only that the grant names the namespace and verifies, key scope and revocation included, the
  same in a public namespace (whose reads ignore a bad grant) as in a private one, so a grant
  limited to some resources, or without `read`, is accepted too (§H.7 "Limited grants"). Its
  `401` is no usable grant; a `410` there is a purged namespace, and a `404` one that doesn't
  exist (to an operator grant): accepted nowhere else, the grant is answered `410` or `404` (§H.4
  "Answers"). A grant an operator key signed (§C.4), which `/principal` verifies too and which
  authorizes nothing this server does, is `401`: its root `kid` names a key of the deployment's
  operator key history (`jwks_uri`, read without a grant and kept 5 minutes, read again once for
  every login asking meanwhile, and after a failed read not for 30 s) under which its signature
  verifies, so a namespace key that carries the same `kid` is never mistaken for it; unless the
  namespace lists that very key under that `kid` too, which makes it the namespace's grant, as
  the core serves it. While the key set can't be read (a `404` too, or a `200` whose body isn't a
  JWK Set, an object with a `keys` array: a proxy not routing `/.well-known`), the core is asked
  of each grant whether the namespace's own keys verify it.
  It is asked again every 5 minutes (`VerifyEvery`, at most 5 minutes, §H.7), or at the next
  request after the core answered it `401`, so a revoked grant, or one
  its key's scope no longer covers, is refused within that time. A refused token loses its
  access, and the user's other tokens are asked again at their next request; the user's state
  (below) stays, reached only through a token the core accepts, so a re-minted grant finds it. A
  grant the core doesn't accept is `401` with the Basic challenge, so clients ask again, and says
  nothing of what is served; it is refused for 30 s without asking the core again (a `410` or
  `404` too), and at most 8 grants are verified at once. Grants must not cross plain HTTP:
  it refuses to start on an address other than loopback without `-tls-cert` and `-tls-key`,
  unless `-insecure`, and warns when `-api` is plain HTTP to another host. Both modes take
  `-tls-cert` and `-tls-key`.
- What the server keeps is per user (§H.7) and never shared with another: in a gateway, a user is
  the root `sub` and `kid` `GET /ns/{ns}/principal` names for the grant, with the namespace whose
  key verified it (a kid names a key of one namespace's document, so the same kid in another
  served namespace is someone else's), never the token: every token of one person, minted again
  or attenuated offline, is the same user, whose own delete is theirs, not someone else's, and
  whose records and guards carry over (a token attenuated to leave out the namespace that
  verified the others is verified in another, and is another user; a token verified again as
  another user, the namespace that verified it refusing it now, whether kept meanwhile or not,
  has its saves without a base of every document its old user had records of refused until it
  reads that document itself: another token's read isn't its reload, and the new user's other
  tokens aren't refused). Temporary files, locks and dead properties, which may hold what one token read (a
  document's backup copy, an editor's swap file with its text), carry over between the tokens
  the issuer minted with the same rights (the root block's `ns`, `can`, `roles`, `rules`,
  `groups` and `attrs`, whatever its times, and whatever the order `ns`, `can`, `roles` and
  `groups` list them in), but a token minted limited to some resources
  (§C.5.1) or attenuated offline (a narrowing block with another `ns`, `can`, `rules` or a `via`:
  a delegate) has its own, and no token reaches the temporary files of a namespace its grant
  doesn't name (§H.6 "served only to that user"). It keeps temporary files and locks (a lock
  lasts at most an hour, `Infinite` too, its owner is at most 1 KiB, and a user holds at most
  256, then `507`) and dead properties (1 MiB a user, the least recently set going first), dropped
  with the user (in a gateway, after an hour idle, or to make room: at most 256 users,
  `MaxPrincipals`, and 8 tokens a user, `MaxTokensPerPrincipal`, so more tokens push out only that
  user's, which are verified again when they come back; never one with a request in flight). Of
  a user's sets of temporary files and locks, 8 are kept for tokens as issued, and 8 for tokens
  narrowed offline from each token their narrowing started from (a delegate's own narrowings
  stay within its 8, not those of the user's other narrowed tokens), from at most 8 such tokens:
  one that holds temporary files or locks is never dropped to make room, a new one is `503`
  then. The bounds on temporary files are the user's, over those sets, so a token
  that reads less can tell from its `507`s how much the user's other tokens keep (the size of a
  backup copy). And the versions of each
  document the user was served or wrote, the bases of their saves (below), with the tombstones
  and restores they wrote, kept for a day apart from the rest, within 128 MiB for all users,
  where the user keeping the most gives way first, so one user's uploads don't push out
  another's records (a write keeps the bytes it sent only where they read otherwise rendered,
  and not when much larger than the rendering, as white space padding would be). A restart
  loses all of it. What is read with
  a grant is kept per token, since another token of the same user may read less: the writer
  settings, namespace documents, catalog trees and tree-service listings below, the last two
  within `-cache-size` over every token, the least recently used going first. Rendered
  documents are cached by revision id for everyone, and handed to a token only after it read the
  head, or the listing, with its own grant.
- `-password-file` and `-bearer-file` readable by others than their owner log a warning.
- Behind a reverse proxy, the proxy must pass the client's `Host` on (nginx: `proxy_set_header Host
  $host`), or set `X-Forwarded-Host`: MOVE and COPY name their destination by the host the client
  used, and another host's is refused (`502`).

**Mounting.** macOS Finder: Go → Connect to Server (⌘K), `http://127.0.0.1:8090/` (`https://…`
for a gateway), as a registered user with any name and the password (the grant). Finder writes
only to servers with locks, which are served (in memory). Windows: File Explorer → This PC → Map
network drive, or `net use Z: https://dav.example/ /user:me PASSWORD`; its WebClient service sends
Basic credentials only over HTTPS by default (`BasicAuthLevel` 1), so serve with `-tls-cert` and
`-tls-key` (for `http://localhost`, `BasicAuthLevel` 2 in the registry allows it). GNOME Files:
Other Locations → Connect to Server, `dav://127.0.0.1:8090/` (`davs://` with TLS), or
`gio mount dav://127.0.0.1:8090/`. davfs2 mounts a local-mode server, but not a gateway with a
grant as its password ("Could not authenticate to server: rejected Basic challenge"; rclone logs
in with the same grant). rclone needs `--ignore-size`, and for copies `--ignore-times` too: see
**rclone** below.

**rclone.** A remote of vendor `other`:

```sh
rclone config create pl webdav url=http://127.0.0.1:8090/ vendor=other user=me \
  pass="$(cat dav.password)" --obscure

rclone copy --ignore-size --ignore-times ./docs pl:docs     # upload: every file, every time
rclone copy --ignore-times pl:docs ./docs                   # download: likewise
rclone mount pl: ~/pl --vfs-cache-mode writes --ignore-size \
  --dir-cache-time 1s --vfs-cache-max-age 5s --vfs-cache-poll-interval 5s   # a mount
```

- The server keeps no modification times rclone can set, and no hashes, so rclone tells files
  apart by size alone (`rclone backend features pl:` shows `"Precision": 3153600000000000000`,
  rclone's "not supported", and no `Hashes`). A raw file reads back as uploaded, but a JSON file
  reads as its document rendered, which is not always the size it was uploaded with: a save
  merged with others' edits reads back larger or smaller (to others, any upload not in its
  rendered form). So:
- **Copies and syncs to the server take `--ignore-size` and `--ignore-times` (`-I`).** Every
  file is sent on each run; one that is unchanged writes nothing (its diff is empty), a changed
  one is an edit rebased as any save is (below), so others' edits since are kept. With
  `--ignore-size` alone, rclone skips every file that already exists ("Sizes identical",
  "Unchanged skipping") and exits 0: edits are silently not sent. Without `--ignore-size`, rclone
  checks the size of each upload, and a save merged with others' edits fails ("corrupted on
  transfer: sizes differ") and is deleted ("Removing failed copy"): the document is tombstoned,
  or in a file tree the file deleted, and each of rclone's retries restores it and deletes it
  again; without `--ignore-times` too, an edit that keeps the size isn't sent.
- **Copies from the server take `--ignore-times`**, else a document someone changed without
  changing its size isn't fetched.
- **A refused save doesn't delete the document.** rclone answers every failed upload (a conflict,
  a file that isn't JSON, one too large, a `422` or `403`) by deleting the file a second later,
  and ignores that DELETE's answer. The server refuses it (`409`, the guard below), and each of
  rclone's retries (`--retries 3`, a mount's write-back) is refused again, its DELETE too: the
  document stays as it was for everyone, and rclone exits with the save's error. Deleting it on
  purpose right after takes one DELETE more per refused save, or none once 10 seconds have
  passed: `rclone deletefile` retries on its own. Nor does a refused upload bring back a document
  you deleted (`rm` in a mount, an `rclone sync` deletion): rclone's DELETE after it is done.
- **A mount takes `--vfs-cache-mode writes --ignore-size` and short cache times**
  (`--dir-cache-time 1s --vfs-cache-max-age 5s --vfs-cache-poll-interval 5s`). Without
  `--ignore-size` the upload of a save merged with others' edits fails on its size and the mount
  deletes the document, retrying the upload, restoring it and deleting it again. rclone tells a
  file's versions apart by size alone and, by default, keeps a directory listing for 5 minutes
  and a file it wrote in its cache for an hour: a file someone else changed then reads as the
  cached copy when its size didn't change, and is cut short at the old size when it grew (the
  kernel reads no further), so `sed -i` or an editor writes clipped JSON back (`400`, refused).
  With the short times another's edit shows within a few seconds. rclone's mount answers
  extended attribute calls with `EIO`, so `ls -l` and `sed -i` print "Input/output error" about
  them; the save is done all the same.
- **After a refused save through a mount** (a conflict, clipped JSON), the program saving sees
  no error with `--vfs-cache-mode writes`: the mount keeps showing its version, read from the
  cache, and rclone retries the upload in the background (after 10 s, 20 s, 40 s, … up to every 5
  minutes: "vfs cache: failed to upload try #N" in its log), refused each time. The way out is to
  write the server's version into the mounted file, `rclone cat pl:docs/x.json > ~/pl/docs/x.json`
  (the shell empties the mounted file before rclone reads, so the refused version isn't sent
  again): that upload writes nothing, and you edit again from there. A login refused a save must
  read the file itself (its conditional GET is answered in full) before its next save without a
  base is taken, and its retries ask no reload of anyone else's, so another program's read
  doesn't let the mount's retries through, but only one with another grant: a program logging in
  with the mount's own (local mode's one password, or a gateway user's grant given to both) is
  the same login, and its read (`rclone cat` to the terminal, a browser) is the reload the `409`
  asks for, after which the mount's next retry saves its old version over the other edit. With
  `--vfs-cache-mode off` the program saving gets
  an I/O error instead and nothing is retried: re-reading the file through the mount (once
  `--dir-cache-time` has passed) is the reload, and an edit of what it reads saves.
- **Without a cache (`--vfs-cache-mode off`)** a program writing a file in place uploads it
  with a PUT, but one saving through a temporary file renamed over it (`sed -i`, editors' safe
  saves) makes rclone DELETE the document, then MOVE the temporary file onto the name (its MOVE
  never overwrites): each such save writes a tombstone and then the restore with the edit, and
  one the server refuses (a file that isn't JSON, a conflict) restores the document as it was
  (below), with an I/O error for the program; the next save is done as usual. A temporary file
  with a scratch name stays in memory; in a file tree, or under a resource name in a flat
  directory, it is a file of its own, which that MOVE deletes once it has restored the original
  with its content, so the original keeps its history. sed's temporary names (`sedAb12Cd`) are
  scratch names (v0.73), so `sed -i` works in a flat directory too; with
  `--vfs-cache-mode writes` rclone renames a file it hasn't uploaded yet in its cache, and then
  uploads it with a PUT.
- `rclone sync` deletes what the source doesn't have: here, a tombstone per document (in a file
  tree, the placement and its item). In a file tree `moveto` renames and moves files and folders
  (below); in a flat directory it moves a file to another name in one batch, the old name's last
  revision naming the new one in `$successor` (§8.1, below), and `moveto` between a flat
  directory and a tree, or another namespace, copies the file and deletes it. rclone sends a
  MKCOL for the parent folder before each upload: `405`, as a folder that exists is, and not
  logged. `rclone mkdir` in a frozen catalog fails at once (`403`).

**Layout.**

```
/                                          a directory per -ns and -catalog
/docs/                                     a flat namespace (§H.2): its live resources
/docs/derby.json                           the JSON document /r/docs/derby
/docs/logo.png                             the raw document /r/docs/logo.png: a file
/cat-season/                               a file tree (§H.2): the children of its files.root
/cat-season/Season 2026/                   a folder node titled "Season 2026"
/cat-season/Season 2026/Derby report.md    a placement titled "Derby report.md": its item,
                                           such as the raw document /r/matches/k3j2…
```

- **Files** (§H.1). A raw document, whose root is a blob reference (`{ "$blob", "type", "size",
  "nonce"? }`, with at most `$schema`, a fresh `$nonce` and a `$successor` beside it, §7.8), is a
  file of the blob's bytes, kept exactly: text files (`.md`, `.txt`, source code) too. Any other
  document is a JSON file. A raw file's type comes from its name's extension, in any letter case,
  by §H.1's table (`md` `text/markdown`, `txt` `text/plain`, `png` `image/png`, `pdf`
  `application/pdf`, `json` `application/json`, …); else from the upload's `Content-Type`, its
  parameters dropped, unless it is `application/octet-stream`, `binary/octet-stream`,
  `application/x-www-form-urlencoded` or `multipart/*`; else the existing file's type (kept on a
  re-save, and on a restore after the user's own DELETE); else `application/octet-stream`. A
  `text/` type needs a UTF-8 body (a leading BOM allowed), otherwise the file is
  `application/octet-stream`, on saves, renames, moves onto a file and copies (§H.1, §3.7). A copy
  is typed as its source, keeping its blob only when the type comes out the same, and a temporary
  file moved onto a name as it was uploaded, unless the name's extension says otherwise.
- **A tree's content namespace is read-only flat** (§H.2, v0.73). A served file tree's
  `catalog.files.ns`, if also served flat (`-ns`), is read-only there: PUT, DELETE, MKCOL and
  LOCK in it, a MOVE into or out of it and a COPY into it are `403`, saying why; its files are
  still listed, read and copied out. Deployments that wrote to a tree's content namespace
  through the flat view write through the tree. A gateway's start reads catalogs without a
  grant, so until a user whose grant reads a served catalog's settings opens its tree, writes in
  every served flat namespace are `403` too (it fails closed).
- **PDFs** (stored type exactly `application/pdf`) are served on `200` and `206` without
  `Content-Security-Policy: sandbox`, still with `nosniff`, and as `Content-Disposition:
  attachment` unless `patchlog dav -inline-pdf` (§7.8, §H.6, v0.73); every other answer keeps
  the sandbox.
- **The flat view** (§H.2). A flat namespace's directory lists its live resources (the head rows
  of the `/heads` of its current `ns_id`): a raw document by its resource name, any other as
  `{name}.json`. Where a raw `x.json` and a JSON document `x` both exist, as an API client can
  make them, the raw file keeps the name and the document is shown, read and written as
  `x (2).json`. A name a live resource has is that file's whatever it looks like (a raw `4913`
  is a file, not vim's probe). A new file is made under its name, which must be a resource name
  (§3.6: lowercase letters, digits, `.`, `_` and `-`, starting with a letter or digit, at most 128
  characters), or for a JSON document `{name}.json`; any other name (`Notes.md`, a Save As
  `Report.json`, `my notes.txt`, `.notes.tmp`, a browser's `invoice (1).pdf`) is refused with
  `403`, saying so, since kept in memory only it would vanish, but for the scratch names below.
  A COPY to one of the names file managers give a copy made beside a live file (Finder's
  Duplicate `x copy.md`, `x copy 2.md` and Keep Both's `x 2.md`; Explorer's `x - Copy.md`, `Copy
  of x.md` and `x (1).md`; GNOME's `x (copy).md`, and the same of any extension) makes a scratch
  file, so a copy renamed to a file's name starts a file from a template; one not renamed
  vanishes with the other scratch files. A new file whose resource another kind of file has
  (`notes.md` beside a JSON document `notes.md`, shown as `notes.md.json`; a JSON `pic.json`
  beside a raw `pic`) is `409`. `x (2).json` keeps naming the JSON document `x` for a client that
  has it open once the raw `x.json` is gone (it is listed as `x.json` then), and is `409` once
  `x` is gone too.
- **Reading.** A raw file is served by this server itself, from its blob through the core and
  never as a redirect to the core's origin, streamed, with ranges (`206`), as its type. A JSON
  file reads as its rendering: the document's canonical text (§3.1), without a top-level `$nonce`
  of the fresh form and a `$successor` of §8.1's, laid out as `JSON.stringify(value, null, 2)`
  lays it out (members and elements on lines of their own, two spaces a level, `{}` and `[]` for
  empty ones, keys in JCS's order, those that look like array indices too), with one final LF:
  the same bytes for the same revision. Every file's ETag is its head revision id (`W/"{id}"`
  where a writer is served its own uploaded bytes rather than the rendering, on GET, HEAD and
  PROPFIND; the PUT's answer stays strong, and a weak tag works in any `If-Match`, a GET's
  included; §H.1, F-H2), and every
  answer, files, listings and error texts alike, carries `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: sandbox`, since this origin holds users' credentials; a `POST`, which
  x/net/webdav would answer as a `GET`, is `405`. A revision that holds exactly what a user wrote reads
  back to that user as they wrote it, so a client checking the size of its upload finds it.
- **Listings** (§H.3): each file's ETag is its row's `target`, its time the row's `created` (or,
  for rows without, the `Last-Modified` of the document's read; with neither, from an older core,
  when the user was first shown the revision, kept in memory only), a raw file's size and type its
  reference's, and a JSON file's size its rendering's (or that of what the user wrote and reads
  back). Both need the head document once per revision: its size and type are kept by revision
  id for good (256 Ki revisions), apart from the documents themselves (`-cache-size`), so a
  listing reads only the documents it hasn't seen.
- Each listing of a flat namespace reads its heads again; a catalog's tree, and its items' heads,
  are read again after 5 seconds, or at once after a write through this server (a tree service's
  listings likewise, below). Nothing is pushed.
- **Sealed and end-to-end namespaces** (Addendum E) need keys this server doesn't hold, so it
  doesn't offer them (§H.7): the root doesn't list them, anything asked of them is `404`, saying
  why, and a tree's placements of items in them aren't listed. A root listing asks `GET
  /ns/{ns}/principal` (§7.4 `writer.level`) of each served namespace the user's grant names, at
  most every 30 seconds per token, for this (and reads a catalog's document, for its file tree);
  one that refuses it is listed all the same, so a grant that reads only some namespaces mounts,
  and the others answer `403` when opened.

**Saving.**

- A written file is buffered whole (a raw file at most `-max-raw-size`, default 64 MiB, the
  core's default `blobSize`; a JSON file and a temporary file at most `-max-file-size`, default 16
  MiB; at most the larger of 8 times `-max-file-size` and twice `-max-raw-size` over every request
  at once, in a gateway a quarter of that, or one raw file, for one user's, else `503`) and
  committed once complete; a body cut short writes nothing, and a `PUT` with
  `Content-Range` (a partial write) is `400`, writing nothing (§H.4). Other request bodies
  (PROPFIND, PROPPATCH, LOCK) are at most 64 KiB (`413`), read whole before they are handled, and
  those over 4 KiB are handled four at a time over the server: x/net/webdav decodes them a value
  per element. A request has 10 minutes to arrive.
- **Which kind a file is** (§H.1). A new file whose name ends in `.json` and whose content is
  I-JSON (a UTF-8 byte order mark dropped) is a JSON document of the name before `.json`; any
  other new file is raw, a `.json` file that isn't I-JSON (comments, duplicate keys, integers
  beyond 2⁵³) included, as a raw file of its whole name. An existing file keeps its kind: a JSON
  file takes only I-JSON (`400` otherwise, nothing written), a raw file any bytes. One the user
  deleted moments ago and writes again (below) is restored as the file it was.
- **Raw files** have no paths to merge, so their base is checked, never merged from: the
  versions the user may have are the revision `If-Match` names, else every version this user was
  served whole or wrote (below), and if, after any of them, someone else changed the bytes (a log
  entry the user didn't write set a member of the reference, or the root) or deleted or restored
  the file, the save is a `409`, so an editor's buffer isn't saved over bytes a preview read; the
  user's own saves since are theirs to replace, so consecutive saves never conflict, whatever
  their sizes, nor does a stale `If-Match` after the user's own save. A version the user had,
  saved unchanged after someone else's bytes, is a `409` too (§H.1 Identity, §H.4): a raw save
  is stored with the uploaded bytes or refused. Then the bytes
  are uploaded as a blob (once however often the head moves meanwhile; `413` over the `blobSize`
  in force, before any upload) and the reference's members set one by one (`/$blob`, `/type`,
  `/size`, `/nonce`), never the root, so a `$schema` or `$successor` beside it stays. Bytes the
  head already holds write nothing, and answer the head's ETag. The revision holds exactly what
  was sent, so its ETag answers the PUT.
- A new name is created (`If-None-Match: *` upstream; a create the core refuses with `410 gone`,
  the name tombstoned meanwhile, as cores answer from v0.73, is written over the tombstone, a
  move restoring the name and a new file the tombstoned resource, while a `412` keeps meaning
  "made meanwhile"); a tombstoned one is restored, so a name
  keeps one chain (§8.2): moments after the user's own DELETE (below), with the edit rebased on
  its last live document; a save from a version from before someone else's delete is a `409`
  (deleted by someone else since you opened it), until a GET finding the file gone, the reload;
  any other write makes the file anew, its root replaced. A save over a name whose last revision
  has `$successor` (someone moved the file away) is a `409` naming the new path (a flat file name
  in the same namespace, else `/r/{ns}/{name}`), also on the first refusal and after the reload
  (§H.2, §H.4); a MOVE of a live file onto the name still makes it anew, so a rename back works.
  A raw file over a JSON document's, or the
  other way round, replaces its root. A purged one is `410`, as is any name of a purged
  namespace. A PUT's own `If-None-Match: *` (create only) is `412` over an existing file, and
  `If-Match: *` (edit only) over a missing one; an empty placeholder (below) exists for both. An
  `If-Match` (or `If` header) tag naming a revision where no file is (a name that never existed,
  a tree's name whose file was deleted or moved, a scratch name) is `412`, never a new file, but
  where it restores the user's own DELETE of moments ago (below).
- An existing JSON file gets the user's edit rebased on its head (§11.3, §H.4): the diff
  (`merge.Diff`) from the version the user edited, the base (as rendered: a `$successor` it
  leaves out stays), to what they wrote, applied to the current head and appended with `If-Match`
  on it. The base is one of the versions the user may have edited: the revision the PUT's
  `If-Match` names (its first value, `W/` dropped), or failing that its `If` header (the first
  entity tag, not negated with `Not`, of the first list that applies to the file: untagged, or
  tagged with its URL), with the user's own writes that revision holds merged; `If-Match: *` only
  asks that the file exist, and the head is the base. Without one, the base is among the versions
  this user was served whole (a GET's body, or a range that is the whole file; a `304`, a
  `HEAD`, a `PROPFIND` and a partial range record nothing) or wrote in the last day, at most 16
  a document (over that, the oldest but the first goes, and never the latest write: the version
  an editor opened stays while a preview reads others' revisions); a save that changed nothing
  is no write. Of those, it is the one closest to what was written (the fewest changed paths): an
  editor's buffer is what it opened or last saved plus the user's edit, while a preview pane's or
  a second window's GET moves on without it. Records are kept by document, and with them the
  document each path named when the user last read it whole or wrote it: a save without a tag at
  a path that names another document now (a tree's title given to a new item after the old one
  was deleted, a raw `x.json` taking the JSON document `x`'s name), or none, is a `409` asking for
  a reload, which a GET of the path is; the user's own DELETE or MOVE forgets the path. A file equal to an older version is a save of it
  unchanged, or, when the user wrote since and the file reverts just what that save changed, an
  undo of it. Edits others made since the base are kept: the patch set holds only the user's
  changes. Others' writes are what differs between the base and the head, and the writes of the
  log entries between them (§11.3), so a value someone changed and changed back counts; the
  user's own entries don't. Writes count whole arrays (an edit anywhere in an element is an edit
  of the array, from the outermost: elements have no identity, so an index one side names is
  another element after the other's insert or delete; §F.3's array rule). Where the user's writes
  overlap others' since the base and what the user wrote differs from the head there, the save is
  `409 Conflict`, naming the paths, and nothing is written. A change both made, or a value
  reloaded since, is no conflict. A delete or restore by someone else between the base and the
  head is a `409` too, never merged over.
- A patch set over `opsPerSet` or `patchSetSize` (§6.6: the limits in force, defaults applied, as
  `GET /ns/{ns}/principal` gives them; else the core's refusal tells) is sent as a root `replace`
  instead, which may be as large as
  `documentSize`, carrying the document's `$successor` and a fresh `$nonce` where nonces apply,
  when the base is the head (§H.4): it then overwrites no one's edit. A restore after the user's
  own DELETE (below) is written whole so when its base is the last live document. A save merged with others'
  edits is `413` instead, asking for a reload, after which the base is the head; it isn't sent
  where the gateway knows the limit.
- The base isn't guessed: a save may change the head only where every version the user may have
  edited agrees with the head (or holds what the user wrote there since), so whichever one their
  program had, no edit someone else made in between is undone or overwritten unseen. Where they
  can't be told apart, as the version an editor opened and a newer one a preview read, when the
  edit covers what changed in between, the save is a `409` too; so is one that another version,
  taken as the base, would apply otherwise as safely, naming where: an undo of the user's save
  combined with a new edit looks like a second program's edit from the version before that save,
  and taken as the latter the undo was dropped. A `409` asks for a reload: the
  user's next GET of the whole document sends it whatever its validators say (a cached copy may
  be what the editor had), and drops the versions recorded before the `409`, so the reloaded one
  is the base of the edit after it; a range read isn't that reload. A `409` to a login that
  must read the file itself first (refused a save of it, or verified as another user, since it
  last read it: a retry, whatever refuses it) asks for none again, so another program's next
  read keeps the version it has open. A version that can't be read
  again for a save (a `429`, a `5xx`) fails it (`503`, `502`) rather than leaving it without a
  base. One the core no longer has (pruned, §8.6), named by `If-Match` or recorded, or whose
  history since is pruned, can't be compared: `409`, asking for a reload. An `If-Match` naming
  no revision of the document is `412`. A head that moves meanwhile (`412`) is read again, the
  edit checked again and resent, up to five times.
- With nothing known of the base (a PUT without `If-Match` from a user never served the document,
  or after a restart), the head is the base, so the file as written wins, as the diff from it;
  over a tombstoned document, a file made anew (above). Records of a document untouched for a
  day expire and count as evicted (§H.4 Records; F-H3 default: per document), so a save without
  a tag is then a `409` until a reload; an idle user's records leave bounded marks past the
  sweep (256 users, 512 documents and 512 paths), and the user's own DELETE or MOVE of a path
  still forgets it, so a new file over the user's own delete is made anew.
  Versions the bounds pushed out are remembered as lost: then a save that changes the document is
  a `409`, rather than rebased on what is left, until the reload that `409` asks for; a read before
  it isn't that reload, since another program of the user's may still have the version pushed out
  open, and its save would be rebased on that read. So is a login pushed out of the 8 a
  document keeps as to read it themselves (refused a save of it, or verified as another user,
  since they last read it) by a ninth: the document is lost, and a reload already due when it
  was pushed out is due no longer, so another program's read doesn't let its save from before
  through. Within one user, two programs
  saving the same value, the last wins; two editing from one version, the second save is a `409`
  (above) until it reloads.
- A PUT answers with the revision as its ETag only when that revision holds exactly what was sent
  (§H.1: its rendering is the uploaded value, whatever the formatting, and whatever `$nonce` it was
  given); one merged with others' edits gets none (RFC 9110 §9.3.4), and the user's next GET or
  HEAD of it is answered in full whatever its validators say: a client may still file what it sent
  under the merged revision's tag, which a HEAD or a listing shows (davfs2 asks with a HEAD after
  such a PUT), and would keep showing it after a `304`. A client that reads the tag from a listing
  and never GETs again keeps its copy. A save that writes nothing (the file already reads so) is
  no write of the user's.
- A save that deletes the original before writing the new version (DELETE, then a PUT, a COPY or
  a MOVE onto the name, of a temporary file or of another file) restores it with the user's edit
  rebased on the last live document, as above, within 30 seconds of the DELETE (§H.6); a file
  moved away since (its last document has `$successor`) is made anew instead. A MOVE of another
  file deletes that file afterwards. If that write fails within 30 seconds of the DELETE,
  whatever refuses it (a `409` conflict, a `422`, a body that isn't JSON or is over
  `-max-file-size`, a frozen namespace, a precondition), the user's own DELETE is undone: the
  document is restored as it was (an empty patch set, if the user's tombstone is still its head),
  as a failed PUT leaves it, and the answer says so. In a file tree, a write to the path of a
  file the user deleted within 30 seconds restores it, its placement and then its item, and a
  refused one restores both as they were (§H.6). A document deleted longer ago stays deleted,
  and rclone's DELETE after its refused upload deletes a restored one again, unless a guard
  from an earlier refusal is still on it (above): the deletion stands.
- `$nonce` is the writer's to refresh: it is never part of an edit, and a fresh one is added where
  the namespace requires nonces (§C.7), as `GET /ns/{ns}/principal`'s writer block says, which a
  grant limited to some resources gets though it can't read the namespace document (§H.7), or
  where that is refused; with a `Blob-Nonce` on a raw file's blob. The writer settings (frozen,
  nonces, encryption level, limits) are kept per token for 30 seconds (it is `no-store`), and
  asked again after the core refuses a write over one of them (`409 frozen`, `422 nonce`, a
  limit). Where nonces are required, a JSON file's root must be an object, which carries the
  `$nonce`: an array or a scalar is `422`, saying why (§H.1).
- The core's refusals come back as such, with its code and message as the text (the status is
  the answer's own, §H.4 "Answers"): `422` with its validation errors (schema, rules, `nonce`,
  signature), one per line; `413` for a limit (the core's `413`, or its `422` with code `limit`:
  a patch set over `patchSetSize` or `opsPerSet` that couldn't be sent whole, a create's over
  `documentSize`, a document over `documentSize`, nesting), naming the limit, what the core
  measured and the limit in force, as in `too large: documentSize 1048577 > 1048576 (§6.6):
  document too large`; the gateway's own checks before sending (`blobSize`, a merged patch set
  over `opsPerSet` or `patchSetSize`, `-max-file-size`, `-max-raw-size`, the bytes read when the
  bound was passed) answer the same way; `403` for a frozen namespace (with
  its `successor`): frozen is for good, and clients retry a `423` as a lock that may go (rclone 30
  times, for 45 seconds); `410` for a purged file or namespace; `401` and `403` (but in local
  mode a `401` refuses the server's own grant, not the user's password, so it is `502` rather
  than a new login prompt). A `429` is waited out when its Retry-After is at most 2 s, and is
  otherwise `503` with Retry-After. A core that can't be reached is `502` (the details are
  logged). `423` and `507` mean only a lock held and this server's memory full.
- An empty file is a file (§H.1): a raw file of 0 bytes is made (`__init__.py`, `.gitkeep`), a raw
  file truncated, and a JSON file refuses it (`400`), as any content that isn't I-JSON. Only where
  the content decides the kind, a LOCK of a new name and a new `.json` name (Finder's 0-byte PUT
  before the content), is it an empty placeholder in memory until content arrives.
- DELETE tombstones (§8.1); with `If-Match` (or an `If` header's entity tag) naming another
  revision than the head, it is `412`. Without a tag it carries `If-Match` on the head it read,
  so a head moved meanwhile is a `409` (in a tree, the placement is restored) (§H.5). On a MOVE,
  `If-Match` (its first value, `W/` dropped) or the `If` header's tag for the source names the
  source, never the target's base: one that isn't the source's head is `412` before anything is
  written, `If-Match: *` asks that the source exist, and for a folder it names the folder node's
  head (F-H1 default). An `If-Match` that isn't an entity tag (unquoted) is `412` on a PUT,
  DELETE or MOVE, and nothing is done. A DELETE that passes destroys the user's locks on the path
  (RFC 4918 §9.6.1), and so does a MOVE on its source. A MOVE or COPY of a file the client holds
  locked, sent with that lock's token, is taken: its destination needs a token only if locked.
- **Guards** (§H.6). A refused PUT of a file, or a refused MOVE onto an existing file (answered
  `4xx` or `5xx`, having written nothing), sets a guard: the same user's DELETE of that path
  within 10 seconds is `409` ("wasn't deleted: this DELETE follows a refused save of the same
  file … delete it again to delete it"), once per refusal, and two refusals never share one:
  rclone deletes any file whose upload failed, a second later, which would tombstone the document
  for everyone (in a file tree, delete the file) because a save was refused. A guard ends only by
  time: a read of the file doesn't lift it (it may be another program's), nor another program's
  save, nor a DELETE that passed. A DELETE naming the revision it deletes (`If-Match`) is
  deliberate and passes, leaving the guards as they are; one that finds nothing uses one up (a
  refused create's cleanup). A refused plain MOVE (to a new name) or COPY sets none, nor does a
  write whose refusal put back the document the user had just deleted (below): the DELETE after
  that leaves it deleted, as the user chose. In a frozen namespace, which takes no DELETE either,
  the DELETE gets the core's `403` instead. A user keeps at most 4096 guards (the oldest go
  first), so many uploads refused at once each keep theirs. In local mode every program is the
  same user: another program's DELETE in those 10 seconds is refused too.
- **MOVE in the flat view** (§H.8). To a free name in the same namespace, one batch (§7.5)
  creates the new resource with the document (a fresh `$nonce` where nonces apply) and appends
  `$successor` naming it to the old one before its tombstone (§8.1), so the old name's `410` says
  where it went; a raw file's blob is copied with `Blob-From` (§7.8), or uploaded again where the
  new name's extension gives it another type. A tombstoned name is restored so, its root
  replaced (one the user deleted within 30 seconds keeps its history: below). To another
  namespace (or a tree) it is a copy, then a delete with `$successor` `/r/{ns}/{name}`. Onto an
  existing file (`Overwrite: T`, or none) it is a save of the source's content into it, its base
  taken as a PUT's, then a delete of the source: the target keeps its history, which is how
  "write a temporary file, rename it over" saves land (§H.5); `Overwrite: F` is `412`. A copy then
  delete deletes only the revision of the source it copied: one someone edited meanwhile stays as
  it is, and the MOVE is a `409` (the target holds the version moved). The source isn't deleted
  for a copy that wrote nothing. A copy then delete whose source the grant can't delete, as the
  core's `GET /ns/{ns}/principal` lists its verbs there (no `delete`, or no `append` for the
  `$successor` a move to another namespace sets), is `403` before anything is written; what only
  the grant's rules decide is known at the delete, which leaves the copy. A JSON
  file keeps a `{name}.json` name and a raw file a raw one, and a JSON file whose root isn't an
  object can't carry `$successor`: those MOVEs are `403` (copy, then delete). COPY to a new name
  creates it from the content (a raw file's bytes read through this server), and COPY over a
  file edits it, as its kind takes it. MKCOL of a folder that exists is `405` (not logged), and
  below a file `409`.

**Temporary and backup files** (§H.6). Editors' and systems' own files, `.DS_Store`, `._*`,
`Thumbs.db`, `~$*`, `*.swp`, `*.swo`, `*.swx`, `4913`, `*~`, `#*#`, `*___jb_tmp___`,
`.goutputstream-*`, LibreOffice's `.~lock.*#` and sed's `sed` followed by six ASCII letters or
digits,
JetBrains' `*___jb_old___` beside its `*___jb_tmp___`, and macOS's `Icon\r` (a folder's custom
icon, a name no title can be), are scratch files, unless a live resource has the name: kept in memory per user and directory (at most 256 files and folders and 32 MiB a
user, 256 MiB in all, then `507`; in a gateway, only in the served namespaces the user's
grant names, else `403`), listed beside the files so editors see what they wrote, and dropped
after an hour untouched, or when the server stops. They never reach the core. In a file tree a
node's name is the node's whatever it looks like, and every other name a title can be is a file.
In a flat directory, other temporary names are files of their own when they are resource names
(`notes.md.tmp`), and refused when not (`.notes.md.tmp`): such a save fails there. Over the bounds,
`._*`, `.DS_Store` and `Thumbs.db` make room for others, least recently used first, or are
dropped rather than refused, so copying many files in doesn't fail on them (Finder reads a `507`
as a full disk).

- A MOVE of a scratch file onto a file's name, the atomic save of gedit, VS Code and most editors,
  commits its content exactly as a PUT would (an edit, a create or a restore), then drops it.
- A MOVE of a file to a scratch name, an editor moving the original aside as a backup before
  writing the new version, copies it (a raw file's bytes, within `-max-file-size`): the file
  stays, and the write that follows is an edit of it (§H.5), its base taken as any save's; once,
  within 30 seconds of the MOVE, even one that creates only (davfs2's `If-None-Match: *`, as it
  takes the name for free after the MOVE, and uploads 10 seconds after the file is closed).
- MKCOL of an app's or a system's folder, anywhere (macOS's `(A Document Being Saved By
  TextEdit)`, `.TemporaryItems`, `.Trashes`, `.Trash`, `.Trash-{uid}`, `.Spotlight-V100`,
  `.fseventsd`, `.DocumentRevisions-V100`), makes a scratch directory, where every name is a
  scratch file. Any other folder, a dot one too (`.github`, `.obsidian`), is a person's: a folder
  node in a file tree, and `403` outside one (§H.8), as is a MOVE giving a scratch directory a
  person's name there: a person's folder in a flat namespace or at the root would keep what is
  saved in it in memory only. Its files go with it, after an hour untouched or when it is
  deleted. In a tree, moving one to a person's name makes a folder of that name.
- At the root only scratch names and app folders can be: no file there reaches the core, so any
  other (a `report.pdf` dropped on the mount's top folder) is `403`.

**File trees** (§H.2). `-catalog` serves catalogs whose namespace document's `catalog` object
carries `files: { "ns", "root", "folder"?, "placement"? }`. One without isn't a file tree, and
isn't served: it is refused at start (`dav: -catalog plain: its namespace document has no
catalog.files …`), read with the server's grant in local mode and without one in a gateway; one
only a user's grant reads answers `404`, saying why, when opened, and the root doesn't list it.
The tree's top level is the children of folder node `files.root`. It is built from the catalog
namespace's documents, read from the core with the user's grant (`tree.BuildGraph`), again after
5 seconds or at once after a write through this server; with `-tree-url` its folders are listed
by the tree service instead (below), and writes still read the documents. `catalog.mode: "tree"`
is assumed: a node with several parents shows under each, and a DELETE takes it out of that one
only.

- **Names.** A folder is a folder node and a file a placement `{ns}.{item}`, whose content is its
  item, read and saved as in the flat view (a raw file typed by its name's extension). Each is
  named by its node's `title`; a placement without one by its item's name, a folder by its node
  name. Titles are Unicode in NFC (a name sent in NFD, as macOS may, is stored in NFC), 1 to 255
  bytes of UTF-8, not `.` or `..`, without `/`, `\`, NUL, characters of `Cc`, `Zl` and `Zp`,
  or the bidirectional controls U+202A–U+202E and U+2066–U+2069 (other `Cf` characters, such as
  joiners, soft hyphens and LRM/RLM, are allowed and shown unescaped, v0.73; the seeded `drive`
  catalog's title rule follows), and, for Windows clients, without a trailing space or dot:
  other names are `403`, saying
  why. A title another tool wrote that breaks these rules is shown escaped (`a/b` as `a%2Fb`, `..`
  as `%2E%2E`, a trailing dot as `%2E`), never passed into a listing as it is. Names hold
  capitals, spaces and any script, and a copy's name (`x copy.md`) or a new folder's (`untitled
  folder`) is a name like any other, renamed by a title change.
- **Siblings** share one set of names, compared after NFC and Unicode simple case folding, a
  character for a character (with `-case-sensitive`, after NFC only), as the file systems of
  Finder's and Explorer's users compare them (so `Maße.txt` and `Masse.txt` are two names): a
  read of a name a sibling has under another case reads that sibling, but a PUT, COPY or MOVE
  onto it is `409`, naming the sibling, so a client telling case apart (rclone, davfs2 on Linux)
  copying `README.md` and `readme.md` doesn't write one over the other, and the guard (above)
  refuses its cleanup DELETE; a write to the spelling the user read the sibling under, or naming
  its revision, is the sibling's. MKCOL of a folder's name under another case is `405`.
  Duplicates a race leaves, or another tool makes, are shown as `name (2).ext`, `name (3).ext`, …
  in order of their nodes' creation in the catalog's log, the first keeping its name, skipping
  numbers whose names a sibling has, and after titles shown as they are where a title is shown
  escaped (an escaped `a/b` never takes a real `a%2Fb`'s name); a folder's number goes at its
  name's end, and a numbered name stays within 255 bytes, its stem cut short.
- **Listings** show folders, and files whose items are live, offered (not sealed or end-to-end)
  and readable with the user's grant: dangling placements, cyclic nodes and items hidden from the
  user aren't shown. A folder's listing reads the heads of its own items (a path's folders above
  only where a name is ambiguous), and the document of each revision once, for its size and type;
  through a tree service, none of them (below).
- **Through a tree service** (§H.3, §H.7). With `-tree-url URL`, the base URL of a `patchlog tree`
  following the served catalogs (`CATALOG=URL` for a catalog's own, repeatable, as `serve -tree-url`
  takes them; `TreeService` and `TreeServices` in `dav.Options`), a folder is listed from the tree
  service's `children` listing, read with the request's grant passed through as its bearer (in local
  mode `-bearer`'s), which the tree service checks and filters the listing by (§B.11.5): every page
  of it, at most 10 pages of 1000 entries, and a folder larger is `403`, never listed cut short;
  its files are opened, written, moved and deleted by name all the same, found in the node
  documents with only the items of the name asked for read. A
  file's ETag is its entry's `head`, and its size, type and time the `file` metadata the tree
  service adds (§H.3), so a folder lists in one request and no item is read for it; a placement
  whose `file` is sealed (an item of a sealed namespace) isn't listed, and one without `file`, or
  without its `modified`, is read from the core as above (an end-to-end namespace's item isn't
  listed). Names are given as above, the same duplicates, escapes and case folding, and a path
  resolves to what its folder lists, every folder on it listed. A write (PUT, DELETE, MOVE, COPY,
  MKCOL) checks what the listing named against the node documents, read again if read before the
  request: a name another user renamed or moved a moment ago, or a name a file was just given,
  which the listing doesn't show yet (it doesn't wait for other users' writes), is resolved from
  the node documents instead, as without a tree service, so a DELETE or MOVE of a renamed file's
  old name is refused and touches nothing, and a PUT of a name a sibling has now is that
  sibling's, never a second file by its name. A placement is deleted, a node renamed or moved, a
  folder deleted or a file in several folders unlinked from one, only as its document was read
  and still named as the path named it: changed since by another program, it is a `409` or
  `404`.
  Placements of a namespace the
  catalog doesn't trust are dangling (§B.5, §H.2): the tree service doesn't list them, and nor
  does this server from the node documents, with or without a tree service, and a folder's DELETE
  deletes them first as dangling placements (§H.5). Implicit placements
  (§B.9, `-self-placing`), which no node holds, aren't listed. A catalog whose `catalog.title` is
  set is listed from its node documents, since the tree service gives placements without a title
  their items' titles (§B.5) and a file is shown by its item's name (§H.2). Listings are kept per
  token for 5 seconds, or until a write through this server. A grant limited to some resources,
  which reads neither the catalog's namespace document nor its `/heads` (§2.1, §7.4), lists through
  the tree service with the tree's settings (`catalog.files`, `catalog.trust`) as last read with any
  grant, this server's own at start included; until some grant read them, the tree answers `404`.
  A tree service without `-access` (§B.11) serves only `g/all` listings, so there such a grant
  gets the tree service's `403`, relayed (v0.73, F-T6).
  Such a grant edits the files it lists and reads; a new file or folder, a move or a delete, which
  the node documents decide, is `403`, saying so, a move before anything is written (onto another
  file, or to another tree or namespace, the copy is the first write). The tree service unreachable is
  `502`, and its `503` (behind the catalog, a sealed namespace's key) a `503` with its
  `Retry-After`: never an empty folder. Its `401` and `403` are the user's grant refused, answered
  as the core's are (in local mode a `401` refuses `-bearer`: `502`, naming the tree service). A
  tree service answers `503` behind until it has caught up with every namespace the catalog
  trusts and can follow, not only with the catalog (started with a fresh database, rebuilt, or
  trusting one lately), rather than list every folder empty or part filled; the gateway answers
  that `503` too.
- **Read-your-writes** through a tree service, which lags the core. After a user's write through
  this server (a new file or folder, a rename, a move, a delete, an edit, wherever it is made, with
  any of their tokens), that user's listings of a tree carry `?min={ns}:{ns_id}` for each namespace
  entry the write produced in the catalog or a namespace it trusts (the write's
  `X-Namespace-Revision`, seen as the core answers it), which the tree service waits for (§B.5),
  until a listing that carried them came back, for at most 10 minutes (at most the last 4 entries
  of 64 namespaces a user); other users' listings don't wait. If it hasn't caught up within
  `-tree-wait` (3 s; the tree service's own `-min-wait`, 2 s, answers sooner), the folder is
  listed from the node documents instead, as without a tree service, and so are the user's
  listings of that tree for 5 seconds, however long the tree service lags within those 10
  minutes: their new file stays listed, and a file they renamed doesn't come back by its old name;
  a grant that can't read the node documents gets `503` with `Retry-After` for 30 s after the
  write, then the tree service's listing without waiting. A `min` the tree service refuses
  (`400`: a namespace it doesn't follow, or the reader can't see) is found per namespace, each
  one's asked for alone: those refused, and those reached, aren't asked for again, the rest
  are, and that listing is from the node documents.
- **New files** (§H.4). A PUT of a new name creates an item in `files.ns` with an opaque name (13
  random base32 characters), and its placement titled with the name, under its folder: one
  `parents` entry, ordered after the folder's last ordered child, so new files list last, and
  `$schema` from `files.placement` where given. The catalog must trust `files.ns` (`403`
  otherwise). A dry run of the placement (§7.5) comes first, so one the core refuses (a frozen
  catalog, a grant that doesn't write it, the catalog's rules) writes nothing; then the item is
  created (`If-None-Match: *`; a raw file's blob uploaded first), then placed, and an item whose
  placement is refused still, the catalog having changed in between, is deleted again at once (a
  `429` waited out as a write's is).
  Its kind is §H.1's: a name ending in `.json` with I-JSON content makes a JSON document, any
  other a raw one. MKCOL makes a folder node so (an opaque name, `title`, `parents`, `order`,
  `$schema` from `files.folder`). Where the catalog requires nonces, each write to it carries a
  fresh `$nonce` (§H.7), as file writes do where `files.ns` requires them.
- **Rename and move** (§H.5). A MOVE within the tree is one append to the node, with `If-Match`
  on its head: a new name replaces its `title`, a new folder its `parents` entry (ordered after
  the last child there), both in one patch set. The item isn't touched, so its history, ETag and
  links stay. A rename to another case of the name is taken whatever `Overwrite` says. A folder
  moves with what is in it, but not into itself or a folder in it (`403`), and not over another
  folder or onto a file (`403`, `412` with `Overwrite: F`). A folder MOVE to another file tree
  makes the folder there, titled with the Destination's last segment, and moves its visible
  children one by one, files as moves across trees (below), and deletes the source folder once
  empty; a part-way failure leaves what was done and is answered as that child's (§H.5,
  v0.73).
- **Onto an existing file** a MOVE saves the source's content into it, its base taken as a PUT's,
  so it keeps its history, then deletes the source: "write a temporary file, rename it over"
  saves land so (the temporary name, unless a scratch name, is a file of the tree meanwhile).
- **Across trees and namespaces** (to another tree, to or from a flat directory) a MOVE copies the
  file, then deletes the source; where its item is deleted, its last revision first takes
  `$successor` naming the copy (§8.1: a bare name in the same namespace, else `/r/{ns}/{name}`),
  in one batch with the tombstone, unless its root isn't an object (a JSON array moves without).
  A MOVE onto a file or across whose source's placement the grant's verbs in the catalog don't
  let it delete (`delete`, or `append` to unlink a file in several folders) is `403` before
  anything is written, as is one by a grant that doesn't read the node documents; what only the
  grant's rules decide is known at the delete, which leaves the copy.
- **Copy** makes a new item with the source's content, and a placement for it: a raw file's blob
  keeps its id and is copied with `Blob-From` (§7.8), or uploaded again where the core refuses
  that (a source of a higher rank, such as a private namespace's, into a public one). A COPY
  or MOVE of a file onto an existing folder is `403` (`412` with `Overwrite: F`; it was `405`).
  Folders are copied (§H.5, v0.73): a new folder titled with the Destination's last segment,
  without the source's `$access`, then its visible children one by one (`Depth: 0` copies the
  folder alone), an app's scratch folder in it as a scratch folder; a part-way failure leaves
  what was done and is answered as that child's, and onto an existing folder or a file it is
  `403` (`412` with `Overwrite: F`). Until §B.12 is settled a folder that carries `$access`, or
  sits under one, is not copied or moved to another tree (`403`, the F-H12 default).
- **Delete a file**: its placement, then, where its item is in `files.ns` (the tree owns it) and
  the user's grant allows `delete` there, its item; else the item stays, unplaced, as a failure
  between the two leaves it. A `DELETE` whose `If-Match` isn't the item's head is `412`, deleting
  nothing, as is one whose item changes between that check and its delete: the placement is
  restored.
- **Delete a folder**: only one without visible children (`409`, naming them, and nothing hidden
  from the user), as the node documents, read for it, have them, never a tree service's listing,
  which lags (a file someone put in it a moment ago); placements whose items are gone (dangling,
  §B.3) aren't contents, and are deleted first, or orphaned where the grant can't delete them
  (`401`/`403`), which doesn't fail the folder's DELETE (§H.5); the user's scratch files in it go
  with it. Deletes
  never recurse, and the tree's top isn't deleted (`403`).
- Writes through a placement go only to items in a namespace the catalog trusts (`catalog.trust`,
  §B.3) or that is served with `-ns`, never to a catalog's own nodes (`403`): a local mode's grant
  may reach namespaces the server wasn't set up to serve.

**Not in the prototype.** Without a tree service, the catalog's trust list beyond bounding writes
and access by subject set (`$access`, §B.11): users see what their grant reads, as the core lists
it. Writes in a tree through the tree service alone: they read the node documents, which a grant
limited to some resources can't. Grants issued by the catalog (§B.11.4): each user's grant is
passed through, so a new file is created before it is placed, never placed first. Merges of
text: raw files conflict as a whole (§H.9). Blob references deeper in a JSON document read and
edit as JSON. Sealed (E.2) and end-to-end (E.3) namespaces, which need keys. History (revisions
and logs as directories), live invalidation, and batches: each file is its own write, so saving
several isn't atomic. Users limited to some resources (rules on `/resource`, §C.5) can't list a
flat namespace, whose `/heads` needs unrestricted read, but can open and write its files by
path, learning the writer settings from `GET /ns/{ns}/principal` (§H.7); a tree's folders they
list through a tree service (above).
PROPFIND with `Depth: infinity` is `403` (`propfind-finite-depth`), and one without Depth lists
one level. Dead properties (PROPPATCH) are kept per user in memory (§H.8), at most 1 MiB a user,
read back by PROPFIND, moved with a MOVE, dropped with a DELETE, an hour untouched or a restart.
Uploads are buffered in memory, not spooled to disk.

### Bundles (§G.4)

```sh
patchlog export -ns matches -mode history -o matches.jsonl  # with schemas and x-ref targets
patchlog bundle verify -i matches.jsonl                      # recompute every id
patchlog import -ns matches -i matches.jsonl -dry-run -atomic
patchlog import -ns matches -i matches.jsonl -pace 0.5       # backfill: split and paced
patchlog import -i all.jsonl -only demo-schemas -pace 1       # part of a bundle: the rest later
patchlog import -i all.jsonl -atomic -ns demo-schemas=demo2-schemas,demo=demo2   # clone under new names
```

- **History bundles** keep ids, so importing one reproduces the source's ids exactly, but for
  documents a renamed import rewrites (Renaming, below).
- **Lines are canonical** (§G.4.1, §I.9): a reader rejects a blank line, a line that isn't byte
  for byte its canonical JSON, or a last line without its 0x0A, and the digest is over the bytes
  as written, so a hand-edited or pretty-printed bundle doesn't import.
- **Authors** (`-authors`, `"authors": true`) adds each history line's author, creation time,
  signature, and its `gesture` and `undoes` (§G.4.1). Imports write the gestures with the
  revisions (batch step objects, §7.5), so undo history survives the move; authors and times
  stay the importer's, as for any batch. Without authors a line carrying them is refused.
- **Signatures** (§C.3.1): with authors, a bundle carries one grant line per grant its history
  references, with the key it verified against at the source; history lines name their grant
  in a `grant` member; a grant line's `stored` is one string, the authority SignedBlock, as
  `/grants/{gid}` serves it (older bundles' arrays are read as their first element, but earlier
  versions can't read new bundles that include authors). `patchlog bundle verify -signatures` reports each revision as verified,
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
  documents are rewritten to them, keeping any `#id` fragment. A deleted resource's snapshot
  line carries no document, and an upstream import appends only a tombstone, so a moved
  resource's `$successor` (§8.1) travels in history bundles, where it is content like any
  other, and not in snapshots.
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
  namespace's gate until the allowance's bucket, as answered requests left it, admits it and
  the requests in flight in whatever order the server handles them. A namespace has no more
  batches in flight than the allowance's burst holds the draws of, nor, where the allowance
  ends, than its rate draws in half the minute before `until`. The first failure stops the
  rest. Without an allowance, batches go one at a time.
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
- **Part of a bundle.** `-only ns,…` imports only those source namespaces (`-ns` still maps
  names). The others' documents are left out as `external` dependencies are (§G.4.1): before
  writing anything the import checks that the target has what its documents reference in
  them, as the bundle has it, by id for a full document's pinned revisions and by name for a
  live reference, and that the upstream namespace of a left-out snapshot document their
  declared references pin holds that snapshot, which those pins are rewritten to. So a bundle can be imported a few
  namespaces at a time, by one process or several at once, those the others reference first,
  and the target ends as one whole import leaves it; only the namespaces imported (and their
  upstream namespaces) are created.
- **Renaming** (§G.4.4). `-ns src=dst` maps source namespaces to new names together, to clone
  a set of them, on another deployment or the same one. Every reference to a renamed namespace
  is rewritten where it is declared, in every document the import brings: `$schema`, `$ref`
  (keeping its `#fragment`), and pinned and live `x-ref` values, as the source's schemas
  declare them; pins of revisions that get new ids take them. A full-history document whose
  steps change is new content: its steps are rewritten one by one and written with new ids,
  never fast-forwarded, its signatures left behind, and its batches' `source.ids` record the
  source ids; a test op tests for the rewritten value, and a reference whose position a later
  schema declares is rewritten by a `replace` op added to that step. In a sealed target, or one
  that requires nonces, rewritten steps get a fresh `$nonce`. A document whose steps change
  nothing keeps its ids, since ids don't include the namespace. Documents of the bundle's
  unmapped namespaces that reference a renamed one are rewritten too, in their own namespace.
  Snapshot documents are rewritten as well, and go through `{dst}-upstream`, a name that must fit
  the 64 characters of §3.6: one that doesn't is refused before anything is written, as is any
  upstream name the import uses that isn't valid. The new ids are computed before anything is
  written, and a batch goes once those of the revisions it pins have committed, checking the
  ids it produced, so dependents are written with the ids their dependencies returned. A
  re-run of the same bundle computes the same ids and writes nothing; where nonces make them
  differ, it finds what the earlier run wrote from its batches' `source.ids`, in the clone's
  chain even if the clone was edited since, and goes on from there, also where a run that
  stopped part-way left off. Strings of the reference form where nothing declares a reference
  can't be found: the dry run and the report list them, and they stay (`rewrittenFrom` names
  the revision whose schema later declares the position, from which the import rewrites it).
  Refused before anything is written: an incremental document (`requires`) that would change,
  read from its base in the target (one that only holds undeclared references keeps its ids
  and imports as without renaming); a pin whose new id the import can't know (an `external`
  pinned into a renamed namespace, a schema's path included, a document `-only` leaves out
  that may change, a snapshot's revision); and a schema whose `$id` names its own revision
  path. A single plain `-ns NAME` that isn't in the bundle is a mapping too, and renames
  unless `NAME` is a branch of the bundle's namespace. Catalog placement names (`<ns>.<name>`) aren't
  renamed, and namespace configuration isn't in the bundle (§G.7): create the renamed targets
  with their roles, rules and keys first. A mapping onto a branch whose base chain reaches the
  source namespace (importing into a branch first) renames nothing: references and ids stay.
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
  JWE per bundle line with `pl: {bundle, line}`, the final one's `pl` carrying `last: true`
  (§G.5.1.1; bundles from earlier versions, with `last` beside `pl`, still read, but earlier
  readers reject new ones). Reordered, spliced, truncated or extended bundles are rejected;
  `source.bundle` is the plaintext bundle's digest. `patchlog export -pad` (with `-recipient`)
  pads each line to its §E.2.2 bucket, and readers strip trailing spaces before the checks.
- **Import** refuses a target less protected than its source (private or sealed into a public
  one) unless `-allow-less-protected`, a sealed target with `read: "public"` ranking public
  (§2.1), so the importer reads a sealed target's document with its keys before planning; it
  creates missing targets as protected as their source (sealed ones sealed, with a fresh
  `$nonce` in the patch sets the importer makes). A snapshot import creates the upstream
  namespace with its target's `nonce` setting (§C.7), and where it or its target requires
  nonces its generated patch sets carry a fresh one too; upstream diffs ignore `$nonce`. An
  existing `{ns}-upstream` takes imports from one origin only: a bundle from another is refused
  at step 1 (import that namespace renamed instead). A renamed import rewrites a `$successor`
  naming a mapped namespace (`/r/{src}/…`). A full-history import
  whose revisions lack nonces into a target that requires them is refused before anything is
  written: import a snapshot instead.
- **E3:** full history carries the ciphertext and the `keyring` verbatim; ids verify over it. It
  imports only into an e2e namespace of the same name (sealed patch sets bind `pl.ns`), which a
  missing target is created as. Every line but the keyring's must be one sealed op whose `kid`
  and `pl.ns` name the namespace, or a restore's `[]` after a tombstone, and an existing
  target's keyring must share the bundle's history, else the import is refused at step 1. Lines
  go in batches per epoch, in epoch order, each epoch's raise of `encryption.epoch` in the batch
  with the keyring line that brings its key (so atomic mode is atomic per epoch); an existing
  target is refused only below the bundle's lowest epoch, or past the epoch of a sealed line it
  lacks, and moving it up needs `config` with a `*` key (§G.5.1). Diverged e2e documents can only
  be skipped: comparing or rewriting them needs a client with the keys (§F.8). A bundle whose
  keyring history holds a revision in the format before v0.63, or a keyring line that isn't a
  keyring document, is refused at step 1, before anything is written, with the reason
  (§G.5.1, §E.3.2, v0.73): such history can't be imported at all, since migrating the keyring at
  the source leaves its earlier revisions as they were, so e2e backups of a namespace whose
  keyring was ever stored before v0.63 can't be restored by bundle import; only a client holding
  the keys can carry the content over, sealed again with new ids. An import's incoming writes
  count the `from` of each `copy` when looking for conflicts, as a merge does for a branch.

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
  become `x-*` annotations, which don't change validation. Each kind of change is reported. A
  `format` draft 2020-12 doesn't define (draft-07's `color`, …) isn't renamed: the server refuses
  it in schemas written since v0.73 (§6.2 step 5), so such an import fails with "not a schema the
  server accepts".
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
A='X-Author: me'   # dev mode: every write names its author (§7.2), else 400

# Create a namespace (its document is the genesis patch set).
curl -X PATCH $B/ns/matches -H "$P" -H "$A" -H 'If-None-Match: *' \
  -d '[{"op":"add","path":"","value":{"read":"public"}}]'

# Create a resource, then append to it with the id from ETag.
curl -i -X PATCH $B/r/matches/derby -H "$P" -H "$A" -H 'If-None-Match: *' \
  -d '[{"op":"add","path":"","value":{"score":"0-0"}}]'
curl -i -X PATCH $B/r/matches/derby -H "$P" -H "$A" -H 'If-Match: "1…"' \
  -d '[{"op":"replace","path":"/score","value":"1-0"}]'

curl -i $B/r/matches/derby                  # 302 to /r/matches/derby/rev/{head}
curl -L $B/r/matches/derby                  # the document
curl -sIL $B/r/matches/derby                # its ETag, Last-Modified and Repr-Digest
curl -L "$B/ns/matches/log"                 # the namespace log
```

### Files and sync clients (§7.1, §7.4, §7.8, §8.1)

Spec v0.54 serves file-style and sync clients, such as a WebDAV gateway, mounted file systems
and editors, which compare their copies with what a deployment holds without fetching
documents, keep files as blobs, move them and overwrite them whole (§11.3). Every field and
header below is optional to a client: responses cached before an upgrade, or served by an
older instance during one, lack them (see [Postgres](#postgres-d8)'s upgrade notes). Spec
v0.55's Addendum H builds on them: how such tools store files, folders and names so they can
share a namespace, with file metadata in tree listings (see [File trees](#file-trees-h2-h3)),
and `GET /ns/{ns}/principal`, from which a writer limited to some resources learns what the
namespace document asks of it (see [Design notes](#design-notes)).

- **`Last-Modified`** on every `200` of `GET` and `HEAD /r/{ns}/{name}/rev/{id}`, in a namespace
  that is neither sealed nor e2e, judged by the namespace serving the read (a sealed branch
  sends none for what it reads through from a plain base): the revision's `created` as an
  HTTP-date, to the second. A revision is immutable, so it never changes, except that it is
  never later than the serving instance's clock (RFC 9110 §8.8.2.1): created times come from
  the writing instance's clock, or a remote base's entries. `If-Modified-Since` no earlier than
  it is a `304`, and `If-None-Match` with the id one too, which decides when both are sent (RFC
  9110 §13.2.2). Sealed and e2e reads, the e2e keyring's and prune snapshots included, carry
  none: sealed logs hide `created` (§E.2.2). There `If-Modified-Since` is ignored, as RFC 9110
  §13.1.3 says for a representation without a modification date, so `304`s can't be probed for
  the time it hides; `If-None-Match` still answers `304`. Browsers may read it (it is
  CORS-safelisted, and CORS allows `If-Modified-Since`).
- **`Repr-Digest: sha-256=:<base64>:`** (RFC 9530) on the same `200`s: the sha-256 of the bytes
  served, the canonical document, which the server serves without content coding. Never in
  sealed or e2e namespaces, whose JWEs it would describe, and whose plaintext digest, and an
  exact length, padding exists to hide; nor for the e2e keyring, though it is served in the
  clear. CORS exposes it. `304`s carry neither header: the `ETag` already names the revision.
- **`/ns/{ns}/rev/{ns_id}/heads` entries** (`{ resource, kind, target, created?, size?,
  digest? }`, a page answered as `{ "heads": [...], "next"? }` since v0.73, where it was
  `{ items, next? }`, which the client and playground still read from older servers) carry, in
  a namespace that is neither sealed nor e2e, judged by the namespace
  serving the page, `created`, the target's created time in the form log entries use, for
  heads and tombstones (not purges: a remote branch's mirror of a resource purged at its base
  doesn't know it); and for live heads `size` and `digest`, the byte length and `sha-256=:…:`
  of the canonical document, exactly what `GET …/rev/{target}` serves and its `Repr-Digest`
  says (for a raw document, the reference's length, not the file's, which the reference's own
  `size` gives). At E2 and E3 all three are absent, on every page, those at `ns_id`s from
  before a raise to sealed included. A branch lists its base's values for what it reads through
  (the same document), a remote branch its base's (§G.3). A head pruned since keeps them, as it
  keeps its target (`/rev/{target}` is then `410`); a purge lists a purge, with none. The Go
  client has them as `HeadItem.Created`, `Size` and `Digest`, a document's headers as
  `Doc.Modified` and `Doc.Digest`, and `client.ReprDigest(b)` computes the form to compare a copy
  with.
- **Purges.** A config write that raises a namespace to sealed purges `ns:{ns}` with the write
  (§9), whatever its `read`, as making it private does, so no edge keeps `/heads` pages with
  these fields, or revisions with these headers. (A level is never lowered, and e2e is set only
  at creation.)
- **Raw documents** (§7.8 Files). A document whose root is a blob reference,
  `{ "$blob", "type", "size", "nonce"? }`, with no other members than `$schema`, a fresh
  `$nonce` and a well-formed `$successor`, which a blob reference at the root may carry (§7.8:
  nowhere else), stands for a file. `GET /r/{ns}/{name}/raw` and `…/rev/{id}/raw` answer `302`
  to `…/blob/{bid}`, the serving namespace's URL (a branch reads its base's blob through), with
  the document URL's `ETag` (and `X-Revision`), cached as that URL is: a head pointer, or
  immutable, tagged `r:{ns}/{name}`. A document that isn't raw is `404 not_found`, cached alike;
  unknown, pruned, purged and tombstoned ids and heads answer as the document URL does (a
  tombstoned head's `410` with `tombstone`, `last` and `successor`). In sealed and e2e
  namespaces, the e2e keyring included, both are `404 not_offered` after the read check, cached
  as the document URL (a level is never lowered); a purged namespace's `410`, and a purged
  resource's (v0.73), come first (§7.1, §8.3, §8.5). The read check is the document's, so
  per-resource grants and edge grants for `/r/{ns}/{name}` cover both URLs; a `schemaReads`
  referrer opens only revision paths. The Go
  client tells a raw document from its value with `client.RawBlobOf`, and asks the server with
  `Client.Raw`.
- **Blob responses** carry `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: sandbox` on every answer of `…/blob/{bid}` and `…/blob/{bid}/e/{e}`,
  `200`, `206`, `304`, the sealed `302` and errors alike, the `400`s for a non-canonical URL or
  an unknown query parameter included (§7.8 Reading): writers choose a blob's type, and its URL
  is on the API's origin, so a page can't run script from one. `sandbox` alone, unlike the
  services' stricter policy, so images and text still display inline. Chromium shows a
  sandboxed PDF as a blank page (its viewer is an extension), so a blob of type
  `application/pdf` is served with `Content-Disposition: attachment` (on `200` and `206`) and
  keeps the sandbox; `serve -inline-pdf` serves its `200` and `206` inline without the sandbox,
  still with `nosniff` (its `304` and `416` keep the sandbox). `text/*` blobs are served as
  `{type}; charset=utf-8` (§7.8, v0.73).
- **Moves** (§8.1). A move is content: the resource's last revision before its tombstone sets a
  top-level `$successor`, a bare name for a resource of the same namespace, resolved against the
  namespace serving the `410`, or `/r/{ns2}/{name2}`. Within one namespace it is one batch
  (create the new resource, then append `$successor` to the old one and delete it). Validation
  leaves a `$successor` of that form out of the instance (§6.2 step 5), as it does `$schema`
  and a fresh `$nonce`, so a closed schema needn't declare it; one of any other form is data.
  The same instance serves E3 client validation and merges, the index's `x-index` and `x-ref`
  walks and the bundle closure. The head pointer's `410` then carries
  `{ "tombstone", "last", "successor"? }`, copied from the last document's `$successor` when it
  is well-formed, in a namespace that is neither sealed nor e2e, judged by the namespace serving
  it; it is read from that document where it is stored, a base's rows or a remote base's mirror
  included, and cached with the head. A `[]` restore brings the document back with its
  `$successor`; a client restoring a moved resource also removes it. Signatures, rules on
  `/doc`, merges, imports, history bundles and remote branches carry it as any content
  (snapshot bundles don't, see [Bundles](#bundles-g4)). The Go client
  reads it as `Head.Successor`; `Client.Moved` falls back to the document at `last` where the
  `410` names none, `E2E.Moved` always folds that document, verified, and ignores a successor
  the `410` names (none comes from a conforming server at E3, which is outside the trust
  boundary), and `client.ResolveSuccessor` resolves a bare name.
- **Whole documents** (§6.6). An append or restore whose first operation other than `test` is
  a root `replace` or `add` may be as large as `documentSize`, as a create may, so a document is
  overwritten on purpose in one request (§11.3); at E3 every create and restore may, and no
  append does. See the limits in [Design notes](#design-notes), and `logPageBytes`, which keeps
  a log page of such patch sets bounded.

`size` and `digest` are stored, not computed, so a listing reads no document: the write that
leaves a revision as a resource's head stores its document's length and sha-256 with it
(`revisions.size`, `digest`), from the canonical bytes the write already holds, and a read of
that revision serves the stored digest as its `Repr-Digest` instead of hashing again. That is
step 7 for every resource write and batch (group commits, merges, rebases and bundle imports
write batches), and the chains remote branches and mirrored schemas insert (§G.3).
Intermediate steps of a multi-step item, which no entry makes a head, tombstones, and
sealed and e2e namespaces store none: they never list them, and a level can't be lowered
(at e2e the server has no document anyway, §E.3). Purges clear them with the patch sets;
prunes keep them, as they keep ids, created times and gestures (§8.6), and a restore from an
archive moves no head. Heads written before the upgrade, or by an older instance during a
rolling one, have none: they are listed without `size` and `digest` until the resource is
written again. Nothing fills them in later: a `/heads` page is immutable and cached for a
year, so a listing already served never gains them (§7.4); a backfill would have to fold the
document of every head at every `ns_id`, not just the current ones; and while older instances
still write, no backfill could finish. They only go: a purge turns its entries into purges,
and a namespace raised to sealed lists them on none of its pages from then on, and purges the
copies cached before. `created` was always stored. Namespaces encrypted at rest, and remote
shadows of such branches, store neither (§E.1 Stored digests): they would sit in plaintext
next to encrypted rows, and let a dump confirm a guess of a head's whole document even after a
purge. A raise to at rest or above clears those stored before, and the first start of this
version clears, once, the ones earlier versions stored at rest (recorded in the `migrations`
table); `/heads` lists `size` and `digest` only for namespaces without encryption. A revision
read at rest still sends `Repr-Digest`, computed from the document it serves (§7.1).

**Beyond the spec.** A resource purge also purges the `/heads` pages of every namespace it
reaches, which carry `heads:{ns}` besides `ns:{ns}` (§9). §8.3 accepts that a digest already
served survives a purge, as ids do, but a cached page would keep listing the purged head's
size and digest, which the origin no longer lists, so the reference clears its own edge's
copies; browsers' copies remain until their `max-age` expires.

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

Status codes (§C.2, §7): the request's shape is judged first, so a malformed id (in the URL,
`since` or `Last-Event-ID`; a well-formed unknown one stays `404`), a malformed precondition or
branch name, a body with a Unicode noncharacter, a malformed `Signature`, or a write without
`X-Author` while authentication is disabled is `400 bad_input`, `no-store`, before
authentication and before an unknown namespace's `404`; on event streams a non-empty
`Last-Event-ID` wins over `since` (§7.3). A batch body is the exception: it is read only up to
the verified principal's `batchSize` (§6.2, §7.5), so its shapes are judged once the grant is
verified. A bearer over the deployment's `grantSize` or `rulesPerGrant` is then `413`. A grant
not naming the namespace in every block that carries `ns` is
`403` before anything is verified or looked up, whether or not the namespace exists; no usable
grant (missing, malformed, badly signed, unknown key, revoked, expired, not yet valid, with a
rule that doesn't compile, or naming `"*"` without being an operator grant) is `401`;
a valid grant that doesn't allow the request is `403` (`404` on reads, which hide existence). A
namespace that doesn't exist answers like an existing non-public one: `401` without a usable
grant (a grant naming it can only be verified by an operator key, and only a forced purge then
gets `404`). Public namespaces ignore an unusable or unrelated grant on reads.

`/ns/{ns}` and every URL under it but the gestures listing and `POST /ns/{ns}/keys` (the
namespace document, its log, events and long-polls, `/heads`, `/branches`, `/grants/…`) need
**unrestricted** read (§2.1, v0.47): the key has no `readScope`, no rule in the grant's blocks or its key's scope refers to
`/resource`, and, with roles, one role listing `read` has no such rule. A grant that reads only
some resources gets `404` there, as for any read it may not make, so it can't list the names
and heads its reads hide; a resource's own URLs, its event stream included, need read on that
resource only. A grant its key's scope doesn't allow (`readScope`, `sub`, `groups`, `maxTtl`,
`requireAt`) is `403` on `/ns/{ns}` and every URL under it in a private namespace, and on `POST
/ns/{ns}/keys`; only a resource's own URLs keep the `404` that hides the resource (§C.2 item 1,
v0.73). Branching, remote registration and a batch's source check need unrestricted
read too; branching and registration check it as gate step 1 checks verbs, in a public
namespace too (v0.49): the grant must allow `read`, read unrestricted and pass its key-scope and
block rules on `/action`, `/principal` and `/now` with `/action` `read`, rules on `/doc` left to
step 6, and a role that counts for read must pass all its rules against a read envelope, as a
read does, so a role whose rule reads `/doc` or `/writes` no longer lets its grant branch or
register a namespace it can't read (§C.2 item 2, v0.73).

A purged namespace (§8.5, §12) answers `410` with `code: "purged"` and `head`, the `ns_id` of
its `purge-ns` entry, which is the log's last (v0.49), so a consumer needn't re-read
`/ns/{ns}`: on `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…` (sealed and e2e
namespaces included), `POST /ns/{ns}/keys` and `/heads` at any revision, as soon as the full
read check passes, the grant's rules included, and before any other answer to a well-formed
request (`not_offered` and the `404` of an unknown id included; v0.50); and on every write,
after authorisation and rate limits and before any other check: resource writes, batches (one
with a config change after its items' authorisation), blob uploads and copies, purges, prunes,
config writes, namespace purges, branching from it and remote registration. A remote branch of
it on another deployment is `410 purged` too, also naming `origin` and `ns` (§G.3). `/ns/{ns}`
and its log stay readable, and the log's `purge-ns` entry says what happened, except in a
sealed namespace (v0.51): the purge destroys the epoch keys that seal its namespace documents
and log, so `/ns/{ns}/rev/{id}`, `/ns/{ns}/rev/{id}/log`, long-polls, `/ns/{ns}/events` and a
resource's events answer `410 purged` with `head` too, after the read check and at any id or
`since`, rather than in the clear. `GET /ns/{ns}` still redirects, to the purge's revision,
which is `410`, and its `head` is how a consumer learns of the purge. The name stays
reserved: creating a namespace or branch under it is `412`, also a retry of the request that
created a branch since purged.

`requireAt`: `at` must have been the head of its namespace at some point within `maxLag` before
the grant was issued, issuance taken as `max(nbf, exp − maxTtl)` of the root block (`nbf` when
the key sets no `maxTtl`); a grant with neither fails the key scope (`403`), since issuance
can't be told (§C.4). `maxTtl` is judged on the root block alone, `exp − max(now, nbf)`. `maxLag` is the
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
`"*"`: any other grant that names `"*"` is `401` on every request (§C.4). An operator grant authorises exactly three things (§C.4): creating a
namespace with its genesis document, creating a remote branch with the schema histories it
mirrors, and forcing a purge or namespace purge (`?force=1`). A creating grant must list
`config` (§C.2 item 2, v0.73: one minted with `can: ["create"]` alone is `403`, as is one asking
about a taken name), and passes the `*`-key guard whatever its key's `can`. Anything else under
one is `401`, as for a key the namespace doesn't list, also for a namespace that doesn't exist
(a forced purge
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
  precondition (a `DELETE` with `If-None-Match: *`, or a batch item whose first step is
  `"delete"` under `ifNoneMatch`, included) isn't checked, `"required"` included, and gets
  `428` or `400`. A malformed `Signature` is `400`, before authentication,
  and so is one whose `<sig>` isn't exactly 86 unpadded base64url characters (§C.3.1; signatures
  stored earlier are still read, `sig.Parse`), and a `Signature` header on any write but a
  resource `PATCH` or `DELETE` (a batch's step objects carry their own `signature`; for blob
  uploads and copies, at check 4 of §7.8).
- `"signatures": "required"` in the namespace document (a `*` key) makes every revision and
  tombstone need a valid signature by a signer of its grant. Narrowing blocks can't carry
  `signers`, so delegated grants can't write there.
- Resource logs serve each revision's `grant: { id, sub, kid }` and `signature`, and
  `GET /ns/{ns}/grants/{gid}` serves the stored grant (`{ id, root, stored }`, the authority
  SignedBlock alone since v0.73, `stored` one string, §C.3, §C.8; rows stored earlier are
  served as
  theirs, and a grant answer an earlier version sealed with `stored` as an array is sealed again
  in the new shape, in the same epoch, the first time it is read, §C.3.1) to readers with
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
  A batch item with two `"delete"` steps in a row is `422 invalid`, at step 2.5 with the other
  precondition failures, in request order (§7.5, v0.73). Unplace grants from the
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
  `ns_config.doc`, `revisions.signature/schema_ref`, `revisions.size/digest` (a head's
  document, for `/heads`, about 40 bytes a row: see
  [Files and sync clients](#files-and-sync-clients-71-74-78-81)),
  `resources.keep`, `heads.seq`, `deks`
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
  …) answer the same way, with the pointer their message names. Since v0.73 the whole document a
  config write or a creation produces is validated first (§6.2 step 4, §7.4, §C.2): members,
  `base`, `drafts`, levels, a base's `*` keys, a public branch, the base's nonce requirement and
  `successor`; then come the patch-set and document limits and an unfrozen branch's
  `branchesPerNamespace`; step 6 runs the `*`-key guard (`403`), then the `in_use` refusals
  (`409`), then the rules. So a write without a `*` key that touches a guarded member and breaks
  a branch field gets the `422`. Branch fields answer `422 invalid` with `errors` pointing at
  the member (`/base`, `/base/at`, `/drafts`, `/encryption`, `/encryption/epoch`, `/keys`,
  `/read`, `/nonce`, `/successor`), at branch creation and in config writes. A branch's level is
  compared with its base's only at creation and on a raise to `e2e`. A config write to a branch
  keeps only the base `*` key entries the branch's document already holds (keys follow the
  base), so one after a base added, replaced or rotated a `*` key goes through; removing or
  changing a copied base `*` key is still `422`. `successor` is checked only by a write that
  sets or changes it: another namespace that exists and isn't purged, for a branch a branch of
  the same base or of a namespace further up its base chain, for any other namespace one that
  isn't a branch (a namespace's creation still refuses any `successor`). `/catalogs` and
  `/maxLag` need a `*` key, as `/keys` does: config writes and a branch's `patches` that cover or
  overlap either are `403` under any other key (§7.4). The addenda's members are
  checked in their shapes: `catalog: { trust?: [namespace names], mode?: "tree" | "dag",
  title?: pointer, files?: { ns, root, folder?, placement? } }` (`files`, v0.55, §H.2: `ns` a
  namespace name, `root` a folder name, without a dot, and `folder` and `placement` schema
  revision paths; whether the catalog trusts `ns` or the schemas resolve is the tools' to check),
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
  resource page at most `logPageBytes` of patch sets (§6.6, default 16 MiB, `serve
  -log-page-bytes`), measured as served (decompressed, decrypted at rest, the sealed op at E3,
  and at E2 the per-entry JWEs themselves, stored or sealed for the page, so where a page ends
  says no more than their padded lengths do, §E.2.2); and a namespace page, whose entries carry
  no patch sets, at most as many resource entries as the page size, a batch entry counting as
  its items. Either bound ends a page before an entry that would take it past, but a page always
  holds one, so a patch set over `logPageBytes` is a page of its own. The byte bound stops the
  scan once the stored rows are sure to exceed it (their stored lengths bound what they serve,
  and a JWE is no shorter than its plaintext unless compressed, which a padded one never is: an
  unpadded E2 page may end sooner than its JWEs would), so a page of large patch sets reads no
  more rows than it serves; a
  range that goes on carries `X-Log-Next: {id}`, the page's last entry and the `since` of the
  next page, an immutable range up to the same id, so every page caches as immutable. Errors are
  the range's on every page: a range crossing a pruning horizon is `410` on all of them. A page
  costs its own rows, however long the range: a resource's chain is its rows in seq order, so a
  page is one `seq > ? … LIMIT` query per ancestry segment it reaches, after a query or two per
  segment to place `since` and look for pruned patch sets, which only exist at or below a
  resource's horizon (or in a purged one); a namespace page is one `LIMIT` query, over the index
  `ns_log (ns, seq)`, so it reads the page's rows however long the namespace. The rows a
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
  folds, and so `follow` (catch-up delivers and checkpoints page by page, §10; a snapshot
  bootstrap, `WithSnapshot` or a new branch, delivers its `/heads` listing a page per batch, the
  first replacing what the consumer holds and the last carrying the checkpoint, and a consumer
  whose checkpoints record the pages in between, `SQLCheckpoints.SaveBatch`, resumes after the
  last one recorded when restarted; the tree service applies a listing whole, at its last page,
  since its listings are cached by checkpoint), the index (`?min`
  checks only the first page), tree and catalog, merge, rebase, release and janitor tooling,
  bundle export and import (whether `requires` is in the target's chain takes one page), remote
  branches mirroring and following their bases (§G.3), and the playground (namespace logs,
  histories and e2e folds; each sealed page is opened as its own range).
- **Long-poll reads are shared** (§7.7, `internal/core/live.go`). A write wakes every long-poll
  waiting on its namespace, and each would read the log after its `since` again: thousands of
  identical transactions for a private namespace that thousands of devices follow, which a CDN
  can't collapse unless it verifies edge grants (§C.5). So a long-poll's first read is checked as
  any read, and while that decision holds its later reads skip the check and are shared: the
  waiters woken by one commit that read the same `since` and page make one read, and its answer
  serves those that ask after it is done, until the namespace's next commit. The decision holds
  while the read cache's meta counter (configuration, purges, prunes, restores, key destruction;
  on Postgres while the tailer is fresh) hasn't moved, before the grant's earliest `exp`, and only
  for grants whose key, block and role rules don't read `/now` (nor the whole envelope); edge
  grants and resource long-polls are read on their own, as before. On server X
  ([docs/CAPACITY.md](docs/CAPACITY.md)) one write to 5,000 private followers went from 3.7–4.1 s
  of core CPU to 0.3–1 s. The local CDN's VCL lets a long-poll with credentials skip Varnish's
  waiting list (`hash_ignore_busy`), so a private one isn't held behind an identical request in
  flight.
- **In-memory caches, per instance**, each bounded and evicting gradually:
  - **Verified bearer grants**, by token: 65,536 by default (`serve -grant-cache`), at most
    32 MiB of tokens, the least recently used out first. A request whose grant isn't kept
    decodes and verifies it (signatures, revocations), so a fleet of devices with grants of their
    own should fit (docs/CAPACITY.md). Only grants whose signature chain verified are kept.
  - **Documents by revision id**: 256 MiB by default (`serve -doc-cache-size`), the least recently
    used out first; a document over a quarter of it isn't kept. Bounded by count before, 4,096
    documents of up to 4 MiB could hold 16 GiB.
  - **The read cache** (revisions and head pointers served without a transaction): 64 MiB of
    revisions by default (`serve -read-cache-size`) and 65,536 entries; past either, entries are
    evicted until both are within three quarters, where it used to start over empty.
  - **Compiled schemas** by revision path: the 512 most recently used, and the 2,048 schema
    documents they were compiled from; one evicted is compiled again when next used.
  - **Rate-limit buckets** (§6.6), on SQLite and under `serve -local-rate-buckets` (on Postgres
    they are rows of `rate_buckets`, shared by the instances, see [Postgres](#postgres-d8)): one
    per namespace, principal and (namespace, resource, principal) written. A bucket that has
    refilled to its burst is the same as a new one, so they are swept once a minute when there
    are more than 1,024.
- **Allowances** (§6.6): `allowances: [{ sub, kid, bucket: { rate, burst }, itemsPerBatch,
  batchSize, until? }]` in a namespace document gives one principal its own bucket (replacing the
  principal and namespace buckets, and a key scope's lower rate) and batch limits, until the
  optional RFC 3339 `until`; the first matching entry whose `until` hasn't passed applies, so an
  ended entry no longer hides a later one (v0.73). They can go
  up to the deployment maximums, set with `serve -max-items-per-batch` and `-max-batch-size`
  (the flag accepts `64MiB`; the document takes bytes); a `bucket` above the maximum of
  `ratePerNamespace` (500/s, burst 1000, unless `serve -max-rate-per-namespace RATE,BURST`
  says otherwise) is `422 limit` naming `ratePerNamespace` (F-L3 default), and stored ones are
  clamped to it, so importers and load harnesses that need more raise that maximum.
- **Limit names** in a namespace document's `limits` object, exactly as §6.6's table:
  `patchSetSize`, `opsPerSet`, `documentSize`, `valueSize`, `pathSize`, `nestingDepth`,
  `rulesPerNamespace`, `itemsPerBatch`, `batchSize`,
  `branchesPerNamespace`, `keepPerResource`, `blobsPerDocument`, `blobSize`, `blobPending`
  (integers, sizes in bytes, up to the deployment maximums, which equal the defaults but for
  `documentSize`), `ratePerResource`, `ratePerPrincipal`,
  `ratePerNamespace`, `blobRate` (`{ rate, burst }`, `blobRate` in bytes), `retryWindow`,
  `remoteRegistration` and `blobGrace` (ISO 8601 durations; `blobGrace` at least `retryWindow`).
  Sizes written with units (`"64 MiB"`), unknown or v0.20 names (`liveBranches`,
  `remoteBranchLife`) and the deployment-only `logPageSize`, `logPageBytes`
  (`serve -log-page-bytes`), `branchDepth`, `exchangeRate` (`serve -exchange-rate`, §C.5),
  `grantSize` and `rulesPerGrant` (§12.2, v0.63) are `422`; documents stored with the last two
  still load, their values ignored. Lowering a deployment maximum doesn't break existing
  namespaces: stored limits, allowances and rule counts are held to the new maximum, as are
  values a write keeps unchanged, and only a write that sets a value above it is `422 limit`.
  `rulesPerNamespace` counts every rule form, role and key-scope rules and nested
  `all`/`any`/`not`/`if`/`then` forms included, and holds a branch's creation as a namespace's. Creates, and appends and restores whose first operation other than `test` is a root
  `replace` or `add` (§6.6 Whole documents), may be as large as `documentSize` instead of
  `patchSetSize`; at E3, where the patch set's shape is sealed, every create and restore may and
  no append does; in a batch they still count toward `batchSize`. Config writes, a batch's
  config change, namespace, branch and remote branch creations are held to `patchSetSize`,
  `opsPerSet`, `documentSize`, `nestingDepth`, `valueSize` and `pathSize` too, a creation
  counting as a create. `valueSize` and `pathSize` bound strings and pointers, and every
  namespace's creation, a branch's, and a config write that changes `limits` or `encryption`
  other than its `epoch`, need `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize` (§6.6
  Values; an e2e configuration adds `36 B × blobsPerDocument`); stored documents aren't held to
  it, and an epoch rotation goes through. `$blob`
  objects must be well-formed and name available blobs that match their type, size and nonce
  (`422`, `code: "blob"`). Allowances may also set `blobRate` and `blobPending`; the deployment
  maximums are set with `serve -max-blob-size` and `-max-blob-pending`.
- **`documentSize` is 1 MiB by default**, where §6.6 says 4 MiB, and a namespace may set it up to
  the deployment maximum, 4 MiB unless `serve -max-document-size` says otherwise;
  `serve -document-size` changes the default (at most the maximum). Every write re-serialises,
  checks and validates the whole document, so an append to a 3.5 MiB document costs 3–4 times one
  to a 16 KiB document, and large documents weigh on the caches ([docs/CAPACITY.md](docs/CAPACITY.md)).
  A namespace holding larger documents sets `"limits": { "documentSize": 4194304 }`; until it
  does, appends that leave a document over 1 MiB, and creates over it, are `422 limit`
  (`413` only where the body is cut off unread, §6.6).
- **Batch sources** (§7.5, §7.8): a local `source.at` is checked against `source.ns`'s chain
  (`422`, `code: "source"`) at step 4, right after the batch limits and before any item's own
  limits and blob references (v0.73), only when the caller may read
  `source.ns` unrestricted (with `Source-Authorization`, if given); then the blobs attached to
  the same resource there, or in a base it reads through, are available as `source.ns` sees it
  at `source.at`. Anyone else's source is recorded unchecked and makes no blobs available. A
  `source.origin` equal to this deployment's own is `422 source` for any caller (v0.73). A
  dry run reports an unavailable blob and runs the later steps anyway: the item reports
  `blob` with the ids it would produce, or a later step's failure with the blob failure under
  `blob`. A write referencing a blob ends every pending entry for it in that resource.
- **Batch limits after authentication** (§7.5): the server authenticates a batch before
  reading its body, and stops reading at 4 × max(the principal's `batchSize`, its allowance's
  if any, and the deployment maximum of `documentSize`), 64 MiB at the defaults, with `413`
  naming `batchSize` and the principal's value as `max`. Item counts and the patch-set total are
  checked at step 4 (`422 limit`).
- **Candidate verbs** (§6.2): a `PATCH` with `If-Match` (in a batch, an item whose first step
  is a patch set) passes step 1 with `append` or `restore`; step 2 settles the verb from the
  resource's state (a branch's view, read-through included) after the idempotent-retry lookup
  and before frozen and the precondition, so a grant that can't restore gets `403` on a
  tombstoned resource, whatever `If-Match` says. A `PATCH` without a precondition (in a batch,
  an item whose first step is a patch set) is checked against `create`, `append` and `restore`
  at step 1 and then gets `428`, so a create-only grant sees `428`, not `403` (§C.2 item 2); a
  `DELETE` with `If-None-Match: *`, and a batch item under `ifNoneMatch` whose first step is a
  delete, get `428` after authorisation, a purged namespace's `410 purged` first (§7.5, v0.73).
  On a tombstoned resource a create is `410 gone` with `head`, the tombstone, never `412`, and
  so are an append on another head and a `DELETE` (§7.2, §8.1, v0.73): clients that took a
  create's `412` as "exists, restore" handle the `410` too, as the merge tool, the release lock,
  the importer, undo and the WebDAV gateway do. A `412 stale` carries no `"head": null` when
  there is no head (§12.1). A create's patches apply to the document `null` (`test "" null`,
  a root `replace`, `copy` or `move`), and stored histories fold, archive, mirror and replay
  their genesis so; one that writes nothing (`[]`, only tests) is `422 invalid`, one that writes
  `null` stores the document `null` (§6.2 step 3).
- **Idempotent retries** (§7.2, v0.73) need the same principal: the same root `sub` and the
  signing `kid`, or, for an entry written with authentication disabled or recording no grant,
  the same author; a retry under another key with the same `sub` gets `412`. That holds for
  resource writes, batches, config writes, namespace creation and branch creation. A branch
  creation's retry matches on principal, `at` (one that omits it counts as naming the
  recorded `at`) and `patches`, judged against the base document in force at the creation, so
  config writes to the base since then don't turn it into a `412`; a taken name is `412` before
  an `at` outside the base's chain gets its `422`, and a namespace creation or branch under a
  taken name is `412` without `config` (an `If-Match` mismatch keeps `{ config }`).
- **Dry runs** (`?dry-run=1`, §7.5, v0.73): an item that would pass reports `status: 201`; a
  batch a submit would answer as an idempotent retry reports every item at `200` with its ids,
  and its config change as `{ status: 200, config }`; a dry run carries no `ns_id`,
  `X-Namespace-Revision` or `X-Config-Revision`. A config change runs its step 1 first, and a
  failure there answers as the config write would; any later failure, the `*`-key guard and the
  rules included, is reported as `config: { status, code, … }` and the items are judged against
  the current configuration; on success `config` is `{ status: 201, config: <id> }`
  (`client.BatchResult.ConfigReport`, `ConfigError()`; `Config` is set only on a submit). Such a
  batch draws the same tokens submitted or dry-run once its items pass step 1, one per item and
  one for the change unless a `*` key made it (F-G4 default). A submitted batch with a config
  change sets `X-Config-Revision` on its `201` and its retry's `200`.
- **Namespace log entries** are `{ …entry, id, prev?, author, via?, grant?, gesture?, undoes?,
  gestures?, created }` (§7.4). `via` (v0.73; resource log entries carry it too, §7.1) lists the
  delegatees of the grant the entry was written under, in order, unhashed; it is absent when
  there are none, sealed with the entry at E2, never recorded on entries the server writes
  itself, mirrored by remote branches (§G.3), and absent on entries written before (`ns_log.via`
  is added empty: a grant is stored once per root id, without its narrowing blocks, so it can't
  be recovered). The client reads it as `LogEntry.Via` and `NSEntry.Via`. `author`, `grant`,
  the gesture members (see Gestures) and
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
  stored grant verifies under the branch's current `*` key for its kid (local bases only). Databases from before v0.37 recorded only the
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
- **`GET /ns/{ns}/principal`** (§7.4, v0.55) answers `200` with `{ "principal", "kid", "key",
  "operator", "can", "roles", "catalog"?, "writer": { "frozen", "successor"?, "nonce",
  "signatures", "level"?, "limits" } }` and `X-Config-Revision` (`key`, `operator` and
  `catalog` since v0.73: the RFC 7638 thumbprint of the verifying key, the same in every
  namespace; whether the grant is an operator grant, false while authentication is disabled;
  and for a namespace whose document has `catalog`, `{ trust, files? }`, or, to a grant without
  unrestricted read of it, an operator grant outside public namespaces included, `files`
  without its `x-` members and `trusted` in place of `trust`; the client's
  `PrincipalInfo.Key`, `Operator` and `Catalog`): the principal of §6.4.1 (`{ id, groups,
  roles, attrs, via, grant }`),
  the root block's `kid`, the verbs its blocks allow, sorted (with roles, only those an
  effective role lists), its effective roles, and what a writer needs from the namespace
  document, which a grant limited to some resources can't read: `frozen`, `successor` if set,
  `nonce` and `signatures` (`"required"` or `"optional"`; a sealed namespace says `"required"`,
  as §E.2.5 holds every patch set there to a fresh `$nonce`), `level` (`at-rest`, `sealed`,
  `e2e`; absent without `encryption`) and `limits`, every key of §6.6 as a namespace document
  writes it (sizes and counts as integers, durations as ISO 8601, rates as `{ rate, burst }`),
  the deployment's defaults and maximums applied, the deployment-only ones being the
  deployment's (an allowance isn't applied). Only the `ns` check and verification apply, so a
  grant limited to some resources or without `read` gets it; none, or one that can't be used, is
  `401`, in a public namespace too; an edge-grant cookie is no grant here; a grant chained to an
  operator key verifies against the operator keys and gets `404` for an absent namespace (and
  `200` for an existing one, as §7.4 says; §C.4 still says `401`); a purged namespace is `410
  purged` with `head` once the grant verifies. It takes no query parameter, draws no rate
  token, works in frozen, sealed and e2e namespaces alike, and every answer is `no-store`. With
  authentication disabled it leaves out `principal` and `kid` and lists every verb. The client
  reads it with `Client.NSPrincipal` (`PrincipalInfo`, `WriterInfo`); undo asks it for the
  namespace's `opsPerSet` and `patchSetSize` when the namespace document can't be read (§11.2),
  falling back to §6.6's defaults on a server that answers `404` there, and such a writer still
  adds a fresh `$nonce` in a private namespace (`NeedsNonce`), as §C.7 recommends. Verification now also applies a key's `readScope:
  "resource"` (§C.2 item 1, §C.4) to every request: a `read` grant it signs that doesn't fix
  `/resource` (§2.1) is refused (`403`, or `404` on a read of a private namespace, as any
  refusal there). `grant.Verify` applies it, so the services' grant checks (`grantcheck`: the
  tree, catalog and index services) refuse the same grants.
- **Limit refusals** (§6.6, §12, v0.55, v0.73): step-4 refusals are `422`, and `413` is kept
  for bodies cut off unread, `grantSize` and blob sizes. Every `413` or `422` with
  `code: "limit"` names the
  limit's key in `limit`, and for sizes and counts carries `measured` and `max`, the limit in
  force: `patchSetSize` (or `documentSize` for a whole-document patch set) and `opsPerSet` of
  the patch set, `documentSize` and `nestingDepth` of the resulting document, `valueSize` and
  `pathSize` of the first string or pointer found too long (canonical bytes, quotes included),
  `blobsPerDocument`, `itemsPerBatch` and `batchSize` (the principal's, with an allowance),
  `branchesPerNamespace` (the live branches with the new one), `branchDepth`, `keepPerResource`,
  `rulesPerGrant` and `rulesPerNamespace`, `grantSize`, `blobSize` and `blobPending`; a
  namespace document over a deployment maximum names that key with its value and the maximum,
  a document failing §6.6's Values inequality names `patchSetSize` with the left side as
  `measured`, and durations and rates (`retryWindow`, `remoteRegistration`, `blobGrace`, the
  rates, an allowance's `blobRate`) carry the key alone. For limits on the resulting document
  (`documentSize`, `nestingDepth`, `valueSize`, `pathSize`, `blobsPerDocument`), `measured` is
  left out when the caller can't read the resource (for a namespace document, without
  unrestricted read). A body the server stops reading names the deployment's `documentSize`
  (resource patch sets, config writes, namespace creations and branches alike) or, for a batch,
  the principal's `batchSize`, with the bytes read as `measured`, a lower bound; a blob sent without `Content-Length` gives `blobSize + 1`.
  A batch item's report carries its refusal's fields. The prune and `/keys` bodies, which no
  limit covers, are `400 bad_input` above 1 MiB, and so is an edge-grant exchange body over room
  for 50 grants of `grantSize` (§12: an exchange over its limits; a grant too large is `413
  grantSize` once decoded). A bearer is held to the deployment's `grantSize` and
  `rulesPerGrant` as it is decoded, before step 1 and the `ns` check (§C.8): `413` for either,
  `rulesPerGrant` counting every rule form of the token's blocks, nested ones included, not
  key-scope rules; a rule that doesn't compile then makes the grant `401`. A config write that
  creates a namespace, or changes its rules or its own `rulesPerNamespace`, is held to that
  bound, as §6.6 says, not only to the deployment's maximums; a document an earlier release
  stored over its own `rulesPerNamespace` takes other writes, a freeze among them. The client reads them with `APIError.Limit` and
  `client.IsLimit`.
- **`GET /`** answers `{ "spec": "0.73", "auth": "grants" | "disabled", "origin", "jwks_uri" }` (§1, §7,
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
internal/dav         WebDAV for file managers and editors: namespaces and catalogs as files, saves as diffs (a prototype)
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
internal/sqlitedsn  SQLite DSNs: a database path escaped, so the driver opens that file; the file earlier releases opened instead
internal/server     HTTP API
internal/lifecycle  /_health and /_ready, phased graceful shutdown (serve, index, tree)
internal/cdnpurge   HTTP cache-tag purges to a CDN (-purge-url)
internal/repurge    the index and tree services' second CDN purges, queued with their commits (D.8)
internal/edge       the verifying edge's headers, private edge directives, edge-grant cookies and an edge's checks (§9, §C.5)
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
