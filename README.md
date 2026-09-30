# patchlog

A Go implementation of the **Patch Log** specification ([docs/SPEC.md](docs/SPEC.md), draft v0.19).
Each resource is an append-only log of content-addressed JSON Patch sets. The server
validates documents that opt in with `$schema`, enforces namespace rules and grants,
and serves immutable, CDN-cacheable revisions.

## What's implemented

| Area | Spec | Status |
|---|---|---|
| I-JSON input, JCS canonical form, base32 ids (`1…`) | §3 | ✅ |
| Revisions, tombstones, namespace chain, names grammar, canonical URLs | §3.3–§3.6 | ✅ |
| Opt-in `$schema` validation (JSON Schema 2020-12, format assertions, strict refs, unknown keywords rejected) | §6.1–§6.3, §6.5 | ✅ |
| Change envelopes, rule engine (`test`, `writes`, `compare`, `all`/`any`/`not`/`if`) | §6.4 | ✅ |
| Limits (configurable, deployment maximums) and token-bucket rate limits | §6.6 | ✅ |
| Reads, writes, gate order, `412`/`428`, idempotent retry | §6.2, §7.1–§7.2 | ✅ |
| SSE events, long-poll with cursors | §7.3, §7.7 | ✅ |
| Namespace documents, log, `/heads`, `/branches` | §7.4 | ✅ |
| Atomic batches (multi-step items, config changes, dry run, retry) | §7.5 | ✅ |
| Local branches: read-through, foreign parents, keys follow the base | §7.6 | ✅ |
| Tombstone, restore, purge (with propagation), freeze, namespace purge | §8.1–§8.5 | ✅ |
| Pruning with horizons, protected revisions, kept documents, archives and retention | §8.6 | ✅ (file:// archives) |
| Cache-Control classes and cache tags | §9 | ✅ (CDN purges go to a pluggable `Purger`, default: log) |
| Grants, narrowing, roles, attributes, key scopes, revocation | Addendum C | ✅ |
| Remote branches: registration (`export`), mirroring with verification, schema mirroring, purge notices | §G.3 | ✅ (mirrored up front) |
| Storage layout | Addendum D.2 | ✅ SQLite (pure Go, `modernc.org/sqlite`) |
| Encryption at rest, cryptographic purge | Addendum E.1 | ✅ (local master key file; KMS adapters to come) |

### Not implemented

- **Addendum B:** catalog branches (§F.8 preview access and merge grants), a `groups`
  namespace, signed manifests and `x-tree-label` titles.
- **§F.7 merge service** (scheduled merges, web status): not built. Its logic is in
  `internal/merge` and the CLI.
- **Addendum E.2/E.3** (sealed, end-to-end): `encryption.level` `"sealed"` or `"e2e"` is
  rejected with `422`. E.1 (at rest) is implemented, see below.
- **Addendum G** (federation): remote branches whose base is itself a branch, lazy
  read-through, and mirroring pinned `x-ref` targets (§G.3). Bundles (§G.4) are implemented
  as `patchlog export/import`; merging a remote branch back is a bundle or merge-tool task.
- **Archives other than `file://`** (§8.6), e.g. object storage.
- CDN edge grants (§C.5): the origin checks grants itself on every read and sets
  `Cache-Control: private` plus `CDN-Cache-Control` for non-public namespaces.
- Author signatures (§C.3): a `Signature` header is stored with the revision and returned
  in the log, but not verified.

## Running the whole stack

```sh
make up        # or: docker compose up --build -d
```

This starts the core server in dev mode, seeds a few demo namespaces and documents, and runs the
search index, the tree service and the branch janitor:

| URL | What |
|---|---|
| http://localhost:8080 | core API |
| http://localhost:8080/playground/ | web playground |
| http://localhost:8081/demo?q=derby | search index (Addendum A) |
| http://localhost:8082/cat/roots | tree service (Addendum B) |

- `make logs` follows the logs.
- `make seed` re-runs the seed, which is safe to repeat.
- `make down` stops the stack and keeps its data; `docker compose down -v` wipes it.
- Data lives in the `data` volume: databases, pruning archives, and the at-rest master key,
  which is created on first start.
- Ports and the origin can be changed with `PATCHLOG_PORT`, `INDEX_PORT`, `TREE_PORT` and
  `PATCHLOG_ORIGIN`.
- Without Docker, `make dev` runs just the core server, and `make check` runs vet, the tests and
  a gofmt check.

## Running

```sh
go build -o patchlog ./cmd/patchlog

# Development: no authentication; X-Author names the author.
./patchlog serve -dev -db dev.db

# With authentication: create an operator key for bootstrapping namespaces (§C.4).
./patchlog keygen                     # prints a public and a private key
./patchlog serve -db prod.db -origin https://cms.example -operator-key <PUBLIC>
```

### Playground

`serve` also hosts a web playground at **`/playground/`** (turn it off with `-playground=false`).
It is plain HTML/JS embedded in the binary and talks to the same-origin API. It has:

- a request inspector with every request's preconditions, status, response headers and error body, plus "copy as curl";
- namespace, resource, history, batch and branch editors;
- live SSE feeds;
- scripted examples: conflict and rebase, schema validation, rules, batch delete+restore, branch read-through.

Run it with `./patchlog serve -dev` and open `http://localhost:8080/playground/`.

### Search index (Addendum A)

`patchlog index -ns matches` follows namespaces and serves a search API on its own origin
(default `:8081`). It indexes fields that schemas mark with `x-index: "text" | "facet" | "sort"`:

```sh
curl -L 'localhost:8081/matches?q=derby*&facet[/league]=allsvenskan&sort=-/kickoff'
```

- `GET /{ns}?…` redirects to `/{ns}/at/{checkpoint}`, which stays correct forever.
- `?min={ns_id}` waits for your own write to be indexed, and answers 503 if it isn't in time.
- In private namespaces the reader's grant is checked locally. Results are routed under
  `/g/{subject-set}/…` and filtered to the resources the grant can read.

### Merge, rebase and cleanup (Addendum F)

```sh
patchlog merge status -branch release-7          # per resource: ahead, behind, clean, conflicting
patchlog merge plan   -branch release-7          # the batch, plus a dry run
patchlog merge apply  -branch release-7 -freeze  # one batch into the base, then freeze with "merged"
patchlog rebase -branch release-7 -new release-7-b -switch
patchlog janitor -ns matches                     # purge merged/superseded branches after `cleanup`
```

- Resources are classified by ancestry, using ids only (§F.3). A fast-forward reproduces the
  branch's ids exactly. A replay reports overlapping `writes` under the array rule, and the
  delete-versus-change cases always go to a person.
- `-resolve name=file.json` replaces a conflicting item's steps with a resolution.
- Earlier merge batches from the same branch count as common ancestors, so a second merge only
  picks up what is new.
- The janitor checks `merged` and `successor` claims against both logs before purging (§F.6).
  Cleanup is opt-in: a branch is purged only once a `cleanup` period, from the branch's or the
  base's document, has passed.

### Pruning archives and retention (§8.6)

```sh
patchlog serve -archive file:///var/lib/patchlog/archive [-archive-root file:///other] [-retention-interval 1h]
patchlog archive restore -db patchlog.db [-from file:///moved/archive] [-ns NS] [-resource NAME]
```

- **Archive first.** Before a prune drops patch sets, it writes them as a full-history bundle
  (§G.4.1) to `{destination}/{ns}/{name}/{horizon}.jsonl`. A later prune writes an incremental
  bundle whose `requires` points at the previous one.
- **410s link to the archive.** Revisions below the horizon answer `410 pruned`, with the
  archive's URL in the body.
- **Who can prune.** With an archive configured, the `prune` verb is enough. Pruning without an
  archive, or below what `retention` keeps, needs a `*` key.
- **Destinations.** A `retention[].archive` destination must lie under an allowed root
  (`-archive` or `-archive-root`), otherwise the config write gets `422`.
- **Purge reaches archives.** Purging deletes the resource's archives too.
- **Retention runs in the background.** Every `-retention-interval`, as `system:retention`, it
  keeps the last `revisions` or everything newer than `age`, whichever keeps more. Protected
  revisions always stay. A rule with no archive destination, when no `-archive` default exists
  either, prunes irreversibly. `/retention` needs a `*` key, the same authority that may prune
  without an archive.
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
  `at`). It needs `read` and `export`, is checked as an `export` envelope, is rate-limited,
  appends a remote `branch` entry, is listed in `/branches` while unexpired, and protects the
  head as of `at` from pruning for the registration lifetime (`limits.remoteBranchLife`,
  default `P30D`).
- **Branch side (B): mirrored up front.** Before the write transaction, B fetches A's
  namespace log up to `at`, `/heads` as of `at`, every resource's log and the `$schema`/`$ref`
  closure, and verifies them all by recomputing ids; `/heads` must agree with the log. It then
  inserts, in one transaction, a hidden shadow namespace `~{branch}` holding A's chain up to
  `at` and A's revisions with identical ids. The remote branch is a local branch of its
  shadow: read-through, foreign parents and logs work unchanged. History A pruned is mirrored
  from the horizon, whose document is kept as a snapshot (only as trustworthy as the channel,
  §8.6). A failed fetch or verification is `502` with `code: "remote"`, and nothing is written.
- **Schemas** are mirrored under the same paths into a non-branch namespace of that name on B,
  created if missing with the branch's `read`, `keys` and `roles`. A path whose chain neither
  contains A's nor is a prefix of it is `409 name_conflict`; a prefix is extended.
- **What doesn't cross.** Keys and revocations are the branch's own (they stop at the shadow),
  A's rules don't apply, B's purges and namespace purge never contact A, and A's registrations
  never block A's own purges. A private base's branch can't be public (A's `read` at `at`, as
  served).
- **Purges.** B follows A's log (`-remote-follow-interval`, or `Engine.SyncRemotes`) and on
  `purge`/`purge-ns` applies §8.3 locally to the names concerned: its own chains, its own
  branches and cache tags. With `-remote-ignore-purges` they are recorded as notices only
  (`Engine.RemoteNotices`). A purge on B also removes the shadow's copy.
- **Registration.** With `-remote-register`, B registers after creating the branch and renews
  seven days before expiry.
- **Origins.** Both deployments need canonical origins (`-origin`), in https. Plain http is
  accepted only for loopback hosts, so two local servers can try this out
  (`-origin http://localhost:8080` and `http://localhost:8081`).

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
  zeroed once the WAL is checkpointed.
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

### Tree and catalog (Addendum B)

`patchlog tree -catalog cat` follows a catalog namespace and the content namespaces it trusts, and
serves folder listings (`children`, `ancestors`, `subtree`, `roots`, `orphans`, `problems`,
`where`, `manifest`) at URLs pinned to the catalog's `ns_id`. Cycles and depth over 64 show up
under `problems`.

With `-access -key SEED -kid KID` it also issues grants from the tree (§B.11):
- `POST /grants` for content verbs, `create` (genesis only; `409` for a taken name), `place`,
  `move` and unplace, with the no-widening rule.
- `POST /read-grants` returns resource-scoped read grants.

Callers authenticate with an ordinary grant for the catalog namespace, and their groups come only
from that grant. Issued grants carry `at` and are refused once the catalog's `maxLag` is exceeded.

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
- **Snapshot bundles** go through `{ns}-upstream` namespaces. Pinned references between snapshot
  documents are rewritten to them, keeping any `#id` fragment.
- **`-atomic`** lands each namespace as one batch, which needs an allowance for large imports
  (§6.6). **`-pace`** splits batches to fit the limits and paces them for backfills.
- **Branches** export with the base's history included, or with `-foreign-parents` naming the base revisions in `requires`.

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

The spec leaves the grant format open (§C.1). This server uses a Biscuit-like chain of
Ed25519-signed JSON blocks:

```
token = base64url( canonical({ "blocks": [ { "b": block, "next": pk, "sig": sig }, … ], "proof": seed }) )
sig_0 = Ed25519(root key,  "patchlog-grant-v1\n" ‖ canonical(b_0) ‖ "\n" ‖ next_0)
sig_i = Ed25519(sk(next_{i-1}), "patchlog-grant-v1\n" ‖ canonical(b_i) ‖ "\n" ‖ next_i ‖ "\n" ‖ sig_{i-1})
```

`proof` is the private seed for the last `next` key: it lets the holder add a narrowing block,
and its absence makes the stored, non-bearer form (§C.3) useless as a credential. The grant id is
`trunc160(sha256(canonical(root block)))`; a block's revocation id is
`text(trunc160(sha256(signature)))`.

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
namespace's name, or `"*"`, in `ns`.

## Design notes

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
  (wrapped data keys of encryption at rest, Addendum E.1); and
  for §G.3 `remote_branches` (registrations at the source: base, remote origin and name,
  `at`, latest and previous entry, expiry), `remote_bases` (per remote branch: its shadow,
  A's origin, namespace and `at`, the follow checkpoint and the registration at A) and
  `remote_notices` (purges seen in A's log, applied or not).
- **Documents are cached by revision id**, since an id determines its document everywhere
  (§3.3). Head snapshots are kept only for documents up to 16 KiB. An intermediate snapshot is
  written after every 100 revisions or 64 KiB of patch sets, so every read folds from the nearest
  snapshot and never folds more than that (D.4).
- **Allowances** (§6.6): `allowances: [{ sub, kid, rate, burst, itemsPerBatch, batchSize }]` in a
  namespace document gives one principal its own bucket and batch limits. They can go up to the
  deployment maximums, set with `serve -max-items-per-batch` and `-max-batch-size`.
- **Limit names** in a namespace document's `limits` object: `patchSetSize`, `opsPerSet`,
  `documentSize`, `nestingDepth`, `rulesPerNamespace`, `rulesPerGrant`, `grantSize`,
  `itemsPerBatch`, `batchSize`, `liveBranches`, `keepPerResource` (integers, lower only),
  `ratePerResource`, `ratePerPrincipal`, `ratePerNamespace` (`{ rate, burst }`),
  `retryWindow` and `remoteBranchLife` (ISO 8601 durations).
- **A forced schema purge** (`POST …/purge?force=1`, §6.1) needs a `*` key.

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
internal/merge       merge, rebase, status, diff (Addendum F)
internal/janitor     branch cleanup with claim verification (§F.6)
internal/tree        tree service: folders, placements, links, manifests (§B.2–§B.9)
internal/catalog     tree-derived access and grant issuing (§B.11)
internal/bundle      bundle format, export and import (§G.4)
internal/archive     file:// archives for pruning and offline restore (§8.6)
internal/keystore    master key file and key wrapping for encryption at rest (Addendum E.1)
internal/jsonv      I-JSON parsing, JCS canonicalisation, equality
internal/ids        content-addressed ids (§3.2–§3.5)
internal/pointer    JSON Pointer
internal/patch      JSON Patch and the `writes` of §6.4.1
internal/rules      the rule language of §6.4.2
internal/schema     $schema resolution and JSON Schema validation
internal/grant      grants, keys, roles and verification (Addendum C)
internal/core       storage and semantics (gate, batches, branches, purge, prune)
internal/server     HTTP API
```

`go test ./...` runs the unit and HTTP integration tests.
