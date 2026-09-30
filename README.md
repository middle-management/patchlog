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
| Grants (Biscuit v3, §C.8), narrowing, sealing, roles, attributes, key scopes, revocation | Addendum C | ✅ |
| Remote branches: registration (`export`), mirroring with verification, schema mirroring, purge notices, bases that are branches, sealed and e2e bases | §G.3, §G.5.2 | ✅ (mirrored up front) |
| Bundles: history and snapshot export and import, sealed bundles, access levels, e2e ciphertext | §G.4, §G.5.1 | ✅ (`patchlog export/import`) |
| Storage layout | Addendum D.2 | ✅ SQLite (pure Go, `modernc.org/sqlite`) |
| Encryption at rest, cryptographic purge | Addendum E.1 | ✅ (local master key file; KMS adapters to come) |
| Sealed for delivery: epoch keys, JWE responses, `POST /ns/{ns}/keys`, rotation, `$nonce` | Addendum E.2 | ✅ (client library decrypts; other consumers don't re-seal yet) |
| End-to-end: sealed patch sets, header checks, blind rules, fold reads, keyring relay, sealed prune snapshots | Addendum E.3 | ✅ (client library seals, folds, validates and administers keyrings; merge refuses; export and remote branches carry ciphertext) |

### Not implemented

- **Addendum B:** catalog branches (§F.8 preview access and merge grants), a `groups`
  namespace, signed manifests and `x-tree-label` titles.
- **§F.7 merge service** (scheduled merges, web status): not built. Its logic is in
  `internal/merge` and the CLI.
- **Addendum E.3 gaps:** merging or rebasing e2e branches (§F.8: decrypt and re-encrypt in a
  client holding both keyrings) and snapshot bundles of e2e namespaces (§G.5.1: a sealed
  genesis by a key holder) are refused; the client library folds a remote branch's
  read-through ciphertext only when the remote base sealed it itself, not its own bases; retention for e2e
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
- `-resolve name=file.json` replaces a conflicting item's steps with a resolution. A `"keep"`
  resolution is still recorded in the batch with an empty step `[]` (in a sealed namespace, a
  patch set that only adds a fresh `$nonce`), so the batch holds the resource's pair, but only
  when the base's head is live. On a tombstone or an absent resource it gets no item, stays
  unmerged, and is offered again by the next merge.
- The batch's `source.at` is the branch revision the plan was classified from. A `412` retry
  re-classifies against the base's new head but keeps that revision; work the branch got
  meanwhile waits for the next merge.
- Earlier merge batches from the same branch count as common ancestors, so a second merge after
  a replay only picks up what is new. Per resource, the pair comes from the most recent such
  batch with an entry for it. Only batches without `origin`, whose `source.ns` is the branch
  and whose author (root `sub` and `kid`) is listed in the base's `merge.authors` count. With
  authentication disabled entries carry no `kid`, so a kid-less entry matches on `sub` alone
  (development only). Without `merge.authors` there are no such common ancestors: a second
  merge after a replay conflicts, and the tool suggests rebasing (§F.5). `status` and `plan`
  show per resource which batch and author its pair came from, and print a hint when the base
  has no `merge.authors` or the merger (`-bearer`'s root `sub`/`kid`, or `-author`) isn't
  listed.
- The janitor checks `merged` and `successor` claims against both logs before purging (§F.6).
  A `merged` claim needs a merge batch by a principal in the base's `merge.authors`; the
  successor's batch for `superseded` needs no such author, as §F.6 states. Cleanup is opt-in: a
  branch is purged only once a `cleanup` period, from the branch's or the base's document, has
  passed.

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
  `at`). It needs `read` and `export`, is checked as an `export` envelope, is rate-limited,
  appends a remote `branch` entry, is listed in `/branches` while unexpired, and protects the
  head as of `at` from pruning for the registration lifetime (`limits.remoteRegistration`,
  default `P30D`).
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
  created if missing with the branch's `read`, `keys` and `roles`. A path whose chain neither
  contains A's nor is a prefix of it is `409 name_conflict`; a prefix is extended.
- **Encryption (§G.5.2).** B refuses a branch less protected than A's namespace as B reads it: a
  private base needs a private or sealed branch, a sealed base a sealed one (it may be public),
  an e2e base an e2e one. For a sealed base, B fetches keys with its own grant, whose `enc` names
  B's key pair (`-remote-identity https://a.example=b.jwk`), mirrors the plaintext and seals
  what it serves under the branch's own epoch keys. For an e2e base, B mirrors the ciphertext
  and the `keyring` verbatim (ids verified over the ciphertext, nothing folded, no schema
  closure) and relays the keyring's wrapped keys under A's kids; history A pruned can't be
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
  - `…/log?since=` ranges and namespace long-polls: **one** JWE per range, never compressed,
    `pl { ns, range: [since, id] }` (`since` `""` from the start), sealing the JSON array.
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
  (also for a `read: "public"` sealed namespace); with `-dev` anyone gets epoch keys. A grant
  restricted to resources (rules on `/resource`, or a key with `readScope: "resource"`) gets
  `K_r` for each requested resource it may read, others get `K_e` (and `resources` is ignored).
  Epochs run from the one in force at the root block's `nbf` (without `nbf`: the first), capped
  to the last `encryption.historyEpochs`, up to the current one, never one that started at or
  after the grant's effective `exp`; requested epochs outside that are omitted. A root block
  with `"enc": { "kty": "OKP", "crv": "X25519", "x" }` gets keys HPKE-wrapped to it
  (`{ kid, resource?, suite, wrapped }`, `seal.WrapKey`) and never raw ones; narrowing blocks
  can't carry `enc`.
- **`$nonce`.** Every create, append and restore patch set must end up setting `/$nonce` to 128
  fresh random bits (26 base32 characters, `seal.HasFreshNonce`) that differ from the previous
  document's, or it is `422 invalid` — so schemas of sealed namespaces must allow `$nonce`. A
  restore with `[]` is exempt: its id hashes the (public) tombstone id and `[]`, so it reveals
  nothing, and the document it brings back was written with a nonce.
- **Rotation.** A config write incrementing `encryption.epoch` (a `*` key, §7.4) rotates;
  earlier revisions keep their epoch and bytes. `-rotate-epochs 24h` rotates every sealed,
  unfrozen namespace whose epoch is that old, as `system:rotate` (`Engine.RotateEpoch`,
  `Engine.RotateDue`). `-rotate-on-revoke` follows a committed config write that adds to
  `revoked` or removes or changes a key with a rotation of that namespace and its sealed
  branches.
- **Access and branches.** `read: "grant"` still decides who may fetch ciphertext (without it:
  `401`/`404`); a sealed namespace may also be `read: "public"`. A branch of a sealed namespace
  must be sealed (the level rule) and has its own epoch keys, sealing read-through content under
  them; a sealed branch of a sealed non-public base may be `public` (it only exposes
  ciphertext; a relaxation of §7.4). A namespace with public dependents that aren't sealed
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
  `/patches` work. Deletes, config, branch and prune writes are checked as usual.
- **No documents on the server.** No head documents, intermediate snapshots or document cache
  for e2e content; the `$schema` index (§6.1 `in_use`, prune protection) sees nothing, and a
  `$schema` into an e2e namespace is `schema_unavailable`.
- **Reads.** `GET /r/{ns}/{name}` redirects as usual. `GET /r/{ns}/{name}/rev/{id}` answers
  `302` with `X-E2E: fold`, `ETag`/`X-Revision` and `Location:
  /r/{ns}/{name}/rev/{id}/log?since={s}`, where `s` is the latest client-supplied snapshot at or
  before `id` in its ancestry (omitted if none); cached with the long public class (a later
  prune leaves the old target correct; clients restart from the horizon on a `410 pruned`).
  Tombstones and purges answer `410` as usual. The log serves entries as stored (the patch sets
  are the sealed ones). A range whose `since` has a snapshot starts with
  `{ "id": s, "kind": "snapshot", "snapshot": "<JWE>" }`, the document at `s` sealed with `pl
  { ns, name, id: s, kind: "snapshot" }` (for a tombstone horizon: the last live document).
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
  with `pl { ns, name, id: horizon, kind: "snapshot" }` and a known epoch's `kid`) and an archive
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
  and every `kid`/`pl` (the namespace or one of its bases), fold from the snapshot or genesis,
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
under `problems`.

With `-access -key SEED -kid KID` it also issues grants from the tree (§B.11):
- `POST /grants` for content verbs, `create` (genesis only; `409` for a taken name), `place`,
  `move` and unplace, with the no-widening rule.
- `POST /read-grants` returns resource-scoped read grants.

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
- **Snapshot bundles** go through `{ns}-upstream` namespaces. Pinned references between snapshot
  documents are rewritten to them, keeping any `#id` fragment.
- **`-atomic`** lands each namespace as one batch, which needs an allowance for large imports
  (§6.6). **`-pace`** splits batches to fit the limits and paces them for backfills.
- **Branches** export with the base's history included, or with `-foreign-parents` naming the base revisions in `requires`.

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
  (sealed ones sealed, with a fresh `$nonce` in the patch sets the importer makes).
- **E3:** full history carries the ciphertext and the `keyring` verbatim; ids verify over it. It
  imports only into an e2e namespace of the same name (sealed patch sets bind `pl.ns`), which a
  missing target is created as, moved up to the bundle's epochs. Diverged e2e documents can only
  be skipped: comparing or rewriting them needs a client with the keys (§F.8).

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
grant (a grant naming it can only be verified by an operator key; then `404`). Public namespaces
ignore an unusable or unrelated grant on reads.

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
just doesn't apply).

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
  (wrapped data keys of encryption at rest, Addendum E.1), `epoch_keys`, `rev_epochs` and
  `sealed` (sealed namespaces, Addendum E.2); and
  for §G.3 `remote_branches` (registrations at the source: base, remote origin and name,
  `at`, latest and previous entry, expiry), `remote_bases` (per remote branch: its shadow,
  A's origin, namespace and `at`, the follow checkpoint and the registration at A) and
  `remote_notices` (purges seen in A's log, applied or not).
- **Documents are cached by revision id**, since an id determines its document everywhere
  (§3.3). Head snapshots are kept only for documents up to 16 KiB. An intermediate snapshot is
  written after every 100 revisions or 64 KiB of patch sets, so every read folds from the nearest
  snapshot and never folds more than that (D.4).
- **Allowances** (§6.6): `allowances: [{ sub, kid, bucket: { rate, burst }, itemsPerBatch,
  batchSize }]` in a namespace document gives one principal its own bucket (replacing the
  principal and namespace buckets, and a key scope's lower rate) and batch limits. They can go
  up to the deployment maximums, set with `serve -max-items-per-batch` and `-max-batch-size`
  (the flag accepts `64MiB`; the document takes bytes).
- **Limit names** in a namespace document's `limits` object, exactly as §6.6's table:
  `patchSetSize`, `opsPerSet`, `documentSize`, `nestingDepth`, `rulesPerNamespace`,
  `rulesPerGrant`, `grantSize`, `itemsPerBatch`, `batchSize`, `branchesPerNamespace`,
  `keepPerResource` (integers, sizes in bytes, lower only), `ratePerResource`,
  `ratePerPrincipal`, `ratePerNamespace` (`{ rate, burst }`), `retryWindow` and
  `remoteRegistration` (ISO 8601 durations). Sizes written with units (`"64 MiB"`), unknown or
  v0.20 names (`liveBranches`, `remoteBranchLife`) and the deployment-only `logPageSize` and
  `branchDepth` are `422`.
- **Batch limits after authentication** (§7.5): the server authenticates a batch before
  reading its body, and stops reading at the principal's `batchSize` (its allowance's, if any,
  plus room for the batch's own JSON) with `413`. Item counts and the patch-set total are
  checked at step 4.
- **Candidate verbs** (§6.2): a `PATCH` with `If-Match` (in a batch, an item whose first step
  is a patch set) passes step 1 with `append` or `restore`; step 2 settles the verb from the
  resource's state (a branch's view, read-through included) after the idempotent-retry lookup
  and before frozen and the precondition, so a grant that can't restore gets `403` on a
  tombstoned resource, whatever `If-Match` says.
- **Namespace log entries** are `{ …entry, id, prev?, author, created, kid? }`. `author` and
  `created` are stored alongside the hashed entry; `kid` is the key that signed the writer's
  root block, present for entries written under a grant (absent with authentication disabled
  and for entries the server writes itself). Merge tools and the janitor match `author` and
  `kid` against the base's `merge: { authors: [{ sub, kid }] }` (§F.3, §F.6), which the server
  validates and guards with a `*` key like `/keys`.
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
internal/seal        JWE sealing, key derivation, HPKE wrapping, $nonce (Addendum E)
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
