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
| Pruning with horizons, protected revisions and kept documents | §8.6 | ✅ (no archive, see below) |
| Cache-Control classes and cache tags | §9 | ✅ (CDN purges go to a pluggable `Purger`, default: log) |
| Grants, narrowing, roles, attributes, key scopes, revocation | Addendum C | ✅ |
| Storage layout | Addendum D.2 | ✅ SQLite (pure Go, `modernc.org/sqlite`) |

### Not implemented

- **Addenda A, B, F** (indexing, catalog/tree service, merge service): these are separate
  consumer services built on the public API; nothing in the core is missing for them.
- **Addendum E** (encryption): a namespace document with `encryption` is rejected with `422`.
- **Addendum G** (federation): remote branches, `export`, bundles and pruning archives.
  Because no archive destination exists, **pruning always needs a grant chained to a `*` key**
  (§8.6), and `retention` policies are validated and stored but not applied automatically.
- CDN edge grants (§C.5): the origin checks grants itself on every read and sets
  `Cache-Control: private` plus `CDN-Cache-Control` for non-public namespaces.
- Author signatures (§C.3): a `Signature` header is stored with the revision and returned
  in the log, but not verified.

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

- **One write transaction at a time.** Every write runs its whole gate (§6.2) inside one
  `BEGIN IMMEDIATE` transaction, also serialised by an in-process mutex. The configuration,
  heads and revocations a write is checked against are exactly those it is inserted against,
  so invariant 6 holds trivially, also across processes sharing the database file. D.3 moves
  validation outside the lock and re-checks instead; that is an optimisation this
  implementation does not make yet.
- **Additions to the D.2 layout**: `namespaces.head_seq/config_seq/base_config_seq`,
  `ns_log.body` (the canonical entry exactly as hashed) and `ns_log.config_seq`,
  `ns_config.doc`, `revisions.signature/schema_ref`, `resources.keep`, and `heads.seq`.
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
  `ratePerResource`, `ratePerPrincipal`, `ratePerNamespace` (`{ rate, burst }`) and
  `retryWindow` (an ISO 8601 duration).
- **A forced schema purge** (`POST …/purge?force=1`, §6.1) needs a `*` key.

## Layout

```
cmd/patchlog        CLI: serve, keygen, grant mint/narrow
internal/playground web UI served at /playground/
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
