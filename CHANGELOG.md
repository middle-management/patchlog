# Changelog

## Unreleased

**Faster bundle imports.** A backfill spent nearly all its time sleeping: it paces at half
the lower of the namespace and principal rates (25 items/s at default limits), 40 s per
1,000-item batch, against about half a second of work.
- **Under an allowance** (§6.6) the importer now paces at the allowance's full rate, since its
  bucket holds up no other writer, and splits batches by its `itemsPerBatch`/`batchSize`. It
  finds its own allowance as the core does (the grant's root `sub` and `kid`, or the author
  with authentication disabled), counts every draw (dry runs, uploads, copies) so it doesn't
  run into 429s, and from a minute before the allowance's `until` goes back to the
  namespace's limits. With an allowance of 1,000 items/s, 2,000 documents wait 3.5 s instead
  of 80 s; 145,000 would take minutes instead of over an hour. Without one, pacing is as
  before, less the time each batch took. Progress lines say what the import is paced by.
- **Planning** reads target heads from `/heads` pages instead of one `GET` per document
  (twice in snapshot mode): 0.005–0.014 requests per document instead of 1–2. A small import
  into a large namespace keeps per-document lookups.
- `BenchmarkImport` (`internal/bundle`) measures an import's work, requests per document and
  the time it would sleep.

The client's requests use a connection pool of their own, a clone of
`http.DefaultTransport`, so code that closes the default one's idle connections doesn't
break them.

## v0.15.3

**Index queries cost what their matches cost (B6).** Every index query read the namespace's
documents in order and tested each against its facets, ranges and `?ref=`, so a facet
matching 100 of 48.7k documents read all of them, and with `sort=` sorted them all. A query
is now driven by its most selective filter when that pays: its matches are read from the
filter's index and looked up, and the other filters tested per document. Which filter drives
is decided by a bounded count on the index, and the plan doesn't depend on SQLite's
statistics. On 48.7k documents, one query / 50 at once:

| query | before | after |
|---|---|---|
| `facet[/accountId]=…` | 109 ms / 6.2 s | 9.4 ms / 0.57 s |
| … `&sort=/accountId` | 237 ms / 17.2 s | 9.7 ms / 0.64 s |
| … `&counts=…` | 602 ms / 29.8 s | 10 ms / 1.15 s |
| … `&q=…` | 5.4 s / 193 s | 137 ms / 10.8 s |
| `ref=…` | 3.9 s / 421 s | 10 ms / 0.76 s |
| a facet with 5,000 values | 7.2 s | 39 ms |
| `ge[/score]=500&lt[/score]=501` | 289 ms | 3.7 ms |

Queries with no selective filter (a plain listing, a facet most documents match) scan as
before. The index replaces `refs_q` with `refs_t`, which leads with the namespace; it is
built when the index opens (about a second per 500k references).

**Development:** CI runs the race detector in jobs of its own; tests run in parallel
(`t.Parallel()`); and Postgres tests reuse migrated databases from a pool, emptied between
tests, instead of creating one each (`internal/pgtest`). CI takes about 2 minutes instead of
5.

## v0.15.2

**Performance**, follow-ups from the v0.15.1 review:
- **Branch `/heads` pages** looked up the branch's base namespace once per name that reads
  through. A read transaction now reads each namespace row once: a branch page takes 27–33 ms
  instead of 161–164 ms on Postgres (a branch of a branch, 34–38 ms instead of 288–297), and
  20–29 ms instead of 36–38 ms on SQLite.
- **The index's `-fetch-concurrency`** now limits fetches across all followed namespaces
  and branches together, not per namespace: `-ns a,b,c` sent up to 24 GETs at once to the
  core (whose Postgres pool has 16 connections) and now sends at most 8. It must be at least
  1.
- **The index reuses its connections** to the core: its client keeps an idle connection per
  fetch (new `client.WithIdleConns`), where `http.DefaultTransport` kept 2 and redialled the
  rest after every page. Catching up 3 × 2,000 documents opened 8–12 connections instead of
  1,500–2,100, at the same speed.

## v0.15.1

**Performance** (found by profiling with the new OpenTelemetry spans). End to end, against
v0.15.0 on a shared 4-CPU box, mixed reads (head pointers, revisions, logs, `/heads`) went
from 557 to 1,552 requests/s on SQLite and from 549 to 1,015 on Postgres, with p99 down from
281 to 66 ms and from 248 to 68 ms:
- **Namespace log pages** resolved each entry's `prev` with its own query (one per entry, a
  round trip each on Postgres). They now come from the page's own rows: a page takes 18 ms
  instead of 160 ms on Postgres, and 13 ms instead of 48 ms on SQLite.
- **`/heads` on SQLite** now batches its lookups as Postgres already did: 48 ms instead of
  218 ms per page.
- **The index** fetches a page's documents concurrently (`-fetch-concurrency`, default 8)
  instead of one at a time, applying them in log order as before. On Postgres under steady
  writes its lag fell from about 950 ms (max 2.6 s) to 24 ms, and `?min` reads no longer
  time out with `503`. The trade-off: it now keeps up, so its reads compete with writers, and
  write throughput with the index and tree following fell by about 23% in that test; lower
  `-fetch-concurrency` trades freshness back.
- **Authenticated reads** now use the read cache once the request is authorised (it served
  only public namespaces before), and verified grants are cached by token, keeping only
  grants that verified. Warm authenticated reads take 0.8 ms instead of 1.3 ms, and the
  authenticated workload ran 29% faster. Authorisation still runs on every request, and
  cache-control is unchanged.

**Build:**
- **Smaller release binaries:** releases, the Docker image and `make build` build with
  grpc-go's `grpcnotrace` tag. It drops gRPC's own request tracing (`golang.org/x/net/trace`,
  off unless `grpc.EnableTracing` is set, which nothing here does), and with it
  `html/template` and `text/template`, whose reflection disabled the linker's dead-code
  elimination. OTLP export over gRPC and HTTP is unchanged. linux/amd64 is 28.4 MB (32.2 MB
  in v0.15.0), linux/arm64 26.7 MB (30.3 MB), darwin/arm64 27.5 MB (31.2 MB),
  windows/amd64 29.0 MB (32.8 MB). A plain `go build`/`go install` works the same, about
  3.8 MB larger.

## v0.15.0

Implements spec **v0.46**, which adopts most of Doors' feedback, fixes the server bugs
Doors reported, and adds OpenTelemetry.

**Changes to check before upgrading:**
- **Keys follow the base both ways:** a branch now accepts keys added to its base after
  it was created (recursively through local bases); a kid both have is the base's entry
  only (§C.4).
- **Operator grants** authorise only creating namespaces (remote branches included) and
  forced purges. A request under one to a namespace that doesn't exist is now `401`, not
  `404` (a forced purge still gets `404`).
- **The gestures listing** answers any reader, filtered to resources its grant may read
  (§7.4); a `?after` naming a resource it can't read is `404`.
- **Unfreezing a branch** whose base already has `branchesPerNamespace` live branches is
  `422 limit`; frozen branches no longer count toward the limit (Doors B3).
- **CORS:** `-cors-origin '*'` with credentials no longer echoes an arbitrary origin;
  credentialed origins are listed with `-cors-credentials-origin`.
- **Tree database** gains an `items.title` column, and **index database** a `sort.raw`
  column; both are added or rebuilt on start.
- `GET /` answers `"spec": "0.46"`.

**New (v0.46):**
- `schemaReads: { for }` in a namespace document: its schema revisions resolve for writes
  in the listed namespaces that pin them, and can be read by revision path by readers of
  documents pinning them, without a grant on the namespace (§6.1).
- `POST /edge-grants` issues edge grants as `Secure`, `HttpOnly` cookies per prefix, which
  the origin verifies itself when no edge is in front (`-edge-grant-key`, else derived from
  `-edge-secret`); cookies authorise only `GET`/`HEAD` under their prefix (§C.5).
- Catalog: `?min` on `POST /grants` and `/read-grants`; a `title` pointer copied into
  listings; `inheritPowers` in `$access` (§B.5, §B.11).
- Index: schema documents indexed under their dialect, with their `$ref`s as references;
  `self: true` on self-references; hits carry sort values and `fields=` (§A).
- Client: undo stacks count a merged gesture for its source author, and `Undo` with
  `UndoAuthor` finds it (§11.2). Bundles look up keys through a branch's bases.

**OpenTelemetry** (off unless `OTEL_*` exporters are configured): traces and metrics over
OTLP (gRPC or HTTP), console output, W3C propagation; route-named HTTP server spans for
`serve` and every service, client spans on outbound calls, engine write spans
(`core.WriteResource`, `core.Batch`, …), transaction spans, and metrics for writes,
group-commit sizes, Postgres lock waits and consumer lag. See the README's Observability
section; `compose.yaml` has an optional Jaeger profile (`--profile otel`). No measurable
cost when off; the binary grows by about 11 MB (the OpenTelemetry SDK, protobuf and gRPC
libraries; the gRPC exporters themselves are about 0.4 MB of it).

**Fixes (reported by Doors):**
- The index's `?min=` redirect could bounce between two checkpoints during an update;
  redirects now follow the committed checkpoint and only move forward (B1).
- `schema_unavailable` named the dialect URL instead of the unresolved pin; it now names
  the revision path. A schema document could `$ref` a revision the writer can't read once
  the validator had cached it; read permission is now checked on the whole closure (B2).
- The standalone tree service left heads and URLs out of listings for grants reading only
  some resources of a content namespace (B4).
- The batch retry lookup read every batch the author had written; it now looks up one
  resource's history (5,000 earlier batches: 24.8 → 0.5 ms per batch on SQLite) (B5).

## v0.14.1

Implements spec **v0.45**, which settles the reference's remaining notes from v0.42 and
v0.44. Nothing changes in behaviour: the text now says what the reference already does.
`GET /` answers `"spec": "0.45"`.

## v0.14.0

Implements spec **v0.44**: reverse-reference queries in the indexing service (Addendum A).

**New:**
- The index collects every `x-ref` reference of typed documents by §6.5's walk, with the
  schema revision each document pins (no `x-index` needed), into a new `refs` table.
- `?ref=/r/{ns}/{name}` finds the documents that reference a resource in any form;
  `…/rev/{id}` only those pinned to that revision; `…%23{entry}` only those naming that
  entry. It combines with the other filters, and hits carry `refs: [{ path, ref }]`.
  Malformed or repeated `ref` is `400`.
- An index database from before v0.44 is rebuilt once at startup, so its references are
  collected.
- `GET /` answers `"spec": "0.44"`.

## v0.13.0

Implements spec **v0.43**, small fixes from the reference's v0.42 notes.

**Changes to check before upgrading:**
- **An operator key authorises only within its period:** grants it signed are refused
  before its `from` as well as after its `until` (§C.4). A key configured with
  `-operator-key` and no history entry is unaffected.
- `GET /` answers `"spec": "0.43"`.

The other v0.43 changes state what the reference already did: grants in sealed namespaces
are sealed under the epoch of the first entry recording them, repeated query parameters are
`400`, and a bundle line whose writing namespace is unknown carries neither `written` nor
`grant`.

## v0.12.0

Implements spec **v0.42**, which settles the reference's v0.41 notes on signatures.

**Changes to check before upgrading:**
- **Unknown query parameters are `400 bad_input`** on every core endpoint, before
  authentication, as are repeated parameters and flag values other than `1`
  (`dry-run=true` used to be ignored and the write made).
- **The gestures listing pages with `?after=`**, as §7.4 says; it took `?since=`. The Go
  client and the playground follow.
- **Author signatures are checked at §6.2 step 2.3**, after rate limits, the retry lookup
  and settling the verb: an idempotent retry is answered as first recorded whatever
  signature it carries, even after `required` was turned on; `403` and `429` come before
  `422`; a dry run reports `422 signature` per item; a write without a usable precondition
  gets `428`/`400`. A batch whose config change is stale fails with that change's `412`.
- **`GET /ns/{ns}/grants/{gid}`** is offered in sealed namespaces (sealed, `pl: { ns, grant }`,
  stored once) and end-to-end ones (clear, `Cache-Control: private`), and is `410` once the
  namespace is purged; `not_offered` is gone. `client.Grant` opens sealed answers.
- **An operator key past its `until` authorises nothing**; it used to be accepted after it.
- `GET /` answers `"spec": "0.42"`.

**Bundles and archives:**
- A grant line's `ns` is the namespace whose entry first recorded the grant; `key` is
  optional, looked up in the namespace document at that entry, then the operator key history
  at the first naming revision's `created`, and left out otherwise.
- History lines for revisions written elsewhere (a branch's read-through, a remote branch's
  base) carry `written`, used in the signing input, so branch bundles verify.
- Sealed and end-to-end exports carry grant lines (`ExportOptions.Bearer`/`Identity` for
  sealed grants); a grant the exporter can't fetch is left off the lines that would name it.
- Pruning archives (§8.6) carry authors and grant lines; restore skips them.

**Performance:**
- **Heads pages on Postgres take a few statements, not three per resource.** A page now
  reads its resources, their heads at `at` (one `LATERAL` join on `head_history`) and those
  revisions in one statement each per namespace level, and resolves from memory.

## v0.11.1

**Fixes:**
- **`GET /ns/{ns}/rev/{at}/heads` pages in time proportional to the page, not the
  namespace.** Each page used to list every name and resolve every head at `at`, and only
  then page, so listing a namespace cost O(N²): about 14 s for 20 000 documents on SQLite
  and 14 minutes for 50 000 on Postgres. A page now takes its names from the `(ns, name)`
  index after the cursor, in byte order (on Postgres, a new `name COLLATE "C"` index),
  and resolves only those. Names with no head at `at` are skipped by fetching further
  chunks. Reported by an implementer.

## v0.11.0

Implements spec **v0.41**: verifiable author signatures (§C.3.1), adopted from the
reference's proposal P1.

**Changes to check before upgrading:**
- **Signatures whose kid the grant lists are now verified** at the end of §6.2 step 1,
  before rate limits: `422 signature`. A malformed `Signature` is `400`, and so is a
  `Signature` header on a batch request (steps carry their own `signature`).
- **Grants:** a root block may list `signers`; a narrowing block carrying it, or a malformed
  entry, makes the grant invalid (`401`).
- Every batch step now stores its own signature; only an item's first step used to.
- `GET /` answers `"spec": "0.41"` and adds `jwks_uri`.

**New:**
- `"signatures": "optional" | "required"` namespace-document member, guarded by a `*` key
  (of the base, in branches). Under `required` every revision and tombstone needs a valid
  signature by a signer of its grant.
- Resource logs and write responses serve each revision's `grant: { id, sub, kid }`.
- `GET /ns/{ns}/grants/{gid}` serves stored grants (`{ id, root, stored }`), including those
  of local bases up to their `at`; `404 not_offered` in sealed and end-to-end namespaces.
- `/.well-known/patchlog-keys`: the operator key history as a JWK Set (`serve
  -operator-key-history`, `-jwks-uri`).
- Go client: `WithSigner`, `SignWrite`, `Step.Signature`, `Client.Grant`, `OperatorKeys`.
- Bundles with authors carry grant lines (with the key each verified against) and a `grant`
  member on history lines; `patchlog bundle verify -signatures [-source URL]` reports
  verified / attested / failed / unsigned / unverifiable per revision.
- `patchlog import`, `merge` (plan/apply/release) and `rebase` sign their own steps with
  `-sign-key kid:seed` or `$PATCHLOG_SIGN_KEY`.

## v0.10.0

Also implements spec **v0.40**, which adopts most of the reference's v0.39 notes.
Two came out the other way, and the reference now follows the text:

**Changes to check before upgrading:**
- **A batch's config change costs a rate token** from the principal and namespace
  buckets unless it is exempt (a `*` key, or only a freeze), as a config write does
  (§6.6). A config-only batch used to cost nothing.
- **A branch of a non-public base can't be `public`, sealed or not** (§7.4), and
  remote branches likewise. A public sealed branch also counts again as a
  dependent that keeps its base from going private (`409 in_use`). Existing public
  sealed branches of private bases are left as they are.
- `GET /` answers `"spec": "0.40"`.


A conformance review against spec v0.39. **This repository is the reference
implementation; the specification is maintained outside it and `docs/SPEC.md`
mirrors that text (see the note at the top of the README).**
[docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) states the reference's positions
the mirror doesn't yet describe. The changes below fix the implementation to
match the spec as written.

**Fixed:**
- **The gate order of §6.2 now holds on every namespace-level write.** An
  unauthenticated caller answers `401` for resource writes, batches, `PATCH /ns`,
  branch creation, remote registration, purge, namespace purge and prune, whatever
  preconditions it omitted and whatever purged state the namespace is in (they were
  allowed to elicit `428` or `410` first). A valid grant without the verb now
  answers `403` before a purged namespace's `410`, which itself comes before the
  precondition's `428` — the order v0.32 pinned for blob uploads.
- **A config-stale batch's idempotent retry draws its rate tokens** (§6.6): the
  whole-batch replay answered `200` without the step-1 draw, so a client could
  re-send it for free.
- **§9's cache classes** on the answers the pagination work had missed: a non-live
  `/log` range's `404` is `short` and its purged `410` is `long`; an unknown id of
  `GET /ns/{ns}/rev/{id}` and `/heads` is `short` (`public, max-age=5`, or
  `private, max-age=5` at the edge) instead of `no-store`.
- **A batch's body-limit step no longer pre-empts the gate:** the purged-namespace
  `410` it answered before the items were authorised moved to the gate proper, so a
  batch's `400`/`403`/`410` report follows §6.2's order.
- A grant with `exp` exactly at an epoch's start is given that epoch's key
  (`POST /ns/{ns}/keys`, §E.2.3 reads "started after").
- Loopback origins accept the whole `127.0.0.0/8`, as §G.3 says (was only
  `localhost`, `127.0.0.1`, `[::1]`).
- The static `x-ref` walk finds references under `propertyNames` and `contentSchema`
  (§6.5), so exports and reverse-reference consumers no longer drop them.

**Added:**
- **A config write may carry `Gesture` and `Undoes`** (§7.2, §7.4): a config entry
  is a single write, so its headers are validated (`400` otherwise),
  stored with the entry outside its id, mixed into what its log entry serves, and
  echoed on the response — a retry answers with what was recorded. This was
  previously ignored silently.

## v0.9.0

Implements spec **v0.39**: gestures for undo and redo.

**Added:**
- **Gestures (§7.2).** Writes may carry `Gesture` and `Undoes` headers (26 base32 characters, `400` otherwise), stored with each revision or tombstone as metadata outside its id; retries answer with what was first recorded. Batch steps may be `{ "patches" | "delete": true, "gesture"?, "undoes"? }`, with item and batch defaults. Resource and namespace logs serve them (`gestures` per step for batches), pruning keeps them, and CORS allows and exposes both headers.
- `GET /ns/{ns}/gestures/{gesture}` lists a gesture's revisions and undos, paged, for readers of the whole namespace; not offered (`404`) in sealed and e2e namespaces.
- Merges carry each replayed revision's gesture (squashing drops them); bundles with `"authors": true` carry them too.
- **Undo and redo (§11.2)** in the Go client: `PlanUndo`, `Undo`, `Redo` and `UndoStack`. The inverse of a gesture's own entries, widened to whole arrays, is checked against the later log for overlapping writes (`ConflictError`) and written as one batch guarded by `ifMatch` with a fresh gesture and `Undoes`; pruned history, missing blobs and schema migrations are reported as `ImpossibleError`. Works for plaintext, sealed and (with `UndoE2E`) e2e namespaces, using the endpoint or a log scan.
- The playground sends a gesture per save, shows gestures in history and the namespace log, and has undo/redo for the current author (plaintext and sealed namespaces).

**Changes to check before upgrading:**
- `client.Delete` takes write options (`…, head string, opts ...WriteOption`) and returns a `*WriteResult`.

## v0.8.0

Implements spec **v0.38**.

**Changes to check before upgrading:**
- **`GET /`** answers `{ "spec": "0.38", "auth": "grants" | "disabled", "origin" }`. Merge, release and janitor tools read the mode from it; `client.WithAuthDisabled` is gone and the tools' `-dev` flag is accepted but ignored.
- **Entries written with authentication disabled record `"grant": null`.** While a deployment runs `disabled`, `merge.authors` and `abandoned` checks match them on their author; under `grants` they count for no one. Entries written in dev mode before this release serve no `grant` and count for no one, so a merge batch or `abandoned` flag written then must be written again.
- **Namespace-document errors** are `422` `code: "invalid"` with `errors: [{ pointer, message }]` (no `path`).
- **E3 prune snapshots** are served at `/rev/{H}` (`200 application/jose`, `X-E2E: snapshot`; a tombstone horizon answers `410` with the snapshot in the body) and are never log entries. Readers fold from `/rev/{H}` plus the range after it.
- **Catalog restore** answers in the spec's order (`404`, `410`, `403`, `409`) and refuses (`403`) a restore that would widen access compared with the item's state at deletion; catalog admins may still restore. Moves of deleted placements are checked like any other move.

**Added:**
- The addenda's namespace-document members (`catalog`, `catalogs.{catalog}`, `merge`, `merged`, `cleanup`) may carry `x-` members; a write may remove a member only an earlier version defined.
- Remote branches ignore members of the base's documents they don't define, whatever the base's spec version.
- Catalog visibility evaluates a role's rules as a read would (the spec's `translator` example now sees its items), counts roles only through subjects the catalog's key may assert, and is pinned to the listing's checkpoint. Grants are issued through those subjects only.
- A reader with namespace-wide read on the namespaces a manifest, `problems` or `orphans` answer covers gets it, without needing every trusted namespace.
- Schema namespaces mirrored for a remote branch record the creating operator's grant.

## v0.7.0

Implements spec **v0.36** and **v0.37**.

**Changes to check before upgrading:**
- **Namespace documents are strict (§7.4).** Only the members the spec defines are accepted (`read`, `keys`, `roles`, `revoked`, `rules`, `limits`, `allowances`, `retention`, `encryption`, `maxLag`, `base`, `frozen`, `successor`, `drafts`, `catalog`, `catalogs`, `merge`, `merged`, `cleanup`, `abandoned`); any other member must start with `x-` (`422` otherwise). Documents stored by earlier versions are served as they are, and a write that leaves such a member unchanged keeps it; rename with `{"op":"move","from":"/title","path":"/x-title"}`. A new branch can't inherit an undefined member. Addendum members are now checked in their shapes, `revoked` entries must be revocation ids, and key entries refuse `x-` fields.
- **Log ranges are paged (§7.1).** `…/rev/{id}/log?since=` answers at most the log page size (default 1,000, `serve -log-page-size`) with `X-Log-Next` when the range goes on. Every bundled client follows pages; other clients must too, and treat a page that stops short without `X-Log-Next` as an error.
- **Namespace log entries carry `grant: {id, sub, kid}`** instead of `kid` (§7.4). Existing databases are migrated: head, tombstone and batch entries get the grant their revisions recorded; older config, branch, purge, purge-ns and prune entries serve none. The merger and janitor match `merge.authors` against the recorded grant: an `abandoned` flag set before the upgrade must be set again, and in dev mode tools must be told so (`client.WithAuthDisabled`, implied by `-author`).
- A retry of a write to a purged resource is `410` (was `200` from the retry lookup, or `409`/`412`).
- `schema import` no longer adds `$schema` to closed schemas, since validation ignores it now (below); `-declare-schema` restores that for servers before this release.
- `tree -release` serves one catalog.
- Catalog listings follow §B.11.5's visibility exactly: folders are visible only through roles without rules, and `problems`, `orphans`, `manifest` and unfiltered `g/all` listings need namespace-wide `read`.

**Added:**
- Validation leaves out a document's top-level `$schema` and a top-level `$nonce` of the fresh-nonce form (§6.2 step 5), so closed schemas type documents as they are; reference walks, annotations, the e2e client and the playground validate the same instance.
- Restore a deleted item through the catalog (`want: ["restore"]`), decided by the roles frozen when it was deleted (§B.11.4).
- Release previews follow the release document live (§B.5); the playground relists with `?min` after its own writes.
- `GET /` answers `{ "spec": "0.37", "origin" }`; remote-branch creation refuses a base of a later version whose documents hold members this version doesn't know.
- `PATCH /ns` answers with `X-Namespace-Revision` and a body `{ config, ns_id }`.
- Blobs can be uploaded to a deleted resource before the restore that references them.
- `/heads` is in byte order of name on both backends.
- `serve`, `index` and `tree` speak HTTP/2 without TLS (h2c) as well as HTTP/1.1 (§7.7). CORS exposes `X-Log-Next`; with `*`, every response carries the allowance.
- **Postgres group commit per namespace** (D.8): under contention, checked writes of one namespace are committed together in one transaction (`-group-commit`, default 32; `-group-commit-wait`). Throughput in one namespace keeps rising with load instead of falling. `-group-commit 1` keeps the old behaviour.

**Fixed:**
- Event streams catch up a page per fetch instead of reading the whole history at once.

## v0.6.0

Implements spec **v0.35**: a delete's rule envelope carries the document being deleted.

**Changes to check before upgrading:**
- The rule envelope of a `delete` now carries the document being deleted as `doc` (before, `null`). A rule that relied on `/doc` being absent for deletes (e.g. `test /doc exists: false` to single out deletes) now behaves differently; test `/action` instead. Rules about a document's shape should exempt `delete`, or documents written under earlier rules can't be deleted.
- A batch item with two `"delete"` steps in a row is now `422 invalid` (it was `410`).

**Added:**
- Rules can decide deletes by content, e.g. only a document's owner may delete it (§6.4.1, §6.4.4). `doc` is read through the bases in a branch, and in a batch it is the document after the item's earlier steps. At E3 `doc` stays `null`, so a delete rule reading `/doc` refuses there. `purge`, `purge-ns` and `read` keep `doc: null`.
- Unplace grants from the catalog service fix `/doc/parents` to the placement's current parents, so it can't be moved before it is deleted (§B.11.4).

**Fixed:**
- A resource's event stream could end without its `purge` event when the purge committed between the stream's two reads (seen on Postgres).

## v0.5.0

Implements spec **v0.34**: feedback from implementing v0.33 (drafts, `in_use`, release tooling, D.8 locking).

**Changes to check before upgrading:**
- Forcing a purge refused as `in_use` (`?force=1`) now needs a grant chained to a deployment operator key (`serve -operator-key`), or, for a purge of a branch or of a resource in one, a `*` key of that branch. A `*` key of a namespace that isn't a branch no longer forces.
- Schema paths in another namespace are now read by the rule for other namespaces (§7.5): the request's grant or a `Source-Authorization` grant must name that namespace and verify under its keys. A grant naming only the namespace written no longer reads schemas in another private namespace.
- `drafts` is `422` in remote branches (and their branches) and in e2e branches.
- Catalog merge grants: the catalog service needs `-merge-key`, `-merge-kid` and `-merge-service`, and issues merge grants only to the merge service; list `{ "sub": <merge service>, "kid": <merge key> }` and every catalog admin who approves `$access` changes in the catalog base's `merge.authors`. `merge.MergeGranter` returns a `*MergeGrantResult`.
- Release plans now carry a digest: plans stored by v0.4.0 must be planned and approved again before `apply`.

### Spec v0.34: drafts and other namespaces (§6.1, §7.4, §7.5)

- **One rule reads other namespaces**, for batch sources, blob copies, drafts and the schema's own namespace: the request's grant or any `Source-Authorization` grant that names the namespace, verifies under its keys and allows the read (a public namespace needs none). Blob copies used the header's grants only when it was present; now either serves. A path `N` can't resolve for the writer, absent or unreadable, falls through to drafts (as before for absent; now also for unreadable by this rule).
- **`drafts`**: `"*"` serves every namespace; `422` outside local branches that aren't e2e; not inherited: branch creation drops `drafts`, `merged` and `abandoned` (besides `frozen` and `successor`). **`GET /ns/{ns}/branches` shows each branch's `drafts`.**
- **Client:** `Branch.Drafts`; `ResolveOptions.For` applies the candidates' visible `drafts.for` for the namespace a document is in (best effort; the index's schema cache and e2e validation pass it). `DraftsMatch`.
- **Exports** needing a draft fail with `bundle.ErrSchemaUnavailable` (`schema_unavailable`), unless the schema's namespace is declared external, when the export walks the draft's content (same everywhere) and the importer checks the target.

### Spec v0.34: forcing `in_use` (§3.5, §6.1, §8.5)

- `?force=1` with a deployment operator key (whose grant then acts without the namespace's rules), or a branch's `*` key for purges in that branch, on `POST /r/{ns}/{name}/purge` and `POST /ns/{ns}/purge`.
- **`forced: true`** on every entry a purge that overrode an `in_use` refusal writes, propagated ones included, in the hashed entry (`internal/verify`, `client.NSEntry.Forced`, remote-branch mirroring). A purge nothing refused isn't marked.
- The `referencing` list names the referencing namespaces in which the caller may read anything (one readable resource suffices), with the request's grant or any `Source-Authorization` grant (now passed on purges and config writes).

### Spec v0.34: releases and catalogs (§F.9, §F.8, §F.6, §B.11.4)

- **Plan digest** (`merge.PlanDigest`, `ReleasePlan.Digest`, `ReleaseStep.Digest`): over the release revision and, per step, every item with its precondition and plaintext steps, `$nonce` values left out, the second half of a split node as `"after": {step, key, item}`. `approve` fails unless planning again gives the stored digest (and `-digest`, if given: `ErrDigest`); `apply` rebuilds each step before submitting it and stops for a new approval if it differs (`ErrPlanChanged`).
- **Catalog merge grants** (`POST /merge-grants`): signed with a dedicated merge key (`catalog.Options.MergeKey/MergeKid/MergeService/MergeTTL`, `tree -merge-key -merge-kid -merge-service -merge-ttl`), only for the merge service, whose grant is the `Authorization`; the approver's grant (`Approver-Authorization`) is checked. Root `sub` the merge service, `attrs.approvedBy` the approver, no groups, rules exactly the batch's `/resource` and `/action` pairs, five minutes by default.
- **`$access` changes** are checked as a dry run and answered `{ "admin": true }`; the merge service submits them under the approver's (a catalog admin's) grant narrowed with its own `via`, the batch's actions and pairs (`ReleaseOptions.AdminGrant`, `Via`; `merge release -merge-bearer`).
- **Folder creation** (§B.11.4): `POST /grants {node, want: ["create"], to}` needs `move` on every folder in `to` and refuses `$access` for non-admins; in merge batches a new folder needs `move` on its parents (was `place`), and tree powers on a folder come only from its own `$access` (admins may enter one nobody holds powers on yet).
- **Step 2** creates a folder a narrowing move needs with its own `$access`, in one piece (no stripped "folder" halves); `catalog.Powers` and `StripPowers` are gone. Tombstoned schema resources merge in step 1. A `placed_item` is fine if step 2 removes the placement.
- **`merged.at`** is the target's `ns_id` after the last batch into it (for the catalog, step 4's), not its head when merged is recorded.
- **`abandoned`** (§F.6): the janitor verifies it (set by a config write under a `*` key of the branch, its own or a base's) and purges after `cleanup.abandoned`; `merge.AbandonRelease` / `patchlog merge release abandon` freeze every branch with it.
- Release previews (§B.5) already hid unreadable branches; the release lock and the release document's optional `at` already matched the definitions (documented).

### D.8 (Postgres)

- **A separate advisory log lock**, `pg_advisory_xact_lock(0x504e, ns)`, taken last and held through commit, orders namespace entries, replacing `SELECT … FOR NO KEY UPDATE` on the namespace row. Several are taken in ascending order (purge propagation, branch creation); a transaction holding one never waits for a namespace lock. Throughput (`-bench 'CreatesOneNamespace|Batch1000'`, interleaved runs, medians, before → after): 166 → 161 writes/s from one writer, 503 → 508 from 8, 431 → 464 from 32, 395 → 473 from 64; a 1,000-item batch 272 → 265 ms.
- **Blob uploads** keep the namespace lock shared; an uploader's pending total is now ordered by a row of its own (`blob_uploaders`): concurrent uploads by one uploader could together exceed `blobPending` before.


### Schema import

- **`schema import` keeps closed blueprints usable and remembers their source.** (1) A typed document's `$schema` is validated against the schema it names (§6.1), so a schema closed at the root (`additionalProperties: false`, `unevaluatedProperties: false`) rejected every document using it; the import didn't add the declaration. For every imported resource the subschemas applying at the instance root (the root, and what it reaches through `$ref` within and across resources, `allOf`, and every branch of `anyOf`/`oneOf`/`if`/`then`/`else`) that are closed now get `"$schema": {"type": "string"}` in `properties`, unless `properties` or a matching `patternProperties` already covers it. This is reported as a conversion (`declared $schema in N closed schemas…`, also in `-json` and the playground plan); a patched subschema also used below the root (a shared `$defs` entry) permits a `$schema` key there too, which is reported; one with `maxProperties`, or a `propertyNames` that rejects `$schema`, is left alone with a warning. `-no-declare-schema` (`Options.NoDeclareSchema`) opts out. (2) `$id` can't be kept (§6.1), so each imported resource's root, and each document bundled under `$defs` for a cycle, now carries `"x-source"` (fetched URL or upload name) and, when the document declared a different `$id` or draft-04 `id`, `"x-source-id"`. Both change content and so revision ids: re-running an import of schemas imported with v0.4.0 appends new revisions to each (and to what pins them); after that, re-runs are idempotent again.

## v0.4.0

Implements spec **v0.33**: schema drafts in branches and releases across namespaces. Also search and schema import in the playground, `patchlog schema import`, and graceful shutdown with health endpoints.

**Changes to check before upgrading:**
- A purge (resource or namespace) that would remove the last available copy of a schema revision that documents still reference is now refused with `409 in_use`. Override with `?force=1` and a `*` key.
- `Source-Authorization` may be repeated; any grant in it that verifies for a namespace serves for it.
- `serve`, `index` and `tree` now drain on SIGTERM (default `-shutdown-timeout 30s`). Give containers a stop grace period longer than that.
- Varnish probes moved to `/_health`.

### Search in the playground

- **Playground:** a **Search** tab queries the index service (Addendum A): a namespace, `q`, `schema`, facet and range filters, `sort`, `counts`, `limit` and paging. Hits show the resource, schema, score, facets and revision, and open in the Resource tab. The checkpoint the index redirected the query to is shown. "Wait for my last write" passes `min=` with the page's last `X-Namespace-Revision` for the namespace. Sealed results (§E.2.6), whole or per hit, are decrypted with the playground's keys; end-to-end namespaces get a note, and a core without an index says so.
- **`serve -index-url URL`:** mounts a read-only proxy to one index service (it serves several namespaces) at `/playground/index/`, like `-tree-url` does for the tree service: `GET`/`HEAD` only, `Authorization` forwarded, cookies and upstream CORS headers dropped, a sandbox CSP, the index's checkpoint redirects rewritten under the prefix, and a two-minute response timeout for `?min=` waits. The two proxies share one implementation.
- **compose:** `compose.yaml`, `compose.host.yaml` and `compose.postgres.yaml` pass `-index-url`, so the demo stack's Search tab finds the seeded `demo` documents.
- **Compose:** the index runs with `-branches`, so branches made in the demo (e.g. from the playground) get their own searchable preview index.

### Schema import

- **`patchlog schema import`:** brings external JSON Schemas (http(s) URLs such as schemastore.org, or local files) into a namespace as schema resources, so documents can use them under §6.1. It fetches every document they `$ref` (base URIs per JSON Schema, `$id` in subschemas, draft-04 `id`), converts them to draft 2020-12 as the server accepts it (`definitions`, array `items`, `dependencies`, boolean `exclusiveMaximum`; unknown keywords become `x-*`), and rewrites every `$ref` to a same-document pointer or a pinned revision path plus JSON Pointer, anchors resolved to pointers. Revision ids are predicted client-side so schemas are written leaves first; reference cycles are merged into one resource under `$defs`. Every schema is compiled before writing, then all are written in one atomic batch (chunked beyond the batch limits). Re-running with unchanged sources writes nothing; a changed source appends. `-name`, `-dry-run`, `-json`, `-max-docs`, `-max-bytes`, `-timeout`. See "Importing external schemas" in the README.
- **Playground:** a **Schemas** tab imports external JSON Schemas from the browser. `POST /playground/schema-import/plan` (`{ns, sources, files, name?}`) runs the `schema import` plan without writing (per document: source, resource, action create/append/restore/unchanged, predicted revision path, rewritten schema, warnings, merged cycles) and returns the batches to write; it reads current heads in process with the request's own `Authorization`/`X-Author`, so a caller plans against what they may read, and uploaded files resolve relative `$ref`s by file name. The tab plans, shows the table and each rewritten schema, then writes the plan itself through `POST /ns/{ns}/batch` with the user's grant (chunked beyond the limits), checks the server-assigned ids against the predicted ones, and shows the root's pinned `$schema` path with a copy button and a "start in the Resource editor" button.
- **`serve -schema-fetch` / `-schema-fetch-hosts`:** URL fetching by the plan endpoint is off by default (uploaded files only). `-schema-fetch` enables it; `-schema-fetch-hosts a,b` limits it to those hosts (redirects and references included), which are also trusted with private addresses. Other hosts are refused when any resolved address is loopback, private, link-local, CGNAT, multicast or unspecified (checked at dial time, connecting to the checked address; environment proxies are ignored). The demo composes enable it for schemastore and raw.githubusercontent.com.
- **`internal/schemaimport`:** `Options.Files`/`NoDisk` plan from in-memory files; `Result.Chunks`, `Resource.Item`/`WireItem` and `BatchLimits` separate planning from writing; `GuardedClient`/`DisabledClient` are the fetch guards.

### Graceful shutdown and health

- **Graceful shutdown** for `serve`, `index` and `tree`. On SIGTERM/SIGINT a server drains (health answers 503, keep-alives off), keeps serving for `-shutdown-delay` (default 0), then stops listening and waits up to `-shutdown-timeout` (default 30s) for requests in flight. Long-polls answer their normal `204` at once, event streams end, and `?min=` waits answer as if they had run out, instead of holding shutdown up. Only when the timeout expires are the remaining requests cancelled, so their transactions roll back; the core's database is closed, and the purge queue flushed, only after every handler has returned. Previously a fixed 5 s timeout closed the database under running handlers. A second signal exits at once. Each phase is logged with the requests it waited for or cancelled.
- **Health endpoints** on all three servers: `GET /_health` (200 `{"status":"ok"}`, 503 `{"status":"draining"}` once shutdown starts; no database access) and `GET /_ready` (also 503 if the core can't reach its database). Both are `no-store` for browsers and CDNs. The `_` prefix can't collide with a namespace or catalog name.
- **`patchlog health [URL]`:** exits 0 if the endpoint answers 200, for container healthchecks without curl or wget.
- **Compose:** healthchecks for the core, index and tree use `patchlog health`; they pass `-shutdown-timeout=20s` and stop with `stop_grace_period: 30s`; the CDN waits for all three origins to be healthy. `compose.host.yaml` keeps healthchecks off (those hosts refuse `docker exec`) and its seed polls `/_health`. The Varnish backend probes read `/_health`, so a draining origin leaves rotation, and health paths are never cached.
- **Core:** `Engine.Ping` (the `/_ready` check), and `Options.BeforeCommit`, a test hook that runs in every write transaction just before it commits.

### Spec v0.33: schema drafts in branches

- **Spec v0.33, core (§6.1, §7.4):** draft schema revisions in branches. In a write to a branch, a `$schema`/`$ref` path its namespace can't resolve is looked up among that namespace's local, non-e2e branches (branches of branches included, own revisions only) that serve the target: the branch itself and its branches, plus the namespaces a new `drafts: {"for": [...]}` member lists (names or `prefix*`) and their branches. The writer needs `read` there, with the request's grant or any grant of `Source-Authorization`, which may now be repeated everywhere it's read (resource writes, batches, blob copies). Paths naming a branch stay `422 schema_ref`; namespaces that aren't branches still resolve only in the path's namespace. Batches to a branch can reference schemas drafted by their earlier items.
- **`in_use` by last copy (§6.1):** references count every revision a branch wrote, and are satisfied by any available copy (in the path's namespace, or in a candidate branch serving the referencing branch). A resource or namespace purge that would remove the last such copy, narrowing `drafts.for`, or raising a draft branch to `e2e` is `409 in_use`, listing the `referencing` namespaces the caller can read. `?force=1` with a `*` key overrides purges, now also for namespace purges. On Postgres a purge locks other copy holders shared (D.8), so concurrent purges of the last two copies can't both succeed. The `revisions` index on `id` is renamed `revisions_by_id` (D.2) on both databases.
- **Federation and bundles (§G.3, §G.4):** creating a remote branch whose documents reference a draft is `422 schema_unavailable`; `patchlog export` refuses such a document with an error naming the branch.
- **Client:** `WithSourceAuthorization`, `WithSourceGrants`, `BatchRequest.SourceAuthorizations` and `CopyBlobWith` send several `Source-Authorization` grants; `ResolveSchema`, `SchemaResolver`, `FindDraft` and `IsBranch` find drafts as validating consumers must. The search index's schema cache resolves drafts for documents of branches; e2e merges validate as the target's gate would (`E2E.ValidateIn`); bundle imports find draft schemas for `x-ref` walks.

### Spec v0.33: releases across namespaces

- **Spec v0.33, release tooling (§F.9):** releases across namespaces.
  - **Release documents** (`internal/release`): `Doc` (`name`, `at`, `branches: {base: {ns, at}}`, `on`, `owners`, unknown fields kept), `Parse`/`Validate`, `ParseRef`, `Load` (live or pinned link, through the client) and `Write`.
  - **`patchlog merge release plan|approve|apply|status`** (`merge.PlanRelease`, `ApproveRelease`, `ApplyRelease`): the four-step merge: schema resources by fast-forward only in `$ref` order, catalog changes that narrow access (the §B.11.4 test on the step-2 batch as a whole; folders a narrowing move needs are created without roles carrying `place`/`move`, which step 4 adds), content branches, then catalog changes that widen access. Conflicts are reported before anything is submitted: `schema_changed`, `narrows_and_widens` (resolved with `-split KEY/NODE=narrow.json`, two halves), `step2_widens`, `placed_item` (`-accept-placement`), `dangling_pin`, `foreign_draft`, `schema_unavailable`, `merge` (content resolutions with `-resolve KEY/NAME=file.json`), and the pre-approval `base_chain`, `frozen`, `purged`. The plan is stored as `{release}.merge` in the release document's namespace (`-state-ns`) with the release revision; approval freezes every listed branch and records its config id; unfreezing a branch or changing the release document invalidates the plan; each step is classified again with a dry run before it is submitted and recorded when done, so `apply` resumes and never reverts; every branch records `merged` only after step 4. One release per catalog base at a time: a lock resource `merge-lock.{catalog}` in the state namespace.
  - **Catalog merge grants (§F.8):** the catalog service's `POST /merge-grants` folds a catalog branch's merge batch onto the base, checks every item as in §B.11.4 (`$access` needs the admin group; placements, moves with no widening, unplacing and edits need the tree powers; a new folder needs `place` on its parents) and signs one grant whose root is the caller under the catalog's key and whose rules allow exactly the batch's resources and actions. The release merge submits steps 2 and 4 under it (`merge.HTTPGranter`, `-catalog-service CAT=URL`), so the catalog's `merge.authors` lists the merging person with the catalog's `kid`.
  - **`patchlog merge release rebase -suffix S`** (`merge.RebaseRelease`): successors of every branch, schema branches first with `drafts.for` naming the other successors in their creation patches; resources whose entries reference a replayed draft are squashed onto its new revision; old branches are switched; a new revision of the release document lists the successors.
  - **Release previews (§B.5):** `tree.Options.Branches` / `patchlog tree -release LINK` follows the listed branches in place of their bases (bootstrapped from their `/heads` at their first entry, `follow.AsBranch`): checkpoints, the combined checkpoint, cache tags, `/_status`, item `url`s and read checks use the branches, so a viewer sees only branches it can read; previews only, no grants.
  - **Janitor:** draft branches (with `drafts`, or holding schema documents and listed by a `-release`) are purged after every other branch; a purge refused with `in_use` is retried at the end of the sweep, then reported as `retry`, never forced.
  - **Merge library:** `Options.SourceAuthorizations` and `Options.BatchClient`, `Plan.Order`, `Plan.Force` (an item for a resource that classifies as merged through a partial merge point), `Plan.SetBatchClient`, `RebaseOptions.Patches` and `Prepare`; `catalog.DiffAccess`, `Powers`, `StripPowers`, `ParseIncludes`; `tree.BuildGraph`, `Graph.With`, `Graph.Actual`, `Graph.ItemHref`.

## v0.3.3

CORS fixes: dev-mode writes and resumed blob downloads from other origins.

- **CORS:** `X-Author` (the author under `serve -dev`) and `If-Range` are allowed in requests, and `X-E2E` is exposed in responses.
- **Tests:** two index tests no longer race the index's checkpoint against the batch they inspect (seen once under `-race` in CI).

## v0.3.2

CORS for the servers, for demos and apps on other origins.

- **CORS** for `serve`, `index` and `tree`, for demos and apps on other origins:
  - `-cors-origin` (repeatable or comma-separated, or `*`) or `PATCHLOG_CORS_ORIGINS`.
  - Preflights are answered by the server; the headers the API reads (`Authorization`, `If-Match`, `Blob-From`, …) are allowed and the ones it sets (`ETag`, `Location`, `X-Namespace-Revision`, …) exposed.
  - With a list of origins, responses say `Vary: Origin`, so the CDN keeps one copy per origin; `*` keeps one for all.
  - `-cors-credentials` for pages that send cookies (grants travel in `Authorization` and don't need it); `-cors-max-age`.
  - The compose files pass `PATCHLOG_CORS_ORIGINS` through.

## v0.3.1

Faster writes on both databases. On Postgres, writes to different resources of one namespace now run in parallel.

### Postgres: writes in one namespace run in parallel

- Resource writes and batches hold their namespace's lock shared. Config writes, purges, prunes, branch operations and blob uploads still take it exclusively.
- Only the namespace-log append is serialized: two statements and the commit, under the namespace row's lock.
- Two writers racing on one resource still give one success and a 412 with the new head. A write that keeps losing retries with the namespace locked exclusively, so every write finishes.
- Every write is now checked inside its own transaction (`LockedCheckBytes` 0).
- Batches insert their rows in multi-row statements.
- Missing resources are cached within a transaction.
- The counts that decide intermediate snapshots live on the resource row.
- New columns, migrated on startup: `namespaces.head_id`, `resources.snap_revs`, `resources.snap_bytes`.

### CPU, both databases

- Blob-reference walks skip documents without `$blob`.
- Canonical key sorting compares ASCII names bytewise.
- Each document's and patch set's canonical form is computed once.

### Measured (4 vCPUs shared with the database, fsync on)

Writes/s, p99 in brackets, for 20–70 KiB creates into one namespace:

| | 1 writer | 8 | 32 | 64 | 1,000-create batch |
|---|---|---|---|---|---|
| Postgres, v0.3.0 | 35 (51 ms) | 51 (228 ms) | 52 (1,376 ms) | 54 (3,225 ms) | 2,623 ms |
| Postgres, now | 161 (11 ms) | 438–500 (40–60 ms) | 350 (282 ms) | 343 (799 ms) | 330 ms |
| SQLite, v0.3.0 | 43 (45 ms) | 81 (154 ms) | 98 (419 ms) | 108 (887 ms) | 1,079 ms |
| SQLite, now | 381 (18 ms) | 669 (32 ms) | 664 (83 ms) | 721 (118 ms) | 252 ms |

## v0.3.0

Implements spec **v0.32** (`docs/SPEC.md`). Blobs are now complete across every namespace level and tool, blob bytes live on disk, and writes on Postgres are faster.

### Blobs everywhere

- **Sealed namespaces (E2):** `GET …/blob/{bid}` redirects (`302`) to `…/blob/{bid}/e/{e}`, which serves the blob in the binary sealed form (`application/vnd.patchlog.sealed-blob`, zero-padded). Each epoch's sealing is stored once; the first instance to store it wins. A blob is served under exactly the epochs of the revisions that reference it. A request for a blob whose revisions have no epoch yet fixes one under the current epoch.
- **End-to-end namespaces (E3):** clients encrypt each blob under its own key, which travels in the sealed reference. Each `sealed` op declares in plaintext the blobs its document references. The server checks those lists (`blobsPerDocument`, availability, sealed type, no duplicates) and uses them for attaching, pruning, purge and bundles. Readers flag revisions whose list differs from the document.
- **Merges** keep E3 blob ids and carry the declared lists over.
- **Bundles** export blob lines and import them: blobs are uploaded, or copied with `Blob-From` within one deployment, before the batches that need them. Sealed bundles seal blob lines like any other line.
- **Archives:** restore brings back the blobs that pruning ended.
- **Remote branches** mirror their base's blobs up front, from plaintext, sealed and E3 bases, and check each one against its id.
- **Playground:** blob references show as chips with previews (images, text), open and download. An "Attach file" control uploads files into public, sealed (with `Blob-Nonce`) and E3 namespaces (encrypted in the browser).
- **Go client:** `GetBlobRef`, `EncryptBlob`/`DecryptBlob`, `E2E.UploadBlob`/`GetBlob`.

### Blob storage on disk

- Blob bytes are stored as files: `serve -blob-dir DIR` or `PATCHLOG_BLOB_DIR`. A SQLite file database defaults to `<db>.blobs/`.
- Each file is written and fsynced before its row commits, and deleted only after the commit that frees it. Every stored copy has its own name, so a cleanup can't delete a concurrent re-upload. A sweep on the leader removes orphan files.
- Range requests read only their range. Bytes encrypted at rest are still per-resource and decrypted whole.
- **Postgres:** several instances must share the directory. Without `-blob-dir`, Postgres keeps bytes in the database and logs a line at startup.
- Rows that the earlier table stored keep working; no migration is needed. Back up the database and the blob directory together.

### Postgres

- **Faster writes:** a small write sends 16 statements instead of about 32. That's 2.9 ms instead of 4.4 ms on a local `postgres:16` with fsync on, and 0.9 ms instead of 1.34 ms when writing in parallel.
  - Small writes are checked inside their namespace's lock, skipping the separate check transaction.
  - Author and namespace ids are cached.
  - Rows are reused within a transaction.
  - A few queries were merged.
- **A second CDN purge:** a durable queue (`cdn_repurge`) sends every CDN tag purge again once no stale instance or replica can still serve the old content.
- **Leader checks:** background jobs confirm they still hold leadership before each step.
- A retried transaction no longer draws rate-limit tokens twice.

### Spec v0.32 behaviour changes

- **Blob upload order (`PUT`):** a purged namespace answers `410` after authorisation and rate limits. A copy with a body or an unreadable `Blob-From` is `400` before anything is read.
- **Pending uploads:** a write that references a blob ends every pending upload of it in that resource, including blobs already attached.
- **Batch `source`:** a bad `source.at` is `422` with the new code `source`. It is checked only for callers who may read the source; for anyone else, the source makes no blobs available.
- **Dry runs** report missing blobs and carry on with the later steps.
- **E3 prune** no longer takes a `blobs` list: the server already keeps every revision's declared list. Clients sort declared lists by binary id.
- **Bundles:** a blob line comes before the first line that mentions the blob (`test` values included). A local import doesn't copy blobs that the batch's `source` already covers. E3 blob lines must have the sealed type and no nonce.
- **Clients** decrypt a sealed blob only when it was served through `…/e/{e}`.
- The merge tool reports batches whose `source.at` isn't in the branch's chain.

### Fixes

- `TestLongPollWakes` no longer fails when a long-poll's cursor boundary falls inside the test's pause.

### Known gaps

- Importing a private or sealed source into an E3 target (re-encrypting blobs) isn't implemented.
- No resumable uploads.
- Restoring an archive of a namespace encrypted at rest deadlocks on an in-memory SQLite database. File databases and Postgres are unaffected.
