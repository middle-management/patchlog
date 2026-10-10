# Changelog

## Unreleased

- **Postgres: large values compressed with lz4.** Patch sets, documents, namespace entries'
  bodies and blob bytes were compressed with pglz, Postgres's default, which took most of the
  time of inserting revisions. The schema now sets lz4 on those columns where the server has it
  (PostgreSQL 14 or later built with lz4), for databases created before too, once, when opened;
  values written earlier stay as they are, and reads take either. On the synthetic Demo Play
  bundle into Postgres 16 (default settings, fsync on, 10,000/s allowance), inserting revisions
  took 16.3 s and takes 6.9 s, and `patchlog import` of the whole bundle took 39.7 s and takes
  26.6 s (batches 24.2 s to 19.0 s, of which the allowance's pacing is now 6.5 s); of its
  content, 19.6 s and 12.0 s.
- **A batch's schemas read ahead.** A write resolved each distinct schema path its documents
  name with three statements of its own, for the namespace, the resource and its head: a batch
  of the synthetic Demo Play bundle, whose data rows are typed by 1,149 schemas of one
  namespace, resolved about 260 on average. Step 5 now reads the revisions the documents pin by
  `$schema` ahead: the rows of their namespaces in one statement (on Postgres once their locks
  are held, taken in key order), then each namespace's resources and heads in two more, and the
  transaction keeps those namespace rows. Importing the whole bundle into Postgres ran 1.10
  million statements and runs 0.91 million (64,717 reads of a namespace by name are 428, 64,447
  of a resource by name 185, 64,289 of a revision 27, beside 333 new ones reading several at
  once); the server's CPU time in batches went from 19.3 s to 15.1 s, on SQLite from 25.8 s to
  22.4 s.
- **Server: a write's check does each thing once.** Step 3 copied every create's whole document
  out of its patch set, and an append's parent document after parsing it, and hashed each
  revision id again after the idempotent-retry lookup had; step 4 walked each resulting document
  for its depth, again for its strings and pointers and again for `$blob` members, and the blob
  check (on SQLite twice, before the write lock and in it) once more. A create's document is now
  its patch set's value, an append applies to the parent's document as parsed, each id is hashed
  once, and the limits are read in one pass from the document's canonical form, which step 4
  computes for `documentSize` anyway. Ids, stored bytes and the limits' answers are unchanged,
  except that of several strings or pointers over `valueSize` or `pathSize` the one reported no
  longer depends on map order. On the full synthetic bundle (in-process) the check phase uses
  27% less CPU on SQLite (15.1 s to 11.0 s) and 25% less on Postgres (18.5 s to 13.9 s), where
  the benchmark's peak heap went from 4.2 GiB to 3.3 GiB.

## v0.17.0

Bundle import on the shape of a measured deployment. `BenchmarkImportDemoPlay` builds a
synthetic copy from the measurements' document counts and sizes per namespace and kind: 64,887
documents, 1,149 of them schemas in the same namespace as snapshot documents, 48,532 data rows
most typed by them, 18 blobs. Under a 10,000/s allowance into a fresh SQLite target, `patchlog
import` of its content (16,355 documents) took 58.6 s with v0.16.1, 23.3 s with v0.16.2 and
takes 16.4 s, the importer's peak RSS 2.3 GB, 1.7 GB and 0.7 GB; of the whole bundle, 109.9 s,
50.8 s and 39.7 s (31.8 s with `-store-compression zstd`), RSS 3.2 GB, 2.8 GB and 1.5 GB. A
re-run of the whole bundle into the target that has it took 100 s, 12.8 s and takes 10.3 s.

- **Pacing by the allowance's burst.** Concurrent batches waited at the gate as if the bucket held
  nothing to spare, each for the draws of all those in flight: 28.5 s of waits on the whole
  bundle, now 2.5 s. The gate takes the bucket to hold what answered requests left (from one
  token when it starts, refilling to the burst), and sends a request once the server admits it
  and those in flight in whatever order it handles them: once the bucket holds a token more
  than they all draw but the least.
- **Namespaces ordered by pins.** Dependencies between namespaces come from pinned references
  only, as within a namespace: a pin of a full document needs its namespace, a snapshot
  document's pin of a bundled snapshot document its upstream namespace. Live references, which
  name no revision that must exist, made one cycle of a deployment's main namespaces, their data
  and both upstreams, which then went one after another.
- **Part of a bundle: `patchlog import -only ns,…`** imports only those source namespaces; `-ns`
  only maps names, so an import of part of a bundle needed a sub-bundle cut out of it, and asked
  for namespaces it then didn't write (a `403` on one it may not create). The others' documents
  are left out as `external` dependencies are (§G.4.1): before writing anything the import checks
  the target for what its documents reference in them, by id for pinned revisions of full
  documents and by name for live references, and requires a left-out snapshot document that
  they pin to be in its upstream namespace as the bundle has it. Staged imports, the namespaces
  others reference first, leave the target as one whole import does.
- **Server: a create stores its document once.** A resource whose head is its whole-document
  genesis, as after every create and every snapshot an import writes (upstream and target), kept
  the document twice: in its patch set and in `heads`. Reads cut it from the patch set, before
  looking for a heads row, with a scan for the value's end instead of a validation, and writes
  store no heads row for it. On the full synthetic bundle (in-process, file-backed SQLite) the
  database is 32% smaller, the write-locked phase uses 16% less CPU and the batches take 14% less
  time; cold reads of such documents are faster. Databases from earlier versions keep their heads
  rows until the head moves, and earlier versions read the new ones, folding from the genesis.
- **Server: compressed patch sets, opt-in (SQLite).** `patchlog serve -store-compression zstd`
  stores the patch sets of namespaces without encryption zstd-compressed, from 1 KiB and when
  that saves an eighth. They are compressed in the write's check phase, outside the write lock;
  ids, limits and reads stay over the canonical JSON, and heads, snapshots and encrypted
  namespaces are never compressed. On the full synthetic bundle (in-process, file-backed
  SQLite, on top of the change above) the database is 62% smaller, the write-locked phase uses
  17% less CPU and the batches take 12% less time; an uncached read of a created document takes
  47% longer at 15 KiB, 23% at 100 KiB. The synthetic content sets the ratio; real content may
  compress less. It is off by default because it is a one-way format change: earlier versions
  answer 500 for every resource with a compressed patch set, and turning it off again doesn't
  decompress them. The first start with it on records it in the database, and a start without
  it then logs that. Postgres refuses it: TOAST compresses there.
- **Snapshot documents held as their canonical bytes.** The importer kept every snapshot document
  as a parsed tree for the whole import, 1.3 to 5 times the size of its canonical form, though
  after planning it only serialised it again. It now keeps the canonical bytes, which the bundle
  reader computes for the digest anyway, and parses a document again only where planning reads
  it; batch requests are the same, byte for byte. x-ref and x-index walks no longer copy the
  instance location at every member. On the whole bundle (`BenchmarkImportDemoPlay`, two runs
  each, alternating), planning took 11.9–15.7 s and takes 5.8–6.3 s, the import 44.8–49.1 s and
  35.1–37.3 s, and the benchmark process's peak heap, its server's included, went from 3.2–3.3
  GiB to 2.4–2.5 GiB; on its content, planning from 7.3–11.6 s to 2.7–3.8 s.
- **Server: schemas resolved once per write.** A batch's documents typed by the same schemas
  resolved and parsed each for every document and `$ref`; a transaction now keeps what it
  resolved, per writer. Parsed schema revisions are kept by id apart from the document cache,
  which a large write fills with its own documents.

## v0.16.2

Bundle import speed. On a synthetic copy of a CMS deployment's content (6,900 snapshot documents,
121 MB, 350 layouts of 100–450 KB; `BenchmarkImportContent`), a `patchlog import` under a
10,000/s allowance into a fresh SQLite target took 58.6 s with v0.16.1 and takes 18.0 s: planning
27.8 s → 6.0 s. A re-run into a target that has it all took 26.7 s and takes 5.7 s, with 75
requests instead of 13,875.

- **Concurrent batches** (`-concurrency`, `ImportOptions.Concurrency`, default 4). A backfill
  under an allowance submits several batches at once, still in dependency order (§G.4.4): a
  namespace's batches start once those of the namespaces it depends on have committed, and a
  batch waits for one in flight that it goes on with or whose documents it pins. Each request
  waits at its namespace's gate until the allowance's bucket has refilled what the requests
  before it drew. A request in flight counts as drawing no earlier than now, so the server
  handling requests out of order doesn't overdraw the bucket. A namespace has only as many
  batches in flight as the allowance's burst holds the draws of, and, where the allowance ends,
  as its rate draws in half the minute before its `until`, so every batch is sent while it
  holds. The first failure stops the rest: batches waiting to send send nothing. The timings
  count wall time covered, not the sum of overlapping waits and requests. Without an
  allowance, batches go one at a time as before.
- **Ordering by pins.** Within a namespace, items follow the documents they pin (schemas
  included), not live references, which name no revision that must exist. An upstream
  namespace no longer depends on a target namespace that holds only snapshot documents (its
  pins of them point upstream once rewritten), so the two no longer form a cycle. Within a
  cycle, what upstream namespaces need of it (schemas, full documents) goes first, then the
  upstream namespaces (§G.4.4 "Upstream first"); they went by name.
- **Re-runs read nothing they can predict.** An upstream head that is the genesis revision of
  the rewritten snapshot, as an earlier import wrote it, is that snapshot: neither its document
  nor its chain is read. A chain is read only when a fast-forward needs it, and not for a target
  where the previous import left both.
- **Planning.** Patch sets the import already holds as values no longer go through JSON text
  and back for revision ids, sizes and blob scans; each is serialised once. Request bodies are
  written as canonical JSON instead of by reflection. Bundle lines are parsed, and snapshot
  documents' x-ref walks run, on parallel workers. Snapshot documents are rewritten in place
  instead of copied, and reference scans don't format a pointer for every string.
- `patchlog import` reads only the bundle's header before importing, unless `-ns` renames a
  namespace; it read the whole bundle once more first.
- **Server: a create's document isn't serialised twice.** The stored document is cut from its
  patch set's canonical form, and the rules envelope parses the patch set again only when a rule
  reads `patches`. Request bodies from clients are parsed as before.
- **Server: a genesis that adds the whole document is its snapshot** (D.4). It no longer gets an
  intermediate snapshot of its own, which doubled a large create's writes; the count of patch
  sets towards the next starts after it, and a read at the genesis cuts the document from it.
- **Server: rate buckets don't refill backwards.** A request that read the clock before another
  drew on the same bucket took tokens off it as negative time; concurrent requests could be
  answered `429` early.
- `BenchmarkImportContent` imports the synthetic content bundle (`PATCHLOG_CONTENT_SCALE`
  scales it), reporting planning, batch and total time, requests and peak heap.

## v0.16.1

- **Index and tree services: a purged namespace or catalog answers `410 purged` with `head`**,
  its `purge-ns` entry, as the core does (§8.5, §12), after the read check; it was `410 gone`
  before any check.
- **Index and tree services read namespaces unrestricted as §C.5 defines** (B8): one read role
  without rules on `/resource` is enough, so a grant with a rule-free reader role and a role
  testing `/resource` by pattern shares a plain reader's subject set and unfiltered answers,
  where it was filtered per item. `grantcheck.ReadsAll` is gone.
- `bundle import` into a namespace it creates splits and paces batches by the `limits` and the
  importer's `allowances` entry of the document it creates it with, not the §6.6 defaults.
- Outgoing HTTP without a configured client (remote branches, sealed grant export, release
  granters, CDN purges, schema fetches, `patchlog health`, `internal/client`) goes over one
  shared clone of `http.DefaultTransport`, never the default transport itself.

## v0.16.0

Implements spec **v0.49**. v0.47 settles all sixteen of the reference's v0.46 notes, most as
the reference did them; v0.48 adds withdrawing edge-grant cookies, references across
namespaces and namespaces that require nonces; v0.49 settles all twenty of the reference's
notes on those two, most with changes here: purged namespaces, access, nonces, import dry runs
and `/_refs`. Fixes implementer reports B7, B8 and B9.

**Changes to check before upgrading (v0.47, v0.49):**
- **`/ns/{ns}` URLs need unrestricted read** (§C.5): the namespace document, its log, events
  and long-polls, `/heads`, `/branches` and `/grants/…`, everything under `/ns/{ns}` but the
  gestures listing and `POST /ns/{ns}/keys`. A grant that reads only some resources (a key
  with `readScope`, or a rule referring to `/resource` in its blocks, its key's scope or every
  read role it carries) now gets `404` there, as for any read it may not make. `/grants/…` was
  `403`; the others answered it, listing names and heads its reads hide. A resource's own
  event stream needs `read` on that resource only, so per-resource grants can now follow it.
  Roles are alternatives, so one read role without `/resource` rules is enough, also for
  branching, remote registration and a batch's source check, which refused a grant with any
  role testing `/resource`. Branching and registration check read as gate step 1 checks verbs
  (v0.49), in a public namespace too: the grant must allow `read`, read unrestricted and pass
  its rules on `/action`, `/principal` and `/now` with `/action` `read`, leaving rules on
  `/doc` to step 6. Registration on a public namespace didn't check read, and branching a
  public base skipped those rules.
- **A purged namespace answers `410` with `code: "purged"`** (was `gone`) **and `head`**, the
  `ns_id` of its `purge-ns` entry, which is the log's last, so a consumer needn't re-read
  `/ns/{ns}` (§8.5, §12, v0.49):
  - on `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…` (in sealed and e2e namespaces
    too, which answered `404 not_offered`), `POST /ns/{ns}/keys` (`404` before any check) and
    `/heads` at any revision, which listed the resources before; after the read check, the
    grant's rules included, cached with the long class (§9). `/ns/{ns}` and its log stay
    readable: the log's `purge-ns` entry says what happened.
  - on every write, after authorisation and rate limits and before any other check, the
    idempotent-retry lookup included: resource writes, batches, blob uploads and copies,
    purges, prunes, config writes, namespace purges, branching from it and remote
    registration. A batch with a config change is refused only after its items'
    authorisation and its rate-limit draw.
  - The name stays reserved: creating a namespace or branch under it is `412`, also for a
    retry of the request that created a branch since purged, which replayed `200`.
- **Edge grants for grants with roles** (`POST /edge-grants`): one role that lists `read` and
  qualifies (none of its rules refers to `/resource` or `/now`, and they pass now for the
  principal) is enough; the grant's blocks and key scope apply on top and may fix `/resource`.
  A role whose own rules test `/resource` never qualifies, even one fixing it, which 0.15.4
  accepted. The answer is all or nothing: any refused namespace refuses the request, `401` if
  any would be `401`, else `403`, where the first refused namespace used to decide. A purged
  namespace is decided last, once the grant verifies and may read there, and the answer is
  `410 purged`, with the `head` of the first one the grant names, only if every refusal is
  one (v0.49). While authentication is disabled, issuance is `404 not_offered`.
- **`POST /ns/{ns}/keys` refuses as other reads do** (§7, §E.2.3, v0.49): a grant that doesn't
  name the namespace is `403`, as for one that doesn't exist (it was `404`), and is ignored in
  a public one (`401`). A `read` grant whose rules refuse reading the namespace unrestricted,
  and that has no read role referring to `/resource` through which it could get `K_r`, is
  `403` (was `404`): epoch keys open every resource. Without `read` it stays `404`.
- **Schema revisions pinned by a public referrer need no grant** (§6.1, v0.49): a
  `schemaReads` referrer in a listed namespace that is public, and neither sealed nor
  end-to-end, opens the revisions it pins to every request, a grant then being ignored as for
  public reads; without a grant such a read was `401`. Any other referrer, one in a public
  sealed namespace included, needs a grant that names its namespace, verifies there and may
  read it, where a grant naming a public listed namespace counted unverified. Answers stay
  `private, max-age=300`. Whether a revision is open is kept per revision path until a write
  to an open listed namespace or a change of configuration or namespaces, so anonymous reads
  don't scan those namespaces each time.
- **A missing or reused `$nonce` in a sealed namespace is `422 nonce`** (was `422 invalid`;
  §C.7, §E.2.5, v0.49), still at gate step 3, so it gets one code whether the namespace is
  sealed, requires nonces or both. A failed `test` or patch is still reported first, as
  `invalid`.
- **Index `?ref=` queries without `q` or `sort` page by resource name** (§A.4, v0.49): `after`
  is a bare name, any string serving as the bound, and `next` is the `after` of the following
  page, which a client sets on the `at` URL it got, as `/_refs` pages; `after` was an offset
  and `next` a URL. Counts still cover every hit. Other queries keep offsets and `next` URLs,
  and a non-numeric `after` is `400` there. The playground's "More results" follows both.
- **`429` bodies carry `retryAfter`**, the wait in seconds as a decimal (§6.6); `Retry-After`
  stays whole seconds, rounded up. `client.APIError.RetryAfter` prefers the body's.
- `GET /` answers `"spec": "0.49"`.

**Also in v0.47:**
- **`schemaReads` referrer reads reach the origin** (§6.1): a schema revision read by a
  reader of a referrer, with the grant in `Authorization` (none for a public referrer, above),
  is served whether or not the request carries the edge's verification, `private, max-age=300`
  and `no-store` for shared caches, since an edge that knows only prefixes forwards it
  undecided. Behind `-edge-secret` it was `403 edge_required`.
- **`fields=` follows the schemas** (§A.4): a path is checked against the `x-index` marks of
  the schemas the namespace's documents use, not against indexed values, so whether a query
  fails never depends on the data. A marked path no document has values at is accepted and
  left out of hits; an unmarked one is `400`; a schema that can't be read for now is `502`. A
  schema marks a path when an `x-index` is reachable from its root along it, as v0.49 now
  defines: through `$ref`, `$dynamicRef`, `properties`, `patternProperties`,
  `additionalProperties`, `dependentSchemas`, `items`, `prefixItems`, `contains` and every
  branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, never through `not`,
  `propertyNames` or `unevaluated*`, with array items at their array's path.
- **A read under an edge-grant cookie checks its `exp`**, so an event stream opened under one
  (the browser case: `EventSource` can't send `Authorization`) ends there; it kept serving
  past the grant's expiry.
- **A `401` no longer shows which namespaces exist:** a grant whose key a namespace doesn't
  list said `unknown key "<kid>"`, where a namespace that doesn't exist says `no key can
  verify the grant`; both now say the latter, also in `POST /edge-grants`' all-or-nothing
  answer (§C.4, §C.5).
- The text now says what the reference already did: operator grants to a missing namespace
  (`401`, a forced purge `404`), a branch's own `kid` applying again once its base removes the
  same `kid`, index hit values, placement titles over item titles, undoing carried gestures,
  dry runs drawing rate tokens, and allowances matching `sub` alone without authentication.

**New (v0.48):**
- **`DELETE /edge-grants?prefix=…`** withdraws edge-grant cookies at sign-out (§C.5): `prefix`
  repeatable, as issuance returned them (`/r/{ns}/{name}`, `/r/{ns}`, `/ns/{ns}`). It answers
  `204`, `no-store`, with an expired `Set-Cookie` of the same name and attributes per prefix (a
  repeated one once), and needs no grant; it answers the same with authentication disabled,
  so sign-out works either way. Another parameter, a bad prefix or none is `400 bad_input`.
  Its CORS preflight is allowed only for credentialed origins, so another site can't sign a
  reader out.
- **`GET /_refs?to=<reference>`** in the index (§A.4) answers "who uses this?" across every
  namespace the index follows that the reader may read, branch previews included, `to` in
  any form `?ref=` takes. It redirects to `/_refs/at/{at}/g/{gs}?to=…`: `at` is a combined
  checkpoint over only the namespaces the answer covers (the body's `namespaces`), so writes
  elsewhere don't move it. `gs` is computed over markers alone: `reads:{ns}` for each private
  namespace the grant reads unrestricted (one read role without `/resource` rules is enough),
  `reads:{ns}:scope:{digest}` for one it reads in part, the digest covering the rules that
  limit it there and the `/principal` values they refer to. Rules on `/now` there make such a
  namespace unreadable, and readers with no marker share the empty set's `gs`.
  - It leaves out namespaces not reached yet, purged ones, and sealed or e2e ones whose keys
    the index doesn't hold. `?min={ns}:{ns_id}` is repeatable, and `400` for a namespace the
    answer doesn't cover; on an `at` URL, a kept answer whose `at` includes every `min` is
    `200`, otherwise it waits and redirects. Only a reader who may see none of the
    namespaces gets `401` or `403`, and an unreadable namespace document is `502` only for a
    namespace the grant names; any other is left out as private.
  - Hits carry `ns` beside the `?ref=` fields, are filtered per resource and come in byte order
    of namespace, then resource name. A page holds `limit` hits after `after`, given as
    `{ns}/{name}`, and `next` is the following page's `after`, which a client sets on the `at`
    URL. Hits from sealed and e2e namespaces are sealed per entry, and an answer with any is
    served only at its canonical URL.
  - Answers are tagged `idx:{ns}` and `r:{ns}/{name}`, kept a minute as B9's results are, and
    dropped by purges.
- **Namespaces that require nonces** (§C.7): `"nonce": "optional" | "required"`, guarded like
  `keys` (in a branch, a `*` key of the base). Where it is required, gate step 3 refuses a
  resource create, append or restore whose resulting document lacks a fresh-form `$nonce`
  differing from its parent's (the last live document's for a restore) with `422 nonce`, item
  by item in batches and dry runs, whatever the patch set's origin; a `[]` restore sends a
  lone fresh `$nonce` instead. Deletes and config, branch and prune writes are exempt. A
  branch copies the setting and can't turn it off, and a base can't start requiring it while
  a branch at any depth that isn't purged, frozen ones included, doesn't: `409 in_use` with
  `dependents`, leaves first, the order to set them in (v0.49). It is `422` in an e2e
  namespace. A remote branch of a base whose current namespace document requires nonces must
  be created requiring them (`422` otherwise); it isn't a dependent at its base, which may
  start requiring them later. Schema namespaces created to mirror for it start optional,
  since their history keeps its ids, and take their source's setting with a config write by
  the creating operator once it is in; they stay optional if the source's namespace document
  can't be read. A schema document may carry a top-level fresh `$nonce`.
- **Tools add the nonces:** undo and redo give every patch-set step of an inverse a fresh
  `$nonce` where nonces are required (a tombstone's inverse is a lone-nonce restore); merge
  plans add one to kept-at-base steps, resolution and squash sets there and in sealed targets
  (new for resolution and squash sets), and squash diffs leave `$nonce` out. Snapshot imports
  create the upstream namespace with its target's setting and nonce the patch sets they
  generate; a full-history import whose revisions lack nonces is refused before anything is
  written (use snapshot mode). `schema import`, release documents (`internal/release`), the
  release tool's stored plans and locks, and the playground (editor restores and the "add
  `$nonce`" preset, catalog folders and moves, undo, blob uploads) add one too where
  required. A writer whose grant can't read the namespace document (rules on `/resource`,
  §C.5) doesn't know the setting, so in a private namespace undo, `schema import`, the release
  tools and the playground add one to every patch set whose document is an object (v0.49,
  §C.7, §11.2; `client.NeedsNonce`), and undo and redo take the encryption level as unknown
  rather than stopping at the document. Bundle imports need the target's namespace documents
  anyway. The playground's catalog panel adds one in sealed catalogs too.

**Also in v0.49:**
- The text now says what the reference already did: edge-grant prefixes are the cookie paths
  (`/r/{ns}/{name}`, `/r/{ns}`, `/ns/{ns}`), `DELETE /edge-grants`' answers, with `prefix` the
  core's one repeatable parameter, `POST /ns/{ns}/keys` serving grants limited per resource,
  a schema document's fresh `$nonce`, the operator creating an import's missing namespaces,
  and what marks a path with `x-index` (above).

**Faster bundle imports, again (B7).** A backfill dry-ran every batch before submitting it,
and a dry run draws the tokens its submit does (§6.6), so each batch paid twice, half of it
in `429` waits:
- **Dry runs:** an import dry-runs only the first batch of each existing target namespace,
  before anything is written, and submits the rest directly: a batch is atomic, so a failed
  submit writes nothing either, and it lists its items as a dry run did. In a namespace the
  import creates, the first item of the first batch is dry-run once the namespace exists, so
  a server that would give the revisions other ids stops the import before anything is
  written there. A later batch that moves heads the target had (a fast-forward, a resolved
  conflict, a restore; not a snapshot's diffs upstream, which no live reference sees) is
  dry-run before its submit, its blobs sent first, since a failure after it would leave
  those heads moved (§G.4.4, v0.49). An import that fast-forwards existing documents pays a
  dry run per such batch, about 20 s per 1,000 items at `-pace 1`; fresh imports pay none.
  `-dry-run` dry-runs the same batches, but for one that goes on with a chain an earlier
  batch cut, reports failures that only need earlier batches written as deferred, uploads no
  blobs (they show as deferred `blob` failures) and writes nothing. A batch that fails only
  for blobs left to its local source is sent again with them uploaded.
- **Pacing** counts every draw (dry runs, submits, blob uploads) with or without an
  allowance, paces dry runs too, and repays a chain cut between batches at
  `ratePerResource`, for its submit and its dry run alike, which an allowance doesn't
  replace (§G.4.4). After a `429` the importer waits by the body's `retryAfter`.
- At `-pace 1` a 1,000-item batch takes about 20 s instead of about 39 s, with no `429`s;
  under a 1,000/s allowance about 1.5 s instead of about 2 s. The reported import (64,887 documents
  in 145 batches into an empty deployment at `-pace 1`, no allowance) drew 894 tokens a batch
  at the principal's 50/s and took 55 min; it now takes about 22 min plus blob uploads. That
  is the floor the default `ratePerPrincipal` sets (64,887 / 50 = 1,298 s): only an allowance
  or a higher `ratePerPrincipal` lowers it, and under a 1,000/s allowance the import takes a
  few minutes.
- The report gains `timings` (planning, blobs, batch requests, paced, after `429`s), which
  the CLI prints as a `time` line. `TooLargeError`, `import -h` and `serve -h` name the
  deployment maximums (`serve -max-items-per-batch`, `-max-batch-size`), and a `401` or `403`
  on the first read of a target namespace says what grant the import needs: read and write in
  every target namespace; an operator grant only creates namespaces, so create missing ones
  first.
- Planning drops a `/heads` listing that answers `410` (a purged namespace) and looks the
  names up, as for a frozen one. `BenchmarkImport` runs against the default limits, adds 6 KB
  documents and reports per batch the batch requests' time, paced waits and `429` waits.

**Edge grants for catalog readers (B8).** A catalog read grant for a reader holding a
rule-free reader role and roles that test `/resource` by pattern was `403` at
`POST /edge-grants`; with roles as alternatives (above) it gets the item's prefix.

**Index answers stay at their checkpoint (B9).** A query redirected to `/{ns}/at/{current}`
was redirected again whenever a write moved the checkpoint before the reader followed it, so
under steady writes readers chased it. The redirect now computes the result at the checkpoint
it names and keeps it, as every result computed or served is kept: in memory, for a minute, at
most 64 MiB, keyed by the result's URL (namespace, `at`, query and the reader's subject set,
and for a sealed namespace the view the result is bound to). A kept result answers its `at`
with `200` however far the checkpoint has moved, so a query takes one redirect from the head
pointer and at most two from a stale `at`; the query's cost moves to the redirect. A purge
drops the kept results showing what it purged.
- Measured (`TestHopsUnderWrites`): at 40 writes/s and 4 readers, 2.7% of follows took two
  redirects on 0.15.4; with 20,000 documents, 200 writes/s and 16 readers, 8% were still
  redirected after five. Now every follow takes exactly one, also while purges of documents
  the queries don't show are applied.
- 0.15.4 redirected more than 0.15.2 because B6 made queries far cheaper: readers make many
  more follows, each racing the same checkpoint rate. Apply batch sizes didn't change.
- **Tree and catalog listings too** (v0.49, §A.4, §B.5): the tree service keeps every listing
  it computes, the one at the `at` a redirect names included, for a minute (at most 64 MiB per
  catalog), so one redirect suffices at any write rate, and an older `at` answers `200` while
  its listing is kept instead of `302`. Listings are keyed by their URL (subject set and
  sealing view included) and by what the reader reads whole, so a reader whose
  namespace-wide reads changed since (a public namespace turned private) isn't served one
  kept from before; listings that depend on the individual reader aren't kept, and sealed
  ones are served only at their canonical URL. A purge drops the kept listings it purged
  (`r:{ns}/{name}`, `ns:{ns}`, `rs:{catalog}`). The index, `/_refs` and the tree service share
  this store (`internal/kept`).
- **Consumers learn a purge from `/heads`** (§8.5, §10): `internal/follow` takes its
  `410 purged` (when starting from a snapshot, or for a branch purged before it got there) as
  the namespace's `purge-ns` entry, at the position the `410`'s `head` names (v0.49; it reads
  `/ns/{ns}` for it when there is none), reports the purge and ends with `ErrPurged`. The
  follower was restarted, or the branch reported failing, indefinitely; the index now answers
  `410` for such a branch.

## v0.15.4

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
