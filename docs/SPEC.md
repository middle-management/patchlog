# Patch Log — Specification

Status: draft v0.43 · 2026-10-06. See the change log at the end.

**Scope.** The core (§1–§13) specifies identity, validation, rules, the HTTP API, caching, deletion, namespaces, atomic batches and branches for collaboratively edited JSON documents. It is implementation-neutral. The addenda cover the rest:

- **Addendum A (suggested):** indexing.

- **Addendum B (suggested):** organising documents in separate catalog namespaces, and tree-derived access.

- **Addendum C (recommended):** capabilities and access.

- **Addendum D:** the reference implementation (Bun + SQLite), with its storage layout, sizing and status.

- **Addendum E (optional):** encryption at rest, sealed delivery and end-to-end.

- **Addendum F (suggested):** working with branches: merge, rebase and cleanup.

- **Addendum G (suggested):** federation and portability: external consumers, remote branches, and export and import bundles.

The key words MUST, SHOULD and MAY are used in their RFC 2119 sense.

---

## 1. Overview

A **resource** is not stored as a document. It is an **append-only log of patch sets**. Each entry is a **revision** whose id is a content hash of its parent id and its patches. The document is always *derived* by folding the patch sets from the first revision.

Validation is **opt-in per document**. If the document produced by a patch set has a `$schema` key, the result MUST validate against that schema. Documents without `$schema` are stored, versioned, cached and deletable just the same, but are not validated. Schemas are themselves resources, and `$schema` points at an immutable schema revision. The schema a revision was validated against is therefore part of the revision's own hashed content.

Multiple editors read and write the same resource. Writes are compare-and-append on the head (HTTP `If-Match`). A stale writer gets `412`, pulls the new revisions, re-applies its patches on the new head and retries.

Everything addressed by a revision id is immutable and cacheable for a long time. Only two things change over time: the **head pointer** (a micro-cached redirect) and the **event stream**.

Several resources of one namespace can be changed together in an atomic **batch**. A **branch** is a namespace created from another at a point in its history: it reads everything through from that snapshot and records only its own changes, which can later be applied to the original as one batch.

Large values, such as images, PDFs or long texts, are **blobs**: immutable bytes attached to a resource, served from their own immutable URLs, and referenced from its documents by id.

### Goals

- Multi-user editing with no silent overwrites.

- Every revision whose document declares a `$schema` is valid against it. Full history, independently verifiable.

- Schema-less documents are equally first-class for storage, caching and collaboration.

- CDN-first reads: the origin serves head pointers and writes, and not much else.

- Minimal moving parts.

### Non-goals (for now)

- Character-level real-time merging (OT/CRDT). Conflicts are resolved by rebase and retry, optionally guarded by JSON Patch `test` ops.

- Transactions across namespaces. A namespace is the unit of atomicity: batches are atomic within one namespace (§7.5), and never across several.

### Conformance

- **A core server** implements §1–§10 and §12 (§11 is non-normative, and §13 lists open questions). Where the core refers to an addendum, it does so only for features a deployment offers, and a server that doesn't offer one degrades as follows:

  - **Addendum C** (grants) is how the core authenticates (§6.2 step 1). A server without it runs with authentication disabled, which is for development only (§7.2): every request then counts as holding a `*` key, so config guards and forced purges are open, and config writes skip namespace rules as `*`-key writes do (§6.4.3); resource writes are still checked. Entries written while authentication is disabled record `"grant": null`, and grant references recorded earlier are still served. `GET /` says which mode a deployment runs in (`"auth": "grants"` or `"disabled"`, §7). While a deployment runs `disabled`, checks that match `merge.authors` (§F.3, §F.6) match an entry with `grant: null` on its author's `sub` alone, and the janitor's `*`-key check for `abandoned` accepts it. Under `grants`, such entries count for no one, so nothing written without authentication is trusted in production. Entries without `grant` at all, written by the server or before v0.37, count for no one.

  - **Addendum E** (encryption) is optional. A server without it refuses `encryption` in namespace documents (`422`), so no namespace is sealed or end-to-end, and every rule the core states for them is vacuous.

  - **Branches** (§7.6) are core, so draft schemas in branches (§6.1) are too. A server can refuse to create branches (`403` for every `branch` grant), and §6.1's draft lookup then never finds a candidate.

  - **Addenda A, B, F and G** describe services and tools built on the public API. A core server needs nothing from them beyond the hooks the core defines for them: `remote` branch entries, the `export` verb, `source` in batches and `GET /`.

  - **Addendum D** describes one implementation and isn't normative.

- **Byte-exact definitions,** such as ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9) and padding buckets (§E.2.2), must agree between implementations. Test vectors for them are planned (§13).

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **Namespace** (`ns`) | A group of resources sharing a namespace log. A namespace is itself versioned: its **namespace document** holds its configuration (rules, keys, limits). |
| **Config revision** | A revision of the namespace document, with its own content-addressed id. |
| **Resource** | A named, versioned JSON document inside a namespace, addressed `{ns}/{name}` (§3.6). |
| **Patch set** | An ordered array of JSON Patch operations (RFC 6902). |
| **Gesture** | The revisions one user action produced, possibly across several saves and resources of a namespace, grouped by an id the client chooses (§7.2). Used for undo and redo (§11.2). |
| **Blob** | Immutable bytes attached to a resource, stored and served apart from its documents, which refer to it with a blob reference (§7.8). |
| **Revision** | A resource log entry: `{ id, parent, kind, patches, author, created }`. |
| **Head** | The latest entry in a resource's log. |
| **Genesis** | The first revision of a resource created from nothing. Its parent is empty. |
| **Foreign parent** | The parent of a resource's first entry in a branch: the base's head for that resource at the branch point (§3.3, §7.6). |
| **Tombstone** | A log entry marking the resource as deleted. It has no patches. |
| **Purge** | Irreversible removal of a resource's content. An administrative action. |
| **Namespace log** | An append-only, hash-chained log of pointer changes (`head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns`, `prune`) for a namespace. |
| **Horizon** | The oldest revision of a resource whose history is still stored in full. Below it, only ids and parent links are kept (§8.6). |
| **Batch** | Writes to several resources of one namespace, applied all or nothing and recorded as one namespace entry (§7.5). |
| **Branch** | A namespace created from a **base** namespace at a namespace revision `at`. It reads the base through as of `at` and records only its own changes (§7.6, Addendum F). |
| **Frozen** | A namespace that accepts no resource writes, e.g. a merged or superseded branch (§8.4). |
| **Schema reference** | The top-level `$schema` string of a document: the URL of an immutable schema revision (§6.1). |
| **Typed document** | A document with `$schema`. It is validated. Otherwise the document is **untyped**. |
| **Change envelope** | The JSON description of a write that rules are evaluated against (§6.4). |
| **Writes** | The JSON Pointers a patch set modifies (§6.4.1). |
| **Principal** | The verified identity behind a request: its id, groups, roles and attributes. |
| **Role** | A named set of verbs and rules in the namespace document. Grants refer to roles by name (§C.1.1). |
| **Grant** | A signed, narrowable capability token presented with a request (Addendum C). |
| **Namespace consumer** | A separate client that derives data from a namespace log, such as a search index (§10). It can always rebuild by replaying the namespace log, which is never pruned. |

---

## 3. Identity

### 3.1 Input and canonical JSON

- **Input.** All JSON accepted by the API MUST be I-JSON (RFC 7493). Servers MUST reject, with `400`:

  - duplicate object keys

  - lone surrogates

  - non-finite numbers

  - numbers whose canonical form (JCS) is an integer literal outside ±(2⁵³−1), i.e. integral values with 2⁵³ ≤ |v| < 10²¹, however they are written. Numbers whose canonical form has an exponent, such as `1e300`, are accepted. Judging by the canonical form means a stored patch set is always accepted again when resent (merges, rebases, imports).

- **Canonical form.** `canonical(v)` is the JSON Canonicalization Scheme (RFC 8785, JCS), encoded as UTF-8.

- **What is stored.** The server stores, serves and hashes `canonical(patches)`, never the bytes as received. Every reader and verifier therefore sees exactly the input that was hashed.

### 3.2 Id format

An id has two forms:

- **Binary form:** 20 bytes. This is what is hashed and stored.

- **Text form:** 33 characters, used in URLs, headers and JSON.

```
text(id) = "1" + base32lower(bytes(id))      -- 1 version char + 32 base32 chars
```

- `base32lower` is the RFC 4648 alphabet in lowercase (`a–z2–7`), with no padding.

- The leading `1` is a **version prefix** meaning *SHA-256 truncated to 160 bits, base32*. It is outside the base32 alphabet, so it can never be confused with id data. A future format gets a new prefix, and old and new ids coexist.

- 160 bits gives about 2⁸⁰ collision resistance, beyond practical attack. Ids are **identifiers, not signatures**. Anything that needs cryptographic binding (author signatures, §C.3) uses the full digest.

### 3.3 Revision id

```
bytes(id) = trunc160( sha256( bytes(parent) ‖ 0x0A ‖ canonical(patches) ) )
```

- `bytes(parent)` is the parent's 20 bytes. For genesis it is empty (zero bytes).

- **Foreign parents.** In a branch, the first entry of a resource MAY instead have a foreign parent: the base's head for that resource as of the branch's `at` (§7.6). The formula is unchanged.

- `trunc160` keeps the first 20 bytes of the digest.

- Ids are **pure content hashes**. Identical histories in two resources have identical ids, so uniqueness is always scoped per resource.

- **An id determines its document everywhere.** Every id covers its parent, so identical ids in different resources or namespaces always denote identical documents. Replaying the same patch sets onto the same parent, in another resource or namespace, reproduces the same ids (Addendum F relies on this).

### 3.4 Tombstone id

```
bytes(id) = trunc160( sha256( bytes(parent) ‖ 0x0A ‖ "tombstone" ) )
```

`parent` is the head being deleted, which may be a foreign parent (§7.6).

### 3.5 Namespace revision id

```
bytes(ns_id) = trunc160( sha256( bytes(prev_ns_id) ‖ 0x0A ‖ canonical(entry) ) )
entry = { "resource": name, "kind": "head" | "tombstone" | "purge", "target": text(revision or tombstone id), "forced"?: true }
      | { "kind": "config", "target": text(config revision id) }
      | { "kind": "batch", "entries": [ config entry?, resource entry… ], "source"?: source }
      | { "kind": "branch", "name": name, "at": text(ns_id), "target": text(the branch's config genesis id) }
      | { "kind": "branch", "remote": { "origin": origin, "ns": name }, "at": text(ns_id) }   // a registered remote branch (§G.3)
      | { "kind": "purge-ns", "forced"?: true }
      | { "resource": name, "kind": "prune", "target": text(horizon id) }                  // §8.6
source = { "origin"?: origin, "ns": name, "at": text(ns_id), "bundle"?: text(digest), "ids"?: { name: text(id) } }
```

- `bytes(prev_ns_id)` is empty for the first entry.

- **`forced`** is present only on a purge that overrode an `in_use` refusal (§6.1), on every entry that purge writes, propagated ones included.

- Ids *inside* `entry` are in text form, so the entry is plain canonical JSON. The same field names are used by the namespace log API (§7.4).

- Config revision ids use the revision formula (§3.3) over the namespace document's own chain.

- **Branch entries** record, in the **base's** chain, that a branch was created (§7.6). `target` is the first config revision of the branch's own chain, so the base's hash chain commits to the branch's existence and starting point.

- **`source`** is hashed with the entry. `origin` is present only for a source in another deployment (Addendum G), and `ids` has at most one member per batch item.

- **Batch entries** (§7.5) list the batch's config change first, if it has one, then one `head` or `tombstone` entry per resource, in request order, each with the resource's **final** entry. Intermediate revisions are in the resource logs. `source` is optional provenance (Addendum F).

- The chain hashes **ids only, never content**, so it stays verifiable after a purge.

- Config changes and resource pointers share **one** chain. The configuration in force for a write is the nearest `config` entry before it (invariant 6).

### 3.6 Names

- Namespace names MUST match `^[a-z0-9][a-z0-9_-]{0,63}$`. They never contain a dot, so a name of the form `{ns}.{name}` can refer unambiguously to a resource in another namespace (Addendum B).

- Resource names MUST match `^[a-z0-9][a-z0-9._-]{0,127}$`.

- Names are flat: they never contain `/`. Hierarchy is data (Addendum B), never part of a name.

- URLs MUST use names verbatim. Percent-encoded forms of these characters are non-canonical and MUST be rejected with `400`, so each resource has exactly one URL spelling for caches, signatures and tags.

### 3.7 Blob id

```
bytes(bid) = trunc160( sha256( "patchlog-blob-v1" ‖ 0x0A ‖ type ‖ 0x0A ‖ nonce ‖ 0x0A ‖ bytes ) )
```

- `type` is the upload's `Content-Type`, lowercased and without parameters, as `type/subtype` (`400` if it can't be parsed). Text blobs are UTF-8.

- `nonce` is empty, or 26 base32 characters (128 random bits), as for `$nonce` (§C.7).

- `bytes` are the blob's bytes as stored: the plaintext, or at E3 the client's ciphertext (§E.3.1).

- The text form is that of §3.2. The prefix keeps blob ids apart from revision ids, and like them they are scoped per resource.

---

## 4. Invariants

- **Append-only.** Entries are never modified or removed, except by purge (§8.3, §8.5) and pruning (§8.6). Both remove content and keep ids and parent links.

- **Linear.** Each resource has exactly one first entry: a genesis, or in a branch an entry with a foreign parent (§7.6). Within a resource, every entry has at most one child, so a head only ever moves to a child of the previous head. The same holds for each namespace chain and each namespace document chain. Logs cannot fork, and history is never rewritten.

- **Valid.** For every non-tombstone revision `r`: if `d = fold(genesis … r)` has a `$schema`, then `d`, without the members §6.2 step 5 leaves out, validates against the schema at that (immutable) reference. Re-validating any revision later gives the same answer, unless that schema was force-purged (§6.1) or its revision was pruned without a kept document (§8.6).

- **Verifiable.** Anyone holding the entries can recompute every id and check every parent link. Below a pruning horizon the ids, parent links, authors, grant references and creation times are kept, but they can be checked only against the archive, and the horizon's document is trusted as a snapshot (§8.6).

- **Ordered namespace log.** Every mutating request that takes effect (`create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `prune`, or a batch) writes exactly one namespace entry, atomically with the change it records.

  - An idempotent retry answered from the log (§7.2) writes nothing.

  - Entries the server writes itself, such as propagated purges (§8.3), are one per namespace affected.

  - Creating a branch of a local base writes its `branch` entry in the base's chain, atomically with the first `config` entry of the branch's own chain.

  - A batch writes one `batch` entry for all of its changes, and is applied entirely or not at all.

  - Blob uploads (§7.8) change no head and write no entry.

- **Configuration in force.** A write is checked against the namespace configuration (rules, keys, revocations, limits) at the head of the namespace chain **at the moment it is inserted**. That configuration is the nearest `config` entry before the write's own entry or, for items of a batch that changes the configuration, the batch's own config change (§7.5).

- **Fixed base.** A branch's `base` is set when it is created and never changes. Reads through a branch see the base exactly as of `at`, except that purges in the base propagate (§8.3). For a base in another deployment, purges arrive as notices, which the other deployment may choose not to follow (§G.3).

- **Referenced blobs.** Every blob that a stored document references is available to its resource (§7.8), and is kept as long as that document is. At E3 the server relies on the writers' declarations (§E.3.1), which readers verify.

---

## 5. Storage requirements

The core does not prescribe a storage engine. An implementation MUST:

- persist, for each entry, its id, its parent, its kind, `canonical(patches)` (until purged), its author, the grant reference (Addendum C), a creation time, and the `gesture` and `undoes` it was written with, if any (§7.2)

- persist an author and a creation time for each namespace log entry, and the grant reference (§C.3) of each entry written on a request (none of these are part of its hash), so purges and namespace purges are attributed, and merges can be checked against `merge.authors` (§F.3)

- persist each blob per resource with its type and nonce, and its uploader while it is pending, know which revisions reference it, and remove it on purge, after pruning, and when it stays unreferenced (§7.8). Blob bytes may live outside the database.

- enforce invariants 2, 5 and 6 atomically, including under concurrent writers and multiple processes

- serve the document at **any** revision id, not only the head. Materialised head snapshots and intermediate snapshots are strongly recommended.

- after purge, retain ids, parent links and namespace entries, and nothing else of the resource's content

- after pruning, retain ids, parent links, authors, grant references, creation times, `gesture` and `undoes` below the horizon, the horizon's document, and the documents kept for protected revisions (§8.6)

- apply a batch atomically, holding invariants 2, 5 and 6 across all of its items

- for branches, persist `base` and answer "what was this resource's head as of namespace revision `n`?" for any resource and any `n` in a base's chain, which read-through (§7.6) needs

- after a namespace purge, retain the namespace document chain, the namespace log and every resource's ids and parent links

Addendum D describes one layout that meets these requirements, with measured sizing.

---

## 6. Validation and rules

### 6.1 Schema references

-
**Opting in.** A document opts in by carrying a top-level string `$schema`.

-
**Accepted forms.** `$schema` MUST match exactly

```
^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$
```

i.e. the path of a schema revision on this service. The only other accepted values are the bundled dialect URLs (e.g. `https://json-schema.org/draft/2020-12/schema`), which mark the document itself as a schema and validate it against the dialect's meta-schema. Anything else is `422` with `code: "schema_ref"`. That includes head URLs, absolute URLs to this host, dot segments, query strings and percent-encoding. No normalisation is applied.

-
**`$id`.** A schema document MUST NOT declare `$id` other than its own revision path. Validators MUST be registered and looked up **only** by revision path.

-
**`$ref`.** `$ref` inside a schema MAY be a same-document fragment (`#…`), or another schema revision path in the form above, optionally followed by a JSON Pointer fragment (`/r/schemas/common/rev/1…#/$defs/address`). A fragment points into an immutable revision, so it is immutable too. Nothing else is resolved.

-
**Never into a branch.** `$schema` and `$ref` MUST NOT name a branch namespace (§7.6), which is temporary by design (`422`, `code: "schema_ref"`). New schema revisions are written to a namespace that isn't a branch, or drafted in a branch of one (below). They are immutable and unused until referenced, so this is safe before a migration is merged (§F.1).

-
**Drafts in branches.** A path still never names a branch. But in a write **to a branch**, a path `/r/N/R/rev/X` that `N` can't resolve for the writer, because `N` lacks it or the writer can't read it there, is looked up in the branches of `N`, so a release can draft its schemas privately (§F.9):

  - The candidates are the local branches of `N`, branches of branches included, that aren't end-to-end encrypted. In a candidate, only revisions it wrote itself count, never those it reads through.

  - A candidate serves writes to itself and to its own branches, and to the namespaces its `drafts.for` lists (§7.4) and their branches: a write qualifies if the namespace written, or any namespace in its `base` chain, is listed. Each candidate is judged by its own `drafts.for`; branches of a candidate don't inherit it.

  - The writer needs `read` on `R` in the candidate, checked by the rule for other namespaces (§7.5). A revision the writer can't read there counts as not found.

  - An id determines its document everywhere (§3.3), so it doesn't matter which candidate holds `X`. The whole `$ref` closure resolves the same way.

  - In a namespace that isn't a branch, paths resolve only in `N`. Nothing in such a namespace therefore depends on a branch, and documents that use drafts can be merged into it only after their schemas have been (§F.9). A merge into a base that is itself a branch, as for a stacked release, may still resolve drafts. At E3 the server doesn't validate (§6.2), so this rests on the merging client (§F.8.1).

  - Clients and consumers that validate such documents find drafts by trying `N`, then the branches it lists (`GET /ns/{N}/branches`, recursively, which shows each branch's `drafts`), trying first the branches named in a release document if there is one (§F.9). Any branch that serves `X` serves the right schema. This is best effort: a client may not see every candidate or every rule, and only the server's check decides whether a write is accepted. Services may also cache a compiled schema by path across namespaces, since a path that resolves always means the same schema.

-
**Within a batch,** items may reference schema revisions created by earlier items of the same batch (§7.5).

-
**Tombstoned schema resources.** Revisions of a tombstoned schema resource still resolve (§8.1), so documents that reference them stay valid and can still be appended to. New references to them are also allowed.

-
**Purged or unknown references.** An unknown or purged reference is `422` with `code: "schema_unavailable"`.

-
**Referenced schema revisions.** A schema revision is **referenced** when any of these names it by `$schema`, or reaches it through `$ref`, transitively:

  - the head, or the last live document, of any unpurged resource in the deployment, a tombstoned document included, so a restore (§8.2) keeps working;

  - the head as of `at` of a resource a branch reads through;

  - any revision a branch wrote, not only its head, since a merge replays and validates every step (§7.5) and branches keep their whole history (§8.6).

-
**Copies.** A reference is satisfied by a copy of the revision whose document is available, neither purged nor pruned: in `N`, or, for a document in a branch, in a branch it may resolve drafts in, judged structurally by the candidate rules above (a local branch of `N`, not E3, serving that namespace), never by any one writer's grants. A fast-forward merge or rebase leaves several copies with the same id. A revision pruned in `N` counts as one `N` can't resolve.

-
**Refusals.** Unless forced (below), a server MUST refuse (`409`, `code: "in_use"`):

  - a purge, of a resource or a namespace, that would remove the last copy satisfying a reference, in any namespace the purge reaches, including the branches it propagates to (§8.3);

  - a config write that would leave a reference without a copy, such as narrowing `drafts.for` or raising a branch that holds drafts to `e2e`.

The answer lists, as `referencing`, the referencing namespaces in which the caller may read anything, by the rule for other namespaces (§7.5). At E3 documents are ciphertext, so the server can't see their references (§E.3.2).

-
**Forcing.** A refused purge can be forced: `?force=1` on the purge request, with a grant chained to a deployment operator key, or, for a purge of a branch or of a resource in one, to a `*` key of that branch, inherited or its own. A forced purge knowingly breaks invariant 3 for the referencing documents, and its entries carry `forced: true` (§3.5).

-
**Read permission.** Resolving a `$schema` or `$ref` requires the writer to have `read` on the copy it resolves to: in the schema's namespace, or in the branch holding a draft (below; Addendum C). Otherwise validation errors could reveal the content of a schema the writer may not read.

-
**Validator cache.** Compiled validators MAY be cached by revision path forever, since references are immutable.

### 6.2 On write

The order of checks at the gate is normative. Only errors in a request's own shape, which no state influences, may come before step 1: malformed names or URLs, content types, header and body syntax, and the size of what is read (`400`, `413`, `415`), unless an endpoint fixes its own order, as blob uploads do (§7.8). Everything else follows this order:

- **Authenticate and authorise** the request (Addendum C): `401` or `403`. This covers the verbs and every grant, key-scope and role rule that refers only to `/action`, `/resource`, `/principal` or `/now` (§C.2), so a grant limited to one resource learns nothing about others. A `PATCH` with `If-Match` may be an append or a restore, which only the resource's state decides. It passes this step if, for `append` or for `restore`, the grant allows that verb and every step-1 rule passes with `/action` set to it. Those are its **candidate verbs**. Step 2 settles which one the write is, and step 6 evaluates the rules again with the settled action. In a batch (§7.5), a patch set that follows a `"delete"` step in the same item is a restore and any other later step an append; those verbs are known from the request and are checked here like `"delete"`. Rate limits (§6.6) are checked last in this step, only for requests that passed it: `429`.

- **Precondition** (§7.2), in this order:

  -
the idempotent-retry lookup (§7.2). It matches only entries written by the same principal, so it reveals nothing to anyone else. It doesn't apply to a purged resource: the answer is `410`, as for every URL of it (§8.3). It answers `200` only if the matched entry's verb (a restore when its parent is a tombstone, an append otherwise) is one of the request's candidate verbs, so a retry after a lost response works whatever happened to the resource since.

  -
for a `PATCH` with `If-Match` (in a batch, an item whose first step is a patch set), settle the verb from the resource's state as the writer sees it:

    - a tombstoned head makes it a restore, a live one an append, and a resource with no head an append

    - a purged resource answers `410`, whichever the verb

    - in a branch, the state is the branch's view (§7.6): a resource read through settles by the base's head as of `at`, and a tombstone there makes the first write a restore, with that tombstone as its foreign parent

A settled verb that isn't a candidate is `403` here, before the `If-Match` comparison, so steps 3–5 never run for the wrong verb and no head is revealed. This reveals only whether the resource is currently deleted, which is what a restore grant is for. In a batch this sub-step runs for every item before the next runs for any, and a `403` here counts as failing authorisation, for §7.5's failure report and for the dry run.

  -
author signatures (§C.3.1): `422` with `code: "signature"`. They come after the retry lookup, so a retry is answered with the entry as first recorded, and after the verb is settled, so authorisation failures are still reported first (§7.5). They need no head: the signed parent is the one the precondition names.

  -
a frozen namespace: `409` (§8.4)

  -
the precondition itself: `428` or `412`

- **Apply** the patches to the parent's document, with operation validation. A delete skips steps 3–5: it has no patches, and what it removes isn't validated. `test` ops are evaluated, and a failing `test` is `422`.

- **Limits** (§6.6) and **blob references** (§7.8): every reference in the resulting document is well-formed and names a blob available to the resource, `422` otherwise.

- **Schema.** If the **resulting** document has `$schema`, resolve it (§6.1) and validate it against JSON Schema draft 2020-12, with format assertions. The instance validated is the document without its top-level `$schema` member, and without a top-level `$nonce` whose value has the fresh-nonce form of §6.4.1. These are mechanics rather than data, so a closed schema (`additionalProperties: false`) needn't declare them, and schemas can't constrain them; a `$nonce` of any other form is validated as data. Clients validating at E3 (§E.3.2) and reference walks (§6.5) use the same instance. Failure is `422` with `{ pointer, message }` errors.

- **Rules.** Namespace rules, and grant, key and role rules (§6.4, §C.2), evaluated against the configuration in force (invariant 6).

- **Hash and insert** atomically, together with the namespace entry.

For a batch (§7.5), each step runs for **every item** before the next step starts, so nothing about any item's precondition is revealed until every item is authorised. Step 7 inserts all items in one atomic operation.

**End-to-end namespaces (§E.3).** For `create`, `append` and `restore` in an `e2e` namespace, step 3 accepts a patch set of one reserved `sealed` op, or `[]` for a restore, and doesn't apply it. Step 4 checks the blobs the op declares (§E.3.1). Step 5 is skipped. The server can't see the resulting document or which paths change, so any namespace, grant, key or role rule that evaluates a `writes` predicate or a `/doc` path fails as a whole for these writes (`422` or `403`), wherever it appears in the rule. E3 namespaces therefore can't carry path or document rules for resource writes (§E.3.2). Config, branch and prune writes are checked as usual. A delete is too, except that its `doc` is null, so a rule that evaluates a `/doc` path fails as a whole for it.

### 6.3 Changing type

- **Adding** `$schema` to an untyped document is an ordinary patch. It succeeds only if the whole document validates.

- **Changing** `$schema` (e.g. migrating to a new schema revision) is an ordinary `replace /$schema`, usually combined in one patch set with the data changes the migration needs. The result must validate against the new schema.

- **Removing** `$schema` makes the document untyped from that revision on. Namespaces can forbid this with a rule (§6.4.4).

- Tombstones carry no document state and are not validated. Neither is the document a delete removes, which rules see as `/doc` (§6.4.1).

### 6.4 Namespace rules

Rules are write-time policy, stored in the namespace document as `rules: [...]`. With no rules, anything goes.

#### 6.4.1 Change envelope

For every write, the server builds:

```
{
  "action":    "create" | "append" | "restore" | "delete" | "purge" | "config" | "read" | "branch" | "purge-ns" | "export" | "prune",
  "resource":  "name",                         // absent for config, purge-ns and export; the new namespace's name for branch
  "principal": { "id": "…", "groups": [ … ], "roles": [ … ], "attrs": { … },
                 "via": [ … ], "grant": "1…" },  // absent when auth is disabled
  "now":       "2026-10-04T18:02:11.482Z",     // server time at the gate
  "writes":    [ "/title", "/blocks/3" ],      // normative, see below
  "doc":       { … },                          // the resulting document; for delete, the document deleted; null for purge, read, purge-ns; { remote, at } for export; { horizon, keep } for prune
  "patches":   [ … ]                           // canonical patch set; [] when there is none
}
```

-
**`writes`** is computed by the server and is the only field path-based policy may rely on. For each operation:

  - `add`, `replace`, `remove`, `copy` write `path`

  - `move` writes **both** `from` and `path`

  - `test` writes nothing

  - A root operation writes `""`. A genesis `add ""` writes `""`.

  - A delete has no patches, so its `writes` and `patches` are `[]`. `within` is true when there are no writes, so it doesn't restrict deleting, nor a restore with `[]`, which writes nothing either: limit both by verb, e.g. narrowing blocks that drop `delete` and `restore` (§C.6), or by rules on `/doc`.

  - An array append `…/-` is recorded with the resulting index.

  - In resource envelopes only, an `add` or `replace` at exactly `/$nonce` whose value is 26 base32 characters (`^[a-z2-7]{26}$`, a fresh nonce, §C.7) is left out, so the nonce never affects path policy or merge conflicts. Any other operation at or below `/$nonce` (a `remove`, a `move` or `copy` to or from it, a deeper path, another value) is a write as usual.

Pointers are compared **segment by segment after RFC 6901 unescaping**, never as strings.

-
**`doc`** is the document as it will be stored if the write succeeds. For a delete it is the document being deleted: the resource's last live document as the target namespace sees it, read through its bases in a branch (§7.6), or, in a batch, the document after the item's earlier steps. For `purge`, `purge-ns` and `read` it is null. In an end-to-end namespace the server can't see documents, so `doc` is null for every resource action there, and a rule that reads `/doc` fails the write (§6.2). Rules can then decide deletes by content, e.g. "only the owner may delete". A replay of a delete (§F.3, §G.4.4) is judged against the document the target has at that step. For `config` it is the resulting namespace document. For `branch` it is the new branch's namespace document, and the envelope is evaluated in the **base** namespace (§7.6).

-
**Batches** produce one envelope per patch set, with the ordinary actions. There is no `batch` action: a batch can do nothing that its items couldn't do one by one.

-
**`principal`** comes from the grant (§C.1). `groups`, `roles` and `attrs` are taken from its root block. `roles` lists only the **effective** roles: those kept by every narrowing block and defined in the configuration in force (§C.1.1). `attrs` is an object of issuer-asserted attributes, `{}` when there are none.

-
**`now`** is the server's clock at the gate, RFC 3339 UTC with millisecond precision. It is read once per request, so every rule sees the same instant. Rules that use it make acceptance time-dependent, but like all rules they judge only the write at hand: history is never re-evaluated.

-
**`read`** envelopes are used only to evaluate grant and role rules on reads (§C.2, item 5). They carry `action`, `resource`, `principal` and `now`, and no `writes`, `doc` or `patches`.

-
There is deliberately no previous state in the envelope. Rules judge the resulting document and the change itself. A delete is no exception: what it changes is the document it removes, which is the state the writer saw just before. `purge`, `purge-ns` and `read` keep `doc: null`: purge is administrative and must work on anything, and read rules stay free of content (§C.5.1).

-
**What rule failures reveal.** A rule that tests `/doc` and fails tells the writer something about that document, for a delete as for an append. A writer who may delete but not read learns only what such a rule tests; namespaces that care keep `delete` with `read`.

#### 6.4.2 Rule forms

```
{ "op": "test", "path": "", "value": … }      // RFC 6902 equality
{ "op": "test", "path": "…", "exists": true | false }                     // presence / absence
{ "op": "test", "path": "…", "schema": { …JSON Schema fragment } }        // anything else
{ "op": "writes", "covers":   "" }    // some write is at or above the pointer (may replace it wholesale)
{ "op": "writes", "overlaps": "" }    // some write is at, above or below the pointer
{ "op": "writes", "within":   ["", …] }   // every write is at or below one of the pointers
{ "op": "compare", "path": "…", "eq" | "lt" | "le" | "gt" | "ge" | "in": { "value": … } | { "path": "" } }
{ "all": [ …rules ] }   { "any": [ …rules ] }   { "not": rule }
{ "if": [ …rules ], "then": [ …rules ] }      // all `if` pass ⇒ all `then` must pass
```

- A missing path fails `value` and `schema` tests and satisfies `exists: false`.

- `within` is true when there are no writes. `covers` and `overlaps` are false when there are none.

- **Path policy MUST use the `writes` predicates**, never patterns over `/patches/*/path`. Those miss `move.from`, root writes and escaping.

- **`compare`** relates a value in the envelope to a literal (`value`) or to another value in the envelope (`path`). This is what attribute-based policy needs: "the owner is the principal", "the lock time has not passed", "the region is one of the principal's".

  - `lt`, `le`, `gt`, `ge` compare two numbers, or two RFC 3339 timestamps as instants.

  - `eq` is RFC 6902 equality. `in` is true when the left value equals an element of the right-hand array.

  - A missing path on either side, or operands of different or unsupported types, make `compare` false.

#### 6.4.3 Evaluation

- Rules run at step 6 of §6.2, in order, and all must pass.

- A failing namespace rule is `422` with `{ "code": "rule", "rule": <index>, "path": <pointer> }`. A failing grant, key or role rule is `403` with `code: "forbidden"`.

- Rules apply **only at write time**, and at read time for grant, key and role rules. Changing them never invalidates existing history.

- **Config writes are rule-checked too.** Namespace rules also apply to `config` writes, except for principals whose grant chains to a key with `can: ["*"]`, so that a bad rule set cannot lock everyone out.

- **Operator overrides.** A purge or namespace purge forced past an `in_use` refusal under a deployment operator grant (§6.1) isn't judged by namespace rules either: forcing is the operator's override of policy, and a rule such as "only `ops` may purge" is policy of the same kind. A purge forced with a `*` key of the branch, inherited or its own, is still judged, and so is any purge while authentication is disabled (§1), where no operator grant is verified.

- **Except as above, rules see every action,** including `delete`, `purge`, `config`, `branch` (evaluated in the base) and `purge-ns`, where `doc` is the deleted document, null or a namespace document. Rules about documents should therefore be scoped with `if` on `/action`, as in §6.4.4. Rules about a document's shape, in particular, should exempt `delete`: otherwise a document written under earlier rules can't be deleted.

#### 6.4.4 Examples

```
[
  { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } }],
    "then": [{ "op": "test", "path": "/doc/$schema", "schema": { "type": "string", "pattern": "^/r/schemas/match/rev/" } }] },

  { "if":   [{ "not": { "op": "test", "path": "/action", "value": "create" } },
             { "op": "writes", "overlaps": "/$schema" }],
    "then": [{ "op": "test", "path": "/doc/$schema", "exists": true }] },

  { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["delete", "purge"] } }],
    "then": [{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "ops" } } }] },

  { "if":   [{ "op": "test", "path": "/action", "value": "append" }],
    "then": [{ "not": { "op": "writes", "covers": "" } }] }
]
```

In order, these say:

- every document is typed with a revision of the match schema

- once typed, `$schema` can't be removed, including by a root replace

- only the `ops` group may delete or purge

- no whole-document replace on ordinary appends

**Attributes and ownership.** One rule, relating the principal, the document and the time:

```
{ "if":   [{ "not": { "op": "test", "path": "/principal/roles", "schema": { "contains": { "const": "editor" } } } },
           { "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore", "delete"] } }],
  "then": [{ "op": "compare", "path": "/doc/owner",  "eq": { "path": "/principal/id" } },
           { "op": "compare", "path": "/doc/region", "in": { "path": "/principal/attrs/regions" } },
           { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["append", "restore"] } }],
             "then": [{ "not": { "op": "writes", "overlaps": "/owner" } },
                      { "not": { "op": "writes", "overlaps": "/lockAt" } }] },
           { "if":   [{ "op": "test", "path": "/doc/lockAt", "exists": true }],
             "then": [{ "op": "compare", "path": "/now", "lt": { "path": "/doc/lockAt" } }] }] }
```

Without the `editor` role, a principal may only create, edit, restore or delete documents it owns, in one of its regions. After creating a document, it can never reassign ownership or touch the lock, and cannot edit or delete after `lockAt`. (Every create writes `""`, which overlaps everything, hence the overlap rules apply only to appends and restores. For a delete, `/doc` is the document being deleted.)

**The pattern for fields that policy depends on.** The envelope has no previous state, so such a field is protected by forbidding writes to it (`writes overlaps`), not by comparing old and new values. `overlaps` also catches root replaces and `move`, so "can't change `/owner`" plus "`/doc/owner` is me" means "it was already mine". Every create writes `""`, which overlaps every path, so such rules must exempt `create` and test the created document instead, as the rule above does; otherwise they forbid creating anything. A delete writes nothing, so overlap rules never stop it; decide deletes by testing `/doc`, the document being deleted, as the rule above does. A restore with a root replace also writes `""`. Exempt it only where a test of the resulting document is enough on its own, such as "no `$access`" (§B.11.3). For ownership fields, keep restores under the overlap rule, as the example does, so that only editors can recreate a deleted document from scratch; otherwise a non-owner could restore someone else's document with itself as owner.

### 6.5 Reserved keys and extension keywords

- **Reserved keys.** Top-level document keys starting with `$`, other than `$schema`, are reserved for conventions (e.g. `$access` and the optional `$parents` in Addendum B, `$nonce` in §C.7). The core stores them like any other data and never interprets them, except that a fresh `$nonce` is left out of `writes` (§6.4.1). Namespace rules may constrain them.

- **`$blob`** is reserved at any depth, not only at the top level: an object whose `$blob` member is a string is a blob reference (§7.8), and must be well-formed (`422`). Schema documents aren't searched for references.

- **`x-*` keywords.** Schema keywords starting with `x-` are annotations. The core validator ignores them, and they carry meaning only for namespace consumers (e.g. `x-index` in Addendum A). Any other unknown keyword makes a schema invalid.

- **`x-ref`** marks a string that references another resource, so tools can follow it: exporters (§G.4.2), static publishers, and reverse-reference indexes that answer "who uses this?".
```
"hero":    { "type": "string", "x-ref": { "pinned": true } },   // "/r/media/photo-12/rev/1q…": exactly that revision
"related": { "type": "array", "items": { "type": "string", "x-ref": {} } },  // "/r/matches/cup": whatever is the head
"trigger": { "type": "string", "x-ref": { "key": "/triggers" } }            // "/r/doors/layout-7#t-42": one entry of layout-7
```

  - Its value is `{ "pinned"?: boolean, "key"?: pointer }`.

  - A pinned reference is a revision path in the form of §6.1. A live reference is a resource path `/r/{ns}/{name}`.

  - **Entries inside a document.** With `key`, a reference names one entry of the target document: `/r/{ns}/{name}#{id}`, or pinned `/r/{ns}/{name}/rev/{rev}#{id}`. `key` is a JSON Pointer into the target document, to either an array of objects with a string `id` member or an object whose member names are the ids. `{id}` is matched against those ids, never against array positions, so references survive reordering. It is percent-encoded as a URI fragment. A reference whose entry doesn't exist is dangling, like one to a missing resource.

  - **Finding references** is a static walk, not annotation collection during validation, so any validator will do. Walk each document, without the members validation leaves out (§6.2 step 5), together with its schema, and at every instance location consider every subschema that could apply: through `$ref`, `properties`, `patternProperties`, `additionalProperties`, `items` and `prefixItems`, **every** branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, and any other keyword that applies a subschema. A string at a location where any of them carries `x-ref` is a reference if it has the form above. This over-approximates, since a branch that didn't validate still counts, which is harmless because the string must also look like a reference. Walking the document along with the schema handles recursive schemas without special cases.

  - Like every `x-*` keyword, the core doesn't check it. A schema can enforce the form with `pattern`.

### 6.6 Limits

-
**Configurable limits.** Every namespace has limits, set in the namespace document under `limits`, with these defaults:

| Limit | Key in `limits` | Default |
|---|---|---|
| patch set size | `patchSetSize` | 256 KiB |
| operations per set | `opsPerSet` | 1,000 |
| document size | `documentSize` | 4 MiB |
| largest string in a document, member names included, as canonical JSON (see Values) | `valueSize` | 64 KiB |
| longest JSON Pointer to any value in a document, as canonical JSON | `pathSize` | 2 KiB |
| nesting depth | `nestingDepth` | 64 |
| rules per namespace | `rulesPerNamespace` | 256 |
| rules per grant chain | `rulesPerGrant` | 32 |
| grant size | `grantSize` | 8 KiB |
| items per batch | `itemsPerBatch` | 1,000 |
| batch size (all patch sets) | `batchSize` | 16 MiB |
| log page size for log ranges (§7.1), `/heads` pages and gesture listings (§7.4), event-stream catch-up (§7.3) and long-poll answers (§7.7), deployment only | `logPageSize` | 1,000 entries |
| branch depth (bases of bases), deployment only | `branchDepth` | 8 |
| live branches per namespace | `branchesPerNamespace` | 100 |
| writes per resource, per principal | `ratePerResource` | 10/s, burst 20 |
| writes per principal | `ratePerPrincipal` | 50/s, burst 100 |
| writes per namespace | `ratePerNamespace` | 500/s, burst 1,000 |
| retry window (history always kept, §8.6); a namespace may raise it up to the deployment maximum | `retryWindow` | `PT5M` |
| documents kept through `keep`, per resource in total (§8.6) | `keepPerResource` | 100 |
| lifetime of a remote branch registration (§G.3) | `remoteRegistration` | `P30D` |
| blob size (§7.8) | `blobSize` | 64 MiB |
| blob references per document | `blobsPerDocument` | 1,000 |
| bytes of pending blobs, per uploader and namespace, at least 4 KiB per blob | `blobPending` | 256 MiB |
| age at which a pending blob is deleted; at least `retryWindow` (`422`, `code: "limit"`, otherwise) | `blobGrace` | `PT24H` |
| blob bytes uploaded per principal, as `{ "rate", "burst" }` in bytes | `blobRate` | 8 MiB/s, burst 256 MiB |

Sizes are integers in bytes, counts are integers, durations are ISO 8601 durations as in `retention` (§8.6), and rates are `{ "rate": <per second>, "burst": <bucket size> }`, e.g. `"limits": { "batchSize": 33554432, "ratePerNamespace": { "rate": 200, "burst": 400 } }`.

-
**Exceeding a limit** is `413` or `422`, with `code: "limit"`.

-
**Creates and restores from scratch.** The patch set of a create, and of a restore whose first operation is a root `replace` (§8.2), may be as large as `documentSize` instead of `patchSetSize`, so any document within the limits can be written in one request. At E3, where the server can't see a patch set's shape, every create and restore gets that bound. In a batch they still count toward `batchSize`. Every other patch set stays within `patchSetSize`.

-
**Values.** `valueSize` and `pathSize` keep every string replaceable by one ordinary append, together with a `test` of its old value (§11), whichever write stored it, sealed or not. Sealing at E3 grows a patch set by about half (base64 and padding), so a config write is `422` (`code: "limit"`) unless `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize`. In an E3 namespace a patch set also carries its declared blob list (§E.3.1, up to 36 bytes per blob), so the left side adds `36 B × blobsPerDocument` there. `valueSize` and `pathSize` are measured as canonical JSON. Larger values belong in blobs (§7.8). At E3 clients check these limits, along with the others on documents (§E.3.2).

-
**Rate limits** are token buckets: the rate refills the bucket, and the burst is its size.

  - **Checked after authorisation**, at the end of step 1 of §6.2. Only authorised requests consume tokens, so a caller can't drain the buckets of resources it may not write, and a `429` tells it nothing it couldn't already see.

  - **Buckets are keyed by the root `sub` and the key that signed the root block** (`kid`, §C.1), never by `via`: any holder can add a narrowing block with a `via` of its choosing, and would get a fresh bucket each time. A plug-in service with its own root grant, from its own key, therefore has a bucket of its own. The per-resource bucket is per resource *and* principal: one writer flooding a resource slows down only itself, and the namespace bucket bounds all writers together.

  - **Exceeding one** is `429 Too Many Requests` with `Retry-After`, `code: "rate"`, and the limit that was hit.

  - **Cost.** A request is admitted while every bucket it draws on holds at least one token, and its cost is then deducted, even below zero. A batch costs one token per resource it touches from each per-resource bucket, and one token per item from the principal and namespace buckets; its `config` change, if any, costs one token from the principal and namespace buckets unless it is exempt (below), as a config write does, so only a batch with no items and an exempt change costs nothing. So a batch larger than a burst is still admitted, takes the buckets below zero, and delays the writes after it. A blob upload (§7.8) costs one token from the per-resource, principal and namespace buckets, and its size from the principal's `blobRate` bucket.

  - **Exempt:** config writes under a `*` key, config writes whose `writes` are non-empty and all at `/frozen`, `/successor` or `/merged` and whose resulting document has `frozen: true`, purges, and entries the server writes itself (purge propagation, §8.3). Freezing a namespace or revoking a key must never wait.

  - A key scope may lower the per-principal rate for the grants it signs (§C.4), e.g. to throttle a plug-in service without touching editors.

  - Clients stay under the limits by combining pending changes (§11).

-
**Allowances.** A namespace document may give a named principal (root `sub` and signing `kid`) its own budget:

```
"allowances": [ { "sub": "svc:importer", "kid": "ops-2026",
                  "bucket": { "rate": 100, "burst": 20000 },   // writes per second, and bucket size
                  "itemsPerBatch": 20000, "batchSize": 67108864,      // 64 MiB, in bytes as in `limits`
                  "blobRate": { "rate": 67108864, "burst": 1073741824 }, "blobPending": 17179869184,   // above the defaults
                  "until": "2026-10-08T00:00:00Z" } ]
```

  - That principal's writes draw on the allowance's own bucket instead of the principal and namespace buckets (an allowance also replaces a key scope's lower `rate`), and its batches may be as large as the allowance says, up to the deployment maximums. Per-resource buckets still apply. Uploads (§7.8) draw on the allowance's bucket too, and an allowance may also set `blobRate` and `blobPending` for that principal. Allowances never exceed the deployment maximums, so a deployment that expects large imports raises those, as the example needs.

  - `until` (optional) is an absolute RFC 3339 time. The allowance applies only while `now` (§6.4.1) is before it, and is ignored afterwards until an administrator removes it. Allowances for an import or a release should set one, so a forgotten entry doesn't leave a principal with a large budget.

  - This is how a large import or release lands as **one** atomic batch without holding up the namespace's other writers. Splitting it into paced batches would make it non-atomic, so pacing suits backfills only (§G.4.4).

  - A large batch still holds the namespace's sequencer while it inserts, so `itemsPerBatch` is chosen with that in mind.

  - Changing `/allowances` requires a `*` key (§7.4). Growth stays an administrator's decision.

-
**Deployment maximums.** A deployment sets a maximum for every limit, and a namespace can only lower it. The retry window is the exception: the deployment sets a minimum and a maximum, and a namespace may raise it up to that maximum. Writes covering or overlapping `/limits` require a `*` key (§7.4), because batch size and item counts bound how long a write holds the namespace's sequencer.

-
**Regular expressions** in rules, grants, key scopes and schemas MUST be evaluated with linear-time semantics (an RE2-compatible subset). Patterns that need backtracking features (backreferences, lookaround) MUST be rejected when the schema, config or grant is accepted. This way no writer-supplied pattern can stall the gate.

---

## 7. HTTP API

Resource URL: `/r/{ns}/{name}`. Namespace URL: `/ns/{ns}`. `GET /` answers `{ "spec": "0.43", "auth": "grants" }`, the version of this spec the deployment implements, as dotted decimal numbers compared component by component (`0.38`, `0.38.1`), and whether authentication is on (`grants`) or `disabled` (§1). Addendum C adds `jwks_uri` (§C.4), and Addendum G `origin` (§G.1). An endpoint of this API accepts only the query parameters this spec defines for it, each at most once, and flags such as `force` and `dry-run` only the value `1`; anything else, a repeated parameter included, is `400` (`bad_input`, not cached), a request-shape error (§6.2), so a client can't mistake a parameter of its own, such as `limit`, for one the server honours, nor `dry-run=true` be ignored and the write made. Services of the addenda define their own. An edge that verifies signed-URL grants (§C.5) strips their parameters before forwarding. Ids appear in text form (§3.2), and in headers as quoted strong ETags, e.g. `"1q3fa9…"`.

**Browsers.** Writes (`PATCH`, `PUT`, `POST`, `DELETE`), and any request with `Authorization`, `If-Match`, `Source-Authorization`, `Signature` or a JSON Patch `Content-Type`, aren't simple requests, so browsers send a CORS preflight, cached per URL. A deployment serving browsers answers preflights with those methods and headers, plus `Gesture`, `Undoes`, `Blob-Nonce`, `Blob-From`, `If-None-Match`, `Range`, `If-Range` and `Last-Event-ID`, allowed; exposes `ETag`, `Location`, `Retry-After`, `Content-Range`, `Gesture`, `Undoes`, `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Cursor` and `X-Log-Next`; and sets `Access-Control-Max-Age`. Responses that vary by origin carry `Vary: Origin`. A deployment that allows every origin sends `Access-Control-Allow-Origin: *` and its exposed headers on every response, with or without `Origin`, so a CDN can cache one answer for all. Reads of public namespaces should be sent without `Authorization`: long-poll URLs are new every interval (§7.7), and every revision behind a head redirect has its own URL, so each would need a preflight. `EventSource` can't send `Authorization`, so SSE in browsers uses edge grants as cookies (§C.5), which need `Access-Control-Allow-Credentials` and a named origin, or a streaming `fetch`.

Requests to private namespaces follow Addendum C. Without `read`, a resource that exists and one that doesn't both answer `404`, so existence is not revealed. The same holds for namespaces: a request without valid credentials to a namespace that doesn't exist answers `401`, exactly as one to an existing namespace whose `read` isn't `public`. Only public namespaces answer unauthenticated requests with content or `404`. With a grant, the server first reads `ns` from its blocks, before looking up any key: a namespace that isn't named in `ns` by every block that carries `ns` (the root block always does, and `"*"` names every namespace) answers `403` without being consulted, whether or not it exists. Reads of a public namespace are the exception: a grant that doesn't name the namespace, or that can't be used (malformed, badly signed, revoked, expired or not yet valid), is ignored, and the read is answered exactly as an unauthenticated one. A client can then send one bearer to every namespace it reads, including public schema namespaces (§6.1), and the namespace reveals nothing it doesn't show everyone. Writes, and every request to a namespace that isn't public or doesn't exist, keep the `403` and `401` answers. Only then is the grant verified against that namespace's keys, or against the deployment operator keys when the root `kid` names one (§C.4). This hides a namespace's existence from requests to it. Namespace names share one space and are not secret (§E.4): creating a namespace or branch with a taken name reveals that it is taken.

### 7.1 Reads

| Request | Response | Cache-Control (public namespace, §9) |
|---|---|---|
| `GET /r/{ns}/{name}` | `302` with `Location: /r/{ns}/{name}/rev/{head}` and `ETag: "{head}"` | head pointer |
| same, never existed | `404` | short |
| same, tombstoned | `410` with `{ "tombstone": id, "last": lastRevisionId }` and `ETag: "{tombstone}"` | head pointer |
| same, purged | `410` | long |
| `HEAD /r/{ns}/{name}` | as `GET`, no body | as `GET` |
| `GET /r/{ns}/{name}/rev/{id}` | `200` with the document at `id`, `ETag: "{id}"`, `X-Revision: {id}`. Honours `If-None-Match` with `304` | immutable |
| same, `id` is a tombstone | `410` | immutable |
| same, unknown `id` | `404` | short |
| same, purged | `410` | long |
| same, below the horizon, without a kept document (§8.6) | `410` with `{ "code": "pruned", "horizon": id, "archive"?: url }` | pruned |
| `GET /r/{ns}/{name}/blob/{bid}` | `200` with the blob, `206` for a range; `404` if pending or unknown, `410` if pruned or purged (§7.8). In sealed namespaces, `302` to `…/blob/{bid}/e/{e}` (§E.2.2) | immutable (a `410` as pruned or long, the `302` as a head pointer) |
| `GET /r/{ns}/{name}/blob/{bid}/e/{e}` | sealed namespaces only: `200` with the blob sealed under epoch `e`, `206` for a range of the sealed bytes; `404` for an epoch it isn't served under (§E.2.2) | immutable |
| `GET /r/{ns}/{name}/rev/{id}/log?since={a}` | `200` with the entries after `a` (exclusive) up to `id` (inclusive). Omitting `since` means from genesis. `404` if `a` is not an ancestor of `id`. `410` naming the horizon if any revision after `a`, up to `id`, has its patch set pruned and not restored from an archive. `a` itself may lie below it. Paged as below | immutable (a `410` is cached as pruned) |

**Paging.** A log range longer than the log page size (§6.6) answers its first page only, oldest first, with the header `X-Log-Next: {id}`: the last entry returned, which is the `since` of the following page, an immutable range up to the same `id`. A client reads pages until the last entry it received is the URL's `id`; a missing `X-Log-Next` before that is an error, so a truncated copy can't pass for the whole range. A range of any length then costs the server one page per request.

- `X-Log-Next` is the id in text form, unquoted, and equals the page's last entry. A page that reaches the URL's `id` needs none, so pages cached before paging existed stay valid. Every page is a correct prefix of its range, so pages cached under an earlier page size stay correct too.

- `404` and `410` are judged over the URL's whole range: `410` if any revision in it has a patch set missing, pruned and not restored from an archive. A server can decide both without reading the range, since patch sets can only be missing at or below a horizon (§8.6), and ancestry is a walk along parent links.

- The sealed snapshot of an E3 prune (§8.6) is served as `/rev/{H}`, never as a log entry, so ranges after the horizon don't contain it. What `/rev/{id}` serves at E3 for other revisions is an open question (§13).

- Long-poll answers (§7.7) use the same page size but carry no `X-Log-Next`: their `X-Revision` or `X-Namespace-Revision` already names the next `since`.

- Sealed pages (§E.2.2) carry their own bounds.

Log entry shape (patches in canonical form):

```
{ "id": "…", "parent": "…", "kind": "rev", "patches": [ … ], "author": "…", "created": "…", "grant"?: { "id", "sub", "kid" }, "signature"?: "…", "gesture"?: "…", "undoes"?: "…" }
{ "id": "…", "parent": "…", "kind": "tombstone", "author": "…", "created": "…", "grant"?: { "id", "sub", "kid" }, "signature"?: "…", "gesture"?: "…", "undoes"?: "…" }
```

`grant` is absent where none was recorded, including writes made while authentication was disabled, whose namespace entries say `"grant": null` (§7.4). All cursors are ids. Internal sequence numbers are never exposed.

### 7.2 Writes

Writes are **never** unconditional: a write without a precondition is `428`. The exceptions are pruning (§8.6) and blob uploads (§7.8), which change no head. Checks run in the order of §6.2, so **authorisation always comes before the precondition**. For a `PATCH` with `If-Match`, authorisation completes at step 2, when the verb is settled. An unauthorised caller never learns whether its precondition matched, and never sees the head.

| Request | Precondition | Success | Failure |
|---|---|---|---|
| **Create:** `PATCH /r/{ns}/{name}`, `Content-Type: application/json-patch+json` | `If-None-Match: *` | `201` with `Location: …/rev/{id}` and `ETag: "{id}"` | `412` if the resource exists (body `{ head }`) · `422` · `410` if purged |
| **Append:** `PATCH /r/{ns}/{name}` | `If-Match: "{parent}"` | `201` with `Location` and `ETag` | `412` + `{ head }` if parent ≠ head · `422` · `410` if tombstoned and `parent` ≠ tombstone · `403` if tombstoned and the grant can't restore (§6.2) · `410` if purged |
| **Restore:** `PATCH` on a tombstoned resource | `If-Match: "{tombstone}"` | `201`. The patches apply to the last live document; `[]` restores it unchanged | as for append |
| **Delete:** `DELETE /r/{ns}/{name}` | `If-Match: "{head}"` | `200` + `{ tombstone }` | `412` + `{ head }` · `410` if already tombstoned |
| **Purge:** `POST /r/{ns}/{name}/purge` | `If-Match: "{head or tombstone}"` | `204` | `412` · `409 in_use` (§6.1) |
| **Upload a blob:** `PUT /r/{ns}/{name}/blob/{bid}` (§7.8) | none | `201` with `ETag: "{bid}"` | in the order of §7.8: `401`/`403` · `429` · `410` if the resource or namespace is purged · `409 frozen` · for a copy, `400`, `422 blob`, then `404` · `400`/`415` · `413` · `422 blob_mismatch` |

-
**Authorization:** `Authorization: Bearer <grant>` (Addendum C). With authentication disabled (development only), `X-Author` names the author.

-
**Author** is the verified principal id. `via` (Addendum C) is recorded with it.

-
**Gestures.** A write MAY carry `Gesture: <id>`, naming the user action it belongs to, and `Undoes: <id>`, naming the gesture it undoes (§11.2). Both are 26 base32 characters (`^[a-z2-7]{26}$`, 128 random bits the client chooses when the action starts), otherwise `400`.

  - They are stored with the revision or tombstone as metadata, like its author: they are not part of its id (§3.3), so identical patches in different gestures still have identical ids, and rules don't see them.

  - A gesture's revisions may span several saves and resources of one namespace. The id is the writer's own label, never verified, so tools group revisions by author and gesture together, and attribute an `Undoes` to whoever wrote it (§11.2).

  - An idempotent retry (§7.2) is answered with the entry as first recorded, whatever its retry carries, and its `Gesture` and `Undoes` headers say what was recorded.

  - A namespace-document write (§7.4) is a write too, and carries them the same way. A batch's `config` change carries none: a batch's defaults apply to its items' steps. Undoing a config change is outside §11.2.

-
**Idempotent retry.** Suppose the precondition fails, but the log already contains the entry this request would have produced, recorded **with that parent**:

  - for an append or restore, the revision id of §3.3 with `If-Match` as parent

  - for a create, the genesis id of §3.3 with an empty parent

  - for `DELETE`, the tombstone id of §3.4

If that entry was written by the **same principal**, respond `200` with it instead of `412` (or `409 frozen`). The check looks anywhere in the log, not only at the head, but not in a purged resource, whose answer is `410` (§6.2). History newer than the retry window (§6.6) is never pruned, so within that window the check always works. Retries after a lost response are then safe even if others have written since, or the namespace was frozen since. A different principal sending identical patches gets `412`.

-
**Frozen namespaces.** Writes to a frozen namespace are `409` with `code: "frozen"` and its `successor`, if any (§8.4), after authorisation and the idempotent-retry lookup (§6.2).

-
**Namespace revision.** Every successful write response carries `X-Namespace-Revision: {ns_id}`, the namespace entry the write produced, for read-your-writes in consumers (e.g. §A.5).

-
**Caching.** Write responses are `Cache-Control: no-store`.

### 7.3 Events (Server-Sent Events)

`GET /r/{ns}/{name}/events?since={id}`. `Last-Event-ID` is also accepted.

- The stream first replays entries after `since`, reading one log page (§7.1) per fetch, then streams live ones.

- Event types are `revision` (data: a log entry), `tombstone`, `purge` and `prune`. The SSE `id:` field is the entry id. Replay follows the rule of §7.1: if a revision to replay has its patch set pruned, the response is `410` and the client reloads the head.

- Responses are `Cache-Control: no-store`, and require `read`.

### 7.4 Namespace

| Request | Response | Cache-Control |
|---|---|---|
| `GET /ns/{ns}` | `302` with `Location: /ns/{ns}/rev/{ns_id}`, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}` | head pointer |
| `GET /ns/{ns}/rev/{ns_id}` | `200` with the namespace document in force at that point in the chain, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}` | immutable |
| `GET /ns/{ns}/rev/{ns_id}/log?since={a}` | `200` with an array of `{ id, prev, kind, resource?, name?, remote?, at?, target?, entries?, source?, forced?, author, grant?, gesture?, undoes?, gestures?, created }`, following §3.5, where `gesture` and `undoes` are those of a single write, and `gestures` maps each resource of a batch to a list of `{ "gesture"?, "undoes"? }`, one per step (§7.2), none of them hashed, and `grant` is `{ "id", "sub", "kid" }`: the grant id (§C.3) in the text form of §3.2, and its root `sub` and `kid`. A local branch's creation records the creator's grant on both its entries, and a namespace's genesis the operator's. `grant` is absent from entries the server writes itself: propagated purges, purges applied from a remote base, and the prunes and epoch rotations the server performs on its own. Prunes and rotations by a janitor or operator service record its grant, and the schema namespaces a remote branch mirrors at creation record the creating operator's. It is `null` on entries written while authentication is disabled (§1), and absent from entries written before v0.37 unless the grant can be recovered from their revisions; such entries count for no one in `merge.authors` and claim checks (§F.3, §F.6). Paged as in §7.1 | immutable |
| `GET /ns/{ns}/rev/{ns_id}/heads?after={name}` | `200` with a page of `{ resource, kind, target }`, one per resource as of that revision, including resources a branch reads through, in ascending byte order of name, strictly after `after`, which is a plain bound and needn't name an existing resource; `next` for the following page | immutable |
| `GET /ns/{ns}/events?since={ns_id}` | SSE of namespace entries | `no-store` |
| `GET /ns/{ns}/gestures/{gesture}` | optional: `200` with `[{ resource, id, kind, gesture?, undoes?, author, ns_id }]`, one per revision or tombstone written with that gesture or undoing it, oldest first, leaving out purged resources. Paged by `logPageSize`, oldest first: a full page carries `X-Log-Next: {resource}/{id}` (its last row, `id` in text form, unquoted; ids repeat across resources), the next page is `?after=` that value, and a page without `X-Log-Next` is the last. Lists revisions and tombstones only: config writes with that gesture are found in the namespace log. Requires unrestricted `read` on the namespace (as §7.6 does). Not offered in sealed or end-to-end namespaces, whose logs are the place to look: `404` with `code: "not_offered"`, after the `read` check | `no-store` |
| `GET /ns/{ns}/grants/{gid}` | `200` with `{ id, root, stored }`, a grant recorded by an entry of this namespace or, in a local branch, of its bases, in its non-bearer form (§C.3.1); `404` for any other. Requires unrestricted `read` on the namespace (as §7.6 does); sealed in sealed namespaces, `private` in end-to-end ones | immutable (`private` at E3) |
| `GET /ns/{ns}/branches` | `200` with `[{ name, at, frozen, purged, successor?, drafts? }]` for the namespace's direct branches, and `{ remote, at, ns_id, expires }` for remote branches whose registration hasn't expired (§G.3). Requires `read` | head pointer |

**Namespace writes.** The namespace document is edited like a resource, with a JSON Patch on its own URL:

| Request | Precondition | Success | Failure |
|---|---|---|---|
| `PATCH /ns/{ns}`, `Content-Type: application/json-patch+json` | `If-Match: "{config_id}"` (the value of `X-Config-Revision`), or `If-None-Match: *` to create | `201` with `X-Config-Revision: {new config_id}`, `X-Namespace-Revision: {ns_id}` and `Location: /ns/{ns}/rev/{ns_id}`, the namespace entry the write produced, and body `{ "config": new config_id, "ns_id" }`. An idempotent retry (§7.2) answers `200` with the same headers and body; when a batch wrote the config change, `ns_id` is the batch's entry | `412` + `{ config }` · `422` · `428` · `401`/`403` |

- **Why `If-Match` takes the config id.** `ns_id` moves on every document write, so conditional config edits would conflict constantly on a busy namespace. The config id only moves when the configuration changes. This is a deliberate, documented use of `If-Match` against a value other than the resource's ETag.

- **Envelope.** Config writes are checked with a `config` envelope (§6.4.1). Key-scope and grant rules apply to them.

- **Keys, roles, revocations, limits and exposure.** Writes covering or overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption` or `/signatures`, and writes that set `read` to `public`, additionally require a grant chained to a key with `can: ["*"]`. A role definition changes what every outstanding grant naming it can do (§C.1.1), so it is guarded like a key. Making a namespace public or changing its encryption exposes everything in it, so those are guarded too. Making `read` stricter needs no `*` key.

- **Validation.** The namespace document is validated against the built-in namespace-document schema of the deployment's version. Rules and patterns must be well-formed and within limits. The members this spec defines are validated strictly:

  - **Core:** `read`, `keys`, `roles`, `revoked`, `rules`, `limits`, `allowances`, `retention`, `encryption`, `maxLag`, `base`, `frozen`, `successor`, `drafts` and `signatures` (§C.3.1).

  - **Addendum B:** `catalog`, `{ "trust"?: [namespace names], "mode"?: "tree" | "dag" }`, and `catalogs`, `{ "<catalog>": { "place"?: [subjects] } }`, where subjects are `group:…` or `user:…`.

  - **Addendum F:** `merge`, `{ "authors": [{ "sub", "kid" }] }`; `merged`, `{ "at" }`; `cleanup`, `{ "merged"?, "superseded"?, "abandoned"? }` as ISO 8601 durations; and `abandoned`, a boolean. They may appear in any namespace. They mean something in branches, and a base's own `cleanup` sets the minimums for its branches (§F.6).

  - **`x-` members.** Any other top-level member must start with `x-` (case-sensitive) and is stored as data. So may members inside the addenda's objects above, except as keys of `catalogs`, which are catalog names. Role entries are open: the core reads `can` and `rules` and ignores the rest, which consumers use, such as `move`, `place` and `includes` (§C.1.1, §B.11.1, §B.11.4). Other nested objects, such as key entries, are strict.

  - **Errors.** Anything else is `422` with `code: "invalid"` and `errors: [{ "pointer", "message" }]`, as for schema validation, so a typo, or a setting from a newer version, is refused rather than silently ignored. This check runs before the `*`-key guard.

  - **Documents stored under an earlier version** may hold members this version doesn't define. A write keeps such a member, or such a field in a key entry, if it leaves it unchanged, may remove it, and is `422` only if it adds or changes one; a `move` to an `x-` name renames it. Creating a branch of such a namespace is `422` until it is renamed, since a branch is a new namespace.

  - **Versions.** `GET /` publishes the spec version a deployment implements (§7). A deployment that reads another's namespace documents, as a remote branch reads its base's (§G.3), ignores members it doesn't define, so a remote branch keeps working when its base upgrades first. Only a tool that copies a document into a namespace refuses one that holds such a member, unless it starts with `x-`; it never refuses on the version alone.

- **Content types.** Other `PATCH` content types are `415`.

- **Logging.** A config change appends a `config` entry to the namespace chain. Namespace events use the entry's `kind` as their event type: `head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns` and `prune`.

- **Branch fields.**

  - `base` is set when a branch is created and can never change (`422`).

  - A config write to a branch MUST NOT remove or change a key entry that is a `*` key in one of its bases (`422`), so the bases' administrators keep control of their branches (§7.6).

  - `frozen` and `successor` have the meaning of §8.4. `successor` MUST name an existing namespace with the same base namespace (`422`). Its `at` may differ, as it does after a rebase (§F.5).

  - A branch of a namespace whose `read` isn't `public` MUST NOT become `public` (`422`), because a branch is a copy (§7.6).

  - A branch MUST NOT have a lower `encryption.level` than its base (`422`), for the same reason.

  - `drafts: { "for": [ … ] }` (optional) lists the other namespaces whose writes may resolve schema paths into this branch, with their branches (§6.1): names, or prefixes ending in `*`. Without it, a branch's drafts serve only itself and its own branches, so nobody can come to depend on them uninvited. Narrowing it is subject to the `in_use` rule of §6.1. A bare `"*"` serves every namespace. `drafts` is `422` in a namespace that isn't a local branch, or that is end-to-end encrypted, where it could have no effect.

  - Conversely, a namespace with public dependents can't stop being public or become sealed (`409`, `code: "in_use"`, with `dependents`). Otherwise its content would stay public through them.

### 7.5 Batches

Writes to several resources of one namespace, applied all or nothing:

```
POST /ns/{ns}/batch
Content-Type: application/json

{ "items": [
    { "resource": "derby", "ifMatch": "1a…", "steps": [ [ …patches ], [ …patches ] ] },   // two revisions
    { "resource": "final", "ifNoneMatch": "*", "steps": [ [ { "op": "add", "path": "", "value": { … } } ] ] },
    { "resource": "cup",   "ifMatch": "1c…", "steps": [ "delete" ] },
    { "resource": "semi",  "ifMatch": "1d…", "steps": [ "delete", [] ] } ],                // delete, then restore
  "config": { "ifMatch": "1k…", "patches": [ … ] },     // optional
  "source": { "ns": "release-7", "at": "1n…" } }        // optional provenance; may name another deployment (Addendum G)
```

-
**Items.** Each item names one resource, at most once per batch, with exactly one precondition as in §7.2 (a missing one is `428`). Its `steps` are applied in order, each chained on the previous one:

  - a patch set appends a revision, or restores if the previous entry is a tombstone

  - `"delete"` appends a tombstone. One that follows another `"delete"`, with no patch set between them, is `422`, as a `DELETE` of a tombstoned resource is `410` (§7.2).

A step may also be an object with exactly one of `"patches": [ … ]` or `"delete": true`, plus optional `gesture` and `undoes` (§7.2) and `signature`, the step's author signature in the form of the `Signature` header (§C.3.1). An item, or the whole batch, may carry `gesture` and `undoes` as defaults, which a step's own values override. Merges use this to carry each replayed revision's gesture (§F.3).

Resource purge is never part of a batch.

-
**Checks.** Every step is checked with its own envelope, following §6.2 across the whole batch.

  - `items` may be empty or absent when `config` is present.

  - The optional `config` change runs steps 1–6 **first**, as a config write (§7.4, including the key and role guards).

  - The items are then checked against the configuration it produces, except that `frozen` and the batch limits (§6.6) always come from the current configuration.

  - Batch limits can depend on the principal, through an allowance (§6.6). The principal is known as soon as the grant is verified, so the server stops reading a body larger than that principal's `batchSize`, plus room for the batch's own envelope (item names, preconditions, a `config` change), at once (`413`), which reveals nothing about any item. Item counts are checked at step 4, like other limits.

  - Items may reference schema revisions created by earlier items (§6.1). Blobs they reference are uploaded or copied before the batch, or, with a local `source`, taken from it, which needs a grant that may read the source there, or one in `Source-Authorization` (§7.8).

-
**Success.** `201` with `{ "ns_id": …, "items": [{ "resource": …, "ids": [ … ] }] }` and `X-Namespace-Revision`. One `batch` entry is appended (§3.5). Clients can compute the ids in advance (§3.3).

-
**Failure.** Nothing is written. The status is that of the earliest failing step of §6.2, and the body is `{ "code": "batch", "items": [{ "index", "status", "code", … }] }` for the items that failed at that step. If any item fails authorisation, only those items are reported.

-
**Dry run.** `?dry-run=1` runs steps 1–6 for every item and writes nothing. A blob that isn't available is reported, and the later steps run as if it were, so a dry run isn't cut short by blobs not yet uploaded. It returns `200` with the report for every item, including the ids a submit would produce. Authorisation still comes first: if any item fails step 1, the dry run answers exactly as a submit would (`401` or `403`, reporting only those items), so it never reveals a precondition before authorisation (§6.2). The result may differ by the time the batch is submitted.

-
**Idempotent retry.** If one earlier `batch` entry by the same principal already contains exactly the entries this batch would produce, and every item's recorded verb is one of its candidate verbs (§6.2), the response is `200` with that batch, as in §7.2. Items of such a retry whose resources have been purged since are `410`, as for single writes (§6.2), before any other precondition.

-
**Reading other namespaces.** Some checks read a namespace other than the one the request names: a batch's local `source` (below), a blob copy's source (§7.8), and a draft schema in a branch (§6.1). Each tries the request's own grant and every grant in `Source-Authorization` headers, which may be repeated. The first that names that namespace, verifies under its keys (§C.2) and allows the read serves. A public namespace needs no grant, as for any read of it (§7). If none serves, the check fails as that section says, revealing nothing about the namespace.

-
**`source`** is recorded in the batch entry. For a local source, and a caller with unrestricted `read` on `source.ns` (as branch creation requires, §7.6; by the rule above), the server checks that `source.at` is in the chain of `source.ns` (`422`, `code: "source"`), at step 4 of §6.2, before blob references, which may depend on it. For any other caller the source is recorded unchecked and makes no blobs available, so the check reveals nothing about a namespace the caller can't read. A source in another deployment carries `origin` and is recorded without checks (§G.3, §G.4.4). An `origin` equal to this deployment's own is `422`. Either way, that the items correspond to the source is asserted by the writer, not verified.

-
**Scope.** A batch never spans namespaces, and there is no other way to change several namespaces atomically.

-
**Events.** Each resource's event stream carries its new entries as usual. The namespace stream carries one `batch` event.

### 7.6 Branches

A branch is a namespace created from a **base** namespace at a namespace revision `at`. It reads the base through as of `at` and records only its own changes. Addendum F describes merging, rebasing and cleaning up branches.

**Creating a branch:**

```
POST /ns/{base}/branches
If-None-Match: *
{ "name": "release-7", "at": "1k…", "patches": [ … ] }     // `at` defaults to the base's current head
```

- **Result.** `201` with `Location: /ns/{name}`, and `X-Namespace-Revision` for the `branch` entry appended to the base's log (§3.5).

  - A taken name is `412`, including one taken by a purged namespace. A retry by the same principal with the same `at` and `patches` gets `200`, as in §7.2.

  - An `at` that isn't in the base's chain is `422`. A purged base is `410`.

- **Configuration.** The branch's namespace document starts as a copy of the base's **current** document, so keys and revocations are up to date.

  - `frozen`, `successor`, `merged`, `abandoned` and `drafts` are removed, `base: { "ns": base, "at": at }` is added, and then `patches` are applied.

  - The branch's configuration chain starts with the genesis patch set `[{ "op": "add", "path": "", "value": <that document> }]`, so its config id is reproducible.

  - A branch's rules, roles and read mode are its own from then on. Its **keys follow the base** (§C.4).

- **Authorisation.**

  - The caller needs `branch` on the base.

  - The caller needs **unrestricted** `read` on the base. No rule in the grant's blocks, its key's scope or its effective roles may refer to `/resource`, and the key may not have `readScope`. Otherwise a reader limited to some resources could branch the namespace and read the rest through the branch. Bases whose read access is decided per document (§C.5.1) should not grant `branch` at all.

  - `patches` covering or overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption` or `/signatures` need a grant chained to a `*` key **of the base**. Every `*` key of the base is kept in the branch and can't be removed from it, so the base's administrators can always freeze and purge its branches.

  - The base's rules evaluate a `branch` envelope. Its `resource` is the new namespace's name, its `doc` is the new namespace document, and its `writes` come from `patches`. A base can therefore decide who may branch it, how branches are named (e.g. `^release-`), and what they may change.

- **A branch is a copy.** Whoever can read the branch can read the base as it was at `at`, under the branch's own configuration. A branch of a namespace that isn't public MUST NOT be public (§7.4).

- **Nesting and number.** A branch may itself be a base, within the branch-depth and branches-per-namespace limits (§6.6).

- **In another deployment.** A branch's base may also live in another deployment, `base: { "origin", "ns", "at" }`. Such a **remote branch** is a new namespace, created with the deployment operator key as §C.4 bootstrapping requires, and is described in §G.3. The rules of this section that rely on one operator (keys following the base, revocation in bases, purge propagation, dependents blocking a namespace purge) do not reach across deployments.

**Reading through.** For a resource with no entries of its own in the branch, the branch answers as the base did at `at`, recursively through bases of bases:

- a `302` to the head as of `at`

- a `410` if it was tombstoned then

- a `404` if it didn't exist then

Everything is served under the branch's own URLs: `/r/{branch}/{name}` and `/r/{branch}/{name}/rev/{id}`. Changes in the base after `at` are never seen, except purges (§8.3).

**History.** `/r/{branch}/{name}/rev/{id}` serves any id in the resource's ancestry as seen from the branch, including base revisions up to the foreign parent. `…/log?since=` crosses the foreign parent. `/r/{branch}/{name}/blob/{bid}` serves every blob available as seen from the branch, including the base's (§7.8).

**First write.** The first write to a read-through resource checks its precondition against the base's head as of `at`, and takes that head as its **foreign parent**, whether it appends, deletes or restores. Creating a name that didn't exist in the base at `at` is an ordinary create.

**Logs.** The branch's namespace log contains only the branch's own entries. Its creation is recorded in the base's log as a `branch` entry, so anything following the base learns of new branches as they appear (§10). `GET /ns/{branch}/rev/{ns_id}/heads` lists every resource as the branch sees it, including read-through ones. `GET /ns/{base}/branches` lists the current branches with their state.

**Branch names are visible to the base's readers,** in its log and listing. Bases that must hide what their branches are about can require opaque names with a rule on the `branch` envelope's `resource` (§6.4.1).

### 7.7 Live reads by long-poll

Server-sent events (§7.3, §7.4) keep one connection per client open to the origin. When many clients follow the same log, a **long-poll** read lets the CDN collapse their identical waiting requests into one:

```
GET /ns/{ns}/log?since={ns_id}&live=long-poll&cursor={c}
GET /r/{ns}/{name}/log?since={id}&live=long-poll&cursor={c}
```

- **Answer.**

  - If there are entries after `since`, the server answers `200` at once with them, oldest first, up to the log page size (§6.6), in the shapes of §7.1 and §7.4. An empty or missing `since` means from the beginning, as in §7.1 and §10. `X-Namespace-Revision` (resource logs: `X-Revision`) names the last entry returned, which is the next `since`.

  - Otherwise it waits until an entry arrives or the current **interval** ends, whichever comes first. The timeout answer is `204`, with the same header naming `since`.

  - Both answers carry `X-Cursor`.

  - A `since` that isn't in the chain is `404`. If any revision after `since` has its patch set pruned, the answer is `410`, as in §7.1. It requires `read`, like any log read.

  - Without `live`, these URLs answer `302` to the immutable range `…/rev/{head}/log?since=…`.

- **Intervals and cursors.**

  - The server divides time into fixed intervals (default 20 seconds) counted from a fixed epoch. The cursor is the interval number, in decimal. Origin instances SHOULD keep their clocks synchronised to well within an interval, e.g. by NTP to under a second. The `204` rule below keeps skew from repeating URLs, but waiters near a boundary would split between cursors and stop collapsing.

  - On `200`, the response cursor is the current interval number. The next request has a new `since`, so its URL is new anyway.

  - On `204`, the response cursor is the greater of the current interval number and the request's cursor plus one. That covers the one case where a URL could repeat: the same `since` after a timeout, or clock skew between origin instances. It is deterministic, so every client waiting at the same `since` holds the same cursor after one idle boundary and stays collapsed. (Durable Streams adds random jitter here; that would split waiters across URLs and defeat collapsing.)

  - A wait ends at the latest at the interval boundary, so every request waiting on the same URL is answered at the same moment.

  - A cursor more than one hour's worth of intervals ahead of the server's is `400`, so cursors can't mint unlimited cache keys.

- **Caching.**

  - The cache key is the path plus `since`, `live` and `cursor`. The page size is fixed by the deployment, not chosen by the client. Any other query parameter is `400`, so it can't be used to bypass the cache.

  - `200`: `public, max-age=0, s-maxage={interval}`. Entries are immutable, and every answer is a correct range starting at `since`. A late reader served a cached copy only misses newer entries, which its next request (with a new `since`) returns at once.

  - `204`: `public, max-age=0, s-maxage=2`, long enough to answer every collapsed waiter, short enough that a late arrival doesn't wait long for data it missed. Some CDNs don't cache `204` by default, so this may need enabling.

  - With request collapsing at the CDN, the origin then sees one request per URL, however many clients wait on it. Private and sealed namespaces follow §9: edge grants, `private` downstream, and edge lifetimes as above. Every reader of a log may read all of it, so collapsing across readers reveals nothing.

  - Tags are those of the log (`ns:{ns}`, and `r:{ns}/{name}` for resource logs), so purges reach cached answers (§8.3).

- **Clients** echo `X-Cursor` as `cursor` in the next request, take the returned revision as the next `since`, and poll again at once after a `200`.

- **Which to use.** SSE stays the simpler choice for a few clients, such as the editors of one document. Long-poll is for many followers of the same log: live pages, feeds, previews and consumers at scale.

- **Several logs at once.** Each followed log holds a connection for a whole wait. Over HTTP/2 or HTTP/3 they share one connection, but over HTTP/1.1 a browser allows about six per host, so a page following several logs starves itself. Serve long-poll over HTTP/2 or later. A combined URL for several logs would defeat collapsing, since every combination is its own cache key, so the spec doesn't define one. A page that follows many logs is better served by a service that follows them and publishes one feed.

### 7.8 Blobs

Large values, such as images, audio, PDFs or long texts, are stored as **blobs**: immutable bytes attached to one resource and referenced from its documents. The document stays small and editable. The blob is uploaded once and served from its own immutable URL. Strings in documents are limited by `valueSize` (§6.6), so anything larger is a blob.

-
**References.** A document refers to a blob with an object whose `$blob` member is a string, at any depth:

```
"hero": { "$blob": "1m4…", "type": "image/jpeg", "size": 1843302 },
"scan": { "$blob": "1p7…", "type": "application/pdf", "size": 412977, "nonce": "k3q…" }   // a private namespace
```

  - `$blob` is the blob id (§3.7), `type` its media type and `size` its length in bytes. `nonce` is present exactly when the blob has one. No other members are allowed, except `sealed` at E3 (§E.3.1).

  - References are found by walking the document, whether or not it has a `$schema`. A malformed one is `422` (`code: "blob"`, §6.5).

  - Schema documents, whose `$schema` is a dialect URL (§6.1), contain no references, so a schema can describe them like any other object, e.g. with `"required": ["$blob"]`.

-
**Attachments.** A blob belongs to a resource in a namespace through an **attachment**:

  - **Pending:** after an upload or a copy, until a revision references it. The **uploader** is the principal as rate limits know it: root `sub` and `kid` (§6.6). After a key rotation, a writer uploads its pending blobs again. A pending blob is invisible: reads answer `404`, and only its uploader can reference it. Each uploader has its own pending entry, even for bytes already stored, so one uploader learns nothing from another's. An entry counts toward its uploader's `blobPending`, at least 4 KiB per blob, and is deleted once it is older than `blobGrace`. Uploading it again restarts that time. A write whose document references the blob ends every pending entry for it in that resource, whoever uploaded it, so uploading a blob that is already attached costs nothing once a write uses it.

  - **Attached:** at step 7 of §6.2, a write attaches every blob its resulting document references to its own resource, in the same transaction as the revision.

  - An attachment lasts while a document still stored for the resource references the blob: the documents at or after the horizon (§8.6), the horizon's and other kept documents, and the last live document of a tombstoned resource. When pruning removes the last such document, the attachment ends and the bytes are deleted; the archive has them (§G.4.1). Purge ends every attachment of the resource (§8.3).

-
**Availability.** A write may reference only blobs **available** to its resource:

  - attached to that resource in this namespace

  - pending there, if the writer uploaded or copied it

  - in a branch, attached to the same resource in a base and referenced by a document in the resource's history as the branch sees it (§7.6). The write attaches it to the branch's own resource, so the branch keeps it whatever the base prunes later.

  - in a batch with a local `source` whose `source.at` the server has checked (§7.5), attached to the same resource in `source.ns`, or in a base it reads through, and referenced by a document in that resource's history as `source.ns` sees it at `source.at` (§7.6). That check needs unrestricted `read` on the source, by the rule for other namespaces (§7.5); a per-resource reader of the source copies instead (below). Anything less makes the blob unavailable. The ranking for copies doesn't apply: the batch publishes the source's documents anyway, and its rules and the merger's grants decide whether it may. Merges and rebases therefore copy nothing (§F.3).

A reference to a blob that isn't available, or that doesn't match the blob's `type`, `size` or `nonce`, is `422` with `code: "blob"`, at step 4 of §6.2.

-
**Uploading.**

```
PUT /r/{ns}/{name}/blob/{bid}
Content-Type: image/jpeg
Blob-Nonce: k3q…              (optional: 26 base32 characters)

```

The checks run in this order:

  - **Authorisation**, at step 1 of §6.2, with `create`, `append` and `restore` as candidate verbs: the upload is allowed if the grant could write the resource with any of them. Then the rate limits (§6.6). Rules beyond step 1 never see an upload: a blob has no effect until a write references it, and that write passes the whole gate.

  - A purged resource, or a purged namespace (§8.5), is `410`. A tombstoned resource accepts uploads, so blobs can be uploaded before a restore that references them.

  - A frozen namespace is `409` (§8.4).

  - A media type that can't be parsed is `400`. In an E3 namespace, any type other than `application/vnd.patchlog.sealed-blob` is `415` (§E.3.1).

  - A body larger than `blobSize`, or one that would take the uploader's pending blobs in the namespace past `blobPending`, is `413`.

  - The server recomputes the id over the body (§3.7). A mismatch is `422` with `code: "blob_mismatch"`.

  - **No precondition.** An upload changes no head, so it needs none (§7.2), and it writes no namespace entry (invariant 5). It is idempotent. The answer is `201` with `ETag: "{bid}"` whether or not the bytes were already stored, and every uploader is charged for its own pending entry, so the answers reveal nothing about what others uploaded.

  - **Copying.** With an empty body and `Blob-From: /r/{ns2}/{name2}/blob/{bid}`, naming the same `bid`, the server copies a blob within the deployment instead of receiving it again:

    - Checks 1–3 run first, for the target. Then a request with a body, or a `Blob-From` that can't be parsed, is `400`, before any body is read, and a different `bid` is `422` (`code: "blob"`).

    - The source is then checked as a read of `/r/{ns2}/{name2}`, by the rule for other namespaces (§7.5). A grant whose blocks name both namespaces, signed by a key they share (as a base and its branches do, §C.4), serves for both. Any failure of this check, including the `401` and `403` cases of §C.2, answers `404`.

    - Namespaces are ranked as for imports (§G.5.1): `public`, then `private` and `sealed` alike, then `e2e`. A copy from a higher rank into a lower one is refused, so content readable only under grants or keys never becomes public through a copy. (A copy into `e2e` needs a sealed blob, check 4.)

    - A source the caller can't read, one of a higher rank, and a blob that §7.8 Reading wouldn't serve there all answer `404`, so a copy reveals nothing about a source the caller can't read.

    - The copy is then checked like an upload of the source's type, nonce and size (checks 4 and 5). It costs a token like an upload, and nothing from `blobRate`. A batch with a local `source` carries `Source-Authorization` in the same way.

-
**Reading.** `GET /r/{ns}/{name}/blob/{bid}` answers `200` with the bytes, `Content-Type` as uploaded, `ETag: "{bid}"` and `Accept-Ranges: bytes`. A range request gets `206`. Sealed namespaces answer as in §E.2.2 instead.

  - Access is that of the resource: whoever may read `/r/{ns}/{name}` may read its blobs, so per-resource grants and edge grants cover them (§C.5, §B.11.5).

  - It serves the blobs attached to the resource and, in a branch, the base's blobs that the branch's view references (§7.6). Pending and unknown blobs are `404`. A tombstoned resource keeps serving its blobs, like its history (§8.1). A blob whose attachment pruning ended is `410` as in §7.1, and every blob of a purged resource is `410`.

  - Caching is immutable, with the resource's tags (§9). In sealed namespaces the URL also names an epoch (§E.2.2).

-
**Encryption.** In sealed namespaces (`level: "sealed"`), writers MUST give the blobs they create a nonce (§C.7). Blobs carried over from another namespace keep their ids, nonce or not, as imports and copies require. Like `$nonce`, this is the writer's obligation, and the server doesn't check it. The server seals blobs on delivery (§E.2.2). At E3 clients encrypt each blob under a key of their own that travels in the sealed reference, and declare in plaintext which blobs each revision references (§E.3.1).

-
**Why per resource.** Read access, sealing keys, cache tags, purge and its propagation to branches all follow the resource's URL, so blobs need no rules of their own. The cost is that the same bytes in two resources are two attachments, which storage may keep once (§D.2).

---

## 8. Deletion and purge

### 8.1 Tombstone (delete)

- `DELETE` with `If-Match: head` appends a tombstone to the resource log **and** a `tombstone` entry to the namespace log, atomically.

- The head pointer then returns `410`. Earlier `/rev/{id}` URLs keep returning `200`, and so do the resource's blobs (§7.8), so history stays readable.

- Further `PATCH` requests return `410`, unless they restore (`If-Match: "{tombstone}"`). A grant without `restore` gets `403` instead, since the verb is settled before the precondition (§6.2).

### 8.2 Restore / recreate

- The chain continues from the tombstone. The first revision after it applies its patches to the last live document.

- `[]` restores the document exactly as it was.

- To recreate from scratch, restore with a root `replace`. Namespace rules decide whether that is allowed (§6.4.4).

- One name always has one chain.

### 8.3 Purge

- **Effect.** The resource's content (patches, snapshots and blobs, §7.8) is removed, and the resource is marked purged. Archived history of the resource (§8.6) is deleted too, or made unreadable by destroying its key. Restoring from an archive MUST skip purged resources. Ids, parent links and namespace entries are kept, so both chains stay verifiable.

- **Namespace entry.** A `purge` entry is appended to the namespace log. Consumers MUST drop the resource and purge their own derived data and cache tags (§10).

- **Responses.** All `/r/{ns}/{name}/…` URLs then return `410`.

- **CDN.** The CDN is purged by tag (§9). Ids are shared across resources, so purge by resource, never by id.

- **Branches.** A purge propagates to the **same name in every branch** of the namespace, recursively, whether the branch reads it through or has its own chain for it. That includes successor generations and chains the branch created itself. The server purges the resource there and appends a `purge` entry to each branch's namespace log.

  - Replayed merges give content new ids, so name, not id, is what identifies "the same content" across a family of branches.

  - Purges never propagate upwards. To remove content everywhere, purge it in the topmost base it reached: the propagation covers every branch below.

- **Limits of purge.**

  - Purge cannot recall copies already held by browsers and other caches the operator doesn't control. §9 bounds how long those can live.

  - Purge does **not** remove hashes. Content-hash ids of low-entropy content can be confirmed by guessing (§C.7).

  - Copies of a blob in other resources (`Blob-From`, §7.8) are separate copies, like any copied text, and stay until those resources are purged too.

### 8.4 Freezing a namespace

- **Freezing.** A config write sets `"frozen": true`. Resource writes and batches are then `409` with `code: "frozen"`, and the body carries `successor` if set. Setting `frozen` to `false` unfreezes the namespace.

- **What still works:**

  - reads, events and namespace consumers

  - config writes

  - resource purges, which must always be possible

  - creating branches from it

  - pruning (§8.6)

- **`successor`** optionally names the namespace that replaces this one, e.g. the next generation of a rebased branch (§F.5). It must have the same base namespace (§7.4). Clients SHOULD move to it (§11).

- **Freezing is the namespace's tombstone.** It keeps everything readable and is reversible. Namespace purge (§8.5) is the irreversible step.

### 8.5 Purging a namespace

- **Request.** `POST /ns/{ns}/purge` with `If-Match: "{ns_id}"`, the namespace head the caller has seen. `204` on success.

- **Requirements.**

  - the `purge-ns` verb (Addendum C), which is separate from `purge` so a role that may purge single resources cannot wipe a namespace

  - the namespace is frozen: otherwise `409` with `code: "not_frozen"`

  - no **dependents**: a namespace whose `base` is this namespace and that isn't purged. Otherwise `409` with `code: "in_use"` and `dependents: [...]`, and cleanup proceeds leaves first.

  - it would remove no last copy of a referenced schema revision (§6.1) referenced from another namespace: otherwise `409` with `code: "in_use"`.

- **Effect.**

  - Every resource is purged as in §8.3, without individual entries. One `purge-ns` entry is appended.

  - The namespace document chain, the namespace log (with authors, §5) and every resource's ids and parent links are kept, so the history of who changed what stays verifiable.

  - All `/r/{ns}/…` URLs, and `/ns/{ns}/grants/…`, return `410`. `/ns/{ns}` and its log stay readable.

  - The name stays reserved and can't be reused.

  - The CDN is purged by the tag `ns:{ns}` (§9).

- **Shared storage.** An implementation that stores identical entries of several namespaces once removes only this namespace's references.

- **Forcing.** A namespace purge refused as `in_use` for schema references can be forced as §6.1 says. Dependents can't be forced.

- **Irreversible.** There is no restore.

### 8.6 Pruning and retention

Pruning bounds the storage of long or fast-growing histories **without changing any id**. URLs, merges, branches and caches that point at kept revisions keep working. Older revisions answer `410` with a link to the archive.

- **Horizon.** Pruning a resource below a horizon revision `H` removes the patch sets of the revisions before `H`.

  - **Kept:** every id, parent link, author, grant reference, creation time, `gesture` and `undoes`, so audit (§C.3) keeps working, and `H`'s document, and the documents kept for protected revisions (below).

  - **Dropped:** the patch sets before `H`, roughly a third of the storage per revision (§D.5), and the attachments of blobs that only the dropped documents referenced (§7.8). The archive carries those blobs. Ids, parent links and log rows still grow linearly; rate limits (§6.6) bound that growth.

  - If `H` is a tombstone, the last live document is kept too, so a restore (§8.2) still works.

- **Request.** `POST /r/{ns}/{name}/prune` with `{ "horizon": id, "keep"?: [ids], "snapshot"?: sealed }` returns `200` with the effective horizon.

  - It needs the `prune` verb, and is checked with a `prune` envelope whose `doc` is `{ horizon, keep }`.

  - It changes no head, so it takes no precondition. It works in frozen namespaces too.

  - `horizon` MUST be an ancestor of the head, or the head itself (`422`). The server moves it down to the oldest protected revision if needed.

  - Going below what `retention` keeps for the resource, or pruning where no archive is configured, needs a grant chained to a `*` key. Applying a retention rule that says `"archive": false`, within what it keeps, needs only `prune`: the `*` key was needed to write that rule.

  - `keep` lists extra revisions whose documents stay available, e.g. targets of pinned `x-ref`s found by a reverse-reference consumer (§6.5). A kept document costs far more than the patch set it replaces, so `keep` is limited (§6.6). Each prune's `keep` replaces the resource's earlier `keep` set. It is `422` in an E3 namespace, where the server can't compute documents. The core doesn't interpret `x-ref`. Pinned references to other pruned revisions get `410`.

  - A `prune` entry `{ resource, kind: "prune", target: H }` is appended to the namespace log, only if the horizon moved. A prune that changes nothing writes nothing.

- **Protected revisions.** The horizon never passes any of these:

  - everything newer than the **retry window** (§6.6), so idempotent retries (§7.2) and rebasing editors keep working

  - each resource's head as of the `at` of every local branch that isn't purged, frozen or not, and of every remote branch whose registration hasn't expired (§7.6, §G.3). Read-through and merges need the history from there on.

- **Protected documents.** These keep their documents below the horizon:

  - referenced schema revisions (§6.1), from any namespace of the deployment. This is the same reverse index the purge refusal of §6.1 needs. At E3 the server can't see references, so protect schemas with `retention`, applied by a key-holding janitor (below). A prune's `keep` asks the server for documents it can't compute there, and is `422` in an E3 namespace.

  - the revisions listed in `keep`

- **Branches don't prune.** A branch's own entries are protected until the branch is purged (§8.5). Branches are short-lived, and merges and rebases need their whole history.

- **Archive.** Before pruning, the server writes the pruned history as a full-history bundle (§G.4.1) to a destination configured by the operator or in `retention`. It MUST NOT write anywhere else. Archives are written with `"authors": true`, grant lines included, so archived signatures stay verifiable.

  - The archive is only as trustworthy as its storage. The kept ids let anyone check an archived revision against the live chain.

  - In encrypted namespaces (Addendum E), archives hold patch sets as stored, under the keys that purge destroys. At E3 the server can't compute documents, so a key-holding client supplies `H`'s document as `snapshot` (or, when `H` is a tombstone, the last live document), sealed like a patch set (§E.3.1), and pruning needs an archive. The server already holds that document's declared blob list. Retention at E3 is therefore applied by a key-holding janitor, not by the server: a client with `read` and `prune` and the epoch keys, which folds each resource, picks the horizon its `retention` asks for, and submits the prune with the sealed `snapshot`. The server skips E3 namespaces when it applies retention itself.

  - Restoring archived history into the live store is an operational task (§D.4).

- **Retention policy.** The namespace document may declare rules that the server, or a janitor with `prune`, applies periodically:
```
"retention": [
  { "select": { "prefix": "telemetry-" }, "keep": { "revisions": 50, "age": "PT10M" } },
  { "keep": { "age": "P2Y" }, "archive": "s3://archive/matches/" } ]
```

  - The first rule whose `select` matches a resource applies. `select` is a name `prefix`, or a list of `names`. A missing `select` matches everything.

  - `keep` keeps whichever is longer: the last `revisions`, or everything newer than `age`. Protected revisions always stay.

  - `archive` is the destination for that rule's archives. A rule without it uses the operator's configured destination. If there is none, the rule applies only if it says `"archive": false`, so irreversible pruning is always explicit. `"archive": false` is `422` in an E3 namespace, where pruning needs an archive.

  - Changing `/retention` requires a `*` key (§7.4). Without an archive, pruning can't be undone.

- **The namespace log is never pruned.** Its rows are small (§D.5), and branches, retries, consumers and verification all depend on it.

- **Pruning is not purge.** Cached copies of pruned revisions and consumers' copies are untouched, and they remain correct because ids don't change. For removal, use purge (§8.3), which also reaches archives.

- **Verification.** Below the horizon, a kept id can't be recomputed without the archive. A client verifying through logs (§G.2) starts from the archive, or from a revision at or after `H` that it has already verified.

- **Merges, branches and exports.**

  - Classification by ancestry (§F.3) uses ids only, so it works across a horizon.

  - Fast-forward and replay both need the patch sets after the common ancestor. Protected revisions keep them for local branches and remote branches whose registration hasn't expired. For anything else, an item whose needed history was pruned is a conflict.

  - A full-history export (§G.4.3) from before the horizon needs the archive. Otherwise use snapshot mode.

---

## 9. Caching

**Public namespaces:**

| Response | Cache-Control | Tag (`Cache-Tag` / `Surrogate-Key`) |
|---|---|---|
| Head pointer (resource or namespace `302`, head `410`) | `public, max-age=0, s-maxage=1, stale-while-revalidate=5` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Immutable (`/rev/{id}`, `/rev/{id}/log`, namespace log ranges (sealed ones may be sealed again with other bytes, §E.2.2), `/ns/{ns}/grants/{gid}` (`private` at E3, §C.3.1), `/blob/{bid}`, `/blob/{bid}/e/{e}` and their ranges) | `public, max-age=86400, s-maxage=31536000, immutable` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Short (unknown id `404`) | `public, max-age=5` | — |
| Long (purged `410`) | `public, max-age=86400, s-maxage=31536000` | — |
| Pruned (`410` below a horizon) | `public, max-age=3600` | `r:{ns}/{name}`, `ns:{ns}` |
| Live long-poll (§7.7) | `200`: `public, max-age=0, s-maxage={interval}` · `204`: `public, max-age=0, s-maxage=2` | as the log |
| Writes, batches, dry runs, SSE | `no-store` | — |

- **Browsers keep immutable content for a day; the CDN keeps it for a year.** Copies the operator cannot purge therefore expire within a day, while the CDN, which can be purged, holds content for a long time.

- **Stale reads are safe.** A stale head read cannot cause a silent overwrite, because every write names its parent.

- **Serving stale.** Immutable responses never change, so an edge MAY keep serving them while the origin is unreachable. A purge still removes them. Head pointers are served stale only within their `stale-while-revalidate`. Live long-poll answers (§7.7), `200` and `204` alike, MUST NOT be served stale: an old answer would end a wait without the change it waits for. They carry no `stale-*` directive, and an edge MUST NOT apply stale-if-error or grace defaults to them.

- **Empty long-poll answers.** The `204` that ends a wait with nothing new must be cached like the `200`, or followers stop collapsing onto one origin request. A CDN that doesn't cache `204` by default SHOULD be configured to do so for these responses.

- **Tags** are `{kind}:{value}`, where `kind` is a lowercase word (`ns`, `r`, and the kinds addenda define, such as `idx` and `rs`) and `value` is made of namespace and resource names (§3.6) joined by `/`. So a tag uses only `a–z`, `0–9`, `.`, `_`, `-`, `:`, `/` and `~`, and never contains a space or a comma. `Cache-Tag` lists a response's tags separated by commas, and `Surrogate-Key` lists the same tags separated by spaces. A purge names whole tags and never matches part of one. How purges reach the CDN is deployment-specific. For a self-hosted CDN, a `PURGE` request with the tags in `X-Purge-Tags`, separated by spaces, is a reasonable convention (Addendum D).

- **Branches** are cached like any namespace, under their own URLs and tags. A purge that propagates to branches (§8.3) purges their tags too.

**Sealed namespaces** (Addendum E, level E2) use the public rules above: everything leaving the origin is ciphertext, and keys decide who can read.

**Private namespaces** (Addendum C §C.5):

-
**Downstream** responses carry `Cache-Control: private` (e.g. `private, max-age=300` for immutable content), so shared caches between the CDN and the reader never store them.

-
**Edge caching needs an edge that verifies grants.** Private content may be cached at the edge only because the edge verifies an edge grant on every request (the grant isn't part of the cache key). A CDN that doesn't verify grants would serve one reader's cached response to anyone. So there are two deployments:

  - **With a verifying edge**, lifetimes at the edge are given with `CDN-Cache-Control` (RFC 9213) or `Surrogate-Control`, using the same values as for public namespaces. The origin rejects private reads that don't carry the edge's verification, such as a shared secret between the CDN and the origin. Otherwise the edge could be bypassed, and a response fetched around it could be one the edge would cache without verifying.

  - **Without one** (no CDN, or a CDN that doesn't verify grants), the origin verifies grants itself and marks private responses `CDN-Cache-Control: no-store` (and `Surrogate-Control: no-store`), so no shared cache stores them. Only public and sealed content is then cached at the edge.

The origin must know which deployment it is in. It sends edge lifetimes for private content only on requests that carry the edge's verification.

-
**Changing a namespace from public to private** requires a tag purge of `ns:{ns}`, which every response of the namespace carries. The origin issues it with the configuration write that makes the change, as it does for any purge. Copies already in browsers remain until their `max-age` expires.

---

## 10. Namespace consumers

Anything that derives data from a namespace, such as a search index, a feed, analytics or a cache warmer, is a **namespace consumer**: a separate client of the public API with no private access to storage. The core provides everything a consumer needs:

- **Checkpoint.** A consumer stores the last `ns_id` it has fully processed. `""` means from the beginning.

- **Catch up.** `GET /ns/{ns}` gives the current `ns_id`. `GET /ns/{ns}/rev/{current}/log?since={checkpoint}` returns the entries in between, page by page (§7.1), and is cacheable.

- **Follow.** `GET /ns/{ns}/events?since={checkpoint}` streams new entries. Where many consumers or pages follow the same namespace, long-poll `GET /ns/{ns}/log?since={checkpoint}&live=long-poll` instead, which the CDN collapses (§7.7).

- **Coalesce.** Within a range of entries, only the latest entry per resource matters.

- **Fetch content** from immutable URLs: `/r/{ns}/{name}/rev/{id}`, schema revisions and blobs (§7.8).

- **Handle every kind of entry:**

  - `head` → process the document

  - `tombstone` → drop the resource

  - `purge` → drop the resource **and purge derived data and cache tags**

  - `config` → the configuration changed, including `frozen` and `successor`

  - `batch` → process its entries **as one unit**, so derived data never shows half a batch

  - `purge-ns` → drop everything from the namespace, and purge derived data and cache tags

  - `branch` → a branch was created. Consumers that don't follow branches ignore it. Those that do start following it (see below).

  - `prune` → history below a horizon is gone from the live store. Most consumers ignore it. The namespace log itself is never pruned, but a consumer that fetches an older revision may get `410 pruned`; it then fetches the resource's head instead (step 4 makes only the latest entry matter anyway).

- **Advance the checkpoint** only after the entries are durably processed. Processing must be idempotent.

- **Verifying grants.** Consumers that verify grants (Addendum C) MUST check keys and revocations as of the namespace **head**, not as of their checkpoint.

- **Starting from a snapshot.** Instead of replaying from `""`, a new consumer MAY list `GET /ns/{ns}/rev/{current}/heads` and then follow the log from `current`.

- **Consumers elsewhere.** A consumer may run in another network or organisation. It then records its checkpoint as `(origin, ns, ns_id)` and verifies what it fetches (§G.2).

- **Branches.**

  - **Discovery.** A consumer that follows branches learns of them from `branch` entries in the logs it already follows, recursively for branches of branches. It needs no polling. Frozen and purged states then arrive in the branch's own log, as `config` and `purge-ns` entries.

  - **Contents.** A branch's `at` usually lies in the past, so the consumer can't reuse its own view of the base. It starts from the branch's `/heads` listing at the branch's first `ns_id`, which includes read-through resources, then follows the branch's own log. The same holds for a branch a consumer is told to follow directly, such as one named in a release document (§F.9).

  - **Access.** It needs `read` on the branch. A consumer that learns of a branch it may not read skips it.

  - Most consumers follow only the namespaces that aren't branches.

- **No core responsibilities for derived data.** The core has no indexing, search or organising responsibilities. Addenda A and B describe consumers built this way.

---

## 11. Client behaviour (non-normative)

- **load:** `GET /r/{ns}/{name}`, following the redirect. Take the document from the body and the head from `X-Revision`.

- **sync(to):** `GET …/rev/{to}/log?since={head}`, following its pages until the entry `to` arrives (§7.1), then apply the entries in order.

- **submit(patches):**

  - `PATCH` with `If-Match: "{head}"`.

  - On `201` or `200`, apply the returned revision.

  - On `412`, `sync(body.head)` and resend. This is the rebase: patches are path-based, so they are re-applied on the new head.

  - On `422` or `403`, surface the errors.

  - Retry a bounded number of times.

- **Conflict safety:** when an edit must not land on changed data, prefix the set with `{ "op": "test", "path": …, "value": <value seen> }`. A retry on changed data then fails with `422` instead of clobbering.

- **watch:** SSE from `since={head}`, or long-poll `…/log?since={head}&live=long-poll` echoing `X-Cursor` (§7.7) when many clients watch the same document. De-duplicate by entry id, because the client's own writes echo back.

- **Deleted resources:** treat `410` on the head as deleted, and keep the last document readable locally.

- **Frozen namespaces:** on `409 frozen`, if a `successor` is given, load the resource from the successor and replay the pending patch sets there. This is the same loop as a rebase on `412`.

- **Several resources at once:** a batch (§7.5). The client can compute the resulting ids itself, so it can chain several sets for one resource in one request.

- **Combining changes under a rate limit:** while a save is in flight, keep collecting edits into one pending patch set. It is simply the diff from the last saved revision, so a later `replace` of a path wins. Send it when the response arrives. If that response is lost, first resend the in-flight set **unchanged** (§7.2), and only then the combined rest. On `429`, wait for `Retry-After`, then send whatever has accumulated. High-frequency input, such as typing or dragging, then yields a few revisions a second, each carrying the latest values. A combined set carries one `Gesture`, so combining across actions makes them one gesture for undo from the log (§11.2); a client that wants each action undoable from the log sends at each action's end instead.

### 11.1 Designing documents

Lessons from loading real data:

-
**Object member order isn't kept.** Documents are stored in canonical form (§3.1), which sorts members by key. Where order matters, such as slides, menu entries or a map shown in order, use an array of objects with an `id` member, which `x-ref` with `key` can address by id (§6.5), or an explicit `order` field.

-
**`$schema` names a revision.** Data from elsewhere that names its schema by URL, or by a head path, is `422` (§6.1). Import tooling resolves it once to the current revision path, and a migration (§6.3) moves documents to a later revision.

-
**Keep namespace names when moving data.** `$schema` and pinned references contain namespace names, so an import maps each source namespace to the target namespace of the same name (§G.1). Renaming on the way rewrites documents and changes every id.

-
**Large values are blobs.** A string longer than `valueSize` can't be stored. An image, a PDF or a long transcript is uploaded as a blob and referenced (§7.8). Base64 inside JSON costs a third more, and every revision that touches it carries it.

-
**Large documents are created whole and then edited in parts.** A create may be as large as `documentSize`, but appends are limited by `patchSetSize` (§6.6). Large additions to an existing document go in several appends, such as an empty object first and then its parts, or in one batch when they must land together (§7.5).

-
**Split documents along the lines of access, editing and size.** A document is the unit of:

  - read access (§C.5): a field that only some readers may see belongs in another resource

  - concurrency: every save names the head, so a document that many people edit at once gets many `412`s and rebases, and its per-resource rate limits apply to all of it (§6.6)

  - merging: conflicts are judged per resource, and per array inside it (§F.3)

  - size: every revision of a large document costs folding, snapshots and bandwidth (§D.4)

A document should be split when it grows without bound (a log, a comment thread), when parts of it have different readers, or when unrelated people edit it at the same time. Link the parts with `x-ref` (§6.5) and group them with a catalog (Addendum B).

### 11.2 Undo and redo

A client keeps its own undo stack for the edits it just made. Gestures (§7.2) make undo work beyond that: after a reload, from another device, and from a history view.

-
**Recording.** When an action starts, the client picks a gesture id and sends it as `Gesture` with every write the action produces, in every resource it touches.

-
**Finding a gesture.** `GET /ns/{ns}/gestures/{gesture}` lists its revisions where offered (§7.4). Otherwise the client scans the logs it follows for entries with that `gesture`, by the same author.

-
**The inverse.** For each resource, walk the gesture's own entries newest first, and turn each into steps of one batch item (§7.5):

  - a revision: the patch set that turns its document back into its parent's, limited to the paths it wrote (§6.4.1), with a write inside an array widened to the whole array, as for merges (§F.3), since inserts and moves shift indices. A `move` whose two ends are unchanged since is inverted as a `move` back, not by copying its subtree twice. A fresh `$nonce` is added where §C.7 asks for one, never an old one restored.

  - a tombstone: a restore with `[]` (§8.2), which brings back the last live document.

  - a restore: the inverse of its patches, then `"delete"`.

  - a genesis: `"delete"`, after the inverses of the later revisions have brought the document back to it. A resource the gesture created ends up deleted, not absent.

These steps undo the gesture and nothing else: edits others made to other paths, even between the gesture's saves, are kept. An edit someone made to a path between two of the gesture's own writes to it was already overwritten by the gesture, and stays lost.

-
**The guard.** Before writing, the client reads the log after the gesture's last entry in each resource, and compares those entries' `writes` (§6.4.1), widened for arrays as above, with the paths the gesture wrote. Any overlap, or a later delete or restore, is a conflict for a person, as in a merge. The batch then names the heads the client checked in `ifMatch`, so a write landing in between makes it fail with `412`, and the client checks again. `test` ops aren't needed for this, which keeps the inverse small, and at E3, where the server doesn't evaluate patches (§6.2), the check is the client's anyway, against decrypted entries.

-
**Writing it.** Apply the steps to the current heads with a fresh `Gesture` and `Undoes: <gesture>`, so history stays append-only. Several resources go in one batch (§7.5). A large inverse is split into more chained steps to stay within `opsPerSet` and `patchSetSize` (§6.6). A gesture can't span namespaces, since a batch can't (§7.5); an action that touched several namespaces is undone per namespace, and may be undone only in part.

-
**When undo is impossible.** If a revision the inverse needs lies below a pruning horizon (`410`), if a blob the earlier document references is no longer available (`422 blob`, §7.8), or if the document's `$schema` has since been migrated so the old values no longer validate (`422 invalid`), the undo fails. These are reported as such, not as conflicts.

-
**Redo** is undoing the undo: its `Undoes` names the undo's gesture. An author's undo stack can be rebuilt on any device from the log: the gestures that author made, minus those the same author undid and didn't redo. An undo by someone else, such as an editor, is shown as undone by them; it doesn't silently drop the gesture from the author's stack, since `Undoes` isn't verified. `Undoes` naming a gesture that no longer exists, for instance after a squashed merge (§F.3), is ignored.

-
**Scope.** A gesture is a client's grouping, and the server only stores it. Who may undo what is decided by the ordinary rules for the writes the undo makes. Config writes may carry a gesture (§7.2), but undoing one is out of scope.

---

## 12. Errors

```
{ "code": "…", "head": "…", "config": "…", "successor": "…", "dependents": [ … ], "items": [ … ], "rule": 0, "path": "/…", "errors": [{ "pointer": "/blocks/1/type", "message": "must be equal to one of the allowed values" }] }
```

| `code` | Status | Meaning |
|---|---|---|
| `bad_input` | 400 | Not I-JSON, non-canonical name or URL, an unknown query parameter (§7), a malformed `Signature` (§C.3.1) |
| `unauthenticated` | 401 | No usable grant: missing, malformed, badly signed, revoked, expired or not yet valid (§C.2) |
| `forbidden` | 403 | Grant, key scope or grant rule refuses the request |
| `not_found` | 404 | Unknown, or not readable by the caller |
| `in_use` | 409 | Purge of the last copy of a referenced schema revision; purge of a namespace with dependents or such revisions; narrowing `drafts.for` or raising a branch to `e2e` while its drafts are referenced (§6.1); making a namespace with public dependents non-public (`dependents` included) |
| `frozen` | 409 | Write to a frozen namespace (`successor` included, if set) |
| `not_frozen` | 409 | Namespace purge of a namespace that isn't frozen |
| `name_conflict` | 409 | A remote branch would need a schema revision at a path that holds a different history (§G.3) |
| `batch` | as the earliest failing step | One or more batch items failed; `items` lists them (§7.5) |
| `gone` | 410 | Tombstoned or purged |
| `stale` | 412 | Precondition failed; `head` or `config` included |
| `limit` | 413 / 422 | A limit of §6.6 was exceeded |
| `invalid` | 422 | Patch application or `test` failed, or `$schema` validation failed |
| `schema_ref` | 422 | Malformed `$schema` or `$ref` |
| `schema_unavailable` | 422 | Unknown or purged schema revision |
| `rule` | 422 | A namespace rule failed |
| `precondition_required` | 428 | No `If-Match` / `If-None-Match` |
| `rate` | 429 | A rate limit of §6.6 was exceeded; `Retry-After` is set |
| `pruned` | 410 | The revision, or a revision of the log range, has its patch set pruned (§8.6) |
| `blob` | 422 | A blob reference is malformed, names a blob that isn't available, or doesn't match it; a copy names another id (§7.8); or an E3 declared list has duplicates or a blob that isn't sealed (§E.3.1) |
| `blob_mismatch` | 422 | An uploaded blob doesn't hash to its id (§7.8) |
| `signature` | 422 | An author signature failed verification, or is missing where the namespace requires one (§C.3.1) |
| `not_offered` | 404 | An optional endpoint this namespace doesn't offer, such as `/gestures` in a sealed namespace (§7.4) |
| `source` | 422 | A batch's local `source.at` isn't in the chain of `source.ns`, for a caller who may read it (§7.5) |

---

## 13. Open questions

- **External schemas:** allow `https://…#sha256=…` pinned references? If so, where are fetched copies stored, and what is the allowlist?

- **SSE payload:** full entries, or ids only (fetching content via the cached range URL)? Long-poll (§7.7) already serves full entries through the CDN.

- **Merge helpers:** automatic `test` op generation for fields an editor displayed?

- **Batch provenance:** should the server verify that a batch's items correspond to its `source` branch's entries?

- **Create conflicts:** a create's `412` returns the existing head to a holder that may have only `create`. Ids aren't secrets (§C.5), but should it answer without the head? The same applies to the per-item preconditions a batch's dry run reports.

- **E3 documents:** the server can't fold E3 documents, so what should `/rev/{id}` serve there, other than a prune's stored snapshot (§7.1)? Head redirects and remote read-through (§G.3) assume a document.

- **Namespace-document versions:** should namespace documents carry a version, or a `$schema` of their own, so deployments of different versions can exchange them?

- **Test vectors:** an addendum of test vectors for the byte-exact definitions (§1, Conformance), before two implementations diverge.

- **Blobs:** resumable or chunked uploads for very large blobs? Ranges of sealed blobs (§E.2.2)?

- **Auth:** see the open questions of Addendum C.

---

# Addendum A — Indexing service (suggested, non-normative)

A search service for typed documents, built as a namespace consumer (§10). It runs as its own process with its own storage and URL space. Several independent indexers can follow the same namespace.

## A.1 Following the namespace

- Follow the namespace as in §10, with one checkpoint per namespace.

- For each coalesced `head` entry:

  - Fetch `/r/{ns}/{name}/rev/{id}`.

  - Without `$schema`, remove any rows for the resource.

  - Otherwise fetch the schema (immutable, so cache its field map forever) and index the annotated fields.

- `tombstone` → remove the resource's rows. `purge` → also purge the service's own cache tags.

- Store the checkpoint in the same transaction as the index writes.

## A.2 What gets indexed: `x-index`

- Schemas opt fields in with `"x-index": "text" | "facet" | "sort"`:

  - `text`: full-text search.

  - `facet`: exact-match filters and counts. Arrays expand to one value per element.

  - `sort`: ordering and range filters.

- The core ignores `x-*` keywords (§6.5).

## A.3 Storage (example, SQLite)

```
CREATE TABLE checkpoints (ns TEXT PRIMARY KEY, ns_id TEXT NOT NULL);
CREATE TABLE docs  (ns TEXT, resource TEXT, head TEXT, schema TEXT, PRIMARY KEY (ns, resource));
CREATE VIRTUAL TABLE text USING fts5(ns UNINDEXED, resource UNINDEXED, schema UNINDEXED, path UNINDEXED, body);
CREATE TABLE facet (ns TEXT, resource TEXT, schema TEXT, path TEXT, value TEXT, PRIMARY KEY (ns, resource, path, value));
CREATE TABLE sort  (ns TEXT, resource TEXT, schema TEXT, path TEXT, value,      PRIMARY KEY (ns, resource, path));
CREATE INDEX facet_q ON facet (ns, schema, path, value);
CREATE INDEX sort_q  ON sort  (ns, schema, path, value);
```

Current state only. History search is out of scope; replay the resource log instead.

## A.4 Query API

Served on the indexing service's own origin, e.g. `https://search.example/`.

| Request | Response | Cache-Control |
|---|---|---|
| `GET /{ns}?q=…&schema=…&facet[/blocks/type]=poll&sort=/kickoff` | `302` to `/{ns}/at/{checkpoint ns_id}?…` | head pointer |
| `GET /{ns}/at/{ns_id}?…` | `200` with `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", …facets }] }` | immutable (a result for a given `at` never changes). Tags `idx:{ns}` and `r:{ns}/{name}` for every hit, so a purge removes every cached result that shows the resource |
| same, an `ns_id` the service no longer keeps results for | `302` to the current checkpoint | head pointer |

- `schema` filters by an exact `$schema` reference, or by prefix to match all revisions of one schema.

- Hits carry the plain document URL (`/r/{ns}/{name}/rev/{id}`). Documents are served by the core's CDN, never by the search service.

- **Private namespaces:** follow the same rules as catalog listings (§B.11.5). Results are keyed by the reader's subject set in the path, and responses never embed per-reader signed URLs.

- **Sealed namespaces:** results are sealed as in §E.2.6.

## A.5 Consistency

- The index is **eventually consistent**. Every response states `at`, the `ns_id` it reflects.

- **Read-your-writes:** `?min={ns_id}` (or `?min={ns}:{ns_id}`, repeatable, for a service that follows several namespaces, §B.5) waits (bounded, e.g. 2 s) until the checkpoint is at or past `min`. If it isn't, the service answers `503` with `Retry-After`. A client takes `min` from `X-Namespace-Revision` on its own write (§7.2).

## A.6 Operations

- **Rebuild:** delete the index and replay from `""`. A new schema revision needs no rebuild; only documents that switch to it are re-indexed, through their normal head change.

- **Alternative backends:** Meilisearch, Typesense, Tantivy and the like work behind the same checkpoint protocol.

- **Access control:** the service re-publishes content, so it MUST enforce the namespace's read permissions by verifying the reader's grant locally (§C.6).

## A.7 Open questions

- Should untyped documents appear in a plain listing, even though they aren't searchable?

- Should queries on a stale `ns_id` redirect to the current checkpoint (as above) or return `404`?

---

# Addendum B — Organising documents (suggested, non-normative)

Trees and DAGs over documents, kept **separate from the documents themselves**. Organisation lives in **catalog namespaces** that hold folders and **placements**, while content namespaces stay untouched. A **tree service** serves listings, and a **catalog** derives access from the tree. Both are namespace consumers (§10). The core never interprets any of it.

## B.1 Principles

- **Names are identity; organisation is separate data.** Content names are flat and stable (§3.6). Where a document sits in a tree is recorded in a catalog, not in the document. Moving it never changes its URL, history or cache keys, and editing it never changes its position.

- **A catalog is a namespace.** It has its own documents, rules, keys, history and namespace log. Several catalogs can organise the same content independently, e.g. by season, by editorial section, or a partner's curated view.

- **Separate histories, separate permissions.** "Who moved this?" lives in the catalog's history, and "who changed the title?" lives in the content's. Organising a catalog needs no write access to content, and editing content needs none to the catalog.

- **Edges live on the node that moves.** A move is a single write to one catalog document: atomic, guarded by `If-Match`, and contending only with other moves of that same node.

## B.2 Catalog namespaces: folders and placements

A catalog namespace (e.g. `cat-season`) contains two kinds of **node**, told apart by their names:

| Node | Name | Purpose |
|---|---|---|
| **Folder** | no dot, e.g. `season-2026` | a catalog-native grouping: title, settings, access |
| **Placement** | `{ns}.{name}` of the item it places, e.g. `matches.derby` | positions one content document in this catalog |

Namespace names contain no dot (§3.6), so a placement name splits unambiguously at its first dot into the **item** `/r/{ns}/{name}`. There is no `item` field: the name *is* the reference.

```
// /r/cat-season/season-2026  (folder)
{ "$schema": "/r/schemas/folder/rev/1f…",
  "title": "Season 2026",
  "parents": [{ "href": "/r/cat-season/root", "order": "a0" }] }
```

```
// /r/cat-season/matches.derby  (placement of /r/matches/derby)
{ "$schema": "/r/schemas/placement/rev/1p…",
  "parents": [
    { "href": "/r/cat-season/season-2026", "order": "a1" },
    { "href": "/r/cat-season/derbies",     "order": "Zz" } ] }
```

- **`parents`:** live links to folders **in the same catalog**. Each entry carries its own `order`, so a node with several parents has a position under each one, and a listing of a folder's children sorts them by the order on their edge to that folder.

  - One entry makes a tree node, several make a DAG node, and the catalog chooses by rule (§B.6).

  - No `parents` (or `[]`) makes a root.

  - Folders nest the same way.

- **`order`:** a fractional-index sort key among siblings, compared by code unit. To place an item between `a1` and `a2`, pick any key in between, e.g. `a1V`. No sibling is ever rewritten. It is optional; unordered siblings sort after ordered ones, then by name.

- **At most one placement per item per catalog.** The name enforces it: creating with `If-None-Match: *` can't produce a duplicate, and "is X in this catalog?" is a single lookup of `/r/{catalog}/{ns}.{name}`.

- **Operations:**

  - **Place:** create the placement.

  - **Move:** `replace /parents`.

  - **Reorder:** `replace /parents/{i}/order`.

  - **Remove from the catalog:** delete the placement. The content document is unaffected.

- **Item-level settings** (e.g. `$access` to share one document with a guest group, §B.11) live on its placement, never in the content.

## B.3 Links

A link is a path on this service:

| Form | Meaning | Changes when the target changes? |
|---|---|---|
| `/r/{ns}/{name}` | **live**: whatever the head is | yes |
| `/r/{ns}/{name}/rev/{id}` | **pinned**: exactly that revision | never |

- **Grammar:** links follow §3.6.

- **Referential integrity** is not enforced. A placement whose item is deleted, or a `parents` entry naming a missing folder, is **dangling**. The tree service drops it from traversals and reports it (§B.5).

## B.4 Manifests (pinned snapshots)

A **manifest** is a document whose links are all pinned. Its own revision id therefore fixes the exact content of everything it lists, much as a Git tree fixes its blobs.

```
{
  "$schema": "/r/schemas/manifest/rev/1m…",
  "catalog": "cat-season",
  "root": "/r/cat-season/season-2026/rev/1a…",
  "entries": [
    { "href": "/r/matches/derby/rev/1q3f…",  "path": ["season-2026"], "order": "a1" },
    { "href": "/r/matches/opener/rev/1c9d…", "path": ["season-2026"], "order": "a0" }
  ]
}
```

- **Uses:** publishing, releases, audits.

- **Creation:** the tree service generates a manifest for a subtree as of a catalog `ns_id` (§B.5), and the client creates it as an ordinary resource.

- **Shared items.** In a DAG, an item reached along several paths has one entry per path, each with that path and the order of its last edge. So an `href` can appear more than once. Consumers that need each item once group entries by `href`.

## B.5 Tree service

A consumer of a **catalog namespace**:

- For each coalesced `head` of a node, it replaces that node's outgoing edges from `parents`.

- `tombstone` and `purge` remove them.

- Item liveness is learned by also following the content namespaces the catalog trusts (§B.6). A placement whose item is gone is marked dangling.

```
CREATE TABLE checkpoints (ns TEXT PRIMARY KEY, ns_id TEXT NOT NULL);           -- the catalog and each trusted content namespace
CREATE TABLE nodes (href TEXT PRIMARY KEY, kind INTEGER NOT NULL,              -- 0 folder · 1 placement
                    item TEXT, item_head TEXT, title TEXT, state INTEGER NOT NULL DEFAULT 0);  -- 0 live · 1 gone · 2 dangling
CREATE TABLE edges (child TEXT NOT NULL, parent TEXT NOT NULL, ord TEXT, PRIMARY KEY (child, parent));
CREATE INDEX edges_by_parent ON edges (parent, ord, child);
```

**Query API.** Listings redirect (`302`, head-pointer caching) to `/{catalog}/at/{at}/…`. A listing depends on the catalog and on the content namespaces it follows (which items exist, their heads), so `at` is the service's **combined checkpoint**, `text(trunc160(sha256(canonical({ ns: ns_id, … }))))` over all of them. A listing at a given `at` never changes, so it uses the immutable class (§9), tagged with every item it shows (`r:{ns}/{name}`) and every namespace in the checkpoint (`ns:{ns}`), so a purge removes cached listings at every `at`. The service answers `200` at an `at` only if it is current or that exact result was stored, and `302` to the current one otherwise. `?min={ns}:{ns_id}`, repeatable, gives read-your-writes (§A.5). A service that follows several catalogs keeps a combined checkpoint per catalog. `?min` is judged against the checkpoint of the catalog in the URL, even for a content namespace that other catalogs follow too. Catalog grants keep the catalog's own `ns_id` as `at` (§B.11.4): the combined checkpoint is in no chain, so `requireAt` can't check it.

| Request | Returns |
|---|---|
| `…/children?of={folder}` | direct children (folders and items), ordered, paginated with `?after={order}` |
| `…/ancestors?of={item or folder}` | every path to a root, for breadcrumbs |
| `…/subtree?of={folder}&depth={n}` | nested listing |
| `…/roots` | nodes without parents |
| `…/orphans` | nodes whose every parent is gone or dangling |
| `…/problems` | cycles, dangling items and dangling parents |
| `…/where?item={/r/ns/name}` | the item's placement and paths in this catalog |
| `…/manifest?of={folder}` | a manifest for the subtree, pinned as of the checkpoint |

-
**Fresh listings after a write.** The redirect to `…/at/{at}/…` is cached like a head pointer, by browsers too, within its `stale-while-revalidate`. A client that relists right after its own write adds `?min={ns}:{ns_id}` from the write's `X-Namespace-Revision` (§A.5), which gives a new URL and waits for the service to catch up, instead of fetching with `no-store`.

-
**Items in listings** carry their content URL and current head. The document itself is always fetched from the core's CDN.

-
**Cycles.** The core can't prevent them. In a DAG no single edge "closes" a cycle, so the unit is the node:

  - every node on a cycle (a strongly connected set of more than one node, or a node that is its own parent) is **cyclic**;

  - a cyclic node and all its edges, including edges to parents off the cycle, are left out of traversals, listings and access (§B.11.2: a cyclic node contributes nothing);

  - `/problems` lists each cycle as its set of nodes. Nodes below a cyclic node that are reached only through it become orphans, and so do the cyclic nodes themselves.

This is deliberately strict. Excluding just one edge would make the result depend on which edge was chosen. Walks are bounded at depth 64, and deeper paths are flagged too.

-
**Shared nodes in DAGs.** Listings are about paths, so `subtree`, `ancestors` and `where` show a node with several parents under each of them. A node reached through several paths, such as the bottom of a diamond, would repeat, and a DAG of repeated diamonds grows exponentially. Services MUST bound a response, by the depth limit and a per-response node limit, and report when a response was cut. They SHOULD expand a shared node only at its first occurrence in a `subtree` response and mark later occurrences `"repeat": true`, without children.

-
**Previews of a release** (§F.9). A tree service previewing a release follows the branches its release document lists in place of their bases: `checkpoints` holds those branches, and placements such as `matches.final` resolve to the release's branch of `matches`. It shows a viewer only branches the viewer can read, serves previews only, and issues no grants (§F.8). A long-running preview service follows the release document's own log (§10), so a new revision of it, such as one listing a rebase's successors, takes effect without a restart.

-
**`mode` is enforced by the catalog's rules** (§B.6), not by consumers. The tree service serves the edges it finds, so a `tree` catalog whose rules allow several parents is served as a DAG. A service MAY report nodes with several parents in a `tree` catalog under `/problems`.

## B.6 Catalog namespace document and rules

```
{
  "catalog": { "trust": ["matches", "docs"], "mode": "tree" },
  "rules": [
    { "op": "test", "path": "/resource", "schema": { "pattern": "^([a-z0-9][a-z0-9_-]*|(matches|docs)\\.[a-z0-9][a-z0-9._-]*)$" } },

    { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } }],
      "then": [{ "op": "test", "path": "/doc/parents", "schema": { "type": "array", "maxItems": 1, "items": {
        "type": "object", "required": ["href"], "additionalProperties": false,
        "properties": {
          "href":  { "type": "string", "pattern": "^/r/cat-season/[a-z0-9][a-z0-9_-]{0,127}$" },
          "order": { "type": "string", "pattern": "^[0-9A-Za-z]{1,64}$" } } } } }] },

    { "if":   [{ "op": "test", "path": "/action", "value": "create" }],
      "then": [{ "op": "test", "path": "/doc/parents", "schema": { "minItems": 1 } }] }
  ]
}
```

- **`catalog.trust`:** the content namespaces whose items may be placed here. The first rule enforces it on placement names, and also allows folder names.

- **`mode`:** `tree` or `dag`. The `maxItems: 1` in the second rule implements `tree`; drop it for a DAG.

- **Parents** are live links to **folders** of this catalog: no dot in the name, so never a placement.

- **No new roots:** every new node must be placed somewhere.

## B.7 Lifecycle

- **Create and place** are two writes with no transaction between them. Create the content first and place it second, or place first: a placement may name an item that doesn't exist yet, and it shows as dangling until it does.

- **Deleting content** leaves its placements dangling. They drop out of listings and access immediately, and are reported for cleanup.

- **Deleting a placement** removes the item from this catalog only.

- **Deleting a folder does not cascade.** Its children appear under `/orphans`. A recursive delete is a client-driven sequence of `DELETE`s.

- **Restoring** a folder or placement re-attaches everything that pointed at it.

- **Moving a subtree** is one write on the subtree's top node.

## B.8 Whole-tree documents (small, curated trees)

For navigation menus, site maps and other small trees (hundreds of nodes, edited rarely and by few people), a whole tree can be **one document**:

```
{ "$schema": "/r/schemas/menu/rev/1n…",
  "root": { "title": "Site", "children": [
    { "title": "News",   "item": "/r/docs/news" },
    { "title": "Season", "children": [ { "item": "/r/matches/derby" }, { "item": "/r/matches/opener" } ] } ] } }
```

- **Atomic reorganisation.** A multi-node reorganisation is one patch set. A move is a JSON Patch `move` between two `children` arrays, so it is still tiny.

- **Snapshots for free.** Every revision is a snapshot of the whole tree; pinning it gives a manifest.

- **Trade-offs:** all edits contend on one head, the document grows with the tree (mind the limits in §6.6), and access is per whole tree. Use catalogs (§B.2) for large or busy trees, or where access follows the tree.

## B.9 Self-placing documents (optional shortcut)

A content document MAY carry `$parents` (same shape as `parents`, linking to folders of one catalog). A tree service configured to accept it for a trusted namespace treats it as an **implicit placement**. If an explicit placement for the same item exists, it wins.

- **Convenient** for single-tree setups where content and organisation are edited by the same people anyway.

- **Couples position to content:** moving the document means editing it, and organising needs write access to content.

- **Not accepted by default:** the catalog (§B.11) doesn't derive access from self-placements unless the content namespace's rules protect `/$parents` as strictly as the catalog protects placements.

## B.10 Access control

- **The core never inherits permissions down a tree.** It only checks the grant presented with a request.

- **A catalog may derive grants from the tree** (§B.11). Authority still flows only through grants, so the core stays independent of the catalog.

- **A separate namespace is the strongest boundary** when a whole body of content needs a different audience.

- **Services that list content** MUST enforce read permissions for every node and item they list, since titles and structure are content too.

## B.11 Catalog: tree-derived access

A **catalog service** is a tree service that also **issues grants**:

- It reads `$access` from folders and placements.

- It computes effective roles per item and subject.

- It signs narrow, short-lived grants with a scoped key.

Its key is listed in the catalog namespace (for organising) and in each trusted content namespace (for reading and editing items). The core enforces those grants like any others and never consults the catalog.

### B.11.1 `$access` and roles

The catalog decides **who has which role where**. Each content namespace decides **what a role means** for its documents.

```
// folder
{ "$schema": "/r/schemas/folder/rev/1f…", "title": "Season 2026",
  "parents": [{ "href": "/r/cat-season/root" }],
  "$access": {
    "group:match-desk":  ["desk"],
    "group:translators": ["translator"],
    "group:fan-club":    ["reader"],
    "user:li":           ["reader"] } }
```

```
// embargoed sub-folder
{ "$schema": "/r/schemas/folder/rev/1f…", "title": "Transfer rumours",
  "parents": [{ "href": "/r/cat-season/season-2026" }],
  "$access": { "inherit": false, "group:editors-in-chief": ["desk"] } }
```

```
// content namespace document (e.g. matches): what each role may do to its documents (§C.1.1)
"roles": {
  "desk":       { "can": ["read", "append"] },
  "translator": { "can": ["read", "append"], "rules": [ { "op": "writes", "within": ["/i18n"] } ] },
  "reader":     { "can": ["read"] } }

// catalog namespace document: what each role may do in the tree
"roles": {
  "desk":       { "move": true, "place": true },
  "translator": {},
  "reader":     {} }
```

- **`$access`** maps subjects (`group:…` or `user:…`) to role names, applied to the **items** below the folder. Role names are all the catalog hands out.

- **Content namespaces own the meaning.** A role's verbs and rules come from the content namespace's `roles`. The same name can mean different things in different namespaces, and a namespace that doesn't define a role grants nothing through it. Content owners can therefore tighten `translator` without touching the catalog.

- **The catalog namespace defines tree powers:**

  - **`move`:** moving nodes out of or into the folder where the role is assigned

  - **`place`:** placing new items directly into that folder

- **`inherit: false`:** stops the ancestor walk at this node.

- **Placements** may carry `$access` too, to share one item.

- **`user:` entries** are for exceptions. Listings are cached per subject set (§B.11.5), so each user with direct entries gets their own listing cache.

- **Schema and history:** the folder and placement schemas validate the structure of `$access`, and changes are versioned and attributed.

### B.11.2 Effective access

- **Subjects.** A caller's subject set is `user:{sub}` plus `group:{g}` for each of its groups (§B.11.6).

- **Walk up.** For an item `x` and a subject `s`, start at `x`'s placement. The effective roles are the **union**, over every path from it up to a root, of the `$access[s]` role names met along that path, including the placement's own. A caller's effective roles are the union over its subjects.

- **Where a path stops:**

  - it stops collecting **after** a node with `inherit: false`

  - a path that reaches a **tombstoned, purged, dangling or cyclic** node ends there, and that node contributes nothing

  - a dangling placement grants nothing, except `create` for an item that has never existed, and `restore` for an item that is tombstoned, not purged, to the roles it had when it was deleted (§B.11.4)

  - deleting a folder or placement can therefore only narrow access, never widen it

- **Across catalogs.** When several catalogs are trusted by the item's namespace, each issues grants from its own computation. An item's total access is the union of what the trusted catalogs grant. A content namespace should therefore list, with scoped keys, only the catalogs it trusts to open it up.

- **Allow-only.** There are no denies, so in a DAG the union is well defined. Roles are alternatives at the gate (§C.1.1), so a union of roles never grants more than the most permissive role in it.

- **Tree powers** (`move`, `place`) apply only at the folder where a role granting them is assigned, and are never inherited.

### B.11.3 Keys and namespace documents

**In the catalog namespace** (writes to folders and placements):

```
{ "read": "grant",
  "keys": [
    { "kid": "ops-2026",   "alg": "Ed25519", "pub": "…", "can": ["*"] },
    { "kid": "catalog-01", "alg": "Ed25519", "pub": "…",
      "can": ["read", "create", "append", "delete", "restore"], "maxTtl": "PT15M", "requireAt": true,
      "groups": { "deny": ["catalog-admins", "ops"] },
      "rules": [
        { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } }],
          "then": [{ "op": "test", "path": "/doc/$access", "exists": false }] },
        { "if":   [{ "not": { "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } } }],
          "then": [{ "not": { "op": "writes", "overlaps": "/$access" } }] } ] } ],
  "maxLag": "PT60S",
  "rules": [
    { "if":   [{ "any": [
                { "all": [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } },
                          { "op": "test", "path": "/doc/$access", "exists": true }] },
                { "all": [{ "not": { "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } } },
                          { "op": "writes", "overlaps": "/$access" }] } ] }],
      "then": [{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "catalog-admins" } } }] } ] }
```

**In each trusted content namespace** (reading and editing items):

```
{ "keys": [
    { "kid": "catalog-01", "alg": "Ed25519", "pub": "…",
      "can": ["read", "create", "append", "restore"], "maxTtl": "PT15M", "readScope": "resource", "requireAt": "cat-season",
      "groups": { "deny": ["ops"] }, "roles": { "allow": ["desk", "translator", "reader"] } } ],
  "roles": { "desk": { … }, "translator": { … }, "reader": { … } },
  "catalogs": { "cat-season": { "place": ["group:match-desk", "group:editors-in-chief"] } } }
```

- **Scoped keys bound the catalog service.**

  - In the catalog it may create, move and delete nodes, but never change `$access`.

  - In content namespaces it may only grant reading, creating, appending and restoring, only for single resources, and only through the roles the content namespace allows it.

  - It may never assert admin groups.

- **Only `catalog-admins` change access settings**, including via root replaces or `move` from `/$access`, because the rules use `writes overlaps`. A create, and a restore with a root replace, write the whole document (`""`), which overlaps every path, so creates and restores are judged by the document they produce instead: a folder or placement may be created or restored with `$access` only by an admin. Deletes write nothing and pass these rules: deleting a node only narrows access (§B.11.2). A later restore is judged by the document it produces, like a create.

- **Content owners decide who may bring their content into a catalog.** `catalogs.{catalog}.place` in the *content* namespace lists the subjects (`group:…` or `user:…`) allowed to create a first placement of its items in that catalog. It is part of the content namespace's own configuration and history.

### B.11.4 Issuing grants

```
POST /grants
Authorization: Bearer
{ "item": "/r/matches/derby", "want": ["append"] }
```

- **Resolve** the caller's subjects (§B.11.6) and look up its effective roles for the item at the current checkpoint, collected only through subjects the catalog's key in that namespace may assert (§B.11.3). Keep only roles that the content namespace defines with a wanted verb.

- **Sign a root grant** for exactly that resource, carrying those role names, with an absolute `exp` within `maxTtl`:

```
{ "kid": "catalog-01", "sub": "user:anna", "groups": ["translators"], "roles": ["translator"],
  "ns": ["matches"], "can": ["append"], "exp": "2026-10-04T18:10:00Z", "at": { "ns": "cat-season", "id": "1k…" },
  "rules": [ { "op": "test", "path": "/resource", "value": "derby" } ] }
```

The grant says **where** (`/resource`) and **who** (`roles`). The `/i18n` restriction is not in it: the gate applies it from the content namespace's definition of `translator`, so changing that definition takes effect on outstanding grants at once. The catalog grants role names without evaluating their rules, so a grant may carry a role whose rules the gate then refuses for a particular write. A client that shows what is editable evaluates the role's rules itself, or submits with `?dry-run=1` in a batch (§7.5).

Organising requests yield grants for the **catalog** namespace, each fixing `/resource` to the node name and `/doc/parents` to exactly the requested target set:

-
**Place** (`{ "item": …, "want": ["place"], "to": [folders] }`). If an earlier placement of the item was deleted, the grant carries only `restore`, and restores it with a root replace instead of creating it. A restore-only grant can't be used as a move: if the placement is live again by the time it is used, the write is an append and is refused at step 2, before anything about the live document is checked (§6.2). On a still-deleted placement, the restore sees the last live document at step 3, as any restore does; placements should carry a fresh `$nonce` (§C.7) so their ids can't be used to confirm guesses. It requires both:

  - the caller is in the content namespace's `catalogs.{catalog}.place` list

  - the caller has a role with `place` assigned on **every** folder in `to`

Placing is a deliberate act of publishing into a folder's audience, so these two checks together are the consent.

-
**Move** (`{ "node": …, "want": ["move"], "to": [folders] }`) requires all of the following:

  - a role with `move` on **every** current parent the node leaves

  - a role with `move` on **every** folder in `to`

  - **no widening:** for every subject, the effective roles for the moved node's subtree after the move must be a subset of what they were before, unless the caller is in `catalog-admins`. Roles are compared by name, but a content namespace may declare that one role includes others: `"desk": { "can": [ … ], "includes": ["reader"] }`. A role counts as present before the move if it, or a role that includes it, was present. So moving an item from where a subject has `desk` to where it has `reader` narrows access. `includes` is transitive, is read from the item's own content namespace, and is trusted as declared: changing `/roles` needs a `*` key there (§C.1.1).

-
**Unplace** (`want: ["delete"]` on a placement) requires a role with `move` on every current parent. The grant fixes `/doc/parents` to exactly those parents, so the placement can't be moved before it is deleted.

-
**Create a folder** (`{ "node": …, "want": ["create"], "to": [folders] }`) requires a role with `move` on every folder in `to`. Items in it get their parents' roles through the walk-up (§B.11.2), but tree powers on it come only from its own `$access`, which needs `catalog-admins`, as any `$access` does. Until an admin gives it some, only admins can move or place anything into it.

-
**Create** (`{ "item": "/r/matches/final", "want": ["create"] }`) makes a new document in a folder:

  - The caller first **places** the new item (above). The placement names a resource that doesn't exist yet, and is dangling until it does (§B.7).

  - The catalog resolves the caller's effective roles from that placement, as for any item, and keeps those the content namespace defines with `create`.

  - It signs a grant fixed to that name with `can: ["create"]`. Such a grant can only ever produce the genesis: a create needs `If-None-Match: *`, which fails once the resource exists. Later edits use ordinary `append` grants.

A name that exists or existed in the content namespace is refused (`409`), so a create grant can never restore or overwrite anything. That reveals the name is taken, as any create would; names are not secrets (§E.4).

-
**Restore** (`{ "item": "/r/matches/final", "want": ["restore"] }`) brings back a deleted item where it was placed. The catalog resolves the caller's effective roles from the `effective` rows it kept when it saw the item's tombstone (§B.11.7), frozen at that moment, so neither placing the deleted item nor moving folders afterwards can be used to undelete it, keeps those the content namespace defines with `restore`, and signs a grant fixed to that name with `can: ["restore"]`. It can only restore: if the item is live by the time the grant is used, the write is an append and is refused at step 2 (§6.2). The item must still have a placement in this catalog; the frozen rows stay those of its deletion even if it was unplaced and placed again. The answers, in order: a name that never existed is `404`, and a purged item `410` (names, and purges in readable logs, aren't secrets, §E.4); a caller without a role granting `read` on the item, in its frozen rows if deleted or its current ones if live, gets `403`, as does one without a role granting `restore`, one whose item has no placement, and one whose restore would widen (§B.11.7, judged with `includes` as for moves); then a live item is `409`.

-
**Accountability.** Every revision records its grant (§C.3), including `at` and `via`, so catalog decisions are auditable afterwards.

### B.11.5 Reads and listings

- **Listing URLs carry the subject set.** Listings are served at `/{catalog}/at/{at}/g/{gs}/…` (`at` as in §B.5), where `gs = text(trunc160(sha256(canonical(sorted subjects))))`. The subjects are the caller's `group:` entries, plus `user:{sub}` only if the catalog has direct entries for that user. The edge admits a request only if the caller's edge grant is bound to that exact `gs`. Listings are cached per (listing, subject set, `at`), so users without direct entries share caches with everyone in the same groups.

- **Listings are filtered by their subject set.** A node is **visible** to a subject set when the walk up from it (§B.11.2) collects a role that grants `read` without conditions: for an item, a role its content namespace defines with `read` and that the catalog's key there may grant (its `roles` and `groups` scope, §B.11.3); for a folder, such a role in some trusted content namespace. A role counts only if it was collected through a subject the key may assert. A role with rules counts if its rules pass when evaluated as a read of the item would evaluate them (§6.4.1: no `writes`, `doc` or `patches`, so `within` is true and `covers` and `overlaps` are false, §6.4.2), with `/principal` holding only the groups the key may assert; a rule that refers to `/now`, or to anything in `/principal` but `/principal/groups`, makes the role not count, since everyone with the same subject set shares the listing and a listing at a given `at` can't change. For a folder, only a role without rules counts. The roles, their definitions and the keys are those as of the content namespaces' `ns_id`s in the listing's combined checkpoint (§B.5), so visibility is pinned to `at` too.

  - `children`, `subtree`, `roots`, `ancestors` and `where` show visible nodes only, and only paths through visible folders. Nothing about a hidden node appears, not even as a count.

  - Response limits, cut markers and pagination (§B.5) apply to the visible nodes, so they reveal nothing about hidden ones.

  - `/read-grants` uses the same test for catalog nodes and their keys.

  - `problems`, `orphans` and `manifest` aren't filtered, and need namespace-wide `read` on the catalog and on the content namespaces they cover (`403` otherwise): for a manifest, those of the items it pins; for `problems` and `orphans`, every trusted one. A public namespace counts as read namespace-wide. So do unfiltered listings (`g/all`), for readers with namespace-wide grants (§C.5): the catalog service issues an edge grant bound to `all` only after checking namespace-wide `read` on the catalog and on every content namespace it trusts, and it expires with the earliest of those grants. Without edge grants, `g/all` listings are served `private`, with a `max-age` no longer than that.

  - `/read-grants` is then needed only for the items a reader opens, not to decide what to list.

- **Listings never embed signed URLs.** Readers obtain per-item edge grants from `POST /read-grants { items: [...] }` (`no-store`). It returns short-lived edge grants scoped to exactly `/r/{ns}/{name}` and `/r/{ns}/{name}/…`. For sealed items and sealed catalog nodes, it also returns per-resource keys `K_r` (§E.2.1), wrapped to the caller's public key in the §E.2.3 format. The catalog service derives them from the epoch keys it holds as a consumer. So a reader who sees items only through catalog roles, with no grant on the content namespace, can still read them and open their entries in listings (§E.2.6):

  - **Which keys.** A content item in a sealed (E2) namespace gets its own `K_r`. An item in an E3 namespace gets none, since clients seal E3 revisions under the epoch key, which `K_r` doesn't open. When the catalog is sealed or E3, the item's placement node also gets its `K_r`, for its listing entry. `items` may also name catalog nodes (`/r/{catalog}/{name}`): a node visible to the caller (§B.11.5, below) gets its `K_r` and no grant, so folder titles can be read.

  - **Checked like grants.** Keys are returned only for items that pass the same role check as the grants. That includes items in **public** sealed namespaces: their ciphertext is public, so the keys are what control access.

  - **Which epochs.** Catalog grants have no start time to bound history. So keys cover the current epoch and the `encryption.historyEpochs` before it, or every epoch the service holds if the namespace sets no cap. A namespace that shouldn't give role-only readers its whole history sets `historyEpochs`. As with `/keys`, losing a role takes effect at the next rotation (§E.2.4).

  - A caller whose grant carries no public key still gets its grants, with `"keysWithheld"` and the reason in place of keys.

- **Readers of a whole content namespace** use a namespace-wide edge grant instead (§C.5).

### B.11.6 Groups

- **Default:** group claims come in the base grant from the identity provider.

- **Alternative:** a `groups` namespace of documents (`{ "members": [...] }`) that the catalog service follows, which gives membership history and self-service.

- **Either way,** key scopes limit which groups and roles the catalog may assert.

### B.11.7 Catalog storage (example)

```
CREATE TABLE nodes     (node TEXT PRIMARY KEY, inherit INTEGER NOT NULL DEFAULT 1);
CREATE TABLE acl       (node TEXT, subject TEXT, role TEXT, PRIMARY KEY (node, subject, role));
CREATE TABLE effective (item TEXT, subject TEXT, role TEXT, PRIMARY KEY (item, subject, role));
CREATE INDEX effective_by_subject ON effective (subject, item);
```

- **Maintenance.** A change to a node's `$access` or `parents`, a tombstone, or an item's deletion recomputes `effective` for the affected subtree.

- **Role definitions** live in the content namespaces and are applied at the gate. Listings depend on which roles grant `read` (§B.11.5), so a change to `/roles` in a content namespace recomputes the visibility it affects.

- **Deleted items** keep their rows in `effective` as they were when the tombstone was seen, marked as tombstoned and no longer recomputed, so a restore (§B.11.4) is resolved from them. A move of a deleted item's placement is checked like any other (§B.11.4), against the roles the item would have now. In addition, a restore is refused (`403`) if the roles the item would have after it, from its current placement, exceed its frozen rows for any subject, so neither a move nor an `$access` change after the deletion widens the audience a restore publishes to. Such an item is restored by a catalog admin.

- **Consistency.** The checkpoints are stored in the same transaction, so `effective` reflects a known catalog `ns_id`, which is the `at` of every grant issued from it.

### B.11.8 Staleness and revocation

- **Staleness is bounded by `maxLag` plus the grant's lifetime.** A grant issued just before an access change remains valid until it expires.

- **For immediate revocation,** add the grant's revocation id to `revoked` (§C.4) in the namespace where it applies.

## B.12 Open questions

- Should listing titles come from the folder, from the item via an `x-tree-label` schema annotation, or both?

- Should manifests be signed for publishing workflows?

- A placement deleted and placed again with a root replace loses its own `$access`, such as an embargo with `inherit: false`. Should re-placing keep the last `$access` unless an admin drops it?

- Should a content namespace be able to *require* that every item is placed in some catalog, e.g. through a catalog-consumer that reports unplaced items?

---

# Addendum C — Capabilities and access (recommended)

How authority is carried and checked. The core provides the hooks:

- `principal`, `writes` and `read` envelopes (§6.4.1)

- the gate order (§6.2)

- a grant reference per revision (§5)

This addendum fills them. The guiding asymmetry: **writes can be fine-grained, reads are per document.** Writes are checked at the gate against the full envelope. Reads are decided when grants are issued (§C.5.1).

It supports three styles of policy, which combine:

- **Role-based:** named roles in the namespace document, referred to by grants (§C.1.1).

- **Attribute-based:** rules relating the principal's attributes, the document and the time (§C.1.2, §6.4.2).

- **Relationship-based:** a service that derives access from structure, such as the catalog (§B.11), and issues grants from it.

## C.1 Grants

A **grant** is a signed token presented as `Authorization: Bearer <grant>`. It consists of a **root block**, signed by a key listed in the namespace document, and zero or more **narrowing blocks**, each chained to the previous one's signature:

```
// root block, signed by key "kid"
{ "kid": "ops-2026", "sub": "user:bob", "groups": ["match-desk"],
  "roles": ["desk"], "attrs": { "regions": ["se", "no"] },
  "ns": ["matches", "docs"], "can": ["read", "append"],
  "nbf": "2026-10-04T08:00:00Z", "exp": "2026-10-05T00:00:00Z", "at": "1k…",
  "rules": [] }
// narrowing block (delegation to a service)
{ "via": "svc:translator", "can": ["append"], "exp": "2026-10-04T20:00:00Z",
  "rules": [ { "op": "writes", "within": ["/i18n/sv"] } ] }
```

-
**Fields:**

  - `kid`: the id of the signing key in the namespace document

  - `sub`, `groups`: the principal's identity, taken from the **root block only**

  - `roles`: role names (§C.1.1). A narrowing block may list a subset.

  - `attrs`: attributes the issuer asserts about the principal (§C.1.2), taken from the **root block only**

  - `ns`: namespaces the grant applies to

  - `can`: `read`, `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export`, `prune`, or `*` for keys only. `export` registers a remote branch (§G.3). A root block with `roles` may omit it, and then its verbs come only from the roles.

  - `nbf`, `exp`: **absolute** RFC 3339 times. The block is valid from `nbf` (optional) until `exp`.

  - `at`: the namespace revision the issuer decided at: an `ns_id` of the namespace itself, or `{ "ns", "id" }` for another namespace the issuer follows, such as a catalog (optional unless the key has `requireAt`)

  - `rules`: rule forms of §6.4.2

  - `via`: in narrowing blocks only, the delegatee

  - `signers`: in the root block only, the principal's signing keys (§C.3.1)

-
**Narrowing only restricts.** A narrowing block may:

  - reduce `ns`, `can` and `roles`

  - set a later `nbf` or an earlier `exp`

  - add `rules`

  - add a `via`

It MUST NOT change `sub`, `groups` or `attrs`. The effective principal is always the root `sub`, `groups` and `attrs`, with `via` listing the delegatees in order. So a delegate can never claim another identity, group or attribute, and rules on `/principal/*` always see who the authority comes from.

-
**Format.** The reference encoding is Biscuit v3 (§C.8). Any encoding that carries the same verified blocks and lets a holder narrow a grant without the issuer would do, but grants can only be shared between implementations that use the same one.

-
**Verification** needs only the namespace's keys (§C.4). There is no central service, so consumers verify grants too.

### C.1.1 Roles

```
"roles": {
  "reader":     { "can": ["read"] },
  "editor":     { "can": ["read", "create", "append", "restore", "delete"] },
  "translator": { "can": ["read", "append"], "rules": [ { "op": "writes", "within": ["/i18n"] } ] } }
```

- **A role** is a named set of verbs and rules in the namespace document. Grants carry role **names**, never their contents.

- **Expanded at the gate.** Names are resolved against the configuration in force when the request is checked (invariant 6).

  - Changing a role's definition changes what every outstanding grant naming it can do, at once and without reissuing grants.

  - Unknown names grant nothing, so removing a role revokes it.

  - Changing `/roles` requires a `*` key (§7.4).

- **Combination.** Roles are alternatives, everything else is conjunctive. A grant with roles allows an action only if:

  - its blocks allow the verb (§C.2), **and**

  - at least one effective role lists the verb and all of that role's rules pass, **and**

  - the key-scope, block and namespace rules pass.

- **Issuers are bounded** by the key scope `roles` (§C.4), just as with `groups`.

- **Groups or roles.** Groups say who someone is, and are managed by the identity provider. Roles say what they may do here, and are managed by the namespace. An issuer maps one to the other (the catalog does it per folder, §B.11). Rules may test either, but rules on roles survive reorganisations of groups.

- **Other fields** in a role entry are ignored by the core and may be used by consumers (e.g. `move` and `place` in a catalog namespace, §B.11.1).

### C.1.2 Attributes and time

Attribute-based policy is the rule language (§6.4.2) applied to four kinds of attribute:

| Attribute of | Where rules find it | Set by |
|---|---|---|
| the principal | `/principal/attrs/…`, `/principal/groups`, `/principal/roles` | the grant's issuer, e.g. from identity-provider claims |
| the document | `/doc/…` | the writers, under the schema and rules |
| the request | `/action`, `/resource`, `/writes` | the server |
| the environment | `/now` | the server's clock |

- **Principal attributes.** `attrs` in the root block carries issuer-asserted facts such as department, region or clearance. The key scope `attrs` is a JSON Schema the asserted object must validate against, so an issuer can be limited to, say, `clearance ≤ 2` or a fixed set of regions.

- **Relations** between attributes use `compare` (§6.4.2), e.g. `/doc/owner eq /principal/id`. See §6.4.4 for a worked rule.

- **Time windows.** `nbf` and `exp` bound when a grant is valid, for embargoes and scheduled access. Rules on `/now` bound what may be done when, for document-level deadlines like `lockAt`.

## C.2 Checking requests

Grants are checked at step 1 of §6.2 (items 1–3 and the first part of item 4), at step 6 (item 4), and on every read (item 5):

-
**Verify the chain:**

  - first, without verifying anything, that every block that carries `ns` names the namespace (`403` otherwise, §7). This `403` comes before the `401` cases below; a token whose blocks can't be parsed at all is `401`. A read of a public namespace skips both and ignores such a grant (§7).

  - the root signature by a key in the configuration in force

  - every block's signature

  - `nbf` ≤ now < `exp` for every block

  - revocation (§C.4)

  - the key's scope, including `maxTtl`, `groups`, `roles`, `attrs`, `requireAt`/`maxLag` and `readScope`

Failures are `401` when there is no usable grant: missing, malformed, badly signed, revoked, expired, or not yet valid (`nbf`). The client should get a new grant. They are `403` when a valid grant doesn't allow the request.

-
**Check the verbs.** `ns` and `can` (the intersection over all blocks) must allow the action. If the grant carries roles, at least one effective role must also list the verb. For a `PATCH` with `If-Match`, this and item 4 are checked for `append` and for `restore` in turn, giving the candidate verbs of §6.2 step 1; only roles listing a candidate verb count.

-
**Build the principal:** `{ id: root sub, groups: root groups, roles: effective roles, attrs: root attrs, via: [...], grant: grant id }`.

-
**Rules.** At step 1, evaluate the key-scope, block and role rules that refer only to `/action`, `/resource`, `/principal` or `/now`, so that a grant limited to one resource never reaches the precondition of another. At step 6, evaluate the key-scope rules and every block's `rules` together with the namespace rules. If the grant carries roles, at least one of the effective roles that list the verb must also pass all of its own rules. A failing grant, key or role rule is `403`.

-
**Reads** evaluate the key-scope, block and role rules against a `read` envelope (§6.4.1), so a grant restricted to one `/resource` reads only that resource.

## C.3 Attribution and signatures

- **Grant per revision.** Each revision stores its grant's id, `trunc160(sha256(canonical(root block)))`.

- **Stored grant form.** The server stores each grant in a **non-bearer** form that no longer verifies as a credential (with Biscuit, the token without its `proof`, §C.8), so audit data and backups cannot be replayed.

- **Optional author signatures.** A client MAY sign `sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖ 0x0A ‖ bytes(parent) ‖ 0x0A ‖ canonical(patches))` with its own key and send `Signature: <alg>:<kid>:<sig>`. `origin` is the deployment's canonical origin in RFC 6454 ASCII serialisation (`scheme://host[:port]`, lowercase, default port omitted), e.g. `https://cms.example`, as published at `GET /` (§G.1).

  - The input is the **full** digest, and is domain-separated and bound to the deployment, namespace and resource, so a signature can't be replayed into another resource with identical history, even in another deployment with the same names.

  - Signatures are stored **alongside** revisions, never inside ids, and served in logs. A server verifies those whose key the grant lists and stores the rest unverified, and a namespace may require them (§C.3.1).

  - A signature binds the namespace, so it verifies only where the revision was written. A revision merged or replayed into another namespace (Addendum F) keeps its signature as provenance, verifiable against the batch's `source`.

### C.3.1 Signer keys and verification

A signature is checked along one chain, every link of which is immutable or in a hash-chained log, so a revision verifies against the keys in force when it was written, not today's:

- the revision's `Signature`, `<alg>:<kid>:<sig>`;

- an entry with that `kid` in the `signers` of the root block of the grant it was written under, named by its grant reference (§C.3);

- the key that signed that root block: a key of the configuration the write was checked against, which is the namespace document in force at its namespace log entry, after the config change of a batch that makes one (§6.2, §7.5); or a deployment operator key in force at its `created` time (§C.4);

- the namespace log for a namespace key, or the deployment's operator key history (§C.4) for an operator key.

- **Signer keys live in grants.** A root block may list `signers: [{ "kid", "alg", "pub" }]`, with `alg: "Ed25519"` and `pub` the public key in base64url. The issuer that vouches for a principal's authority vouches for its keys, so no registry is needed, and a new key comes with a new grant; old revisions keep the grant they were written under.

  - `kid`s are unique within `signers` and contain no `:`. `pub` and the `<sig>` of a signature are base64url without padding (43 and 86 characters). An entry with any other member or `alg` makes the grant invalid (`401`).

  - Issuers MUST list a key only after the principal has proved possession of it, and MUST NOT list one `pub` for two subjects. The signing input names no principal, so otherwise a holder could attach someone else's signature to its own write.

  - Narrowing blocks MUST NOT carry `signers` (`401`), so a holder can't add a key of its own. A delegated write is therefore signed with the root principal's key or not at all.

  - A namespace document can't list signers. Bots and other long-lived writers get grants with `signers` like anyone else.

- **Tombstones** are signed over the same input with the ASCII bytes `tombstone` in place of `canonical(patches)`, as their ids are (§3.4). A canonical patch set starts with `[`, so the two never collide, and a delete's signature can't pass for an empty append's.

- **At the gate.** When a write carries a signature whose `kid` its grant's `signers` list, the server MUST verify it, after the retry lookup and the verb (§6.2 step 2.3); a bad one is `422` with `code: "signature"`, and so is one whose `alg` isn't that signer's. A signature with any other `kid` is stored unverified, and readers treat it as unattributed.

  - **The parent** in the input is the one the write's precondition names: its `If-Match` id, empty for a create, and in a batch the item's `ifMatch` (empty with `ifNoneMatch`) for its first step and the previous step's id for each later one. A write is accepted only on that parent, so it is the one the revision gets. A write without a usable precondition can't be checked, and gets the precondition's own error (`428`, or `400` for a malformed one).

  - A `Signature` header or step member that isn't `<alg>:<kid>:<sig>` with a base64url `<sig>` is `400` (`bad_input`), as a request-shape error.

  - **Retries.** An idempotent retry (§7.2) is answered with the entry as first recorded, whatever well-formed signature it carries or lacks, even after `required` was turned on: the write was accepted once, and the retry adds nothing.

  - At E3 the input covers the sealed patch set as sent (§E.3.1), so the server verifies without content keys.

  - In a batch, each step object (§7.5) carries its own `signature`. The `Signature` header covers single writes, and is `400` on a batch request.

- **Requiring signatures.** A namespace document may set `"signatures": "required"`; the default is `"optional"`. Every revision and tombstone written to such a namespace then needs a valid signature by a signer of its grant (`422 signature` otherwise, at the same point of the gate). A batch's items are judged under the configuration its config change produces; if that change fails, the batch fails with it.

  - It covers resource revisions and tombstones; namespace documents aren't signed. It is judged by the configuration the gate checks the write against: for a batch item, the one its batch's config change produces (§7.5). Revisions written before it was turned on, and those a branch reads through from its base, aren't covered, so a reader relying on it checks the log position, not only the current document.

  - Changing it needs a `*` key (§7.4).

  - Merges, replays and imports (§F.3, §G.4.4) write new revisions in the target, where the original signatures don't verify, so the writer signs its own steps. A step's `signature` is always the writer's own: original signatures aren't re-sent, and stay reachable through the batch's `source`, verifiable there.

  - Delegated grants can't sign (above), so services that write to such a namespace need root grants of their own (§C.6). While authentication is disabled (§1) no grant lists signers, so every resource write to such a namespace fails.

- **Reading grants.** `GET /ns/{ns}/grants/{gid}` answers `{ "id", "root", "stored" }`. `stored` is the non-bearer form (§C.8) as a JSON array of the token's protobuf `SignedBlock`s in order, authority first, each in base64url without padding. A verifier checks the authority block's signature under the key `root.kid` names, that its one `grant_block` string equals `canonical(root)` byte for byte, and that `id` is `text(trunc160(sha256(that string)))`.

  - It serves the grants recorded by namespace log entries of this namespace and, in a local branch, of its bases up to their `at`, recursively; any other is `404`. A revision a remote branch reads through is verified at its base (§G.3). In a purged namespace it is `410` after the `read` check, since the content its signatures cover is gone (§8.5).

  - A grant shows the principal's groups and attributes and every narrowing block, so it needs unrestricted `read` on the namespace. In a public namespace that is anyone, so issuers keep the `groups` and `attrs` of grants with `signers` for public namespaces to what may be public. It is immutable.

  - Sealed namespaces seal it like a log entry, with `pl: { "ns", "grant": gid }` (§E.2.2), under the epoch that sealed the first namespace log entry recording it, so it reaches the readers who could read that entry and no others. A grant recorded only by a branch's base is sealed under the branch's current epoch, like content it reads through. End-to-end namespaces serve it in the clear, as the server holds it in the clear and serves their logs so (§E.4), with `Cache-Control: private` instead of the immutable class (§9), since a grant shows more than a log entry does.

  - Bundles carry the grants their history references (§G.4.1), so they verify offline.

- **Verifiers** follow the chain with the namespace document's history (from its log, or the key entries a bundle carries) and the operator key history. Verifiers don't check `revoked` (§C.4): the gate refused revoked grants when the write was made, and a later revocation doesn't unsign history. A signature that fails, or whose chain can't be completed, is reported as such. It says nothing about the content, which ids verify (invariant 4), only about who wrote it.

## C.4 Keys, scopes and revocation

-
**Keys.** The namespace document lists `keys: [{ kid, alg, pub, can, … }]`. Root blocks must be signed by one of them. Changing keys and scopes is an ordinary config write, and requires a `*` key (§7.4).

-
**Key scope.** A key entry may restrict every grant it signs:

| Field | Restriction |
|---|---|
| `can` | verbs its grants may contain |
| `maxTtl` | longest remaining lifetime: `exp − max(now, nbf)` |
| `sub` | pattern the root `sub` must match |
| `groups` | `{ "allow": [...] }` or `{ "deny": [...] }` on asserted groups |
| `roles` | `{ "allow": [...] }` or `{ "deny": [...] }` on asserted roles |
| `attrs` | a JSON Schema the asserted `attrs` must validate against |
| `rules` | conditions added to every grant |
| `readScope: "resource"` | every `read` grant must fix `/resource` with a rule |
| `rate` | a lower per-principal write rate for grants it signs, `{ "rate", "burst" }` as in `limits` (§6.6) |
| `maxLag` | a stricter `maxLag` than the namespace's for `at` in grants it signs (see `requireAt`) |
| `requireAt` | `true`: `at` must be an `ns_id` in this namespace's chain. A namespace name: `at` must be in that namespace's chain. Either way `at` must have been that namespace's head at some point within `maxLag` before the grant was issued, taken as `max(nbf, exp − maxTtl)`, or `nbf` when the key sets no `maxTtl`. A `requireAt` key SHOULD set `maxTtl`. The namespace document of the namespace `at` belongs to sets `maxLag` (default 60 seconds), a key may set a stricter one of its own, and the smaller applies |

-
**Revocation.**

  - Grants should be short-lived and refreshed by their issuer.

  - For immediate revocation, add a **revocation id** to `revoked: [...]` in the namespace document. A block's revocation id is `text(trunc160(sha256(its signature)))`. A chain containing any revoked block is rejected. Revoking a root block therefore revokes everything narrowed from it, however it was re-serialised.

  - Revocation is per namespace. Issuers revoke in every namespace a grant lists.

  - **In a branch**, a chain is also rejected if any of its blocks is revoked in any of the branch's bases.

-
**Keys follow the base.** A branch copies its base's keys when it is created (§7.6). A key that a branch shares with a base (same `kid`) is accepted only while it is still present, with the same `pub`, in that base's current configuration. Removing or replacing a compromised key in a base therefore removes it from every branch too. Keys added only to a branch were added with a base `*` key (§7.6), and are the branch's own.

-
**Bootstrapping.** Creating a namespace needs a deployment-level operator key configured outside the system. It is the one step that cannot describe itself. A grant for a namespace that doesn't exist yet names it in `ns`, or uses `"*"`, which only grants signed by an operator key may do. Branches are the exception: they are created with a `branch` grant on their base (§7.6).

-
**Operator key history.** A deployment publishes its operator keys as a JWK Set (RFC 7517) at the `jwks_uri` it gives at `GET /` (§7), by default `/.well-known/patchlog-keys`. Verifiers read the URI there rather than guess a path. `/.well-known/jwks.json` is a convention, not a registered name, and an identity provider on the same domain may publish keys for another purpose there.

  - Each key is an OKP Ed25519 JWK with `kid` and `use: "sig"`, plus `"patchlog": { "from", "until"? }`, the RFC 3339 period it was in force. Generic JOSE tools ignore that member. The set is served as `application/jwk-set+json`, publicly cached for minutes, e.g. `public, max-age=300`.

  - The period is the operator's to declare. `from` MUST be no later than the first entry written under a grant the key signed, so a deployment publishing a key it already used gives the time the key was configured, or else the time of the deployment's first entry. A key authorises only within its period: grants it signed are refused before its `from` and after its `until`, and verify only for revisions created within it. The gate and verifiers then agree, and a key published later can't vouch for older history.

  - It is a history, not a current set: keys are never removed, and `kid`s never reused. A grant signed by an operator key verifies against the key in force at the revision's `created` time (§C.3.1).

  - It lists no namespace keys. Those are in namespace documents, whose hash-chained log is a stronger source than a document served over HTTPS, and listing those of private namespaces would reveal that they exist (§E.4).

  - Trust in it rests on TLS and the origin, as a remote branch's trust in its base does (§G.3). A verifier that wants more pins operator keys obtained out of band.

## C.5 Reading

- **Read modes.** A namespace document declares `"read": "public" | "grant"`. Independently, it may be **sealed** (Addendum E), in which case content can be served publicly and only key holders can decrypt it.

  -
**Public:** cached publicly (§9). Only namespaces whose base, if any, is public may be public (§7.6).

  -
**Grant:** served through CDN edge grants (signed cookies or URLs). The origin issues an edge grant in exchange for a verified grant with `read`, scoped to the **smallest prefix the grant allows**:

    - `/r/{ns}/{name}` and `/r/{ns}/{name}/…` when its rules fix `/resource`

    - otherwise `/r/{ns}/…` and `/ns/{ns}/…`

The edge verifies the edge grant on every request, and it is not part of the cache key. Downstream caching is `private` (§9). The edge grant's lifetime is the revocation latency, so keep it short (5–15 minutes). No edge grant is issued before the grant's `nbf`, and none outlives its `exp`.

- **Per document, not per field.** Never filter fields per reader: that multiplies cached copies and defeats caching. Keep sensitive fields in a separate resource in a private namespace, and link to it.

- **Ids are not secrets.** Ids leak through logs, referrers and parent links. They are defence in depth, never access control.

- **The stream is metadata.** Names and edit timing can be sensitive, so `/ns/{ns}/…` and every events stream require `read`.

### C.5.1 Reads are decided at issuance

- **Why.** A read envelope has no document, and the edge serves cached bytes without looking inside them. A read decision therefore cannot depend on content at request time.

- **Writes** get full attribute-based checks at the gate: rules see the principal, the resulting document and the time.

- **Reads** that depend on content are decided by an **issuer** that follows the namespace, evaluates the policy per document, and issues grants fixed to the resources that pass, with `nbf`/`exp` for time windows. "Readers see matches in their own regions" becomes:

```
{ "kid": "access-01", "sub": "user:li", "attrs": { "regions": ["se"] },
  "ns": ["matches"], "can": ["read"], "at": "1k…",
  "nbf": "2026-10-04T18:00:00Z", "exp": "2026-10-04T18:15:00Z",      // embargo lifts at 18:00
  "rules": [ { "op": "test", "path": "/resource", "value": "derby" } ] }
```

  The catalog (§B.11) is one such issuer. An access service evaluating attribute policies is another.

- **Evaluated directly on reads:** rules over `/principal`, `/resource`, `/action` and `/now`, such as office hours, or a resource-name prefix per region.

- **Consequence.** A content-based read decision lags the content by up to `maxLag` plus the grant's lifetime (§B.11.8). Where that is too slow, move the sensitive part into its own resource, or seal it (Addendum E) and revoke by rotating keys.

## C.6 Consumers and plug-in services

- **Least privilege.**

  - A service gets `read` for what it follows.

  - A service that writes back gets a narrowing block with `writes within` its own paths, and without `delete`, `purge`, `config`, `branch`, `purge-ns`, `export` or `prune`.

  - A service that **proposes** changes, such as an AI summariser or a bulk rename, can write to a branch instead of the base (Addendum F). A person then reviews and merges, and the service needs no write access to the base at all.

  - A translator narrowed to `within ["/i18n"]` cannot write anything else, however it spells its patches, apart from a fresh `$nonce` (§6.4.1).

- **Services that re-publish content MUST enforce reader permissions.** Search, tree and catalog results are filtered by the reader's verified grant. Private results are cached per subject set (§B.11.5), not per request, and never with embedded bearer URLs.

## C.7 Private content and guessable hashes

- **Guessing from ids.** A revision id is a hash of its parent id and its patch set. Parent ids are public: they appear in URLs, redirects, events and logs, and no encryption level hides them (§E.4). So anyone can confirm a guess of a low-entropy patch set (`replace /score "2-1"`, an email address) against the next id. A nonce only in genesis doesn't help, because the guesser starts from the parent, not from genesis.

- **A nonce in every patch set.** In private namespaces with guessable content, every patch set SHOULD `add` `/$nonce` with 128 fresh random bits, base32 (26 characters). `add` works whether or not the key exists yet. Every id then depends on a secret the guesser lacks. Such a write is left out of `writes` (§6.4.1), so path rules and merges ignore it, and validation doesn't see the key (§6.2).

- **Blobs.** A blob id is a hash of its bytes (§3.7), so the same applies. In private namespaces with guessable blobs, uploads SHOULD carry a `Blob-Nonce`, and in sealed namespaces writers MUST give the blobs they create one (§7.8).

- **Encryption:** see Addendum E. Sealed namespaces MUST refresh `$nonce` in every patch set. At E3 ids are over ciphertext with a random IV, so no nonce is needed.

## C.8 Reference encoding: Biscuit v3

Grants are carried as Biscuit v3 tokens. Biscuit provides exactly what §C.1 needs and is hard to get right alone: a chain of signed blocks that a **holder** can extend offline. Each block is signed with an ephemeral key whose private half travels in the token, so anyone holding a grant can add a narrowing block, and nobody can remove or alter one. Libraries exist for several languages.

- **One block, one fact.** Each block of §C.1 is one Biscuit block containing exactly one fact, `grant_block(<string>)`, whose string is the block's canonical JSON (§3.1). The string MUST be I-JSON and equal to its own canonical form (`401` otherwise), so every verifier reads the same fields. The authority block carries the root block; each appended block carries one narrowing block, in order.

  - A block with anything else (other facts, rules, checks, scopes), or a third-party block, makes the token invalid (`401`).

  - Biscuit's Datalog is not evaluated. The server verifies the signature chain with a Biscuit library, extracts the JSON blocks, and applies §C.2 to them. Validity times are the blocks' `nbf` and `exp`, not Datalog time checks.

- **Keys.** Every signature in the token is Ed25519, including the ephemeral keys that sign narrowing blocks, verified strictly (RFC 8032, with `S < L`). A token using any other algorithm is `401`. Ed25519 signatures can't be altered without the key, so a block's signature, and therefore its revocation id, is fixed once it exists. The root key entry says `alg: "Ed25519"`. Biscuit's `rootKeyId` is a number, so the key is named by `kid` inside the root block. The verifier reads it, looks up that key in the configuration in force, and verifies with it. A wrong `kid` fails verification like any bad signature.

- **Revocation ids** (§C.4) are `text(trunc160(sha256(sig)))`, where `sig` is the block's Biscuit signature. Revoking the authority block's id revokes every grant narrowed from it.

- **Sealed tokens** are accepted. A holder seals a grant to stop anyone narrowing it further.

- **Stored form** (§C.3). The server stores the ordered list of blocks with their signatures and next keys, without the token's `proof`. Every block signature can still be checked, but it is no longer a token, so audit data can't be replayed as a credential.

- **Transport.** `Authorization: Bearer <token>`, the token as Biscuit's URL-safe base64, with or without the `biscuit:` prefix. The grant size limit (§6.6) applies to the decoded bytes.

- **Grant id** (§C.3) stays `trunc160(sha256(canonical(root block)))`, over the root block's JSON, so it doesn't depend on the encoding.

## C.9 Open questions

- Should revocation lists be shared across namespaces, e.g. per issuer?

- Should role definitions be shareable across namespaces, e.g. as a resource referenced by immutable revision, like `$schema`?

---

# Addendum D — Reference implementation (Bun + SQLite)

Everything in this addendum is specific to the implementation in this repository. It is not part of the specification. D.2–D.5 describe the SQLite layout; D.8 describes an alternative on Postgres.

## D.1 Stack

- Bun and TypeScript (strict), `bun:sqlite`, `Bun.serve` and `Bun.CryptoHasher`.

- Dependencies: `ajv`, `ajv-formats` and `fast-json-patch`. ajv doesn't collect annotations, which is why §6.5 finds `x-ref` with a static walk instead. Two more are needed for the spec:

  - an RFC 8785 canonicaliser, or an in-house one

  - a linear-time regex engine plugged into ajv's `code.regExp` option, e.g. an RE2 binding (§6.6)

- One process and one SQLite file in WAL mode.

## D.2 Storage layout

- **Each hash is stored once**, as a 20-byte BLOB. Everything else references rows by integer.

- **Names are stored once.** Namespace, resource and author names live in their own tables.

- **Timestamps** are integer Unix milliseconds.

```
CREATE TABLE namespaces (
  ns       INTEGER PRIMARY KEY,
  name     TEXT    NOT NULL UNIQUE,
  base     INTEGER REFERENCES namespaces,  -- NULL unless a branch
  base_at  INTEGER,                        -- ns_log.seq of `at` in the base
  frozen   INTEGER NOT NULL DEFAULT 0,
  purged   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE authors    (author INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);

CREATE TABLE resources (
  res      INTEGER PRIMARY KEY,
  ns       INTEGER NOT NULL REFERENCES namespaces,
  name     TEXT    NOT NULL,
  head_seq INTEGER,                        -- current head entry (revision or tombstone)
  state    INTEGER NOT NULL DEFAULT 0,     -- 0 live · 1 tombstoned · 2 purged
  horizon_seq INTEGER,                     -- §8.6; NULL if never pruned
  UNIQUE (ns, name)
);

CREATE TABLE revisions (
  seq        INTEGER PRIMARY KEY,
  res        INTEGER NOT NULL REFERENCES resources,
  id         BLOB    NOT NULL,             -- 20 bytes
  parent_seq INTEGER,                      -- NULL for genesis; a row of another resource for a foreign parent
  first      INTEGER NOT NULL DEFAULT 0,   -- 1 for the resource's first entry (genesis or foreign parent)
  kind       INTEGER NOT NULL,             -- 0 rev · 1 tombstone
  patches    TEXT,                         -- canonical JSON; NULL for tombstones, after purge, and below a horizon
  author     INTEGER NOT NULL REFERENCES authors,
  via        TEXT,                         -- JSON array, when delegated
  gesture    TEXT,                         -- §7.2, metadata, not hashed
  undoes     TEXT,
  grant_id   BLOB,                         -- §C.3
  created    INTEGER NOT NULL,
  UNIQUE (res, id),
  UNIQUE (res, parent_seq)
);
CREATE UNIQUE INDEX one_first ON revisions (res) WHERE first = 1;
CREATE INDEX revisions_by_id ON revisions (id);   -- finds draft schema revisions in branches (§6.1)
CREATE INDEX revisions_by_gesture ON revisions (gesture) WHERE gesture IS NOT NULL;  -- §7.4
CREATE INDEX revisions_by_undoes ON revisions (undoes) WHERE undoes IS NOT NULL;

CREATE TABLE grants (id BLOB PRIMARY KEY, blocks TEXT NOT NULL,               -- non-bearer form (§C.3)
                     sub TEXT NOT NULL, kid TEXT NOT NULL);   -- root sub and kid, in plaintext even under E1 (§E.1), so log reads never need the key store

CREATE TABLE heads (res INTEGER PRIMARY KEY REFERENCES resources, doc TEXT NOT NULL);   -- a cache, only for small documents (D.4)
CREATE TABLE snapshots (res INTEGER NOT NULL REFERENCES resources, seq INTEGER NOT NULL REFERENCES revisions, doc TEXT NOT NULL, PRIMARY KEY (res, seq)) WITHOUT ROWID;  -- documents kept below a horizon (§8.6)

CREATE TABLE ns_log (
  seq        INTEGER PRIMARY KEY,
  ns         INTEGER NOT NULL REFERENCES namespaces,
  id         BLOB    NOT NULL,
  prev_seq   INTEGER,
  kind       INTEGER NOT NULL,             -- 0 head · 1 tombstone · 2 purge · 3 config · 4 batch · 5 purge-ns · 6 branch · 7 prune
  target_seq INTEGER,                      -- revisions.seq, or ns_config.seq (for branch: the branch's config genesis); NULL for batch and purge-ns
  entries    TEXT,                         -- a batch's entries, canonical JSON in request order (§3.5)
  source     TEXT,                         -- a batch's `source`, canonical JSON
  grant_id   BLOB,                         -- §C.3; the root `sub` and `kid` are read from the stored grant
  author     INTEGER NOT NULL REFERENCES authors,
  created    INTEGER NOT NULL,
  UNIQUE (ns, id),
  UNIQUE (ns, prev_seq)
);
CREATE UNIQUE INDEX one_ns_first ON ns_log (ns) WHERE prev_seq IS NULL;

-- one row per head change of any write, including every item of a batch
CREATE TABLE head_history (
  res        INTEGER NOT NULL REFERENCES resources,
  ns_seq     INTEGER NOT NULL REFERENCES ns_log,
  target_seq INTEGER NOT NULL REFERENCES revisions,
  PRIMARY KEY (res, ns_seq)
) WITHOUT ROWID;

CREATE TABLE blobs (                        -- attached blobs
  res      INTEGER NOT NULL REFERENCES resources,
  bid      BLOB    NOT NULL,                -- 20 bytes (§3.7)
  type     TEXT    NOT NULL,
  nonce    TEXT,
  size     INTEGER NOT NULL,
  hash     BLOB    NOT NULL,                -- sha256 of the bytes
  file     TEXT    NOT NULL,                -- this copy's own name in blob storage: hash plus a random suffix
  created  INTEGER NOT NULL,
  pruned   INTEGER NOT NULL DEFAULT 0,      -- 1 once pruning ended the attachment: answers 410
  PRIMARY KEY (res, bid)
) WITHOUT ROWID;
CREATE TABLE blob_refs (                    -- runs of revisions whose documents reference a blob
  res      INTEGER NOT NULL REFERENCES resources,
  bid      BLOB    NOT NULL,
  from_seq INTEGER NOT NULL REFERENCES revisions,  -- first revision of the run
  to_seq   INTEGER REFERENCES revisions,           -- first revision after it; NULL while the head references it
  PRIMARY KEY (res, bid, from_seq)
) WITHOUT ROWID;
CREATE TABLE blob_pending (                 -- one row per resource, blob and uploader
  res      INTEGER NOT NULL REFERENCES resources,
  bid      BLOB    NOT NULL,
  uploader TEXT    NOT NULL,                -- root sub and kid
  type     TEXT    NOT NULL,
  nonce    TEXT,
  size     INTEGER NOT NULL,
  hash     BLOB    NOT NULL,
  file     TEXT    NOT NULL,
  created  INTEGER NOT NULL,
  PRIMARY KEY (res, bid, uploader)
) WITHOUT ROWID;

CREATE TABLE ns_config (
  seq        INTEGER PRIMARY KEY,
  ns         INTEGER NOT NULL REFERENCES namespaces,
  id         BLOB    NOT NULL,
  parent_seq INTEGER,
  patches    TEXT    NOT NULL,
  author     INTEGER NOT NULL REFERENCES authors,
  created    INTEGER NOT NULL,
  UNIQUE (ns, id),
  UNIQUE (ns, parent_seq)
);
CREATE UNIQUE INDEX one_config_genesis ON ns_config (ns) WHERE parent_seq IS NULL;
```

- **`head_history`** answers read-through (§7.6) and `/heads` (§7.4): the head of a resource as of `at` is its latest row with `ns_seq ≤ base_at`.

- **Blob bytes live outside SQLite**, as files in a blob directory or objects in a bucket. Large values in rows would bloat the WAL and the page cache. The database row decides which bytes exist; the store only holds them.

  - **One name per stored copy.** Each copy is stored under its own name, the `hash` plus a random suffix, recorded in its row, so a delete only ever removes its own file. Names by `hash` alone race: a cleanup commits the deletion of the last row, a concurrent upload of the same bytes writes the same file and inserts a new row, and the cleanup's delete after commit then removes the file the new row names. Storing identical bytes once is possible only if deletes are ordered with re-uploads of the same `hash`, e.g. by one lock on it held from writing the file until the row commits.

  - **Ordering.** A file is written durably before the transaction that adds its row commits: to a temporary name, `fsync`, rename, then `fsync` of the directory. A crash then leaves at most an orphan file. A file is deleted only after the commit that leaves its row gone, or marked pruned. A sweep removes files that no row names and that are older than a grace period longer than any transaction.

  - **Encryption at rest.** Under per-resource E1 keys (§E.1), each copy is encrypted under its resource's key, and a row inserted for a blob taken from another resource (a base, a batch's `source` or a copy) gets its own re-encrypted copy, written before the write lock is taken.

  - **Attaching** happens in the write transaction: D.3's re-check also confirms that every blob the write references is still attached, or still pending for the writer. The commit opens a `blob_refs` run for each blob the new document starts to reference, closes the runs of those it stops referencing (a tombstone closes none, since the last live document stays stored), inserts a `blobs` row unless one exists (a row marked `pruned` has its mark cleared and is reused), and deletes every `blob_pending` row for the blobs it references.

  - A background task deletes `blob_pending` rows past `blobGrace`, in a write transaction. The pruner marks `pruned` on the rows none of whose runs still reaches a stored document.

  - Branches and batch sources find blobs through runs that cover a revision in their view.

  - In sealed namespaces, `sealings (ns, name, id, e, bytes)` holds each revision's stored sealing, whose first insert fixes its epoch. The epochs a blob is served under (§E.2.2) are worked out at read time from the sealings of the revisions that reference it. `blob_epochs (ns, name, bid, e, file)` has a row only for each sealed copy of a blob actually stored, as a file written in the order above, and its first insert decides which copy wins across instances. Both are keyed by name, so a branch can store sealings of read-through content without creating resource rows on a read.

- **Rows are not shared between namespaces.** A branch that replays the same patch sets produces the same ids, but stores its own rows. Namespace purge (§8.5) therefore just clears `patches`, `heads`, `snapshots`, `blobs`, `blob_refs` and `blob_pending` for the namespace's resources, and `blob_epochs` for every name in it, read-through ones included. A resource purge clears its name's `blob_epochs` rows in every branch it reaches. Their files are deleted after the commit. Deleting a plaintext file is no secure erasure: only encryption at rest makes a purge final, since the purge destroys the per-resource keys (§E.1).

## D.3 Write path

- **Outside any transaction:** authenticate, parse I-JSON, apply the patches to the cached head, check limits, validate, and evaluate rules against the configuration at the current namespace head.

- **Insert:** `BEGIN IMMEDIATE`, then re-check that the resource head, namespace config id and `revoked` list are unchanged. In a branch, also re-check the keys and `revoked` lists of every base (§C.4).

  - If they are, insert the revision, its `head_history` row, the namespace entry and, for small documents, the head snapshot (D.4), and commit.

  - If not, roll back and redo step 1, or return `412` if the resource head moved.

- **Batches** follow the same path. All items are validated outside the lock. Then one `BEGIN IMMEDIATE` re-checks every item's head and the configuration, and inserts, in one transaction:

  - the batch's `ns_config` row, if it changes the configuration

  - every revision, with its `head_history` row and, for small documents, its head snapshot

  - one `ns_log` row, with `entries` and `source`

- **Heavy work happens outside the lock.** Validation and rule evaluation never run inside the single SQLite write lock, and invariant 6 still holds. Where the lock is per namespace (D.8), small writes MAY be checked inside it instead, which saves the separate check phase and its round trips at the cost of holding the lock a little longer. Keep large writes and batches outside.

- **Constraint violations are handled explicitly:**

  - A `UNIQUE (res, …)` violation means a concurrent writer won: `412`.

  - A `UNIQUE (ns, prev_seq)` violation is a namespace-chain race between different resources, which is retried internally.

## D.4 Snapshots and caches

-
**Head snapshots are a cache for small documents.** `heads` is updated in the write transaction, with an in-memory LRU in front of it, but only for documents up to a threshold (default 16 KiB). Rewriting a large document on every save costs its whole size in writes each time: a 300 KB document edited a few times a second would write about 1 MB/s for one editor.

-
**Intermediate snapshots** go into `snapshots` (D.2) whenever 64 KiB of patch sets or 100 revisions have accumulated since the last one, whichever comes first. A large head, or any old revision, is served by folding from the nearest snapshot at or before it, so a read never folds more than that. Folding from genesis is only for short logs.

-
**Pruning.** A pruned row keeps `id` and `parent_seq` and sets `patches` to NULL. The horizon's document, and any kept ones, go into a `snapshots (res, seq, doc)` table. `resources.horizon_seq` marks the horizon. A background pruner applies `retention`, writing the archive bundle before it drops anything.

-
**Restoring from an archive** is an offline task. Skip purged resources (§8.3). Re-insert each patch set whose recomputed id matches the kept row, then clear `horizon_seq`. Attachments that pruning ended come back at the same time, with their blobs from the archive, and the recorded `410` epochs (§E.2.2) are cleared.

-
**Rate limits** are in-memory token buckets per (resource, principal), principal and namespace, where the principal is the root `sub` and signing `kid`. With one process that is exact. Several processes would need a shared counter, or would split the limits between them.

## D.5 Sizing (measured)

- **How it was measured:** SQLite (`bun:sqlite`, 4 KiB pages, after `VACUUM`) on 10,000 documents × 100 revisions, scaled linearly. Reproduce with `DOCS=10000 bun bench/storage.ts`, which builds both layouts.

- **Test data:**

  - Head documents are ~2.8 KB of JSON; ~4.1 KB per document once SQLite row and page overhead is included.

  - Patch mix: 55% single `replace`, 25% `add` of a block, 12% two-op edits, 8% `test` + `replace`.

  - The average patch set is ~95 B of JSON, or ~107 B including the amortised genesis.

| Layout | Per revision | 1M docs × 100 revisions |
|---|---|---|
| v0.1: hex text ids, repeated names, ISO timestamps | ~1,005 B | ~100 GB |
| **D.2 layout** (including head snapshots) | **~334 B** | **~33 GB** |

- **Breakdown:**

  - revision rows ~163 B (patch JSON ~107 B, id 20 B)

  - namespace log rows ~39 B

  - hash indexes ~90 B

  - head snapshots ~41 B amortised

- **Not measured:** `grant_id` and `via` add roughly 20–40 B, and `head_history` about 25 B per head change.

- **Throughput:** ~21,000 revisions/s on one thread, including hashing and canonicalisation.

- **Further options:**

  - zstd with a trained dictionary for `patches`

  - an 8-byte id-prefix index

- **Consumers' own storage is not included.**

## D.6 Implementation status

The current code (`log.ts`, `server.ts`, `client.ts`, `demo.ts`) predates most of this spec.

| Area | Status |
|---|---|
| Content-addressed revisions, SHA-256 | ⚠️ 64-char hex over `parent + "\n" + patches`; to change to §3.2–3.3 |
| Canonical JSON | ⚠️ sorted-key JSON, not JCS; no I-JSON input checks |
| Storage | ⚠️ single table, text ids; to change to D.2 |
| Schema validation | ⚠️ single global `schema.json`; to change to opt-in `$schema` (§6.1) |
| Linear log, ids unique per resource | ✅ |
| Replay and verification | ✅ |
| Head redirect, immutable `/rev/{id}`, `/rev/{id}/log?since=`, ETag/304 | ✅ (cache headers to update per §9) |
| SSE with catch-up | ✅ |
| Long-poll with cursors (§7.7) | ❌ |
| Client load / sync / submit-with-rebase / watch | ⚠️ uses the old `POST` + body `parent` + `409` API |
| Writes | ⚠️ `POST`, `409`; to change to `PATCH` + `If-Match`, gate order of §6.2, `412`/`428`, idempotent retry |
| Namespaces, names grammar, namespace log and document, rules with `writes` and `compare` | ❌ |
| Tombstone / restore / purge | ❌ |
| Limits, linear-time regex | ❌ |
| Addendum C grants, roles and attributes | ❌ |
| Batches, branches, freeze, namespace purge | ❌ |
| Remote branches: read-through, verification, schema mirroring (§G.3) | ❌ |
| Rate limits, pruning and retention (§6.6, §8.6) | ❌ |
| Blobs (§7.8) | ❌ |
| Addenda A and B services, Addendum F merge service, Addendum G export and import tools | ❌ (optional, separate processes) |

## D.7 Suggested order

- **Ids, canonicalisation and storage:** §3 (JCS, I-JSON, base32 ids) and D.2. Everything builds on these, and changing ids later breaks every cached URL.

- **Write path:** `PATCH` with `If-Match`/`If-None-Match`, `412`/`428`, idempotent retry, D.3.

- **Namespaces:** URL scheme and name grammar, the namespace log and document, `writes` and the rule engine, limits.

- **`$schema`:** strict references, bundled meta-schemas.

- **Deletion:** tombstones, restore, purge, cache tags, §9 headers.

- **Grants:** Addendum C: chain verification and key scopes first, then roles and attributes (§C.1.1–C.1.2).

- **Batches and branches:** batches first (§7.5, useful on their own), then branches with read-through and foreign parents (§7.6), freeze and namespace purge (§8.4–8.5).

- **Export and import tools** (Addendum G), as separate programs using the public API.

- **Hardening:** a test per invariant (§4) and per rule predicate, and fuzzing of `writes` computation against JSON Pointer escaping.

## D.8 Postgres layout (alternative)

For deployments that already run Postgres. The model is the one of D.2 and D.3; this section lists what changes. Postgres brings high availability, backups and point-in-time recovery, and lets the application servers be stateless, so rolling deploys and several instances need nothing special.

- **Locks per namespace, not per database.** Writers to different namespaces run in parallel, and validation still happens before any lock.

- **Namespace state.** Writes that change a namespace's configuration or state (config writes, purges, prunes, branch creation, freezing) take its advisory lock `pg_advisory_xact_lock(<class>, ns)` exclusively. Resource writes, batches and blob uploads take it shared, as they do for every other namespace their decision reads, then re-check the config id and revocations as in D.3. So the configuration can't change between a write's check and its insert (invariant 6), while writes to different resources of one namespace proceed in parallel.

- **Same resource.** Races between writes to one resource are decided at insert, by the constraints of D.2: one child per parent, one entry per id, one first entry, and a head that moves only from the head the precondition matched. The loser re-checks and gets `412` with the new head, or the answer for a retried write (§7.2). D.3's re-check is then exact only for namespace-level state.

- **The log append** is serialized separately and last: a write takes a second advisory lock, in a class of its own, `pg_advisory_xact_lock(<log class>, ns)`, just before appending its namespace entry, and holds it through commit. Log locks are taken after all other locks, in ascending key order when a write appends to several logs (purge propagation, branch creation), each while holding that namespace's state lock, so they can't take part in a deadlock. (A row lock on the namespace would conflict with the key-share locks that inserting a resource row takes on it, and deadlock concurrent creates.) Entries of one namespace therefore commit, and their sequence numbers grow, in log order. Other per-namespace counters, such as an uploader's pending blob total (§7.8), use row locks of their own.

- Branch creation locks the base, which receives the `branch` entry, then creates the branch.

- Purge propagation (§8.3) locks the affected namespaces in ascending lock-key order (below), so concurrent propagations can't deadlock.

- **Other namespaces a write depends on** are locked too, in shared mode: the namespaces its `$schema` and its whole `$ref` closure resolve into (§6.1), branches holding drafts included, and, in a branch, every base whose keys and revocations it re-checks (§C.4). Config writes, purges and prunes take their namespace's lock exclusively. A purge also takes, in shared mode, the lock of every other namespace holding a copy of a referenced schema revision it would remove (§6.1), whether or not that copy serves the reference, as locks found late (below), so two purges can't each remove one of the last two copies. A schema purge or a base revocation therefore can't commit between a write's check and its insert.

- Locks are taken in ascending lock-key order, whatever their mode, so no two writers can deadlock. Some writes find their locks as they go: a branch's bases, a `$ref` closure, a batch's `source`, the branches a purge reaches. One that needs a lock below one it holds tries it without waiting (`pg_try_advisory_xact_lock`, or `…_shared`), and if that fails, rolls back and restarts, taking in order every lock it has found so far. A key it holds shared and now needs exclusively counts as found late too. Each restart only grows the set, so the loop ends.

- Writes run in `READ COMMITTED`, which is enough with those locks provided every re-check reads after the locks are held: a namespace row read before taking its lock is read again. The check phase of D.3 and reads each use one snapshot (`REPEATABLE READ READ ONLY`), so they see one consistent state.

- Use the two-argument form with a fixed class id, `pg_advisory_xact_lock(<class>, ns)`, so these locks never collide with other advisory locks in a shared database. Its arguments are 32-bit, so fold the `bigint` namespace id into an `int4`, e.g. its low 32 bits. Then the lock-key order is that of the folded keys, and each key is taken once, in the strongest mode any of its namespaces needs, or two namespaces with one key can deadlock. Alternatively use the one-argument `int8` form, with the class in the high 16 bits. Either way, retry a transaction that Postgres aborts with `40P01`.

- **Rows shared by all namespaces,** such as authors, stored grants and namespace names, aren't covered by any namespace lock. Insert them with `ON CONFLICT DO NOTHING` and select them again. A unique violation on one of them retries the transaction (others mean what D.3 says).

- **Exact bytes.** `patches`, `heads.doc`, snapshots and `ns_log.entries` are `text` holding canonical JSON, never `jsonb`, which reorders keys and normalises numbers. Ids must be served and re-hashed from exactly the stored bytes (§3.1). Anything that may be encrypted at rest (§E.1), such as patch sets, head and other snapshots and stored grants, is `bytea` instead, holding the canonical JSON or its encryption.

- **Content apart from the skeleton.** Patch sets live in their own table, so purge and pruning are `DELETE`s rather than updates that leave dead rows in an append-heavy table:

```
CREATE TABLE namespaces (
  ns       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name     text    NOT NULL UNIQUE,
  base     bigint  REFERENCES namespaces,
  base_at  bigint,
  frozen   boolean NOT NULL DEFAULT false,
  purged   boolean NOT NULL DEFAULT false
);
CREATE TABLE authors (author bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text NOT NULL UNIQUE);

CREATE TABLE resources (
  res         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ns          bigint   NOT NULL REFERENCES namespaces,
  name        text     NOT NULL,
  head_seq    bigint,
  state       smallint NOT NULL DEFAULT 0,       -- 0 live · 1 tombstoned · 2 purged
  horizon_seq bigint,
  UNIQUE (ns, name)
);

CREATE TABLE revisions (                          -- the skeleton: kept after purge and pruning
  seq        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  res        bigint   NOT NULL REFERENCES resources,
  id         bytea    NOT NULL CHECK (octet_length(id) = 20),
  parent_seq bigint   REFERENCES revisions,
  first      boolean  NOT NULL DEFAULT false,
  kind       smallint NOT NULL,                   -- 0 rev · 1 tombstone
  author     bigint   NOT NULL REFERENCES authors,
  via        jsonb,
  grant_id   bytea,
  created    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (res, id),
  UNIQUE (res, parent_seq)
);
CREATE UNIQUE INDEX one_first ON revisions (res) WHERE first;
CREATE INDEX revisions_by_id ON revisions (id);

CREATE TABLE patch_sets (seq bigint PRIMARY KEY REFERENCES revisions, patches text NOT NULL);
CREATE TABLE heads (res bigint PRIMARY KEY REFERENCES resources, doc text NOT NULL) WITH (fillfactor = 70);
CREATE TABLE snapshots (res bigint NOT NULL REFERENCES resources, seq bigint NOT NULL REFERENCES revisions,
                        doc text NOT NULL, PRIMARY KEY (res, seq));
-- grants, ns_log, head_history and ns_config as in D.2, with bytea ids and bigint keys.
-- Times may be timestamptz or, as in D.2, integer milliseconds.
```

-
`heads` is the only table updated in place, and holds only small documents (D.4). A value over about 2 KB is stored out of line (TOAST) and rewritten whole on every update, so larger documents are served by folding from `snapshots`. The lower `fillfactor` keeps the small updates on the same page (HOT updates), so they need little vacuuming.

-
The other tables are insert-only, which autovacuum handles cheaply. Purge and pruning delete from `patch_sets`, `snapshots` and `heads`, and vacuum reclaims the space.

-
**Waking live readers: a tailer, not `NOTIFY`.** Postgres serialises the commit of every transaction that sent a `NOTIFY`, across the whole database, which would undo the parallelism above. Instead each instance runs one **tailer**:

- It reads new `ns_log` rows by sequence every 50–100 ms (`WHERE seq > $last ORDER BY seq`, an index range scan), and wakes the long-polls (§7.7) and SSE streams waiting on those namespaces. They then read their entries by id.

- Entries of one namespace commit in order (above), but those of different namespaces don't, and a large batch can take a while to commit. So the tailer follows transaction ids, not sequence numbers, as a transactional outbox does: `ns_log` gains `xid xid8 NOT NULL DEFAULT pg_current_xact_id()` (indexed), and each poll reads `WHERE xid >= $from AND xid < pg_snapshot_xmin(pg_current_snapshot()) ORDER BY xid`, then advances `$from` to that `xmin`. Everything below `xmin` has committed or aborted, so no transaction, however long, is skipped. (These functions exist from Postgres 13.) The same `xmin` means a long transaction anywhere in the database holds back every tailer, so keep transactions short and set `idle_in_transaction_session_timeout`.

- A wake-up is a hint, never data: waiters always re-read from their own `since`, so a late wake-up delays and never loses anything.

- Logical decoding can replace polling, at the cost of `wal_level = logical` and a replication slot per instance.

- Transaction-scoped advisory locks work through a transaction-pooling layer such as pgbouncer, so the write path needs no dedicated connections.

-
**Blobs.** Bytes go to a bucket, or to a shared filesystem that every instance mounts, named and ordered as D.2 gives, not into `bytea` columns, which are limited to 1 GB and rewritten through TOAST. The blob tables are as in D.2.

- **Back up the database and the blob store together.** A database restored to an earlier point names files deleted since. So keep deleted files, or the bucket's object versions, for as long as point-in-time recovery reaches back, and let the orphan sweep and deletes after commit remove a file only once it is older than that window. A purge's plaintext files are then gone only after the window; with encryption at rest, the destroyed key ends them at once (§E.1).

-
**Per-instance caches.** A cache keyed by id holds content that never changes, but what a read of an id may return does: purge, pruning, namespace purge, key destruction and a switch to private all change it. So does a switch to sealed, and a restore from an archive. Every commit that does any of these increments a one-row generation counter, which the tailer reads on each poll:

- An instance serves from its caches only while its last successful poll started within a bound, such as three poll intervals, and empties them when the counter moves. Such commits are rare, so the counter is no hot spot, and emptying is cheap.

- A read notes the counter before it takes its snapshot, and fills the cache only if the counter is still the same afterwards, so a read that began before a purge can't put purged content back.

- A stale instance, or a lagging replica (below), may still answer the CDN for a moment, which would put purged content back at the edge for a year. So each CDN tag purge (§8.3) is sent again by a durable background job, keyed on the purge's namespace entry, once that bound, the longest replica lag allowed and a hard response deadline have all passed. Compiled validators need none of this: a write re-checks its schemas under their shared locks.

-
**Background jobs** (retention and pruning, epoch rotation, the blob sweep, following remote bases) run once per deployment. A session-level advisory lock in a class of its own elects the instance that runs them, and another takes over if that session ends. It needs a dedicated connection that bypasses any transaction-pooling layer, and the leader checks that it still holds the lock before each step of a job, so a leader that lost its session stops. Job steps are idempotent, since a step may still be under way when that happens.

-
**Rate buckets** (§6.6) are per instance and approximate, each instance enforcing its share of the limits, unless a shared counter is available, e.g. in Redis.

-
**Replicas.** The CDN is the read tier, so replicas matter little. Serve head pointers from the primary, or from a replica that has replayed at least the revision a client presents (`X-Namespace-Revision`, §7.2). Immutable reads may use any replica. One that doesn't have the id yet asks the primary instead of answering `404`, because a cached `404` would hide a revision that exists.

-
**Throughput: one flush per write, per namespace.** The log lock is held through commit, so each write's WAL flush happens inside it, and a namespace takes about 1 / (log append + flush) writes a second. At 0.5–2 ms per flush, that is about 500–2,000 single writes a second per namespace; everything before the append runs in parallel. The bound comes from the chain itself, since each entry names the one before it; releasing the lock earlier would only turn the waiting into `UNIQUE (ns, prev_seq)` retries. Group commit combines flushes of different namespaces, so the database as a whole scales further. Past the bound, use batches (§7.5), which put many entries under one flush. Don't turn off `synchronous_commit`: an acknowledged write could then vanish in a crash.

-
**Contention.** Without more, throughput in one namespace peaks and then falls as writers are added: in one implementation, about 800 writes a second at peak, and about 300 with more than 8 concurrent writers and the CPU idle. Waiters queue on the log lock, and each hand-over costs a wake-up on top of the flush. Two remedies, which combine:

-
**Group commit per namespace.** An instance queues its checked resource writes and batches per namespace, never config, purge, prune or branch writes, nor batches that change the configuration, and one transaction commits several of them, with the outcome each would have had under its own savepoint: each gets its own namespace entry, chained in queue order. Concurrent writes have no order the spec requires.

  - **Statements, not savepoints.** Per-write savepoints cost a dozen sequential statements each and can be slower than no grouping. Instead, the group inserts every write's revision rows first, sorted by resource, one statement per table, before taking the log lock, and re-checks under the shared namespace locks. Then, under the log lock, it reads the namespace head, computes the entries' ids in queue order (§3.5), and inserts the namespace entries and their `head_history` rows (D.2), which reference them, and commits. Only those are written under the log lock, as on the single-write path; writing anything else there lets groups on different instances deadlock with each other and with single writes.

  - **Answered alone.** A write that conflicts with an earlier write of its group (the same resource), or that finds the configuration changed, leaves the group and takes the single-write path after the group commits: the idempotent-retry answer (§7.2), a `412`, or a fresh check against the new configuration. It draws no rate tokens again. A write that loses an insert race leaves the group and is answered alone, and the group runs again without it, a few times at most; an error the group can't retry is answered by running each write alone, so one write's failure doesn't refuse the others.

  - **Grants.** Each entry records the grant of its own request (§7.4), even when one principal has several writes in a group under different keys.

  - **Cancellation.** One request's cancellation doesn't abort its group; the group is cancelled only if all its requests are.

  - **When to group.** Queued writes are checked outside the lock, which costs a read transaction that a check inside the lock (D.3) saves. So group only under contention: while no group is active, a few writes per namespace at a time take the check-inside path, and the rest queue.

Throughput then grows with load, up to about the group size / (per-group statements + flush).

-
**One writer per namespace.** Route each namespace's writes to one instance, e.g. by hashing its name, so the groups aren't split between instances that contend for the same lock. That instance then enforces the namespace's and its resources' whole rate limits (§6.6), not a share of them. Per-principal limits span namespaces, so they still need a shared counter, or are split between instances.

Expect a curve that rises to the single-write bound, then stays flat with group commit, rather than falling.

-
**Sizing (estimate, not measured).** Expect roughly 450–500 B per revision against D.5's 334 B: Postgres adds a 23-byte header plus alignment to every row, and only compresses values over about 2 KB, so small patch sets stay uncompressed. Port `bench/storage.ts` before relying on this.

-
**Partitioning** is optional and only for large deployments: hash-partition `revisions`, `patch_sets`, `ns_log` and `head_history` by namespace. Unique keys must then include the partition key, so those tables gain an `ns` column.

---

# Addendum E — Encryption (optional)

Encryption is defined by **who is trusted with plaintext**. Each level trades features for confidentiality:

| Level | Who can read plaintext | What keeps working | Main use |
|---|---|---|---|
| **E1 · At rest** | origin | everything | protects disks, backups, database dumps |
| **E2 · Sealed for delivery** | origin + key holders | everything, **plus** public caching of private content | private content that must scale through the CDN |
| **E3 · End-to-end** | key holders only | ordering, preconditions, ids, verb-level grants | content the operator must not be able to read |

The levels are per namespace and cumulative in intent: E3 includes E2's delivery format. A namespace declares its level in its namespace document: `"encryption": { "level": "at-rest" | "sealed" | "e2e", … }`.

## E.1 At rest

- **What it is.** The origin encrypts stored patches, snapshots and grants with keys from a key management service, e.g. SQLite page-level encryption or a per-row AEAD.

- **What it doesn't change.** The protocol, ids, caching and every other part of this spec are unaffected. It protects storage media and backups, not the CDN or readers.

- **Purge becomes cryptographic.** With a key per resource, purging destroys the key, which also makes backups unreadable.

## E.2 Sealed for delivery

The origin keeps plaintext, so validation, rules, `writes`, idempotent retry, consumers and the catalog all work unchanged. Everything that leaves the origin for a sealed namespace is **encrypted**. The CDN and every cache in between then hold only ciphertext, and can cache it **publicly**. Keys, not edge grants, decide who can read.

### E.2.1 Keys

- **Epoch keys.** The namespace has a sequence of **epoch keys** `K_e` (256-bit random), each identified by `kid = "{ns}#{e}"`.

- The current epoch is recorded in the namespace document: `encryption.epoch`.

- Key material is never in the document or the log. The origin holds it, backed by a KMS.

- **Per-resource keys** are derived one way:
```
K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name)
```

A holder of `K_r` can decrypt that resource's revisions of epoch `e` and nothing else. It cannot recover `K_e`.

- **Rotation.** A config write that increments `encryption.epoch` starts a new epoch, and it is recorded in the namespace chain. Like any write to `/encryption`, it needs a `*` key (§7.4), so scheduled rotation runs as an operator service.

- Revisions written from then on are sealed under the new epoch.

- **Old revisions keep their old epoch forever.** Their URLs are immutable, and so are their cached bytes.

- **Rotation schedule.** Rotate on a schedule (e.g. daily) and whenever read access is revoked.

### E.2.2 Sealed representation

Responses for sealed namespaces use `Content-Type: application/jose` and a JWE (RFC 7516) in compact serialization:

- **Algorithms:** `alg: "dir"` and `enc: "A256GCM"`, both supported by WebCrypto in every browser.

- **Protected header:** `{ "alg": "dir", "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "id", "kind" } }`.

- The `pl` claims are integrity-protected as AAD, so a ciphertext can't be replayed under another resource, revision or epoch.

- For a grant (§C.3.1), `pl` carries `{ "ns", "grant": gid }`.

- For namespace log ranges, `pl` carries `{ "ns", "range": [since, last] }`, the bounds of the page actually served (§7.1), or `[since, id]` for an empty page. Resource log ranges are sealed entry by entry, each with its own `pl.id`, so their pages chain from `since` to `X-Log-Next`.

- **What gets sealed:**

- `/rev/{id}` documents

- `/rev/{id}/log` entries (patches, author, `via`, grant, signature)

- namespace documents

- namespace log ranges

- grants (§C.3.1)

- event payloads

- blobs, in a binary form (below)

- **What stays in the clear:**

- URLs, and therefore names and ids

- status codes

- `ETag`, `X-Revision`, `X-Config-Revision`

- sizes and timing

- **Stored once, served forever.** Sealed bytes for a revision, a document, a resource log entry or a grant are produced once, stored, and served identically forever, so ETags, `304`s and caching are unchanged. Namespace log ranges (§7.4) are the exception: one range per `since` would store a page for every entry, so a deployment MAY keep only some, oldest evicted first, and seal an evicted range again on request, with fresh bytes, under the epoch key and `pad` setting current then. The plaintext is the same except for fields a later version has added (below), so readers accept either copy and MUST NOT rely on one; a range's `ETag`, if it has one, is weak. Fields a later version adds to what is sealed, such as `grant` in log entries (§7.4), are absent from bytes sealed before; readers accept both. In sealed namespaces, grants recovered for entries written before v0.37 (§7.4) are therefore missing from bytes sealed before, and from a range sealed again only if the server still lacks them; they don't count in the janitor's checks (§F.6).

- **Compression.** Compress **before** sealing, and only within a single revision's own content. Log ranges seal each entry separately, so content from different authors is never compressed together (the CRIME/BREACH class of attack).

- **Padding (optional).** A namespace MAY set `"pad": true` in its `encryption` object. Then every JWE sealed for it, by the server at E2 and by clients at E3 (§E.3.1), pads its plaintext to a size bucket before encryption:

- **Format.** The plaintext is the UTF-8 JSON that would otherwise be sealed, followed by ASCII spaces (`0x20`) up to the padded length. Trailing whitespace is valid JSON, so readers need nothing new. A blob is padded with zero bytes instead, inside its sealed form (below).

- **Buckets.** For a plaintext of `L` bytes, the padded length is `max(256, padmé(L))`, where `E = ⌊log₂ L⌋`, `S = ⌊log₂ E⌋ + 1`, and `padmé(L)` rounds `L` up to a multiple of `2^(E − S)`. The overhead is at most 12%, and a size reveals only about `log₂ log₂ L` bits.

- **No compression.** Padded payloads are never compressed and carry no `zip` header, since a compression ratio leaks the content that padding is meant to hide.

- **Scope.** Each JWE is padded as a whole, including every JWE of a log range. Turning `pad` on or off affects only what is sealed afterwards: stored sealed bytes are served unchanged forever, and a log range sealed again after eviction (above) is padded as the namespace says then.

- **At E3** ids are over ciphertext, so padding is part of what is hashed, and a retry reuses the exact ciphertext. The server can't check padding there. Readers with keys SHOULD flag a patch set that isn't padded to its bucket when the namespace had `pad` on at that revision, like a failed validation (§E.3.2). That is judged by the namespace document in force at the revision's namespace log entry. A batch that changes the configuration judges its items under the configuration before it. Revisions written while `pad` was off are never flagged.

- Padding hides sizes within a bucket. It does not hide counts, timing or the number of revisions (§E.4).

- **Sealed blobs.** A JWE would grow a large blob by a third in base64, so blobs (§7.8) use a binary form, `application/vnd.patchlog.sealed-blob`:
```
"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(plaintext) ‖ tag
plaintext = size ‖ bytes ‖ padding
```

- `len` is the length of `header` as a 4-byte big-endian integer, and `header` is canonical JSON. `iv` is 12 random bytes, and the tag is 16 bytes. The additional data is everything before `iv`, so the header is integrity-protected like a JWE's protected header.

- `size` is the length of `bytes` as an 8-byte big-endian integer, so the ciphertext commits to the true length. `padding` is zero bytes, present only with `pad`, up to the bucket of the whole plaintext. Readers check that it is all zeros.

- **At E2** the header is `{ "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "blob": bid } }`, and the key is the one the resource's revisions of epoch `e` are sealed under (§E.2.1), so per-resource readers can open it.

- **Epochs.** A blob outlives epochs, and a reader may hold only some of them. In a sealed namespace, `…/blob/{bid}` therefore answers `302` (head-pointer caching) to `…/blob/{bid}/e/{e}`, and a reader that holds only older epochs asks for one of those it holds. The epochs served are the epochs of the revisions here whose documents are still stored and reference the blob. A revision's epoch is fixed by its first stored sealing, the first one stored winning as for blobs: when it is written, or, for one read through from a base or written before the namespace was sealed, when it is first served (§E.2.5). A request for a blob none of whose referencing revisions has an epoch yet fixes the newest of them under the current epoch first. So a reader can open a blob under precisely the epochs in which it can read a document that references it. Others are `404`, sent with `no-store`, since a branch may come to serve a read-through revision under a new epoch. An epoch whose referencing revisions were all pruned answers `410` as in §7.1 where the server recorded it when pruning, and `404` otherwise. A branch's stored sealings of a base's blobs are its own copies: pruning in the base doesn't delete them (§8.6), but the branch stops serving them, answers as above, and MAY delete them. `…/blob/{bid}` redirects to the latest served epoch. Each epoch's sealing is produced once and stored, the first one stored winning when two instances seal at once, and only the stored bytes are served, unchanged, with `ETag: "{bid}.{e}"`. Its `Content-Type` is the sealed type: the blob's own type is in its reference. Clients open sealed blobs only in namespaces whose namespace document says they are sealed, or after the epoch redirect, since any namespace may store a file of that type.

- Range requests are served over the sealed bytes, which lets a download resume, but a range can't be decrypted on its own. Media that must stream in ranges belongs in a namespace that isn't sealed, or is split into several blobs.

### E.2.3 Getting keys

```
POST /ns/{ns}/keys
Authorization: Bearer
{ "epochs": [3, 4], "resources": ["derby"] }      // resources only for per-resource grants
```

- **What a grant gets:**

- A grant whose rules fix `/resource` (`readScope: "resource"`) gets **per-resource keys** `K_r`.

- Any other `read` grant gets epoch keys `K_e`.

- **Which epochs:**

- By default, epochs from the grant's first allowed epoch up to the current one. A namespace may cap history with `encryption.historyEpochs`.

- A grant never receives epochs that started after its `exp`.

- **Responses** are `Cache-Control: no-store`, and are wrapped to the caller's public key when the grant carries one (`"enc": { "kty": "OKP", "crv": "X25519", … }` in the root block; HPKE, RFC 9180). This keeps raw keys out of logs and proxies.

- **Consumers** (search, catalog) fetch keys the same way, with their own grants, and seal what they re-publish (§E.2.5).

### E.2.4 Revocation, honestly

- **Future content.** Revoking read access means rotating the epoch. The revoked reader gets no keys for the new epoch, and so can't read anything written afterwards.

- **Past content.** Anything sealed under epochs the reader already held remains readable to them, from their own copies or the CDN's. That is inherent: they could have saved the plaintext anyway.

- **Reducing past exposure:**

- shorter epochs

- per-resource keys via the catalog, so each reader holds only what they were granted

- purge, which removes content and keys (E.1)

### E.2.5 Interaction with the rest of the spec

- **Caching (§9).** Sealed namespaces use the **public** caching rules, including `public` downstream and one-year edge lifetimes. Edge grants become optional: they are needed only if **metadata** (names, sizes, timing) must also be hidden.

- **Ids (§3).** Ids are still computed over plaintext canonical patches. Sealed namespaces MUST refresh `$nonce` in every patch set (§C.7), so plaintext can't be confirmed by guessing from ids.

- **Consumers and addenda.** Search indexes, catalog listings and tree listings over a sealed namespace are served **sealed under that namespace's keys**, with per-resource sealing for per-item listings where needed. So a derived view never leaks what its source hid. §E.2.6 gives the format.

- **Schemas** usually live in a public namespace. A sealed schema namespace works too, but every writer and consumer then needs its keys.

- **Branches (Addendum F)** of a sealed namespace MUST be sealed. At E2 a branch has its own epoch keys, and the server seals read-through content under them like anything else it serves. Read-through revisions, and revisions written before a namespace became sealed, are sealed under the epoch current when they are first served, and keep that epoch. For E3, see §F.8.

### E.2.6 Derived views

This section applies to services that serve views derived from sealed namespaces, such as search results (Addendum A) and tree and catalog listings (Addendum B).

- **Getting keys.** A service reads a sealed namespace like any reader. It holds its own key pair and a grant with `read`, and fetches epoch keys through §E.2.3. At E3, only a service whose public key is a recipient in the namespace's `keyring` can derive anything. Any other service skips the namespace and says so in its status. It MUST NOT index or list ciphertext as if it were content. A service that holds keys is inside the namespace's trust boundary, like any other reader.

- **What gets sealed.** Every value a view derives from a sealed namespace's content is sealed. This covers facets, scores, snippets, titles and `$access`-derived details. What §E.2.2 already leaves in the clear stays in the clear: names, ids, URLs and heads, as well as the view's own structure, `at`, `ns`, order and pagination cursors.

- **Whole-response sealing.** When every sealed value in a response comes from one namespace, and the reader may read that whole namespace (or it is public), the service MAY serve the whole response as one JWE in the §E.2.2 format, sealed under the epoch key `K_e`, with `Content-Type: application/jose` and `pl: { "ns", "view" }`.

- **Per-entry sealing.** Otherwise, including a single-source view for a reader whose grant gives only per-resource keys, the response stays JSON. Each entry (a hit, a child, a node) that carries sealed values replaces them with `"sealed": "<JWE compact>"`. The entry is sealed under the per-resource key `K_r` of the entry's own resource (§E.2.1), with `kid` naming the epoch it was derived from and `pl: { "ns", "name", "view" }`. So a reader with either `K_e` or that `K_r` can open it. A reader decrypts the entries it holds keys for and shows the rest by name only. Folders and placements from a sealed catalog namespace are entries of that namespace. Which form a reader gets depends on its grant, so the two forms are different views and are cached apart (§B.11.5).

- **Aggregates.** Values that combine several resources, such as facet counts, have no entry of their own. They are served only in whole-response form. A service refuses them (`400`) to a reader that would get per-entry sealing.

- **`view`** is the request target, path and query, of the `…/at/{at}/…` URL that the response is served at, exactly as the service's redirect gave it. It binds the ciphertext to one query at one checkpoint, so a result can't be replayed under another query, subject set (§B.11.5) or `at`. Readers MUST compare `pl` with the URL they fetched.

- **Stored once, served forever.** A view at a given `at` is sealed once, under the epoch key current when it is produced, and then served unchanged, like revisions (§E.2.2). Views produced after a rotation use the new epoch. Padding (`pad`) follows the source namespace. Whole-response sealing pads only when every source is padded, and then compression is off as well.

- **Caching** follows §E.2.5: views of sealed namespaces use the public rules, with the tags of §A.4 and §B.5.

- **Local storage.** A queryable index can't be sealed row by row: full-text search, facets and sorting need plaintext. So a service keeps what it derives from a sealed namespace in storage encrypted as the core's is at E1 (§E.1), with keys held outside that storage, such as an encrypted volume or database. Views it has sealed (above) may be stored as they are. A purge of the source, or the destruction of its keys, MUST remove the derived data: rows are deleted and freed pages overwritten, stored sealed views are deleted, and cached keys are forgotten.

- **Queries are metadata.** Query strings are in URLs, so the service, the CDN and anyone who sees the URL learn them, whatever the level (§E.4).

## E.3 End-to-end

The origin never sees plaintext. Clients encrypt patch sets before sending them and decrypt what they read. The server becomes an **ordered, access-controlled log of opaque entries**.

### E.3.1 Wire format

- **Patch sets.** A write's body is `[{ "op": "sealed", "value": "<JWE compact>" }]`: a one-element patch set with a reserved `sealed` op, whose JWE protected header carries `kid` and `pl: { ns, name, parent }`.

- **Ids.** The server hashes it like any patch set (§3.3), so ids are **over ciphertext**.

- **Retries.** A client MUST keep the exact ciphertext until the write is acknowledged, so that a retry reproduces the same id (§7.2).

- **Namespace documents stay plaintext.** The server must be able to read keys, rules and limits.

- **Blobs.** A client encrypts each blob under a fresh random 256-bit key of its own, in the sealed-blob form of §E.2.2 with the header `{ "enc": "A256GCM" }`, and uploads the result with `Content-Type: application/vnd.patchlog.sealed-blob`. The blob id is therefore over ciphertext, and needs no nonce. The key goes into the reference, inside the sealed document:
```
{ "$blob": "1m4…", "type": "application/vnd.patchlog.sealed-blob", "size": 1843363,
  "sealed": { "key": "", "type": "image/jpeg", "size": 1843302 } }
```

`sealed.type` and `sealed.size` describe the plaintext. Whoever can read the document can read the blob, and nobody else can. With `pad`, the plaintext is padded with zero bytes before encryption (§E.2.2).

- **Declared blobs.** The server can't see references at E3, so the `sealed` op lists, in plaintext, the id of every blob the resulting document references: `[{ "op": "sealed", "value": "<JWE compact>", "blobs": ["1m4…"] }]`. Writers omit the member when the list is empty, and otherwise sort it by the ids' binary form (§3.2). Ids at E3 are over ciphertext with a random IV and differ on every sealing anyway, so the server accepts an empty list either omitted or as `[]`, in any order, and readers compare lists as sets. A list with duplicates is `422` (`code: "blob"`), and so is a declared blob whose type isn't the sealed type, so a batch's `source` can't bring a plaintext blob in. A restore with `[]` keeps the list of the last live document, and a sealed empty set that keeps a document unchanged (§F.3) repeats its list. The list is part of the hashed patch set, and the server keeps it with the revision's skeleton after pruning, so it knows what kept documents reference. Its length is checked against `blobsPerDocument`. The server checks that the blobs are available (§7.8), and uses the lists for unreferenced blobs, pruning, purge and bundles. Readers MUST compare the list with the decrypted document, and flag a revision whose list differs, like a failed validation (§E.3.2). A prune's sealed `snapshot` needs no list (§8.6): the server keeps the declared list of every revision, including the one whose document the snapshot is.

- **Merges keep blobs.** A blob's key travels inside the document, not under the namespace's keys. Re-sealing a patch set for another namespace (§F.8.1) therefore leaves its references unchanged, and the blob's ciphertext and id with them.

- **Padding.** In a namespace with `pad`, clients pad the plaintext of every sealed patch set as in §E.2.2, before encrypting.

### E.3.2 What the server can and cannot do

| Feature | E3 |
|---|---|
| Ordering, `If-Match`, `412`, idempotent retry | ✅ |
| Ids, chain verification | ✅ over ciphertext |
| Grants and roles on verbs, `/resource`, `/action`, `/now` and the principal | ✅ |
| `$schema` validation | ❌ moves to clients |
| Rules on `/doc` (including role rules), `writes` path policy | ❌ the server cannot see paths, so such rules make resource writes fail (§6.2) |
| Search, catalog `$access`, derived listings | only in services that hold keys |
| Public caching of content | ✅ (ciphertext) |
| Limits on documents (`documentSize`, `valueSize`, `pathSize`, `nestingDepth`) | ❌ checked by clients (`blobsPerDocument` by the server, on the declared list) |
| Blob references | declared in plaintext by writers, verified by readers (§E.3.1) |

- **Validation moves to clients.**

- Every client MUST validate the decrypted document against its `$schema` before writing, and SHOULD verify it on read, leaving out the same members as the server (§6.2 step 5).

- A revision that fails validation on read is **flagged**, and its author, recorded by the server as usual, is accountable. It is not silently applied.

- Invariant 3 becomes a property checked by readers rather than enforced by the gate.

- **Path-level permissions** (e.g. translators only touching `/i18n`) need a separate resource per permission boundary, since the server can't see inside a patch.

- **Keys.** Key distribution uses §E.2.3 with one difference: the server only relays **wrapped** keys.

- Epoch keys are wrapped per recipient public key (HPKE) by a key-holding admin client, and stored as a `keyring` resource in the namespace.

- Adding a reader means wrapping the current epoch key for them. Revoking means rotating the epoch and re-wrapping for the remaining readers, done by a key holder, never by the server.

## E.4 Metadata that no level hides

- **What remains visible:**

- resource and namespace names (they are in URLs)

- ids and parent links

- sizes

- edit timing

- author identities and the grants they wrote with (recorded by the server, §7.4; at E3 served in the clear to readers, §C.3.1)

- the shape of the namespace log

- gesture ids, which group edits into user actions (§7.2). At E2 they are sealed with log entries; at E3 the server sees them, so clients that must hide the grouping keep it inside their sealed content instead

- query strings of derived views (§E.2.6)

- blob sizes and counts; at E3, which revisions reference which blobs; at E2, which epochs a blob is served under

- whether a blob carried over without a nonce matches a guess (§C.7)

- **Mitigations:**

- opaque names (e.g. random slugs) in sensitive namespaces

- padding sealed payloads to size buckets (`pad`, §E.2.2)

- edge grants to hide existence from non-readers

- accept that the operator of E3 still sees who writes when

## E.5 Open questions

- Should E2 epoch keys be per namespace (simple) or per catalog folder (finer revocation, more keys)?

- Should E3 allow clients to reveal a **plaintext `writes` list** alongside the sealed patch set? The server could then enforce path policy on the claim, with readers verifying it matches the decrypted patches.

- Should key custody for E2 use an external KMS interface in the core, or stay an implementation detail (Addendum D)?

---

# Addendum F — Branches, merge and rebase (suggested)

The core provides branches (§7.6), atomic batches (§7.5), and namespace freeze and purge (§8.4–8.5). This addendum describes how to use them for drafts, releases, previews and reviewed changes. **Merge and rebase are procedures built from core requests, not server operations.** Clients or a merge service (§F.7) carry them out, and the core never rewrites history.

## F.1 Model

```
matches      ──●──────●──────●────────────────◆  batch, source: release-7
                 \ at                         ↑
release-7         └── derby′ ── cup′ ── +final ┘
                  (everything else is matches as of `at`)
```

-
**A branch is a fixed snapshot of its base plus its own changes.** Its `base` never changes. A resource the branch hasn't touched reads through; the first write gives it its own chain, starting at a foreign parent.

-
**A branch is an ordinary namespace.** It has URLs, caching, rules, keys, consumers and an event stream, and every tool that works on a namespace works on it.

-
**Uses:**

| Use | How |
|---|---|
| Drafts and review | Authors write in a branch, an editor merges |
| Releases | Prepare many documents, publish them as one batch per namespace, possibly at a set time (§F.9 for releases across namespaces) |
| Schema migrations | Write the new schema revision to the schema namespace first, or draft it in a branch of the schema namespace (§6.1, §F.9). Migrate the documents in a branch, then merge them as one batch whose config change updates the rule that allows the new `$schema` |
| Previews | Point a preview site at the branch |
| Proposals from services | A plug-in service writes to a branch instead of the base (§C.6) |
| Private drafts of public content | A branch with `read: "grant"` |
| Catalog reorganisations | Branch a catalog namespace (Addendum B), review, merge the moves in one step |

## F.2 Creating and working in a branch

```
POST /ns/matches/branches
Authorization: Bearer
{ "name": "release-7",
  "patches": [
    { "op": "replace", "path": "/read", "value": "grant" },
    { "op": "add", "path": "/cleanup", "value": { "merged": "P7D", "superseded": "P30D" } } ] }
```

- **Configuration.** The branch starts with a copy of the base's current namespace document (§7.6). Its rules, roles and read mode are then its own, while its keys keep following the base (§C.4).

- **Base policy.** The base's rules see a `branch` envelope whose `resource` is the new name. A base can therefore require, for example, that branches are named `release-…` and are never public.

- **Grants name namespaces explicitly.** A grant for `matches` does not work in `release-7`. Issuers add branches to the grants they issue, typically only for the people working on the branch. For a release that spans several namespaces, they add every branch it lists (§F.9).

- **Editors** need nothing new: load, sync, submit and watch work exactly as in §11.

- **Consumers** that need the whole branch, such as a preview index, learn of it from the `branch` entry in the base's log. They follow it as in §10: the branch's `/heads`, then the branch's log.

- **The base keeps moving.** The branch doesn't see it (invariant 7) until it is rebased (§F.5). Purges are the exception (§8.3).

## F.3 Merge

A merge is **one batch into the base**, built from the branch's changes:

-
**Collect** the resources the branch changed, from its namespace log.

-
**Classify** each resource by **ancestry**, comparing the base's current head `B` with the branch's head `H`. Ids determine documents (§3.3), so ancestry is a question about ids:

| Relation | Batch item |
|---|---|
| `B` = `H` | none: already merged |
| `B` is an ancestor of `H` (including the foreign parent, and "absent in the base" for a resource the branch created) | **fast-forward:** the branch's entries after `B`, with `ifMatch: B` (or `ifNoneMatch: *`). The resulting ids are **identical** to the branch's. (At E3 this is a re-sealed replay instead, §F.8.1.) |
| `H` is an ancestor of `B` | none: the base already has it and more |
| neither | **replay** the branch's entries after their latest common ancestor onto `B`, with new ids. **Always review it:** it conflicts if the two sides' `writes` overlap (see below), or if history it needs was pruned (§8.6), and `test` ops, schemas and rules catch the rest. |
| resource purged in the base | none: report it |

Tombstones are entries like any other, and a `"delete"` step reproduces them (§7.5). Two cases always need a person, however they classify: deleting a document the base has since changed, and changing one the base has since deleted.

-
**Dry run** the batch (`?dry-run=1`) for a per-item report.

-
**Resolve** each conflicting resource by replacing its steps with one resolution set against `B`.

-
**Submit** the batch with `source: { ns: "release-7", at: <the branch's ns_id> }`, where `at` is the branch revision the batch was classified from in step 2, not a later one. It is all or nothing, and consumers see the whole release as one entry. If the base moves meanwhile, the affected items fail with `412`: re-classify those and resubmit.

-
**Freeze the branch** with a config write that also records `"merged": { "at": <the base's ns_id> }`, a convention read by the janitor (§F.6). Alternatively keep working and merge again later: classification by ancestry makes a second merge pick up exactly what is new. After a replayed merge, the replayed ids exist only in the base, so ancestry by ids alone finds no common point. Instead, treat each earlier merge batch from the same branch as a common ancestor: its `source.at` fixes the branch's state, and its entries name the base revisions it produced, so each resource has a known pair (branch revision as of `source.at`, base revision from the batch). A second merge then replays only what the branch changed since.

- Per resource, the pair comes from the most recent such batch that has an entry for it.

- A resource deliberately kept at the base's version is still recorded in the batch with an empty step `[]`, but only when the base's head is a live document. That writes a revision with identical content, so consumers see a head change and nothing different. In sealed namespaces the step is a fresh `$nonce` add (E2, §C.7) or a sealed empty set (E3). Where the base's head is a tombstone or absent, `[]` would restore or fail, so such a resource can't be recorded this way: it stays unmerged and is offered again.

- `source` is asserted, not verified (§7.5), so only batches without `origin`, whose `source.ns` is the branch, whose `source.at` is in the branch's chain, and whose recorded grant (§C.3) has a root `sub` and `kid` listed in the base's `merge.authors`, count. The merger checks the chain itself, as the janitor does (§F.6), since the server checks it only for callers who may read the branch (§7.5). The base declares them in its namespace document, e.g. `"merge": { "authors": [{ "sub": "svc:merge", "kid": "ops-2026" }] }`. A catalog's merge batches are submitted by the merge service under grants the catalog service signs for it (§F.8), so one entry for the merge service and the catalog's merge key covers them; changing `/merge` needs a `*` key (§7.4). Merges by anyone else, such as an editor merging by hand, aren't tracked this way, so a branch merged like that should be rebased (§F.5) before it is merged again. The dry run lists, per resource, which batch and author its pair came from. Rebasing (§F.5) remains an alternative.

- **Blobs.** A merge within the deployment copies nothing: the blobs the branch attached are available to the batch's items through its `source`, and are attached in the base when it commits (§7.8). The merger's grant must therefore also read the branch, or the batch carries one that does in `Source-Authorization`. Blob ids don't depend on where a blob is stored, so fast-forwards still reproduce the branch's ids. A merge from another deployment uploads the blobs first (§G.3). The dry run reports a missing blob as a `blob` failure.

- **Conflicts inside arrays.** `writes` are compared segment by segment, and array indices shift. So `/blocks/0` in the base and `/blocks/3` in the branch don't overlap as pointers, yet replaying the branch's `remove /blocks/3` after the base's insert at 0 removes a different block. For merge and rebase, a write whose last segment addresses an array element (an index or `-`) counts as a write to the whole array.

- **Configuration is never merged implicitly.** The branch's own configuration (read mode, cleanup) stays in the branch. A config change meant for the base, such as a migration rule, goes in the batch's `config` explicitly.

- **Squash** replaces a resource's steps with one set that has the same effect. The base's log stays shorter, but per-set history and `test` ops are lost. Replaying is the default.

- **Authorisation.** The batch is checked in the base, under the merger's grant: the merger needs the base's verbs for every item, and the base's rules apply. Branch authors need no rights in the base at all, so review is structural.

- **Attribution.** Merged revisions, fast-forwarded or replayed, are recorded with the merger as author. The merger MAY carry each source revision's `gesture` and `undoes` in its steps (§7.5), so history views keep their grouping; squashing loses them. The batch's `source` points at the branch revisions, whose authors are recorded there, and audit views show both. Author signatures bind the namespace (§C.3), so they verify against the `source` branch, not the base. In a namespace that requires signatures, the merger signs its own steps (§C.3.1).

## F.4 Stacked branches

- **A branch of a branch** (`B2` based on `release-7`) reads through both, up to the branch depth limit (§6.6).

- **It is never broken by its base moving on.** Its snapshot of `release-7` stays as it was. Namespace purge refuses to remove a base that still has dependents (§8.5).

- **Retargeting after a merge is almost free.** Say `release-7` merged into `matches` by fast-forward. Its revisions then exist in `matches` with the same ids, so `matches`' heads are ancestors of `B2`'s. Rebasing `B2` onto `matches` (§F.5) fast-forwards every resource that nothing else changed, and reproduces `B2`'s ids.

## F.5 Rebase: a successor branch

There is no rebase operation. To bring `release-7` up to date with `matches`:

- **Create** `release-7-b` from `matches` at its current head.

- **Replay** `release-7`'s changes into it with batches carrying `source: { ns: "release-7", at }`, classified by ancestry exactly as in §F.3, but against the new branch. Resources that `matches` didn't change since the old `at` fast-forward and keep the **same ids** as before. At E3 they are re-sealed for the new branch and get new ids (§F.8.1).

- **Resuming.** When replaying resumes, batches in the successor without `origin` whose `source.ns` is the old branch count as earlier merges (§F.3), whoever wrote them, even without `merge.authors`. The successor isn't in use yet, and §F.6 trusts the same batches to decide that a branch was superseded. Without this, a resumed rebase that replayed rather than fast-forwarded (always the case at E3, §F.8.1) would conflict on every resource.

- **Resolve** conflicts, over as many batches and people as it takes. The new branch isn't in use yet, and the old one keeps working meanwhile.

- **Switch** with one config write on the old branch: `"frozen": true, "successor": "release-7-b"`. Then replay whatever the old branch received after step 2.

- **Editors** of the old branch get `409 frozen` with the successor. They reload from it and replay their pending sets, the same loop as a rebase on `412` (§11).

- **No history is rewritten.** The old generation stays readable, so reviewing a rebase is a diff between two namespaces, and every earlier link still works.

- **Previews** follow the `successor` chain.

- **Keeping branches fresh** is a service task: rebase whenever the dry run is clean, and stop and flag the branch for a person on a conflict (§F.7).

## F.6 Lifecycle and cleanup

| State | Namespace | Reversible |
|---|---|---|
| Live | a working branch | — |
| Frozen | merged (`merged`) or superseded (`successor`), readable for review | yes: unfreeze |
| Purged | content gone; ids, logs and configuration kept; name reserved | no |

-
**Cleanup** is plain data in the branch's namespace document, e.g. `"cleanup": { "merged": "P7D", "superseded": "P30D", "abandoned": "P30D" }`. The core doesn't enforce it. (It is unrelated to `retention`, §8.6, which prunes history and doesn't apply in branches.) Without `cleanup`, the janitor never purges the branch.

-
**A janitor service** follows the bases, discovers branches from their `branch` entries, and follows those too. It purges a branch when all of these hold:

- it is frozen, and merged, superseded or abandoned

- its cleanup period has passed, and so have any minimums the base sets in its own `cleanup`

- it has no dependents (leaves are purged first)

The janitor needs `purge-ns` on branches only, never on bases.

-
**The janitor MUST verify claims, not trust them.** `merged`, `successor`, `abandoned` and `cleanup` are fields any config writer of the branch can set. Before purging, it checks:

- **merged:** the base's log has a batch **without `origin`**, by a principal listed in the base's `merge.authors` (§F.3), whose `source.ns` is the branch and whose `source.at` is in the branch's chain, and the branch's log has no `head`, `tombstone` or `batch` entry after `source.at`, so no document changed after the merge. `config` entries (such as the freeze), `prune` entries and propagated purges are allowed.

- **superseded:** the successor exists, isn't purged and has the same base namespace, its log has a batch without `origin` whose `source.ns` is the branch and whose `source.at` is in the branch's chain, and the branch's log has no `head`, `tombstone` or `batch` entry after that `source.at`. So the successor really took over the branch's work.

- **abandoned:** the branch's document has `"abandoned": true`, set by a config write whose recorded grant (§C.3) chains to a `*` key of the branch, inherited or its own. A flag set before v0.37, whose entry records no grant, doesn't count and must be set again. Only its administrators can give up everyone's unmerged work.

- At E3, entries for the branch's `keyring` resource are allowed after `source.at` too, in either check, since the keyring is never merged (§F.8.1). A batch counts only if it has other items.

A branch with no `head`, `tombstone` or `batch` entry of its own counts as merged. Otherwise a co-author with `config` on a branch could get everyone else's unmerged work purged.

## F.7 Merge service (plug-in, optional)

-
**Discovery:** follows bases and picks up new branches from `branch` entries (§10).

-
**Status:** per branch and resource, ahead, behind, clean or conflicting, from `writes` overlap.

-
**Diffs:** branch against base, and generation against generation after a rebase.

-
**Preparation:** builds batches and runs dry runs for a person to approve, with resolution sets for conflicts.

-
**Automation (optional):**

- rebase branches whenever that is clean

- merge at a set time, e.g. an embargoed release

"Clean" means every resource fast-forwards, or replays without overlapping `writes` under the array rule of §F.3. Anything else waits for a person, who sees the replayed result next to the reviewed branch document.

-
**Least privilege:**

- `read` on bases and branches

- `branch` on bases, and writes in branches, for rebases

- write access to a base only if it merges on its own

## F.8 Access, encryption, catalogs and indexes

- **Reads.** A branch is a copy of its base (§7.6). Creating one needs unrestricted `read` on the base, and a branch of a namespace that isn't public can't be public. A namespace with public branches can't become private until they are dealt with (§7.4).

- **Keys and revocation** in a base reach its branches (§C.4). Roles and rules don't: a branch's writes stay in the branch until a merge, which the base's own rules judge.

- **Sealed namespaces (Addendum E).** A branch of a sealed namespace MUST be sealed.

- **E2:** the branch has its own epoch keys, and the server seals read-through content under them (§E.2.5). Ids are over plaintext, so fast-forward merges keep ids.

- **E3:**

  - Read-through content stays the base's ciphertext, readable only with the base's keys as of `at` (its `keyring` is read through too).

  - Sealed patch sets bind their namespace (§E.3.1), so merging and rebasing always decrypt and re-encrypt under the target's keys, in a client that holds both. They never fast-forward.

  - Purging a merged branch then leaves nothing in the base depending on the branch's keys.

- **Catalogs (Addendum B).**

- A catalog namespace can be branched to prepare a reorganisation.

- A catalog service MAY compute preview access from a branch, but MUST issue content grants only from the catalog it follows as the base. Otherwise an unmerged branch could grant access.

- Merging a catalog branch goes through the catalog service. It checks every move and placement in the batch as in §B.11.4, including no widening, and issues one grant covering exactly that batch: its rules allow exactly the batch's pairs of `/resource` and `/action`, and it expires within minutes. It can't fix the documents or the batch's `source` themselves, since a fast-forward passes through intermediate states and `source` isn't in the envelope (§6.4.1). So the catalog service signs merge grants with a key used for nothing else, only for the merge service (root `sub` the merge service's, `attrs.approvedBy` the person who approved the plan), and hands them to nobody else. The merge service submits exactly the batch that was checked. The catalog base lists that pair of `sub` and `kid` in `merge.authors` (§F.3).

- Changes to `$access` need `catalog-admins` (§B.11.3), which the catalog key may never assert. A catalog batch that changes `$access` is therefore checked by the catalog service in a dry run and submitted under the grant of a person in `catalog-admins`, through the merge service, which adds a narrowing block with its own `via` (§C.1). The catalog base lists each such admin in `merge.authors`, so the batch counts as a merge; admins are trusted with that.

- A catalog branch in a release previews against the release's content branches (§B.5), and is merged in two batches around the content (§F.9).

- **Indexes (Addendum A).** Search over a branch is a separate preview index built as in §10 (branches). The main index follows only the base.

### F.8.1 Merging and rebasing at E3

The server can't read patches at E3, so a merge (§F.3) or a rebase (§F.5) is carried out by a client that holds keys, such as the merge service (§F.7). The batch it submits is an ordinary batch, sealed for the target.

-
**Keys.** The merger needs to read the branch and to write the target:

- for reading, the branch's own epochs, plus the base's epochs up to the branch's `at` for read-through content;

- for writing, the target's current epoch key.

A `kid` `{ns}#{e}` names the namespace whose `keyring` holds its key. Read-through content in a branch keeps the base's ciphertext and `kid`. A client asks the namespace it is reading for keys first: `POST /ns/{branch}/keys` relays the entries of keyrings the branch reads through, including a remote branch's mirrored keyring, whose base doesn't exist on that server (§G.5.2). It asks the `kid`'s namespace only if that fails. The branch's own writes carry the branch's `kid`s, and a branch's `keyring` is never merged.

-
**Classification** is by ancestry over ids, exactly as in §F.3. Ids are over ciphertext, and that is enough: read-through content keeps the base's ids, and a branch's first entry names the base's id as its foreign parent. Two rows of the table change:

- **`B` is an ancestor of `H`**: a **re-sealed replay** rather than a fast-forward. The branch's entries after `B` are re-sealed onto `B` in order. The base hasn't changed the resource, so no conflict check is needed, but the ids are new.

- **Neither**: a replay with the conflict check, as in §F.3.

There are never fast-forwards at E3, even between namespaces with the same keys, because each sealed patch set binds its namespace and parent (§E.3.1).

-
**Re-sealing an entry.** The merger decrypts the patch set and checks its `pl` against where it was read: the branch (or the base, for read-through content), the resource, and the entry's parent. It then seals the same plaintext patches under the target's current epoch, with a fresh IV and `pl: { ns: target, name, parent }`. Here `parent` is `B` for the first entry, and after that the id the previous entry of the same item produces. The merger computes each new id itself (§3.3, over the sealed patch set), so it can seal a whole chain before submitting. The target's `pad` applies (§E.2.2). A tombstone has no patches and needs no sealing: its id follows from its new parent (§3.4).

-
**Blobs** keep their ciphertext and ids, since their keys travel in the re-sealed patches (§E.3.1), and are available through the batch's `source` like any merge's (§7.8). Each re-sealed op keeps its `blobs` list.

-
**Conflicts** are found by the merger. It computes `writes` from the decrypted patch sets and compares them as in §F.3, including the rule for arrays. The server's dry run can only check preconditions, verbs and limits.

-
**Validation.** Before submitting, the merger folds every item and validates each resulting document against its `$schema` (§E.3.2), resolved as the target's gate would resolve it (§6.1): only in the schema namespaces themselves when the target isn't a branch. A document that fails is a conflict for a person, reported with kind `invalid` next to the overlap conflicts. A resource kept at the base's version is recorded with a sealed empty set (§F.3).

-
**Retries.** The merger keeps the sealed batch byte for byte until it is acknowledged, so a retry reproduces the same ids (§E.3.1). Re-classifying after a `412`, or changing a resolution, seals the affected items again, and they get new ids.

-
**Later merges and the janitor.** Every E3 merge is a replay, so a second merge finds its common ancestors in earlier merge batches by `merge.authors` (§F.3). Those, like the janitor's `merged` and `superseded` checks (§F.6), use only namespace logs, `source` and `merge.authors`, which stay plaintext at E3, so the janitor needs no keys. Without such a batch, for instance when the base lists no `merge.authors`, a merger MAY count a resource as merged when the target's head document equals the branch's head document, compared as decrypted plaintext. Every other resource the branch changed conflicts, and rebasing (§F.5) is the way forward.

-
**Rebases** (§F.5) re-seal in the same way, with the successor as the target. Only read-through content keeps its ids. Remote branches (§G.5.2) are merged in the same way, with the target's keys.

-
After a merge, nothing in the target depends on the branch's keys, so purging the branch, or destroying its keys, loses nothing that was merged.

## F.9 Releases across namespaces

A release often spans several namespaces: new documents in `matches`, their placements in a catalog namespace `cat-season` (Addendum B), and perhaps a new schema revision in `schemas`. Each is branched as usual, and the branches are listed together in a **release document**: an ordinary resource that tools read, and the core never does.

```
// /r/releases/release-7
{ "name": "release-7",
  "at": "1c…",                                   // optional: combined checkpoint the branches started from (§B.5)
  "branches": { "matches":    { "ns": "matches-r7",    "at": "1k…" },
                "cat-season": { "ns": "cat-season-r7", "at": "1m…" },
                "schemas":    { "ns": "schemas-r7",    "at": "1d…" } },
  "on": "/r/releases/release-6/rev/1x…",          // optional: the release this one builds on
  "owners": ["user:anna"] }
```

-
**Where it lives.** Release documents live in a namespace whose rules decide who may create and change them, and can, for example, forbid changing `branches` once a merge has started. A release document only says which branches go together: every tool that acts on it checks for itself, under its own authority, what it is about to do.

-
**Starting.** Each branch's own `at` is authoritative; the document's `at` is optional, and is dropped after a rebase. The branches SHOULD start at heads that were current together, such as the `ns_id`s in a catalog service's combined checkpoint (§B.5), so the preview shows content and catalog as they were at one moment.

-
**Documents keep naming the bases.** Placements say `matches.final`, `x-ref`s say `/r/matches/…`, and `$schema` says `/r/schemas/…`, never the branch names. Nothing is rewritten when the branches merge, and a fast-forward still reproduces every id.

-
**Schemas.** Draft schema revisions are written in the release's branch of the schema namespace, and documents in the release's other branches resolve them by their base paths (§6.1). No namespace name is special: a namespace that keeps its schemas next to its content drafts them in its own branch, which is then all a release needs. A separate draft branch serves only itself until it lists the release's other branches in `drafts.for` (§7.4).

-
**Reading.** Previews and tree services follow the listed branches in place of their bases (§B.5), and show each viewer only branches the viewer can read. Items in a content branch the viewer can't read are hidden, not shown from the base, and a viewer who can't read the catalog branch gets `403`. Grant issuers add every listed branch (§F.2).

-
**Merging** is one batch per branch. Namespaces stay the unit of atomicity (§1), so the release as a whole isn't atomic. Before approval, the merge service checks that each listed branch's `base` chain reaches the listed base and that the branch isn't frozen or purged; on resuming, it accepts the freeze its own approval made. It records the release document's revision in its plan, and a person approves the plan's **digest**: `text(trunc160(sha256(canonical(plan))))`, over the release revision and, per step, every item with its precondition and its steps as plaintext, with `$nonce` values left out, before any sealing. Resulting ids are left out too, and a precondition on the result of an earlier step is written as that step and item, not as an id, so fresh nonces and re-sealing at E2 and E3 don't change the digest. Approval fails if planning again doesn't give the same digest, and approving freezes every listed branch (§8.4), so no new drafts or references arrive mid-merge; unfreezing one invalidates the plan. Each step is classified again, with a dry run, right before it is submitted, and stops for a new approval if it differs from the approved plan. It orders the batches so that each state in between is safe:

- **Schemas, by fast-forward only,** in `$ref` order. A schema resource is one whose documents are schemas, with a dialect URL as `$schema` (§6.1). Its tombstones and restores fast-forward like any entry, and revisions of a tombstoned schema resource still resolve (§6.1). Then `$schema` paths resolve in the bases too. A schema resource the base changed since `at` can't fast-forward, and replaying it would give new ids that no document references. That is a conflict: rebase (below), and migrate the documents to the new revision with `replace /$schema` (§6.3). A branch that holds both schemas and content merges its schema resources here and its content in step 3.

- **Catalog changes that narrow access.** A change goes here when, for every subject, the effective roles on every node afterwards are a subset of those before, judged by the test of §B.11.4 on the step-2 batch as a whole, whoever merges, `catalog-admins` included. That covers unplacing, moves into more restricted folders and `$access` edits that remove roles. A folder the release creates goes here, with its own `$access`, when a narrowing move needs it. An empty folder gives access to nothing but its title and its tree powers, so the subset test applies to the items moved into it, not to the folder itself. Its title, and the powers its `$access` gives, take effect from then on.

- **Content branches,** in any order. New documents aren't placed yet, so catalog listings don't show them, and catalog roles grant nothing on them.

- **Catalog changes that widen access:** new placements, and the remaining moves and `$access` edits. This step publishes the release.

Before submitting anything, the merge service reports these as conflicts for a person:

- a catalog node whose change narrows access for some subjects and widens it for others. It is resolved with two resolution sets (§F.3), one narrowing for step 2 and one widening for step 4.

- a content item that step 3 creates or restores and that a placement in the catalog base already names, which step 3 would publish under that placement. It is fine if step 2 removes that placement, or if the release keeps it unchanged and its approver accepts that; any other change to it is a conflict.

- a pinned `x-ref` (§6.5) or manifest entry (§B.4) naming a revision of another listed branch that the merge replays rather than fast-forwards, which would dangle. At E3 every merge replays (§F.8.1), so pinned references between branches of an E3 release must be rewritten after the merge.

- a document resolving a draft in a branch the release doesn't list, which ties this release to another one.

The merge service stores the whole plan, both halves of every split node included, before it submits step 2, and a merge that stops part-way resumes from that plan. Each batch carries its own `source`, so steps not yet submitted can still be classified again (§F.3). Catalog batches are submitted by the merge service under grants the catalog service signs for it, or, where they change `$access`, by a catalog admin (§F.8); the catalog base lists both in `merge.authors`. A split node's step-2 batch records a pair for it, but the step-4 batch is more recent and replaces that pair (§F.3), and until then the stored plan, not classification, decides what is left. A merge service resumes and never reverts. Every branch records `merged` only after step 4, with `at` the target's `ns_id` after the last batch into it: for the catalog, after step 4.

- **Exposure between steps.** Step 1 makes the schema drafts visible to readers of the schema namespace. Step 3 makes new documents visible to anyone who reads the content namespace directly: by URL in a public namespace, and to namespace-wide readers and consumers such as search indexes. Where that matters, keep the content private and read it through the catalog, or keep catalog and content in one namespace (§B.8, §B.9), where one branch suffices.

-
**Several releases.**

- Releases on the same bases merge one at a time. Steps 2 and 4 are classified against the base as it is, and another release's catalog changes in between can turn a narrowing move into a widening one without touching the moved node, so preconditions wouldn't catch it. The merge service merges one release per catalog base at a time, for instance with a lock resource per catalog base in the release namespace, such as `merge-lock.cat-season`, whose document names its holder: taking it is an append with `If-Match` that sets the holder when there is none, and releasing it is an append that clears it. A merge service resuming from a stored plan takes over the lock that plan holds, and classifies each step again, with a dry run, right before submitting it.

- Two drafts of the same schema resource in different releases both start from its head, so only the first merged fast-forwards. The other release is rebased onto it, and its documents move to a revision that has both changes. Larger schema changes avoid this by going into a new schema resource. Since schema revisions are harmless until referenced, a release may also merge its step 1 early, accepting that the drafts become visible.

- A release built on another one branches that release's branches and names it in `on`. Its `branches` are still keyed by the namespaces paths name, and each listed branch's `base` chain must reach the branch of the earlier release it is merged into. Its documents resolve drafts from both, since branches of branches are candidates too (§6.1), as long as the earlier release's draft branches list the earlier release's branches in `drafts.for`, since their branches are served too.

-
**Rebasing** a release creates a successor of each branch (§F.5) and lists them in a new revision of the release document. The schema successor is created with `drafts.for` naming the other successors, in its creation `patches`, and is replayed first, so the others' documents resolve as they are replayed. A draft that has to be replayed gets a new id, and older entries naming the old one can't be replayed into the successors. So a resource whose entries reference such a draft is squashed (§F.3): one resolution set against its new base, reaching the branch's document with `$schema` moved to the new revision.

-
**Cleanup.** The janitor (§F.6) purges each branch as usual. A draft branch can't be purged while documents rely on its last copy of a revision (§6.1), so the janitor purges the release's other branches first. The release document only orders this, and never authorises a purge.

-
**Abandoning** a release before step 1 leaves nothing in the bases. After step 1, the merged schema revisions stay in the schema namespace's history, unused. Its branches are frozen with `abandoned: true` by an administrator, and the janitor then cleans them up (§F.6).

## F.10 Open questions

- Should grants have a form covering a namespace **and its branches**, or all the branches of a release, e.g. `ns: ["matches/*"]`?

- Releases with branches in several deployments, and exporting documents that reference drafts (§G.3, §G.4).

- Should there be a stable alias that follows `successor` chains, for previews and bookmarks?

- Should the server verify that a batch's items correspond to its `source` (§13)?

- Should the server offer three-way diffs, or leave them to the merge service?

---

# Addendum G — Federation and portability (suggested)

Ids are hashes of content, never of location, so the same history has the same ids in every deployment. This addendum uses that to move content between deployments, whether staging and production, a partner's servers, an offline site or a new operator:

- **External consumers** read another deployment's namespaces (§G.2).

- **Remote branches** read a snapshot and send changes back (§G.3).

- **Bundles** carry documents in a file, with or without their history (§G.4).

**What it adds to the core:**

- the remote form of `base` (§7.6)

- `remote` branch entries (§3.5)

- the `export` verb (§C.1)

- `origin` in batch sources (§3.5) and in author signatures (§C.3)

- the `x-ref` annotation (§6.5)

- the `name_conflict` error

Remote read-through runs in the receiving deployment's server. Export and import are separate tools using the public API.

## G.1 Principles

- **Every deployment has one canonical origin.** It is published at `GET /` as `{ "origin": "https://cms.example", "spec": "0.43", "auth": "grants", "jwks_uri": "https://cms.example/.well-known/patchlog-keys" }`, in the form of §C.3, next to the spec version the core publishes there (§7.4).

- **Ids travel, trust doesn't.** Content that comes **with its history** can be verified by anyone by recomputing ids (invariant 4), given a trusted starting point: an `ns_id` or revision id obtained from the source itself. Integrity then needs no trusted transport, cache or mirror. Snapshots, headers and listings not covered by ids are only as trustworthy as their channel.

- **A deployment boundary is a trust boundary.** Each deployment applies its own grants, rules and schemas at its own gate. Nothing arriving from elsewhere bypasses them.

- **Nothing is atomic across deployments,** just as nothing is atomic across namespaces (§1, §7.5).

- **Copies can't be recalled.** Once content is in another operator's hands, a purge there is a request, not a guarantee. Treat any read grant for a private namespace as disclosure.

- **Names are stable across environments.** `$schema` and pinned references are paths that contain namespace and resource names (§6.1, §6.5). Renaming would change documents and therefore ids. Keep names the same everywhere, and let the origin say which environment it is.

| Guarantee | Within a deployment | Across deployments |
|---|---|---|
| Ids and verification | ✅ | ✅ identical, for content with history |
| Fast-forward merges keep ids | ✅ | ✅, except E3 across differently named namespaces (§F.8) |
| Batch atomicity | per namespace | per namespace, on the receiving side |
| Keys and revocations follow the base | ✅ (§C.4) | ❌ each side has its own |
| Purges propagate to branches | ✅ (§8.3) | notices only (§G.3) |
| Base can freeze or purge its branches | ✅ | ❌ |
| Dependents block a namespace purge | ✅ (§8.5) | ❌ |

## G.2 External consumers

A consumer in another network or organisation works exactly as in §10, with three additions:

- **Checkpoint.** It stores `(origin, ns, ns_id)`, so a consumer following several deployments never mixes them up.

- **Verification.**

- Revisions are verified through their log (`/r/{ns}/{name}/rev/{id}/log`), by recomputing ids back to a revision already verified.

- The namespace chain is verified entry by entry from the checkpoint.

- A consumer SHOULD verify, and MUST when it fetches through a cache or mirror it doesn't control.

- Below a pruning horizon, verification needs the archive, or a revision at or after the horizon that was already verified (§8.6).

- **Access.** Public namespaces need nothing. Private ones need a `read` grant from the source deployment, and the consumer's storage then holds a copy (§G.1).

## G.3 Remote branches

A branch on deployment B whose base is a namespace on deployment A:

```
"base": { "origin": "https://cms.example", "ns": "matches", "at": "1k…" }
```

-
**Creating one.** A remote branch is a new namespace on B and is created as §C.4 bootstrapping requires, with B's deployment operator key: `PATCH /ns/{name}` with `If-None-Match: *` and a genesis that sets the remote `base`.

- Its namespace document is B's own. Nothing is copied from A's configuration, although tooling MAY copy A's `roles` as a starting point.

- No entry is written to any local chain, since the base's chain is on A.

- `at` comes from A: B takes it from A's namespace head and verifies A's namespace log up to it.

-
**Schemas, at creation.** `$schema` paths resolve on B's own server. So at creation, B:

- reads A's `/ns/{ns}/rev/{at}/heads` once

- collects the `$schema` and `$ref` closure of every resource

- mirrors each schema resource's history, up to the referenced revisions (if any of them doesn't resolve in its namespace itself, as with drafts in a branch, §6.1, creation fails with `422`, `code: "schema_unavailable"`), into the namespace of the same name on B, created if missing, since `$schema` paths contain the namespace name. It must not be a branch.

The ids prove the copies exact. If B already has a resource at one of those paths whose chain neither contains A's nor is a prefix of it, creation fails with `409 name_conflict`. Pinned `x-ref`s in read-through documents resolve on B only if B mirrors their targets too.

-
**Reading through.** B answers for untouched resources as A did at `at` (§7.6). It uses only A's immutable URLs: `/ns/{ns}/rev/{at}/log`, `/ns/{ns}/rev/{at}/heads`, `/r/{ns}/{name}/rev/{id}/log`, `/r/{ns}/{name}/rev/{id}` and `/r/{ns}/{name}/blob/{bid}`.

- B verifies each listed head against A's namespace log up to `at`, each revision through its log, and each blob against its id (§3.7), using the reference that names it.

- If A's namespace is itself a branch, its read-through heads aren't in its own log. B verifies each of them against the log of the base that wrote it, following A's `base` and `at` (from A's configuration chain) recursively. If B can't read those bases, it can't create the remote branch (`422`). B records the names it followed in the branch's `base` as `"chain"`: A's namespace first, then its base, and so on, as of `at`. Clients reading an E3 remote branch accept read-through ciphertext whose `pl.ns` is in `chain` (§G.5.2), since none of those namespaces exists on B.

- B MAY fetch lazily, proxying and caching, or mirror everything up front. It serves the content under its own URLs.

- A lazily fetching B depends on keeping A's read access: a fetch that fails is `502` for that resource. It also depends on A's pruning: A protects history from `at` on only while B's registration lasts, and older history and the blobs it references not at all (§8.6), so they may become `410`. Mirror up front, blobs included, to be independent.

- A's head is never needed until a rebase or merge.

-
**Registration (optional).** B may register the branch with A through `POST /ns/{ns}/branches` on A, with `{ "remote": { "origin": "https://b.example", "ns": "release-7" }, "at": … }` and `If-None-Match: *`, which fails (`412`) only while an unexpired registration of the same `remote` exists. To renew, B sends `If-Match` with the `ns_id` of the latest entry for that `remote`, and the same `at` (`422` otherwise). A retry by the same principal whose `If-Match` names the entry before the latest gets `200` with the latest.

- It needs `read` and `export` on A. It is evaluated as an `export` envelope whose `doc` is `{ "remote": { "origin", "ns" }, "at" }`, so A's rules can restrict who registers what, and where.

- `origin` MUST be an `https` origin (§G.1), except that `http` is allowed for loopback hosts (`localhost`, `127.0.0.0/8`, `[::1]`) so local deployments can test federation. `at` MUST be in A's chain (`422`).

- A appends a `branch` entry with `remote` (§3.5), and lists it in `/branches` as `{ remote, at, ns_id, expires }` only. Remote entries don't count toward the branches-per-namespace limit, but are rate-limited.

- Consumers, janitors and merge services MUST NOT fetch from a `remote` entry automatically. The origin is asserted by the registrant.

- **Registrations expire.** A registration protects A's history from pruning (§8.6) only for the registration lifetime (§6.6), counted from its latest `remote` entry. B renews by registering again with the same `remote` and `at`, which appends a new entry. After expiry A may prune past `at`, and merging history it pruned is a conflict for B (§F.3). So an `export` grant can't pin A's retention forever.

-
**Purges.**

- B SHOULD follow A's namespace log whether or not it registered. On `purge` or `purge-ns` it MUST apply §8.3 locally: its own chains for that name, its own branches and its cache tags.

- Copies B already served, and unregistered copies elsewhere, are beyond A's reach (§G.1).

-
**What doesn't reach across.** A's keys and revocations don't apply to B, and A can't freeze or purge B. A remote branch never blocks a namespace purge on A.

-
**Merging back** is a batch on A (§7.5), classified by ancestry as in §F.3 and submitted by a principal with a grant on A.

- Its `source` is `{ "origin": "https://b.example", "ns": "release-7", "at": … }`, recorded as asserted. A's gate checks every item, and fast-forwards reproduce B's ids.

- Schema revisions created on B are exported to A first, as a full-history bundle (§G.4). Otherwise items referencing them fail with `schema_unavailable`.

- Blobs that B's revisions reference and A doesn't have are uploaded to A first (§7.8), by the same principal that submits the batch, since pending blobs are usable only by their uploader.

- The batch can come from B's side or from A's merge service fetching B's branch. The result is the same.

-
**Rebasing** is §F.5 on B, with the new branch based on A's current head.

## G.4 Bundles

A bundle carries selected documents from one deployment to another as a file: for release promotion, fixtures, handovers, or a backup of part of a namespace. Exporting is a consumer (§G.2), and importing is a client of the batch API (§7.5). A server MAY offer `GET /ns/{ns}/rev/{at}/bundle?select=…` as an optimisation, with `authors=1` for `"authors": true`.

### G.4.1 Format

Newline-delimited JSON (`application/vnd.patchlog.bundle+jsonl`). The first line is the header, followed by one line per entry:

```
{ "bundle": 1, "origin": "https://staging.example", "created": "2026-09-25T10:00:00Z",
  "at": { "matches": "1k…", "schemas": "1d…" },
  "docs": { "schemas/match": { "history": "full", "head": "1s…" },
            "matches/derby": { "history": "full", "head": "1a…" },
            "matches/cup":   { "history": "snapshot", "head": "1c…" } },
  "external": ["media/photo-12"],                          // dependencies deliberately left out
  "requires": { "matches/derby": "1h…" },                  // incremental: must already be in the target
  "authors": false,
  "access": { "matches": "private", "schemas": "public" } }      // source protection, §G.5
{ "ns": "schemas", "resource": "match", "id": "1s…", "parent": "", "kind": "rev", "patches": [ … ] }
{ "ns": "matches", "resource": "derby", "id": "1a…", "parent": "1h…", "kind": "rev", "patches": [ … ] }
{ "ns": "matches", "resource": "cup", "snapshot": "1c…", "doc": { … } }
{ "ns": "matches", "resource": "derby", "blob": "1m4…", "type": "image/jpeg", "data": "" }
```

- **Full-history lines** come in chain order per resource. Every id is recomputed, and the last line per resource MUST be that document's `docs[…].head`.

- Every `docs` entry MUST have lines. Any mismatch rejects the whole bundle, so a truncated bundle can't import silently.

- A chain starts at genesis or right after its `requires` id. Chains exported from a branch include the base's entries back to genesis, or name the foreign parent in `requires`. `ns` is always the exporting namespace.

- **Snapshot lines** carry the document and its source id as provenance. A document tombstoned at the source is `{ …, "snapshot": <tombstone id>, "deleted": true }`.

- **Blob lines** carry every blob that an exported document references, from any exported revision of a `full` document or from a snapshot. Each comes once per resource, with `nonce` if it has one, before the first line that **mentions** it: one whose patches carry its id as a `$blob` member or as the value of an operation whose path ends in `/$blob`, whose snapshot document references it, or whose declared list (§E.3.1) names it. `data` is the bytes in base64url, written without padding; readers accept either. The importer recomputes each id (§3.7), and a mismatch rejects the bundle. An incremental bundle MAY leave out blobs that the history up to `requires` already references, since the target has them. In a sealed bundle (§G.5.1.1), a blob line is base64 inside a JWE, about 1.8 times the blob's size.

- **`requires`** applies only to `full` documents. `requires[r]` MUST be in the target's chain for `r`. If the target has moved on along another line, `r` is a conflict.

- **Authors, `via`, grant ids, author signatures, creation times, `gesture` and `undoes`** are included only with `"authors": true`. With them, history lines carry `grant: gid` (the id only, not §7.1's object), and a bundle carries one grant line `{ "ns", "grant": gid, "root", "stored", "key"?: { "kid", "alg", "pub" } }` per grant its lines name, before the first line that does. Its `ns` is the namespace whose entry first recorded the grant, in the form of `written` below. An exporter that can't fetch a grant leaves `grant` off the lines that would name it. A line naming a grant with no earlier grant line, a second grant line for one grant, or a grant line in a bundle without `"authors": true` rejects the bundle.

- **`written`.** A signature binds the namespace it was written in (§C.3), and history lines name the exporting namespace. A line for a revision written elsewhere, such as one a branch reads through from its base, also carries `written`: that namespace's name, or `{ "origin", "ns" }` when it is in another deployment, as a remote branch's base is. Verifiers use it, and its `origin`, in the signing input. An exporter that can't determine it, because no log it can read records the revision, writes the line without `written` and without `grant` rather than guess, so its signature reports as unverifiable.

- **`key`** is the key entry the grant's root block verified against at the source (§C.3.1): a key of the namespace document in force at the first entry that recorded the grant, or else an operator key in force at the `created` of the first revision naming the grant (§C.4). An exporter that can find neither leaves `key` out. `key` is attested by the exporter, not proven: the digest isn't a signature (Trust, below).

- Bundle tools SHOULD verify signatures through §C.3.1's chain against the line's `written` origin, else the header's `origin`. A tool holding the source's namespace log, or its operator key history, checks `key` at the revision's position; otherwise it reports the signature as attested, not verified. An importer signs its own steps (§C.3.1); the original signatures stay in the bundle, which its batches' `source` names (§G.4.4).

- **Never exported:** purged content.

- **Consistency.** Each namespace is exported as of its own `at`, taken when the export starts.

- **Digest.** A bundle's digest, recorded as `source.bundle` (§G.4.4), is `text(trunc160(sha256(b)))`, where `b` is the bundle as written: each line's canonical JSON (§3.1) followed by one newline (0x0A), header first. A file written that way has exactly those bytes.

- **Trust.** Headers and snapshot lines are only as trustworthy as the channel that delivered the bundle, until signed bundles exist (§G.7). A bundle can be encrypted to its recipients as a sealed bundle (§G.5.1).

### G.4.2 Selection and dependencies

A selection is a list of resources, or anything a resolver turns into one, e.g. a catalog folder (Addendum B). The **dependency closure** is built in three levels:

- **Core references, always** (a document that references a schema revision existing only in a branch, §6.1, can't be exported until that branch is merged: `schema_unavailable`, unless that schema's namespace is declared `external`, when the importer checks the target instead): the `$schema` of **every exported revision**, not only the head's, `$ref` inside those schemas, and the blobs those revisions reference (§7.8).

- **Declared references:** fields marked `x-ref` in the documents' schemas (§6.5). A **pinned** reference needs that exact revision. A **live** reference needs the head as of the export's `at`.

- **Application resolvers:** tool plug-ins for relationships no schema expresses, e.g. "a match brings its team pages" or "a folder brings its placements".

Untyped documents get only level 3, plus an opt-in rule that treats any string matching `^/r/` as a reference. Dependencies can be left out on purpose with `external`. The importer then checks that they exist in the target: by id for pinned references, by name for live ones.

### G.4.3 History or snapshot

Each document is exported in one of two modes:

|  | `full` | `snapshot` |
|---|---|---|
| Contents | every revision, or those after `requires` | the head document only |
| Ids in the target | identical to the source | new, derived from the sequence of snapshots imported |
| Verifiable lineage | ✅ | ❌ provenance only |
| Later imports | fast-forward or merge (§F.3) | merge through the upstream namespace (§G.4.4) |
| Old drafts and authors | included (authors optional) | never included |

- **Schemas are always `full`.** `$schema` and `$ref` then resolve unchanged, and nothing that validation depends on is ever rewritten.

- **Modes close downward.** Everything a `full` document reaches through `$schema`, `$ref` or a pinned `x-ref` MUST also be `full`, because a `full` document can't be rewritten without changing its ids. A pinned reference to a revision other than a document's head also forces `full` for that document.

- **No shallow mode.** Keeping the source id on a document without its ancestors would give an id nobody can recompute, breaking invariant 4.

### G.4.4 Importing

- **Check the bundle** (§G.4.1), including `requires` and `external` against the target. Nothing is written if this fails.

- **Classify full-history documents** by ancestry, as in §F.3:

- missing in the target: created with the whole chain, keeping its ids

- the target has an ancestor: fast-forward

- the target already has it, or has moved beyond it: nothing

- a different history: conflict

- **Import snapshot documents through an upstream namespace.** The target keeps one namespace per source namespace for them, e.g. `matches-upstream`, written only by imports.

- **Upstream first.** Each import appends to each snapshot document there one revision: `diff(previous snapshot, new snapshot)`, or a genesis the first time. For a deleted document it appends a tombstone. An empty diff writes nothing. The upstream chain is exactly the sequence of snapshots as imported, and its ids depend only on that sequence, except in a sealed target: there each generated patch set carries a fresh `$nonce` (§C.7), so the ids differ from one import to the next. Diffs ignore `$nonce`, so an unchanged snapshot still writes nothing.

- **Then the target, as a merge from upstream.** The first time, the target fast-forwards and so shares the upstream ids. Later, the base is the upstream revision recorded in the previous import batch's `source.ids`, and the upstream revisions after it are replayed onto the target's head. They conflict where they overlap the target's own changes (the array rule of §F.3). A deletion conflicts if the target changed the document.

- **Pinned references in snapshot documents** that point at other snapshot documents are rewritten to the matching upstream revision path, `/r/{ns}-upstream/{name}/rev/{id}`, keeping any `#{id}` fragment (§6.5). That path always exists and is exactly the imported snapshot. Pinned strings that aren't declared can't be found, so the dry run lists them.

- **Dry run, then resolve conflicts,** as in §F.3: skip the document, take the bundle's version, or replay.

- **Submit batches in dependency order.**

- **Order.** Dependencies go first: schemas, upstream namespaces, then the documents that reference them. Namespaces whose pinned references form a cycle go together as far as each batch allows.

- **Size.** Batches are split to fit §6.6, which makes the import non-atomic. A backfill can accept that, and its tool paces the batches at a fraction of the namespace rate so other writers aren't held up. An import that must land at once, such as a release, runs as one batch under an allowance (§6.6), typically as a merge from a branch it was first imported into (§F.3).

- **Blobs first.** The blobs a batch needs are those its steps' values mention (§G.4.1), since references the target's head already has are attached there. They are uploaded before it by the importer, or copied with `Blob-From` within one deployment (§7.8), unless the batch's local `source` already makes them available. Uploads change no head, so they don't count as writes for step 1: an import that will submit uploads its blobs before the dry run of step 4, and one that only dry-runs uploads none, and gets them reported as missing (§7.5). A snapshot document's blobs go to both its upstream resource and its target. Pending blobs expire after `blobGrace`, so a long review re-uploads them, which restarts it. A large import needs an allowance that raises the importer's `blobPending` (§6.6).

- **Rewriting waits for its targets.** A document's references are rewritten only after the batches of its dependencies have committed, using the ids they returned.

- **Source.** Each batch's `source` is `{ "origin", "ns", "at", "bundle": <digest>, "ids": { name: upstream or source id } }`, and the importer is recorded as author.

- **Partial failure.** A failure part-way can leave dependencies updated. New resources are unused, but updated heads take effect, and live references see them. So promotions that change existing dependencies should be dry-run end to end first.

- **Today's rules judge old history.** A full-history import replays every step through the target's **current** gate (§6.2), as the importer, at the current `now`. Rules on `/principal`, `/now`, `writes` or, for replayed deletes, `/doc` may reject history that was valid at the source. Such imports need an importer whose roles satisfy those rules, or snapshot mode.

Tooling is non-normative. For example:

```
patchlog export --from https://staging.example --select matches/derby,matches/cup \
                --deps schema,x-ref --history snapshot > release-7.plb
patchlog import release-7.plb --to https://cms.example --dry-run
```

## G.5 Encryption (Addendum E)

- **Obligations A can't enforce.** A remote branch or import of a private or sealed namespace MUST itself be private or sealed (§7.4, §E.2.5). A can't enforce this. It is part of what an `export` grant entrusts.

- **E2.** An exporter with keys decrypts, so the bundle holds plaintext and should be encrypted to its recipient. A remote branch has its own epoch keys.

- **E3.** Bundles and remote branches carry ciphertext, and ids over it verify as usual. Keys travel separately, via the keyring, to recipients who may read. Merges across differently named namespaces re-encrypt, so they never fast-forward (§F.8). Snapshots need a client with keys, and a sealed genesis isn't deterministic (random IV).

### G.5.1 Bundles

- **`access`** in the header gives each exporting namespace's protection: `"public"`, `"private"` (read-restricted, with or without E1), `"sealed"` (E2) or `"e2e"` (E3). Exporters MUST include it. An importer treats a namespace that is missing from it as `"private"`.

- **Importing.** The importer enforces what A can't. It MUST refuse to import into a target that is less protected than the source, unless an operator overrides this explicitly for that import:

- A `public` source may go into any target.

- A `private` or `sealed` source goes into a private or sealed target. An importer that holds the target's keys MAY also import it into an `e2e` target by sealing each patch set client-side, encrypting each blob as in §E.3.1 and rewriting its references to the new blob ids. Only a client with the target's keys can do this. That re-encryption changes the ids, like any E3 merge (§F.8).

- An `e2e` source goes only into an `e2e` target **with the same namespace name**, since sealed patch sets bind `pl.ns` (§E.3.1). Lines carry the ciphertext verbatim, including the `keyring` resource, and ids verify as usual. Its blob lines have the sealed type and no nonce (§E.3.1), since declared lists carry only ids, and an importer refuses one that doesn't, before uploading anything. Importing under another name is a merge, done by a client that holds both sets of keys. A target created for the import starts at the bundle's lowest epoch and is moved up one epoch at a time as its keyring lines arrive, so the importer needs `config` on the target, with a `*` key (§7.4). An existing target whose epoch is below the bundle's is refused.

- **E3 snapshots.** A snapshot line of an `e2e` namespace needs an exporter with keys. The exporter replaces `doc` with `"patches": [{ "op": "sealed", … }]`, a sealed genesis under the source's current epoch with its `blobs` list (§E.3.1), and `snapshot` keeps the source id as provenance. The genesis id is computed over that ciphertext, so each export produces a different one.

- **Plaintext of protected sources.** A bundle with lines from a `private` or `sealed` namespace holds plaintext, and SHOULD be delivered as a sealed bundle. Exporters SHOULD refuse to write it unsealed unless asked to.

#### G.5.1.1 Sealed bundles

A sealed bundle (`application/vnd.patchlog.sealed-bundle+jsonl`) encrypts a bundle line by line, so it can be written and read as a stream:

```
{ "sealedBundle": 1, "id": "",
  "recipients": [ { "kid": "", "suite": "hpke-base-0x0020-0x0001-0x0002", "wrapped": "" } ] }

…
```

- **Envelope line.** `id` is 128 random bits, base64url without padding. The content key `K_b` is 256 random bits, wrapped for each recipient with HPKE (RFC 9180, base mode). The suite is the one of §E.2.3: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. The HPKE `info` is `"patchlog-bundle-v1" ‖ 0x0A ‖ id`. A recipient's `kid` is the RFC 7638 thumbprint of its X25519 public key as a JWK (`{ crv, kty, x }`, SHA-256, base64url).

- **Lines.** Each following line is a JWE compact under `K_b`, with `alg: "dir"` and `enc: "A256GCM"`. Its protected header carries `pl: { "bundle": id, "line": n }` and, on the last line only, `"last": true`. The plaintext of line `n` is bundle line `n` (header = 0) as canonical JSON, without its newline. Lines are never compressed.

- **Checks.** A reader MUST reject the whole sealed bundle if any line fails to decrypt, if `pl.bundle` differs from `id`, if line numbers are not 0, 1, 2… in order, or if no line says `last` or a line follows it. Reordered, spliced or truncated sealed bundles are therefore rejected. The decrypted bundle is then checked as in §G.4.1.

- **Digest.** `source.bundle` is the digest of the decrypted bundle (§G.4.1), so it is the same however the bundle was delivered.

- **What stays visible:** the number of lines, their sizes and the recipients' thumbprints. Padding (§E.2.2) MAY be applied to each line's plaintext.

### G.5.2 Remote branches

- A remote branch of a `private`, `sealed` or `e2e` source MUST be at least as protected. B refuses to register it otherwise. B learns the source's level from the source's namespace document. If B can't read that document, it MUST refuse, since it can't tell the level.

- **E2 sources.** B fetches keys from A with its own key pair and grant (§E.2.3), mirrors the plaintext, and seals what it serves under the branch's own epoch keys.

- **E3 sources.** B mirrors ciphertext and the `keyring` verbatim, and verifies ids over the ciphertext. A remote branch of an E3 namespace keeps its source's namespace name in `pl.ns`, so its readers use the source's keys, which B relays from the mirrored keyring through `POST /ns/{branch}/keys` (§F.8.1). Read-through content sealed further up, by A's own bases, carries their names and is accepted when they are in `base.chain` (§G.3). Their keys are in those namespaces' keyrings. B relays them when it mirrors those keyrings, and otherwise readers fetch them from A with grants of their own there. Writes to the branch are sealed under keys the branch's own key holders manage, and are merged back by re-encryption (§F.8).

- **Epoch start times** decide which epochs B relays to a grant (§E.2.3). B takes them from the source's namespace documents, which B can't verify against the chain, so they are only as trustworthy as the channel. That limits the harm: relayed entries are wrapped to keyring recipients, so a wrong start time can only change which wrapped keys a grant receives, never who can unwrap them.

## G.6 Multi-region (outlook)

A read-only mirror is a remote branch that is never written. A mirror that tracks its source needs periodic rebasing, which creates a new namespace each time (§F.5). So it needs a stable alias that follows `successor` (§F.10) before it can serve stable URLs. Multi-primary writes would need a way to order concurrent heads, and are out of scope.

## G.7 Open questions

- Absolute pinned references (§13), so a bundle or remote branch can point back at its origin instead of mirroring.

- Signed bundles, covering the header and every line.

- A namespace flag such as `export: false`, as a policy statement that well-behaved deployments respect.

- Should registered remote branches confirm purges back to A (a purge receipt)?

---

## Change log

- **v0.2:** opt-in `$schema`.

- **v0.3:** namespace document and test-op rules.

- **v0.4:** 160-bit base32 ids and compact storage.

- **v0.5:** indexing moved to Addendum A.

- **v0.6:** Addendum B, organising documents.

- **v0.7:** Addendum C, capabilities and access.

- **v0.8:** catalog with tree-derived access.

- **v0.9 (review):**

- **Rules and paths:** normative `writes` and `covers`/`overlaps`/`within` predicates, replacing path regexes.

- **Grants:** identity only from root blocks; grant rules on reads; auth before precondition; idempotent retry scoped to the same principal and searching the whole log.

- **Input and names:** I-JSON input and JCS required; name grammar; strict `$schema` grammar and `$id` handling; tombstoned schema revisions resolve.

- **Namespaces and limits:** namespace ETag is `ns_id`, with `X-Config-Revision` for config preconditions; `config` action; limits and linear-time regexes.

- **Caching:** private-namespace caching (`private` downstream, CDN-only lifetimes); browser `max-age` of one day; consumers purge derived data.

- **Catalog:** listings keyed by group set with no embedded signed URLs; moves require both sides and no widening; gone ancestors end the walk; scoped keys gain `sub`, `groups`, `readScope` and `requireAt`/`maxLag`.

- **Grant storage and signatures:** non-bearer grant storage; per-block revocation ids; domain-separated full-digest signatures; `$nonce` for private namespaces.

- **Structure:** implementation detail moved to Addendum D.

- **v0.10:** Addendum B reworked around catalog namespaces: folders and placement documents are separate from content, with several catalogs per content set, whole-tree documents for small trees and `$parents` kept as an optional shortcut. Namespace names contain no dot.

- **v0.11:** Addendum E, encryption: E1 at rest, E2 sealed for delivery (JWE with `dir` and A256GCM, epoch and per-resource keys, public caching of private content), E3 end-to-end.

- **v0.12:** envelope field `after` renamed `doc`.

- **v0.13:** roles, attributes and time.

- **Core:** `principal.roles` and `principal.attrs`, `now` in the envelope, `compare` rule form, worked ownership and lock rule; `/roles` guarded like `/keys`.

- **Grants:** `roles`, `attrs` and `nbf`; key scopes gain `roles` and `attrs`; roles expanded at the gate as alternatives (§C.1.1); reads decided at issuance (§C.5.1).

- **Catalog:** `$access` maps subjects to role names; content namespaces define what roles mean, the catalog namespace defines `move` and `place`; listings keyed by subject set.

- **v0.14:** batches and branches.

- **Core:** atomic batches within a namespace (§7.5); branches with a fixed base, read-through and foreign parents (§7.6); namespace freeze and purge (§8.4–8.5); resource purges propagate to branches; `batch` and `purge-ns` namespace entries; `ns:{ns}` tag on every response; invariant 7.

- **Grants:** `branch` and `purge-ns` verbs; revocation checked in every base.

- **Addendum F:** merge as a batch classified by ancestry, rebase as a successor branch, stacked branches, lifecycle and a verifying janitor, merge service, and access, encryption, catalogs and indexes for branches (F.8).

- **Review fixes:**

  - rules that refer only to the request run at step 1, so resource-scoped grants can't probe preconditions

  - the frozen check runs after authorisation and the idempotent-retry lookup

  - branch keys follow the base, and branch creation can't add keys without a base `*` key or read around a resource-scoped grant

  - purges propagate by name to every branch

  - no `$schema` into branches

  - public dependents block making a base private

  - catalog `at` names its namespace (`requireAt` takes a namespace)

  - `/limits` guarded like `/keys`, with deployment maximums

  - authors on namespace entries

  - `/heads` snapshot listing

  - §6.4.4 examples scoped by action

- **v0.15:** `branch` entries in the base's namespace log, written atomically with the branch's first config entry, so consumers of a base discover branches without polling (§3.5, §7.6, §10).

- **v0.16:** Addendum G, federation and portability.

- **External consumers:** origin-qualified checkpoints, and verification through logs.

- **Remote branches:** created with the operator key, with schema mirroring, optional registration (`export` verb, `remote` branch entries) and purge notices.

- **Bundles:** full-history or snapshot documents, with modes closing downward and schemas always full; a dependency closure through `x-ref`; import classified by ancestry, with snapshots merged through an upstream namespace.

- **Core:** the `x-ref` annotation (§6.5); a `source` grammar with `origin` (§3.5); author signatures bound to a canonical origin (`patchlog-sig-v2`).

- **v0.17:** growth control.

- **Rate limits:** per resource and principal, per principal and per namespace, as token buckets checked after authorisation and answered with `429 rate`; batches cost one token per item and may overdraw a full bucket; admin config writes and purges are exempt; key scopes may lower them.

- **Clients** combine pending changes while a save is in flight, resending a lost set unchanged first (§11).

- **Pruning below a horizon (§8.6):** ids and parent links are kept; protected revisions and the retry window are never pruned; branch points and every branch's own entries are protected; history is archived as a full-history bundle to an operator- or policy-configured destination, and purge reaches archives; a `retention` policy is guarded like `/limits`; the namespace log is never pruned; a `prune` entry kind and verb. Addendum F's branch `retention` field is renamed `cleanup`.

- **v0.18 (review):**

- **Rate limits** are keyed by the root `sub` and signing key, never by `via`, which any holder can add; big batches take buckets below zero; the freeze exemption covers only real freezes; the retry window is the one limit a namespace can raise, up to a deployment maximum.

- **Guessing from ids:** a fresh `$nonce` is added in every patch set, not only genesis, since parent ids are public; only an `add` or `replace` of a well-formed nonce is left out of `writes`.

- **Exposure:** setting `read` to `public` and any change under `/encryption` need a `*` key; a branch can't be less encrypted than its base.

- **Schemas:** a *referenced schema revision* is defined once (heads and last live documents across the deployment, read-through included, closed over `$ref`) and protected from pruning and purge.

- **Remote registrations** expire after 30 days unless renewed with `If-Match`, so they can't pin a base's retention forever.

- **Janitor:** the `merged` check tolerates the post-merge freeze, and `superseded` requires the successor to have replayed the branch (rebase replays carry `source`).

- **Fixes:** `successor` needs the same base namespace, not the same `at`; pruning keeps grant references and creation times, and `keep` is limited per resource in total; at E3, path and document rules make resource writes fail; pruning is the one write without a precondition; log-range `410` is defined; invariants 3 and 5 reworded.

- **v0.19:** live reads by long-poll with cursors (§7.7). Deterministic time-interval cursors make every waiting URL new each interval, with no jitter so waiters stay collapsed, the page size is fixed by the deployment, waits end at interval boundaries, and `200` and `204` answers are briefly cacheable, so the CDN collapses many followers of one log into one origin request. Addendum D gains D.8, a Postgres layout with a lock per namespace, content stored apart from the skeleton, and `LISTEN`/`NOTIFY` to wake live readers.

- **v0.20:** feedback from mapping a signage product onto the spec.

- **Allowances** (§6.6): an administrator can give a named principal its own rate and batch limits, so a large import or release lands as one atomic batch without holding up other writers. Paced splitting is for backfills only (§G.4.4).

- **`x-ref`** gains `key`, for references to one entry inside a document, resolved by id (§6.5). References are found by a static walk of document and schema together, so no validator needs annotation output.

- **Catalog:** a create flow: place the new item, then get a create grant fixed to its name, usable for the genesis only (§B.11.4).

- **Addendum D:** head snapshots only for small documents, with intermediate snapshots bounding every fold (D.4). In D.8, a tailer replaces `NOTIFY`, which serialises commits across the database, and the throughput bound is stated honestly as one flush per write per namespace.

- **v0.21:** fixes from the first full implementation.

- **Catalog:** re-placing an item uses a restore-only grant; a `PATCH` with `If-Match` passes step 1 with either `append` or `restore`, and the verb is settled at step 2, after the idempotent-retry lookup and before the precondition is compared (§6.2). The `$access` rules (§B.11.3) exempt creates and restores and judge the resulting document instead, since a create writes `""` and overlaps every path; as written they rejected every new folder and placement. §6.4.4 now states the pattern. No-widening compares roles by name with declared `includes` (§B.11.4). Tree listings pin a combined checkpoint over every namespace they follow (§B.5).

- **Interoperability:** Biscuit v3 is the reference encoding for grants, one JSON block per Biscuit block, with Datalog unused (§C.8); JSON keys and units for every limit (§6.6); the bundle digest is defined (§G.4.1); `maxLag` is set by the namespace and may be tightened by a key (§C.4); operator grants may name a namespace that doesn't exist yet (§C.4).

- **Errors and existence:** expired and not-yet-valid grants are `401` (§C.2); unknown namespaces answer unauthenticated requests with `401`, like private ones, and grants are checked against `ns` before any key lookup (§7); a dry run with unauthorised items answers as a submit would (§7.5); batch limits are checked after authentication (§7.5).

- **Loosened:** `$ref` may carry a JSON Pointer fragment into another revision (§6.1); `http` origins on loopback for local federation tests (§G.3); the integer range is judged on canonical form, so `1e300` is accepted and stored patch sets always round-trip (§3.1).

- **Defined:** remote bases that are branches are verified through their bases (§G.3); mirrored schemas keep their namespace name (§G.3); retention without an archive must say `archive: false` (§8.6); no `cleanup` means the janitor keeps the branch (§F.6); a second merge after a replay uses earlier merge batches, by authors the base lists in `merge.authors`, as common ancestors (§F.3), and the janitor trusts only those batches (§F.6); `at`-pinned query results use the immutable cache class (§A.4, §B.5).

- **v0.22:** public reads ignore a grant that doesn't name the namespace or can't be used, and answer as unauthenticated (§7, §C.2), so a client can send one bearer to every namespace it reads, such as a public schema namespace next to a private one.

- **v0.23:** optional padding of sealed payloads, `"encryption": { …, "pad": true }`: space-padded plaintext to Padmé buckets of at least 256 bytes, never compressed, at E2 and E3 alike (§E.2.2, §E.3.1, §E.4).

- **v0.24:** the sealed format of derived views (§E.2.6). A response from a single source may be one JWE with `pl: { ns, view }`. Otherwise entries are sealed one by one under their own namespace's key, with `pl: { ns, name, view }`, where `view` is the `at` URL's path and query. Only content-derived values are sealed; names, ids, URLs and structure stay in the clear. Services at E3 need to be keyring recipients, derived data is purged with its source, and query strings are listed as visible metadata (§E.4).

- **v0.25:** encryption for bundles and remote branches (§G.5). Bundle headers give each namespace's protection in `access`, and importers refuse a less protected target unless an operator overrides it; E3 bundles import only under the same namespace name. Sealed bundles (§G.5.1.1) encrypt line by line under an HPKE-wrapped content key, with `pl: { bundle, line }` and a `last` marker, so reordering and truncation are detected, and the digest stays over the plaintext. Remote branches must be at least as protected as their source (§G.5.2).

- **v0.26:** merging and rebasing at E3 (§F.8.1). A client with keys classifies by ancestry over ciphertext ids. What would be a fast-forward becomes a re-sealed replay with new ids, and there are never fast-forwards at E3. Each re-sealed patch set is bound to the target and to the id of the entry before it. The merger checks conflicts on decrypted `writes` and validates against `$schema` before submitting. Later merges and the janitor work from plaintext namespace logs, and a `kid` names the namespace whose keyring holds its key.

- **v0.27:** feedback from implementing E-4.

- **Derived views (§E.2.6):** entries are sealed under the resource's `K_r`, so per-resource readers can open them. Single-source views use per-entry sealing for per-resource readers. Aggregates such as counts are served only whole. Queryable service storage is encrypted like E1, not sealed per row. Catalog `/read-grants` returns wrapped `K_r` for sealed items (§B.11.5).

- **Merges (§F.5, §F.6, §F.8.1):** a resumed rebase trusts the old branch's batches in the successor. Without `merge.authors`, an E3 merge may count identical documents as merged. The janitor ignores keyring entries after a merge. Validation failures are `invalid` conflicts. Clients ask the namespace they read for keys, which relays keyrings it reads through.

- **Padding (§E.2.2):** whether a revision should be padded follows the configuration at its namespace log entry.

- **Bundles and remote branches (§G.4.4, §G.5):** upstream chains of sealed targets aren't deterministic. E3 imports into new targets need `config` to step through epochs. B refuses a remote branch whose source document it can't read. Epoch start times from the source are unverified but can't widen decryption.

- **v0.28:** catalog `/read-grants` keys are defined (§B.11.5). There is no `K_r` for E3 items, and there are keys for placement and folder nodes of sealed catalogs. Keys are checked by role even in public sealed namespaces, and `historyEpochs` bounds the epochs, since catalog grants have no start time. Remote branches record the base chain they verified as `base.chain`, so clients can accept read-through ciphertext from a source that is itself a branch (§G.3, §G.5.2).

- **v0.29:** feedback from running a real CDN in front of the implementation (§9). Private content is cached at the edge only with a grant-verifying edge. Otherwise the origin marks it `CDN-Cache-Control: no-store`, and edge lifetimes go only to requests carrying the edge's verification. The origin purges `ns:{ns}` itself when a namespace becomes private. Stale serving is defined: immutable content MAY be served while the origin is unreachable, head pointers only within `stale-while-revalidate`, and long-poll answers never. Empty long-poll `204`s must be cached. The tag grammar and delimiters are defined, purges match whole tags, and `PURGE` with `X-Purge-Tags` is suggested for self-hosted CDNs.

- **v0.30:** feedback from seeding a DAG catalog (Addendum B). Each parent edge carries its own `order`, and children sort by the edge to the listed folder (§B.2). Manifests have one entry per path (§B.4). Every node on a cycle is left out along with all its edges, and `/problems` lists cycles by node (§B.5). Listings show shared nodes under each parent, responses are bounded and SHOULD mark repeats (§B.5). `mode` is enforced by the catalog's rules, not consumers. `?min` applies per catalog in multi-catalog services.

- **v0.31:** feedback from loading real data.

- **Blobs** (§7.8): large values are immutable bytes attached to a resource, uploaded with `PUT /r/{ns}/{name}/blob/{bid}`, served immutably with ranges, and referenced from documents as `{ "$blob", "type", "size", "nonce"? }`. Ids hash type, nonce and bytes (§3.7). Access, cache tags, purge and branch read-through follow the resource. Uploads stay pending and invisible until a write attaches them, and expire otherwise. Pruning archives blobs with their documents (§8.6). Merges take blobs through the batch's `source`, imports upload them or copy them with `Blob-From` (§F.3, §G.4.4), and bundles carry blob lines (§G.4.1). At E2 blobs are sealed in a binary form, once per epoch. At E3 each blob has its own key inside the sealed reference, so merges keep blob ids, and writers declare referenced blobs in plaintext for the server (§E.2.2, §E.3.1).

- **Sizes:** creates, and restores from scratch, may be as large as `documentSize` (§6.6). `valueSize` and `pathSize` bound every string so that any value can be replaced by one append, even sealed and with a `test`.

- **Allowances** take an optional `until` (§6.6).

- **Designing documents** (§11.1): member order, `$schema` revision paths, keeping namespace names on import, blobs, and when to split a document.

- **v0.32:** feedback from implementing v0.31 in Go, on Postgres and with blobs.

- **Blobs (§7.8):** a copy's `400`s come before its source is read, and a purged namespace is `410` after authorisation, like a purged resource. Attaching a blob ends every pending entry for it. A batch's `source` is judged in the source's own view, only for callers who may read it, and a bad `source.at` has its own code, `source` (§7.5, §12). Dry runs report missing blobs and carry on.

- **Sealed blobs (§E.2.2):** epochs are defined for revisions not yet sealed, pruned epochs are `410` only where recorded, ranges are over the sealed bytes, and clients open sealed blobs only where they know the namespace is sealed. Read-through and pre-sealing revisions keep the epoch they were first served under (§E.2.5). At E3, declared lists have a preferred form, no duplicates and only sealed blobs, and a prune needs no list (§E.3.1, §8.6).

- **Bundles and federation (§G):** "before the first line that mentions it" is defined, blob lines are unpadded base64url, imports upload blobs before their dry run, local imports need no copies, E3 blob lines and re-encrypting imports are specified, and lazily mirrored remote branches may lose blobs to pruning.

- **Addendum D:** blob bytes are written durably before their row commits, deleted after it, and stored under one name per copy, so a delete can't hit a re-upload; `blob_refs` runs record which revisions reference a blob, and `blob_epochs` is keyed by name. On Postgres: 32-bit lock keys, try-and-restart for locks found late, shared rows, snapshots, `bytea` where encryption at rest applies, a generation counter that bounds cache staleness, with a second CDN purge, one runner for background jobs, and small writes checked inside the lock (D.3).

- **v0.33:** releases across namespaces (§F.9). In a write to a branch, a schema path its namespace can't resolve is looked up among revisions written in that namespace's branches (§6.1), so a release drafts its schemas privately and its documents never name a branch. Paths in bases still resolve only in the base. Purges are refused only for the last available copy of a referenced revision, counting every revision a branch wrote. A draft branch serves only itself and its branches unless `drafts.for` names others (§7.4), and clients find drafts by trying the branches. The branches of a release are listed in an ordinary release document that previews, grant issuers and the merge service read (§B.5). The merge service merges in a safe order: schemas by fast-forward, catalog changes that narrow access, content, then catalog changes that widen it, and reports in advance the conflicts that order can't make safe.

- **v0.34:** feedback from implementing v0.33 in Go.

- **Drafts (§6.1, §7.4, §7.5):** a path `N` can't resolve for the writer, absent or unreadable, falls through to drafts. One rule reads other namespaces, for batch sources, blob copies and drafts alike: the request's grant or any `Source-Authorization` grant. `drafts` is only for local branches that aren't E3, `"*"` is allowed, it isn't inherited, and the branch listing shows it. Client resolution is best effort, and services may cache schemas by path.

- **`in_use` (§3.5, §6.1, §8.5):** forcing a purge is `?force=1` with a deployment operator key, or a branch's `*` key for purges in that branch, and every entry it writes says `forced: true`; the refusal lists the `referencing` namespaces the caller may read. Remote branches and exports that would need drafts answer `schema_unavailable`.

- **Releases (§F.9) and catalogs:** approval binds to a plan digest; catalog merge grants are bounded per resource and action, signed by a dedicated key only for the merge service, which submits them itself (§F.3, §F.8); `$access` changes are submitted by a catalog admin; folders have a creation rule (§B.11.4); `abandoned` is a claim the janitor verifies (§F.6); previews hide unreadable branches; split nodes, `merged.at`, the release lock and the release's optional `at` are defined.

- **D.8:** resource writes and blob uploads lock their namespace shared and state changes exclusively, a separate advisory log lock, taken last, orders the namespace entries, and same-resource races are decided by constraints at insert.

- **v0.35:** a delete's envelope carries the document being deleted as `doc`, so rules can decide deletes by content, e.g. "only the owner may delete" (§6.4.1). `patches` and `writes` stay `[]`, so `within` doesn't restrict deletes: limit them by verb or by rules on `/doc`. `purge`, `purge-ns` and `read` keep `doc: null`, and in end-to-end namespaces `doc` is null for every resource action. The ownership example (§6.4.4) now covers deletes. Also fixed: the catalog's shape rule (§B.6) failed every delete, so placements couldn't be removed; unplace grants now pin `/doc/parents`; two deletes in a row in a batch item are `422`.

- **v0.36:** feedback from running the implementation.

- **Catalog:** listings are filtered by their subject set, with visibility defined once for listings and `/read-grants`, limits and pagination over the visible nodes, and unfiltered endpoints only for namespace-wide readers (§B.11.5); a deleted item can be restored through the catalog, by the roles it had when it was deleted (§B.11.2, §B.11.4); grants carry role names without evaluating their rules, so clients that show what is editable check them; previews follow the release document; relisting after a write uses `?min` (§B.5).

- **Schemas:** validation ignores a document's top-level `$schema`, and a top-level `$nonce` of the fresh-nonce form, so closed schemas work without declaring them (§6.2, invariant 3).

- **Live reads:** following several logs needs HTTP/2 or later, or a service that fans them out (§7.7).

- **D.8:** group commit per namespace and routing a namespace's writes to one instance keep throughput from falling under contention.

- **v0.37:** review of the core.

- **Conformance** (§1): what a core server implements, and how it degrades without the optional addenda.

- **Namespace log:** entries record their grant, so merges can be checked against `merge.authors` (§5, §7.4, D.2); log ranges are paged (§7.1); `/heads` is ordered by name; the namespace `PATCH` response is defined.

- **Edges:** a retry on a purged resource is `410`; blobs may be uploaded to a tombstoned resource before a restore; namespace-document members are listed, and others must start with `x-`; `GET /` publishes the spec version; origin clocks must agree well within a long-poll interval (§7.7); CORS and SSE for browsers (§7).

- **Editorial:** invariant 5 and the referenced-schema rules of §6.1 are split into lists.

- **v0.38:** feedback from implementing v0.36 and v0.37.

- **Catalog (§B.11.4, §B.11.5, §B.11.7):** a role's rules count for visibility when they pass as a read would evaluate them, so the `translator` example sees what it may read; roles count only through subjects the catalog's key may assert; visibility is pinned to the listing's checkpoint; a restore that would widen access compared with the item's frozen rows is refused, and restore's answers are ordered so they reveal nothing to callers without `read`; restore needs a current placement, and its status codes are defined; the unfiltered endpoints and `g/all` without edge grants are defined.

- **Group commit (D.8):** rows are inserted before the log lock in a few statements rather than under savepoints, writes that conflict within a group are answered alone, each entry records its own grant, and groups form only under contention.

- **Grants on log entries (§1, §7, §7.4):** `GET /` says whether authentication is on; entries written without authentication record `grant: null`, and merge and claim checks match them on their author; the grant id's text form, the entries without a grant and those from before v0.37 are defined; D.2 keeps the root `sub` and `kid` in plaintext.

- **Paged ranges (§7.1):** `404` and `410` are judged over the whole range, `X-Log-Next` is unquoted, pages may end without it at the range's id, long-poll answers carry none, E3 prune snapshots are never log entries, `logPageSize` also sizes `/heads` and catch-up, and sealed pages are defined for resource logs.

- **Namespace documents (§7.4):** the addenda's members have defined shapes and may carry `x-` members, as may role entries; errors are `422 invalid` with pointers; members stored under an earlier version are kept until changed; tools refuse another deployment's documents only for unknown members, not for the version alone.

- **Also:** a retried batch's purged items are `410`; a retried namespace `PATCH` answers `200`; spec versions are dotted decimals; CORS sends `*` on every response when every origin is allowed.

- **Note for tools:** since v0.36, validation leaves out a document's top-level `$schema` and fresh `$nonce`; schema tools that also talk to older servers still declare `$schema` in closed schemas.

- **v0.39:** gestures for undo and redo. A write may carry `Gesture` and `Undoes` ids, 128 random bits the client picks per user action, stored with each revision as metadata, outside its id (§7.2). Logs serve them, a batch can set them per step, and an optional endpoint lists a gesture's revisions (§7.4, §7.5). Undo is a client procedure (§11.2): the inverse of the gesture's own entries, newest first and widened to whole arrays, written after checking the later log for overlapping writes and guarded by `ifMatch`; redo undoes the undo, and an author's stack counts that author's undos, showing others' as such. Merges and bundles may carry gestures along (§F.3, §G.4.1), and pruning keeps them.

- **v0.40:** feedback from a second implementation (the reference, through its v0.9.0).

- **Rules (§6.4.3):** a purge forced under a deployment operator grant isn't judged by namespace rules; one forced with a branch's `*` key still is.

- **Gate (§6.2):** errors in a request's own shape (`400`, `413`, `415`) may come before authentication; nothing else may.

- **Gestures (§7.2, §7.4):** config writes carry them too, a batch's config change doesn't, and undoing config is out of scope; the gestures listing pages by `{resource}/{id}`, leaves out purged resources, and answers `404 not_offered` in sealed namespaces.

- **Limits (§6.6, §7.5):** a batch's config change costs a token; the body bound leaves room for the batch envelope.

- **Encryption (§E.2.2, §8.6):** sealed namespace log ranges may be evicted and sealed again; `keep` is `422` at E3, and E3 retention is a key-holding client's job.

- **Roles (§7.4):** the core reads `can` and `rules` in role entries; `includes` is the catalog's.

- **Signatures (§C.3, §G.4.1):** stored and served, not verified by the server unless it knows the key (`422 signature`); bundle tools SHOULD verify when they can.

- **Not adopted:** a public sealed branch of a non-public base. Ciphertext would be safe, but names, sizes and timing aren't, and the base's `read: "grant"` is what hides them from the public (§E.4), so §7.4 keeps its rule.

- **v0.41:** verifiable author signatures (§C.3.1), from a proposal by the reference implementation.

- **Keys:** a grant's root block may list the principal's `signers`, so an issuer vouches for keys as it does for authority, and old revisions verify against the keys in force when they were written. Narrowing blocks can't add any.

- **Verification:** the server verifies a signature whose key the grant lists, at the end of §6.2 step 1 (`422 signature`); issuers list keys only after proof of possession; resource logs serve each revision's grant and signature; `GET /ns/{ns}/grants/{gid}` serves stored grants, with `stored` defined byte for byte; bundles with authors carry them with the keys they verified against, attested by the exporter (§G.4.1).

- **Requiring them:** `signatures: "required"` in the namespace document (`*` key); batch steps carry their own `signature`; mergers and importers sign what they write.

- **Tombstones** now have a signing input, with `tombstone` in place of the patch set, so a delete's signature can't pass for an empty append's.

- **Operator keys** are published as a JWK Set history at the `jwks_uri` of `GET /`, by default `/.well-known/patchlog-keys` (§C.4). Namespace keys aren't listed there: their source is the namespace log.

- Two §C.9 questions are answered and removed.

- **v0.42:** signatures as implemented by the reference (§C.3.1).

- **Gate (§6.2):** signatures are checked at step 2.3, after the retry lookup and the verb, so a retry is answered as first recorded and authorisation failures are still reported first; the signed parent is the one the precondition names; a malformed `Signature` is `400`.

- **Grants:** the endpoint is offered in sealed namespaces, sealed with `pl: { ns, grant }`, and at E3 in the clear with `private` caching, so sealed and E3 bundles can carry grants; a purged namespace answers `410`; in public namespaces grants are public. Resource logs leave `grant` out where none was recorded.

- **Operator keys (§C.4):** the period is the operator's to declare, `from` no later than first use; the set is `application/jwk-set+json`.

- **Bundles (§G.4.1):** history lines name their grant; a line for a revision written in another namespace says where (`written`); how an exporter finds `key` is defined; malformed grant lines reject the bundle. Archives carry grants (§8.6).

- **Query parameters (§7):** a core endpoint accepts only those the spec defines, and flags only `1`; others are `400`. The bundle endpoint takes `authors=1`.

- **v0.43:** small fixes from implementing v0.42. A grant in a sealed namespace is sealed under the epoch of the first entry recording it (§C.3.1); repeated query parameters are `400` (§7); an operator key's `from` binds like its `until` (§C.4); a bundle line whose writing namespace is unknown carries neither `written` nor `grant` (§G.4.1).
