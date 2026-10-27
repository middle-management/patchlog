# Patch Log — Specification

Status: draft v0.73 · 2026-10-22. See Changes at the end, and CHANGELOG.md for the full history.

**Scope.** The core (§1–§13) specifies identity, validation, rules, the HTTP API, caching, deletion, namespaces, atomic batches and branches for collaboratively edited JSON documents. It is implementation-neutral. The addenda cover the rest:

- **Addendum A (suggested):** indexing.

- **Addendum B (suggested):** organising documents in separate catalog namespaces, and tree-derived access.

- **Addendum C (recommended):** capabilities and access.

- **Addendum E (optional):** encryption at rest, sealed delivery and end-to-end.

- **Addendum F (suggested):** working with branches: merge, rebase and cleanup.

- **Addendum G (suggested):** federation and portability: external consumers, remote branches, and export and import bundles.

- **Addendum H (suggested, non-normative):** files: how file tools, such as WebDAV gateways and mounts, store files, folders and names so they can share a namespace.

- **Addendum I (normative):** test vectors for the byte-exact definitions.

**Reading this spec.** MUST, SHOULD and MAY are used as in RFC 2119. Elsewhere in §1–§10, §12 and, for whatever implements them, the addenda not marked non-normative, a statement of what a server, service or tool does or answers ("a purged base is `410`") is a requirement as strong as MUST, and tables there are normative where they give statuses, codes, limits or shapes. §1 before its Conformance subsection, §11, §13 and sections marked non-normative or as examples are informative, except the rendering of §H.1, which binds tools that claim Addendum H (§I.10). Lowercase "must" states a condition that a check tests ("the grant must allow the action"), and when it fails, the answer is that check's. Terms listed in §2 and §2.1 are defined there.

---

## 1. Overview

A **resource** is an **append-only log of patch sets**, not a stored document. Each entry is a **revision** whose id hashes its parent id and its patches (§3.3). The document is *derived* by folding the patch sets from the first revision.

Validation is **opt-in per document**: a document with `$schema` validates against the immutable schema revision it names (§6.1); one without isn't validated. Schemas are themselves resources, and since `$schema` is content, the schema a revision was validated against is part of its hashed content.

Writes are compare-and-append on the head (`If-Match`): a stale writer gets `412`, pulls the new revisions, re-applies its patches and retries (§11).

Everything addressed by a revision id is immutable and long-cacheable; only the **head pointer** (a micro-cached redirect) and the **event stream** change.

An atomic **batch** changes several resources of one namespace. A **branch** is a namespace created from another at a point in its history: it reads through that snapshot, records only its own changes, and can later be applied to the original as one batch.

Large values, such as images, PDFs or long texts, are **blobs**: immutable bytes attached to a resource, served from their own immutable URLs, and referenced from its documents by id.

### Goals

- Multi-user editing with no silent overwrites.

- Every revision whose document declares a `$schema` is valid against it. Full history, independently verifiable.

- Schema-less documents are equally first-class for storage, caching and collaboration.

- CDN-first reads: the origin serves head pointers and writes, and not much else.

- Minimal moving parts.

### Non-goals (for now)

- Character-level real-time merging (OT/CRDT). Conflicts are resolved by rebase and retry, optionally guarded by JSON Patch `test` ops.

- Transactions across namespaces. A namespace is the unit of atomicity (§7.5).

### Conformance

- **A core server** implements §1–§10 and §12. The core refers to an addendum only for features a deployment offers; a server without one degrades as follows:

  - **Addendum C** (grants) is how the core authenticates (§6.2 step 1); a server running `"auth": "grants"` implements all of it. Without it, authentication is disabled (`"auth": "disabled"`, §7), for development only (§7.2): every request counts as holding a `*` key, so config guards, forced purges and the creation of namespaces and remote branches are open, and config writes skip namespace rules as `*`-key writes do (§6.4.3); resource writes are still checked. Namespace entries then record `"grant": null` (§7.4); grant references recorded earlier are still served. While `disabled`, checks that match `merge.authors` (§F.3, §F.6) match an entry with `grant: null` on its author's `sub` alone, and the janitor's `*`-key checks for `abandoned` and `superseded` accept it. Under `grants`, such entries count for no one. Entries without `grant` at all (§7.4) count for no one.

  - **Addendum E** (encryption) is optional, and so is each of its levels. A server without it refuses `encryption` in namespace documents, and one without a level refuses that level (`422`, `invalid`); the core's rules for the levels it lacks are then vacuous. A remote branch whose source is raised to a level its server lacks (§G.5.2) answers for every resource its source had at `at`, read through or written on since, and not purged since (§8.3), as for a failed fetch (`502`, `upstream`, §G.3), and refuses writes to them other than purges the same way, at step 2.1 of §6.2 (check 2 of §7.8 for uploads and copies), and so does each branch on that server whose base chain reaches it, for those of them it reads through or has written on since; a batch's local `source` takes no blobs from any of these resources (§7.8).

  - **Branches** (§7.6), and so draft schemas in branches (§6.1), are core. A server can refuse to create local branches: `branch` is then `403`, after verification (§C.2), and absent from `/principal`'s `can` (§7.4), and §6.1's draft lookup finds no candidate. Remote registration (§G.3) is unaffected.

  - **Addenda A, B, F, G and H** describe services and tools on the public API. A core server needs from them only the hooks the core defines: `remote` branch entries, the `export` verb, `source` in batches, `GET /`, the bundles that pruning archives to (§8.6: §G.4.1, and §G.5.1.1 where encrypted), their namespace-document members (§12.3) and `/principal`'s `catalog` (§7.4). Remote branches (§G.3) are optional: a server without them refuses a remote `base` (`422`).

- **Byte-exact definitions,** such as ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9) and padding buckets (§E.2.2), MUST agree between implementations. A conforming implementation reproduces the test vectors of Addendum I for each part it implements; some are still to come (§I.11).

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **Namespace** (`ns`) | A group of resources sharing a namespace log. It is itself versioned: its **namespace document** holds its configuration (rules, keys, limits). |
| **Config revision** | A revision of the namespace document, with its own content-addressed id. |
| **Resource** | A named, versioned JSON document inside a namespace, addressed `{ns}/{name}` (§3.6). |
| **Patch set** | An ordered array of JSON Patch operations (RFC 6902). |
| **Gesture** | The revisions one user action produced, possibly across several saves and resources of a namespace, grouped by an id the client chooses (§7.2). Used for undo and redo (§11.2). |
| **Blob** | Immutable bytes attached to a resource, stored and served apart from its documents, which refer to it with a blob reference (§7.8). |
| **Revision** | A resource log entry with patches (§7.1). |
| **Head** | The latest entry in a resource's log. |
| **Genesis** | The first revision of a resource created from nothing. Its parent is empty. |
| **Foreign parent** | The parent of the first entry, in a branch, of a resource it reads through: the base's head for that resource at the branch point (§3.3, §7.6). |
| **Tombstone** | A log entry marking the resource as deleted. It has no patches. |
| **Purge** | Irreversible removal of a resource's content. An administrative action. |
| **Namespace log** | An append-only, hash-chained log of pointer changes (`head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns`, `prune`) for a namespace. |
| **Horizon** | The oldest revision of a resource whose history is still stored in full. Below it, patch sets are dropped (§8.6). |
| **Batch** | Writes to several resources of one namespace, applied all or nothing and recorded as one namespace entry (§7.5). |
| **Branch** | A namespace created from a **base** namespace at a namespace revision `at`. It reads the base through as of `at` and records only its own changes (§7.6, Addendum F). |
| **Frozen** | A namespace that accepts no resource writes, batches with items, or blob uploads and copies, e.g. a merged or superseded branch (§8.4). |
| **Schema reference** | The top-level `$schema` string of a document: the URL of an immutable schema revision (§6.1). |
| **Typed document** | A document with `$schema`, which is validated. One without is **untyped**. |
| **Change envelope** | The JSON description of a write that rules are evaluated against (§6.4). |
| **Writes** | The JSON Pointers a patch set modifies (§6.4.1). |
| **Principal** | The verified identity behind a request: its id, groups, roles and attributes. |
| **Role** | A named set of verbs and rules in the namespace document. Grants refer to roles by name (§C.1.1). |
| **Grant** | A signed, narrowable capability token presented with a request (Addendum C). |
| **Namespace consumer** | A separate client that derives data from a namespace log, such as a search index (§10). |

### 2.1 Defined terms

- **Dependents** of a namespace: the namespaces whose `base` is this namespace and that aren't purged.

- **Edge prefix.** The scope of an edge grant (§C.5): `/r/{ns}/{name}`, `/r/{ns}` or `/ns/{ns}`, with names valid under §3.6. A prefix **covers** its own URL and everything below it, segment by segment, as RFC 6265 path matching does: `/r/demo` covers `/r/demo/x`, but neither `/r/demo-x/…` nor `/r/demox`. A service's prefix under its own root (§C.5.3) covers in the same way.

- **Effective roles** of a grant that carries roles, one with a block that lists `roles`: the roles its root block lists that every narrowing block listing `roles` keeps and that the configuration in force defines (§C.1.1).

- **Encryption level** of a namespace: its `encryption.level` (Addendum E), ranked none (no `encryption`) < `at-rest` < `sealed` < `e2e`. A **sealed** namespace is one at `sealed` (E2) only; one at `e2e` (E3) is **end-to-end**, and the spec names both where it means both.

- **Protection** of a namespace, for content moved between namespaces. **Invariant:** moving content never makes it readable, in the clear or by key, to anyone who couldn't read it at its source, unless a caller who can read it there writes it itself, as a merge does (§F.3), or an operator overrides one import. Reading a sealed source takes keys that open the content (§E.2.3). Within that bound, a move the caller's grants allow works within a namespace, between equal ranks and upward, except that only a key holder seals content into `e2e`, and an import keeps an `e2e` source's lines under its own name (§G.5.1). As a **source**, a namespace is `e2e` at E3, `sealed` at E2 whatever its `read`, and otherwise `public` or `private` by its `read`. A source whose protection isn't known, such as one missing from a bundle's `access` (§G.5.1), counts as `private`. As a **target**, a namespace has the same protection, except that a sealed namespace whose `read` is `public` is `public`. They rank `public` < `private` = `sealed` < `e2e`. A blob copy (§7.8), a remote branch's schema mirror (§G.3), a rebase's replay into its successor (§F.5) and, unless an operator overrides it for that import, an import (§G.5.1) never move content into another namespace that ranks below its source. Nothing else is ranked: branches follow §7.4, a batch's local `source` makes blobs available whatever the ranks (§7.8), and a writer may write what it can read wherever its grants allow, as merges do (§F.3). From a sealed source, public or not, and from an `e2e` one for a blob from before a raise from `sealed` (Addendum E, Levels), a blob copy or a batch's local `source` takes only a blob that opens, under an epoch it is served under there, fixed as a request for the blob would fix one (§E.2.2), with keys §E.2.3 gives there to the request's own grant or one in `Source-Authorization` (§7.5): a copy of any other is `404`, and a local `source` doesn't make it available (§7.8).

- **Fixes `/resource`.** A grant's rules fix `/resource` when a rule of its blocks or its key's scope, at top level or nested only in `all`s, tests `/resource` against one name (`value`), or against a finite set: a `schema` of only `enum`, or a `compare` with `in` and a literal array. `compare` with `eq` and a literal counts as `value`. Where several rules fix it, the names are those that satisfy all of them. An empty set, or any literal of a fixing rule that isn't a valid name (§3.6), even one the intersection drops, means the grant doesn't fix `/resource`. A key with `readScope: "resource"` (§C.4) requires every grant it signs that can allow `read` (§C.2 item 2) to fix it.

- **Qualifying role** (for edge grants, §C.5): an effective role that lists `read`, whose rules don't refer to `/now`, refer to `/resource` only if the grant fixes it, and pass now against a `read` envelope (§6.4.1) for the grant's principal, with `/resource` set to each name it fixes, or, if it fixes none, once.

- **Referrer** of a schema revision, in a namespace `N` that sets `schemaReads` (§6.1): an unpurged resource of a namespace that `schemaReads.for` lists, `N` included, whose head, or last live document if it is tombstoned, reaches the revision through `$schema` and the `$ref` closure. Only that namespace's own resources count, not what a branch reads through, and a schema document's own `$ref`s don't make it a referrer, as for the refusals of §6.1.

- **Unrestricted read** of a namespace: a grant has it when it may `read` there (§C.2 item 2), its key has no `readScope`, no rule in its blocks or its key's scope refers to `/resource`, and, if it carries roles, an effective role that lists `read` has no rule referring to `/resource`. Where a request needs it, only such roles count for `read`; branching and remote registration check it at gate step 1 (§C.2 item 2).

---

## 3. Identity

### 3.1 Input and canonical JSON

- **Input.** All JSON the API accepts MUST be I-JSON (RFC 7493). Servers MUST reject with `400` what it forbids in a request body other than a blob upload's (grants: §C.8), such as invalid UTF-8, duplicate object keys, lone surrogates and Unicode noncharacters, and:

  - numbers that overflow an IEEE 754 double, such as `1e400`

  - numbers whose canonical form (JCS) is an integer literal outside ±(2⁵³−1), i.e. integral values with 2⁵³ ≤ |v| < 10²¹, however they are written. Numbers whose canonical form has an exponent, such as `1e300`, are accepted, and a number that underflows is read as the nearest double, so `1e-400` is `0`.

- **Canonical form.** `canonical(v)` is the JSON Canonicalization Scheme (RFC 8785, JCS), encoded as UTF-8.

- **What is stored.** The server stores, serves and hashes `canonical(patches)`, never the bytes as received.

### 3.2 Id format

An id has two forms:

- **Binary form:** 20 bytes, hashed and stored.

- **Text form:** 33 characters, used in URLs, headers and JSON.

```
text(id) = "1" + base32lower(bytes(id))      -- 1 version char + 32 base32 chars
```

- `base32lower` is the RFC 4648 alphabet in lowercase (`a–z2–7`), with no padding.

- The leading `1` is a **version prefix** meaning *SHA-256 truncated to 160 bits, base32*. It is outside the base32 alphabet. A future format gets a new prefix, and old and new ids coexist.

- Ids (about 2⁸⁰ collision resistance) are **identifiers, not signatures**. Anything that needs cryptographic binding (author signatures, §C.3) uses the full digest.

### 3.3 Revision id

```
bytes(id) = trunc160( sha256( bytes(parent) ‖ 0x0A ‖ canonical(patches) ) )
```

- `bytes(parent)` is the parent's 20 bytes. For genesis it is empty (zero bytes).

- **Foreign parents.** In a branch, the first entry of a resource it reads through has a foreign parent instead (§2, §7.6). The formula is unchanged.

- `trunc160` keeps the first 20 bytes of the digest.

- Ids are **pure content hashes**, so uniqueness is scoped per resource. **An id determines its document everywhere:** identical ids denote identical documents, and replaying the same patch sets onto the same parent, in any resource or namespace, reproduces the same ids (Addendum F).

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

- A `purge` entry's `target` is the resource's head or tombstone as the namespace it is written in sees it, read through in a branch (§7.6).

- Ids *inside* `entry` are in text form. The namespace log API (§7.4) uses the same field names.

- Config revision ids use the revision formula (§3.3) over the namespace document's own chain.

- **Branch entries** are written in the **base's** chain (§7.6).

- **`source`** is hashed with the entry. `origin` is present only for a source in another deployment (Addendum G), as that deployment's canonical origin in the form of §C.3, and `ids` has at most one member per batch item, named by its resource. A `source` of any other shape is `400` (`bad_input`), a request-shape error (§6.2).

- **Batch entries** (§7.5) list the batch's config change first, if it has one, then one `head` or `tombstone` entry per resource, in request order, each with the resource's **final** entry. Intermediate revisions are in the resource logs.

- The chain hashes **ids only, never content**, so it stays verifiable after a purge.

- Config changes and resource pointers share **one** chain, which fixes the configuration in force for each write (invariant 6).

### 3.6 Names

- Namespace names MUST match `^[a-z0-9][a-z0-9_-]{0,63}$`. Without dots, `{ns}.{name}` can name a resource in another namespace unambiguously (Addendum B).

- Resource names MUST match `^[a-z0-9][a-z0-9._-]{0,127}$`.

- Hierarchy is data (Addendum B), never part of a name.

- URLs MUST use names verbatim; percent-escapes are `400` (§7).

### 3.7 Blob id

```
bytes(bid) = trunc160( sha256( "patchlog-blob-v1" ‖ 0x0A ‖ type ‖ 0x0A ‖ nonce ‖ 0x0A ‖ bytes ) )
```

- `type` is the upload's `Content-Type`, lowercased and without parameters, as `type/subtype` (`400` if it is missing or can't be parsed). Text blobs are UTF-8, which the server doesn't check.

- `nonce` is empty, or 26 base32 characters (128 random bits), as for `$nonce` (§C.7), hashed as ASCII.

- `bytes` are the blob's bytes as stored: the plaintext, or at E3 the client's ciphertext (§E.3.1).

- The text form is that of §3.2. Blob ids, like revision ids, are scoped per resource.

---

## 4. Invariants

- **Append-only.** Entries are never modified or removed, except by purge (§8.3, §8.5) and pruning (§8.6). Both remove content and keep ids and parent links.

- **Linear.** Each resource has exactly one first entry: a genesis, or in a branch an entry with a foreign parent (§7.6). Within a resource, every entry has at most one child: a head only moves to a child of the previous head. The same holds for each namespace chain and namespace document chain. Logs never fork.

- **Valid.** For every non-tombstone revision `r`: if `d = fold(genesis … r)` has a `$schema`, then `d`, without the members §6.2 step 5 leaves out, validates against the schema at that (immutable) reference. Re-validating any revision later gives the same answer, unless that schema revision, or one in its `$ref` closure, was purged (§6.1, §8.3) or pruned without a kept document (§8.6). At E3 readers check this, not the gate (§E.3.2).

- **Verifiable.** Anyone holding the entries can recompute every id and check every parent link. Below a pruning horizon, ids can be checked only against the archive, and the horizon's document is trusted as a snapshot (§8.6).

- **Ordered namespace log.** Every mutating request that takes effect (`create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `export`, `purge-ns`, `prune`, or a batch) writes exactly one entry in the chain of the namespace it addresses, atomically with the change it records.

  - An idempotent retry answered from the log (§7.2) writes nothing.

  - Entries the server writes itself, such as propagated purges (§8.3), are one per resource and namespace affected.

  - Creating a branch of a local base writes its `branch` entry in the base's chain, atomically with the first `config` entry of the branch's own chain. Creating a remote branch also writes the schema histories it mirrors (§G.3).

  - A batch writes one `batch` entry for all of its changes.

  - Blob uploads and copies (§7.8) write no entry.

- **Configuration in force.** A write is checked against the namespace configuration (rules, keys, revocations, limits, and in a branch its local bases' current keys and revocations, §C.4) at the head of the namespace chain **at the moment it is inserted**. That configuration is the namespace document recorded by the nearest `config` entry, or `batch` entry with a config change, before the write's own entry, or for a batch's items as §7.5 says. A namespace's creation, and a write to its document that changes what one of its own bounds limits, are held to the bounds of the document they produce (§6.6).

- **Fixed base.** A branch's `base` is set when it is created and never changes. Reads through a branch see the base exactly as of `at`, except that purges in the base propagate (§8.3) and the base's pruning applies (§8.6). For a base in another deployment, purges arrive as notices, which the branch's deployment SHOULD follow and MUST apply as it sees them (§G.3).

- **Referenced blobs.** Every blob that a stored document references is available to its resource (§7.8), and is kept as long as that document is. At E3 the server relies on the writers' declarations (§E.3.1), which readers verify.

---

## 5. Storage requirements

The core does not prescribe a storage engine. An implementation MUST:

- persist, for each entry, its id, its parent, its kind, `canonical(patches)` (until purged or pruned) in a form it is recovered from exactly, its author and `via`, the grant reference (Addendum C), a creation time, and the `gesture`, `undoes` and author signature it was written with, if any (§7.2, §C.3)

- persist an author, its `via` and a creation time for each namespace log entry, and the grant reference (§C.3) of each entry written on a request, with the grant's non-bearer form (none of these are part of its hash)

- persist each blob per resource with its type and nonce, and its uploader while it is pending, know which revisions reference it, and remove it on purge, after pruning, and when it stays unreferenced (§7.8). Blob bytes may live outside the database.

- enforce invariants 2, 5 and 6 atomically, including under concurrent writers and multiple processes

- serve the document at **any** revision id that isn't purged, or pruned without a kept document (§8.3, §8.6), outside end-to-end namespaces (§7.1), except revisions from before a raise to `e2e` (Addendum E, Levels) and a prune's sealed snapshot (§8.6). Materialised head and intermediate snapshots are strongly recommended.

- after purge, retain ids, parent links and namespace entries, and nothing else of the resource's content

- after pruning, retain what §8.6 keeps

- apply a batch atomically, holding invariants 2, 5 and 6 across all of its items

- for branches, persist `base` and answer "what was this resource's head as of namespace revision `n`?" for any resource and any `n` in a base's chain (§7.6)

- after a namespace purge, retain the namespace document chain, the namespace log and every resource's ids and parent links

How things are stored is the implementation's choice, compressed or encrypted (§E.1) included, as long as nothing observable changes: reads serve the exact canonical bytes, and ids and limits are computed over them.

---

## 6. Validation and rules

### 6.1 Schema references

-
**Opting in.** A document opts in by carrying a top-level `$schema`, which MUST be a string (`422`, `code: "schema_ref"`).

-
**Accepted forms.** `$schema` MUST match exactly

```
^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$
```

(a schema revision path on this service), or be the dialect URL `https://json-schema.org/draft/2020-12/schema`, which marks the document itself as a schema, validated against that dialect's meta-schema. Anything else, including head URLs, absolute URLs to this host, dot segments, query strings and percent-encoding, is `422` with `code: "schema_ref"`. No normalisation is applied. A schema stored under an earlier version is compiled as that version did.

-
**`$id`.** A schema document MUST NOT use the `$id` keyword in any subschema, nor `$schema` in any but its root (`422`, `invalid`). Validators MUST be registered and looked up **only** by revision path.

-
**`$ref`.** `$dynamicRef` MUST be a same-document fragment (`422`, `code: "schema_ref"`). `$ref` inside a schema MAY be a same-document fragment (`#…`) or a schema revision path in the form above, optionally with a fragment (`/r/schemas/common/rev/1…#/$defs/address`). A fragment that is empty or starts with `/` is percent-decoded and read as a JSON Pointer (RFC 6901, section 6); any other is a plain name, which an `$anchor` or `$dynamicAnchor` of the schema it reaches must define. Nothing else is resolved. A schema document's own `$ref`s resolve when it is written, at step 5 of §6.2; one whose fragment names nothing in the schema it reaches makes the schema invalid (`422`, `invalid`).

-
**Never into a branch.** `$schema` and `$ref` MUST NOT name a branch namespace (§7.6; `422`, `code: "schema_ref"`); a path naming a branch in which the writer can't read the revision is `schema_unavailable` (below), as for a namespace that doesn't exist. New schema revisions are written to a namespace that isn't a branch, even before a migration is merged (§F.1), or drafted in a branch of one (below).

-
**Schemas follow their documents.** A namespace `N` MAY set `"schemaReads": { "for": [ … ] }`, namespace names or prefixes ending in `*`, matched as `drafts.for` is (§7.4) but never against a branch; `N` itself always counts. A schema revision in `N`, one whose own `$schema` is a dialect URL, then:

  - resolves for a write to a listed namespace, or to a local branch of one, branches of branches included, whose document pins it through `$schema` or its `$ref` closure, without the `read` that resolving otherwise needs (below);

  - may be read by revision path, even under a grant that doesn't name `N`, or doesn't verify or can't read the revision there (§7), when the grant may read a **referrer** of it (§2.1) in a listed namespace the grant names, verifying under that namespace's keys and allowing a read of that referrer (§C.2), even where its `read` is `public`. A referrer in a listed namespace that is public, and neither sealed nor end-to-end, counts for every request, and a grant is then ignored, as for public reads (§7). So listing a public namespace makes public the schema revisions its documents reach through `$schema` and the `$ref` closure, though `N` stays private. A read under a grant carries it in `Authorization` (no edge cookie's path covers `N`). An edge that knows only prefixes forwards such a read to the origin, never refusing it, and the origin serves it `private`.

That is all it opens: never the schema resource's head, log or other revisions, a document that isn't a schema, or a draft in a branch (§7.6).

  - Anyone who may write to a listed namespace can pin such a revision once they know its id (ids aren't secrets, §C.5), so keep nothing in such schemas that only `N`'s readers may see.

  - It is `422` in sealed and end-to-end namespaces (Addendum E, Levels).

-
**Drafts in branches.** In a write **to a branch**, a path `/r/N/R/rev/X` that `N` can't resolve for the writer (`N` lacks it, or the writer can't read it there) is looked up in the branches of `N` (§F.9):

  - The candidates are the local branches of `N`, branches of branches included, that aren't end-to-end. In a candidate, only revisions it wrote itself count.

  - A candidate serves writes to itself and to its own branches, and to the namespaces its `drafts.for` lists (§7.4) and their branches: a write qualifies if the namespace written, or any namespace in its `base` chain, is listed. Each candidate is judged by its own `drafts.for`; branches of a candidate don't inherit it.

  - The writer needs `read` on `R` in the candidate, checked as for reading other namespaces (§7.5); a revision it can't read there counts as not found.

  - Any candidate that holds `X` will do (§3.3). The whole `$ref` closure resolves the same way.

  - In a namespace that isn't a branch, paths resolve only in `N`, so documents that use drafts can be merged into it only after their schemas have been (§F.9). A merge into a base that is itself a branch, as for a stacked release, may still resolve drafts. At E3, where the server doesn't validate (§6.2), this rests on the merging client (§F.8.1).

  - Clients and consumers that validate such documents try `N`, then the branches of a release document if there is one (§F.9), then those `GET /ns/{N}/branches` lists, recursively. This is best effort: only the server's check decides whether a write is accepted.

-
**Within a batch,** items may reference schema revisions created by earlier items (§7.5).

-
**Tombstoned schema resources.** Revisions of a tombstoned schema resource still resolve (§8.1), for new references too.

-
**Purged or unknown references.** A reference that is unknown, purged, pruned without a kept document (§8.6) or unreadable by the writer, or that names a tombstone, a document that isn't a schema, or a revision written while its namespace was end-to-end, which the server can't read (§E.3), is `422` with `code: "schema_unavailable"` and `path` the revision path that didn't resolve.

-
**Referenced schema revisions.** A schema revision is **referenced** when any of these names it by `$schema`, or reaches it through that schema's `$ref` closure:

  - the head, or the last live document if it is tombstoned (§8.2), of any unpurged resource in the deployment;

  - the head as of `at` of a resource a branch reads through, or its last live document then if it was tombstoned;

  - any revision a branch wrote, not only its head (a merge replays and validates every step, §7.5).

-
**Copies.** A reference is satisfied by a copy of the revision whose document is neither purged nor pruned: in `N`, or, for a document in a branch, in a branch it may resolve drafts in, judged structurally by the candidate rules above, never by any one writer's grants. A revision pruned in `N` counts as one `N` can't resolve.

-
**Refusals.** Unless forced (below), a server MUST refuse (`409`, `code: "in_use"`):

  - a purge, of a resource or a namespace, that would remove the last copy satisfying a reference, in any namespace it reaches, branches it propagates to included (§8.3);

  - a config write that would leave a reference without a copy, such as narrowing `drafts.for`.

The answer lists, as `referencing`, the referencing namespaces in which the caller may read anything, judged as for reading other namespaces (§7.5). At E3 the server can't see references (§E.3.2).

-
**Forcing.** A refused purge can be forced: `?force=1` on the purge request, with a grant chained to a deployment operator key, or, for a purge of a branch or of a resource in one, to a `*` key of that branch, inherited or its own; under any other grant, `?force=1` is `403` at step 1 of §6.2, whether or not the purge needs it. A forced purge knowingly breaks invariant 3 for the referencing documents, and its entries carry `forced: true` (§3.5).

-
**Read permission.** Resolving a `$schema` or `$ref` requires the writer to have `read` on the copy it resolves to: in the schema's namespace, or in the branch holding a draft (Addendum C), judged as for reading other namespaces (§7.5) where that isn't the namespace written, unless that namespace opens it with `schemaReads` (above). From a sealed namespace, public or not, and from an end-to-end one for a revision from before a raise from `sealed`, it also takes keys that §E.2.3 gives there, for the epoch the revision is served under, fixed as a read of it would fix one (§E.2.2), to the request's own grant or one in `Source-Authorization` (§7.5, §2.1 Protection), in the namespace written too; without them the revision is unreadable by the writer (`schema_unavailable`, above).

-
**Validator cache.** Compiled validators MAY be cached by revision path, forever and across namespaces, drafts included (§3.3).

### 6.2 On write

The order of checks at the gate is normative. Only errors in a request's own shape, which no state influences, may come before step 1: malformed names or URLs, content types, header and body syntax, and the size of what is read (`400`, `413`, `415`), unless an endpoint fixes its own order, as blob uploads do (§7.8). A batch body cut off as §7.5 says, by the verified principal's `batchSize`, is `413` once the grant is verified, before its verbs are checked. Everything else follows this order:

- **Authenticate and authorise** the request (Addendum C): `401` or `403`. This covers the verbs and the grant, key-scope and role rules that refer only to `/action`, `/resource`, `/principal` or `/now`, as §C.2 says. Rate limits (§6.6) are checked last in this step, only for requests that passed it: `429`.

- **Precondition** (§7.2), in this order:

  -
the idempotent-retry lookup (§7.2), with its verb check (§C.2 item 2). It doesn't apply to a purged resource, which answers `410` (§8.3), nor in a purged namespace, where every write is `410` with `code: "purged"` at this point, before any later check (§8.5), nor to a resource that §1 has a branch answer `502` for, whose writes other than purges are `502` at this point.

  -
for a `PATCH` with `If-Match` (in a batch, an item whose first step is a patch set under `ifMatch`), settle the verb from the resource's state as the writer sees it:

    - a tombstoned head makes it a restore, a live one an append, and a resource with no head an append

    - a purged resource answers `410`, whichever the verb

    - in a branch, the state is the branch's view (§7.6): a resource read through settles by the base's head as of `at`, and a tombstone there makes the first write a restore, with that tombstone as its foreign parent

A settled verb that isn't a candidate (§C.2 item 2) is `403` here, before the `If-Match` comparison, and counts as failing authorisation, for §7.5's failure report and for the dry run.

  -
author signatures (§C.3.1): `422` with `code: "signature"`. They need no head: the signed parent is the one the precondition names.

  -
a frozen namespace: `409` (§8.4)

  -
the precondition itself: `428`, `412`, or `410` on a tombstoned resource (§7.2), and in a batch `422` for a `"delete"` that follows a `"delete"` (§7.5)

- **Apply** the patches to the parent's document, `null` for a create, with operation validation; a failing `test` is `422`. A delete skips steps 3–5. In a namespace that requires nonces, a resource create, append or restore is then checked for a fresh `$nonce` (§C.7): `422 nonce`.

- **Limits** (§6.6) and **blob references** (§7.8), after the namespace document a config write or a branch's creation results in is validated as §7.4 says, and a prune's `horizon`, `keep` and `snapshot`, and at E3 its archive, are checked as §8.6 says (`422`, `invalid`, or `limit` for a limit such as `keepPerResource`): every reference in the resulting document is well-formed and names a blob available to the resource, `422` otherwise.

- **Schema.** If the **resulting** document has `$schema`, resolve it (§6.1) and validate it against JSON Schema draft 2020-12, with format assertions for the formats it defines; a schema naming any other `format` is invalid, as an unknown keyword is (§6.5). The instance validated is the document without its top-level `$schema`, a top-level `$nonce` of the fresh form (§6.4.1), and a top-level `$successor` of the form of §8.1, so a closed schema needn't declare them, and no schema can constrain them; a `$nonce` or `$successor` of any other form is validated as data. Failure is `422` with `{ pointer, message }` errors.

- **Rules.** The `*`-key guard (§C.2), then a config write's `in_use` refusals (§6.1, §7.4), then grant, key and role rules (§C.2 item 4), then namespace rules (§6.4), evaluated against the configuration in force (invariant 6); in a batch, each of these for every item before the next for any.

- **Hash and insert** atomically, together with the namespace entry.

For a batch (§7.5), each step, and each sub-step of step 2, runs for **every item** before the next starts, and step 7 inserts all items in one atomic operation.

**End-to-end namespaces (§E.3).** For `create`, `append` and `restore` in an `e2e` namespace, of any resource but `keyring` (§E.3.2), step 3 accepts a patch set of one reserved `sealed` op that passes the checks of §E.3.1, or `[]` for a restore, and doesn't apply it; anything else is `422` (`invalid`). Step 4 checks the blobs the op declares (§E.3.1). Step 5 is skipped. Any namespace, grant, key or role rule whose outcome depends on a `writes` predicate, or on a `/writes` or `/doc` path, fails as a whole for these writes (`422` or `403`); one that passes, or fails, whatever they would give is decided as usual. Config, branch and prune writes are checked as usual, and so is a delete, except that its `doc` is null, so a rule whose outcome depends on a `/doc` path fails as a whole for it too.

### 6.3 Changing type

- **Adding** `$schema` to an untyped document is an ordinary patch; the whole document must validate.

- **Changing** `$schema` is an ordinary `replace /$schema`, usually in one patch set with the data changes the migration needs; the result must validate against the new schema.

- **Removing** `$schema` makes the document untyped from that revision on. Namespaces can forbid this with a rule (§6.4.4).

- Tombstones are not validated, nor is the document a delete removes, which rules see as `/doc` (§6.4.1).

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
  "doc":       { … },                          // the resulting document; for delete, the document deleted; null for purge and purge-ns; { remote, at } for export; { horizon, keep? } for prune, as sent
  "patches":   [ … ]                           // canonical patch set; [] when there is none
}
```

-
**`writes`** is computed by the server. For each operation:

  - `add`, `replace`, `remove`, `copy` write `path`

  - `move` writes **both** `from` and `path`

  - `test` writes nothing

  - A root operation, a genesis `add ""` included, writes `""`.

  - A delete's `writes` and `patches` are `[]`. So `within` (§6.4.2) restricts neither deleting nor a restore with `[]`: limit both by verb, e.g. narrowing blocks that drop `delete` and `restore` (§C.6), or by rules on `/doc`.

  - An array append `…/-` is recorded with the resulting index.

  - An `add`, `copy` or `move` into an array at an index below its length, and a `remove` or `move` of an element that isn't its last, shift the elements after it, so they also write the array itself.

  - In resource envelopes only, an `add` or `replace` at exactly `/$nonce` whose value is 26 base32 characters (`^[a-z2-7]{26}$`, a fresh nonce, §C.7) is left out. Any other operation at or below `/$nonce` (a `remove`, a `move` or `copy` to or from it, a deeper path, another value) is a write as usual.

Pointers are compared **segment by segment after RFC 6901 unescaping**, never as strings.

-
**`doc`** is the document as it will be stored if the write succeeds. For a delete it is the document being deleted: the resource's last live document as the target namespace sees it, read through its bases in a branch (§7.6), or, in a batch, the document after the item's earlier steps; a replay of a delete (§F.3, §G.4.4) is judged against the document the target has at that step. For `config` it is the resulting namespace document. For `branch` it is the new branch's namespace document, and the envelope is evaluated in the **base** namespace (§7.6). In an end-to-end namespace `doc` is null for `create`, `append`, `restore` and `delete` of every resource but `keyring` (§E.3.2), and a rule whose outcome depends on a `/doc` path fails the write (§6.2).

-
**Batches** produce one envelope per patch set, with the ordinary actions. There is no `batch` action.

-
**`principal`** comes from the grant (§C.1). `groups` and `attrs` are taken from its root block, and `roles` lists its effective roles (§2.1). `attrs` is an object of issuer-asserted attributes, `{}` when there are none, and `groups`, `roles` and `via` are `[]` when there are none, `roles` for a grant without roles too.

-
**`now`** is the server's clock at the gate, RFC 3339 UTC with millisecond precision, read once per request.

-
**`read`** envelopes are used only to evaluate grant and role rules on reads (§C.2, item 5). They carry `action`, `resource`, `principal` and `now`, and no `writes`, `doc` or `patches`.

-
There is deliberately no previous state in the envelope. Rules judge the resulting document and the change itself; for a delete, the document it removes.

-
**What rule failures reveal.** A failing rule on `/doc` tells the writer something about the document, a deleted one included; namespaces that care grant `delete` only with `read`.

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

- A `schema` is a JSON Schema draft 2020-12 fragment, applied with format assertions as at step 5 of §6.2, held to §6.1's `$id` ban, §6.5 and §6.6 like a schema document, with no `$schema` keyword in any subschema, whose `$ref` and `$dynamicRef` are same-document fragments only: otherwise a namespace document is `422` (`invalid`), and a grant invalid (`401`).

- `within` is true when there are no writes. `covers` and `overlaps` are false when there are none.

- **Path policy MUST use the `writes` predicates**, never patterns over `/patches/*/path`. Those miss `move.from`, root writes and escaping.

- **`compare`** relates a value in the envelope to a literal (`value`) or to another value in the envelope (`path`).

  - `lt`, `le`, `gt`, `ge` compare two numbers, or two RFC 3339 `date-time` strings as instants, at the full precision of their fractional seconds; one with a leap second (`:60`) is of an unsupported type.

  - `eq` is RFC 6902 equality. `in` is true when the left value equals an element of the right-hand array, and false when the right-hand side isn't an array.

  - A missing path on either side makes `compare` false, and so do operands of different or unsupported types for `lt`, `le`, `gt` and `ge`.

#### 6.4.3 Evaluation

- Rules run at step 6 of §6.2, in order, and all must pass.

- A failing namespace rule is `422` with `{ "code": "rule", "rule": <index>, "path": <pointer> }`, where `path` points at the failing rule form in the namespace document, such as `/rules/3/then/0`, descending only through the first failing member of an `all` or a `then`. A failing grant, key or role rule is `403` with `code: "forbidden"`.

- Rules apply **only at write time**, and at read time for grant, key and role rules. Changing them never invalidates existing history.

- **Config writes are rule-checked too.** Namespace rules also apply to `config` writes, except for principals whose grant chains to a key with `can: ["*"]`, and for a namespace's creation under the operator grant that creates it.

- **Operator overrides.** A purge or namespace purge forced past an `in_use` refusal under a deployment operator grant (§6.1) isn't judged by namespace rules either. A purge forced with a `*` key of the branch, inherited or its own, is still judged, and so is any purge while authentication is disabled (§1).

- **Except as above, rules see every action,** including `delete`, `purge`, `config`, `branch` (evaluated in the base) and `purge-ns` (`doc` as in §6.4.1). Rules about documents should be scoped with `if` on `/action`, as in §6.4.4, and rules about a document's shape should exempt `delete`, or a document written under earlier rules can't be deleted.

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

- once typed, `$schema` can't be removed, including by a root replace or a restore written as one

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

Without the `editor` role, a principal may only create, edit, restore or delete documents it owns, in one of its regions. After creating a document, it can never reassign ownership or touch the lock, and cannot edit or delete after `lockAt`.

**The pattern for fields that policy depends on.** Such a field is protected by forbidding writes to it (`writes overlaps`, which also catches root replaces and `move`), not by comparing old and new values: "can't change `/owner`" plus "`/doc/owner` is me" means "it was already mine". Every create writes `""`, which overlaps every path, so such rules must exempt `create` and test the created document instead. A delete writes nothing, so decide deletes by testing `/doc`. A restore with a root replace also writes `""`; exempt it only where a test of the resulting document is enough on its own, such as "no `$access`" (§B.11.3). Keep restores under the overlap rule for ownership fields, as the example does, or a non-owner could restore someone else's document with itself as owner.

### 6.5 Reserved keys and extension keywords

- **Reserved keys.** Top-level document keys starting with `$`, other than `$schema`, are reserved for conventions (e.g. `$access` in Addendum B, `$nonce` in §C.7, `$successor` in §8.1). The core stores them like any other data and never interprets them, except that a fresh `$nonce` is left out of `writes` (§6.4.1) and can be required (§C.7), and a well-formed `$successor` is read into a deleted resource's `410` (§8.1). Validation leaves both out (§6.2 step 5). Namespace rules may constrain them.

- **`$blob`** is reserved at any depth, not only at the top level: an object whose `$blob` member is a string is a blob reference (§7.8), and must be well-formed (`422`). Schema documents and namespace documents aren't searched for references.

- **`x-*` keywords.** Schema keywords starting with `x-` are annotations, ignored by the core validator and meaningful only to namespace consumers (e.g. `x-index` in Addendum A). Any other unknown keyword makes a schema invalid, `dependencies`, `$recursiveAnchor` and `$recursiveRef` included; `definitions` holds subschemas, as `$defs` does. In a schema document, a top-level `$nonce` or `$successor` that step 5 of §6.2 leaves out isn't a keyword: it is left out before the document is checked against its dialect and compiled.

- **`x-ref`** marks a string that references another resource, for tools such as exporters (§G.4.2) and reverse-reference indexes (§A.4).
```
"hero":    { "type": "string", "x-ref": { "pinned": true } },   // "/r/media/photo-12/rev/1q…": exactly that revision
"related": { "type": "array", "items": { "type": "string", "x-ref": {} } },  // "/r/matches/cup": whatever is the head
"trigger": { "type": "string", "x-ref": { "key": "/triggers" } }            // "/r/doors/layout-7#t-42": one entry of layout-7
```

  - Its value is `{ "pinned"?: boolean, "key"?: pointer }`.

  - A pinned reference is a revision path in the form of §6.1. A live reference is a resource path `/r/{ns}/{name}`.

  - **Entries inside a document.** With `key`, a reference names one entry of the target document: `/r/{ns}/{name}#{id}`, or pinned `/r/{ns}/{name}/rev/{rev}#{id}`. `key` is a JSON Pointer into the target document, to either an array of objects with a string `id` member or an object whose member names are the ids. `{id}` is matched against those ids, never against array positions. It is percent-encoded as a URI fragment. A reference whose entry doesn't exist is dangling, like one to a missing resource.

  - **Finding references** is a static walk, not annotation collection during validation. Walk each document, without the members validation leaves out (§6.2 step 5), together with its schema, and at every instance location consider every subschema that could apply: through `$ref`, `properties`, `patternProperties`, `additionalProperties`, `items` and `prefixItems`, **every** branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, and any other keyword that applies a subschema. A string at a location where any of them carries `x-ref` is a reference if it has the form above, even if that subschema didn't validate.

  - The core doesn't check it. A schema can enforce the form with `pattern`.

### 6.6 Limits

-
**Configurable limits.** Every namespace has limits, set in the namespace document under `limits` (§12.2: keys, defaults, value formats). Config writes, a batch's `config` change and a branch's `patches` are held to the patch-set and document limits as resource writes are, a namespace's creation counting as a create, and their bodies are cut off as a resource `PATCH`'s are.

-
**Exceeding a limit** is `413` where a request is refused before or while it is read (below, §7.5, §C.8), or where §7.8 says so, and `422` otherwise, with `code: "limit"`, `limit` naming its key, and, for sizes and counts, `measured` and `max`. Where the server stopped reading an oversized body, `measured` is a lower bound, counted in body bytes, and before step 1 of §6.2, `max` is the deployment's. For `pathSize` and `valueSize`, `measured` is the first value found too long, quotes included; for `branchesPerNamespace`, the base's live branches with the new or unfrozen one; for `blobPending`, the pending bytes with this blob, each counted as at least 4 KiB; for a blob without `Content-Length`, `blobSize` + 1. Durations and rates give `limit` alone. For a limit on the resulting document (`documentSize`, `nestingDepth`, `valueSize`, `pathSize`, `blobsPerDocument`), `measured` is left out for a grant that can't read the resource. Bodies of endpoints that have no limit of their own (prune, `/keys`) are `400` (`bad_input`) above 1 MiB, and a resource `PATCH` body more than four times the larger of the deployment maximums of `patchSetSize` and `documentSize` is `413` before parsing, naming `documentSize` with the deployment maximum, and a batch body cut off as §7.5 says names `batchSize`, with the verified principal's as `max`. Clients tolerate a refusal without `measured`.

-
**Whole documents.** The patch set of a create, and of an append or restore whose first operation other than `test` is a root `replace` or `add` (§8.2), further operations allowed after it, may be as large as `documentSize` instead of `patchSetSize`. At E3 every create and restore gets that bound, and appends stay within `patchSetSize`. In a batch they still count toward `batchSize`. Every other patch set, one that starts with a root `copy`, `move` or `remove` included, stays within `patchSetSize`.

-
**Values.** `valueSize` and `pathSize` keep every string replaceable by one ordinary append, together with a `test` of its old value (§11), whichever write stored it, sealed or not. Sealing at E3 grows a patch set by about half, so a namespace's creation, a branch's included, and a config write that changes `limits` or `encryption` are `422` (`code: "limit"`, `limit: "patchSetSize"`, `measured` the left side and `max` the `patchSetSize`) unless, in the configuration they result in, `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize`. In a namespace that configuration makes E3, the left side adds `36 B × blobsPerDocument`, for the declared blob list (§E.3.1). Larger values belong in blobs (§7.8).

-
**Rate limits** are token buckets: the rate refills the bucket, and the burst is its size. They are checked at the end of step 1 of §6.2.

  - **Buckets are keyed by the root `sub` and the key that signed the root block** (`kid`, §C.1), never by `via`, which any holder can set in a narrowing block. The per-resource bucket is per resource *and* principal, and the namespace bucket bounds all writers together.

  - **Exceeding one** is `429 Too Many Requests` with `Retry-After`, `code: "rate"`, `limit` naming a bucket that was hit (a §6.6 key, `allowance` or `allowance.blobRate`), and `retryAfter`, the wait in seconds, as a decimal number, until every bucket it draws on holds a token. `Retry-After` is whole seconds, rounded up.

  - **Dry runs** (§7.5) draw tokens as the submit would.

  - **Cost.** A request is admitted while every bucket it draws on holds at least one token, and its cost is then deducted, even below zero. The check and the deduction are one atomic step across every instance that shares the store, and with the write where there is one. A request refused after admission keeps its deduction. A batch costs one token per resource it touches from each per-resource bucket, and one token per item from the principal and namespace buckets; its `config` change, if any, costs one token from the principal and namespace buckets unless it is exempt (below), as a config write does. A blob upload (§7.8) costs one token from the per-resource, principal and namespace buckets, and its size from the principal's `blobRate` bucket. Any other write that isn't exempt costs one token from the principal and namespace buckets of the namespace whose chain records it, the base's for a branch's creation, and a resource write or a prune one from its per-resource bucket too.

  - **Exempt:** config writes under a `*` key, config writes whose `writes` are non-empty and all at `/frozen`, `/successor` or `/merged` and whose resulting document has `frozen: true`, purges, and entries the server writes itself (purge propagation, §8.3).

  - A key scope may lower the per-principal rate for the grants it signs (§C.4).

-
**Allowances.** A namespace document may give a named principal (root `sub` and signing `kid`) its own budget:

```
"allowances": [ { "sub": "svc:importer", "kid": "ops-2026",
                  "bucket": { "rate": 100, "burst": 20000 },   // writes per second, and bucket size
                  "itemsPerBatch": 20000, "batchSize": 67108864,      // 64 MiB, in bytes as in `limits`
                  "blobRate": { "rate": 67108864, "burst": 1073741824 }, "blobPending": 17179869184,   // above the defaults
                  "until": "2026-10-08T00:00:00Z" } ]
```

  - That principal's writes and uploads (§7.8) draw on the allowance's own bucket instead of the principal and namespace buckets (an allowance also replaces a key scope's lower `rate`); per-resource buckets still apply. Its batches may be as large as the allowance says. An allowance may also set `blobRate` and `blobPending` for that principal. Allowances never exceed the deployment maximums, `bucket` that of `ratePerNamespace` and the rest those of their own limits, which the example needs raised: one set above them is `422` (`code: "limit"`), and one stored before a maximum was lowered is held to it.

  - While authentication is disabled (§1) there is no `kid`, so buckets are keyed by the author, and an allowance matches the author's `sub` alone. Either way, the first matching entry whose `until` hasn't passed applies.

  - `until` (optional) is an absolute RFC 3339 time. The allowance applies only while `now` (§6.4.1) is before it, and is ignored afterwards until an administrator removes it. Allowances for an import or a release should set one.

  - This lets a large import or release land as **one** atomic batch without holding up other writers; paced batches aren't atomic and suit backfills only (§G.4.4).

  - A large batch still holds the namespace's sequencer while it inserts, so `itemsPerBatch` is chosen with that in mind.

-
**Deployment defaults and maximums.** A deployment sets a default and a maximum for every limit, the defaults of §12.2 unless it says otherwise, and a namespace may set any value up to the maximum, except for limits marked deployment only in §12.2. The retry window also has a deployment minimum. A write that sets a value above the maximum, or a retry window below the minimum, is `422` (`code: "limit"`); a value stored before the maximum was lowered is held to it, as allowances are. A namespace's own bound, such as a lowered `rulesPerNamespace`, holds its creation and every write that changes what it bounds, a write that lowers a count still over the bound included, which is refused, so the namespace is brought under its bound in one write; other writes, freezes included, still pass a document an earlier release stored over it.

-
**Regular expressions** in rules, grants, key scopes and schemas MUST be evaluated with RE2 syntax and semantics, which match in linear time, reading `\uXXXX` as `\x{XXXX}`, a surrogate pair of such escapes as the one code point it encodes, and a lone surrogate as a pattern RE2 doesn't accept; the `regex` format asserts the same syntax. A pattern RE2 doesn't accept, such as one with backreferences or lookaround, makes a schema or config `422` (`invalid`) when written, and a grant that carries one invalid (`401`).

---

## 7. HTTP API

- **URLs.** Resource URL: `/r/{ns}/{name}`. Namespace URL: `/ns/{ns}`. A path other than `/` with an empty segment (`//`, or a trailing `/`), a `.` or `..` segment, or any percent-escape is `400` (`bad_input`); names never need escapes (§3.6). Ids appear in text form (§3.2); one that isn't, in a URL, a write's precondition other than `If-None-Match: *`, `Last-Event-ID` or a request field such as `ifMatch` outside a namespace document (§7.4), is `400` (`bad_input`), a request-shape error (§6.2). In `ETag`, `If-Match`, `If-None-Match` and `If-Range` an id is quoted as a strong entity tag, e.g. `"1q3fa9…"`, and a write's precondition is one such tag or `If-None-Match: *` (`400`, `bad_input`, for `If-Match: *`, a weak tag or a list); a sealed `ETag` adds `.{e}` (§E.2.2), which a write's precondition leaves out. In `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Log-Next` and `Last-Event-ID` it is unquoted, as in URLs.

- **`GET /`** answers `{ "origin": "https://cms.example", "spec": "0.73", "auth": "grants" }`: the deployment's canonical origin (§C.3), the spec version it implements, as dotted decimal numbers compared component by component (`0.38`, `0.38.1`), and whether authentication is on (`grants`) or `disabled` (§1). Addendum C adds `jwks_uri` (§C.4). The version is informational: a client, peer or tool MUST NOT refuse a deployment on the version alone; it learns what is offered from the endpoints (`404 not_offered` for an optional one, a plain `404` from an older server) and a namespace's settings from `GET /ns/{ns}/principal` (§7.4).

- **Query parameters.** An endpoint accepts only the query parameters this spec defines for it, each at most once unless defined as repeatable (in the core, only `prefix` of `DELETE /edge-grants`, §C.5.4), and flags such as `force` and `dry-run` only the value `1`. Anything else, a repeated parameter included, is `400` (`bad_input`, not cached), a request-shape error (§6.2). Services of the addenda define their own. An edge that verifies signed-URL grants (§C.5) strips their parameters before forwarding, and passes the grant on as the cookie it stands for (§C.5.3), which the origin verifies as any cookie.

**Browsers.**

- Writes (`PATCH`, `PUT`, `POST`, `DELETE`) and requests with `Authorization`, `If-Match`, `Source-Authorization`, `Signature` or a JSON Patch `Content-Type` need a CORS preflight, cached per URL.

- A deployment serving browsers answers preflights with those methods and headers, plus `Gesture`, `Undoes`, `Blob-Nonce`, `Blob-From`, `X-Author`, `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range` and `Last-Event-ID`, allowed; exposes `ETag`, `Location`, `Repr-Digest`, `Retry-After`, `Content-Range`, `Gesture`, `Undoes`, `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Cursor` and `X-Log-Next`; and sets `Access-Control-Max-Age`.

- Responses that vary by origin carry `Vary: Origin`. A deployment that allows every origin, and names no credentialed origins (§C.5.2), sends `Access-Control-Allow-Origin: *` and its exposed headers on every response, with or without `Origin`.

- Clients should read public namespaces without `Authorization`, which would need a preflight for every long-poll interval (§7.7) and every revision URL.

- `EventSource` can't send `Authorization`, so SSE in browsers uses edge grants as cookies (§C.5), which need `Access-Control-Allow-Credentials` and a named origin, or a streaming `fetch`.

**Private namespaces and existence.** Requests are answered in this order, which hides a namespace's existence; those to private namespaces follow Addendum C:

- **Reads of a public namespace**, other than `GET /ns/{ns}/principal` (§7.4) and `POST /ns/{ns}/keys` (§E.2.3), ignore any grant and answer exactly as unauthenticated ones, with content or `404`. Only these, and the schema revisions a public referrer opens (§6.1), answer unauthenticated requests with content or `404`.

- **The `ns` check.** With a grant, the server first reads `ns` from its blocks, before looking up any key: a namespace not named in `ns` by every block that carries `ns` (the root block always does; `"*"` names every namespace) answers `403` without being consulted, whether or not it exists, except for a schema revision it opens with `schemaReads` (§6.1).

- **Verification.** Only then is the grant verified against that namespace's keys, or the deployment operator keys when the root `kid` names one (§C.4). Without valid credentials the answer is `401`, alike for a namespace that doesn't exist and one whose `read` isn't `public`, unless the request is for a schema revision a referrer opens to it (§6.1), which this step and the next never refuse.

- **Resources.** Without `read`, a resource that exists and one that doesn't both answer `404`.

Writes, `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`, and every request to a namespace that isn't public or doesn't exist, keep the `403` and `401` answers of steps 2 and 3. Namespace names share one space and are not secret (§E.4): creating a namespace or branch with a taken name reveals that it is taken.

### 7.1 Reads

| Request | Response | Cache-Control (public namespace, §9) |
|---|---|---|
| `GET /r/{ns}/{name}` | `302` with `Location: /r/{ns}/{name}/rev/{head}` and `ETag: "{head}"` | head pointer |
| same, never existed | `404` | short |
| same, tombstoned | `410` with `{ "tombstone": id, "last": lastRevisionId, "successor"? }` and `ETag: "{tombstone}"` (§8.1) | head pointer |
| same, purged | `410` | long |
| `HEAD /r/{ns}/{name}` | as `GET`, no body | as `GET` |
| `GET /r/{ns}/{name}/rev/{id}` | `200` with the document at `id`, `ETag: "{id}"` (`"{id}.{e}"` when sealed, §E.2.2), `X-Revision: {id}`. In a namespace that is neither sealed nor end-to-end, also `Last-Modified`, the revision's `created` as an HTTP date (to the second), and, without content coding, `Repr-Digest` (RFC 9530) of the document, served as canonical JSON (§3.1); sealed and end-to-end reads carry neither (§E.2.2). Honours `If-None-Match`, and `If-Modified-Since` when `If-None-Match` is absent and `Last-Modified` is sent, with `304`; elsewhere `If-Modified-Since` is ignored, so it can't probe a hidden time (RFC 9110, section 13.1.3) | immutable |
| same, `id` is a tombstone | `410` | immutable |
| same, unknown `id` | `404` | short |
| same, purged | `410` | long |
| same, below the horizon, without a kept document (§8.6) | `410` with `{ "code": "pruned", "horizon": id, "archive"?: url }` | pruned |
| `GET /r/{ns}/{name}/blob/{bid}` | `200` with the blob, `206` for a range; `404` if pending or unknown, `410` if pruned or purged (§7.8). In sealed namespaces, and at E3 for blobs from before a raise from `sealed` (Addendum E), `302` to `…/blob/{bid}/e/{e}` (§E.2.2) | immutable (a `404` as short, a `410` as pruned, or as long where the resource is purged; the `302` as a head pointer) |
| `GET /r/{ns}/{name}/raw`, `GET /r/{ns}/{name}/rev/{id}/raw` | for a **raw** document (§7.8): `302` to `…/blob/{bid}`. Unknown, pruned, purged and tombstoned ids and heads answer as the matching document URL does; a document that isn't raw is `404` (`not_found`). In sealed or end-to-end namespaces, `404` with `code: "not_offered"`, after the read check, which is the document's (§7.8) | as the document URL it stands for (head pointer or immutable), for its `302` and both `404`s, with its tags |
| `GET /r/{ns}/{name}/blob/{bid}/e/{e}` | sealed namespaces, and at E3 blobs from before a raise from `sealed`, only: `200` with the blob sealed under epoch `e`, `206` for a range of the sealed bytes; `404` for an epoch it isn't served under, or `410` where §E.2.2 says. In other namespaces, and for other blobs at E3, `404` with `code: "not_offered"`, after the resource's read check (§7.8) | immutable (the epoch `404` `no-store` and its `410` as pruned, §E.2.2; the `not_offered` `404` as short) |
| `GET /r/{ns}/{name}/rev/{id}/log?since={a}` | `200` with the entries after `a` (exclusive) up to `id` (inclusive); an empty or omitted `since` means from genesis. `404` if `id` is unknown, or `a` is neither `id` nor an ancestor of it; `since={id}` is an empty range. `410`, as for a revision below the horizon, if any revision after `a`, up to `id`, has its patch set pruned and not restored from an archive; `a` itself may lie below the horizon. Paged as below | immutable (a `404` as short, a `410` as pruned, or as long where the resource is purged) |

**Paging.** A log range longer than the log page size (§6.6), counting a batch entry as its items, or whose patch sets exceed `logPageBytes`, or that spans an `e2e` raise (Addendum E), answers its first page only: a page ends before an entry that would take it past either bound or across the raise, but always holds one, so a batch larger than a page is a page of its own. At E2, `logPageBytes` counts each entry's sealed bytes as served; a range sealed again with other bytes (§E.2.2) may end its pages elsewhere. Pages are oldest first, with the header `X-Log-Next: {id}`: the last entry returned, which is the `since` of the following page, an immutable range up to the same `id`. A client reads pages until the last entry it received, or the `since` of an empty range, is the URL's `id`; a missing `X-Log-Next` before that is an error.

- A page that reaches the URL's `id` needs no `X-Log-Next`. Every page is a correct prefix of its range.

- `404` and `410` are judged over the URL's whole range.

- The sealed snapshot of an E3 prune (§8.6) is served as `/rev/{H}`, never as a log entry, except where `H` is from before a raise to `e2e`, which is served as before (Addendum E, Levels). What `/rev/{id}` serves at E3 for other revisions written at `e2e` is an open question (§13).

- **Continuations.** Every paged answer names how to continue: log ranges in `X-Log-Next` (the next `since`), `/heads` in its body's `next` (the next `after`), the gestures listing in `X-Log-Next` (the next `after`). A client passes the value back exactly as given.

- Long-poll answers (§7.7) use the same page limits but carry no `X-Log-Next`: their `X-Revision` or `X-Namespace-Revision` already names the next `since`.

- Sealed pages (§E.2.2) carry their own bounds.

Log entry shape (patches in canonical form):

```
{ "id": "…", "parent": "…", "kind": "rev", "patches": [ … ], "author": "…", "via"?: [ … ], "created": "…", "grant"?: { "id", "sub", "kid" }, "signature"?: "…", "gesture"?: "…", "undoes"?: "…" }
{ "id": "…", "parent": "…", "kind": "tombstone", "author": "…", "via"?: [ … ], "created": "…", "grant"?: { "id", "sub", "kid" }, "signature"?: "…", "gesture"?: "…", "undoes"?: "…" }
```

`created` is the entry's creation time (§5), here and in namespace entries (§7.4), in RFC 3339 UTC with millisecond precision. `via` lists the grant's delegatees in order (§C.1), absent when there are none. `grant` is absent where none was recorded, including writes made while authentication was disabled, whose namespace entries say `"grant": null` (§7.4). All cursors are ids. Internal sequence numbers are never exposed.

### 7.2 Writes

Writes are **never** unconditional: a write without a precondition is `428`, and one with both `If-Match` and `If-None-Match` is `400` (`bad_input`), a request-shape error (§6.2). Pruning (§8.6) and blob uploads (§7.8), which change no head, take none, and one sent is `428` (§12.1): for a prune at step 2.5 of §6.2 (§8.6), for an upload at check 4 of §7.8. Checks run in the order of §6.2, so **authorisation always comes before the precondition** (for a `PATCH` with `If-Match`, it completes at step 2, when the verb is settled), and an unauthorised caller never learns whether its precondition matched or sees the head.

| Request | Precondition | Success | Failure |
|---|---|---|---|
| **Create:** `PATCH /r/{ns}/{name}`, `Content-Type: application/json-patch+json` | `If-None-Match: *` | `201` with `Location: …/rev/{id}` and `ETag: "{id}"` | `412` if the resource is live (body `{ head }`) · `410` (`gone`) if it is tombstoned, with `head` the tombstone (§8.1) · `422` · `410` if purged |
| **Append:** `PATCH /r/{ns}/{name}` | `If-Match: "{parent}"` | `201` with `Location` and `ETag` | `412` + `{ head }` if parent ≠ head · `422` · `410` (`gone`, with `head`) if tombstoned and `parent` ≠ tombstone · `403` if tombstoned and the grant can't restore (§6.2) · `410` if purged |
| **Restore:** `PATCH` on a tombstoned resource | `If-Match: "{tombstone}"` | `201`; the patches apply to the last live document (§8.2) | as for append |
| **Delete:** `DELETE /r/{ns}/{name}` | `If-Match: "{head}"` | `200` + `{ tombstone }` | `412` + `{ head }` · `410` (`gone`, with `head`) if already tombstoned |
| **Purge:** `POST /r/{ns}/{name}/purge` | `If-Match: "{head or tombstone}"` | `204` | `412` + `{ head }` · `409 in_use` (§6.1), after the precondition (§8.5) |
| **Upload a blob:** `PUT /r/{ns}/{name}/blob/{bid}` (§7.8) | none | `201` with `ETag: "{bid}"` | in the order of §7.8: `400` for the URL, `{bid}` included · `401`/`403` · `429` · `410` if the resource or namespace is purged · `409 frozen` · for a copy, `400`, `422 blob`, then `404` · `400`/`415`/`428` · `413` · `422 blob_mismatch` |

-
**Content types.** A resource `PATCH` with any `Content-Type` other than `application/json-patch+json`, or none, is `415`, a request-shape error (§6.2), as is any other JSON body, such as a batch's, not sent as `application/json`. A JSON body's `Content-Type` is compared as a media type (RFC 9110, section 8.3.1), ignoring case and a `charset` parameter naming UTF-8; any other parameter is `415`.

-
**Authorization:** `Authorization: Bearer <grant>` (Addendum C). With authentication disabled (development only), `X-Author` names the author; a write without it is `400` (`bad_input`).

-
**Author** is the verified principal id. `via` (Addendum C) is recorded with it.

-
**Gestures.** A write MAY carry `Gesture: <id>`, naming the user action it belongs to, and `Undoes: <id>`, naming the gesture it undoes (§11.2). Both are 26 base32 characters (`^[a-z2-7]{26}$`, 128 random bits the client chooses when the action starts), otherwise `400`.

  - They are stored with the revision or tombstone as metadata, like its author: not part of its id (§3.3), and not seen by rules.

  - The id is the writer's own label, never verified: tools group revisions by author and gesture together, and attribute an `Undoes` to whoever wrote it (§11.2).

  - An idempotent retry answers with the entry as first recorded, whatever the retry carries, with the recorded `Gesture` and `Undoes` as headers.

  - A namespace-document write (§7.4) carries them the same way; a batch's `config` change carries none, the batch's defaults applying to its items' steps. Undoing a config change is outside §11.2.

-
**Idempotent retry.** Suppose the precondition fails, but the log already contains the entry this request would have produced, recorded **with that parent**:

  - for an append or restore, the revision id of §3.3 with `If-Match` as parent

  - for a create, the genesis id of §3.3 with an empty parent

  - for `DELETE`, the tombstone id of §3.4

If that entry was written by the **same principal**, the same root `sub` and `kid` (§6.6; while authentication is disabled, the same author), and the retry passes the verb check of §C.2 item 2, respond `200` with it, answered as its write succeeded (`Location` and `ETag`, or `{ tombstone }`), instead of `412` (or a `410` on a tombstoned resource, or `409 frozen`). The check looks anywhere in the resource's log in the namespace written, not only at the head, but not at entries a branch reads through (§7.6), nor in a purged resource, whose answer is `410` (§6.2). Within the retry window (§6.6, §8.6) it always works. A different principal sending identical patches gets `412`.

-
**Frozen namespaces.** Resource writes, batches with items, and blob uploads and copies (§7.8) are `409` there, with `code: "frozen"` and any `successor`, after authorisation and the idempotent-retry lookup (§6.2, §8.4).

-
**Namespace revision.** Every successful write that records a namespace entry answers with `X-Namespace-Revision: {ns_id}`, that entry, for read-your-writes in consumers (e.g. §A.5): creates, appends, restores and deletes, purges and namespace purges (on their `204`, §8.3, §8.5), config writes (§7.4), batches (§7.5), branch creation and remote registration (§7.6, §G.3), and a prune that moved the horizon or changed `keep` (§8.6). An idempotent retry carries the entry that recorded the original write, a batch's included. Blob uploads and copies, a prune that changes nothing and a dry run write no entry and carry none.

-
**Caching.** Write responses are `Cache-Control: no-store`.

### 7.3 Events (Server-Sent Events)

`GET /r/{ns}/{name}/events?since={id}`, and `GET /ns/{ns}/events?since={ns_id}` for the namespace log. `Last-Event-ID` is also accepted, and wins over `since` when both are sent. Without either, or with an empty `since`, the stream replays from genesis (§7.1), and for a resource with no entries yet it waits for the first, as long-poll does (§7.7).

- The stream first replays entries after `since`, one log page (§7.1) per fetch, then streams live ones. Replay is judged as its log range is, before any event is sent: a `since` not in the log is `404`, and a revision to replay whose patch set is pruned `410`, after which the client reloads the head. A prune that reaches a page not yet sent ends the stream, so the reconnect gets the `410`.

- A resource stream's event types are `revision` and `tombstone`, whose data is the resource log entry (§7.1) and whose SSE `id:` field is its id, and `purge` and `prune`, whose data is the namespace entry that records them (§7.4) without its `id` and `prev`, and which carry no `id:` field. A resource stream ends after its `purge` event. A namespace purge sends no `purge` event (§8.5): it ends the resource's streams. Replay carries only `revision` and `tombstone` events.

- A namespace stream's events are its log entries as §7.4 serves them, with each entry's `id` as the `id:` field. It ends after its `purge-ns` event, or at once when `since` names that entry (§8.5).

- Responses are `Cache-Control: no-store`, and require `read`, unrestricted for a namespace stream (§2.1). Before each event, the stream judges that read check again, as for a request made then, and ends instead if it fails; it also ends, at the latest, when the grant or cookie it was admitted under expires (§C.2, §C.5.3).

### 7.4 Namespace

| Request | Response | Cache-Control |
|---|---|---|
| `GET /ns/{ns}` | `302` with `Location: /ns/{ns}/rev/{ns_id}`, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}` | head pointer |
| `GET /ns/{ns}/rev/{ns_id}` | `200` with the namespace document in force at that point in the chain, `ETag: "{ns_id}"` (`"{ns_id}.{e}"` when sealed, §E.2.2), `X-Config-Revision: {config_id}`. An `ns_id` not in the chain is `404` here, and at its `/log` and `/heads` | immutable (a `404` as short) |
| `GET /ns/{ns}/rev/{ns_id}/log?since={a}` | `200` with an array of `{ id, prev, kind, resource?, name?, remote?, at?, target?, entries?, source?, forced?, author, via?, grant?, gesture?, undoes?, gestures?, created }`, following §3.5, where `gesture` and `undoes` are those of a single write, and `gestures` maps each resource of a batch to a list of `{ "gesture"?, "undoes"? }`, one per step (§7.2), none of them hashed, and `grant` is `{ "id", "sub", "kid" }`: the grant id (§C.3) in text form, and its root `sub` and `kid`. A local branch's creation records the creator's grant on both its entries, a namespace's genesis the operator's, a janitor's prune the janitor's, and the schema namespaces a remote branch mirrors at creation the creating operator's. `grant` is absent from entries the server writes itself (propagated purges, purges applied from a remote base, its own prunes, §8.6) and from entries written before v0.37 unless it can be recovered from their revisions, and `null` on entries written while authentication is disabled; how these count in `merge.authors` and claim checks (§F.3, §F.6) is §1's. An empty or omitted `since` means from the chain's first entry. `404` if `a` is neither `ns_id` nor earlier in its chain. Paged as in §7.1 | immutable |
| `GET /ns/{ns}/rev/{ns_id}/heads?after={name}` | `200` with `{ "heads": [ … ], "next"? }`, a page of `{ resource, kind, target, created?, size?, digest? }`, one per resource as of that revision, `kind` and `target` those of its latest `head`, `tombstone` or `purge` entry (§3.5), including resources a branch reads through, in ascending byte order of name, strictly after `after`, a plain bound that needn't name an existing resource; `next` for the following page, absent on the last. In a namespace that is neither sealed nor end-to-end, judged by the namespace serving the page, `created` is the target entry's, and for a live head of a resource that isn't purged `size` is the length of its canonical document in bytes and `digest` the `Repr-Digest` value of it uncoded (`sha-256=:…:`); at E2 and E3 all three are absent (§E.2.2). Pages carry the tag `heads:{ns}`, purged with every resource purge in the namespace. All three are optional, and readers MUST NOT rely on them: a server stores them at write time, so a page lacks them for rows written before it did, and a page once served never gains them. `410` once the namespace is purged (§8.5) | immutable |
| `GET /ns/{ns}/events?since={ns_id}` | SSE of namespace entries (§7.3) | `no-store` |
| `GET /ns/{ns}/principal` | `200` with what the grant in `Authorization` is here: `{ "principal", "kid", "key", "operator", "can", "roles", "writer": { "frozen": bool, "successor"?, "nonce": "optional" | "required", "signatures": "optional" | "required", "level"?: "at-rest" | "sealed" | "e2e", "limits" }, "catalog"?: { "trust", "files"? } }`, with `X-Config-Revision`. `principal` is that of §6.4.1; `kid` names the key that verified the root block, and `key` is the RFC 7638 SHA-256 thumbprint, base64url without padding, of the key as a JWK (`{"crv":"Ed25519","kty":"OKP","x":<pub>}` for a namespace key, the published JWK for an operator key), which, unlike a `kid`, means the same key in every namespace (§H.7); `operator` is true for an operator grant (§C.4), whose `can` is its blocks' verbs and `roles` `[]`. Otherwise `can` is the verbs its blocks and key allow, where it carries roles only those an effective role lists, and `roles` its effective roles; `can` never lists `branch` where the server refuses local branches (§1). `writer` gives whether the namespace is frozen, its `successor`, `nonce` (`required` where the namespace document requires nonces or the namespace is sealed at E2, otherwise `optional`), `signatures`, the encryption level (absent without `encryption`), and every §6.6 limit in force, at the namespace's value or else the deployment's default, deployment-only ones at the deployment's values, without allowances or a key scope's `rate`. `catalog`, for a catalog namespace, gives `catalog.trust` (`[]` when absent) and `catalog.files` (§B.6, §H.2); a grant without unrestricted `read` of the catalog gets `files` without its `x-` members, and in place of `trust` only `trusted`, whether `files.ns` is trusted. Only the `ns` check (§7) and verification (§C.2 item 1, key scope included) apply, with no verb check and no rule, so a grant limited to some resources, or without `read`, learns these settings (§C.5). To an operator grant, a namespace that doesn't exist is `404` (§C.4). A grant that fails the `ns` check is `403` (§7, step 2), and one that can't be used, or none, `401`, even in a public namespace. While authentication is disabled (§1) it answers `200` without `principal`, `kid` and `key`, with `operator: false`, `can` every verb the server allows and `roles` `[]`, and `404` for a namespace that doesn't exist. It draws no rate token. A purged namespace answers `410` once the grant verifies (§8.5) | `no-store` |
| `GET /ns/{ns}/gestures/{gesture}` | `400` (`bad_input`), a request-shape error (§6.2), for a `{gesture}` not of the form of §7.2. Otherwise optional, and not offered in sealed or end-to-end namespaces; where not offered, `404` with `code: "not_offered"`, after the `read` check. `200` with `[{ resource, id, kind, gesture?, undoes?, author, ns_id }]`, one per revision or tombstone written with that gesture or undoing it, oldest first, leaving out purged resources. Paged by `logPageSize`: a full page carries `X-Log-Next: {resource}/{id}` (its last row; ids repeat across resources), the next page is `?after=` that value, an `after` that names no such entry of a resource the grant may read is `404`, and a page without `X-Log-Next` is the last. Answers any reader, listing only entries for resources its grant may read | `no-store` |
| `GET /ns/{ns}/grants/{gid}` | `200` with `{ id, root, stored }`, a grant recorded by an entry of this namespace or, in a local branch, of its bases up to their `at`, in its non-bearer form (§C.3.1); `404` for any other. Requires unrestricted `read` (§2.1); sealed in sealed namespaces, `private` in end-to-end ones | immutable (`private` at E3) |
| `GET /ns/{ns}/branches` | `200` with `[{ name, at, frozen, purged, successor?, drafts? }]` for the namespace's direct branches, and `{ remote, at, ns_id, expires }` for remote branches whose registration hasn't expired (§G.3). Requires unrestricted `read` (§2.1). `410` once the namespace is purged (§8.5) | head pointer |

**Namespace writes.** The namespace document is edited like a resource, with a JSON Patch on its own URL:

| Request | Precondition | Success | Failure |
|---|---|---|---|
| `PATCH /ns/{ns}`, `Content-Type: application/json-patch+json` | `If-Match: "{config_id}"` (the value of `X-Config-Revision`, quoted), or `If-None-Match: *` to create | `201` with `X-Config-Revision: {new config_id}`, `X-Namespace-Revision: {ns_id}` and `Location: /ns/{ns}/rev/{ns_id}`, the namespace entry the write produced, and body `{ "config": new config_id, "ns_id" }`. An idempotent retry (§7.2) answers `200` with the same headers and body; when a batch wrote the config change, `ns_id` is the batch's entry | `412` + `{ config }`, without `config` for a creation under a taken name, as for a branch (§7.6) · `422` · `428` · `401`/`403` |

- **`If-Match` takes the config id,** not the `ETag`, deliberately: `ns_id` moves on every document write, the config id only when the configuration changes.

- **Envelope.** Config writes are checked with a `config` envelope (§6.4.1). Key-scope and grant rules apply to them.

- **Keys, roles, revocations, limits and exposure.** Writes covering or overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption`, `/signatures`, `/nonce`, `/schemaReads`, `/catalogs` or `/maxLag`, and writes that set `read` to `public`, need a `*` key (§C.2). Making `read` stricter needs no `*` key.

- **Validation.** The namespace document is validated against the built-in namespace-document schema of the deployment's version. Rules and patterns must be well-formed and within limits. The members this spec defines are validated strictly:

  - **Members.** The members this spec defines, the core's and those of Addenda B and F, are listed in §12.3 with their shapes.

  - **`x-` members.** Any other top-level member must start with `x-` (case-sensitive) and is stored as data. So may members inside the addenda's objects (§12.3), except as keys of `catalogs`, which are catalog names. Role entries are open: the core reads `can` and `rules` and ignores the rest, which consumers use, such as `move`, `place` and `includes` (§C.1.1, §B.11.1, §B.11.4). Other nested objects, such as key entries, are strict.

  - **Errors.** Anything else is `422` with `code: "invalid"` and `errors: [{ "pointer", "message" }]`, as for schema validation.

  - **Documents stored under an earlier version** may hold members this version doesn't define. A write keeps such a member, or such a field in a key entry, if it leaves it unchanged, may remove it, and is `422` only if it adds or changes one; a `move` to an `x-` name renames it. Creating a branch of such a namespace is `422` until it is renamed.

  - **Versions.** A deployment that reads another's namespace documents, as a remote branch reads its base's (§G.3), ignores members it doesn't define. Only a tool that copies a document into a namespace refuses one that holds such a member, unless it starts with `x-`; none refuses on the spec version alone (§7).

- **Content types.** Other `PATCH` content types are `415`.

- **Logging.** A config change appends a `config` entry to the namespace chain. Namespace events use the entry's `kind` as their event type: `head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns` and `prune`.

- **Branch fields.** Their `422`s are validation errors (`invalid`, with `errors` pointing at the member, above).

  - `base` is set when a branch is created and can never change (`422`). A namespace created with `PATCH` may set only a remote `base` (§G.3); one without `origin` is `422`.

  - A config write to a branch MUST NOT remove or change a key entry that is a `*` key in one of its bases (`422`, §7.6).

  - `frozen` and `successor` have the meaning of §8.4, in any namespace. A write that sets or changes `successor` MUST name another namespace that exists and isn't purged (`422`): for a branch, a branch of the same base or of a namespace further up this branch's `base` chain, whose `at` may differ, as after a rebase (§F.4, §F.5); for a namespace that isn't a branch, another namespace that isn't a branch.

  - A branch of a namespace whose `read` isn't `public` MUST NOT become `public` (`422`, §7.6).

  - A branch MUST NOT break the level rules of Addendum E (Levels, `422`), nor turn off a `nonce` requirement its base has (`422`, §C.7).

  - `drafts: { "for": [ … ] }` (optional) lists the other namespaces whose writes may resolve schema paths into this branch, with their branches (§6.1): names, or prefixes ending in `*`. Without it, a branch's drafts serve only itself and its own branches. Narrowing it is subject to the `in_use` rule of §6.1. A bare `"*"` serves every namespace. `drafts` is `422` in a namespace that isn't a local branch, or that is end-to-end.

  - Conversely, a namespace with public dependents can't stop being public (`409`, `code: "in_use"`, with `dependents`).

  - Likewise, a namespace can't start requiring nonces while a dependent doesn't (`409`, `code: "in_use"`, with `dependents`, §C.7), nor raise its level above a dependent's (Addendum E, Levels). Both are set in the branches first, leaves first.

### 7.5 Batches

Writes to several resources of one namespace, applied all or nothing:

```
POST /ns/{ns}/batch
Content-Type: application/json

{ "items": [
    { "resource": "derby", "ifMatch": "1a…", "steps": [ [ …patches ], [ …patches ] ] },   // two revisions
    { "resource": "final", "ifNoneMatch": "*", "steps": [ [ { "op": "add", "path": "", "value": { … } } ] ] },
    { "resource": "cup",   "ifMatch": "1c…", "steps": [ "delete" ] },
    { "resource": "semi",  "ifMatch": "1d…", "steps": [ "delete", [] ] } ],                // delete, then restore (a fresh $nonce instead of [] where required)
  "config": { "ifMatch": "1k…", "patches": [ … ] },     // optional
  "source": { "ns": "release-7", "at": "1n…" } }        // optional provenance; may name another deployment (Addendum G)
```

-
**Items.** Each item names one resource, at most once per batch, with exactly one precondition as in §7.2 (a missing one is `428`). A batch that names a resource twice, an item with both `ifMatch` and `ifNoneMatch`, or an item without steps, is `400` (`bad_input`), a request-shape error (§6.2). Its `steps` are applied in order, each chained on the previous one:

  - a patch set appends a revision, or restores if the previous entry is a tombstone

  - `"delete"` appends a tombstone. One that is the first step of an item under `ifNoneMatch` is `428`, at step 2.5 of §6.2, as a `DELETE` with `If-None-Match: *` is (§12.1); one that follows another `"delete"` with no patch set between them is `422` (`invalid`), also at step 2.5, where a `DELETE` of a tombstoned head fails (§7.2).

A step may also be an object with exactly one of `"patches": [ … ]` or `"delete": true`, plus optional `gesture` and `undoes` (§7.2) and `signature`, the step's author signature in the form of the `Signature` header (§C.3.1). An item, or the whole batch, may carry `gesture` and `undoes` as defaults, which a step's own values override. The whole batch may carry them as `Gesture` and `Undoes` headers instead; one sent both ways is `400` (`bad_input`).

Resource purge is never part of a batch.

-
**Checks.** Every step is checked with its own envelope, following §6.2 across the whole batch.

  - `items` may be empty or absent when `config` is present. A batch with neither items nor `config` is `400` (`bad_input`), a request-shape error (§6.2).

  - The optional `config` change runs steps 1–6 **first**, as a config write (§7.4), its `*`-key guard included (§C.2).

  - The items are then checked against the configuration it produces, except that `frozen` and the batch limits (§6.6) always come from the current configuration. `frozen` refuses items only, so a batch with no items works in a frozen namespace (§8.4).

  - Batch limits can depend on the principal, through an allowance (§6.6). The server stops reading, at once (`413`), a body more than four times the larger of the verified principal's `batchSize` and the deployment maximum of `documentSize`, as for a resource `PATCH` (§6.6), which leaves room for the batch's own envelope (item names, preconditions, a `config` change). Item counts, and the total size of the items' canonical patch sets against `batchSize`, are checked at step 4, like other limits, before any item's own.

  - Items may reference schema revisions created by earlier items (§6.1), and blobs uploaded or copied before the batch or, with a local `source`, taken from it (§7.8).

-
**Success.** `201` with `{ "ns_id": …, "config"?: …, "items": [{ "resource": …, "ids": [ … ] }] }` and `X-Namespace-Revision`, with `config` and `X-Config-Revision` the new config id when the batch has a `config` change. One `batch` entry is appended (§3.5).

-
**Failure.** Nothing is written. The status is that of the earliest failing step of §6.2, or, where items fail that step with different statuses, that of the first of them in request order, and the body is `{ "code": "batch", "items": [{ "index", "status", "code", … }] }` for the items that failed at that step (e.g. `"code": "signature"`, §C.3.1). If any item fails authorisation, only those items are reported. A `config` change that fails is answered as that config write would be (§7.4), without `items`: it runs first, so no item has been checked yet. A purged namespace (§8.5), a frozen namespace (§8.4), a rate limit, `itemsPerBatch` or `batchSize` (§6.6), and a refused `source` (below) are answered as for a single write, without `items`.

-
**Dry run.** `?dry-run=1` runs steps 1–6 for the `config` change, if any, and for every item, as a submit would, and writes nothing. The items are checked against the configuration the change would produce, or the current one if the change fails after step 1. A blob that isn't available is reported, and the later steps run as if it were. It returns `200` with `{ "items": [{ "index", "status", "code"?, "ids"?, … }], "config"? }`, the report for every item, with `status` `201` for one that would pass, or `200` for each item when a submit would be answered as an idempotent retry (below), including the ids a submit would produce and any `signature` failure, and, as `config`, the report for the `config` change, with the config id a submit would produce. Authorisation still comes first: if the `config` change fails step 1, the dry run answers as that config write would; otherwise, if any item fails authorisation (§6.2 steps 1 and 2.2), `401` or `403`, reporting only those items; a rate limit, a purged or frozen namespace, `itemsPerBatch` or `batchSize`, and a refused `source` are answered as for a submit. The result may differ by the time the batch is submitted.

-
**Idempotent retry.** If one earlier `batch` entry by the same principal already contains exactly the entries this batch would produce, its config entry included, with the `config` change's `ifMatch` as that revision's parent, as for a config write (§7.4), and every item passes the retry's verb check (§C.2 item 2), the response is `200` with that batch, as in §7.2. Only `batch` entries match a batch's retry, so a batch with only a `config` change retries an earlier `batch` entry that holds just that config entry. If the resource of any item has been purged since, the retry fails as a single write's does (§6.2): `410`, before any other precondition, with the `batch` body listing those items (`code: "gone"`, §8.3).

-
**Reading other namespaces.** Some checks read a namespace other than the one the request names: a batch's local `source` (below), a blob copy's source (§7.8), and a schema revision in another namespace, a draft in a branch included (§6.1). Each tries the request's own grant and every grant in `Source-Authorization` headers, which may be repeated. The first that names that namespace, verifies under its keys (§C.2) and allows that check's read serves. A public namespace needs no grant (§7). If none serves, the check fails as that section says, revealing nothing about the namespace.

-
**`source`** is recorded in the batch entry. For a local source and a caller with unrestricted `read` on `source.ns` (§2.1, by the rule above), the server checks that `source.at` is in the chain of `source.ns` (`422`, `code: "source"`), at step 4 of §6.2, after the batch limits and before any item's own checks, so before blob references. For any other caller the source is recorded unchecked and makes no blobs available. A source in another deployment carries `origin` and is recorded without checks (§G.3, §G.4.4); an `origin` equal to this deployment's own is `422` with `code: "source"`, for any caller, at the same step. That the items correspond to the source is asserted by the writer, not verified.

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

- **Request.** `patches` defaults to `[]`. For a local branch, `at` defaults to the base's current head, the latest `ns_id` of its chain when the branch entry is inserted, and `If-None-Match: *` is required; `If-Match` alone is `428` too, at step 2.5 of §6.2, and never answered as a retry. A remote branch's registration (§G.3) uses this endpoint too, and renews with `If-Match`.

- **Result** of a local branch's creation: `201` with `Location: /ns/{name}`, and `X-Namespace-Revision` for the `branch` entry appended to the base's log (§3.5).

  - A taken name is `412`, with no `head` or `config`, including one taken by a purged namespace. A retry by the same principal with the same `at` and `patches` gets `200`, as in §7.2, until the branch is purged; after that it is `412` too. A retry of a local branch's creation that omits `at` counts as naming the `at` recorded for that branch.

  - An `at` that isn't in the base's chain is `422`. A purged base is `410` with `code: "purged"` (§8.5).

- **Configuration.** The branch's namespace document starts as a copy of the base's **current** document.

  - `frozen`, `successor`, `merged`, `abandoned`, `cleanup`, `drafts` and `schemaReads` are removed, `base: { "ns": base, "at": at }` is added, and then `patches` are applied.

  - The branch's configuration chain starts with one entry, the genesis patch set `[{ "op": "add", "path": "", "value": <that document> }]`, where `<that document>` is the document after `patches` are applied, so its config id is reproducible. It is the `target` of the base's `branch` entry (§3.5).

  - A branch's rules, roles and read mode are its own from then on. Its **keys follow the base** (§C.4).

- **Authorisation** of a local branch needs `branch` and unrestricted `read` (§2.1) on the base, checked as §C.2 item 2 says. Bases whose read access is decided per document (§C.5.1) should grant `branch` only to a service that creates branches for editors limited to some documents (§F.8).

  - The `*`-key guard (§C.2) applies to `patches`, with a `*` key **of the base**. Every `*` key of the base is kept in the branch and can't be removed from it.

  - The base's rules evaluate a `branch` envelope. Its `resource` is the new namespace's name, its `doc` is the new namespace document, and its `writes` come from `patches`.

  - Failures answer as for other writes (§6.2, §C.2).

- **A branch is a copy.** Whoever can read the branch can read the base as it was at `at`, under the branch's own configuration. A branch of a namespace that isn't public MUST NOT be public (§7.4).

- **Nesting and number.** A branch may itself be a base, within the branch-depth and branches-per-namespace limits (§6.6).

- **In another deployment.** A branch's base may also live in another deployment, `base: { "origin", "ns", "at", "chain" }`. Such a **remote branch** is a new namespace, created with the deployment operator key as §C.4 bootstrapping requires, and is described in §G.3. The rules of this section that rely on one operator (keys following the base, revocation in bases, purge propagation, dependents blocking a namespace purge) do not reach across deployments.

**Reading through.** For a resource with no entries of its own in the branch, the branch answers as the base did at `at`, recursively through bases of bases:

- a `302` with `Location: /r/{branch}/{name}/rev/{id}` and `ETag: "{id}"`, where `id` is the head as of `at`

- a `410` if it was tombstoned then

- a `404` if it didn't exist then

Everything is served under the branch's own URLs: `/r/{branch}/{name}` and `/r/{branch}/{name}/rev/{id}`. Changes in the base after `at` are never seen, except purges (§8.3) and the base's pruning (§8.6).

**History.** `/r/{branch}/{name}/rev/{id}` serves any id in the resource's ancestry as seen from the branch, including base revisions up to the foreign parent. `…/log?since=` crosses the foreign parent. `/r/{branch}/{name}/blob/{bid}` serves the base's blobs that the branch's view references, as well as its own (§7.8 Reading).

**First write.** The first write to a read-through resource checks its precondition against the base's head as of `at`, and takes that head as its **foreign parent**, whether it appends, deletes or restores. If the document it builds on, or for a delete the one it deletes, is pruned (§8.6), as in a branch created at an `at` older than the base's horizon, the write is `410` (`pruned`) once its precondition passes. Creating a name that didn't exist in the base at `at` is an ordinary create.

**Logs.** The branch's namespace log contains only the branch's own entries. Its creation is recorded in the base's log as a `branch` entry (§10).

**Branch names are visible to the base's readers,** in its log and listing. Bases that must hide what their branches are about can require opaque names with a rule on the `branch` envelope's `resource` (§6.4.1).

### 7.7 Live reads by long-poll

SSE (§7.3) holds one origin connection per client. When many clients follow the same log, a **long-poll** read lets the CDN collapse their identical waiting requests into one:

```
GET /ns/{ns}/log?since={ns_id}&live=long-poll&cursor={c}
GET /r/{ns}/{name}/log?since={id}&live=long-poll&cursor={c}
```

- **Answer.**

  - If there are entries after `since` (empty or missing: from the beginning), the server answers `200` at once with them, up to one log page (§7.1), in the shapes of §7.1 and §7.4. `X-Namespace-Revision` (resource logs: `X-Revision`) names the last entry returned, which is the next `since`.

  - Otherwise it waits until an entry arrives or the current **interval** ends. The timeout answer is `204`, with the same header naming `since`, or without it when `since` is empty; the client's next `since` then stays empty.

  - Both answers carry `X-Cursor`.

  - A `since` not in the chain is `404`, and a pruned range `410`, as in §7.1. A resource with no entries waits as for an empty `since`. A namespace log needs unrestricted `read` (§2.1), a resource log `read` on that resource.

  - Without `live`, these URLs answer `302`, cached as a head pointer (§9), to the immutable range `…/rev/{head}/log?since=…`, and a resource with no entries `404`, cached as short.

- **Intervals and cursors.**

  - The server divides time into fixed intervals (default 20 seconds) counted from a fixed epoch. The cursor is the interval number, in decimal. Origin instances SHOULD keep their clocks synchronised to well within an interval, e.g. by NTP to under a second.

  - On `200`, the response cursor is the current interval number.

  - On `204`, the response cursor is the greater of the current interval number and the request's cursor plus one, so the same `since` after a timeout, or under clock skew, never repeats a URL. It is deterministic, with no jitter, so every client waiting at the same `since` holds the same cursor after one idle boundary.

  - A wait ends at the latest at the interval boundary.

  - A cursor more than one hour's worth of intervals ahead of or behind the server's is `400` (behind: the client then omits it). A request without a cursor, or with one behind the server's by less, is answered at once: with the entries after `since` if there are any, otherwise `204` with the current cursor in `X-Cursor`. One ahead by an hour's worth or less waits as a current one does, until this server's interval boundary at the latest, and its `204` carries the request's cursor plus one.

- **Caching.**

  - The cache key is the path plus `since`, `live` and `cursor`. The page size is fixed by the deployment, not chosen by the client. Any other query parameter, a `live` other than `long-poll`, or a `cursor` that isn't a decimal number, is `400` (§7).

  - `200`: `public, max-age=0, s-maxage={interval}`; every answer is a correct range starting at `since`.

  - `204`: `public, max-age=0, s-maxage=2` (§9).

  - Private namespaces follow §9: edge grants, `private` downstream, and edge lifetimes as above.

  - Tags are those of the log (`ns:{ns}`, and `r:{ns}/{name}` for resource logs), so purges reach cached answers (§8.3).

- **Clients** echo `X-Cursor` as `cursor` in the next request, take the returned revision as the next `since`, and poll again at once after a `200`.

- **Which to use.** SSE for a few clients, such as the editors of one document; long-poll for many followers of the same log.

- **Several logs at once.** Each followed log holds a connection for a whole wait, and HTTP/1.1 browsers allow about six per host, so serve long-poll over HTTP/2 or later. No combined URL for several logs is defined, since it would defeat collapsing; a page that follows many logs is better served by a service that follows them and publishes one feed.

### 7.8 Blobs

Large values, such as images, audio, PDFs or long texts, are stored as **blobs**: immutable bytes attached to one resource, referenced from its documents and served from their own immutable URLs. Strings in documents are limited by `valueSize` (§6.6).

-
**References.** A document refers to a blob with an object whose `$blob` member is a string, at any depth:

```
"hero": { "$blob": "1m4…", "type": "image/jpeg", "size": 1843302 },
"scan": { "$blob": "1p7…", "type": "application/pdf", "size": 412977, "nonce": "k3q…" }   // a private namespace
```

  - `$blob` is the blob id (§3.7), `type` its media type and `size` its length in bytes. `nonce` is present exactly when the blob has one. No other members are allowed, except `sealed` at E3 (§E.3.1). At a raw document's root (below), the top-level members validation leaves out aren't part of the reference.

  - References are found by walking the document, whether or not it has a `$schema`. A malformed one is `422` (`code: "blob"`, §6.5).

  - Schema documents, whose `$schema` is a dialect URL (§6.1), contain no references, so a schema can describe them like any other object, e.g. with `"required": ["$blob"]`.

-
**Attachments.** A blob belongs to a resource in a namespace through an **attachment**:

  - **Pending:** after an upload or a copy, until a revision references it. The **uploader** is the principal as rate limits know it: root `sub` and `kid` (§6.6). After a key rotation, a writer uploads its pending blobs again. A pending blob is invisible: reads answer `404`, and only its uploader can reference it. Each uploader has its own pending entry, even for bytes already stored. An entry counts toward its uploader's `blobPending`, at least 4 KiB per blob, and is deleted once it is older than `blobGrace`; uploading it again restarts that time. A write whose document references the blob ends every pending entry for it in that resource, whoever uploaded it.

  - **Attached:** at step 7 of §6.2, a write attaches every blob its resulting document references to its own resource, in the same transaction as the revision.

  - An attachment lasts while a document still stored for the resource references the blob: the documents at or after the horizon (§8.6), the horizon's and other kept documents, and the last live document of a tombstoned resource. When pruning removes the last such document, the attachment ends and its bytes are deleted; storage that keeps identical bytes once (Why per resource, below) removes only this attachment's reference, and the bytes go when nothing holds them. Purge ends every attachment of the resource (§8.3).

-
**Availability.** A write may reference only blobs **available** to its resource:

  - attached to that resource in this namespace

  - pending there, if the writer uploaded or copied it

  - in a branch, attached to the same resource in a base and referenced by a document in the resource's history as the branch sees it (§7.6). The write attaches it to the branch's own resource.

  - in a batch with a local `source` whose `source.at` the server has checked (§7.5), attached to the same resource in `source.ns`, or in a base it reads through, and referenced by a document in that resource's history as `source.ns` sees it at `source.at` (§7.6), whatever the ranks, but from a sealed `source.ns`, or an `e2e` one's blobs from before a raise from `sealed`, only blobs the caller's keys open (§2.1).

A reference to a blob that isn't available, or that doesn't match the blob's `type`, `size` or `nonce`, is `422` with `code: "blob"`, at step 4 of §6.2.

-
**Uploading.**

```
PUT /r/{ns}/{name}/blob/{bid}
Content-Type: image/jpeg
Blob-Nonce: k3q…              (optional: 26 base32 characters)

```

The checks run in this order:

  - **Authorisation** at step 1 of §6.2, with `create`, `append` and `restore` as candidates (§C.2 item 2), then the rate limits (§6.6). Rules beyond step 1 never see an upload.

  - A purged resource is `410`, and any upload to a purged namespace `410` with `code: "purged"` (§8.5). A tombstoned resource accepts uploads.

  - A frozen namespace is `409` (§8.4).

  - A media type that can't be parsed, or a `Blob-Nonce` that isn't 26 base32 characters (`^[a-z2-7]{26}$`, §3.7), an empty one included, is `400` (`bad_input`): a writer whose blob has an empty nonce sends no `Blob-Nonce`. In an E3 namespace, any type other than `application/vnd.patchlog.sealed-blob` is `415` (§E.3.1).

  - A body larger than `blobSize`, or one that would take the uploader's pending blobs in the namespace past `blobPending`, is `413`.

  - The server recomputes the id over the body (§3.7), with the `Blob-Nonce` as its nonce, empty without one. A mismatch is `422` with `code: "blob_mismatch"`.

Errors in the URL and its query parameters (§7), a malformed `{bid}` included (`400`, `bad_input`), come before check 1. Any other request-shape error of an upload, in its headers, is `400` (`bad_input`) at check 4, and a copy's come where Copying says.

  - **No precondition.** An upload takes none (§7.2), one sent being `428` at check 4 (§12.1), and writes no namespace entry (invariant 5). It is idempotent: the answer is `201` with `ETag: "{bid}"` whether or not the bytes were already stored, and every uploader is charged for its own pending entry.

  - **Copying.** With an empty body and `Blob-From: /r/{ns2}/{name2}/blob/{bid}`, naming the same `bid`, the server copies a blob within the deployment instead of receiving it again:

    - Checks 1–3 run first, for the target. Then a request with a body, or a `Blob-From` that can't be parsed, is `400`, before any body is read, and a different `bid` is `422` (`code: "blob"`).

    - The source is then checked as a read of `/r/{ns2}/{name2}`, judged as for reading other namespaces (§7.5). A grant whose blocks name both namespaces, signed by a key they share (as a base and its branches do, §C.4), serves for both. Any failure of this check, including the `401` and `403` cases of §C.2, answers `404`.

    - A copy also answers `404` if it goes into another namespace that ranks below its source (§2.1), if Reading (below) wouldn't serve the blob at the source, or if the caller's keys don't open a blob from a sealed source, or from an `e2e` one from before a raise from `sealed` (§2.1). (A copy into `e2e` needs a sealed blob, check 4.)

    - The copy is then checked like an upload of the source's type, nonce and size (checks 4 and 5), whatever `Content-Type` and `Blob-Nonce` it carries. It costs a token like an upload, and nothing from `blobRate`. A batch with a local `source` carries `Source-Authorization` in the same way.

-
**Files.** A document whose root is a blob reference, `{ "$blob", "type", "size", "nonce"? }`, with no other members than the top-level ones that validation leaves out (§6.2 step 5: `$schema`, a fresh `$nonce`, a `$successor`), is **raw**: it stands for a file, such as an image or a Markdown text, served at `…/raw` (§7.1) with the blob's type. The read check of both `…/raw` and `…/blob/{bid}` is the document's own; a `schemaReads` referrer (§6.1) opens revision paths only. `size` in `/heads` (§7.4) is the reference's length, not the file's.

-
**Reading.** Every response to a blob URL, errors included, carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, so a page can't run script from one. The one exception: a stored `type` of exactly `application/pdf`, in a `200` or `206`, may go without the sandbox (which blanks Chromium's PDF viewer), still with `nosniff`; a deployment serves PDFs with `Content-Disposition: attachment` unless it opts into inline display. `GET /r/{ns}/{name}/blob/{bid}` answers `200` with the bytes, `Content-Type` its stored type (§3.7), with `; charset=utf-8` for a `text/*` type, `ETag: "{bid}"` and `Accept-Ranges: bytes`, and `206` for a range. Sealed namespaces, and at E3 blobs from before a raise from `sealed`, answer as in §E.2.2 instead.

  - Access is that of the resource: whoever may read `/r/{ns}/{name}` may read its blobs (§C.5, §B.11.5).

  - It serves the blobs attached to the resource and, in a branch, the base's blobs that the branch's view references (§7.6). Pending and unknown blobs are `404`. A tombstoned resource keeps serving its blobs, like its history (§8.1). A blob whose attachment pruning ended is `410` as in §7.1, and every blob of a purged resource is `410`.

  - Caching is immutable, with the resource's tags (§9). In sealed namespaces, and for those blobs at E3, the URL also names an epoch (§E.2.2).

-
**Encryption.** In sealed namespaces, and in those that require nonces, writers MUST give the blobs they create a nonce (§C.7); the server doesn't check it. Blobs carried over from another namespace keep their ids, nonce or not. The server seals blobs on delivery (§E.2.2). At E3 clients encrypt each blob under a key of their own and declare in plaintext which blobs each revision references (§E.3.1).

-
**Why per resource.** Read access, sealing keys, cache tags and purge, with its propagation to branches, follow the resource's URL, so blobs need no rules of their own. The same bytes in two resources are two attachments, which storage may keep once.

---

## 8. Deletion and purge

### 8.1 Tombstone (delete)

- `DELETE` with `If-Match: head` appends a tombstone to the resource log **and** a `tombstone` entry to the namespace log, atomically.

- **Moves.** There is no rename, so a move is recorded in content: the resource's last revision before its tombstone sets the top-level `$successor` (§6.5) to the resource that replaces it, as a bare name for one in the same namespace, resolved against the namespace that serves the `410`, or as `/r/{ns2}/{name2}` for one in another, with names valid under §3.6. Either form is well-formed wherever the document is, whatever `ns2` names. Within one namespace a move is one batch: create the new resource, then append `$successor` to the old one and delete it, its blobs copied first with `Blob-From` (§7.8); across namespaces it is two writes. An editor whose grant fixes one name (§2.1) can't move: catalog grants carry no `delete` in a content namespace (§B.11.3). A grant fixed to both names with `create`, `append` and `delete`, and `read` where blobs are copied, can. `$successor` is otherwise ordinary content for the chain, signatures, rules, merges and imports; validation leaves it out (§6.2 step 5).

- The head pointer then returns `410`, with `successor` copied from the last document's `$successor` if well-formed, in a namespace that is neither sealed nor end-to-end; elsewhere clients read it from the document at `last`. It is whatever the last document names, whoever wrote it: a namespace that cares protects `/$successor` by rule (§6.4.1, `/doc` for deletes). A restore keeps `$successor`, so a client restoring a moved resource also sends `remove /$successor`, with a fresh `$nonce` where required (§C.7). Earlier `/rev/{id}` URLs and the resource's blobs (§7.8) keep returning `200`.

- Further `PATCH` requests return `410` unless they restore (`If-Match: "{tombstone}"`); that `410`, and a `DELETE`'s, has `code: "gone"` and `head`, the tombstone (§7.2). A `PATCH` with `If-Match` under a grant without `restore` gets `403` instead (§6.2 step 2.2).

### 8.2 Restore / recreate

- The chain continues from the tombstone. The first revision after it applies its patches to the last live document.

- `[]` restores the document exactly as it was, `$successor` included (§8.1); where nonces are required (§C.7), just a fresh `$nonce` does.

- To recreate from scratch, restore with a root `replace`, if namespace rules allow it (§6.4.4).

### 8.3 Purge

- **Effect.** The resource's content (patches, snapshots and blobs, §7.8) is removed and the resource marked purged; storage that keeps identical content once removes only this resource's references to it (§7.8, §8.5). Its archived history (§8.6) is deleted too, or made unreadable by destroying its key, and restoring from an archive MUST skip purged resources. Ids, parent links and namespace entries are kept.

- **Namespace entry.** A `purge` entry is appended to the namespace log. Consumers MUST drop the resource and purge their own derived data and cache tags (§10).

- **Responses.** All `/r/{ns}/{name}/…` URLs then return `410`, before a `not_offered` as in §8.5, once the caller passes the read check for that URL, or, for a write, step 1 of §6.2; until then a read answers as for a resource the caller can't read (§7 step 4).

- **CDN.** The CDN is purged by tag (§9), `heads:{ns}` included (§7.4), never by id, since ids are shared across resources.

- **Branches.** A purge propagates to the **same name in every branch** of the namespace, recursively, whether the branch reads it through or has its own chain for it, successor generations and chains the branch created itself included. A branch that sees no entry for the name, read through or its own, is skipped, though its own branches aren't. A branch created later, at an `at` before the purge, sees the name as purged where it would read an entry for it through (§7.6): it answers `410` for it, and its `/heads` lists it as `purge`, with its head as of `at` as `target`. In each branch the propagation reaches, the server purges the resource and appends a `purge` entry to that branch's namespace log.

  - Purges never propagate upwards: to remove content everywhere, purge it in the topmost base it reached.

- **Limits of purge.** Purge can't recall copies held by browsers and other caches the operator doesn't control (§9 bounds their lifetime), and does **not** remove hashes: content-hash ids of low-entropy content, and the `digest` of `/heads` pages already served (§7.4), can be confirmed by guessing, which requiring nonces avoids (§C.7). Copies of a blob in other resources (`Blob-From`, §7.8) stay until those resources are purged too.

### 8.4 Freezing a namespace

- **Freezing.** A config write sets `"frozen": true`, and `false` unfreezes. Resource writes, batches with items, and blob uploads and copies (§7.8) are then `409` with `code: "frozen"`, and `successor` if set, at step 2.4 of §6.2 (check 3 of §7.8 for uploads), after the idempotent-retry lookup, so a retry of a write recorded before the freeze still answers `200` (§7.2). A batch with no items is a config write (§7.5). Unfreezing a branch whose base already has `branchesPerNamespace` live branches is `422` (`code: "limit"`, `limit: "branchesPerNamespace"`, §6.6), `max` being the base's value.

- **What still works:** reads, events and namespace consumers; config writes; resource purges, and namespace purges, which require it (§8.5); creating branches from it; pruning (§8.6).

- **`successor`** optionally names the namespace that replaces this one, e.g. the next generation of a rebased branch (§F.5), as §7.4 constrains it. Clients SHOULD move to it (§11).

- **Freezing is the namespace's tombstone:** reversible, with everything still readable. Namespace purge (§8.5) is the irreversible step.

### 8.5 Purging a namespace

-
**Request.** `POST /ns/{ns}/purge` with `If-Match: "{ns_id}"`, the namespace head the caller has seen. `204` on success; `428`, and `412` with the current `{ head }`, as for any write (§7.2).

-
**Requirements**, checked in this order, as §6.2 orders a write: the verb (step 1); frozen (step 2.4); the precondition (`428`, `412`); dependents, then schema references; all before rules (step 6). A purged namespace is `410` at step 2.1 (table below).

  - the `purge-ns` verb (Addendum C), distinct from `purge`

  - the namespace is frozen: otherwise `409` with `code: "not_frozen"`

  - no **dependents** (§2.1): otherwise `409` with `code: "in_use"` and `dependents: [...]`; cleanup proceeds leaves first

  - it would remove no last copy of a schema revision (§6.1) referenced from another namespace (its own documents are purged with it): otherwise `409` with `code: "in_use"` and `referencing` (§6.1)

-
**Effect.**

  - Every resource is purged as in §8.3, without individual entries, and one `purge-ns` entry is appended, the log's last: purges propagated from a base (§8.3, §G.3) and retention prunes (§8.6) skip a purged namespace.

  - The namespace document chain, the namespace log (with authors, §5) and every resource's ids and parent links are kept.

  - The name stays reserved.

  - The CDN is purged by the tag `ns:{ns}` (§9).

-
**Answers afterwards.** Every `410` here has `code: "purged"` and `head`, the `ns_id` of the `purge-ns` entry. Other sections point to this table.

| Request | Answer |
|---|---|
| `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…`, `/ns/{ns}/keys`, `/ns/{ns}/principal`, `/ns/{ns}/branches`, and `/heads` at any revision | `410`, as soon as the full read check for that URL passes (the grant's rules, unrestricted `read` where the URL needs it, any `read` for the gestures listing, §E.2.3's test for `/keys`, and for `/principal` verification alone), and before any other answer to a well-formed request, `not_offered` included |
| `/ns/{ns}` and `/ns/{ns}/rev/{ns_id}`, logs, events and long-poll included | served as before; where sealed, `410` (below) |
| Any write to it: resource writes, batches, blob uploads and copies (§7.8), purges, prunes, config writes, branching from it (§7.6) and remote registration (§G.3) | `410`, after authorisation and rate limits and before any other check (§6.2, step 2.1) |
| Creating a namespace or a branch under its name (a creation under the reserved name, not a write to it, §7.6), and a branch creator's retry once the branch is purged | `412` |
| Creating a remote branch whose base on A, or a base in its chain, is purged (§G.3) | `410` for any `at`, before `at` is checked, with `ns`, `head` and `origin` naming the first purged namespace found, A's before its bases' |
| Edge-grant issuance for a grant naming it (§C.5.2) | `410` only if every namespace refused is purged and the grant verifies there, with `ns` and `head` naming the first, as §C.5.2 says |

**Sealed namespaces.** Where namespace documents and log ranges are sealed (§E.2.2), the purge destroys the epoch keys that seal them (§E.2.4), and those reads, events and long-poll included, answer `410` too. `GET /ns/{ns}` still redirects, to a revision that is `410` where it is sealed, whose `head` tells a consumer of the purge.

-
**Shared storage.** Storage that keeps identical entries of several namespaces once removes only this namespace's references.

-
**Forcing.** An `in_use` refusal for schema references can be forced as §6.1 says; one for dependents can't.

-
**Irreversible.** There is no restore.

### 8.6 Pruning and retention

Pruning bounds the storage of long or fast-growing histories **without changing any id**, so whatever points at kept revisions keeps working. Revisions below the horizon without a kept document answer `410` (`pruned`), with a link to the archive if there is one (§7.1).

- **Horizon.** Pruning a resource below a horizon revision `H` drops the patch sets of the revisions before `H`, and the attachments of blobs that only the dropped documents referenced (§7.8), which the archive carries.

  - **Kept:** every id, parent link, author, grant reference, creation time, `gesture` and `undoes` (for audit, §C.3); the ids of the blobs whose attachments it ends, for their `410` (§7.8); `H`'s document; the protected documents (below); and, if `H` is a tombstone, the last live document, for a restore (§8.2).

- **Request.** `POST /r/{ns}/{name}/prune` with `{ "horizon": id, "keep"?: [ids], "snapshot"?: sealed }` returns `200` with `{ "horizon": id }`, the effective horizon.

  - It needs the `prune` verb, is checked with a `prune` envelope whose `doc` is `{ horizon, keep? }` as sent (§6.4.1), takes no precondition (§7.2), one sent being `428`, at step 2.5 of §6.2 (§12.1), and works in frozen namespaces too.

  - `horizon` MUST be the head or an ancestor of it (`422`). The server lowers it to the oldest protected revision if needed, never below the current horizon, giving the effective horizon.

  - Going below what `retention` keeps for the resource, which is everything where no rule matches it, or pruning where no archive is configured, needs a grant chained to a `*` key. Applying a retention rule that says `"archive": false`, within what it keeps, needs only `prune`.

  - `keep` lists extra revisions whose documents stay available, e.g. targets of pinned `x-ref`s found by a reverse-reference index (§6.5, §A.4), up to `keepPerResource` (§12.2). Outside a branch, each `keep` id MUST be a revision of the resource whose document is still served rather than `410` (`pruned`), or the prune is `422`. A prune that sends `keep` replaces the resource's earlier `keep` set (`[]` clears it); one without `keep` leaves it. `keep` is `422` in an E3 namespace. Pinned references to other pruned revisions get `410`.

  - A `prune` entry `{ resource, kind: "prune", target }`, `target` the effective horizon, is appended to the namespace log only if the prune moved the horizon or changed the `keep` set; otherwise it writes nothing.

- **Protected revisions.** The horizon never passes:

  - anything newer than the **retry window** (§6.6)

  - the resource's head as of the `at` of every unpurged local branch, frozen or not, and of every remote branch whose registration hasn't expired (§7.6, §G.3)

- **Protected documents.** These keep their documents below the horizon:

  - schema revisions referenced (§6.1) from any namespace of the deployment. At E3 the server can't see references, so protect schemas with `retention`, applied by a key-holding janitor (below).

  - the revisions listed in `keep`

- **Branches don't prune.** A branch's own entries are protected until it is purged (§8.5), and only the base prunes the history the branch reads through. A prune in a branch, once its checks pass, moves no horizon: it answers `200` with the resource's current horizon as the branch sees it, or its genesis id where it has none, ignores `keep`, and writes nothing.

- **Archive.** Before pruning, the server writes the pruned history as a full-history bundle (§G.4.1), with `"authors": true` and grant lines, to a destination configured by the operator or in `retention`, and MUST NOT write anywhere else. Only two prunes go without one: under a `*` key where no destination is configured (Request), and applying a retention rule that says `"archive": false` (Retention policy).

  - Kept ids let anyone check an archived revision against the live chain.

  - In encrypted namespaces (Addendum E), archives are sealed bundles (§G.5.1.1), one per resource, whose only recipient is a key the server holds for that resource, which purge destroys (§E.1). At E3, where the server can't compute documents, a key-holding client supplies `H`'s document (the last live one when `H` is a tombstone) as `snapshot`, sealed like a patch set (§E.3.1), and pruning needs an archive: a prune there without `snapshot`, or where no archive is configured, is `422` (`invalid`), with or without a `*` key, as `keep` is there, and so is a `snapshot` anywhere else. At E3, if the effective horizon moves the horizon but isn't `H`, the prune is `422` (`invalid`) with it as `horizon`, and the client resends with that revision's document; the server already holds its declared blob list. So the server skips E3 namespaces when it applies retention: there a key-holding janitor, a client with `read`, `prune` and the epoch keys, applies it: it folds each resource, picks the horizon its `retention` asks for, and submits the prune with the sealed `snapshot`.

  - Restoring archived history into the live store is an operational task.

- **Retention policy.** The namespace document may declare rules that the server, or a janitor with `prune`, applies periodically:
```
"retention": [
  { "select": { "prefix": "telemetry-" }, "keep": { "revisions": 50, "age": "PT10M" } },
  { "keep": { "age": "P2Y" }, "archive": "s3://archive/matches/" } ]
```

  - The first rule whose `select` matches a resource applies. `select` is a name `prefix`, or a list of `names`. A missing `select` matches everything.

  - `keep` keeps whichever is longer: the last `revisions`, or everything newer than `age`. Protected revisions always stay. A rule without `keep`, or whose `keep` has neither, is `422` (`invalid`, §7.4).

  - `archive` is the rule's archive destination, by default the operator's. A rule with neither applies only if it says `"archive": false`, which is `422` in an E3 namespace; otherwise the resources it selects keep everything, as where no rule matches.

  - Changing `/retention` requires a `*` key (§7.4).

- **The namespace log is never pruned.**

- **Pruning is not purge.** Cached and consumers' copies of pruned revisions are untouched, and stay correct. For removal, use purge (§8.3), which also reaches archives.

- **Verification.** Below the horizon, ids can be checked only against the archive (invariant 4), so a client verifying through logs (§G.2) starts from it, or from a revision at or after `H` that it has already verified.

- **Merges, branches and exports.** Classification by ancestry (§F.3) uses ids only, so it works across a horizon. Fast-forward and replay need the patch sets after the common ancestor, which protected revisions keep for local branches and unexpired remote ones; otherwise an item whose needed history was pruned is a conflict. A full-history export (§G.4.3) from before the horizon needs the archive; otherwise use snapshot mode.

---

## 9. Caching

**Public namespaces:**

| Response | Cache-Control | Tag (`Cache-Tag` / `Surrogate-Key`) |
|---|---|---|
| Head pointer (resource or namespace `302`, head `410`) | `public, max-age=0, s-maxage=1, stale-while-revalidate=5` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Immutable (`/rev/{id}`, `/rev/{id}/log`, `/ns/{ns}/rev/{ns_id}`, its `/heads` pages (also tagged `heads:{ns}`, §7.4), namespace log ranges (sealed ones may be sealed again with other bytes, §E.2.2), `/ns/{ns}/grants/{gid}` (`private` at E3, §C.3.1), `/blob/{bid}`, `/blob/{bid}/e/{e}` and their ranges) | `public, max-age=86400, s-maxage=31536000, immutable` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Short (unknown id `404`) | `public, max-age=5` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Long (`410` of a purged resource or namespace, on a URL that isn't `no-store`, §8.3, §8.5) | `public, max-age=86400, s-maxage=31536000` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Pruned (`410` below a horizon) | `public, max-age=3600` | `r:{ns}/{name}`, `ns:{ns}` |
| Live long-poll (§7.7) | `200`: `public, max-age=0, s-maxage={interval}` · `204`: `public, max-age=0, s-maxage=2` | as the log |
| Writes, batches, dry runs, SSE, a `502` (§G.3) | `no-store` | — |

-
**Browsers keep immutable content for a day, the CDN for a year,** since only the CDN can be purged.

-
**Serving stale.** An edge MAY keep serving immutable responses while the origin is unreachable; a purge still removes them. Head pointers are served stale only within their `stale-while-revalidate`. Live long-poll answers (§7.7), `200` and `204` alike, MUST NOT be served stale: they carry no `stale-*` directive, and an edge MUST NOT apply stale-if-error or grace defaults to them.

-
**Empty long-poll answers.** The `204` that ends a wait with nothing new is cacheable too, for its own lifetime (§7.7), and a CDN that doesn't cache `204` by default SHOULD be configured to cache these responses.

-
**Tags** are `{kind}:{value}`, where `kind` is a lowercase word (§12.8) and `value` is namespace and resource names (§3.6) joined by `/`. `Cache-Tag` lists a response's tags separated by commas, and `Surrogate-Key` the same tags separated by spaces. A purge names whole tags, never part of one. How purges reach the CDN is deployment-specific; for a self-hosted CDN, a `PURGE` request with the tags in `X-Purge-Tags`, separated by spaces, is a reasonable convention.

-
**Branches** are cached like any namespace, under their own URLs and tags, which purges propagated to them (§8.3) purge too.

**Sealed namespaces** (Addendum E) are cached by their `read` mode, like any other.

**Private namespaces** (Addendum C §C.5):

- **Downstream** responses carry `Cache-Control: private`, with a `max-age` no longer than their public class's (e.g. `private, max-age=300` for immutable content).

- **Edge caching needs an edge that verifies an edge grant on every request** (§C.5):

  - **With a verifying edge**, the origin gives edge lifetimes with `CDN-Cache-Control` (RFC 9213) or `Surrogate-Control`, at the values for public namespaces, only to a read the edge verified itself, as its two headers say (§C.5.3): only when both are present, each header is one line without a comma, the secret matches, the prefix covers the URL, and the request carries no other credential: no `Authorization`, `Source-Authorization` or signed-URL parameters. The origin still authorises the read itself, from the cookie or grant, which the edge forwards (§C.5.3); the headers decide only the lifetimes, never when an event stream ends (§7.3).

  - **Everything else private is `CDN-Cache-Control: no-store`** (and `Surrogate-Control: no-store`), with or without an edge: reads with a grant in `Authorization`, schema revisions opened by a referrer (§6.1), and reads the edge only relayed.

  - **Without one** (no CDN, or a CDN that doesn't verify grants), every private response is therefore `no-store`, and only public namespaces are cached at the edge. The origin is configured with which deployment it is in.

- **Making a namespace private**, or raising it to sealed or end-to-end, requires a purge of the tag `ns:{ns}`, which every response of the namespace that the table above tags carries, issued by the origin with the configuration write. Copies already in browsers remain until their `max-age` expires.

---

## 10. Namespace consumers

A **namespace consumer** (§2), such as a search index or a feed, is a client of the public API with no private access to storage. It works as follows:

- **Checkpoint.** A consumer stores the last `ns_id` it has fully processed. `""` means from the beginning.

- **Catch up.** `GET /ns/{ns}` gives the current `ns_id`. `GET /ns/{ns}/rev/{current}/log?since={checkpoint}` returns the entries in between, page by page (§7.1), and is cacheable.

- **Follow.** `GET /ns/{ns}/events?since={checkpoint}` streams new entries. Where many consumers or pages follow the same namespace, long-poll `GET /ns/{ns}/log?since={checkpoint}&live=long-poll` instead (§7.7), in a private namespace with an edge-grant cookie, since only reads under an edge grant collapse (§9, §C.5).

- **Coalesce.** Within a range of entries, only the latest `head`, `tombstone` or `purge` entry per resource matters, inside batches too. A new consumer that needs only current state lists `GET /ns/{ns}/rev/{current}/heads` (§7.4; `410` once purged, §8.5), or scans the log once and fetches each resource's last revision, and then follows from `current`.

- **Fetch content** from immutable URLs: `/r/{ns}/{name}/rev/{id}`, schema revisions and blobs (§7.8).

- **Handle every kind of entry:**

  - `head` → process the document

  - `tombstone` → drop the resource

  - `purge` → drop the resource **and purge derived data and cache tags**

  - `config` → the configuration changed, including `frozen` and `successor`

  - `batch` → process its entries **as one unit**, so derived data never shows half a batch

  - `purge-ns` → drop everything from the namespace, and purge derived data and cache tags. Where log ranges are sealed, a `410` `purged` stands for it (§8.5).

  - `branch` → with `name`, a branch was created, which consumers that follow branches start following (below); with `remote`, a remote branch was registered or renewed, which consumers never fetch from (§G.3).

  - `prune` → usually ignored. A consumer that fetches a pruned revision gets `410 pruned` (§8.6) and fetches the head instead; if the head is pruned too, as a branch's read-through one can be (§7.6), it treats the resource as absent until a later entry.

- **Advance the checkpoint** only after the entries are durably processed. Processing is idempotent.

- **Verifying grants.** Consumers that verify grants presented to them (Addendum C, §C.6) MUST check keys and revocations as of the namespace **head**, and in a branch as of its local bases' heads too (§C.4), not as of their checkpoint. Grants recorded with entries are verified as §C.3.1 says.

- **Consumers elsewhere**, in another network or organisation, record their checkpoint as `(origin, ns, ns_id)` and verify what they fetch as §G.2 says.

- **Branches.**

  - **Discovery.** A consumer that follows branches learns of them from `branch` entries with `name` in the logs it already follows, recursively, and, if it started from `/heads` (step 4), of earlier ones from `GET /ns/{ns}/branches` (§7.4). Frozen and purged states then arrive in the branch's own log, as `config` and `purge-ns` entries (step 6).

  - **Contents.** A consumer can't reuse its own view of the base: it starts from the branch's `/heads` listing at the branch's first `ns_id`, which includes read-through resources, then follows the branch's own log. So too for a branch it is told to follow directly, such as one named in a release document (§F.9).

  - **Access.** It needs unrestricted `read` on the branch (§2.1). A consumer that learns of a branch it may not read skips it.

- **The core derives nothing:** no indexing, search or organising. Addenda A and B describe consumers that do.

---

## 11. Client behaviour (non-normative)

- **load:** `GET /r/{ns}/{name}`, following the redirect; the head is `X-Revision`.

- **sync(to):** `GET …/rev/{to}/log?since={head}`, following pages until `to` arrives (§7.1); apply the entries in order.

- **submit(patches):** `PATCH` with `If-Match: "{head}"`. On `201` or `200`, apply the returned revision. On `412`, `sync(body.head)` and resend the same patches, re-sealed at E3 (§E.3.1) and re-signed if signed (§C.3.1): this is the rebase. On `422` or `403`, surface the errors. Retry a bounded number of times.

- **Conflict safety:** prefix a set that must not land on changed data with `{ "op": "test", "path": …, "value": <value seen> }`; a retry on changed data then fails with `422`, or at E3, where the server applies nothing (§6.2), when the client applies it to the new head before re-sealing.

- **watch:** SSE from `since={head}`, or long-poll echoing `X-Cursor` (§7.7). De-duplicate by entry id: the client's own writes echo back.

- **Deleted resources:** a `410` on the head means deleted. A `successor` (§8.1) means the resource moved: offer it as a link, and follow it automatically only into a namespace the client already trusts; a catalog grants nothing there (Addendum B). Where the `410` can't carry one (sealed, end-to-end), read `$successor` from the document at `last`. At E3 ignore a `410`'s `successor`, which a conforming server never sends there, and read the verified document at `last`; a sealed-namespace client that doesn't trust caches does the same before following one automatically.

- **Frozen namespaces:** on `409 frozen` with a `successor`, load the resource there and replay the pending patch sets, the same loop as a rebase on `412`.

- **Combining changes under a rate limit:** while a save is in flight, collect edits into one pending patch set, the diff from the last saved revision, and send it when the response arrives. If that response is lost, first resend the in-flight set **unchanged** (§7.2), then the rest. On `429`, wait for `Retry-After`, then send what has accumulated. A combined set carries one `Gesture`, so combining across actions makes them one gesture for undo (§11.2).

- **Presence is out of scope.** As writes, cursors and selections would exceed `ratePerResource` (§6.6) and stay in the log. Use a side channel that admits a client with the same read decision as the resource (§C.5), stamps each message with the verified principal, and keeps nothing.

### 11.1 Designing documents

-
**Object member order isn't kept** (§3.1). Where order matters, use an array of objects with an `id` member, which `x-ref` with `key` can address (§6.5), or an explicit `order` field.

-
**`$schema` names a revision** (§6.1). Import tooling resolves a schema URL or head path once to the current revision path; a migration (§6.3) moves documents to a later one.

-
**Keep namespace names when moving data.** `$schema` and pinned references contain them, so an import maps each source namespace to the target of the same name (§G.1); renaming rewrites documents and changes every id.

-
**Large values are blobs.** A string longer than `valueSize` can't be stored; upload an image, a PDF or a long transcript as a blob and reference it (§7.8).

-
**Large documents are created whole and then edited in parts.** A create, outside E3 an append or restore that starts with a root `replace` or `add`, and at E3 any restore, may be as large as `documentSize`; other appends are limited by `patchSetSize` (§6.6). Add large parts in several appends, or in one batch when they must land together (§7.5).

-
**Split documents along the lines of access, editing and size.** A document is the unit of read access (§C.5), of concurrency (every save names the head, and per-resource rate limits apply to all of it, §6.6), of merge conflicts (§F.3), and of the cost of every revision.

Split one that grows without bound (a log, a comment thread), has parts with different readers, or is edited by unrelated people at once. Link the parts with `x-ref` (§6.5) and group them with a catalog (Addendum B).

### 11.2 Undo and redo

Gestures (§7.2) make undo work beyond a client's own stack: after a reload, from another device, and from a history view.

-
**Recording.** When an action starts, the client picks a gesture id and sends it as `Gesture` with every write the action produces.

-
**Finding a gesture.** `GET /ns/{ns}/gestures/{gesture}` lists its revisions where offered (§7.4). Otherwise the client scans the logs it follows for entries with that `gesture` by the same author. A writer limited to some resources, in a sealed or end-to-end namespace (no listing), scans the logs of the documents it knows the action touched, learning the level, and at E3 the epoch and `pad`, from `/keys` (§E.2.3). Lacking the namespace log, it credits every carried gesture to the merger (see Redo), and reports an undo as impossible when a log it read doesn't begin at genesis and the gesture's oldest entry is that log's oldest, since a pruning horizon may lie there unseen. If that holds for only some resources of a gesture, the undo is partial, and the client asks the user first.

-
**The inverse.** For each resource, turn the gesture's own entries, newest first, into steps of one batch item (§7.5):

  - a revision: the patch set that turns its document back into its parent's, limited to the paths it wrote (§6.4.1), with array-element writes widened to the whole array, as for merges (§F.3). A `move` whose two ends are unchanged since is inverted as a `move` back. Add a fresh `$nonce` where §C.7 asks for one, never restoring an old one; where nonces are required, every patch-set step of an inverse adds one, even one before a `"delete"`.

  - a tombstone: a restore with `[]` (§8.2), or just a fresh `$nonce` where one is required.

  - a restore: the inverse of its patches, then `"delete"`.

  - a genesis: `"delete"`, after the later inverses. A resource the gesture created ends up deleted, not absent.

Edits others made to other paths, even between the gesture's saves, are kept; one made to a path between two of the gesture's own writes to it stays lost.

-
**The guard.** Before writing, compare the `writes` (§6.4.1), widened for arrays as above, of each resource's entries after the gesture's last one with the paths the gesture wrote. Any overlap, or a later delete or restore, is a conflict for a person, as in a merge. The batch names the checked heads in `ifMatch`, so a write landing in between makes it fail with `412`, and the client checks again. No `test` ops are needed; at E3 the client checks against decrypted entries.

-
**Writing it.** Apply the steps to the current heads in one batch (§7.5), with a fresh `Gesture` and `Undoes: <gesture>`, splitting a large inverse into more chained steps to stay within `opsPerSet` and `patchSetSize` (§6.6). An action that touched several namespaces is undone per namespace, possibly only in part.

-
**When undo is impossible:** a revision the inverse needs lies below a pruning horizon (`410`), a blob the earlier document references is no longer available (`422 blob`, §7.8), or a `$schema` migration means the old values no longer validate (`422 invalid`). These are reported as such, not as conflicts.

-
**Redo** is undoing the undo: its `Undoes` names the undo's gesture. An author's undo stack, rebuildable on any device from the log, is the gestures that author made, minus those the same author undid and didn't redo. A gesture a merge carried into the base (§F.3) counts for the author who wrote it in `source.ns` only when the batch counts as a merge under §F.3, and otherwise for whoever wrote the batch, since `source` is unverified. The source author undoes a carried gesture under their own grant, planned against the merger's entries in the base. An undo by someone else is shown as theirs and doesn't drop the gesture from the author's stack, since `Undoes` isn't verified. `Undoes` naming a gesture that no longer exists, such as after a squashed merge (§F.3), is ignored.

-
**Scope.** The server only stores gestures; who may undo what is decided by the ordinary rules for the undo's writes. Undoing a config write is out of scope (§7.2).

### 11.3 Whole-document clients

File-style clients (WebDAV gateways, mounts, sync tools, editors) hold a whole new document and the revision it started from, its **base**, which may be older than the head. They write it as follows:

- **Head is the base.** Send the base-to-new patch set with `If-Match: "{base}"`.

- **Head has moved.** Compute `ours`, the writes (§6.4.1) of the base-to-new patch set plus the `from` of each `copy`, and `theirs`, the writes of the log entries from base to head (§7.1), widening array-element writes to the whole array (§F.3). Any overlap is a conflict, and so is a tombstone or restore between base and head: refuse the save and show both versions. Never merge values. A base whose log range is `410` (§7.1) can't be compared; the client reloads and asks.

- **No overlap.** Send the same base-to-new patches with `If-Match: "{head}"`, re-sealed at E3 (§E.3.1) and re-signed if signed (§C.3.1); never a head-to-new diff, which would revert every edit since the base. A `412` means the head moved again: go back to step 2. The stored document is the head's with these changes, not `new` (at E3, the readers' fold), so read `/rev/{id}` of the new revision.

- **Overwriting on purpose,** whatever the head, is a root `replace` with `If-Match: "{head}"` (up to `documentSize`, §6.6, except at E3), only when the user means to overwrite.

- **Deleted.** A `410` on the head means the document was deleted. If it names a `successor`, or, where it can't (sealed, end-to-end), the document at `last` has a `$successor` (§8.1), the file moved there: the client offers the user the new path rather than writing to it unasked.

Where nonces are required or the namespace is sealed (§C.7), every patch set adds a fresh `$nonce`. The server checks only the precondition; the patch set it stores is the client's.

---

## 12. Registries

§12.1 (errors), §12.2 (limits) and §12.3 (namespace-document members) define what they list; where a §12.3 row states no shape, or only names a structure, the cited section gives it. The other registries are indexes: the cited section governs, and a row adds no requirement; in particular, which query parameters an endpoint accepts is decided by §7's rule for query parameters and the section defining the endpoint.

### 12.1 Errors

```
{ "code": "…", "origin": "…", "ns": "…", "head": "…", "tombstone": "…", "last": "…", "horizon": "…", "archive": "…", "limit": "…", "measured": 0, "max": 0, "retryAfter": 0, "min": [ … ], "config": "…", "successor": "…", "dependents": [ … ], "referencing": [ … ], "items": [ … ], "rule": 0, "path": "/…", "errors": [{ "pointer": "/blocks/1/type", "message": "must be equal to one of the allowed values" }] }
```

| `code` | Status | Meaning |
|---|---|---|
| `bad_input` | 400 | Any `400`, e.g.: not I-JSON (§3.1); a malformed `source` (§3.5); a non-canonical name or URL (empty, dot or escaped path segments included); an unknown or repeated query parameter, or a malformed id, precondition or long-poll value (§7, §7.7); an oversized body without a limit of its own (§6.6); both `If-Match` and `If-None-Match` on a write, a malformed `Gesture` or `Undoes`, or a missing `X-Author` (§7.2, §7.4); a batch naming a resource twice, giving an item two preconditions or no steps, or with neither items nor `config` (§7.5); a malformed upload or copy (§7.8); a malformed or misplaced `Signature` (§C.3.1); an edge-grant exchange that is empty, over its limits or also carries `Authorization`, or a withdrawal without a valid `prefix` (§C.5) |
| `unauthenticated` | 401 | No usable grant: missing, malformed, badly signed, revoked, expired or not yet valid (§7, §C.2, §C.4) |
| `forbidden` | 403 | The grant doesn't allow the request: its `ns`, verbs, key scope or rules (§6.2, §6.4.3, §7), or the key it needs, such as a `*` key (§6.1, §C.2); or the server refuses local branches (§1) |
| `not_found` | 404 | Unknown, or not readable by the caller; `…/raw` of a document that isn't raw (§7.1); a refused blob copy (§7.8) |
| `in_use` | 409 | Purge of the last copy of a referenced schema revision, or of a namespace with dependents or such revisions (§8.5); a config write that would leave a reference without a copy, such as narrowing `drafts.for` (§6.1, `referencing` included); making a namespace with public dependents non-public, raising its level above a dependent's (Addendum E, Levels), or requiring nonces while one doesn't (§7.4, `dependents` included) |
| `frozen` | 409 | A resource write, a batch with items, or a blob upload or copy in a frozen namespace (§8.4; `successor` included, if set) |
| `not_frozen` | 409 | Namespace purge of a namespace that isn't frozen (§8.5) |
| `name_conflict` | 409 | A remote branch would need a schema revision at a path that holds a different history, or in a namespace that is a branch (§G.3) |
| `batch` | as the earliest failing step | One or more batch items failed; `items` lists them (§7.5) |
| `gone` | 410 | A tombstoned head, with `tombstone`, `last` and, outside sealed and end-to-end namespaces, `successor` if its last document's `$successor` is well-formed (§7.1, §8.1); a create, append or delete on a tombstoned resource, with `head` the tombstone (§7.2, §8.1); a revision URL that names a tombstone (§7.1); or a purged resource (§8.3) |
| `purged` | 410 | A `410` of §8.5's table, or a service's for a purged namespace (§A.4, §B.11.4); `head` names the purged namespace's `purge-ns` entry; where a request named several namespaces, or the base is in another deployment, `ns` (and `origin`) name that namespace |
| `stale` | 412 | Precondition failed; `head` or `config` where the request's section gives one and there is one |
| `limit` | 413 / 422 | A limit of §6.6 was exceeded (§8.4, §C.8 included), or set beyond the deployment's bounds; `limit` names it, with `measured` and `max` as §6.6 gives them |
| `unsupported_type` | 415 | A body whose `Content-Type` the endpoint doesn't take: a `PATCH` other than JSON Patch (§7.2, §7.4), another JSON request body not sent as `application/json` (§7.2, §C.5.2), or an upload other than the sealed-blob type at E3 (§7.8) |
| `invalid` | 422 | Patch application or `test` failed (at E3, a refused patch set, `sealed` op or `keyring` document, §E.3.1, §E.3.2), `$schema` validation failed, or any other `422` without a code of its own, such as a refused namespace document (§7.4), prune (§8.6) or branch `at` (§7.6, §G.3) |
| `schema_ref` | 422 | A `$schema`, `$ref` or `$dynamicRef` of a form §6.1 doesn't accept, or naming a branch namespace (§6.1) |
| `schema_unavailable` | 422 | A schema revision path that doesn't resolve for the writer: unknown, purged, pruned without a kept document, a tombstone, not a schema, written at E3, or unreadable (§6.1, §G.3); `path` names it |
| `rule` | 422 | A namespace rule failed; `rule` and `path` locate it (§6.4.3) |
| `precondition_required` | 428 | No precondition, or not the one the request takes (§7.2, §7.5, §7.6); any at all on a prune or blob upload (§7.8, §8.6) |
| `behind` | 503 | A service hasn't caught up with what a query or listing needs (§A.4, §B.5), or with a `min` (§A.5, §B.11.4), or can't yet fetch the keys a view needs (§E.2.6); `Retry-After` is set |
| `upstream` | 502 | A remote branch's creation, or a fetch of what it reads through, failed at its base's deployment (§G.3); a resource whose source was raised to a level the server lacks, in a remote branch or a branch reading through one, for reads and for writes other than purges (§1, §6.2); or a service couldn't read a namespace document a grant names (§A.4). `origin` names the deployment of the remote base in its chain, if any |
| `rate` | 429 | A rate limit of §6.6 was exceeded; `limit`, `retryAfter` and `Retry-After` as §6.6 gives them |
| `pruned` | 410 | The revision is below the horizon without a kept document, or a revision of the log range has its patch set pruned (§7.1, §7.3, §7.7, §8.6), with `horizon` and `archive` as §7.1 gives them; or pruning ended a blob's attachment (§7.8), or removed every revision that served it under an epoch (§E.2.2); or a branch's first write builds on a pruned document (§7.6) |
| `blob` | 422 | A blob reference is malformed (§6.5), names a blob that isn't available, or doesn't match it; a copy names another id (§7.8); or an E3 declared list has duplicates, or a blob not of the sealed type or with a nonce (§E.3.1) |
| `blob_mismatch` | 422 | An uploaded blob doesn't hash to its id (§7.8) |
| `signature` | 422 | An author signature failed verification, or is missing where the namespace requires one (§C.3.1) |
| `nonce` | 422 | A resource write whose resulting document lacks a `$nonce` of the fresh form, differing from the previous document's, in a namespace that requires one, or a sealed one whose server enforces it (§C.7, §E.2.5) |
| `not_offered` | 404 | An optional endpoint or feature this namespace, catalog or deployment doesn't offer, such as `/gestures` or `…/raw` in a sealed namespace (§7.1, §7.4), `/keys` in one that is neither sealed nor end-to-end (§E.2.3), `/edge-grants` with authentication disabled (§C.5), or `lookup` and organising or merge grants where a catalog lacks them (§B.5, §B.11.4, §F.8) |
| `source` | 422 | A batch's local `source.at` isn't in the chain of `source.ns`, for a caller with unrestricted `read` on it, or a `source.origin` that is this deployment's own (§7.5) |

### 12.2 Limits

The limits of §6.6, with their keys in a namespace document's `limits` and their defaults:

| Limit | Key in `limits` | Default |
|---|---|---|
| patch set size | `patchSetSize` | 256 KiB |
| operations per set | `opsPerSet` | 1,000 |
| document size | `documentSize` | 1 MiB (deployment maximum typically 4 MiB) |
| largest string in a document, member names included, as canonical JSON (see Values, §6.6) | `valueSize` | 64 KiB |
| longest JSON Pointer to any value in a document, as canonical JSON | `pathSize` | 2 KiB |
| nesting depth: the arrays and objects on the longest path from the root to a value, the root included (`{"a":[1]}` has 2) | `nestingDepth` | 64 |
| rules in the namespace document: in `rules`, roles and key scopes | `rulesPerNamespace` | 256 |
| rules per grant chain, deployment only | `rulesPerGrant` | 32 |
| grant size, deployment only | `grantSize` | 8 KiB |
| items per batch | `itemsPerBatch` | 1,000 |
| batch size (all items' patch sets) | `batchSize` | 16 MiB |
| bytes of patch sets per log page, sealed ones as served (§7.1, §7.3, §7.7), at least one entry per page, deployment only | `logPageBytes` | 16 MiB |
| log page size, in resource entries, a batch entry counting as its items, for log ranges (§7.1), `/heads` pages and gesture listings (§7.4), event-stream catch-up (§7.3) and long-poll answers (§7.7), deployment only | `logPageSize` | 1,000 entries |
| branch depth (bases of bases), deployment only | `branchDepth` | 8 |
| live local branches per namespace: neither frozen nor purged (§F.6, §G.3) | `branchesPerNamespace` | 100 |
| writes and blob uploads per resource, per principal | `ratePerResource` | 10/s, burst 20 |
| writes and blob uploads per principal | `ratePerPrincipal` | 50/s, burst 100 |
| writes and blob uploads per namespace | `ratePerNamespace` | 500/s, burst 1,000 |
| retry window (history always kept, §8.6), at least the deployment minimum | `retryWindow` | `PT5M` |
| documents kept through `keep`, per resource in total (§8.6) | `keepPerResource` | 100 |
| lifetime of a remote branch registration (§G.3) | `remoteRegistration` | `P30D` |
| blob size (§7.8) | `blobSize` | 64 MiB |
| blob references per document | `blobsPerDocument` | 1,000 |
| bytes of pending blobs, per uploader and namespace, at least 4 KiB per blob | `blobPending` | 256 MiB |
| age at which a pending blob is deleted; at least `retryWindow` (`422`, `code: "limit"`, otherwise) | `blobGrace` | `PT24H` |
| blob bytes uploaded per principal, as `{ "rate", "burst" }` in bytes | `blobRate` | 8 MiB/s, burst 256 MiB |
| edge-grant exchanges and key requests per principal (§C.5, §E.2.3), deployment only | `exchangeRate` | 10/s, burst 100 |

A namespace document that sets a limit marked deployment only is `422` (`invalid`, §7.4). Sizes are integers in bytes, counts are integers (`rulesPerNamespace` and `rulesPerGrant` count every rule form, those nested in `all`, `any`, `not`, `if` and `then` included), durations are ISO 8601 durations as in `retention` (§8.6), and rates are `{ "rate": <per second>, "burst": <bucket size> }`, e.g. `"limits": { "batchSize": 33554432, "ratePerNamespace": { "rate": 200, "burst": 400 } }`.

### 12.3 Namespace-document members

Validated strictly as §7.4 says, which also lists the members whose writes need a `*` key.

| Member | Shape | Defined in |
|---|---|---|
| `read` | `"public"` | `"grant"` | §C.5 |
| `keys` | array of key entries | §C.4 |
| `roles` | object of role definitions | §C.1.1 |
| `revoked` | revocation ids | §C.4 |
| `rules` | array of rules | §6.4 |
| `limits` | object of limits | §6.6, §12.2 |
| `allowances` | array of allowances | §6.6 |
| `retention` | retention rules | §8.6 |
| `encryption` | `{ "level": "at-rest" | "sealed" | "e2e", "epoch"?, "pad"?, "historyEpochs"? }`: `epoch` an integer ≥ 0 (default 0), `pad` a boolean (default false), `historyEpochs` an integer ≥ 0 (no cap without it), the last three only at `sealed` and `e2e` | Addendum E |
| `maxLag` | ISO 8601 duration, as in the example of §B.11.3 | §C.4 |
| `base` | `{ "ns", "at" }`, or for a remote branch `{ "origin", "ns", "at", "chain": [names] }` | §7.4, §7.6, §G.3 |
| `frozen`, `successor` |  | §7.4, §8.4 |
| `drafts` | `{ "for": [names or prefixes] }` | §6.1, §7.4 |
| `signatures` | `"optional"` | `"required"` | §C.3.1 |
| `nonce` | `"optional"` | `"required"` | §C.7 |
| `schemaReads` | `{ "for": [names or prefixes] }` | §6.1 |
| `catalog` (Addendum B) | `{ "trust"?: [namespace names], "mode"?: "tree" | "dag", "title"?: pointer, "files"?: { "ns", "root", "folder"?, "placement"? } }`, with `root` a folder node name, `folder` and `placement` schema revision paths, and `x-` members allowed | §B.5, §B.6, §H.2 |
| `catalogs` (Addendum B) | `{ "<catalog>": { "place"?: [subjects] } }`, where subjects are `group:…` or `user:…` | §B.11 |
| `merge` (Addendum F) | `{ "authors": [{ "sub", "kid" }] }` | §F.3 |
| `merged` (Addendum F) | `{ "at" }` | §F.3, §F.6 |
| `cleanup` (Addendum F) | `{ "merged"?, "superseded"?, "abandoned"? }`, as ISO 8601 durations | §F.6 |
| `abandoned` (Addendum F) | boolean | §F.6 |

Addendum F's members may appear in any namespace. They mean something in branches, and a base's own `cleanup` sets its branches' minimums (§F.6).

### 12.4 Query parameters

On the core server. Services of the addenda define their own (§A.4, §B.5, §B.11).

| Parameter | Endpoints | Value | Defined in |
|---|---|---|---|
| `since` | resource and namespace log ranges, event streams and long-poll URLs | an id or `ns_id`, or empty for genesis | §7.1, §7.3, §7.4, §7.7 |
| `live` | long-poll URLs | `long-poll` | §7.7 |
| `cursor` | long-poll URLs | an `X-Cursor` value | §7.7 |
| `after` | `/heads` pages; gesture listings | a resource name; an `X-Log-Next` value | §7.4 |
| `dry-run` | `POST /ns/{ns}/batch` | flag, `1` | §7.5 |
| `force` | `POST /r/{ns}/{name}/purge`, `POST /ns/{ns}/purge` | flag, `1` | §6.1, §8.5 |
| `prefix` | `DELETE /edge-grants`, repeatable | an edge prefix | §C.5.4 |

### 12.5 Headers

Headers this spec defines, and standard headers it gives a particular use.

| Header | In | Defined in |
|---|---|---|
| `Authorization` | request: a grant | §7.2, §C.1 |
| `X-Author` | request, with authentication disabled | §7.2 |
| `If-Match`, `If-None-Match` | request: preconditions, and `If-None-Match` for conditional reads | §7.1, §7.2, §7.4, §7.6 |
| `If-Modified-Since` | request | §7.1 |
| `Content-Type` | request: JSON Patch for resource and namespace writes, JSON for other bodies, the blob's type for uploads; response: the blob's type on blob reads, and the sealed types | §7.2, §7.4, §7.5, §7.8, §C.5.2, §E.2.2 |
| `Content-Length` | request: blob uploads | §6.6 |
| `Signature` | request: an author signature | §C.3.1 |
| `Gesture`, `Undoes` | request and response | §7.2 |
| `Source-Authorization` | request, repeatable | §7.5, §7.8 |
| `Blob-Nonce`, `Blob-From` | request: blob uploads and copies | §7.8 |
| `Range`, `If-Range` | request: blob reads | §7, §7.8, §E.2.2 |
| `Last-Event-ID` | request: event streams | §7.3 |
| `Cookie` | request: edge grants | §C.5.3 |
| `Origin` | request: browsers | §7 |
| `ETag`, `Location` | response | §7 |
| `X-Revision` | response | §7.1, §7.7 |
| `X-Namespace-Revision` | response to a write that records a namespace entry, and long-poll answers | §7.2, §7.4, §7.5, §7.6, §7.7 |
| `X-Config-Revision` | response | §7.4, §7.5 |
| `X-Cursor` | response: long-poll | §7.7 |
| `X-Log-Next` | response: paged logs and listings | §7.1, §7.4 |
| `Last-Modified`, `Repr-Digest` | response: plaintext reads | §7.1 |
| `Retry-After` | response: `429`, and a service's `503` | §6.6, §12.1, §A.5, §B.5 |
| `Accept-Ranges`, `Content-Range` | response: blob reads | §7.8, §E.2.2 |
| `Content-Security-Policy`, `X-Content-Type-Options`, `Content-Disposition` | response: blob reads | §7.8 |
| `Cache-Control`, `CDN-Cache-Control`, `Surrogate-Control` | response | §9 |
| `Cache-Tag`, `Surrogate-Key` | response: cache tags | §9 |
| `Set-Cookie` | response: edge grants | §C.5.2, §C.5.4 |
| `Vary`, `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Expose-Headers`, `Access-Control-Max-Age`, `Access-Control-Allow-Credentials` | response: browsers | §7, §C.5.2 |
| `X-Edge-Verified`, `X-Edge-Prefix` | edge to origin, the default names | §C.5.3 |
| `X-Purge-Tags` | purge request to a self-hosted CDN, by convention | §9 |

### 12.6 Verbs

What a grant's `can` and a role may list (§C.1), and the envelope's `action` (§6.4.1).

| Verb | Allows | Defined in |
|---|---|---|
| `read` | reading | §C.5 |
| `create`, `append`, `restore` | creating, appending to and restoring a resource | §7.2, §8.2 |
| `delete` | deleting a resource | §8.1 |
| `purge` | purging a resource | §C.1, §8.3 |
| `config` | writing the namespace document | §7.4 |
| `branch` | creating a branch | §7.6 |
| `purge-ns` | purging a namespace | §8.5 |
| `export` | registering a remote branch | §G.3 |
| `prune` | pruning a resource's history | §8.6 |
| `*` | keys only | §C.1, §C.4 |

### 12.7 Entry kinds

A resource log's entries are of kind `rev` or `tombstone` (§7.1), and its event stream's events of type `revision`, `tombstone`, `purge` or `prune` (§7.3). Namespace entry kinds (§3.5), also the namespace event types (§7.4):

| Kind | Written by | Defined in |
|---|---|---|
| `head` | a create, append or restore | §3.5, §7.2 |
| `tombstone` | a delete | §8.1 |
| `purge` | a resource purge, its propagation, or one applied from a remote base | §8.3, §G.3 |
| `config` | a namespace-document write | §7.4 |
| `batch` | a batch | §7.5 |
| `branch` | creating a branch, or registering or renewing a remote one | §7.6, §G.3 |
| `purge-ns` | a namespace purge | §8.5 |
| `prune` | pruning | §8.6 |

### 12.8 Cache-tag kinds

Tags are `{kind}:{value}` (§9).

| Tag | On | Defined in |
|---|---|---|
| `ns:{ns}` | every response of the namespace that §9's table tags | §9 |
| `r:{ns}/{name}` | responses for the resource | §9 |
| `heads:{ns}` | `/heads` pages | §7.4 |
| `idx:{ns}` | index answers (Addendum A) | §A.4 |

### 12.9 Reserved keys and schema keywords

| Name | Where | Defined in |
|---|---|---|
| `$schema` | top level of a document | §6.1 |
| `$nonce` | top level of a document | §6.4.1, §C.7 |
| `$successor` | top level of a document | §8.1 |
| `$access`, `$parents` | top level of a document (Addendum B) | §B.11, §B.9 |
| `$blob` | any depth | §6.5, §7.8 |
| `$id`, `$ref`, `$dynamicRef` | schema keywords, constrained | §6.1 |
| `definitions`, `dependencies`, `$recursiveAnchor`, `$recursiveRef` | schema keywords: the first read as `$defs`, the rest invalid | §6.5 |
| `x-*` | schema keywords: annotations | §6.5 |
| `x-ref` | schema keyword | §6.5 |
| `x-index` | schema keyword (Addendum A) | §A.2 |

---

## 13. Open questions

- **External schemas:** allow `https://…#sha256=…` pinned references? If so, where are fetched copies stored, under what allowlist?

- **Merge helpers:** automatic `test` op generation for fields an editor displayed?

- **Create conflicts:** a create's `412`, or `410` (`gone`) with the tombstone, and a batch dry run's per-item preconditions, show the existing head to a holder that may have only `create`. Ids aren't secrets (§C.5), but should they omit it?

- **E3 documents:** what should `/rev/{id}` serve where the server can't fold, other than a prune's stored snapshot (§7.1)? Head redirects and remote read-through (§G.3) assume a document.

- **E3 document size:** sealing grows a whole-document create or restore by about half, so should `documentSize` allow for it at E3, as `patchSetSize` does, or should clients check the sealed size (§6.6)?

- **Blobs:** resumable or chunked uploads for very large blobs? A sealed-blob format whose ranges decrypt alone (§E.2.2)?

- **Scoped branches:** a branch whose read-through is limited to the resources its creator could read at `at`, so editors limited to some documents could branch without a service (§F.8).

- **E3 prunes in branches:** should a branch's prune at E3, which moves nothing (§8.6), skip the `snapshot` and archive checks?

- **Service cursors:** when an index or tree service redirects a page URL whose `at` it no longer keeps, what becomes of a positional `after` (§A.4, §B.5, §E.2.6)?

- **Mirrored schemas:** which namespace entries record the schema histories a remote branch mirrors at creation (§G.3), and is a creation that fails at a later mirror undone in the earlier ones (invariant 5)?

- **Server-written entries:** what `author` and `via` do the entries the server writes itself carry (propagated purges, purges applied from a remote base, its own prunes, §7.4), which §5 persists: the causing purge's, a deployment identity, or none?

- **Auth:** see the open questions of Addendum C.

---

# Addendum A — Indexing service (suggested)

A search service for typed documents: a namespace consumer (§10) with its own process, storage and URL space.

## A.1 Following the namespace

- Follow the namespace as in §10, with one checkpoint per namespace.

- For each coalesced `head` entry:

  - Fetch `/r/{ns}/{name}/rev/{id}`.

  - Without `$schema`, remove any rows for the resource.

  - A schema document, whose `$schema` is a dialect URL (§6.1), is indexed against that dialect's meta-schema: `schema=` with the dialect URL lists schema documents, and the revision paths of `$ref` keywords at schema positions, fragment dropped, count as references (§A.2).

  - Otherwise fetch the schema revision the document pins (immutable: cache its field map forever), and index the annotated fields and the references (§A.2). A schema revision answering `403`, `404` or `410`, or one the service can't open for want of keys (§6.1, §E.2.3), leaves the document indexed as one without `$schema`.

- `tombstone` → remove the resource's rows. `purge` → also purge `idx:{ns}` from the service's own cache and drop kept results (§A.4). A `config` entry on which §9 purges `ns:{ns}` → purge `idx:{ns}` too.

- Store the checkpoint in the same transaction as the index writes.

## A.2 What gets indexed: `x-index`

- Schemas opt fields in with `"x-index"`: `"text"`, `"facet"` or `"sort"`, or an array of them, e.g. `["facet", "sort"]` (only strings, numbers and booleans are collected, by the walk below and only through the keywords that mark a path, §A.4):

  - `text`: full-text search.

  - `facet`: exact-match filters and counts. Arrays expand to one value per element. A value matches and counts as its string form: a string as itself, a number or boolean as its canonical JSON (§3.1).

  - `sort`: ordering, ascending, or descending with `sort=-{path}`. A document sorts by its least value at the path in either direction, numbers before strings before booleans, numbers by value, strings by UTF-8 bytes and `false` before `true`, and documents without one last in either direction.

- **References** need no `x-index`: walk each document with the schema revision it pins, not the schema's head, and keep the references §6.5's walk finds. Store each target as `{ ns, name }`, with the revision of a pinned reference and the entry of an `#id` one, and its path: the full instance pointer, array indices included (`/related/0`). `x-index` rows name the field, without indices.

  - References in untyped documents aren't found.

  - Don't scan text for paths instead: an embedded copy of another document, or an id mentioned in prose, isn't a reference.

## A.3 Storage (example, SQLite)

```
CREATE TABLE checkpoints (ns TEXT PRIMARY KEY, ns_id TEXT NOT NULL);
CREATE TABLE docs  (ns TEXT, resource TEXT, head TEXT, schema TEXT, PRIMARY KEY (ns, resource));
CREATE VIRTUAL TABLE text USING fts5(ns UNINDEXED, resource UNINDEXED, schema UNINDEXED, path UNINDEXED, body);
CREATE TABLE facet (ns TEXT, resource TEXT, schema TEXT, path TEXT, value TEXT, PRIMARY KEY (ns, resource, path, value));
CREATE TABLE sort  (ns TEXT, resource TEXT, schema TEXT, path TEXT, value,      PRIMARY KEY (ns, resource, path));
CREATE TABLE refs  (ns TEXT, resource TEXT, schema TEXT, path TEXT, ref TEXT,  -- ref as written
                    target_ns TEXT, target TEXT, rev TEXT, entry TEXT, PRIMARY KEY (ns, resource, path));
CREATE INDEX facet_q ON facet (ns, schema, path, value);
CREATE INDEX sort_q  ON sort  (ns, schema, path, value);
CREATE INDEX refs_q  ON refs  (target_ns, target, rev, entry);
```

Current state only; for history, replay the resource log.

## A.4 Query API

Served on the indexing service's own origin, e.g. `https://search.example/`.

| Request | Response | Cache-Control |
|---|---|---|
| `GET /{ns}?q=…&schema=…&facet[/blocks/type]=poll&sort=/kickoff` | `302` to `/{ns}/at/{checkpoint ns_id}?…`, or `/{ns}/g/{gs}/at/…` for private namespaces (below) | head pointer; `private, no-store` where the redirect adds `/g/{gs}` (§B.11.5) |
| `GET /{ns}/at/{ns_id}?…` | `200` with `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", …facets }] }` | immutable. Tags `idx:{ns}` and `r:{ns}/{name}` for every hit |
| same, an `ns_id` the service no longer keeps results for | `302` to the current checkpoint | head pointer |

-
**Bounded redirects.** A service SHOULD answer `200` at any `at` it redirected to for a while afterwards (e.g. a minute), computing or keeping that result, so one redirect suffices. A kept result mustn't outlive the reads it was computed for: a service keys kept results by what the reader reads whole too, and drops those computed before reads narrowed.

-
A query of a namespace the service doesn't follow, or of a sealed or end-to-end one whose keys it lacks (§E.2.6), is `404`, and of a purged one `410` (`purged`). Until the service has a checkpoint for one it follows, a query of it is answered, once the reader's grant verifies, `503`, `no-store`, with `code: "behind"` and `Retry-After` (§B.5).

-
`schema` filters by an exact `$schema` reference, or by a schema's resource path `/r/{ns}/{name}` to match all its revisions.

-
`ref` finds the documents of `{ns}` that reference a resource, and combines with the other filters:

  - `?ref=/r/{ns2}/{name}`: references to it in any form, live, pinned or to an entry

  - `?ref=/r/{ns2}/{name}/rev/{id}`: only those pinned to that revision

  - `?ref=/r/{ns2}/{name}%23{entry}`: only those naming that entry, pinned or not.

  - `?ref=/r/{ns2}/{name}/rev/{id}%23{entry}`: only those naming that entry and pinned to that revision.

**Across namespaces.** `GET /_refs?to=<reference>`, with `to` in any of the forms above, asks every namespace the service follows that the reader may see.

  - It redirects to `/_refs/g/{gs}/at/{at}?to=…`, with `at` the combined checkpoint (§B.5) over only the namespaces the reader may see.

  - **`gs`** is computed, and its URLs served, as in §B.11.5, but over these markers: `reads:{ns}` for each followed namespace that isn't public and where the reader's grant would be issued a namespace-wide edge grant (§C.5.2), and `reads:{ns}:scope:{digest}` for one where it allows `read` otherwise, `digest` covering the rules that limit it there, of its blocks, its key's scope and each effective role that lists `read` (§2.1), and the `/principal` values they refer to. A namespace where those rules refer to `/now` counts as unreadable. Readers with no marker share the empty set's `gs`, and so do requests with neither a grant nor a cookie, `401` only as **Coverage** says; the path always has `/g/{gs}`.

  - It takes `?min={ns}:{ns_id}`, repeatable, as any `at` URL does (§A.5); a `min` for a namespace the reader can't see, or the service doesn't follow, is `400`, purged ones excepted (§A.5).

  - **Answers** are `{ "at", "namespaces": { ns: ns_id, … }, "hits": [ … ], "next"? }`, where `namespaces` lists what `at` covers. Hits carry `ns` beside the fields of a `ref` hit, are filtered per item by those rules as catalog listings are (§B.11.5), and come in byte order of `ns`, then resource name. A page holds at most `limit` hits (the service sets a default and a maximum, and a larger `limit` is `400`), strictly after `after`, given as `{ns}/{name}` and compared as the pair (`ns`, name), split at its first `/`; `next` is the `after` of the following page, absent on the last. For a namespace read only in part, `at` and its `ns_id` show when it changed (§C.6). Hits from sealed and end-to-end namespaces are sealed per entry (§E.2.6), never as a whole response.

  - **Coverage.** It includes branch previews (§F.8), and leaves out namespaces it hasn't reached yet, purged ones, and sealed or end-to-end ones whose keys it lacks; a `min` naming one of those, purged ones excepted (§A.5), is `400`. Only a reader who may see none of the namespaces gets `401` or `403`. If the service can't read the namespace document of one the grant names, the answer is `502`; any other namespace whose document it can't read is left out, as one the reader can't see.

  - It is tagged `idx:{ns}` for every namespace in `at`, and `r:{ns}/{name}` per hit.

Each hit of a `ref` query carries `refs: [{ "path", "ref" }]`, the locations and the strings that matched, as written; hits of other queries don't. Hits come in `sort` order where it is given, else, for a query with `q`, by descending `score`, else by resource name, and ties go by resource name. Every query pages as `/_refs` does, with `after` a bare resource name, or, for a query with `q` or `sort`, the opaque value its `next` gives. A document that references itself is a hit of its own query, with `"self": true`.

-
**Delete guards are advisory:** a guard asks with `?min=` (§A.5) and can still race a write that adds a reference. The core enforces references only for schemas (§6.1).

-
**Branches.** In a branch's preview index (§F.8), `ref` matches targets as written, naming the base (§F.9), and hits are the branch's versions of the referrers.

-
Hits carry the plain document URL (`/r/{ns}/{name}/rev/{id}`), served by the core's CDN, never by the search service.

-
**Fields in hits.** Hits carry their facet and `sort` values, each as `"<path>": [values]`, a list even for one value; a path marked both `facet` and `sort` shows its facet values. `fields=/name,/title` also asks for those indexed fields, `text` ones included. `counts=/a,/b` adds `counts`, `{ "<path>": { "<value>": <hits> } }`, over every hit, not only the page. A `fields` path that no schema indexed in `{ns}` for a document the reader may see marks with `x-index`, a `facet[…]` or `counts` path none of those schemas marks `facet`, or a `sort` path none of them marks `sort`, is `400`. A schema **marks** a path when an `x-index` is reachable from its root along that path, whatever the data: through `$ref` and `$dynamicRef`, `properties`, `patternProperties`, `additionalProperties`, `dependentSchemas`, `items`, `prefixItems` and `contains`, and every branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, never through `not`, `propertyNames` or `unevaluated*`; array items count at their array's path (§A.2). A marked path that a hit has no values at is left out of that hit.

-
**Private namespaces:** results are served at `/{ns}/g/{gs}/at/{ns_id}?…`, with `gs` and its URLs as for `/_refs` (above), and hits filtered as there, over `{ns}` alone, each `score` computed only from documents the reader may see; a reader with no marker for `{ns}` gets `401` or `403`.

-
**Sealed and end-to-end namespaces:** results are sealed as in §E.2.6. At E3 only a service that holds keys can walk documents (§E.3.2).

## A.5 Consistency

- The index is **eventually consistent**. Every response states `at`, the `ns_id` it reflects.

- **Read-your-writes:** `?min={ns_id}`, once, on a query of one namespace (or `?min={ns}:{ns_id}`, repeatable, for a service that follows several namespaces, §B.5) waits (bounded, e.g. 2 s) until the checkpoint is at or past `min`, or else answers `503`, `no-store`, with `code: "behind"` and `Retry-After`. A client takes `min` from `X-Namespace-Revision` on its own write (§7.2).

- **`min` always redirects.** The `302` drops `min`: to the current checkpoint, or, on an `…/at/{at}/…` URL whose `at` already includes every `min`, to the same URL without it. A service that can't tell whether `at` includes them, because it no longer keeps that `at`'s per-namespace checkpoints, or because `min` names a namespace that the URL's `at` doesn't cover but the current checkpoint does, and that the reader may see, redirects to the current checkpoint, in one hop. A `min` naming any other namespace is `400` (§A.4), and the body's `min` lists the ones refused. On `/_refs` and tree listings, a `min` naming a purged namespace redirects to the current checkpoint without a read check (a purge is no secret, §E.4). In tree listings, which cover every followed namespace, `302` against `503` shows whether an `ns_id` is in the chain of a namespace whose items the reader can't see, and `400` which namespaces aren't followed; ids and names aren't secrets (§C.5, §E.4). A tool keeps each `min` from its own writes until a listing that carried it has been answered `200` after its redirect, for ten minutes at most, and drops those a `400` lists; a grant that can't see a namespace can't wait for its writes there, and lists from what it wrote. A `200` is never served at a URL with `min` (§E.2.6).

- **Canonical URLs.** A service's redirects give the query in one form: parameters sorted by name, then value, comparing their decoded UTF-8 bytes, and every byte other than ALPHA, DIGIT, `-`, `.`, `_` and `~` percent-encoded in uppercase hex (so a space is `%20`, never `+`). Indexes and tree services (§B.5) answer `200` only at that form and redirect others to it (§E.2.6). Repeatable parameters, such as `min`, are sets, sorted like the rest. A parameter the service doesn't define, or a non-repeatable one given twice, is `400` (§7), and a list whose order matters is one value, such as `fields=/name,/title`.

## A.6 Operations

- **Rebuild:** delete the index and replay from `""`, as a consumer that starts deriving something new does, once (§10). A new schema revision needs no rebuild: documents that switch to it are re-indexed through their head change.

- **Access control:** the service MUST enforce the namespace's read permissions by verifying the reader's grant locally (§C.6).

---

# Addendum B — Organising documents (suggested)

Trees and DAGs over documents, kept apart from them in **catalog namespaces** of folders and **placements**; content namespaces stay untouched. A **tree service** serves listings, and a **catalog service** also derives access from the tree and issues grants (§B.11); both are namespace consumers (§10). The core never interprets any of it.

## B.1 Principles

- **Names are identity; organisation is separate data.** Content names are flat and stable (§3.6), and a document's position is recorded in a catalog, not in the document: moving it never changes its URL, history or cache keys, and editing it never changes its position.

- **A catalog is a namespace.** It has its own documents, rules, keys, history and namespace log. Several catalogs can organise the same content independently.

- **Separate histories, separate permissions.** Moves are in the catalog's history, edits in the content's. Organising a catalog needs no write access to content, and editing content needs none to the catalog.

- **Edges live on the node that moves.** A move is one write to one catalog document, contending only with other moves of that node.

## B.2 Catalog namespaces: folders and placements

A catalog namespace (e.g. `cat-season`) contains two kinds of **node**, told apart by their names:

| Node | Name | Purpose |
|---|---|---|
| **Folder** | no dot, e.g. `season-2026` | a catalog-native grouping: title, settings, access |
| **Placement** | `{ns}.{name}` of the item it places, e.g. `matches.derby` | positions one content document in this catalog |

A placement name splits at its first dot into the **item** `/r/{ns}/{name}` (§3.6); there is no `item` field. An item can be placed only where `{ns}.{name}` has at most 128 characters (§3.6).

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

- **`parents`:** live links to folders **in the same catalog**, each with its own `order`: a folder's children sort by the order on their edge to it.

  - One entry makes a tree node, several make a DAG node, and the catalog chooses by rule (§B.6).

  - No `parents` (or `[]`) makes a root.

  - Folders nest the same way.

- **`order`:** an optional fractional-index sort key among siblings, compared by UTF-8 bytes: between `a1` and `a2`, pick any key in between, e.g. `a1V`; no sibling is rewritten. Unordered siblings sort after ordered ones, and siblings with equal or no `order` by node name.

- **At most one placement per item per catalog,** enforced by the name: "is X in this catalog?" is one lookup of `/r/{catalog}/{ns}.{name}`.

- **Operations:** place by creating the placement, move with `replace /parents`, reorder with `replace /parents/{i}/order`, and remove from the catalog by deleting the placement, which leaves the content document unaffected.

- **Item-level settings** (e.g. `$access`, §B.11) live on its placement, never in the content.

## B.3 Links

A link is a live (`/r/{ns}/{name}`) or pinned (`/r/{ns}/{name}/rev/{id}`) path on this service, as for `x-ref` (§6.5), with names valid under §3.6.

- **Referential integrity** is not enforced. A placement whose item is deleted, or a `parents` entry naming a missing folder or anything but a live link to a folder of this catalog, is **dangling**. The tree service drops it from traversals and reports it (§B.5).

## B.4 Manifests (pinned snapshots)

A **manifest** is a document whose links are all pinned, so its revision id fixes the exact content of everything it lists.

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

- **Creation:** the tree service generates a manifest for a subtree as of a catalog `ns_id` (§B.5), and the client creates it as an ordinary resource.

- **Shared items.** In a DAG, an item reached along several paths has one entry per path, each with that path and the order of its last edge, so an `href` can repeat.

## B.5 Tree service

A consumer of a **catalog namespace**:

- For each coalesced `head` of a node, it replaces that node's outgoing edges from `parents`.

- `tombstone` and `purge` remove them.

- It also follows the content namespaces the catalog trusts (§B.6), and marks a placement whose item is gone, or in a namespace the catalog doesn't trust, dangling.

```
CREATE TABLE checkpoints (ns TEXT PRIMARY KEY, ns_id TEXT NOT NULL);           -- the catalog and each trusted content namespace
CREATE TABLE nodes (href TEXT PRIMARY KEY, kind INTEGER NOT NULL,              -- 0 folder · 1 placement
                    item TEXT, item_head TEXT, title TEXT, state INTEGER NOT NULL DEFAULT 0);  -- 0 live · 1 gone · 2 dangling
CREATE TABLE edges (child TEXT NOT NULL, parent TEXT NOT NULL, ord TEXT, PRIMARY KEY (child, parent));
CREATE INDEX edges_by_parent ON edges (parent, ord, child);
```

**Query API.** Served on the tree service's own origin, or under a root of its own (§C.5.3), which the paths below are relative to. Listings redirect (`302`, head-pointer caching) to `/{catalog}/at/{at}/…` or `/{catalog}/g/{gs}/at/{at}/…`, as §B.11.5 says. `at` is the service's **combined checkpoint**, `text(trunc160(sha256(canonical({ ns: ns_id, … }))))` over the catalog and the content namespaces it follows. A listing at a given `at` never changes, so it uses the immutable class (§9), tagged with every item it shows (`r:{ns}/{name}`) and every namespace in the checkpoint (`ns:{ns}`); a service whose cache the origin's purges don't reach purges these tags itself, as §A.1 does. The service answers `200` at an `at` only if it is current or that exact result was stored, and `302` to the current one otherwise. It SHOULD store the result at an `at` it redirects to for a while (§A.4). `?min={ns}:{ns_id}`, repeatable, gives read-your-writes (§A.5). A service that follows several catalogs keeps a combined checkpoint per catalog. `?min` is judged against the checkpoint of the catalog in the URL, even for a content namespace that other catalogs follow too.

| Request | Returns |
|---|---|
| `…/children?of={folder}` | direct children (folders and items), ordered, paginated as `/_refs` is (§A.4), with an opaque `next`, with `total`, the number of visible children; each node carries `born`, the `created` of its first revision, which in a sealed or end-to-end catalog is sealed per entry (§E.2.6) |
| `…/lookup?path={titles}` | the node a path of titles, joined with `/`, names, from the folder `root` of a file tree (§H.2), or, where `root` is hidden from the reader, from the visible roots of its subject set (§B.11.5), filtered like `children`. Titles compare after NFC and Unicode simple case folding (§H.2); a numbered or escaped display name doesn't resolve, and a tool then lists the folder; where siblings share a title it answers the earliest `born`, then node name; a path that doesn't resolve to a visible node is `404` (§B.11.5). Not offered in catalogs without `files`, or in sealed or end-to-end ones (`404`, `not_offered`) |
| `…/ancestors?of={node}` | every path to a root, for breadcrumbs |
| `…/subtree?of={folder}&depth={n}` | nested listing |
| `…/roots` | nodes without parents |
| `…/orphans` | cyclic nodes, and nodes with parents, all of them gone, dangling or cyclic |
| `…/problems` | cycles, dangling items and dangling parents |
| `…/where?item={/r/ns/name}` | the item's placement and paths in this catalog |
| `…/manifest?of={folder}` | a manifest for the subtree, pinned as of the checkpoint |

-
**Parameters** name a node by its node name (§B.2), and an item as `/r/{ns}/{name}`. One not in this catalog is `404`, and so is one hidden from the reader (§B.11.5).

-
**Fresh listings after a write.** The redirect is cached like a head pointer, by browsers too: a client relisting right after its own write adds `?min` (§A.5), not `no-store`.

-
**Behind.** Until it has caught up with the catalog and every namespace it follows, a service answers listings, once the reader's grant verifies, `503`, `no-store`, with `code: "behind"`, `Retry-After`, and, as `ns`, the namespace it waits for only to a reader with unrestricted `read` (§2.1) of the catalog, never a listing whose placements dangle for want of data. Caught up means reaching the head it read when catch-up started (§10), not a first checkpoint; a restart on the same store doesn't wait again. A namespace it can't follow as configured (purged, refused it, unknown, or sealed or end-to-end without keys it can have) isn't waited for, and its placements dangle (§B.7); a fetch that failed for the moment (a transport error, `5xx`, `429`) is waited for.

-
**Items in listings** carry their content URL and current head, and, in a file tree, `file` (§H.3). The document itself is always fetched from the core's CDN. A catalog may set `"title": <JSON Pointer>` in its `catalog` object; the service then copies the string at that pointer in each item's head into listings as `title`, for items in namespaces that aren't sealed or end-to-end. A placement's own `title` wins over the item's.

-
**Cycles.** The core can't prevent them, and they are handled per node:

  - every node on a cycle (a strongly connected set of more than one node, or a node that is its own parent) is **cyclic**;

  - a cyclic node and all its edges, including edges to parents off the cycle, are left out of traversals, listings and access (§B.11.2);

  - `/problems` lists each cycle as its set of nodes, and `/orphans` lists them too.

Walks are bounded at depth 64, and deeper paths are flagged too.

-
**Shared nodes in DAGs.** `subtree`, `ancestors` and `where` show a node with several parents under each of them. Services MUST bound a response, by the depth limit and a per-response node limit, and report when a response was cut. They SHOULD expand a shared node only at its first occurrence in a `subtree` response and mark later occurrences `"repeat": true`, without children.

-
**Previews of a release** (§F.9). A tree service previewing a release follows the branches its release document lists in place of their bases: `checkpoints` holds those branches, and a placement resolves to the release's branch of its item's namespace, if it lists one. It shows a viewer only branches the viewer can read, serves previews only, and issues no grants (§F.8). A long-running preview service follows the release document's own log (§10), so a new revision of it takes effect without a restart.

-
**`mode` is enforced by the catalog's rules** (§B.6), not by consumers: a `tree` catalog whose rules allow several parents is served as a DAG. A service MAY report nodes with several parents in a `tree` catalog under `/problems`.

## B.6 Catalog namespace document and rules

```
{
  "catalog": { "trust": ["matches", "docs"], "mode": "tree" },
  "rules": [
    { "op": "test", "path": "/resource", "schema": { "pattern": "^([a-z0-9][a-z0-9_-]*|(matches|docs)\\.[a-z0-9][a-z0-9._-]*)$" } },

    { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } },
               { "op": "test", "path": "/doc/parents", "exists": true }],
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

- **`files`** (optional) makes the catalog a file tree (§H.2).

- **`mode`:** `tree` or `dag`. The `maxItems: 1` in the second rule implements `tree`; drop it for a DAG.

- **Parents** are **folders** of this catalog: no dot in the name.

- **No new roots:** every new node must be placed somewhere.

## B.7 Lifecycle

- **Create and place** are two writes with no transaction between them, in either order: a placement may name an item that doesn't exist yet, and dangles until it does.

- **Deleting content** leaves its placements dangling. They drop out of listings and access immediately, and are reported for cleanup.

- **Deleting a placement** removes the item from this catalog only.

- **Deleting a folder does not cascade.** Its children appear under `/orphans`. A recursive delete is a client-driven sequence of `DELETE`s.

- **Restoring** a folder or placement re-attaches everything that pointed at it.

## B.8 Whole-tree documents (small, curated trees)

A small tree, such as a menu (hundreds of nodes, edited rarely and by few people), can be **one document**:

```
{ "$schema": "/r/schemas/menu/rev/1n…",
  "root": { "title": "Site", "children": [
    { "title": "News",   "item": "/r/docs/news" },
    { "title": "Season", "children": [ { "item": "/r/matches/derby" }, { "item": "/r/matches/opener" } ] } ] } }
```

- **Atomic reorganisation.** A multi-node reorganisation is one patch set; a move is a JSON Patch `move` between two `children` arrays.

- **Snapshots for free.** Every revision is a snapshot of the whole tree; pinning it gives a manifest.

- **Trade-offs:** all edits contend on one head, the document grows with the tree (mind the limits in §6.6), and access is per whole tree. Use catalogs (§B.2) for large or busy trees, or where access follows the tree.

## B.9 Self-placing documents (optional shortcut)

A content document MAY carry `$parents` (same shape as `parents`, linking to folders of one catalog). A tree service configured to accept it for a trusted namespace treats it as an **implicit placement**. If an explicit placement for the same item exists, live, deleted or purged, it wins.

- **Trade-off:** convenient for single-tree setups where the same people edit content and organisation, but moving the document means editing it, and organising needs write access to content.

- **Not accepted by default:** the catalog (§B.11) doesn't derive access from self-placements unless the content namespace's rules protect `/$parents` as strictly as the catalog protects placements. Where it does, a Place of a self-placed item also needs what a Move from its `$parents` needs (§B.11.4): `move` on each, and no widening.

## B.10 Access control

- **The core never inherits permissions down a tree;** it checks only the grant presented with a request.

- **A catalog may derive grants from the tree** (§B.11). Authority still flows only through grants.

- **A separate namespace is the strongest boundary** when a whole body of content needs a different audience.

- **Services that list content** MUST enforce read permissions for every node and item they list, titles and structure included.

## B.11 Catalog: tree-derived access

A **catalog service** is a tree service that also **issues grants**: it reads `$access` from folders and placements, computes each subject's roles at each item, and signs narrow, short-lived grants with a scoped key. Its key is listed in the catalog namespace (for organising) and in each trusted content namespace (for reading and editing items).

**Invariant.** Only a role the caller holds at the decision, counted through the catalog's key (§B.11.2), grants, shows or powers anything, and an organising grant permits only the change it judged. Unless its writer is in `catalog-admins`, no write widens any subject's roles at a node that exists or existed, or at an item that is or was placed, as §B.11.4 judges it at the grant's decision (§B.11.8). A hidden node is answered as a missing one, except to `catalog-admins` organising and where §B.11.4 answers `409` (names are not secrets). A listing URL serves a reader only the subject set its credentials prove.

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
  "desk":       { "can": ["read", "create", "append", "restore"] },
  "translator": { "can": ["read", "append"], "rules": [ { "op": "writes", "within": ["/i18n"] } ] },
  "reader":     { "can": ["read"] } }

// catalog namespace document: what each role may do in the tree
"roles": {
  "desk":       { "move": true, "place": true },
  "translator": {},
  "reader":     {} }
```

-
**`$access`** maps subjects (`group:…` or `user:…`) to role names, applied to the **items** below the folder. Role names are all the catalog hands out.

-
A role's verbs and rules come from the content namespace's `roles`, and a namespace that doesn't define a role grants nothing through it.

-
**The catalog namespace defines tree powers:**

  - **`move`:** moving nodes out of or into a folder

  - **`place`:** placing new items directly into a folder

Where a role has them is §B.11.2's.

-
**`inherit: false`** and **`inheritPowers: true`** change the walk up (§B.11.2).

-
**Placements** may carry `$access` too.

-
**`user:` entries** are for exceptions: each user with direct entries gets their own listing cache (§B.11.5).

-
**Schema:** the folder and placement schemas validate the structure of `$access`.

### B.11.2 Effective access

- **Subjects.** A caller's subject set is its `sub`, if it starts with `user:` (e.g. `user:li`), plus `group:{g}` for each of its groups (§B.11.6).

- **Walk up.** A subject `s`'s **roles at a node** are the **union**, over every path from the node up to a root, of the `$access[s]` role names met along that path, including the node's own; an item's are those at its placement. A caller's roles at a node are the union over its subjects.

- **Where a path stops:**

  - it stops collecting **after** a node with `inherit: false`

  - a path that reaches a **tombstoned, purged, dangling or cyclic** node ends there, and that node contributes nothing

  - a dangling placement grants nothing, except, for an item in a namespace the catalog trusts, `create` for an item that has never existed, and `restore` for an item that is tombstoned, not purged, to those of the roles it had when it was deleted that it would have now if live (§B.11.4)

  - deleting a node that isn't cyclic (§B.5) can therefore only narrow access, never widen it

- **Through the key.** In a content namespace, a role **counts** for a verb when the namespace defines it with that verb and the catalog's key there may grant it to the caller: the key's `can` lists the verb, its `roles` scope allows the role, its `sub` scope, if it has one, matches the caller's `sub`, and the role was collected through the caller's `sub` or a group its `groups` scope allows (§B.11.3, §C.4).

- **Across catalogs.** Each catalog the item's namespace trusts issues grants from its own computation, and an item's total access is their union. A content namespace should list, with scoped keys, only the catalogs it trusts to open it up.

- **Allow-only.** There are no denies. Roles are alternatives at the gate (§C.1.1), so a union of roles never grants more than its most permissive role.

- **Tree powers** (`move`, `place`) apply only at the folder where a role granting them is assigned, unless the folder's `$access` sets `"inheritPowers": true`; then roles collected on the walk up from it grant them there too. Powers count only at a live folder that isn't cyclic, and only through subjects the catalog's key in the catalog may assert. At a folder without `$access` but with parents, a subject's role has a power when that subject's role has it at every one of them, each `parents` entry counting, and a tombstoned, purged, dangling or cyclic parent giving none. Moves stay bounded by no widening (§B.11.4).

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
      "groups": { "deny": ["ops"] }, "roles": { "allow": ["desk", "translator", "reader"] },
      "rules": [{ "op": "test", "path": "/principal/roles", "schema": { "minItems": 1 } }] } ],
  "roles": { "desk": { … }, "translator": { … }, "reader": { … } },
  "catalogs": { "cat-season": { "place": ["group:match-desk", "group:editors-in-chief"] } } }
```

- **Scoped keys bound the catalog service.**

  - In the catalog it may create, move and delete nodes, but never change `$access`.

  - In content namespaces it may only grant reading, creating, appending and restoring, reading only in grants that fix `/resource` (§2.1), and only through the roles the content namespace allows it, which its key's `rules` require every grant to carry.

  - It may never assert admin groups.

- **Only `catalog-admins` change access settings**, including via root replaces or `move` from `/$access`. Creates and restores are judged by the document they produce instead: a folder or placement may be created or restored with `$access` only by an admin. Deletes write nothing and pass these rules (§B.11.2).

- **Content owners decide who may bring their content into a catalog.** `catalogs.{catalog}.place` in the *content* namespace lists the subjects (`group:…` or `user:…`) allowed to place its items in that catalog (§B.11.4).

### B.11.4 Issuing grants

```
POST /grants
Authorization: Bearer
{ "item": "/r/matches/derby", "want": ["append"] }
```

- **Resolve** the caller's subjects (§B.11.6) and look up its roles at the item at the current checkpoint, and keep only those that count there for a wanted verb (§B.11.2).

- **Sign a root grant** for exactly that resource, carrying those role names, with an absolute `exp` within `maxTtl`:

```
{ "kid": "catalog-01", "sub": "user:anna", "groups": ["translators"], "roles": ["translator"],
  "ns": ["matches"], "can": ["append"], "exp": "2026-10-04T18:10:00Z", "at": { "ns": "cat-season", "id": "1k…" },
  "rules": [ { "op": "test", "path": "/resource", "value": "derby" } ] }
```

The grant says **where** (`/resource`) and **who** (`roles`). The `/i18n` restriction is not in it: the gate applies it from the content namespace's definition of `translator` (§C.1.1). The catalog grants role names without evaluating their rules, so the gate may still refuse a write under them. Item requests other than Place and Create answer as Restore's list does (below): in a purged namespace `410`; `404`; for a purged item, `403` without a role that counts for `read` at its placement, computed as for a live item, and `410` otherwise; then `403` when no role is kept.

**Read-your-writes.** `POST /grants` and `POST /read-grants` accept `?min={ns}:{ns_id}`, repeatable: the service decides at a checkpoint at or past every `min`, or answers `503` as listings do (§A.5).

- A client passes the `X-Namespace-Revision` of its own placement or `$access` write.

- A decision on an item also depends on its content namespace: after creating a document it placed, or restoring one, a client passes `min` for both.

- **`checkpoint`.** Answers carry `checkpoint`, `{ ns: ns_id, … }`: the `ns_id`s, as of the decision, of every namespace whose state it read: the catalog, each named item's namespace, and, for decisions that read roles or `includes` elsewhere (a folder's visibility, a move's no-widening check), those content namespaces too. A client that caches a decision keys it by those entries. It goes beside each grant, never inside it, and beside refusals decided at it (`403`, `404`, `409`, `410`); a refusal from state it doesn't pin, such as a name the core has and the service hasn't seen yet, has none and isn't cached. It isn't the grants' own `at`, which is the catalog's `ns_id` alone. `POST /grants` answers `200` with `{ "grant", "checkpoint", "parents"?, "head"? }`, `parents` for a Move grant that pins them (below), and `head`, the node's head revision as decided, for a Move or an Unplace or delete; `POST /read-grants` answers `200` with `{ "items": [{ "item", "grant"?, "public"?, "keys"?, "keysWithheld"?, "status"?, "code"? }], "checkpoint" }`, one per item in request order, with `status` and `code` (§12.1) for an item refused or undecided.

Organising requests yield grants for the **catalog** namespace, without `roles`, each with the verb its write needs (`create` for Place and Create a folder, `append` for Move, `delete` for Unplace or delete a folder) unless a request below gives another, fixing `/resource` to the node name and `/doc/parents` to exactly the requested target set, compared by `href`: each entry's `order` is the writer's (§B.2). The answers, unless a request below gives its own, in order: `400` for a malformed request; `404` for a `node`, a new folder's excepted, that isn't an untombstoned node of this catalog, a `to` entry that isn't a live folder of it, or, to a caller not in `catalog-admins`, one hidden from it (§B.11.5), a new folder's name excepted; `403` for a requirement below that fails, or an `item` in a namespace the catalog doesn't trust; then `409`. In an end-to-end catalog, whose writes fail rules on `/doc` (§6.2), the service issues no organising grants (`404`, `not_offered`). A caller in `catalog-admins` needs no tree power; any other also needs a non-empty `to` in a request that takes one, and can't move, unplace or delete a node without parents, or one with a parent hidden from it, since its grant would name that parent.

-
**Place** (`{ "item": …, "want": ["place"], "to": [folders] }`) requires both:

  - the caller is in the content namespace's `catalogs.{catalog}.place` list

  - the caller has a role with `place` on **every** folder in `to`

If an earlier placement of the item was deleted, the grant carries only `restore`, and restores it with a root replace instead of creating it, which must not widen (below). A restore-only grant can't be used as a move: if the placement is live again when it is used, the write is an append, refused at step 2 (§6.2). A Place of an item whose placement is live is `409`, and one whose placement was purged `410`, both where the answers above put `409`. Placements should carry a fresh `$nonce` (§C.7), so their ids can't confirm guesses.

-
**Move** (`{ "node": …, "want": ["move"], "to": [folders] }`) requires a role with `move` on **every** current parent the node leaves and on **every** folder in `to`, and no widening; a `to` entry that is the node or below it is `403`. A Move grant may also change the node's other members, `$access` excepted (§B.11.3): a rename is a move to the node's current parents. Unless the caller is in `catalog-admins`, a Move grant also requires its patch set to begin with a `test` of `/parents` against the node's parents as decided, which the answer gives as `parents`, so it moves the node only from where it was judged.

-
**No widening:** for every subject, the roles of every node after the write must be a subset of those before, unless the caller is in `catalog-admins`. For a move both are roles at a node (§B.11.2), computed as for live items, even for an item that is deleted or not yet created; only the moved node and the nodes below it, along every edge, can change. For re-placing a placement (above) or restoring an item (below), the item's roles from its placement after the write are compared with its frozen rows (§B.11.7). A role counts as present before if it, or a role that includes it, was: a content namespace may declare `"desk": { "can": [ … ], "includes": ["reader"] }`. `includes` is transitive, is read from the item's own content namespace, and is trusted as declared (§C.1.1); a folder's roles compare by name.

-
**Unplace or delete a folder** (`want: ["delete"]` on a node) requires a role with `move` on every current parent. The grant fixes `/doc/parents` to exactly those parents, as above. Folders are restored only by `catalog-admins`, under grants of their own: the service answers a request naming a tombstoned folder `404`, as above.

-
**Create a folder** (`{ "node": …, "want": ["create"], "to": [folders] }`), with `node` a folder name (§B.2; `400` otherwise) that no node has or had, and no `parents` entry or accepted `$parents` (§B.9) names, hidden ones included (`409`; names are not secrets, §E.4), requires a role with `move` on every folder in `to`. Items in it get its parents' roles and, until a `catalog-admins` member gives it `$access` (§B.11.3), each subject's role has the powers there that it has at all its parents (§B.11.2).

-
**Create** (`{ "item": "/r/matches/final", "want": ["create"] }`) makes a new document in a folder:

  - The caller first **places** the new item (above), which dangles until it exists (§B.7).

  - The catalog resolves the caller's roles at that placement and keeps those that count for `create` (§B.11.2).

  - It signs a grant fixed to that name with `can: ["create"]`, which can only ever produce the genesis (a create needs `If-None-Match: *`). Later edits use ordinary `append` grants.

The answers, in order: in a purged namespace `410` (below); `409` for a name that exists or existed in the content namespace, since names are not secrets (§E.4); then `403` for a caller whose item has no placement in this catalog, or who has no role kept.

-
**Restore** (`{ "item": "/r/matches/final", "want": ["restore"] }`) brings back a deleted item where it was placed. The catalog resolves the caller's roles at the item from the `effective` rows it kept when it saw the item's tombstone (§B.11.7), keeps those that count for `restore` (§B.11.2) both there and at its placement now, computed as for a live item, and signs a grant fixed to that name with `can: ["restore"]`. If the item is live when the grant is used, the write is an append, refused at step 2 (§6.2). The item must still have a placement in this catalog; the frozen rows stay those of its deletion even if it was unplaced and placed again. The answers, in order: in a purged namespace every name is `410`, for restores and creates alike (§8.5, §E.4); a name that never existed is `404`; a caller without a role that counts for `read` on the item both at its placement now, computed as for a live item, and, if it is deleted, in its frozen rows, gets `403`; then a purged item is `410` (§8.3), and a live item `409`; then `403` for a caller without a role kept, one whose item has no placement, or one whose restore would widen (above).

-
**Accountability.** Revisions record the grant, with its `at`, and `via` (§C.3, §7.1).

### B.11.5 Reads and listings

- **Listing URLs carry the subject set.** A listing whose combined checkpoint (§B.5) has only public namespaces is served at `/{catalog}/at/{at}/…`, unfiltered, while they stay public. Any other is served at `/{catalog}/g/{gs}/at/{at}/…`, where `gs` is `all` (below) or `text(trunc160(sha256(canonical(subjects))))`, `subjects` an array in byte order of UTF-8, without duplicates. The subjects are the caller's `group:` entries, plus its `sub` only if the catalog has direct entries for that user, or its key in a content namespace it trusts has a `sub` scope (§B.11.2). A listing URL without `at` is under the prefix too (`/{catalog}/g/{gs}/children?…`), with the `gs` the exchange's `prefixes` gives; one without `/g/{gs}` is redirected to its `…/g/{gs}/at/{at}/…` URL by the grant in `Authorization`, `private, no-store`. A grant in `Authorization` reads only at its own `gs`, or at `all` where it qualifies (below), and is `403` elsewhere; a request that needs `/g/{gs}` and carries neither a grant nor a cookie the service verifies is `401`. A tree service without §B.11 serves only `all` (`403` otherwise). The edge admits a request only if the caller's edge grant is bound to that exact `gs`: a cookie the service mints with a key of its own (§C.5) for the prefix `/{catalog}/g/{gs}`, after resolving the caller's subjects, at an exchange endpoint of its own that follows §C.5's issuance rules, `application/json`, `415` and credentialed CORS included. Services apply §9 to their own origin.

  - A service keeps which subjects each `gs` stands for (§C.5.3). A `gs` cookie other than `all` authorises listings of that subject set only: `problems`, `orphans` and manifests stay `403` under it.

  - A service applies `exchangeRate` (§6.6) to its own exchanges, its buckets shared across its instances as the origin's are. Listings are cached per (listing, subject set, `at`).

- **Listings are filtered by their subject set.** A node is **visible** to a subject set when the walk up from it (§B.11.2) collects a role that counts for `read` (§B.11.2), with the caller's `sub` that of the set's `user:` subject (a set without one fails a `sub` scope), and whose own rules and the key's scope `rules` pass as a read would evaluate them (§6.4.1, §6.4.2), with `/principal` holding only the groups the key may assert and, as `roles`, that role. For an item, that is a role of its own content namespace, with `/resource` its name. For a folder, it is a role of some trusted content namespace whose rules don't refer to `/resource`, through a key whose scope `rules` refer only to `/principal/groups` and `/principal/roles`. A rule that refers to `/now`, or to anything in `/principal` but `groups` and `roles`, makes the role not count. The roles, their definitions and the keys are those as of the content namespaces' `ns_id`s in the listing's combined checkpoint (§B.5).

  - `children`, `subtree`, `roots`, `ancestors` and `where` show visible nodes only, and only paths through visible folders. A visible node whose parents are all hidden is a root for that subject set: `roots` lists it, and paths end at it. Nothing about a hidden node appears, not even as a count: a request that names one, here, as a catalog node in `/read-grants` (below) or, from a caller not in `catalog-admins`, in an organising request (§B.11.4), where a dangling placement is judged as if its item were live, is answered as one naming a node not in this catalog (`404`), except a new folder's name and a Place of an item whose placement is live, which are `409` (§B.11.4).

  - Response limits, cut markers and pagination (§B.5) apply to the visible nodes.

  - `/read-grants` uses the same test for catalog nodes and their keys.

  - `problems`, `orphans` and `manifest` aren't filtered, and need unrestricted `read` (§2.1) on the catalog and on the content namespaces they cover (`403` otherwise): for a manifest, those of the items it pins; for `problems` and `orphans`, every one in the combined checkpoint. A public namespace counts as read unrestricted. Unfiltered listings (`g/all`) are for readers whose grants would be issued a namespace-wide edge grant (`/r/{ns}` and `/ns/{ns}`, §C.5.2): the catalog service issues an edge grant bound to `all` only after checking that for every namespace in its combined checkpoint (§B.5) that isn't public, and it expires with the earliest of those grants. Such a cookie covers every later `at`, so the service answers `403` at an `at` that includes a namespace that wasn't in its combined checkpoint at issuance, such as one trusted since, until the reader exchanges again. A service that mints with the default format takes the issue time as `exp` less the 15-minute cookie maximum (§C.5.2), unless it recorded the issue; one that needs it exactly uses a format of its own with an issue time (§C.5.3). A namespace that turns private stays readable under a live `g/all` cookie until the cookie expires, the revocation latency. Without edge grants, `g/all` listings are served `private`, with a `max-age` no longer than that.

- **Listings never embed signed URLs.** Readers obtain per-item edge grants from `POST /read-grants { items: [...] }` (`no-store`). It returns short-lived grants, carrying the roles that make each item visible (above), fixed to exactly `/r/{ns}/{name}` and `/r/{ns}/{name}/…`, which the client exchanges at the origin's `POST /edge-grants` for cookies (§C.5.2), or edge grants in a signed-URL form the deployment's edge verifies.

  - **Every item at once.** "May this reader read all of these?" is one call: it may if every item comes back with a grant, or as `"public": true`, which an item in a public namespace that isn't sealed does instead of a grant, or, for a catalog node or an item in a public sealed namespace, with its key alone; a sealed item in a private namespace comes with both. An item is refused as `POST /grants` refuses an item request (§B.11.4), only the roles that make it visible (above) counting, so a hidden item is answered as one without a placement (`403`), as Restore's read check answers it. A catalog node is `400` in a catalog that is neither sealed nor end-to-end, and otherwise `404` if hidden (above). An item answered with a `4xx` status is refused, and one with a `5xx` status is undecided and asked again. A service may cap the items of one request (e.g. 100, `400` above). Revisions needn't be named, though for sealed items the keys returned cover only some epochs (below).

  - **Keys.** For sealed items, and nodes of sealed or end-to-end catalogs, it also returns per-resource keys `K_r` (§E.2.1), wrapped to the caller's public key in the §E.2.3 format. The catalog service derives them from the epoch keys it holds as a consumer.

  - **Which keys.** A content item in a sealed (E2) namespace gets its own `K_r`. An item in an E3 namespace gets none. When the catalog is sealed or E3, the item's placement node also gets its `K_r`. `items` may also name catalog nodes (`/r/{catalog}/{name}`): a node visible to the caller (above) gets its `K_r` and no grant.

  - **Checked like grants.** Keys are returned only for items that pass the same role check as the grants, items in **public** sealed namespaces included.

  - **Which epochs.** Keys cover the current epoch and the `encryption.historyEpochs` before it, or every epoch the service holds if the namespace sets no cap. As with `/keys`, losing a role takes effect at the next rotation (§E.2.4).

  - A caller whose grant carries no public key still gets its grants, with `"keysWithheld"` and the reason in place of keys.

- **Readers of a whole content namespace** use a namespace-wide edge grant instead (§C.5).

### B.11.6 Groups

- **Default:** group claims come in the base grant from the identity provider.

- **Alternative:** a `groups` namespace of documents (`{ "members": [...] }`) that the catalog service follows.

- **Either way,** key scopes limit which groups and roles the catalog may assert.

### B.11.7 Catalog storage

For example:

```
CREATE TABLE nodes     (node TEXT PRIMARY KEY, inherit INTEGER NOT NULL DEFAULT 1);
CREATE TABLE acl       (node TEXT, subject TEXT, role TEXT, PRIMARY KEY (node, subject, role));
CREATE TABLE effective (item TEXT, subject TEXT, role TEXT, PRIMARY KEY (item, subject, role));
CREATE INDEX effective_by_subject ON effective (subject, item);
```

- **Maintenance.** A change to a node's `$access` or `parents`, a tombstone, or an item's deletion or restore recomputes `effective` for the affected subtree.

- **Role definitions** are applied at the gate, but a change to `/roles` in a content namespace recomputes the listing visibility it affects (§B.11.5).

- **Deleted items** keep their rows in `effective` as they were when the tombstone was seen, marked as tombstoned and no longer recomputed, for restores (§B.11.4). A deleted placement's rows are kept apart the same way, until it is placed again (§B.11.4). Restores and re-placings are checked against these rows for no widening (§B.11.4).

- **Consistency.** The checkpoints are stored in the same transaction, so `effective` reflects a known catalog `ns_id`, which is the `at` of every grant issued from it.

### B.11.8 Staleness and revocation

- **Staleness is bounded by `maxLag` plus the grant's lifetime,** and for keys handed out for sealed items by the next rotation (§E.2.4).

- **Overtaken decisions.** A grant is judged at its decision. A later change by someone else, such as a move of an ancestor of the node or a `catalog-admins` edit, isn't seen by grants already issued: a Move grant can still take its node out of a folder narrowed since. So a Move grant's `exp` is at most the catalog's `maxLag` (§7.4) after its decision.

- **For immediate revocation,** add the grant's revocation id to `revoked` (§C.4) in the namespace where it applies.

## B.12 Open questions

- Should a content namespace be able to *require* that every item is placed in some catalog, e.g. through a catalog-consumer that reports unplaced items?

- Should a copy, or a move onto an existing file, in a tree with tree-derived access (§H.5) be refused where the target's roles would exceed the source's, as a move's are (§B.11.4)?

---

# Addendum C — Capabilities and access (recommended)

How authority is carried and checked, filling the core's hooks: the `principal`, `writes` and `read` envelopes (§6.4.1), the gate order (§6.2) and a grant reference per revision (§5). **Writes can be fine-grained, reads are per document:** writes are checked at the gate against the full envelope, reads are decided when grants are issued (§C.5.1).

Three styles of policy combine:

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

  - `roles`: role names (§C.1.1), which give the grant its effective roles (§2.1).

  - `attrs`: attributes the issuer asserts about the principal (§C.1.2), taken from the **root block only**

  - `ns`: namespaces the grant applies to

  - `can`: `read`, `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export`, `prune`, or `*` for keys only (in a block, the grant is invalid, `401`). `export` registers a remote branch (§G.3). A root block without it MUST list `roles` (`401`), and its verbs then come only from the roles.

  - `nbf`, `exp`: **absolute** RFC 3339 times. The block is valid from `nbf` (optional) until `exp`.

  - `at`: the namespace revision the issuer decided at: an `ns_id` of the namespace itself, or `{ "ns", "id" }` for another namespace the issuer follows, such as a catalog (optional unless the key has `requireAt`)

  - `rules`: rule forms of §6.4.2

  - `via`: in narrowing blocks only, the delegatee

  - `signers`: in the root block only, the principal's signing keys (§C.3.1)

  - `enc`: in the root block only, the principal's X25519 public key that keys are wrapped to (§E.2.3); one of another form makes the grant invalid (`401`)

-
**Narrowing only restricts.** A narrowing block may:

  - reduce `ns`, `can` and `roles`

  - set a later `nbf` or an earlier `exp`

  - add `rules`

  - add a `via`

It carries no other member, and one it leaves out restricts nothing. A root block MUST carry `kid`, `sub`, `ns` and `exp`, and only members listed above for it. A block that breaks this makes the grant invalid (`401`); values that don't narrow, other than `"*"` (`can` above, §C.4), restrict nothing more, since `ns`, `can` and `roles` are intersected and every block's times are checked (§C.2). The effective principal is always the root `sub`, `groups` and `attrs`, with `via` listing the delegatees in order.

-
**Format.** Grants are Biscuit v3 tokens (§C.8).

-
**Verification** needs only published keys: the namespace's, its local bases' and the deployment's operator keys (§C.4), so consumers verify grants too.

### C.1.1 Roles

```
"roles": {
  "reader":     { "can": ["read"] },
  "editor":     { "can": ["read", "create", "append", "restore", "delete"] },
  "translator": { "can": ["read", "append"], "rules": [ { "op": "writes", "within": ["/i18n"] } ] } }
```

-
Grants carry role **names**, never their contents.

-
**Expanded at the gate,** against the configuration in force when the request is checked (invariant 6). Changing a role's definition changes at once what every outstanding grant naming it can do. Unknown names grant nothing, so removing a role revokes it. `roles: []` grants no verb (§C.2); a grant without role checks leaves `roles` out.

-
**Combination.** Roles are alternatives, everything else is conjunctive (§C.2 items 2 and 4).

-
**Issuers are bounded** by the key scope `roles` (§C.4), just as with `groups`.

-
**Other fields** in a role entry are for consumers (§7.4).

### C.1.2 Attributes and time

Attribute-based policy is the rule language (§6.4.2) applied to four kinds of attribute:

| Attribute of | Where rules find it | Set by |
|---|---|---|
| the principal | `/principal/attrs/…`, `/principal/groups`, `/principal/roles` | the grant's issuer, e.g. from identity-provider claims |
| the document | `/doc/…` | the writers, under the schema and rules |
| the request | `/action`, `/resource`, `/writes` | the server |
| the environment | `/now` | the server's clock |

- **Principal attributes.** `attrs` in the root block carries issuer-asserted facts such as department, region or clearance, bounded by the key scope `attrs` (§C.4), e.g. to `clearance ≤ 2`.

- **Relations** between attributes use `compare` (§6.4.2); §6.4.4 has a worked rule.

- **Time windows.** `nbf` and `exp` bound when a grant is valid (embargoes, scheduled access); rules on `/now` bound what may be done when (deadlines like `lockAt`).

## C.2 Checking requests

**Invariant.** A request is allowed only through what every block, the key's scope and, if the grant carries roles, at least one effective role allow together, and a grant its key's scope doesn't allow allows nothing. No role, verb or namespace a narrowing block drops counts, and "unrestricted read", "qualifying role" and "fixes `/resource`" (§2.1) are judged so that no grant reads more than its rules permit. Members that widen exposure or touch keys change only under a `*` key, or the operator grant that creates the namespace.

Grants are checked at step 1 of §6.2 (items 1–3 and the first part of item 4), at step 2 (item 2's retry check and settling), at step 6 (the `*`-key guard, then item 4), and on every read (item 5):

-
**Verify the chain:**

  - first, without verifying anything, the `ns` check of §7 (`403`), before the `401` cases below; a token whose blocks can't be parsed at all is `401`. Reads of a public namespace ignore the grant, except as §7 says.

  - the root signature by a key in the configuration in force

  - every block's signature

  - `nbf` ≤ now < `exp` for every block

  - revocation (§C.4)

  - the key's scope, including `can`, `sub`, `maxTtl`, `groups`, `roles`, `attrs`, `requireAt`/`maxLag` and `readScope`. A grant that can allow `read` (item 2), from a key with `readScope: "resource"`, that doesn't fix `/resource` (§2.1) fails the scope: `403` on every request that doesn't ignore the grant, writes included (and `404` for a read of a resource in a private namespace, §7)

Failures are `401` when there is no usable grant: missing, malformed, badly signed, revoked, expired, or not yet valid (`nbf`). They are `403` when a valid grant doesn't allow the request.

-
**Check the verbs.** A verb is allowed when `ns` and `can` (the intersection over all blocks), and the key's `can` for a namespace key, allow it, and, if the grant carries roles, an effective role (§2.1) lists it. A request checks the verb of its action (§6.4.1), with these exceptions and additions:

  - **Several verbs.** A resource `PATCH` under `If-Match`, and a batch item whose first step is a patch set under `ifMatch`, check `append` and `restore`; either without a usable precondition, and a blob upload (§7.8), check `create`, `append` and `restore`. The write's **candidate verbs** are those for which this item and item 4's step-1 rules pass, with `/action` set to the verb and only roles that list it counting; it passes if it has one. A `PATCH` or item without a usable precondition then gets `428` at step 2.5 of §6.2.

  - **Settling.** Step 2.2 of §6.2 settles the verb of a `PATCH` under `If-Match`, or of such a batch item, and refuses one that isn't a candidate. An idempotent retry of one (§7.2, §7.5) answers `200` only if the recorded entry's verb, a restore when its parent is a tombstone and an append otherwise, is a candidate; any other retry has its one verb.

  - **Later steps** of a batch item have the verb the request gives them, checked like `"delete"`: a patch set whose previous step is a `"delete"` is a restore, any other an append.

  - **Unrestricted `read`.** Branching (§7.6) and remote registration (§G.3) also check `read` on the namespace they name as base, which the grant must read unrestricted (§2.1), public or not. Its key-scope and block rules that refer only to `/action`, `/principal` or `/now` must pass with `/action` set to `read`, the rest being left to step 6, against the write's own envelope; and a role that counts for `read` must pass all its rules against a `read` envelope, as in item 5.

  - **Operator grants** (§C.4) check `config` for a namespace's creation, a remote branch's with the schema histories it mirrors included, and `purge` or `purge-ns` for a forced purge (§6.1).

-
**Build the principal:** `{ id: root sub, groups: root groups, roles: effective roles, attrs: root attrs, via: [...], grant: grant id }`.

-
**Rules** of the key scope, the blocks and the roles. At step 1, those that refer only to `/action`, `/resource`, `/principal` or `/now`, with `/action` set to the verb checked. At step 6, all of them, with the write's verb, as settled where it had candidates, then the namespace rules (§6.2). Roles are alternatives: if the grant carries roles, the role rules evaluated must pass for at least one effective role that lists the verb. A failing grant, key or role rule is `403`.

-
**Reads** evaluate the key-scope, block and role rules against a `read` envelope (§6.4.1), roles as in item 4.

**`*` keys.** A config write (§7.4, §7.5) covering or overlapping one of the members §7.4 lists, or setting `read` to `public`, needs a grant chained to a key with `can: ["*"]`, or, for a namespace's creation, the operator grant that creates it (§C.4). So do a branch's `patches` that cover or overlap one of those members, with a `*` key of the base (§7.6), and the prunes §8.6 names. This guard runs first at step 6, after any namespace-document validation (§7.4): `403` (`forbidden`) otherwise. Forcing a purge has its own guard, at step 1 (§6.1).

## C.3 Attribution and signatures

- **Grant per revision.** Each revision stores its grant's id, `trunc160(sha256(canonical(root block)))`.

- **Stored grant form.** The server stores each grant in a **non-bearer** form that no longer verifies as a credential (§C.8).

- **Optional author signatures.** A client MAY sign `sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖ 0x0A ‖ bytes(parent) ‖ 0x0A ‖ canonical(patches))` with its own key and send `Signature: <alg>:<kid>:<sig>`. `origin` is the deployment's canonical origin in RFC 6454 ASCII serialisation (`scheme://host[:port]`, lowercase, default port omitted), as published at `GET /` (§7).

  - The input is the **full** digest, bound to the deployment, namespace and resource, so a signature can't be replayed into another resource with identical history.

  - Signatures are stored **alongside** revisions, never inside ids, and served in logs. Verifying and requiring them: §C.3.1.

### C.3.1 Signer keys and verification

A signature is checked along one chain against the keys in force when the revision was written, not today's, every link immutable or in a hash-chained log except the operator key history (§C.4) and `created` times (§5):

- the revision's `Signature`, `<alg>:<kid>:<sig>`;

- an entry with that `kid` in the `signers` of the root block of the grant it was written under, named by its grant reference (§C.3);

- the key that signed that root block: a key of the configuration the write was checked against (in a branch, its own keys and those its local bases had at the entry's `created`, §C.4), which is the namespace document in force at its namespace log entry, after the config change of a batch that makes one (§6.2, §7.5); or a deployment operator key in force at its `created` time (§C.4);

- the namespace log for a namespace key, or the deployment's operator key history (§C.4) for an operator key.

- **Signer keys live in grants.** A root block may list `signers: [{ "kid", "alg", "pub" }]`, with `alg: "Ed25519"` and `pub` the public key in base64url.

  - `kid`s are unique within `signers` and contain no `:`. `pub` and the `<sig>` of a signature are base64url without padding (43 and 86 characters). An entry that breaks these rules, or has any other member or `alg`, makes the grant invalid (`401`).

  - Issuers MUST list a key only after the principal has proved possession of it, and MUST NOT list one `pub` for two subjects, since the signing input names no principal.

  - Narrowing blocks MUST NOT carry `signers` (`401`), so a delegated write is signed with the root principal's key or not at all.

  - A namespace document can't list signers, so bots too get grants with `signers`.

- **Tombstones** are signed over the same input with the ASCII bytes `tombstone` in place of `canonical(patches)`, as their ids are (§3.4).

- **At the gate.** When a write carries a signature whose `kid` its grant's `signers` list, the server MUST verify it at §6.2 step 2.3; a bad one is `422` with `code: "signature"`, and so is one whose `alg` isn't that signer's. A signature with any other `kid` is stored unverified, and readers treat it as unattributed.

  - **The parent** in the input is the one the write's precondition names: its `If-Match` id, empty for a create, and in a batch the item's `ifMatch` (empty with `ifNoneMatch`) for its first step and the previous step's id for each later one. A write without a usable precondition isn't checked here, and gets `428` at step 2.5.

  - A `Signature` header or step member that isn't `<alg>:<kid>:<sig>` with an 86-character base64url `<sig>` is `400` (`bad_input`), as a request-shape error.

  - **Retries.** An idempotent retry (§7.2) answers the entry as first recorded, whatever well-formed signature it carries or lacks, even after `required` was turned on.

  - At E3 the input covers the sealed patch set as sent (§E.3.1), so the server verifies without content keys.

  - In a batch, each step object (§7.5) carries its own `signature`. The `Signature` header covers a single `PATCH` or `DELETE` of a resource, and is `400` (`bad_input`) on any other write.

- **Requiring signatures.** A namespace document may set `"signatures": "required"`; the default is `"optional"`. Every revision and tombstone written to such a namespace then needs a valid signature by a signer of its grant (`422 signature` otherwise, at the same point of the gate). A batch's items are judged under the configuration its config change produces (§7.5); if that change fails, only a replay can still succeed, answered as first recorded.

  - Namespace documents aren't signed. Revisions written before it was turned on, and those a branch reads through from its base, aren't covered, so a reader relying on it checks the log position, not only the current document.

  - Merges, replays and imports (§F.3, §G.4.4) write new revisions in the target, so a step's `signature` is always the writer's own. Original signatures aren't re-sent, and stay verifiable through the batch's `source`: a bundle's for an import, a branch's until it is purged (§F.6).

  - Services that write to such a namespace need root grants of their own (above, §C.6). While authentication is disabled (§1), every resource write to such a namespace fails.

- **Reading grants.** `GET /ns/{ns}/grants/{gid}` answers `{ "id", "root", "stored" }`. `stored` is the non-bearer form (§C.8) of the first token recorded with that id: its authority block, a protobuf `SignedBlock` in base64url without padding. A verifier checks its signature under the key `root.kid` names, that its one `grant_block` string equals `canonical(root)` byte for byte, and that `id` is `text(trunc160(sha256(that string)))`.

  - It serves the grants recorded by namespace log entries of this namespace and, in a local branch, of its bases up to their `at`, recursively; any other is `404`. A revision a remote branch reads through is verified at its base (§G.3). In a purged namespace it is `410` (§8.5).

  - It needs unrestricted `read` on the namespace, which in a public namespace everyone has, so issuers keep the `groups` and `attrs` of grants for public namespaces to what may be public. It is immutable.

  - Sealed namespaces seal it as §E.2.2 says. A grant recorded only by a branch's base is sealed under the branch's current epoch, like content it reads through. End-to-end namespaces serve it in the clear (§E.4), or sealed if it is from before a raise from `sealed` (Addendum E, Levels), with `Cache-Control: private` instead of the immutable class (§9), and `no-store` for shared caches (`CDN-Cache-Control`, `Surrogate-Control`).

- **Verifiers** follow the chain with the namespace document's history, and in a branch its local bases' too (from their logs, or the key entries a bundle carries) and the operator key history. Verifiers don't check `revoked` (§C.4): a later revocation doesn't unsign history. A signature that fails, or whose chain can't be completed, is reported as such; it says nothing about the content, which ids verify (invariant 4).

## C.4 Keys, scopes and revocation

-
**Keys.** The namespace document lists `keys`, each entry with `kid`, unique within `keys`, `alg: "Ed25519"`, `pub` the public key in base64url without padding (43 characters), and `can`, and optionally the scope fields below, `maxTtl` and `maxLag` as ISO 8601 durations; one stored without `can` allows no verb. Root blocks must be signed by one of them. Changing keys and scopes is a config write requiring a `*` key (§7.4).

-
**Key scope.** A key entry may restrict every grant it signs:

| Field | Restriction |
|---|---|
| `can` | verbs its grants may contain, every verb for `*`. A root block whose `can` lists any other fails the scope, and verbs from roles are bounded by it (§C.2 item 2) |
| `maxTtl` | longest remaining lifetime of the root block, `exp − max(now, nbf)` |
| `sub` | a regular expression (§6.6) that the whole root `sub` must match |
| `groups` | `{ "allow": [...] }` or `{ "deny": [...] }` on asserted groups |
| `roles` | `{ "allow": [...] }` or `{ "deny": [...] }` on asserted roles |
| `attrs` | a JSON Schema the asserted `attrs` must validate against, held to the rules of a rule's `schema` (§6.4.2) |
| `rules` | conditions added to every grant |
| `readScope: "resource"` | every grant it signs that can allow `read` must fix `/resource` (§2.1) |
| `rate` | a lower per-principal write rate for grants it signs, `{ "rate", "burst" }` as in `limits` (§6.6): their `ratePerPrincipal` bucket takes the smaller rate and the smaller burst of the two, and its `429` names `ratePerPrincipal` |
| `maxLag` | a stricter `maxLag` for `at` (see `requireAt`) |
| `requireAt` | `true`: `at` must be an `ns_id` in the chain of the namespace the grant is checked in, also for a base's key in a branch. A namespace name: `at` must be in that namespace's chain. Either way `at` must not have been superseded in that namespace's chain more than `maxLag` before the grant was issued, taken as the later of the root block's `nbf` and `exp − maxTtl`, of those that exist; with neither `nbf` nor a `maxTtl` the grant fails the scope. A `requireAt` key SHOULD set `maxTtl`. The namespace document of the namespace `at` belongs to sets `maxLag` (default 60 seconds), a key may set a stricter one of its own, and the smaller applies |

-
**Revocation.**

  - Grants should be short-lived and refreshed by their issuer.

  - For immediate revocation, add a **revocation id** to `revoked: [...]` in the namespace document. A root block's revocation id is its grant id in text (§C.3), and a narrowing block's is `text(trunc160(sha256(its signature)))`. A chain containing any revoked block is rejected. Revoking a root block therefore revokes everything narrowed from it, however it was re-serialised or re-minted.

  - Revocation is per namespace. Issuers revoke in every namespace a grant lists.

  - **In a branch**, a chain is also rejected if any of its blocks is revoked in any of the branch's local bases.

-
**Keys follow the base.** A branch accepts its base's **current** keys as well as its own: a key added to the base after the branch was created works in the branch too, and one removed or replaced in the base stops working in every branch. A key the branch shares with its base (same `kid`) is the base's, accepted only while the base has it with the same `pub`; if the base later adds a `kid` the branch already has, only the base's entry is accepted, and if the base removes it again the branch's own entry applies once more. That holds only for a `kid` the branch added itself (§7.6); one copied from the base at creation never falls back. In nested branches this applies recursively, through every local base. Keys added only to a branch were added with a base `*` key (§7.6), and are the branch's own. A branch can't refuse a base key.

-
**Bootstrapping.** Creating a namespace needs a deployment-level operator key configured outside the system. A grant for a namespace that doesn't exist yet names it in `ns`, or uses `"*"`, which only grants signed by an operator key may do (`401` otherwise). Branches are the exception: they are created with a `branch` grant on their base (§7.6).

-
**Operator grants**, with the verb each action needs (§C.2), authorise exactly: creating a namespace with its genesis document; creating a remote branch, including the schema histories it mirrors and their `nonce` settings (§G.3, §C.7); and forcing a purge or namespace purge (§6.1). Any other request under one is `401`, as for a key the namespace doesn't list, except requests that need no grant, such as public reads, `GET /` and `DELETE /edge-grants`, which ignore it (§7, §C.5.4), and `GET /ns/{ns}/principal`, which describes it (§7.4). A grant whose root `kid` names both an operator key and a key of the namespace document is verified against the namespace's key first, and is a namespace grant when that key verifies it. Under one, a forced purge and `GET /ns/{ns}/principal` answer `404` for a namespace that doesn't exist. The `ns` check (§7) still answers `403` first, and a purged namespace `410`.

-
**Operator key history.** A deployment publishes its operator keys as a JWK Set (RFC 7517) at the `jwks_uri` it gives at `GET /` (§7), by default `/.well-known/patchlog-keys`; verifiers take the URI from `GET /` rather than guess. Only a `200` whose body is a JWK Set with a `keys` array is a read of the history; anything else (a `404`, `{}`, an error page) is a failed read, never an empty history.

  - Each key is an OKP Ed25519 JWK with `kid` and `use: "sig"`, plus `"patchlog": { "from", "until"? }`, the RFC 3339 period it was in force. The set is served as `application/jwk-set+json`, publicly cached for minutes, e.g. `public, max-age=300`.

  - `from` MUST be no later than the first entry written under a grant the key signed, so a deployment publishing a key it already used gives the time the key was configured, or else the time of the deployment's first entry. A key authorises only within its period: grants it signed are refused (`401`) before its `from` and after its `until`, and verify only for revisions created within it. An operator grant is revoked everywhere only by ending its key's period with `until`, so operator grants are kept short.

  - It is a history, not a current set: keys are never removed, and `kid`s never reused.

  - It lists no namespace keys; those are in namespace documents.

  - Trust in it rests on TLS and the origin. A verifier that wants more pins operator keys obtained out of band.

## C.5 Reading

- **Read modes.** A namespace document declares `"read": "public" | "grant"`, by default `"grant"`. Independently, it may be **sealed** (Addendum E): content may then be served publicly, and only key holders decrypt it.

  - **Public:** cached publicly (§9).

  - **Grant:** served with the grant in `Authorization` (§9), or through CDN edge grants, signed cookies (or signed URLs, where a deployment's edge verifies them) that the origin issues in exchange for a verified grant with `read` (§C.5.2–§C.5.4). The edge grant is not part of the cache key. Downstream caching is `private` (§9).

- **Per document, not per field.** Never filter fields per reader; keep sensitive fields in a separate resource in a private namespace, and link to it.

- **Ids are not secrets.** Ids leak through logs, referrers and parent links: defence in depth, never access control.

- **The stream is metadata.** Reads of `/ns/{ns}` and everything under it, its events stream and long-poll included, require **unrestricted** `read` (§2.1), while a resource's own URLs, its events included, need `read` on that resource.

  - **Three exceptions,** all answered by the origin with the grant in `Authorization`, `no-store`: the gestures listing, filtered per resource (§7.4); `GET /ns/{ns}/principal` (§7.4); and `POST /ns/{ns}/keys` (§E.2.3). Otherwise a reader limited to some documents follows them through a filtering proxy (§C.6) or the catalog.

### C.5.1 Reads are decided at issuance

-
**Why.** A read envelope has no document, and the edge serves cached bytes unseen, so a read decision cannot depend on content at request time.

-
**Reads** that depend on content are decided by an **issuer** that follows the namespace, evaluates the policy per document, and issues grants fixed to the resources that pass, with `nbf`/`exp` for time windows. "Readers see matches in their own regions" becomes:

```
{ "kid": "access-01", "sub": "user:li", "attrs": { "regions": ["se"] },
  "ns": ["matches"], "can": ["read"], "at": "1k…",
  "nbf": "2026-10-04T18:00:00Z", "exp": "2026-10-04T18:15:00Z",      // embargo lifts at 18:00
  "rules": [ { "op": "test", "path": "/resource", "value": "derby" } ] }
```

  The catalog (§B.11) is one such issuer.

- **Evaluated directly on reads:** rules over `/principal`, `/resource`, `/action` and `/now`, such as office hours.

- **Consequence.** A content-based read decision lags the content by up to `maxLag` plus the grant's lifetime (§B.11.8). Where that is too slow, move the sensitive part into its own resource, or seal it (Addendum E) and revoke by rotating keys.

### C.5.2 Issuing edge grants

-
**Scope.** An edge grant is scoped to the **smallest edge prefix** (§2.1) the grant allows:

  - `/r/{ns}/{name}`, one per name, when its rules fix `/resource` (§2.1)

  - otherwise `/r/{ns}` and `/ns/{ns}`

-
**Request.** `POST /edge-grants` on the origin, with the grant in `Authorization`, or several grants as `{ "grants": [ … ] }` in the body, with `Content-Type: application/json`, so a form on another site can't send it without a preflight. It issues, for each grant, for every namespace that all its blocks carrying `ns` name.

-
**Answer.** `200` with `{ "prefixes": [ … ], "exp" }` and one `Set-Cookie` per prefix, with no `Domain` attribute (host-only): `Path` set to the prefix, `Secure`, `HttpOnly`, `SameSite=None` when the deployment names credentialed origins and `Lax` otherwise, and named per prefix (§C.5.3). They last until the earliest `exp` among the grant's blocks or 15 minutes, whichever is sooner; a prefix several grants give gets one cookie, lasting as long as the longest, and the body's `exp` is the earliest, as an RFC 3339 time.

-
**Refusals:**

| Condition | Answer |
|---|---|
| Authentication is disabled (§1) | `404`, `code: "not_offered"`, before the body is read |
| A body that isn't `application/json` | `415` |
| Neither `Authorization` nor a body | `401` |
| A body with no grants or more than 50, or together with `Authorization` | `400` (`bad_input`) |
| A namespace a grant names doesn't exist, or the grant fails verification there | `401` or `403`, as for any request (§7, §C.2) |
| The grant has no `read` there; the rules of its blocks or key scope refer to `/resource` without fixing it (§2.1), or to `/now` | `403` |
| The grant carries roles and none is a qualifying role (§2.1) | `403` |
| The rules of the grant's blocks or key scope don't pass now against a `read` envelope (§6.4.1) for its principal, with `/resource` set to each name it fixes, if any | `403` |
| A namespace a grant names is purged | `410`, `code: "purged"`, if the grant verifies in it (§8.5) |
| More than 100 distinct prefixes | `400` (`bad_input`), once nothing else is refused |
| A body larger than 50 grants of `grantSize` can be | `400` (`bad_input`), before it is parsed; a single grant over `grantSize` is `413` once decoded |
| A principal's `exchangeRate` bucket is empty | `429`, `code: "rate"`, `limit: "exchangeRate"`, once nothing else is refused |

**All or nothing.** The answer covers every grant and namespace sent, never skipping a refused one: `401` if any refusal is `401`, else `403` if any is `403`, and `410` only when every namespace refused is purged and the grant verifies in each, with `ns` and `head` naming the first refused one in the order the grants and their root blocks list them.

-
**Rate.** Once nothing is refused, the prefix cap's `400` included, the request draws one token, however many grants it carries, from the `exchangeRate` bucket (§6.6) of each distinct principal among them, keyed as write buckets are, and from no write bucket.

-
**Browsers.** A page on another origin calls it with credentials. Credentialed responses name that origin from the deployment's list, with `Access-Control-Allow-Credentials: true` and `Vary: Origin`, never `*` and never an echoed `Origin` (§7, browsers).

-
**What a cookie authorises:** only `GET` and `HEAD` under its prefix. Cookies the origin mints never cover a service's URLs, and a service's never cover core ones.

-
**Many documents.** Browsers keep about 150–180 cookies per host, evicting the oldest, so a reader of many documents is better served by a namespace-wide grant, if it may read the whole namespace, or by a proxy (§C.6).

### C.5.3 Edge-grant format and checks

- **Format.** The cookie's format is the deployment's. This one is the default:

  - the name is `__Secure-pl-eg-` followed by the first 8 bytes of `sha256(prefix)` in lowercase hex;

  - the value is `base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))`, without padding, where `c` is the canonical JSON (§3.1) of `{ "kid", "p": prefix, "exp": <seconds since the epoch> }`, those three members exactly. A value whose `c` has other members, or isn't canonical byte for byte, is ignored; a minter that needs more uses a format of its own;

  - `kid` names the key, which the minter and the edges hold.

- **Keys.** Each key vouches only for its own prefixes: the origin's for the core edge prefixes (§2.1); a service's for prefixes under a root of its own, which never overlaps `/r/` or `/ns/`. Origins and edges SHOULD accept several keys at once and mint with the newest: a key is rotated by adding the next one, to edges before the minter, and dropping the old one once its cookies have expired.

- **Service-minted grants.** A service behind the same edge can mint edge grants for output derived from documents, with a key the origin never holds. It mints one only after checking that the reader may read every document the output derives from, lets it expire no later than the earliest of those reads, and withdraws its own cookies, since `DELETE /edge-grants` takes only core prefixes.

- **What an edge MUST check** on every request, cache hits included, before serving it or forwarding it as verified:

  - the method is `GET` or `HEAD`, and there is no `Authorization`;

  - the path has no empty, `.` or `..` segment and no percent-escape, `/` itself excepted, since the cache keys the raw URL;

  - a cookie whose name is derived from its own `p`, as above; others are ignored;

  - `c` in the format above, a `kid` it holds that vouches for `p`, and a valid MAC;

  - `exp` is in the future;

  - `p` covers the path segment by segment: the path is `p` or starts with `p/` (§2.1).

- **Forwarding.** A request that passes is forwarded, on a cache miss, with its cookies, from which the origin still authorises it and takes the `exp` that ends an event stream (§7.3), and with the edge's verification headers (§9): by default `X-Edge-Verified` carrying the secret it shares with the origin, and `X-Edge-Prefix` the `p` it checked, each as exactly one header line without a comma, both stripped from incoming requests. One covering cookie is enough. A request that fails any check is forwarded without them, and the origin answers it as it would without an edge. An edge MAY answer a failure of check 2 itself; the origin answers `400` either way (§7).

- **Without the edge.** A cookie the edge didn't verify, because no verifying edge is in front or the request went around it, is verified by the origin, which answers with `CDN-Cache-Control: no-store` (§9). A cookie counts only on a request without `Authorization`.

- **Attribution.** Cookie reads have no principal, so a deployment that logs reads attributes them to the prefix.

- **Revocation** reaches an edge only when a cookie expires: a cookie carries no grant id, and `DELETE /edge-grants` clears only the calling browser. That is why lifetimes are short.

### C.5.4 Withdrawing edge grants

`DELETE /edge-grants?prefix=…`, `prefix` repeatable and taken from the `prefixes` issuance returned, answers `204`, `no-store`, with an expired `Set-Cookie` of the same name and attributes for each prefix named, once even if it is named twice.

- A request without `prefix`, or with one that isn't an edge prefix (§2.1), is `400` (`bad_input`).

- It needs no grant, ignores any it is sent, and answers the same while authentication is disabled (§1).

- Only `DELETE` withdraws, and its preflight is allowed only for the credentialed origins of issuance.

- A client calls it at sign-out, or before another user signs in on the same browser. It removes the browser's copies only: a copied cookie stays valid until it expires.

## C.6 Consumers and plug-in services

-
**Services verify as the origin does.** A service that verifies grants locally applies keys, scopes and revocations exactly as §C.2 does, `readScope` included.

-
**Least privilege.**

  - A service gets `read` for what it follows.

  - A service that writes back gets a narrowing block with `writes within` its own paths, and without `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export` or `prune`.

  - A service that **proposes** changes can write to a branch instead of the base (Addendum F), for a person to review and merge, and needs no write access to the base.

-
**Filtering proxies.** A service serving a namespace's `/ns/{ns}/…` view filtered per document can hide names and content but not timing: the namespace revision, `X-Namespace-Revision` and long-poll wake-ups move on edits the reader can't see. It pages and derives cursors itself, such as for `/heads`, and never passes upstream ones on, since they can name hidden resources. Content whose timing must be hidden goes in its own namespace (§B.10).

-
**Services that re-publish content MUST enforce reader permissions.** Search, tree and catalog results are filtered by the reader's verified grant. Private results are cached per `gs` (§B.11.5, §A.4), not per request, and never with embedded bearer URLs.

## C.7 Private content and guessable hashes

- **Guessing from ids.** A revision id hashes its parent id, which is public and no encryption level hides (§E.4), and its patch set, so anyone can confirm a guess of a low-entropy patch set (`replace /score "2-1"`, an email address) against the next id. A nonce only in genesis doesn't help: the guesser starts from the parent.

- **A nonce in every patch set.** In private namespaces with guessable content, every patch set SHOULD `add` `/$nonce` with 128 fresh random bits, base32 (26 characters). `add` works whether or not the key exists yet. Such a write is left out of `writes` (§6.4.1), and validation doesn't see the key (§6.2).

- **Requiring it.** A namespace MAY set `"nonce": "required"` (default `"optional"`). Then, at gate step 3 (§6.2), the document a resource create, append or restore results in MUST have a top-level `$nonce` of the fresh form that differs from the parent's, or from the last live document's for a restore; otherwise the write is `422` with `code: "nonce"`. The sealed-namespace rule (§E.2.5) is the writer's; a server that enforces it as well answers `422 nonce` at the same point. A failed `test` or patch application is still reported first, as `invalid`.

  -
Deletes, and config, branch and prune writes, are exempt. A restore that would be `[]` sends just a fresh nonce, and so does a step that keeps a document unchanged.

  -
The check applies to every patch set, whatever its origin, so history written where nonces weren't required, such as a branch made before the setting or a full history from another deployment, can't be fast-forwarded or imported in full into such a namespace, only re-authored with a fresh `$nonce` per step or imported as a snapshot. Set it when the namespace is created. Merge tools that build a resolution or squash set (§F.3) add a fresh `$nonce` to it where required.

  -
A branch copies it and can't turn off one its base has, a base can't start requiring it while a dependent doesn't, and setting or changing it needs a `*` key (all §7.4). It is `422` in an end-to-end namespace (Addendum E, Levels).

  -
A remote branch of a base whose current namespace document requires nonces when the branch is created MUST be created requiring them too (`422` otherwise, §G.3). A remote branch isn't a dependent on A, so A may start requiring nonces later, and B's history must then be re-authored to merge. Schema namespaces that B creates to mirror for it start `optional`, and take their source's setting with a config write once their history is in, under the operator grant that creates the remote branch, as part of its creation; they stay `optional` if B can't read the source's namespace document.

  -
The upstream namespace of a snapshot import (§G.4.4) takes its target's setting.

  -
A writer without unrestricted `read` (§2.1) of the namespace document learns the setting from `GET /ns/{ns}/principal` (§7.4); one that doesn't ask adds a fresh `$nonce` to every patch set in a private namespace, as recommended above.

- **Blobs.** A blob id is a hash of its bytes (§3.7), so the same applies. In private namespaces with guessable blobs, uploads SHOULD carry a `Blob-Nonce`; §7.8 requires one in sealed namespaces and where nonces are required.

- **Encryption:** sealed namespaces refresh `$nonce` in every patch set (§E.2.5). At E3 ids are over ciphertext with a random IV, so no nonce is needed.

## C.8 Encoding: Biscuit v3

Grants are Biscuit v3 tokens: a chain of signed blocks that a **holder** can extend offline. Each block is signed with an ephemeral key whose private half travels in the token, so anyone holding a grant can add a narrowing block, and nobody can remove or alter one.

- **One block, one fact.** Each block of §C.1 is one Biscuit block containing exactly one fact, `grant_block(<string>)`, whose string is the block's canonical JSON (§3.1). The string MUST be I-JSON and equal to its own canonical form (`401` otherwise). The authority block carries the root block; each appended block carries one narrowing block, in order.

  - A block with anything else (other facts, rules, checks, scopes), or a third-party block, makes the token invalid (`401`).

  - Biscuit's Datalog is not evaluated. The server verifies the signature chain with a Biscuit library, extracts the JSON blocks, and applies §C.2 to them. Validity times are the blocks' `nbf` and `exp`, not Datalog time checks.

- **Keys.** Every signature in the token is Ed25519, including the ephemeral keys that sign narrowing blocks, verified strictly (RFC 8032, with `S < L`). A token using any other algorithm is `401`. Ed25519 signatures can't be altered without the key, so a narrowing block's revocation id is fixed once it exists. The root key entry says `alg: "Ed25519"`. The key is named by `kid` inside the root block, not by Biscuit's numeric `rootKeyId`; the verifier looks it up in the configuration in force and verifies with it. A wrong `kid` fails verification like any bad signature.

- **Revocation ids** (§C.4) of narrowing blocks are over the block's Biscuit signature.

- **Sealed tokens** are accepted.

- **Stored form** (§C.3). The server stores the authority block with its signature and next key, without the other blocks or the token's `proof`. Its signature can still be checked, but it is no longer a token, so audit data can't be replayed as a credential.

- **Transport.** `Authorization: Bearer <token>`, the token as Biscuit's URL-safe base64, with or without the `biscuit:` prefix. `grantSize` (§6.6), counted in decoded bytes, and `rulesPerGrant` are checked before step 1 of §6.2, and on any other request that doesn't ignore the grant (§7) before its `ns` check, as request-shape errors (`413`, `code: "limit"`).

## C.9 Open questions

- Should revocation lists be shared across unrelated namespaces, e.g. per issuer? A base's already reach its branches (§C.4).

- Should role definitions be shareable across namespaces, e.g. as a resource referenced by immutable revision, like `$schema`?

---

# Addendum E — Encryption (optional)

Encryption is defined by **who is trusted with plaintext**. Each level trades features for confidentiality:

| Level | Who can read plaintext | What keeps working | Main use |
|---|---|---|---|
| **E1 · At rest** | origin | everything | protects disks, backups, database dumps |
| **E2 · Sealed for delivery** | origin + key holders | everything, **plus** public caching of ciphertext | confidential content that must scale through the CDN |
| **E3 · End-to-end** | key holders only | ordering, preconditions, ids, verb-level grants | content the operator must not be able to read |

The levels are per namespace and cumulative in intent; E3 clients seal in E2's JWE format (§E.3.1).

**Levels.** A namespace declares its level in its namespace document, `"encryption": { "level": "at-rest" | "sealed" | "e2e", … }`, ranked as in §2.1.

- **Invariant.** Levels never go down, no namespace is raised above a dependent, and a branch never serves what it reads through at a weaker level than its base serves it (a remote one once it sees the raise, §G.5.2), nor, at `e2e`, from an `at` before the base's `e2e` raise. Content from before a raise to `e2e` is never served at a weaker level or under an epoch from after the raise, and an epoch key reaches only grants whose window covers that epoch. A sealed payload's `pl` and `kid` bind where and in which epoch it was sealed, and readers compare them in full with what they fetched, accepting a base's `ns` for content read through.

- **Changing it.** A write that lowers or removes the level is `422` (`invalid`), and so is one that raises `sealed` to `e2e` without starting a new epoch (§E.2.1), since the origin holds the earlier epochs' keys. A namespace document holding a member its level refuses (§6.1, §7.4, §8.6, §C.7) is `422` (`invalid`) whichever member the write changes, so a raise removes such members in the same write. The origin purges the namespace's cache tag with a raise to `sealed` or `e2e` (§9).

- **Branches and dependents.** A branch is at least at its base's level, and `e2e` only over an `e2e` base: a branch's creation that breaks this, or a config write that raises a branch to `e2e` over a base that isn't, is `422`, as a branch field (§7.4); other config writes don't check it. A write that raises a namespace above a dependent's level is `409` (`in_use`, with `dependents`). So levels are raised in the branches first, leaves first, and only a namespace without dependents becomes `e2e`. Remote branches: §G.5.2.

- **After a raise,** `Last-Modified`, `Repr-Digest`, `/heads` fields, caching, `…/raw` and the gestures listing follow the new level (§7.1, §7.4, §9). Content stored before the raise is served:

  - after a raise to `sealed`, as §E.2.2 says for content from before the namespace was sealed;

  - after a raise to `e2e`, as at the level before: in the clear, or, from `sealed`, sealed as §E.2.2 says, with the last epoch and `pad` setting before the raise in place of the current ones. That content is the revisions, resource log entries, namespace documents and log ranges from before the raise, the grants first recorded before it, and the blobs those revisions reference, sealed ones keeping their epoch URLs under those revisions' epochs only. `/keys` gives the keys of epochs before the raise as at E2 (§E.2.3), leaving out, rather than answering `403`, those a grant wouldn't get there. In a log, the raise lies before the namespace entry (`config` or `batch`) that made the namespace end-to-end, or, in a resource log, before the first entry written with or after it; no log page spans it (§7.1).

- **Branches of a raised base** can't be created, or raised to `e2e`, with an `at` before its `e2e` raise (`422`, as a branch field), since the epoch key in force at an earlier `at` also opens what the base sealed after it. They serve what they read through from before the raise as the base serves it, and readers accept the base's `ns` in its `pl` and `kid`. A branch's `/keys` gives the base's keys for it as at E2, `K_r` derived with the base's `ns`, for the base epochs §E.2.3 selects; a remote branch fetches them from its source with its own grant. They also open a public base's namespace log and documents from before the raise.

- **Later writes** at `e2e`, other than a restore's `[]`, declare only sealed blobs (§E.3.1), so a document keeps an earlier blob otherwise only as a copy the client encrypted. Imports of history from before an `e2e` raise: §G.5.1.

## E.1 At rest

- **What it is.** The origin encrypts stored patches, snapshots and grants with keys from a key management service (KMS), e.g. SQLite page-level encryption or a per-row AEAD.

- **What it doesn't change:** anything else in this spec. It protects storage media and backups, not the CDN or readers.

- **Purge becomes cryptographic.** With a key per resource, purging destroys the key, which also makes backups unreadable.

- **Stored digests.** A server that stores `/heads` `size` and `digest` (§7.4) keeps a plaintext sha-256 of each head's document beside its encrypted content: like ids (§C.7), a dump or backup, even one from before a purge, confirms a guess of a document without a `$nonce`. The fields are optional (§7.4): at rest it leaves them out, computes them at read time, or keeps them under the resource's key.

## E.2 Sealed for delivery

The origin keeps plaintext, so validation, rules, `writes`, idempotent retry, consumers and the catalog work unchanged. Content leaving the origin for a sealed namespace is **encrypted** (§E.2.2), so the CDN and every cache in between hold only ciphertext, and a sealed namespace can be `public` yet readable only by key holders.

### E.2.1 Keys

- **Epoch keys.** The namespace has a sequence of **epoch keys** `K_e` (256-bit random), each identified by `kid = "{ns}#{e}"`.

  - The current epoch is recorded in the namespace document: `encryption.epoch`.

  - Key material is never in the document or the log. The origin holds it, backed by a KMS.

- **Per-resource keys** are derived one way:
```
K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name), 32 bytes
```

A holder of `K_r` can decrypt that resource's revisions of epoch `e` and nothing else. It cannot recover `K_e`.

- **Rotation.** A config write that increments `encryption.epoch` starts a new epoch, recorded in the namespace chain. In a namespace already at `sealed` or `e2e`, a write may change `epoch` only by adding one (`422`, `invalid`). It needs a `*` key (§7.4), so scheduled rotation runs as an operator service.

  - Revisions written from then on are sealed under the new epoch.

  - **Old revisions keep their epoch forever,** as their URLs and cached bytes are immutable.

- **Rotation schedule.** Rotate on a schedule (e.g. daily) and whenever read access is revoked.

### E.2.2 Sealed representation

Sealed payloads are JWEs (RFC 7516) in compact serialization, each served alone as `Content-Type: application/jose`. A resource log range or resource long-poll answer is a JSON array of its entries' JWEs, served as `application/json`, and an SSE event's `data` is one JWE.

-
**Algorithms:** `alg: "dir"` and `enc: "A256GCM"`.

-
**Protected header:** `{ "alg": "dir", "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { … } }`, with `pl` as below. Ids in `pl` are in text form, and an empty one is `""`.

  - The `pl` claims are integrity-protected as AAD, so a ciphertext can't be replayed under another resource, revision or epoch. Readers MUST compare `pl`, and the namespace that `kid` names, with what they fetched, accepting in both a base's `ns` for content a branch reads through (§E.3.1, Levels above).

-
**What gets sealed,** each under the key, epoch and `pl` given here:

| Payload | Key | Epoch | `pl` |
|---|---|---|---|
| `/rev/{id}` document | `K_r` | the revision's | `{ "ns", "name", "id", "kind": "doc" }` |
| resource log entry (patches, author, `via`, grant, signature), in a range or as a `revision` or `tombstone` event | `K_r` | the revision's | `{ "ns", "name", "id", "kind" }`, `kind` the entry's (`rev` or `tombstone`) |
| resource `purge` or `prune` event | `K_r` | current | `{ "ns", "name", "kind" }`, `kind` the event type |
| namespace document at `ns_id` | `K_e` | in force at `ns_id` | `{ "ns", "id": ns_id, "kind": "doc" }` |
| namespace log range or long-poll answer, or a namespace event as a range of its one entry | `K_e` | current | `{ "ns", "range": [since, last] }`: the bounds of the page actually served (§7.1), `[since, id]` for an empty page, `[prev, id]` for an event, whose plaintext is the entry itself (§7.3) |
| grant (§C.3.1) | `K_e` | in force at the first namespace log entry recording it | `{ "ns", "grant": gid }` |
| blob, in a binary form (Sealed blobs, below) | `K_r` | each epoch it is served under | as in Sealed blobs |

The epoch in force at a namespace entry is the `encryption.epoch` of the namespace document in force there. A revision's epoch is the current one when it is first sealed (Epochs, below), and so is that of a namespace document or grant from before the namespace was sealed, or of a grant only a base records (§C.3.1).

-
**What stays in the clear:** everything else, such as URLs (and therefore names and ids), status codes, headers, error and `410` bodies, and `/heads` and `/branches` pages; and sizes and timing, except that the exact `created` of each revision, a document's length and its digest aren't sent outside the sealed logs (§7.1, §7.4). Live timing and padded sizes stay visible.

-
**Stored once, served forever.** Sealed bytes for a revision, a document, a resource log entry or a grant are produced once, stored, and served identically forever, so `304`s and caching work as without sealing. A sealed revision or namespace document has `ETag: "{id}.{e}"`, as a sealed blob does, since it may have been served in plaintext under `"{id}"` before the namespace was sealed. Namespace log ranges (§7.4) are the exception: a deployment MAY keep only some, oldest evicted first, and seal an evicted range again on request, with fresh bytes, under the epoch key and `pad` setting current then. The plaintext is the same except for fields a later version has added (below); readers accept either copy and MUST NOT rely on one. A range's `ETag`, if any, is weak. Fields a later version adds to what is sealed, such as `grant` in log entries (§7.4), are absent from bytes sealed before; readers accept both. So grants recovered for entries written before v0.37 (§7.4) are missing from bytes sealed before, and from a range sealed again only if the server still lacks them; they don't count in the janitor's checks (§F.6).

-
**Compression.** Sealed payloads are never compressed and carry no `zip` header, since a document holds content from several authors (the CRIME/BREACH class of attack).

-
**Padding (optional).** A namespace MAY set `"pad": true` in its `encryption` object. Then every JWE sealed for it, by the server at E2 and by clients at E3 (§E.3.1), pads its plaintext to a size bucket before encryption:

  - **Format.** The plaintext is the UTF-8 JSON that would otherwise be sealed, followed by ASCII spaces (`0x20`) up to the padded length. A blob is padded with zero bytes instead, inside its sealed form (below).

  - **Buckets.** For a plaintext of `L` bytes, the padded length is 256 for `L` ≤ 256, otherwise `padmé(L)`, where `E = ⌊log₂ L⌋`, `S = ⌊log₂ E⌋ + 1`, and `padmé(L)` rounds `L` up to a multiple of `2^(E − S)`.

  - **Scope.** Each JWE is padded as a whole, including every JWE of a log range. Turning `pad` on or off affects only what is sealed afterwards, a log range sealed again after eviction (above) included.

  - **At E3** the server can't check padding. Readers with keys SHOULD flag, like a failed validation (§E.3.2), a patch set not padded to its bucket when `pad` was on at that revision, judged by the namespace document in force at the revision's namespace log entry, and for a batch that changes the configuration, by the configuration it produces (§7.5). Revisions written while `pad` was off are never flagged.

-
**Sealed blobs.** Blobs (§7.8) use a binary form rather than a JWE, `application/vnd.patchlog.sealed-blob`:

```
"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(plaintext) ‖ tag
plaintext = size ‖ bytes ‖ padding
```

  - `len` is the length of `header` as a 4-byte big-endian integer, and `header` is canonical JSON. `iv` is 12 random bytes, and the tag is 16 bytes. The additional data is everything before `iv`.

  - `size` is the length of `bytes` as an 8-byte big-endian integer. `padding` is zero bytes, present only with `pad`, up to the bucket of `size ‖ bytes`. Readers check that it is all zeros.

  - **At E2** the header is `{ "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "blob": bid } }`, and the key is the resource's `K_r` of epoch `e` (§E.2.1).

  - **Epochs.** A reader may hold only some of a blob's epochs. In a sealed namespace, and at E3 for blobs from before a raise from `sealed`, `…/blob/{bid}` answers `302` (head-pointer caching) to `…/blob/{bid}/e/{e}` for the latest served epoch, and a reader that holds only older epochs asks for one of those. The epochs served are those of the revisions here whose documents are still stored and reference the blob. A revision's epoch is fixed by its first stored sealing, the first one stored winning as for blobs: when it is written, or, for one read through from a base or written before the namespace was sealed, when it is first served. A request for a blob none of whose referencing revisions has an epoch yet first fixes the newest of them under the current epoch. So a reader can open a blob under precisely the epochs in which it can read a document that references it. Other epochs are `404`, with `no-store`, since a branch may come to serve a read-through revision under a new epoch. An epoch whose referencing revisions were all pruned answers `410` as in §7.1 where the server recorded it when pruning, and `404` otherwise. A branch's stored sealings of a base's blobs are its own copies: pruning in the base doesn't delete them (§8.6), but the branch stops serving them, answers as above, and MAY delete them. Each epoch's sealing is produced once and stored, the first one stored winning when two instances seal at once, and only the stored bytes are served, unchanged, with `ETag: "{bid}.{e}"` and the sealed type as `Content-Type` (the blob's own type is in its reference). Clients open sealed blobs only in namespaces whose namespace document says they are sealed or end-to-end, or after the epoch redirect, since any namespace may store a file of that type.

  - Range requests are served over the sealed bytes: a download can resume, but a range can't be decrypted alone, so media that must stream in ranges belongs in a namespace that isn't sealed, or in several blobs.

### E.2.3 Getting keys

```
POST /ns/{ns}/keys
Authorization: Bearer
{ "epochs": [3, 4], "resources": ["derby"] }      // resources only for per-resource grants
```

- **What a grant gets** at E2:

  - A grant whose rules fix `/resource` (§2.1, `readScope: "resource"`) gets **per-resource keys** `K_r` for the names in `resources`, by default every name it fixes. A name it doesn't fix, or may not read, is `403`.

  - Any other `read` grant gets epoch keys `K_e` if it reads the namespace unrestricted (§2.1), and is `403` otherwise; `resources` is ignored.

- **Which epochs:** those in `epochs`, by default all, from the epoch in force (§E.2.2) at the last namespace entry created at or before the latest `nbf` among the grant's blocks, a `batch` entry's config change included, or the namespace's first epoch where there is none or it wasn't yet sealed or end-to-end there (the current one if no block has `nbf`), up to the current one, and where `encryption.historyEpochs` is set, no more than the current one and that many before it. Others are left out, so a reader may lack the epoch a grant is sealed under (§E.2.2), and then reports the signatures naming it as unverifiable (§C.3.1).

- **At E3,** `/keys` relays to a `read` grant the entries whose `to` is its `enc`'s thumbprint, without a read of `keyring` itself, so a writer limited to some resources gets what it may hold: those of the `keyring` resource (§E.3.2) for the epochs above, and in a branch those of its bases' keyrings as of `at` (§F.8.1), whether or not it has written its own `keyring` since, for its bases' epochs up to `at`, starting, as above, from the epoch each base had in force at the latest `nbf`, or at `at` if that is earlier, and, where no block has `nbf`, from the epoch that base has in force now, so none once it has moved past its epoch at `at`; `epochs` doesn't select among them. For epochs before an `e2e` raise, see Levels (above).

- **Wrapping.** Keys are wrapped to `enc`, an X25519 public key as a JWK of only `kty: "OKP"`, `crv: "X25519"` and `x`, its 32 bytes in base64url without padding (43 characters), in the grant's root block (§C.1, `401` otherwise), with HPKE (RFC 9180) in base mode (auth mode for `keyring` entries, §E.3.2), the suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, and an empty `aad`. The plaintext is the key's 32 bytes, and the `info` is `"patchlog-key-v1" ‖ 0x0A ‖ kid ‖ 0x0A ‖ name`, with `name` empty for `K_e`. `wrapped` is HPKE's 32-byte encapsulated key followed by the ciphertext. A public key's thumbprint is its JWK's RFC 7638 SHA-256 thumbprint. Both are base64url without padding.

- **Responses** are `{ "epoch", "level", "pad", "keys": [{ "kid", "name"?, "from"?, "wrapped" }] }`, `Cache-Control: no-store`, with `name` for a `K_r` and `from` for a keyring entry (§E.3.2). At E2, a grant without `enc` gets each key in base64url as `key`, in place of `wrapped`. `epoch` is the current epoch; with `level` and `pad`, a writer limited to some resources needs it to seal (§E.3.1) and can't read it in the namespace document (§C.5). In a namespace that is neither sealed nor end-to-end, `/keys` is `404` with `code: "not_offered"`. A request draws a token from `exchangeRate` (§6.6), as `/edge-grants` does.

### E.2.4 Revocation, honestly

- **Future content.** Revoking read access means rotating the epoch of the namespace and of each of its branches, recursively, which the base's `*` keys can do (§7.6). The revoked reader gets no keys for the new epoch, and so can't read anything written afterwards.

- **Past content.** Anything sealed under epochs the reader already held remains readable to them, from their own copies or the CDN's.

- **Reducing past exposure:**

  - shorter epochs

  - per-resource keys via the catalog, so each reader holds only what they were granted

  - purge, which removes content and keys (E.1)

### E.2.5 Interaction with the rest of the spec

- **Caching (§9)** follows the `read` mode. A public sealed namespace is cached publicly, and keys alone decide who reads it; with `read: "grant"`, edge grants also hide **metadata** (names, sizes, timing).

- **Ids (§3).** Ids are still computed over plaintext canonical patches. Sealed namespaces MUST refresh `$nonce` in every patch set (§C.7), so plaintext can't be confirmed by guessing from ids.

- **Consumers and addenda.** Views derived from a sealed namespace are sealed as §E.2.6 says.

- **Schemas** may live in a sealed namespace, but every writer and consumer then needs its keys.

- **Branches (Addendum F).** At E2 a branch has its own epoch keys, and the server seals read-through content under them when it is first served (§E.2.2). For E3, see §F.8.

### E.2.6 Derived views

For services that serve views derived from sealed and end-to-end namespaces, such as search results (Addendum A) and tree and catalog listings (Addendum B):

- **Getting keys.** A service reads like any reader, with its own key pair and a grant with `read`, fetching epoch keys through §E.2.3. At E3, only a service whose public key is a recipient in the namespace's `keyring` can derive anything. Any other skips the namespace, says so in its status, and MUST NOT index or list ciphertext as if it were content.

- **What gets sealed.** Every value a view derives from such a namespace's content is sealed, such as facets, scores, snippets, titles and `$access`-derived details. What §E.2.2 leaves in the clear stays so: names, ids, URLs and heads, and the view's own structure, `at`, `ns`, order and pagination cursors. A cursor never encodes a sealed value such as a sort key; a position in the result serves.

- **Whole-response sealing.** When every sealed value in a response, values of another resource (below) excepted, comes from one namespace that isn't public, every reader its URL admits may read it whole (`g/all`, §B.11.5, or an index `gs` with `reads:{ns}`, §A.4), and every such value derives from revisions served under one epoch, the service MAY serve the whole response as one JWE in the §E.2.2 format, sealed under that epoch's key `K_e`, with `Content-Type: application/jose` and `pl: { "ns", "view" }`.

- **Per-entry sealing.** Otherwise, including a single-source view for a reader whose grant gives only per-resource keys, the response stays JSON. Each entry (a hit, a child, a node) that carries sealed values replaces them with `"sealed": "<JWE compact>"`. The entry is sealed under the per-resource key `K_r` of the entry's own resource (§E.2.1), with `kid` naming the epoch the revision it derives from is served under (§E.2.2) and `pl: { "ns", "name", "view" }`. A reader decrypts the entries it holds keys for and shows the rest by name only. Folders and placements from a sealed or end-to-end catalog namespace are entries of that namespace.

- **Aggregates.** Values that combine several resources, such as facet counts, have no entry of their own and are served only in whole-response form. A service refuses them (`400`) to a reader that would get per-entry sealing.

- **`view`** is the request target, path and query, of the `…/at/{at}/…` URL that the response is served at, exactly as the service's redirect gave it. Readers MUST compare `pl` with the URL they fetched, so a result can't be replayed under another query, subject set (§B.11.5) or `at`.

- **Values of another resource.** A value an entry carries that derives from a resource other than the entry's own, such as a placement's `file` drawn from its item (§H.3), is sealed in place of the value as `{ "sealed": "<JWE compact>" }`, under that resource's `K_r`, with `kid` the epoch the revision it derives from is served under, `pl: { "ns", "name", "view" }` where `ns` and `name` name the other resource and `view` is the response's, and its namespace's padding. It nests inside a whole-response JWE where the rest of the response is sealed whole. While that namespace's keys can't be fetched, the service answers `503` rather than a view without the value, which it would then keep.

- **Stored once, served forever.** A view at a given `at` is sealed once, under the epochs above, and then served unchanged, like revisions (§E.2.2). A stored view is keyed by its URL and the shape of the reader's keys, as kept results are (§A.4). Padding (`pad`) follows the source namespace. Whole-response sealing pads only when every source is padded.

- **Caching** is public only for a view whose sources are all public (§9); other views are private results (§C.6). Tags are those of §A.4 and §B.5.

- **Local storage.** Full-text search, facets and sorting need plaintext, so a service keeps what it derives from a sealed or end-to-end namespace in storage encrypted as the core's is at E1 (§E.1), with keys held outside that storage, such as an encrypted volume or database. Views it has sealed (above) may be stored as they are. A purge of the source, or the destruction of its keys, MUST remove the derived data: rows are deleted and freed pages overwritten, stored sealed views are deleted, and cached keys are forgotten.

- **Queries are metadata.** Query strings are in URLs, so the service, the CDN and anyone who sees the URL learn them, whatever the level (§E.4).

## E.3 End-to-end

The origin never sees plaintext: clients encrypt patch sets before sending them and decrypt what they read, and the server becomes an **ordered, access-controlled log of opaque entries**.

### E.3.1 Wire format

- **Patch sets.** A write's body is `[{ "op": "sealed", "value": "<JWE compact>" }]`: a one-element patch set with a reserved `sealed` op, sealed under the resource's `K_r` (§E.2.1) of the epoch its `kid` names, and whose JWE protected header (§E.2.2) carries `kid` and `pl: { ns, name, parent }`. At step 3 of §6.2 the server checks that the op has no members but `op`, `value` and `blobs`, that `pl` names this namespace, the resource and the parent a signature would bind (§C.3.1), and that `kid` names this namespace's epoch in force (invariant 6) and the header has no `zip` (§E.2.2); otherwise the write is `422` (`invalid`). Readers check `pl` too, accepting a base's `ns` for content read through (§F.8, §G.3). A prune's `snapshot` (§8.6) is one such op, with `pl: { ns, name, id }` naming the revision whose document it is, and `kid` set by the newest revision in that revision's chain that isn't a tombstone and whose patch set isn't `[]`: this namespace's epoch of its `sealed` op where the op is its own, not a base's; the epoch that revision is served under where it is from before a raise from `sealed` (Addendum E, Levels); and otherwise this namespace's epoch in force; the server checks both (`422`, `invalid`).

- **Ids.** The server hashes it like any patch set (§3.3), so ids are **over ciphertext**.

- **Retries.** A client MUST keep the exact ciphertext until the write is acknowledged, so that a retry reproduces the same id (§7.2).

- **Namespace documents stay plaintext,** for the server to read keys, rules and limits.

- **Blobs.** A client encrypts each blob under a fresh random 256-bit key of its own, in the sealed-blob form of §E.2.2 with the header `{ "enc": "A256GCM" }`, and uploads the result with `Content-Type: application/vnd.patchlog.sealed-blob`. The blob id is therefore over ciphertext, and needs no nonce. The key goes into the reference, inside the sealed document:
```
{ "$blob": "1m4…", "type": "application/vnd.patchlog.sealed-blob", "size": 1843363,
  "sealed": { "key": "", "type": "image/jpeg", "size": 1843302 } }
```

`sealed.type` and `sealed.size` describe the plaintext.

- **Declared blobs.** The `sealed` op lists, in plaintext, the id of every blob the resulting document references: `[{ "op": "sealed", "value": "<JWE compact>", "blobs": ["1m4…"] }]`. Writers omit the member when the list is empty, and otherwise sort it by the ids' binary form (§3.2). The server accepts an empty list either omitted or as `[]`, and a list in any order; readers compare lists as sets. A list with duplicates is `422` (`code: "blob"`), and so is a declared blob whose type isn't the sealed type or that has a nonce. A restore with the empty patch set `[]` keeps the list of the last live document, and a sealed empty set that keeps a document unchanged (§F.3) repeats its list. The list is part of the hashed patch set, and the server keeps it with the revision's skeleton after pruning. Its length is checked against `blobsPerDocument`. The server checks that the blobs are available (§7.8), and uses the lists for unreferenced blobs, pruning, purge and bundles. Readers MUST compare the list with the decrypted document, and flag a revision whose list differs, like a failed validation (§E.3.2). A prune's sealed `snapshot` needs no list (§8.6): the server has that of the revision whose document it is.

- **Merges keep blobs.** A blob's key travels inside the document, so re-sealing a patch set for another namespace (§F.8.1) leaves its references, and the blob's ciphertext and id, unchanged.

### E.3.2 What the server can and cannot do

| Feature | E3 |
|---|---|
| Ordering, `If-Match`, `412`, idempotent retry | ✅ |
| Ids, chain verification | ✅ over ciphertext |
| Grants and roles on verbs, `/resource`, `/action`, `/now` and the principal | ✅ |
| `$schema` validation | ❌ moves to clients |
| Rules on `/doc` (including role rules), `writes` path policy | ❌ the server cannot see paths, so such rules make resource writes fail (§6.2) |
| Search, catalog `$access`, derived listings | only in services that hold keys |
| Caching of content | ✅ by `read` mode (§9), as ciphertext |
| Limits on documents (`documentSize`, `valueSize`, `pathSize`, `nestingDepth`) | ❌ checked by clients (`blobsPerDocument` by the server, on the declared list) |
| Blob references | declared in plaintext by writers, verified by readers (§E.3.1) |

- **Validation moves to clients.**

  - Every client MUST validate the decrypted document against its `$schema` before writing, and SHOULD verify it on read, leaving out the same members as the server (§6.2 step 5).

  - A revision that fails validation on read is **flagged** but still folded, and its author, recorded by the server as usual, is accountable. One whose patch set doesn't apply to its parent's document, a failing `test` included, is flagged too, and readers fold on from the parent's document as if it were `[]`.

  - Invariant 3 becomes a property checked by readers rather than enforced by the gate.

- **Path-level permissions** (e.g. translators only touching `/i18n`) need a separate resource per permission boundary.

- **Keys.** Key distribution uses §E.2.3, except that the server only relays **wrapped** keys.

  - Epoch keys are wrapped per recipient public key (§E.2.3) by a key-holding admin client, and stored in the namespace's `keyring` resource. Its document is `{ "keys": [{ "kid": "{ns}#{e}", "to", "from", "wrapped" }] }`, `to` and `from` being the thumbprints (§E.2.3) of the recipient and of the admin's X25519 key, with no other members but a `$nonce` (§C.7), and no two entries for one `kid` and `to` (`422`, `invalid`). Entries are wrapped as in §E.2.3 but in HPKE auth mode under that admin key, and a client seals only under a key whose `from` it trusts to distribute keys, configured out of band: anyone can wrap to a thumbprint, the server included. It is written in plaintext and checked as outside E3 (§6.2), and rules on `/resource` (§6.4) decide who may write it.

  - Adding a reader means wrapping the current epoch key for them. Revoking means rotating the epoch and re-wrapping for the remaining readers, done by a key holder, never by the server.

## E.4 Metadata that no level hides

- **What remains visible:**

  - resource and namespace names (they are in URLs)

  - ids and parent links

  - sizes, padded where `pad` is set

  - edit timing as it happens; at E2 the exact `created` of past revisions is sealed in the logs (§7.1), and at E3 it is served in the clear, except in logs from before a raise from `sealed` (Levels, above)

  - author identities and the grants they wrote with (recorded by the server, §7.4; at E3 served in the clear to readers, except those from before a raise from `sealed`, §C.3.1); at E3, which public keys the `keyring` wraps each epoch to and from

  - the shape of the namespace log

  - gesture ids (§7.2): sealed with log entries at E2; seen by the server at E3, so clients that must hide the grouping keep it inside their sealed content

  - query strings of derived views (§E.2.6)

  - blob sizes and counts; at E3, which revisions reference which blobs; at E2, which epochs a blob is served under

  - whether a blob carried over without a nonce matches a guess (§C.7)

- **Mitigations:**

  - opaque names (e.g. random slugs) in sensitive namespaces

  - padding sealed payloads to size buckets (`pad`, §E.2.2)

  - edge grants to hide existence from non-readers

  - accept that the operator of E3 still sees who writes when

## E.5 Open questions

- Should E3 allow clients to reveal a **plaintext `writes` list** alongside the sealed patch set? The server could then enforce path policy on the claim, with readers verifying it matches the decrypted patches.

- Should `/keys` refuse grants whose read rules refer to `/now`, as `POST /edge-grants` does (§C.5.2), since keys outlast the time window?

- Should `keyring` be reserved in every namespace, since a raise to `e2e`, or an import into an `e2e` target, turns an existing `keyring` resource into the plaintext key ring (§E.3.2)?

---

# Addendum F — Branches, merge and rebase (suggested)

This addendum uses the core's branches (§7.6), atomic batches (§7.5), and namespace freeze and purge (§8.4–8.5) for drafts, releases, previews and reviewed changes. **Merge and rebase are procedures built from core requests, not server operations,** carried out by clients or a merge service (§F.7); the core never rewrites history.

## F.1 Model

```
matches      ──●──────●──────●────────────────◆  batch, source: release-7
                 \ at                         ↑
release-7         └── derby′ ── cup′ ── +final ┘
                  (everything else is matches as of `at`)
```

-
**A branch is a fixed snapshot of its base plus its own changes** (§7.6).

-
**A branch is an ordinary namespace:** every tool that works on a namespace works on it.

-
**Uses:**

| Use | How |
|---|---|
| Drafts and review | Authors write in a branch, an editor merges |
| Releases | Prepare many documents, publish them as one batch per namespace, possibly at a set time (§F.9) |
| Schema migrations | Write the new schema revision first, or draft it in a branch of the schema namespace (§6.1, §F.9); migrate the documents in a branch and merge them as one batch whose `config` updates the rule allowing the new `$schema` |
| Previews | Point a preview site at the branch |
| Proposals from services | A plug-in service writes to a branch instead of the base (§C.6) |
| Private drafts of public content | A branch with `read: "grant"` |
| Catalog reorganisations | Branch a catalog namespace (Addendum B), review, merge the moves in one step |

## F.2 Creating and working in a branch

```
POST /ns/matches/branches
If-None-Match: *
Authorization: Bearer
{ "name": "release-7",
  "patches": [
    { "op": "replace", "path": "/read", "value": "grant" },
    { "op": "add", "path": "/cleanup", "value": { "merged": "P7D", "superseded": "P30D" } } ] }
```

-
**Configuration and base policy** are §7.6's; the base's rules can, e.g., require names such as `release-…`.

-
**Grants name namespaces explicitly:** one for `matches` doesn't work in `release-7`. Issuers add the branch, or for a release every branch it lists (§F.9), to the grants they issue, typically only for the people working on it.

-
**Consumers** that need the whole branch, such as a preview index, follow it as in §10 (Branches).

-
**The base keeps moving;** the branch sees it only after a rebase (§F.5), purges (§8.3) and the base's pruning (§8.6) excepted.

## F.3 Merge

A merge is **one batch into the base**, built from the branch's changes:

-
**Collect** the resources the branch changed, from its namespace log.

-
**Classify** each resource by **ancestry** of ids (§3.3), comparing the base's current head `B` with the branch's head `H`:

| Relation | Batch item |
|---|---|
| `B` = `H` | none: already merged |
| `B` is an ancestor of `H` (including the foreign parent, and "absent in the base" for a resource the branch created) | **fast-forward:** the branch's entries after `B`, with `ifMatch: B` (or `ifNoneMatch: *`). The resulting ids are **identical** to the branch's. (At E3 this is a re-sealed replay instead, §F.8.1.) |
| `H` is an ancestor of `B` | none: the base already has it and more |
| neither | **replay** the branch's entries after their latest common ancestor onto `B`, with new ids. **Always review it:** it conflicts if the two sides' `writes` overlap, the branch's counting the `from` of each `copy` too (§11.3), or if history it needs was pruned (§8.6), and `test` ops, schemas and rules catch the rest. |
| resource purged in the base or the branch | none: report it |

A `"delete"` step reproduces a tombstone (§7.5). Two cases always need a person, however they classify: deleting a document the base has since changed, and changing one the base has since deleted.

-
**Dry run** the batch (`?dry-run=1`) for a per-item report.

-
**Resolve** each conflicting resource by replacing its steps with one resolution set against `B`.

-
**Submit** the batch with `source: { ns: "release-7", at: <the branch's ns_id> }`, `at` being the branch revision step 2 classified from, not a later one. Consumers see the whole release as one entry (§7.5). If the base moves meanwhile, the affected items fail with `412`: re-classify those and resubmit.

-
**Freeze the branch** with a config write that also records `"merged": { "at": <the base's ns_id> }`, which the janitor reads (§F.6). Or keep working and merge again later: ancestry picks up exactly what is new. After a replayed merge, whose ids exist only in the base, treat each earlier merge batch from the same branch as a common ancestor: each resource has a known pair (branch revision as of the batch's `source.at`, base revision from the batch's entries), and a second merge replays only what the branch changed since.

  - Per resource, the pair comes from the most recent such batch that has an entry for it.

  - A resource deliberately kept at the base's version is still recorded in the batch, writing a revision with identical content: with an empty step `[]`, or instead a fresh `$nonce` add where nonces are required or the namespace is sealed (§C.7), or a sealed empty set at E3. Only a live base head can be recorded so: over a tombstone or absence `[]` would restore or fail, so such a resource stays unmerged and is offered again, and so does one at E3 whose base head references a blob that a `sealed` op can't declare, such as one from before a raise to `e2e` (§E.3.1, Addendum E, Levels).

  - `source` is asserted, not verified (§7.5), so only batches count that have no `origin`, whose `source.ns` is the branch, whose `source.at` is in the branch's chain (the merger checks this itself, §7.5), and whose recorded grant (§C.3) has a root `sub` and `kid` listed in the base's current `merge.authors`, declared in its namespace document, e.g. `"merge": { "authors": [{ "sub": "svc:merge", "kid": "ops-2026" }] }`. Removing an author withdraws its earlier batches, so a retired `kid` stays listed while branches it merged may merge again or await cleanup. For a catalog, one entry for the merge service and the catalog's merge key covers its merge batches (§F.8); changing `/merge` needs a `*` key (§7.4). Merges by anyone else, such as an editor merging by hand, aren't tracked, so such a branch should be rebased (§F.5) before it is merged again. The merger's dry-run report lists, per resource, which batch and author its pair came from.

- **Blobs.** A merger with unrestricted `read` on the branch copies nothing within the deployment: the batch's `source` makes the branch's blobs available (§7.8). Any other merger copies them first (§7.8), or uploads them where the ranks refuse a copy (§2.1), and a merge from another deployment uploads them (§G.3).

- **Nonces.** Tools that diff documents for a merge or a review leave out a fresh `$nonce`, as `writes` do (§6.4.1).

- **Conflicts inside arrays.** Array indices shift, so for merge and rebase a write whose last segment addresses an array element (an index or `-`) counts as a write to the whole array.

- **Configuration is never merged implicitly.** A config change meant for the base, such as a migration rule, goes in the batch's `config`.

- **Squash** replaces a resource's steps with one set of the same effect, losing per-set history and `test` ops. Replaying is the default.

- **Authorisation.** The batch is checked in the base under the merger's grant: the merger needs the base's verbs for every item, and the base's rules apply. Branch authors need no rights in the base.

- **Attribution.** Merged revisions, fast-forwarded or replayed, record the merger as author; the original authors stay in the branch's log, after a purge too unless the log is sealed (§8.5), and their signatures stay verifiable in the branch revisions `source` points at until the branch is purged (§F.6). The merger MAY carry each source revision's `gesture` and `undoes` in its steps (§7.5); squashing loses them. Where signatures are required, the merger signs its own steps (§C.3.1).

## F.4 Stacked branches

- **A branch of a branch** (`B2` based on `release-7`) reads through both, up to the branch depth limit (§6.6).

- **It is never broken by its base moving on:** its snapshot of `release-7` stays as it was, and a base with dependents can't be purged (§8.5).

- **Retargeting after a merge is almost free.** After `release-7` fast-forwards into `matches`, rebasing `B2` onto `matches` (§F.5) fast-forwards every resource that nothing else changed, reproducing `B2`'s ids, except at E3 (§F.8.1).

## F.5 Rebase: a successor branch

To bring `release-7` up to date with `matches`:

- **Create** `release-7-b` from `matches` at its current head, with `patches` that give it the old branch's `read`, or `"grant"` where that would rank it below the old branch (§2.1), as for a sealed branch whose `read` is `public`. A rebase never replays into a successor that ranks below the old branch.

- **Replay** `release-7`'s changes into it with batches carrying `source: { ns: "release-7", at }`, classified as in §F.3 but against the new branch. Resources that `matches` didn't change since the old `at` fast-forward and keep the **same ids**, except at E3 (§F.8.1).

- **Resuming.** When replaying resumes, batches in the successor without `origin` whose `source.ns` is the old branch count as earlier merges (§F.3), whoever wrote them, even without `merge.authors`; the janitor counts only those by `merge.authors` or under a `*` key of the old branch (§F.6).

- **Resolve** conflicts, over as many batches and people as it takes; the old branch keeps working meanwhile.

- **Switch** with one config write on the old branch: `"frozen": true, "successor": "release-7-b"`. Then replay whatever the old branch received after step 2.

- **Editors** of the old branch get `409 frozen` with the successor (§8.4), reload from it and replay their pending sets, as on `412` (§11).

- **The old generation stays readable:** reviewing a rebase is a diff between two namespaces, and every earlier link still works.

- **Previews** follow the `successor` chain.

## F.6 Lifecycle and cleanup

| State | Namespace | Reversible |
|---|---|---|
| Live | a working branch | — |
| Frozen | merged (`merged`) or superseded (`successor`), readable for review | yes: unfreeze |
| Purged | content gone, as in §8.5; name reserved | no |

-
**Cleanup** is plain data in the branch's namespace document, e.g. `"cleanup": { "merged": "P7D", "superseded": "P30D", "abandoned": "P30D" }`. The core doesn't enforce it. Without `cleanup`, the janitor never purges the branch.

-
**A janitor service** follows the bases and their branches (§10), and purges a branch when all of these hold:

  - it is frozen, and merged, superseded or abandoned

  - its cleanup period, the member of its `cleanup` for the state it is purged as, has passed (without one, it isn't purged as that state), counted from the last config write that froze it or set `merged`, `successor` or `abandoned`, and so have any minimums the base sets in its own `cleanup`

  - it has no dependents (leaves are purged first)

The janitor needs `purge-ns` on branches only, never on bases.

-
**The janitor MUST verify claims,** which any config writer of the branch can set: `merged`, `successor`, `abandoned` and `cleanup`, which it holds to the base's minimums (above). Before purging, it checks:

  - **merged:** the base's log has a batch **without `origin`**, by a principal listed in the base's current `merge.authors` (§F.3), whose `source.ns` is the branch and whose `source.at` is in the branch's chain, and the branch's log has no `head`, `tombstone` or `batch` entry after `source.at`. Entries of other kinds, such as the freeze's `config`, are allowed. A remote branch, merged back with `origin` (§G.3), never passes: it is cleaned up as superseded or abandoned, or by hand.

  - **superseded:** the successor is still one §7.4 allows, or was until a purge after the branch was frozen (not for a sealed successor, whose log the purge makes `410`, §8.5), its log has a batch without `origin` whose `source.ns` is the branch, whose `source.at` is in the branch's chain, and whose recorded grant has a root `sub` and `kid` in the base's current `merge.authors` or chains to a current `*` key of the branch, and the branch's log has no `head`, `tombstone` or `batch` entry after that `source.at`.

  - **abandoned:** the branch's document has `"abandoned": true`, set by a config write whose recorded grant (§C.3) chains to a current `*` key of the branch, inherited or its own. A flag set before v0.37, whose entry records no grant, doesn't count and must be set again.

  - At E3, entries for the branch's `keyring` resource, which is never merged (§F.8.1), are allowed after `source.at` too, in either check; a batch counts only if it has other items.

In either check, every resource with a `head`, `tombstone` or `batch` entry of the branch's own up to `source.at`, other than its `keyring` at E3, must also have an entry in a batch that counts there, or a head that the head of the batch's namespace equals or descends from. A branch with no `head`, `tombstone` or `batch` entry of its own, other than for its `keyring` at E3, counts as merged.

## F.7 Merge service (plug-in, optional)

-
**Discovery:** follows bases and picks up new branches from `branch` entries (§10).

-
**Status:** per branch and resource, ahead, behind, clean or conflicting, from `writes` overlap.

-
**Diffs:** branch against base, and generation against generation after a rebase.

-
**Preparation:** batches and dry runs, with resolution sets for conflicts, for a person to approve.

-
**Automation (optional):**

  - rebase branches whenever every resource fast-forwards, or at E3 is re-sealed onto an unchanged base (§F.8.1)

  - submit at a set time a batch a person approved, e.g. an embargoed release

Anything else, including any replay a person hasn't approved (§F.3), waits for a person, who sees the replayed result next to the reviewed branch document.

-
**Least privilege:**

  - `read` on bases and branches

  - `branch` on bases, and writes in branches, for rebases

  - `config` on branches, to freeze them and record `merged` or `successor`, and writes to its merge locks (§F.9)

  - write access to a base only if it merges on its own

## F.8 Access, encryption, catalogs and indexes

- **Editors limited to some documents** can't branch the base themselves (§7.6). A service that may branch it creates the branch for them, recorded with `via` (§C.1), with `read: "grant"`, and issues them grants on it fixed to the resources their base grants cover, as the catalog does for the base (§B.11.4). A branch scoped by the creator's own reads is an open question (§13).

- **Keys and revocation** in a base reach its branches (§C.4); roles and rules don't (§7.6, §F.3).

- **Encryption (Addendum E),** whose Levels also bind a branch's level to its base's:

  - **E2:** as §E.2.5 says; ids are over plaintext, so fast-forward merges keep ids.

  - **E3:** read-through content stays the base's ciphertext, and merging and rebasing re-seal (§F.8.1).

- **Catalogs (Addendum B).**

  - A catalog service MAY compute preview access from a branch, but MUST issue content grants only from the catalog it follows as the base.

  - Merging a catalog branch goes through the catalog service, which for an end-to-end catalog issues no merge grants and checks no catalog batch (`404`, `not_offered`), as for organising requests (§B.11.4). It checks every change in the batch as §B.11.4 checks organising requests, with the person who approved the plan as the caller, resolved from that person's own grant as §B.11.4 resolves one, and no widening whoever approved, and issues one grant covering exactly that batch: its rules allow exactly the batch's pairs of `/resource` and `/action`, and it expires within minutes. As it can't fix the documents or the batch's `source` (§6.4.1), the catalog service signs merge grants with a key used for nothing else, which can neither assert admin groups nor write `$access` (§B.11.3), only for the merge service (root `sub` the merge service's, `attrs.approvedBy` the person who approved the plan), and hands them to nobody else. The merge service submits exactly the batch that was checked. The catalog base lists that pair of `sub` and `kid` in `merge.authors` (§F.3).

  - Changes to `$access`, and moves and re-placings that widen (§B.11.4), need `catalog-admins` (§B.11.3), which the catalog key may never assert. A catalog batch with such a change is therefore checked by the catalog service in a dry run, except in an end-to-end catalog (above), with the person in `catalog-admins` whose grant it goes under as the caller, and submitted under that grant, through the merge service, which adds a narrowing block with its own `via` (§C.1). The catalog base lists each such admin in `merge.authors`, so the batch counts as a merge.

  - A catalog branch in a release previews against the release's content branches (§B.5), and is merged in two batches around the content (§F.9).

- **Indexes (Addendum A).** Search over a branch is a separate preview index (§10, Branches); the main index follows only the base.

### F.8.1 Merging and rebasing at E3

At E3 a merge (§F.3) or a rebase (§F.5) is carried out by a client that holds keys, such as the merge service (§F.7), and submitted as an ordinary batch sealed for the target.

-
**Keys.** The merger needs to read the branch and to write the target:

  - for reading, the branch's own epochs, plus the base's epochs up to the branch's `at` for read-through content;

  - for writing, the target's current epoch key.

A `kid` `{ns}#{e}` names the namespace whose `keyring` holds its key. Read-through content in a branch keeps the base's ciphertext and `kid`. A client asks the namespace it is reading for keys first: `POST /ns/{branch}/keys` relays the entries of its bases' keyrings as of `at` (§E.2.3), including a remote branch's mirrored keyring (§G.5.2), and gives a raised base's keys from before its raise as at E2 (Addendum E, Levels); only if that fails does it ask the `kid`'s namespace. The branch's own writes carry the branch's `kid`s, and a branch's `keyring` is never merged.

-
**Classification** is by ancestry over ids, as in §F.3; ids over ciphertext suffice, since read-through content keeps the base's ids (§7.6). Two rows of the table change:

  - **`B` is an ancestor of `H`**: a **re-sealed replay** rather than a fast-forward: the branch's entries after `B` re-sealed onto `B` in order, with new ids and no conflict check.

  - **Neither**: a replay with the conflict check, as in §F.3.

There are never fast-forwards at E3, even between namespaces with the same keys, because each sealed patch set binds its namespace and parent (§E.3.1).

-
**Re-sealing an entry.** The merger decrypts the patch set and checks its `pl` against where it was read: the branch (or the base, for read-through content), the resource, and the entry's parent. It then seals the same plaintext patches under the target's current epoch, with a fresh IV and `pl: { ns: target, name, parent }`. Here `parent` is `B` for the first entry, and after that the id the previous entry of the same item produces. The merger computes each new id itself (§3.3, over the sealed patch set). The target's `pad` applies (§E.2.2). A tombstone has no patches and needs no sealing: its id follows from its new parent (§3.4).

-
**Blobs** keep their ciphertext and ids, since their keys travel in the re-sealed patches (§E.3.1), and are made available as for any merge (§F.3). Each re-sealed op keeps its `blobs` list.

-
**Conflicts** are found by the merger, from the `writes` of the decrypted patch sets compared as in §F.3, arrays included; the server's dry run can only check preconditions, verbs and limits.

-
**Validation.** Before submitting, the merger folds every item and validates each resulting document against its `$schema` (§E.3.2), resolved as the target's gate would resolve it (§6.1). A document that fails is a conflict for a person, reported with kind `invalid` next to the overlap conflicts.

-
**Retries.** The merger keeps the sealed batch byte for byte until it is acknowledged, so a retry reproduces the same ids (§E.3.1). Re-classifying after a `412`, or changing a resolution, seals the affected items again, and they get new ids.

-
**Later merges and the janitor.** Every E3 merge is a replay, so a second merge finds its common ancestors in earlier merge batches (§F.3); these, like the janitor's checks (§F.6), need no keys. Without such a batch, for instance when the base lists no `merge.authors`, a merger MAY count a resource as merged when the target's and the branch's head documents are equal as decrypted plaintext. Every other resource the branch changed conflicts, and rebasing (§F.5) is the way forward.

-
**Rebases** (§F.5) re-seal in the same way, with the successor as the target. Only read-through content keeps its ids. Remote branches (§G.5.2) are merged in the same way, with the target's keys.

## F.9 Releases across namespaces

A release may span several namespaces, e.g. new documents in `matches`, their placements in a catalog namespace `cat-season` (Addendum B), and a new schema revision in `schemas`. Each is branched as usual, and the branches are listed in a **release document**: an ordinary resource that tools read and the core doesn't.

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
**Where it lives.** In a namespace whose rules decide who may create and change release documents, e.g. forbidding changes to `branches` once a merge has started. A release document only says which branches go together: every tool acting on it checks for itself, under its own authority, what it is about to do.

-
**Starting.** Each branch's own `at` is authoritative; the document's `at` is optional, and is dropped after a rebase. The branches SHOULD start at heads that were current together, such as the `ns_id`s in a catalog service's combined checkpoint (§B.5).

-
**Documents keep naming the bases** (placements `matches.final`, `x-ref`s `/r/matches/…`, `$schema` `/r/schemas/…`), never the branch names, so nothing is rewritten when the branches merge.

-
**Schemas.** Draft schema revisions are written in the release's branch of the schema namespace, and documents in the release's other branches resolve them by their base paths (§6.1) once that branch lists the other branches in `drafts.for` (§7.4). No namespace name is special: a namespace that keeps its schemas next to its content drafts them in its own branch, which is then all a release needs.

-
**Reading.** Previews follow the listed branches as §B.5 says. Items in a content branch the viewer can't read are hidden, not shown from the base, and a viewer who can't read the catalog branch gets `403`.

-
**Merging** is one batch per branch, so the release as a whole isn't atomic (§7.5). Before approval, the merge service checks that each listed branch's `base` is the namespace it is keyed by, or, for a release built on another, that release's branch for the same key where it lists one (below), and that the branch isn't frozen or purged; on resuming, it accepts the freeze its own approval made. A person approves the plan's **digest**, `text(trunc160(sha256(canonical(plan))))`, where `plan` is `{ "release": <the release document's revision path>, "batches": [{ "ns", "source", "config"?, "items": [{ "resource", "ifMatch" | "ifNoneMatch", "steps" }] }] }`: the batches in the order they will be submitted, their members as §7.5 sends them but before any sealing, each step its plaintext patch set without fresh `$nonce` ops (§6.4.1) and without a fresh top-level `$nonce` in the value of a root operation, or `"delete"`, and a precondition on an earlier batch's result `{ "batch", "item" }`, or `{ "batch" }` for its config id, indices from 0, in place of an id. The plan has no other members. Implementations agree on the digest of a given plan, not on how a plan is ordered, and fresh nonces, signatures and re-sealing at E2 and E3 don't change it. Approval fails if planning again doesn't give the same digest, and approving freezes every listed branch (§8.4); each `source.at` stays the branch's `ns_id` before that freeze when a step is classified again; unfreezing one invalidates the plan. Each step is classified again, with a dry run, right before it is submitted, and stops for a new approval if it differs from the approved plan. It orders the batches so that each state in between is safe:

  - **Schemas, by fast-forward only,** in `$ref` order. A schema resource is one whose documents are schemas, with a dialect URL as `$schema` (§6.1); its tombstones and restores fast-forward like any entry. A schema resource the base changed since `at` can't fast-forward, and replaying it would give new ids that no document references: that is a conflict. Rebase (below), and migrate the documents to the new revision with `replace /$schema` (§6.3). A branch that holds both schemas and content merges its schema resources here and its content in step 3. An end-to-end schema namespace isn't branched for a release (§F.8.1, §6.1): new revisions are written to it first.

  - **Catalog changes that narrow access.** A change goes here when, for every subject, the roles at every node afterwards are a subset of those before, judged by the test of §B.11.4 on the step-2 batch as a whole, whoever merges, `catalog-admins` included. That covers unplacing, `$access` edits that remove roles, and moves into folders that give no subject a role it lacked. A folder the release creates goes here, with its own `$access`, when a narrowing move needs it; the subset test applies to the items moved into it, not to the folder itself, whose title and `$access` powers take effect from then on.

  - **Content branches,** in any order. New documents aren't placed yet.

  - **Catalog changes that widen access:** new placements, and the remaining moves and `$access` edits. This step publishes the release.

Before submitting anything, the merge service reports these as conflicts for a person:

  - a catalog node whose change narrows access for some subjects and widens it for others, resolved with two resolution sets (§F.3): one narrowing for step 2, one widening for step 4.

  - a content item that step 3 creates or restores and that a placement in the catalog base already names, unless step 2 removes that placement, or the release keeps it unchanged and its approver accepts that.

  - a pinned `x-ref` (§6.5) or manifest entry (§B.4) naming a revision of another listed branch that the merge replays rather than fast-forwards. At E3 every merge replays (§F.8.1), so such references must be rewritten after the merge.

  - a document resolving a draft in a branch the release doesn't list.

The merge service stores the whole plan, both halves of every split node included, before it submits step 2, and a merge that stops part-way resumes from that plan and never reverts. Catalog batches are submitted as §F.8 says, by authors the catalog base lists in `merge.authors`. A split node's step-2 batch records a pair for it, which the more recent step-4 batch replaces (§F.3); until then the stored plan, not classification, decides what is left. Every branch records `merged` only after step 4, with `at` the target's `ns_id` after the last batch into it: for the catalog, after step 4.

  - **Exposure between steps.** Step 1 shows the schema drafts to readers of the schema namespace; step 3 shows new documents to whoever reads the content namespace directly: by URL in a public namespace, readers with unrestricted `read`, and consumers such as search indexes. Where that matters, keep the content private and read it through the catalog, or keep catalog and content in one namespace (§B.8, §B.9).

-
**Several releases.**

  - Releases on the same bases merge one at a time: the merge service merges one release per catalog base at a time, under the merge lock below, since another release's catalog changes can turn a narrowing move into a widening one without touching the moved node, which preconditions wouldn't catch.

  - **The merge lock** is a resource per catalog base in the release namespace, `merge-lock.{catalog}`, where `{catalog}` is the catalog base's namespace name (releases on one catalog base keep their documents in one namespace, so they share it), whose document is `{ "holder": <the merge service's sub>, "plan"?: <plan digest> }` while held and `{}` while free. It is advisory, taken by compare-and-append: the first take is a create with `If-None-Match: *`, later ones an append with `If-Match` on a free head, each setting `holder`; the holder sets `plan` with a further compare-and-append once its plan is stored, and releases the lock with an append back to `{}`. A resuming service replaces `holder` with its own `sub`, by compare-and-append, only if the lock's `plan` is the digest of the plan it stored; any other held lock is released by a person.

  - Two drafts of the same schema resource in different releases both start from its head, so only the first merged fast-forwards; the other release is rebased onto it, and its documents move to a revision that has both changes. Larger schema changes avoid this by going into a new schema resource, and a release may also merge its step 1 early, accepting that the drafts become visible.

  - A release built on another one branches that release's branches and names it in `on`. Its `branches` are still keyed by the namespaces paths name, and each listed branch's `base` is the earlier release's branch for the same key where it lists one. Its documents resolve drafts from both (§6.1), as long as the earlier release's draft branches list the earlier release's branches in `drafts.for`.

-
**Rebasing** a release creates a successor of each branch (§F.5) and lists them in a new revision of the release document. The schema successor is created with `drafts.for` naming the other successors, in its creation `patches`, and is replayed first. A draft that has to be replayed gets a new id, so a resource whose entries reference such a draft is squashed (§F.3): one resolution set against its new base, reaching the branch's document with `$schema` moved to the new revision.

-
**Cleanup.** The janitor (§F.6) purges each branch as usual, the release's draft branch last, since it can't be purged while documents rely on its last copy of a revision (§6.1). The release document only orders this, and never authorises a purge.

-
**Abandoning** a release before step 1 leaves nothing in the bases; after it, the merged schema revisions stay unused in the schema namespace's history. Its branches are frozen with `abandoned: true` by an administrator (§F.6).

## F.10 Open questions

- Should grants have a form covering a namespace **and its branches**, or all the branches of a release, e.g. `ns: ["matches/*"]`?

- Releases with branches in several deployments (§G.3).

- Should there be a stable alias that follows `successor` chains, for previews and bookmarks?

- Should the server offer three-way diffs, or leave them to the merge service?

---

# Addendum G — Federation and portability (suggested)

Ids hash content, never location, so a history has the same ids in every deployment. This addendum uses that to move content between deployments, such as staging and production, a partner's servers, an offline site or a new operator:

- **External consumers** read another deployment's namespaces (§G.2).

- **Remote branches** read a snapshot and send changes back (§G.3).

- **Bundles** carry documents in a file, with or without their history (§G.4).

**What it adds to the core:**

- the remote form of `base` (§7.6)

- `remote` branch entries (§3.5)

- the `export` verb (§C.1)

- `origin` in batch sources (§3.5)

- the `x-ref` annotation (§6.5)

- the `name_conflict` and `upstream` errors, and the `remoteRegistration` limit

Remote branches are an optional feature of the receiving deployment's server (§1). Export and import are separate tools using the public API.

## G.1 Principles

- **Every deployment has one canonical origin,** published at `GET /` (§7).

- **Ids travel, trust doesn't.** Anyone can verify content that comes **with its history** by recomputing ids (invariant 4) from a trusted starting point, an `ns_id` or revision id obtained from the source itself, whatever transport, cache or mirror delivered it. Snapshots, headers and listings not covered by ids are only as trustworthy as their channel.

- **A deployment boundary is a trust boundary.** Each deployment applies its own grants, rules and schemas at its own gate, to everything arriving from elsewhere.

- **Nothing is atomic across deployments,** just as nothing is atomic across namespaces (§1, §7.5).

- **Copies can't be recalled.** Once content is in another operator's hands, a purge there is a request, not a guarantee. Treat any read grant for a private namespace as disclosure.

- **Names are stable across environments.** Keep names the same everywhere (§11.1), and let the origin say which environment it is.

| Guarantee | Within a deployment | Across deployments |
|---|---|---|
| Ids and verification | ✅ | ✅ identical, for content with history |
| Fast-forward merges keep ids | ✅, except at E3 (§F.8.1) | ✅, except at E3, where only a bundle into a same-named namespace keeps them (§G.5.1) |
| Batch atomicity | per namespace | per namespace, on the receiving side |
| Keys and revocations follow the base | ✅ (§C.4) | ❌ each side has its own |
| Purges propagate to branches | ✅ (§8.3) | notices only (§G.3) |
| Base can freeze or purge its branches | ✅ | ❌ |
| Dependents block a namespace purge | ✅ (§8.5) | ❌ |

## G.2 External consumers

A consumer in another network or organisation works as in §10, plus:

- **Checkpoint.** It stores `(origin, ns, ns_id)`.

- **Verification.**

  - Revisions are verified through their log (`/r/{ns}/{name}/rev/{id}/log`), by recomputing ids back to a revision already verified, and the namespace chain entry by entry from the checkpoint.

  - A consumer SHOULD verify, and MUST when it fetches through a cache or mirror it doesn't control.

  - Below a pruning horizon, see §8.6.

- **Access.** Public namespaces need nothing. Private ones need a `read` grant from the source deployment, and the consumer's storage then holds a copy (§G.1).

## G.3 Remote branches

A branch on deployment B whose base is a namespace on deployment A:

```
"base": { "origin": "https://cms.example", "ns": "matches", "at": "1k…", "chain": ["matches"] }
```

-
**Creating one.** A remote branch is a new namespace on B (§7.6), created with B's deployment operator key (§C.4): `PATCH /ns/{name}` with `If-None-Match: *` and a genesis that sets the remote `base`.

  - Its namespace document is B's own, with nothing copied from A's configuration, though tooling MAY start from A's `roles`. It MUST require nonces if A's does (§C.7, `422` otherwise).

  - No `branch` entry is written on B.

  - The creator gives `at`, usually A's namespace head, and `chain`: A's namespace, then its base, and so on, as of `at`. B checks that `origin` isn't its own, that `at` is in A's chain, verifies A's namespace log up to it, and checks that `chain` names the bases it follows (below), `422` otherwise.

  - If A's namespace, or a base in its chain, is purged, creation is `410 purged` as §8.5 gives, not `422` as for a base B can't read (below). If A's deployment doesn't answer, or answers `5xx`, creation is `502` (`upstream`).

-
**Schemas, at creation.** `$schema` paths resolve on B's own server. So at creation, B, unless the source is end-to-end (§G.5.2):

  - reads A's `/ns/{ns}/rev/{at}/heads` once

  - collects the `$schema` and `$ref` closure of every resource

  - mirrors each schema resource's history, up to the referenced revisions (if any of them doesn't resolve in its namespace itself, as with drafts in a branch, §6.1, creation fails with `422`, `code: "schema_unavailable"`), into the namespace of the same name on B. B creates a missing one with the genesis document `{ "read": "public" }` if its source is `public` (§2.1), and `{ "read": "grant" }` otherwise. A mirror, created or existing, that ranks below its source (§2.1) is `422`.

If that namespace on B is a branch, or holds a resource at one of those paths whose chain neither contains A's nor is a prefix of it, creation fails with `409 name_conflict`; if it refuses the history, as a frozen or purged one does, with that refusal. Pinned `x-ref`s in read-through documents resolve on B only if B mirrors their targets too.

-
**Reading through.** B answers for untouched resources as A did at `at` (§7.6). A `$successor` (§8.1) read through resolves on B, the deployment serving it. B uses only A's immutable URLs: `/ns/{ns}/rev/{ns_id}` and its `/log` and `/heads`, `/r/{ns}/{name}/rev/{id}` and its `/log`, and `/r/{ns}/{name}/blob/{bid}`, or the `…/e/{e}` URL it redirects to (§E.2.2); and `POST /ns/{ns}/keys` for an E2 source (§G.5.2), or for an E3 one's epochs from before its raise (Addendum E, Levels).

  - B verifies each listed head against A's namespace log up to `at`, each revision through its log, and each blob against its id (§3.7), using the reference that names it.

  - If A's namespace is itself a branch, its read-through heads aren't in its own log. B verifies each of them against the log of the base that wrote it, following A's `base` and `at` (from A's configuration chain) recursively. If B can't read those bases, it can't create the remote branch (`422`). Clients reading an E3 remote branch accept read-through ciphertext whose `pl.ns` is in `chain` (§G.5.2).

  - B MAY fetch lazily, proxying and caching, or mirror everything up front. It serves the content under its own URLs.

  - A lazy fetch that fails, as when B loses A's read access, is `502` (`upstream`) for that resource. A protects history from `at` on only while B's registration lasts, and older history and the blobs it references not at all (§8.6), so they may become `410`. Mirroring up front, blobs included, avoids both.

-
**Registration (optional).** B may register the branch with A through `POST /ns/{ns}/branches` on A, with `{ "remote": { "origin": "https://b.example", "ns": "release-7" }, "at": … }` and `If-None-Match: *`, which fails (`412`) only while an unexpired registration of the same `remote` exists. To renew, B sends `If-Match` with the `ns_id` of the latest entry for that `remote`, expired or not (`412` otherwise), and the same `at` (`422` otherwise). Success is `201` with `X-Namespace-Revision`. A retry by the same principal, whose `If-Match` names the entry before the latest, or with `If-None-Match: *` where the latest is its own, unexpired, with the same `at`, gets `200` with the latest.

  - It needs unrestricted `read` (§2.1) and `export` on A. It is evaluated as an `export` envelope whose `doc` is `{ "remote": { "origin", "ns" }, "at" }`.

  - `origin` MUST be an `https` origin, or `http` for a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), and `at` MUST be in A's chain (`422` for either).

  - A appends a `branch` entry with `remote` (§3.5), and lists it in `/branches` as `{ remote, at, ns_id, expires }` only, `expires` as an RFC 3339 time. Remote entries don't count toward `branchesPerNamespace`.

  - Consumers, janitors and merge services MUST NOT fetch from a `remote` entry automatically. The origin is asserted by the registrant.

  - **Registrations expire.** A registration protects A's history from pruning (§8.6) only for the registration lifetime (`remoteRegistration`, §12.2), counted from its latest `remote` entry, which each renewal appends. After expiry A may prune past `at`, and merging history it pruned is a conflict for B (§F.3).

-
**Purges.**

  - B SHOULD follow A's namespace log whether or not it registered. On `purge` it MUST apply §8.3 locally: its own chains for that name, its own branches and its cache tags; on `purge-ns`, the same for every name A had at `at`. Purges in A's schema namespaces don't reach the schemas B mirrored, which are copies (§G.1).

-
**Merging back** is a batch on A (§7.5), classified by ancestry as in §F.3 and submitted by a principal with a grant on A.

  - Its `source` is `{ "origin": "https://b.example", "ns": "release-7", "at": … }`, recorded as asserted. A's gate checks every item, and fast-forwards reproduce B's ids.

  - Schema revisions created on B are exported to A first, as a full-history bundle (§G.4), or items referencing them fail with `schema_unavailable`.

  - Blobs that B's revisions reference and A doesn't have are uploaded to A first by the principal that submits the batch, as only their uploader can use pending blobs (§7.8).

  - The batch may come from B's side or from A's merge service fetching B's branch.

-
**Rebasing** is §F.5 on B, with the new branch based on A's current head.

## G.4 Bundles

A bundle carries selected documents between deployments as a file, e.g. for release promotion, fixtures, handovers or a partial backup. Exporting is a consumer (§G.2), and importing a client of the batch API (§7.5).

### G.4.1 Format

Newline-delimited JSON (`application/vnd.patchlog.bundle+jsonl`): each line is canonical JSON (§3.1) followed by one `0x0A`, and a bundle with any other line is rejected. The first line is the header, followed by one line per entry:

```
{ "bundle": 1, "origin": "https://staging.example", "created": "2026-09-25T10:00:00Z",
  "at": { "matches": "1k…", "schemas": "1d…" },
  "docs": { "schemas/match": { "history": "full", "head": "1s…" },
            "matches/derby": { "history": "full", "head": "1a…" },
            "matches/cup":   { "history": "snapshot", "head": "1c…" } },
  "external": ["media/photo-12"],                          // dependencies deliberately left out
  "requires": { "matches/derby": "1h…" },                  // incremental: must already be in the target
  "authors": false,
  "access": { "matches": "private", "schemas": "public" } }      // source protection, §2.1
{ "ns": "schemas", "resource": "match", "id": "1s…", "parent": "", "kind": "rev", "patches": [ … ] }
{ "ns": "matches", "resource": "derby", "id": "1a…", "parent": "1h…", "kind": "rev", "patches": [ … ] }
{ "ns": "matches", "resource": "cup", "snapshot": "1c…", "doc": { … } }
{ "ns": "matches", "resource": "derby", "blob": "1m4…", "type": "image/jpeg", "data": "" }
```

- **Full-history lines** are resource log entries (§7.1), of kind `rev` or `tombstone`, with `ns` and `resource`, and with authorship members only as below. They come in chain order per resource. Every id is recomputed, and the last line per resource MUST be that document's `docs[…].head`.

  - Every `docs` entry MUST have lines, and every line naming a resource MUST have a `docs` entry. Any mismatch rejects the whole bundle.

  - A chain starts at genesis or right after its `requires` id. Chains exported from a branch include the base's entries back to genesis, or name the foreign parent in `requires`. `ns` is always the exporting namespace.

- **Snapshot lines** carry the document and its source id as provenance: one per `snapshot` document, whose `snapshot` MUST be its `docs[…].head`. A document tombstoned at the source is `{ …, "snapshot": <tombstone id>, "deleted": true }`, without its document, so a move's `$successor` (§8.1) travels only in history bundles. The dependency closure (§G.4.2) doesn't follow successors.

- **Blob lines** carry every blob that an exported document references, from any exported revision of a `full` document or from a snapshot. Each comes once per resource, with `nonce` if it has one, before the first line that **mentions** it: one whose patches carry its id as a `$blob` member or as the value of an operation whose path ends in `/$blob`, whose snapshot document references it, or whose declared list (§E.3.1) names it. `data` is the bytes in base64url, written without padding; readers accept either. The importer recomputes each id (§3.7), and a mismatch rejects the bundle. An incremental bundle MAY leave out blobs that the history up to `requires` already references.

- **`requires`** applies only to `full` documents. `requires[r]` MUST be in the target's chain for `r`. If the target has moved on along another line, `r` is a conflict.

- **Authors, `via`, grant ids, author signatures, creation times, `gesture` and `undoes`** are included only with `"authors": true`. With them, history lines carry `grant: gid` (the id only, not §7.1's object), and a bundle carries one grant line `{ "ns", "grant": gid, "root", "stored", "key"?: { "kid", "alg", "pub" } }` per grant its lines name, before the first line that does. Its `ns` is the namespace whose entry first recorded the grant, in the form of `written` below. An exporter that can't fetch a grant leaves `grant` off the lines that would name it. A line naming a grant with no earlier grant line, a second grant line for one grant, or a grant line in a bundle without `"authors": true` rejects the bundle.

  - **`written`.** A line for a revision written in a namespace other than the exporting one, such as one a branch reads through from its base, also carries `written`: that namespace's name, or `{ "origin", "ns" }` when it is in another deployment, as a remote branch's base is. Verifiers use it, and its `origin`, in the signing input (§C.3). An exporter that can't determine it, because no log it can read records the revision, writes the line without `written` and without `grant` rather than guess, so its signature reports as unverifiable.

  - **`key`** is the key entry the grant's root block verified against at the source (§C.3.1): a key of the namespace document in force at the first entry that recorded the grant (in a branch, or of its local bases' then), or else an operator key in force at the `created` of the first revision naming the grant (§C.4). An exporter that can find neither leaves `key` out. `key` is attested by the exporter, not proven: the digest isn't a signature (Trust, below).

  - Bundle tools SHOULD verify signatures through §C.3.1's chain against the line's `written` origin, else the header's `origin`. A tool holding the source's namespace log, or its operator key history, checks `key` at the revision's position; otherwise it reports the signature as attested, not verified. An importer signs its own steps (§C.3.1); the original signatures stay in the bundle, which its batches' `source` names (§G.4.4).

- **Never exported:** purged content.

- **Consistency.** Each namespace is exported as of its own `at`, taken when the export starts.

- **Digest.** A bundle's digest, recorded as `source.bundle` (§G.4.4), is `text(trunc160(sha256(b)))`, where `b` is the bundle's bytes as written (§I.9).

- **Trust.** Headers and snapshot lines are only as trustworthy as their channel (§G.1) until signed bundles exist (§G.7). A sealed bundle (§G.5.1) hides a bundle from all but its recipients, but anyone with their public keys can write one.

### G.4.2 Selection and dependencies

A selection is a list of resources, or anything a resolver turns into one, e.g. a catalog folder (Addendum B). The **dependency closure** is built in three levels:

- **Core references, always** (a document that references a schema revision existing only in a branch, §6.1, can't be exported until that branch is merged: `schema_unavailable`, unless that schema's namespace is declared `external`, when the importer checks the target instead): the `$schema` of **every exported revision**, not only the head's, `$ref` inside those schemas, and the blobs those revisions reference (§7.8).

- **Declared references:** fields marked `x-ref` in the documents' schemas (§6.5). A **pinned** reference needs that exact revision. A **live** reference needs the head as of the export's `at`.

- **Application resolvers:** tool plug-ins for relationships no schema expresses, e.g. "a match brings its team pages" or "a folder brings its placements".

Untyped documents have no level 2, but an opt-in rule may treat any string in them matching `^/r/` as a reference. Dependencies left out on purpose with `external` are checked by the importer to exist in the target: by id for pinned references, by name for live ones.

### G.4.3 History or snapshot

Each document is exported in one of two modes:

|  | `full` | `snapshot` |
|---|---|---|
| Contents | every revision, or those after `requires` | the head document only |
| Ids in the target | identical to the source | new, derived from the sequence of snapshots imported |
| Verifiable lineage | ✅ | ❌ provenance only |
| Later imports | fast-forward or merge (§F.3) | merge through the upstream namespace (§G.4.4) |
| Old drafts and authors | included (authors optional) | never included |

- **Schemas are always `full`.**

- **Modes close downward.** Everything a `full` document reaches through `$schema`, `$ref` or a pinned `x-ref` MUST also be `full`. A pinned reference to a revision other than a document's head also forces `full` for that document.

- **No shallow mode:** a source id without its ancestors couldn't be recomputed (invariant 4).

### G.4.4 Importing

- **Check the bundle** (§G.4.1), including `requires` and `external` against the target. Nothing is written if this fails.

- **Classify full-history documents** by ancestry, as in §F.3:

  - missing in the target: created with the whole chain, keeping its ids

  - the target has an ancestor: fast-forward

  - the target already has it, or has moved beyond it: nothing

  - a different history: conflict

  - purged in the target: nothing, reported (§F.3)

- **Import snapshot documents through an upstream namespace.** The target keeps one namespace per source namespace for them, `{ns}-upstream`, written only by imports from one origin; a name that breaks §3.6, or a bundle from another origin than the imports that wrote it, is refused at step 1, so a second origin's namespace is imported renamed (below).

  - **Upstream first.** Each import appends to each snapshot document there one revision: `diff(previous snapshot, new snapshot)`, or a genesis the first time. For a deleted document it appends a tombstone where the upstream document is live, and otherwise writes nothing. An empty diff writes nothing, and diffs ignore `$nonce`. The upstream chain is exactly the sequence of snapshots as imported, and its ids depend only on that sequence, except where the target or the upstream namespace is sealed, or the upstream namespace requires nonces as its target does: there each generated patch set carries a fresh `$nonce` (§C.7).

  - **Then the target, as a merge from upstream.** The first time, the target fast-forwards and so shares the upstream ids, or conflicts (step 4) if it already has the document. Later, the base is the upstream revision recorded in the previous import batch's `source.ids`, and the upstream revisions after it are replayed onto the target's head. They conflict where they overlap the target's own changes (the array rule of §F.3). A deletion conflicts if the target changed the document.

  - **Pinned references in snapshot documents** that point at other snapshot documents are rewritten to the matching upstream revision path, `/r/{ns}-upstream/{name}/rev/{id}`, keeping any `#{id}` fragment (§6.5). The dry run lists undeclared strings that have the form of a revision path.

- **Dry run, then resolve conflicts,** as in §F.3: skip the document, take the bundle's version, or replay. A dry run draws what its submit does (§6.6), so a tool needn't dry-run every batch: it may dry-run each existing namespace's first batch, and a new namespace's first item as a batch of its own, and rely on each later batch's own failure report (§7.5), except for batches that change existing dependencies, which are dry-run first (below). Appends to an upstream namespace don't count as such: only pins name upstream revisions, and those don't change.

- **Submit batches in dependency order.**

  - **Order.** Dependency order is per batch: a batch goes once every batch holding a revision it pins, schemas included, has committed. Live references order nothing. Batches with no such dependency between them may be in flight at once, except batches that write the same resource, which chain through `ifMatch` and go in order. A pin of a full document needs its namespace's batches first, and a snapshot document's pin of another bundled snapshot needs its upstream namespace's. In a cycle of namespaces, what the upstream namespaces need (schemas, full documents) goes first, then the upstream namespaces' batches, then the batches that pin them.

  - **Size.** Batches split to fit §6.6 make the import non-atomic, which a backfill can accept. Its tool paces the batches, dry runs included (§6.6), at a fraction of the lower of the namespace's and its own principal's rate. Under an allowance it may use the allowance's full rate, counting dry runs; per-resource buckets still apply (§6.6). With several batches in flight, a request is paced as drawing at the moment it is sent: the server may draw later, after later requests, but never earlier. An import that must land at once, such as a release, runs as one batch under an allowance (§6.6), typically as a merge from a branch it was first imported into (§F.3).

  - **Blobs first.** The blobs a batch needs are those its steps' values mention (§G.4.1). They are uploaded before it by the importer, or copied with `Blob-From` within one deployment (§7.8), unless the batch's local `source` already makes them available. Uploads aren't writes for step 1: an import that will submit uploads a batch's blobs before that batch's dry run, if it has one (step 4), and one that only dry-runs uploads none, and gets them reported as missing (§7.5). A snapshot document's blobs go to both its upstream resource and its target. Pending blobs expire after `blobGrace` (§7.8), so a long review re-uploads them. A large import needs an allowance that raises the importer's `blobPending` (§6.6).

  - **Missing namespaces.** Under authentication, creating a namespace takes an operator grant (§C.4), and a grant for a namespace that doesn't exist yet is `401` (§7). So the operator creates the missing namespaces, upstream ones included, before step 1, with keys that include the importer's and, for pacing at full rate, an allowance for it (§6.6).

  - **Renaming.** An import MAY map a set of source namespaces to new names together (`src=dst`), to clone them; snapshot documents then go through `{dst}-upstream`. It rewrites every reference to a mapped namespace: `$schema`, `$ref`, pinned and live `x-ref` values, and pins to revisions, which take the new ids. Rewritten documents are new content: a full-history document's steps are rewritten and submitted one by one with new ids, never fast-forwarded, and their signatures don't carry over; `source.ids` records the source ids. The dry run lists undeclared strings naming a mapped namespace (`/r/{src}/…`). Catalog placement names aren't renamed, and a renamed namespace's configuration isn't in the bundle (§G.7). Further:

    - a `$successor` naming a mapped namespace (`/r/{src}/…`), and the value of an `add` or `replace` at `/$successor` in a history line, is rewritten as any reference is, and a bare one needs nothing;

    - documents of unmapped namespaces in the bundle that reference a renamed one are rewritten too, and a reference that only a later revision's schema declares is rewritten in that revision, by an added `replace`;

    - a renamed namespace's upstream (step 3) is `{dst}-upstream`;

    - mapping onto a branch whose `base` chain reaches `src` isn't a rename: references and ids are kept;

    - refused at step 1, since the new value can't be known: an incremental document that would change, whose `requires` names a source id; a full-history document's pin whose new id isn't known, because its target is `external`, left out, or a snapshot document's revision;

    - where nonces are fresh, ids differ between runs, so a re-run recognises its earlier writes by the import batches' `source.ids`.

  - **Rewriting waits for its targets.** A document's references are rewritten only after the batches of its dependencies have committed, using the ids they returned.

  - **Source.** Each batch's `source` is `{ "origin", "ns", "at", "bundle": <digest>, "ids": { name: upstream or source id } }`, without `origin` when the bundle's `origin` is the target's own (§7.5), and the importer is recorded as author.

  - **Partial failure.** A failure part-way can leave dependencies updated: new resources are unused, but updated heads take effect, and live references see them. So promotions that change existing dependencies should be dry-run end to end first. Where the limits allow, submit such a promotion, within one namespace, as one batch, whose dry run is end to end. Otherwise a dry run sees only what is committed: a tool dry-runs each later batch that moves heads the target had, reports as deferred any failure that wouldn't occur once the earlier batches are written, and skips a batch that continues a chain an earlier one cuts.

- **Today's rules judge old history.** A full-history import replays every step through the target's **current** gate (§6.2), as the importer, at the current `now`. Rules on `/principal`, `/now`, `writes` or, for replayed deletes, `/doc` may reject history that was valid at the source, and so may a target that requires nonces, or a sealed one, whose writers add a fresh `$nonce` to every patch set (§C.7, §E.2.5). Such imports need an importer whose roles satisfy those rules, or snapshot mode.

## G.5 Encryption (Addendum E)

- **Obligations A can't enforce.** A can't enforce B's checks on a remote branch (§G.5.2), or an importer's (§G.5.1); an `export` grant entrusts them.

- **E2.** An exporter with keys decrypts, so the bundle holds plaintext (§G.5.1). A remote branch has its own epoch keys.

- **E3.** Bundles and remote branches carry ciphertext, and ids over it verify as usual. Keys travel separately, via the keyring, to recipients who may read.

### G.5.1 Bundles

- **`access`** in the header gives each exporting namespace's protection as a source (§2.1): `"public"`, `"private"`, `"sealed"` or `"e2e"`. Exporters MUST include it.

- **Importing.** At step 1 (§G.4.4), the importer refuses a bundle that would put a namespace's lines into a target, or into that target's upstream namespace (§G.4.4), that ranks below that namespace (§2.1), unless an operator explicitly overrides this for that import. An importer that holds an `e2e` target's keys MAY import a source that isn't `e2e` into it by sealing each patch set client-side, encrypting each blob as in §E.3.1 and rewriting its references to the new blob ids. The ids change, so pins to them, incremental documents and later imports are handled as for a renamed import (§G.4.4).

  - An `e2e` source goes only into an `e2e` target **with the same namespace name**, override or not, since sealed patch sets bind `pl.ns` (§E.3.1). Lines carry the ciphertext, and the plaintext `keyring` (§E.3.2), verbatim, and ids verify as usual. At step 1 the importer refuses a bundle with a blob line that lacks the sealed type or has a nonce (§E.3.1), or with a `rev` line other than the `keyring`'s whose `patches` are neither one `sealed` op whose `pl.ns` and `kid` name the line's `ns` nor a restore's `[]`, such as one from before the source became end-to-end (Addendum E, Levels) or one a branch reads through from its base. Such history, and an import under another name, is carried over as a merge by a client that holds both sets of keys, with new ids. A target created for the import starts at the bundle's lowest epoch and is moved up one epoch at a time as its keyring lines arrive, so the importer needs `config` on the target, with a `*` key (§7.4). An existing target is moved up the same way, and is refused at step 1 if its `keyring` would conflict with the bundle's (step 2), since a `kid` would then name two keys, or if its epoch is below the bundle's lowest or above that of a line it lacks, since step 3 accepts only the epoch in force (§E.3.1).

- **No snapshots at E3.** Documents of an `e2e` source are exported `full`, and an importer refuses snapshot documents for an `e2e` target at step 1 (§G.4.4, §F.8.1).

- **Plaintext of protected sources.** A bundle with lines from a `private` or `sealed` namespace holds plaintext, and SHOULD be delivered as a sealed bundle. Exporters SHOULD refuse to write it unsealed unless asked to.

#### G.5.1.1 Sealed bundles

A sealed bundle (`application/vnd.patchlog.sealed-bundle+jsonl`) encrypts a bundle line by line, so it can be written and read as a stream:

```
{ "sealedBundle": 1, "id": "",
  "recipients": [ { "kid": "", "suite": "hpke-base-0x0020-0x0001-0x0002", "wrapped": "" } ] }

…
```

- **Envelope line.** `id` is 128 random bits, base64url without padding. The content key `K_b` is 256 random bits, wrapped for each recipient as keys are in §E.2.3, but with the `info` `"patchlog-bundle-v1" ‖ 0x0A ‖ id`, `id` as its 22 ASCII characters. A recipient's `kid` is its thumbprint (§E.2.3).

- **Lines.** Each following line is a JWE compact under `K_b`, with `alg: "dir"` and `enc: "A256GCM"`. Its protected header carries `pl: { "bundle": id, "line": n, "last"?: true }`, with `last` on the last line only. The plaintext of line `n` is bundle line `n` (header = 0) as canonical JSON, without its newline. Lines are never compressed.

- **Checks.** A reader MUST reject the whole sealed bundle if any line fails to decrypt, if `pl.bundle` differs from `id`, if line numbers are not 0, 1, 2… in order, or if no line says `last` or a line follows it. The decrypted bundle is then checked as in §G.4.1.

- **Digest.** `source.bundle` is the digest of the decrypted bundle (§G.4.1).

- **What stays visible:** the number of lines, their sizes and the recipients' thumbprints. Padding (§E.2.2) MAY be applied to each line's plaintext, and is removed before the checks and the digest.

### G.5.2 Remote branches

- B MUST refuse (`422`) to create a remote branch whose `read` or level §7.4 would refuse for a local branch of its source, or whose source's namespace document it can't read, and likewise a config write that makes it `public`, raises it to `e2e` or turns off a `nonce` requirement its source has, judged by its source's current namespace document, read for that write and refused as creation is where it can't be (§G.3), and MUST raise its level when it sees its source do so in the log it follows (§G.3), as far as Levels allow, raising its own dependents first, leaves first (§7.4); it SHOULD restrict its `read` when its source does, and rebase (§G.3) where Levels refuse the raise, as for an `at` before an `e2e` raise.

- **E2 sources.** B fetches keys from A with its own key pair and grant (§E.2.3), mirrors the plaintext, and seals what it serves under the branch's own epoch keys.

- **E3 sources.** B mirrors ciphertext and the `keyring` verbatim, and verifies ids over the ciphertext. The branch's name MUST NOT be in `base.chain` (`422`), since a `kid` `{ns}#{e}` names one keyring (§F.8.1). B skips §G.3's schema step, and the creator imports the schemas first, as a full-history bundle (§G.4). A remote branch of an E3 namespace keeps its source's namespace name in `pl.ns`, so its readers use the source's keys, which B relays from the mirrored keyring through `POST /ns/{branch}/keys` (§F.8.1). Read-through content sealed further up, by A's own bases, carries their names and is accepted when they are in `base.chain` (§G.3); B relays their keys when it mirrors those namespaces' keyrings, and otherwise readers fetch them from A with grants of their own there. Writes to the branch are sealed under keys the branch's own key holders manage, and are merged back by re-encryption (§F.8).

- **Epoch start times** decide which epochs B relays to a grant (§E.2.3). B takes the epochs from the source's namespace documents and their start times from its namespace log, whose `created` times aren't hashed (§5), so the times are only as trustworthy as the channel. Relayed keyring entries are wrapped to keyring recipients, so a wrong start time changes only which of them a grant receives, never who can unwrap them. For the keys B hands out itself, those of a source's epochs from before its `e2e` raise (Addendum E, Levels), B reads the start times only from A's origin (§G.1) or caches A controls, never from a mirror or other intermediary.

## G.6 Multi-region (outlook)

A read-only mirror is a remote branch that is never written. A mirror that tracks its source needs periodic rebasing, each a new namespace (§F.5), so stable URLs need an alias that follows `successor` (§F.10). Multi-primary writes would need a way to order concurrent heads, and are out of scope.

## G.7 Open questions

- Should bundles carry namespace configuration (roles, rules, limits, `schemaReads`), so a renamed import (§G.4.4) can clone a set of namespaces with its policy? Keys and allowances are trust decisions of the target, which an importer shouldn't take over unasked.

- Absolute pinned references, in `$schema` (§13) and `x-ref`, so a bundle or remote branch can point back at its origin instead of mirroring.

- Signed bundles, covering the header and every line.

- A namespace flag such as `export: false`, as a policy statement that well-behaved deployments respect.

- Should registered remote branches confirm purges back to A (a purge receipt)?

# Addendum H — Files (suggested, non-normative)

Tools that show namespaces as files, such as WebDAV gateways, mounted file systems, sync tools and editors, follow these conventions so that they can share a namespace. A gateway is an ordinary client of the core API (§11), and needs nothing more from a core server.

## H.1 What a file is

-
**Raw files.** Every file other than a JSON file is a **raw** document (§7.8), its bytes kept exactly. Text files (`.md`, `.txt`, source code) are raw too. Their `type`, which is part of the blob id (§3.7), is taken from the file name's extension, in any letter case, by this table; for an extension the table lacks, or none, the upload's `Content-Type`, parameters dropped (§3.7), if it is given and isn't `application/octet-stream`, `binary/octet-stream`, `application/x-www-form-urlencoded` or `multipart/*`; otherwise, for an existing file, the type it has, and for a new one `application/octet-stream`. At E3 the reference's `sealed` member holds the file's `type` and `size`, and its own are the sealed blob's (§E.3.1). A `text/` type needs a body in UTF-8 (§3.7), a leading BOM allowed; any other body gets `application/octet-stream`.

| Extensions | Type | Extensions | Type |
|---|---|---|---|
| `md`, `markdown` | `text/markdown` | `png` | `image/png` |
| `txt`, `text` | `text/plain` | `jpg`, `jpeg` | `image/jpeg` |
| `html`, `htm` | `text/html` | `gif` | `image/gif` |
| `css` | `text/css` | `webp` | `image/webp` |
| `js`, `mjs` | `text/javascript` | `svg` | `image/svg+xml` |
| `csv` | `text/csv` | `pdf` | `application/pdf` |
| `xml` | `application/xml` | `zip` | `application/zip` |
| `yaml`, `yml` | `application/yaml` | `docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| `json` (not I-JSON, below) | `application/json` | `xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

-
**JSON files.** A document that isn't raw is a **JSON file**: the file is the document's value, read as its **rendering**. The rendering is the canonical JSON text (§3.1) of the document without a top-level `$nonce` of the fresh form (§6.4.1) and without a top-level `$successor` of the form of §8.1, laid out as ECMAScript `JSON.stringify(value, null, 2)` lays it out: every member and element on its own line, indented two spaces per level, `": "` after member names, `,` at line ends, empty objects and arrays as `{}` and `[]`, LF line ends, and one final LF. Tokens, member order included, are exactly JCS's: implementations lay out the canonical text, and never re-serialise a parsed object (§I.10). Its type is `application/json`.

-
**Which kind a new file is.** A new file whose name ends in `.json` (in any case) and whose body is I-JSON (a leading UTF-8 BOM dropped; in this addendum, I-JSON is what §3.1 accepts) is a JSON file; any other new file is raw, a `.json` file that isn't I-JSON included. An existing file keeps its kind: a JSON file accepts only I-JSON, a leading BOM dropped (`400` otherwise), and a raw file any bytes.

-
**Empty files.** An empty body makes or truncates a 0-byte raw file (`touch`, `.gitkeep`, `__init__.py`), except over a JSON file (`400`) and except under a new `.json` name: that, and a `LOCK` of a new name, is held by the gateway as a placeholder (§H.7), listed as a 0-byte file, until a body arrives and decides its kind. An empty body decides nothing.

-
**Writer's bytes.** Every tool shows a document as the same rendering. A gateway MAY also serve a writer its own bytes back for a revision that holds exactly what it sent, for clients that check the size they uploaded; everyone else gets the rendering. The writer's bytes go under the weak `ETag` `W/"{id}"`, which a gateway takes like the strong one in any `If-Match`, as a save's base (§H.4) and as a delete's or move's precondition (§H.5).

-
**Nonces.** Where nonces are required (§C.7) or the namespace is sealed (E2; at E3 ids need none), a JSON file's root must be an object, which carries `$nonce`, and a gateway refuses any other root there (`422`, saying why). A raw file's root carries `$nonce` beside the reference, and its blob a `Blob-Nonce` (§7.8).

-
**Identity.** A file's `ETag` is its item's head revision id, so it names the content, not the bytes a client holds. A raw save is always stored with the uploaded value, and a JSON save when the stored document's rendering parses to it, whatever the upload's formatting. After a save the gateway merged with others' edits (§H.4), the next `GET`, `HEAD` or `PROPFIND` of the file is answered in full, whatever validators it carries.

## H.2 Trees

Resource names are flat and limited (§3.6), so a tree of files lives in a catalog namespace (Addendum B), with names as data:

-
**A file tree is a catalog** `C`. Its `catalog` object (§B.6, §7.4) carries `"files": { "ns", "root", "folder"?, "placement"? }`, which may also hold `x-` members (§7.4):

  - `ns`, the content namespace new files are created in. A tool checks that `C` trusts it before creating there (§H.4); the namespace document doesn't require it. The tree **owns** an item in `files.ns`: a gateway takes any item there to be placed only in this tree, and doesn't also serve `files.ns` as a writable flat folder;

  - `root`, the node name (§B.2: no dot) of the folder whose children are the tree's top level. It is created without parents, either when the catalog is set up, before its rules forbid new roots (§B.6), or under a rule that exempts it;

  - `folder` and `placement`, schema revision paths that new folder and placement nodes carry as `$schema`.

-
**Folders** are folder nodes (§B.2), with opaque names without a dot. A folder's name in the tree is its `title`.

-
**Files** are placements, named `{ns}.{item}` (§B.2). A file's name in the tree is its placement's `title`. The item `/r/{ns}/{item}` has an opaque name, such as 13 random base32 characters; a readable stem is allowed but means nothing once the file is renamed. A node without a non-empty string `title`, written by another tool, is shown by its item's name, or a folder by its node name. A file tree doesn't set `catalog.title` (§B.5); where one does, tools read titles from the placement documents, never from listings.

-
**Untrusted namespaces.** Placements of items in namespaces `C` doesn't trust are dangling (§B.5), and a tool leaves them out, whether it lists through the tree service or from the node documents.

-
**Shape.** File trees set `catalog.mode: "tree"` (§B.6): a file or folder has exactly one parent, inside the `root` subtree. New nodes get an `order` after their last sibling (§B.2).

-
**Titles** are Unicode in NFC, 1 to 255 bytes of UTF-8, never `.` or `..`, and without `/`, `\`, NUL, or characters of the categories `Cc`, `Zl` and `Zp`, or the bidirectional controls U+202A–U+202E and U+2066–U+2069 (other `Cf` characters, such as joiners, are allowed); a catalog enforces this with a rule `pattern` (RE2 classes such as `\p{Cc}`) and the byte length in the tool. A gateway converts names it receives in NFD, as macOS sends them, to NFC, refuses a trailing space or dot on create and rename for every client, and shows an existing one escaped. A title written by another tool that breaks these rules is shown with each offending character, a trailing space or dot, and a whole `.` or `..` percent-encoded as UTF-8, the stem shortened so the name stays within 255 bytes (`a/b.txt` as `a%2Fb.txt`); an escaped name never takes the name of a real title, which keeps it, and is numbered as a duplicate instead, within 255 bytes.

-
**Siblings.** Files and folders in one folder share one set of names, compared after NFC and, unless a gateway is set to be case-sensitive, after Unicode simple case folding, as NTFS compares names (not full folding). Tools refuse to create a name a visible sibling has; the source of a `MOVE` isn't its sibling, so a rename that only changes case is allowed. A `PUT`, `COPY` or `MOVE` to a name that matches a sibling only under another case is `409`, naming the sibling, and sets a guard (§H.6), unless the request carries a tag or the user read or wrote that file under this spelling; `MKCOL` under another case is `405`, and a folder in the middle of a path matches whatever its case. A duplicate left by a race is shown as `name (2).ext`, `name (3).ext`, … in order of the nodes' `born` (§B.5), then node name, the first keeping its name; a number that would collide with a real title is skipped, and the stem is shortened so the name stays within 255 bytes.

-
**Access.** In a catalog with tree-derived access (§B.11), a user's rights to read, place and move come from the catalog's grants and `/read-grants`, not from a grant on the content namespace.

-
**Flat view.** A namespace may also be shown without a catalog, as one directory whose file names are resource names: a raw document as its name, any other document as `{name}.json`. If a raw resource `x.json` and a document `x` both exist, the raw file keeps its name and the document is shown by the duplicate rule above. The flat view has §3.6's names and no folders; a rename is a copy and a delete (§H.5, §8.1). A new file whose resource is tombstoned, where §H.6 doesn't restore it, restores it with a root `replace` (§8.2), except one whose last revision has a `$successor`, which is `409`, naming the new path. A new file whose resource is a live document shown under another file name (a new `x.json` beside a raw `x`, or a new raw `x` beside a JSON document shown as `x.json`) is `409`, naming that file.

-
**Not covered:** branches of file trees (§F.9) and manifests (§B.4).

## H.3 Listings

- **In a tree,** a folder is listed from the tree service's `children` listing, with `total`, the top level from `roots` where `root` is hidden from the user (§B.11.5), and a path of titles is resolved with its `lookup` (§B.5); a case-sensitive gateway lists the folder instead when the answer's title differs in case. A tree service following a file tree adds to each placement of an item in any namespace the catalog trusts `file: { "size", "type", "modified"? }` from the item's head, which it reads for this once per revision, cacheable for good: for a raw file, the blob reference's `size` and `type`; for a JSON file, the length of its rendering and `application/json`; and `modified`, the head's `created`, where it is known. For items in sealed namespaces it seals `file` as a value of another resource (§E.2.6). Where it can't give `file`, it says why: `"file": { "absent": "e2e" }` for an end-to-end item, `{ "absent": "pending" }` for a head it hasn't read yet, which a tool reads from the core.

- **A folder too large to list whole** (beyond what a tool pages through) is refused (`403`, saying why), never listed cut short: a sync tool deletes what it doesn't see. A path inside it still resolves by `lookup`, or, in a sealed or end-to-end catalog, which doesn't offer that (§B.5), is `403` too.

- **A tree service that is behind** answers `503 behind` with `Retry-After` (§B.5); a tool passes it on, and deletes nothing on the strength of a listing meanwhile.

- **Read-your-writes.** A tool sends the `X-Namespace-Revision` of each of its writes, the catalog's and the content namespace's, as `?min` on later listings, kept and dropped as §A.5 says.

- **In the flat view,** a directory is listed from the `head` rows of `/heads` (§7.4), tombstones and purges left out: `ETag` from `target`, the time from `created`. A JSON file's size is its rendering's, not `/heads`' `size`, and a raw file's is the blob reference's `size` (at E3 its `sealed.size`), so both need the head document once per revision, cacheable for good.

- **Where times are absent,** rows without `created` take `Last-Modified` from the document read for the size (§7.1). In sealed and end-to-end namespaces a gateway with keys takes them from the logs.

- **Sealed and end-to-end catalogs** seal their titles too, so a gateway without the catalog's keys doesn't offer the tree.

## H.4 Saving a file

A save is §11.3's procedure, with these specifics:

-
**Names before writes.** A listing lags the core, so before any write a tool checks the names it resolved from a listing against the node documents, found through the catalog's `/heads` (§7.4): each node still in its folder under that name, and no node under a name the listing lacked. Where they disagree it reads the graph again and resolves the path from the node documents. A folder's emptiness is taken only from the node documents. A grant that can't read them keeps the listing's view for names, and deletes no folder (`403`). A name the tree service's filtered listing lacks is never revealed or edited: a `PUT` onto a name only a sibling hidden from the user has creates a new file.

-
**The base.** The entity tag a client sends in `If-Match` (its first value, `W/` dropped) or, failing that, in an `If` header (the first tag of the first list that applies to this resource and isn't negated with `Not`; tag-only lists are not lock tokens) names the **base**: the revision the client opened. This deviates from RFC 9110 on purpose, for `PUT` only: an older tag is not a failed precondition but the starting point of a rebase. `If-Match: *` asks only that the file exist, and the head is the base. A tag naming a revision where the path holds no file (a new name, a flat name that never existed) is `412`, not a create; one naming a revision of a flat resource another user has since deleted is `409`, as a delete between base and head is.

  - An unknown revision is `412`. A pruned one is `409`, asking for a reload, and so is a recorded base below a horizon, or a pruned range between base and head. A read that fails (`429`, `5xx`) fails the save (`503`, `502`); the head is never taken as the base instead.

  - **Records.** Without a tag, a gateway MAY keep, per user (§H.7) and path, the revisions it served that user in full and the ones it wrote for them, with the item each path named when last read whole or written. A `304`, `HEAD` or `PROPFIND` records nothing, and a save that changed nothing isn't a write. Records outlive sessions, for a day, and a path whose records expired counts as evicted. A save at a path that now names another document, or none, is `409`, and a `GET` of the path is the reload; the user's own `DELETE` or `MOVE` forgets the path, except a move to a scratch name (§H.5). When the budget is full the oldest records other than the first and the latest write go first; a path never recorded takes the head as its base, while one whose records were evicted is `409`.

  - **Several records.** For a JSON file the save is checked against every one of the user's recorded versions, each taken as the base: if any two would give different documents, the save is `409`, naming the paths. As the one exception to that rule, a save without a tag that sets back a value someone else changed is merged, keeping the other value.

  - **The reload** a `409` asks for is a full read of the file by the token that was refused (its conditional `GET` is answered `200`, not `304`), and that read becomes the path's only record; a refusal re-arms nothing for the user's other tokens. After a `409` because someone else deleted the file, the `GET` that finds it gone (`404`) is the reload, and the next save restores the file as §H.6 restores one after a delete, except a file whose last revision has a `$successor`, which no save recreates: the save is `409`, naming the new path (§11.3).

  - With no base at all, the head is the base, and the save overwrites others' edits on the paths it changes. Clients SHOULD send their `ETag` back.

-
**Others' writes.** `theirs` (§11.3) is the writes of the log entries between base and head by other users (§H.7), leaving out the user's own, unlike §11.3; a value changed and changed back is still a conflict.

-
**JSON files** are saved as a patch set from the base's rendering (the base document without the members §H.1 leaves out) to the new file, parsed, so the base's `$successor` is kept, and `add /$nonce` carries a fresh value where §C.7 asks for one. The overlap rule is §11.3's, except that a write anywhere inside an array counts for the whole outermost array. A patch set over `opsPerSet` or `patchSetSize` (§6.6) becomes a root `replace` carrying the fresh `$nonce` and any `$successor`, if the base is the head and the namespace isn't end-to-end, and is `413` otherwise.

-
**Raw files** have no paths to merge. A raw save is checked against every version the user had (the `If-Match` revision, else every version served to them or written by them) and conflicts only if someone else changed the bytes, or deleted or restored the file, after any of them; the user's own writes are theirs. Then the body is spooled and hashed, uploaded as a blob (§7.8; `413` above `blobSize`, before any upload), and the blob reference's members set one by one with `add`, `replace` or `remove` (`/$blob`, `/type`, `/size`, `/nonce`, and at E3 `/sealed`), with a fresh `/$nonce` where nonces apply, never the root, which would drop `$schema` and `$successor`. A `412` retry reuses the pending blob rather than uploading again. Bytes are compared by blob id, so under nonces identical bytes count as a change.

-
**New files** in a tree: check that `C` trusts `files.ns`. Where grants come from the catalog (§B.11), place first, then upload the blob of a raw file and create the item with `If-None-Match: *`, since the create grant is resolved from the placement (§B.11.4); the placement dangles meanwhile (§B.7) and is deleted if the create fails. Otherwise dry-run the placement as a one-item batch (§7.5) before any upload, then upload, create the item and place it, and remove the item at once if the placement fails. Nobody else deletes an unplaced item younger than `blobGrace` (§6.6).

-
**Partial writes** (`PUT` with `Content-Range`) are `400`, and so is a body cut short; nothing is written. `POST` to a file is `405`, with `Allow`.

-
**Answers** a gateway gives, to any request:

| Case | Gateway answers |
|---|---|
| Saved, stored with the uploaded value (§H.1) | `201` or `204`, with the new revision as `ETag`, even where the rendering's bytes differ from the upload's: a deliberate deviation from RFC 9110 (section 9.3.4) |
| Saved, merged by the gateway with others' edits | `201` or `204`, no `ETag`, and the next read in full (§H.1) |
| Overlap with others' edits since the base, a delete or restore by another user (§H.7) between base and head (§11.3), a pruned base, records that disagree or were evicted, a path that now names another file, or a file moved away | `409`, naming the paths, and telling the user to reload |
| The client's own precondition failed: `If-None-Match: *` on a live file (but see the move-aside, §H.5), `If-Match` naming an unknown revision, or where the path holds no file (a flat resource another user deleted excepted, §H.4), `Overwrite: F` on an existing target | `412` |
| A new name that breaks the title rules or ends in a space or dot (§H.2), or that isn't a resource name in the flat view (§H.2, §H.6); a new file where `C` doesn't trust `files.ns` | `403`, saying why |
| Validation, rules, blob or nonce refused (`422`), or the grant refused (`401`, `403`), by the core or by the tree service | that answer, with its message; where the user can't fix it, as when the gateway's own grant is refused, `502` naming the service |
| Frozen namespace | `403`, naming the successor; never `423` (§H.6) |
| Purged | `410` |
| Rate limited, or a service behind, for longer than a client waits (§6.6, §B.5) | `503` with `Retry-After` |
| A tree service that can't be reached | `502` |
| A limit exceeded (the core's `413` or `422` with `code: "limit"`) | `413`, in one shape: `too large: {limit} {measured} > {max} (§6.6): {message}`, a limit without sizes named alone, and a `413` that names no limit keeping the core's text |
| A bound of the gateway's own (an upload buffer, a file-size setting, `blobSize` checked before an upload) | `413` in the same shape, naming its setting, `measured` a lower bound where reading stopped |
| The gateway's own memory for scratch files or locks full (§H.6) | `507`; bounds are generous |

## H.5 Deleting, renaming, moving and copying

- **Delete a file:** delete its placement, then, where the tree owns the item (§H.2) and the grant allows `delete` there, the item; otherwise the item stays, unplaced or placed elsewhere.  A failure between the two leaves an unplaced item (§H.4). The delete carries `If-Match` on the head the tool read: a client's `If-Match` that isn't the head is `412`, and the gateway's own delete finding the head moved since its read is `409`.

- **Delete a folder:** only one without visible children, taken from the node documents (§H.4); `409` otherwise, naming those children and nothing hidden from the caller (§B.11.5). Dangling placements (§B.3) aren't contents: the gateway deletes those it can first, and the rest are orphaned like hidden ones. Placements the user can't see don't stop the delete and become orphans (§B.7), visible under `/orphans` to readers with unrestricted `read`. A child placed while the folder is deleted is orphaned too.

- **Rename or move within a tree:** one append to the node's `title` or `parents`, with `If-Match`, beginning, under a Move grant from the catalog (§B.11.4), with the `test` of `/parents` it requires, after checking that the node's document still has the name and parent the path named (`404` otherwise). The new parent must be inside the `root` subtree, and not the node itself or a descendant of it (`403`); the race that could still make a cycle is visible in `/problems` (§B.5). On any `MOVE`, a client's `If-Match` names the source, and one that isn't its head is `412`, as for a delete.

- **Move onto an existing file** (`Overwrite: T`, which is what an absent `Overwrite` means; `F` is `412`): a save of the source's content into the target (§H.4, with the target's base taken as §H.4 says, though never from `If-Match`, which names the source), then a delete of the source as above, so the target keeps its history. A `MOVE` or `COPY` onto an existing folder, or of a folder onto a file, is `403` (`412` with `Overwrite: F`).

- **Moves that copy** (onto an existing file, across trees or namespaces) check first that the source can be deleted; then copy, then delete the source with `If-Match` naming the revision copied. A source that changed since is `409` and stays; a delete that fails anyway leaves the copy, with no rollback.

- **Move to a scratch name** (§H.6), an editor's backup step: the file is copied into scratch and stays live. The next create-only `PUT` of the original path by the same user within 30 seconds is accepted once as an edit, with its base taken as for any untagged save (§H.4), rather than `412`.

- **Across trees or namespaces:** when the item itself goes to another namespace, its last revision before the tombstone carries `$successor` (§8.1); a JSON file whose root isn't an object can't, and moves without one. Within one tree the item doesn't move, and needs none.

- **Copy:** a new item with the source's current content, and a placement for it; a `COPY` onto an existing file (`Overwrite: T`) is instead a save of the source's content into the target, as for a move onto it. A folder is copied, or moved to another tree, as a new folder node titled with the destination's last segment, without the source's `$access`, which only `catalog-admins` set (§B.11.3), its visible children then copied or moved into it one by one (`Depth: 0` copies the folder alone), and a moved folder deleted once empty; a failure part-way leaves what was done, with no rollback, and is answered as that child's request would be. A raw file's blob is copied with `Blob-From` where §7.8 allows it, and otherwise the file's bytes are uploaded again: decrypted with the reference's key from an `e2e` source, and encrypted under a fresh key, with a new id, into an `e2e` target (§E.3.1).

## H.6 Clients as they are

Lessons from running real clients against a gateway:

-
**Scratch files.** Editor and system files are kept by the gateway in bounded memory (§H.7), never written to the core:

  - files: `.DS_Store`, `._*`, `Thumbs.db`, `Icon` followed by CR (U+000D), `~$*`, `.~lock.*#`, `*.swp`, `*.swo`, `*.swx` (vim's swap files), `4913`, `*~`, `#*#`, `*___jb_tmp___`, `*___jb_old___`, `.goutputstream-*`, `sed` followed by six letters or digits (as `sed -i` names its temporary file);

  - folders: `(A Document Being Saved By …)`, `.Trashes`, `.Trash`, `.Trash-*`, `.Spotlight-V100`, `.fseventsd`, `.DocumentRevisions-V100`, `.TemporaryItems`. A folder is scratch only if listed: any other folder, a dot folder included, is real.

  - An existing node with such a name is a real file: an existing name always wins over a pattern. The names a file manager gives a copy beside a file (`x copy.txt`, `x (1).txt`) are real names in a tree, and, in the flat view, where no resource name has a space, scratch only as `COPY` destinations; a plain `PUT` of one there is `403`.

-
**Delete, then write.** Some clients delete a file before writing it again, or, as rclone does, about a second after any refused upload. So:

  - A write to a path the same user deleted within the last 30 seconds restores that file (its placement, then its item) rebased on its last live document (§8.2), rather than creating a new file; a restore whose patch set would exceed `opsPerSet` or `patchSetSize` is written as a whole-document `replace` when its base is the last live document. If the restore is refused (`403`, `410`), the write creates a new file or is refused as such a write would be. A file that was moved away (its item has `$successor`) is never restored this way.

  - If such a write is refused, the user's delete is undone where it can be: what it removed is restored. Never a delete older than 30 seconds.

  - A refused `PUT` or `COPY`, a refused move onto a file, or a refused case variant (§H.2) sets a guard: that user's `DELETE` of that path within the next 10 seconds is `409`, once per refusal. A `DELETE` that carries `If-Match` passes, and leaves the guard in place. A refused plain move sets none, two refusals never share one guard, a guard ends only by time, not by another program's write, and none is set after an undo. Guards are sized for many uploads at once.

-
**Locks** (`LOCK`, `UNLOCK`) are kept by the gateway, per user, bounded, and never sent to the core. Finder and davfs2 need them to write. They protect nothing between users or against other API writers. A `DELETE` drops the user's locks on the path and below (RFC 4918, section 9.6), and a `MOVE` or `COPY` sent with the source's lock token isn't `412` for want of a lock on the destination.

-
**Dead properties** (`PROPPATCH`) are refused, or kept by the gateway per user and scope (§H.7), up to a bound past which the least recently set path's are dropped, moved with a `MOVE` and dropped with a `DELETE`; never acknowledged and kept nowhere.

-
**Listings.** A listing of `Depth: infinity` is `403` (`propfind-finite-depth`); `PROPFIND` without `Depth` is `1`, not RFC 4918's infinity (section 9.1).

-
**Headers.** A gateway serves raw files itself, from `…/raw` or the blob, under the revision's `ETag`, never as a cross-origin redirect. Every response it gives, JSON files, scratch files and error bodies included, carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox` (PDFs excepted from the sandbox, §7.8).

-
**Status codes.** Clients read `423` as "retry later" and `507` as a full disk; they are used only for what they mean.

## H.7 Access and encryption

- **Grants.** A gateway either passes each user's grant through as the bearer of every core request, or holds its own grant and narrows it per user with `via` (§C.1). Either way the core authorises every core read and write. A gateway with its own grant doesn't serve a tree with tree-derived access (§B.11), whose tree service and `/read-grants` decide for the root block's subjects, which narrowing can't change (§C.1, §B.11.5); in other trees it hides from each user what that user's narrowed grant can't read.

- **Users.** A user is the root `sub` with the `key` that verified the root block, from `GET /ns/{ns}/principal` (§7.4), so `(key, sub)` neither merges different people nor splits one person whose token is reminted under the same key; after a key rotation the person is a new user. A user's own entries are those whose `grant` has its `sub` and a `kid` that named its `key` when written, and, in a tree with tree-derived access, those in content namespaces whose `grant` has its `sub` and a `kid` that named the catalog's key there (§B.11.4). With authentication disabled, a user is an `X-Author` (§7.2), and its entries those with that `author`. Operator grants (`operator: true`) are never users of a gateway (`403`). With a narrowed gateway grant, the user is the one the gateway named in `via`; the core's rate buckets, pending blobs and recorded authorship then belong to the gateway's principal, shared by its users (§6.6, §7.8), so a user's own entries are only those the gateway recorded writing for it. A gateway that uses one bearer for everyone is one user, and programs sharing one grant count as one.

- **What a user's tokens share.** State that holds no content (guards, the user's own deletes, move-aside marks, records) is per user. State that holds content (scratch files, placeholders, locks with their owners, dead properties) is kept per user and **scope**, the token's rights: its root block without `kid`, `sub`, `nbf`, `exp`, `at`, `enc` and `signers`, and its narrowing blocks without `nbf` and `exp`, with `ns`, `can`, `roles` and `groups` compared as sets. It is served only to a token of that scope whose grant names the namespace, never to a narrower one. Caches of what was read (documents, graphs, listings, writer blocks) are per token. Each kind of per-user state is bounded per user; a new scope when content scopes are full is `503` with `Retry-After`, never a drop of one holding content.

- **Re-checking.** A gateway creates state for a grant only after the core has accepted it, bounds the users it keeps state for, and re-checks a grant at least every five minutes. It relies on a `writer` block (§7.4) for 30 seconds at most, and reads it again after `409 frozen`, `422 nonce` or a limit refusal. When the core refuses a token, the gateway stops serving it; the user's state stays for the user's other tokens, each re-checked at its next request.

- **Limited grants.** A grant limited to some resources can't list a flat namespace (`/heads` needs unrestricted read, §2.1); in a tree with tree-derived access it lists through the tree service, which filters by the reader (§B.11.5), and elsewhere it can't list (§B.5). It learns what it needs to write, and the tree's settings, from `GET /ns/{ns}/principal` (§7.4).

- **Catalog writes** (titles, parents, new nodes) carry a fresh `$nonce` where the catalog requires nonces or is sealed (§C.7), as file writes do.

- **Sealed and end-to-end namespaces** need keys (Addendum E). A gateway without them doesn't offer those namespaces, never showing their files as writable empty files.

## H.8 WebDAV

One mapping, as an example:

| WebDAV | In a tree | In the flat view |
|---|---|---|
| `PROPFIND` (`Depth` 0 or 1) | `children` of the folder (§H.3) | `/heads` (§H.3) |
| `GET`, `HEAD` | the item: its bytes for a raw file (§H.6), the rendering for a JSON file | the same |
| `PUT` | §H.4 | §H.4 |
| `DELETE` | §H.5 | delete the resource |
| `MKCOL` | a folder node | `403` |
| `MOVE` | §H.5 | `403`, or a create and a delete with `$successor` in one batch |
| `COPY` | §H.5 | a new resource |
| `LOCK`, `UNLOCK` | in the gateway (§H.6) | the same |
| `PROPPATCH` | refused, or kept in the gateway (§H.6) | the same |
| `POST` | `405` | `405` |

## H.9 Open questions

- Line-level merges for text files, which are raw and conflict as a whole.

- Should the tree service, rather than each tool, flag sibling title collisions and unplaced items, e.g. in `/problems` (§B.12)?

- A tentative delete, or an atomic "replace content", for clients that delete before they write, so the deleted window isn't visible to every reader.

- Branches of file trees, and manifests that keep titles.

# Addendum I — Test vectors (normative)

Values that §1 requires implementations to agree on byte for byte. Each was computed by the reference implementation and recomputed independently from the text. Byte strings are hex unless marked otherwise, and JSON is shown in its canonical form (§3.1). A conforming implementation reproduces every value here for each part of the spec it implements, and rejects every input marked as rejected.

## I.1 Canonical JSON (§3.1)

| Input | Verdict | Canonical form |
|---|---|---|
| `{"a":1,"b":2.0}` | accept | `{"a":1,"b":2}` |
| `{"a":1e2}` | accept | `{"a":100}` |
| `{"a":9007199254740991}` (2⁵³−1) | accept | `{"a":9007199254740991}` |
| `{"a":9007199254740992}` (2⁵³) | `400` | — |
| `{"a":-9007199254740992}` | `400` | — |
| `{"a":1000000000000000000000}` (10²¹, integer literal) | accept | `{"a":1e+21}` |
| `{"a":1e21}` | accept | `{"a":1e+21}` |
| `{"a":1e300}` | accept | `{"a":1e+300}` |
| `{"a":0.1}` | accept | `{"a":0.1}` |
| `{"a":1,"a":2}` (duplicate key) | `400` | — |

Members sort by UTF-16 code units: `{"b":1,"a":2,"ä":3}` is `{"a":2,"b":1,"ä":3}`, and keys with characters above U+FFFF sort by their surrogate pairs.

## I.2 Ids (§3.2–§3.5)

```
patches₁ = [{"op":"add","path":"","value":{"title":"Hello","views":0}}]
patches₂ = [{"op":"replace","path":"/views","value":1}]
```

| Quantity | Text form | Bytes |
|---|---|---|
| genesis `g`, parent empty, `patches₁` | `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll` | `5e8c8d1cecdd67fd2e5a750b07aa0f91fd4ab16b` |
| child `c`, parent `g`, `patches₂` | `1sywh54kpo3c4ezn2znktvl3avge4zl5d` | `962c7ef14f76c5c265bacb553aaf60a989ccafa3` |
| tombstone of `c` | `1idx6u2b3z42obqmwsgmlzvrfuutks2bq` | `40efea683bcf34e0c1969198bcd625a526a96830` |

Text ids are exactly 33 characters, `1` then 32 of `a–z2–7`; 160 bits fill 32 characters exactly, so there are no padding bits. Rejected: `1L2GI2HHM3VT72LS2OUFQPKQPSH6UVMLL` (uppercase), `1l2gi2hhm3vt72ls2oufqpkqpsh6uvml` (32 characters), `1l2gi2hhm3vt72ls2oufqpkqpsh6uvml1` (`1` isn't in the alphabet), and `2l2gi2hhm3vt72ls2oufqpkqpsh6uvmll` (unknown version prefix).

Namespace chain:

```
entry₁ = {"kind":"config","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
ns_id₁ = 1vmctae4vewju6nvxi374rkrkmyzpdrif                     (previous empty)
entry₂ = {"kind":"head","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
ns_id₂ = 1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm                     (previous ns_id₁)
```

## I.3 Blob ids (§3.7)

For the 15 bytes `hello patchlog\n` with `type` `text/plain`:

| Nonce | Id |
|---|---|
| none | `1m5jj344d7tz7cicfmq53ayhmwuubpmyt` |
| `aaaaaaaaaaaaaaaaaaaaaaaaaa` | `1hdwkfub2zymqzgc75snybxosfk67633s` |

## I.4 Grant ids and author signatures (§C.3, §C.3.1)

Root block:

```
{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}
```

Grant id: `15swdvi5nbnlkv76v7y6k77h52atov6ru`.

Signing input for `origin` `https://cms.example`, `ns` `matches`, `name` `derby`, parent `g` and `patches₂`:

```
sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖ 0x0A ‖ bytes(g) ‖ 0x0A ‖ canonical(patches₂))
  = 43bba3f8e86bdd96435153ddb0d704cab7e5e9459087f3fd78c157b6a7102c54
```

The Ed25519 signature (RFC 8032) over the 32 raw bytes of that digest verifies under the public key `RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM` (base64url, as a signer's `pub`), listed under `kid` `key-1` in a grant's `signers`:

```
Ed25519:key-1:Zdm2HSg4Fefj9ZaOYm2nYdW7xyLjKc_6T8CruK76EDEL_H6rnZd_sKdQrlevjtIQDGpiudAJjyHigradmHXXCA
```

A tombstone's signature uses the ASCII bytes `tombstone` in place of `canonical(patches)`.

## I.5 Edge-grant cookies (§C.5.3)

With the key `3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708`, checked with a clock before `exp`:

```
c     = {"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}
name  = __Secure-pl-eg-4390e78526d94754
value = eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw
```

An edge ignores: claims with a fourth member; claims that aren't canonical byte for byte, such as the same members reordered; a MAC that verifies only over a re-encoding of the claims, not over the value as received; a name that doesn't match its `p`; an `exp` in the past; a `p` that covers the path only as a string prefix (`/r/demo` for `/r/demox`).

## I.6 Padding buckets (§E.2.2)

| `L` | Padded | `L` | Padded |
|---|---|---|---|
| 1 | 256 | 513 | 544 |
| 255 | 256 | 1000 | 1024 |
| 256 | 256 | 4096 | 4096 |
| 257 | 272 | 1000000 | 1015808 |
| 300 | 304 | 1048576 | 1048576 |
| 511 | 512 | 67108864 | 67108864 |

The rows just above a power of two (257, 513) are where rounding errors show.

## I.7 Per-resource keys (§E.2.1)

For `K_e` the bytes `00 01 … 1f`, `ns` `demo` and `name` `derby`, 32 bytes out:

```
K_r = 37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25
```

## I.8 Subject sets and combined checkpoints (§B.5, §B.11.5)

The two `ns_id`s of I.2 serve as inputs only.

```
subjects = ["group:match-desk","user:anna"]      gs = 17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm
{"cat":"1vmctae4vewju6nvxi374rkrkmyzpdrif","matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"}
                                                 at = 1vwnfnoyshruyx4lul4a25rtctooiph5v
```

## I.9 Bundle digests (§G.4.1)

The digest covers the bytes as written: these two lines, each followed by one LF (a digest test only, not an importable bundle), give `1b3a64kkqf3o6f3rglkgi6ok5hgldbne6`.

```
{"authors":false,"bundle":1,"origin":"https://staging.example"}
{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}
```

## I.10 File renderings (§H.1)

It binds tools that claim Addendum H. The document

```
{"$nonce":"abcdefghijklmnopqrstuvwxyz","10":true,"2":[],"items":[{"id":"a","n":1.5},{}],"title":"Café"}
```

renders as these 118 bytes (sha-256 `c7e8bfb3ff3fed1b111dda8cce06b4f2c1b7615565e828f4777ebf63055e887c`), the fresh `$nonce` left out and `"10"` before `"2"`, as JCS orders them, where ECMAScript's `JSON.stringify` of a parsed object would put `"2"` first:

```
{
  "10": true,
  "2": [],
  "items": [
    {
      "id": "a",
      "n": 1.5
    },
    {}
  ],
  "title": "Café"
}
```

## I.11 Still to come

Plan digests (§F.9); file renderings with a `$successor`, a `$nonce` not of the fresh form, escapes, an array root and an exponent (§H.1); sealed bundles (§G.5.1.1), with their rejection cases; the sealed-blob layout and sealed payloads with their `pl` (§E.2.2); wrapped keys (§E.2.3); Biscuit encodings (§C.8), with a token failing each acceptance rule, and their revocation ids (§C.4).

---

## Changes

The full history is in CHANGELOG.md, and the conformance checklist in CONFORMANCE.md. Since v0.58:

- **v0.59:** checklist items for §8 (DEL-1 to DEL-18), now in CONFORMANCE.md.

- **v0.60:** answers for the cases §7 and §8 left open or stated inconsistently, found while writing their checklist items. Most only say what the rest of the spec already implies; these choose:

  - **Create on a deleted resource** is `410` (`gone`) with `head` the tombstone, never `412`, so a client's rebase loop can't turn a create into a restore (§7.2, §8.1).

  - **Resource event streams:** `Last-Event-ID` wins over `since`, and no `since` means from genesis; `purge` and `prune` events carry the namespace entry without `id` and `prev`, and no `id:` field; a namespace purge ends resource event streams, with no `purge` event (§7.3).

  - **Batches:** a resource named twice, two preconditions, or neither `items` nor `config` are `400`; a dry run runs and reports the `config` change too; a batch whose `config` change fails is answered as that config write (§7.5).

  - **Branches:** a local branch's creation without `If-None-Match` is `428`; its genesis is the document after `patches`; a retry that omits `at` matches the recorded one; `/ns/{ns}/branches` is `410` after a namespace purge (§7.4, §7.6, §8.5).

  - **Long-poll:** a request without a cursor is answered at once, as one behind is (§7.7).

  - **`successor`** names a namespace with the same base in every namespace, so a namespace that isn't a branch names one that isn't either (§7.4, §8.4).

  - **Namespace purge** checks in §6.2's order: verb, purged, `not_frozen`, precondition (`428`/`412`), dependents, schema copies, rules; its `412` carries `{ head }`, and its schema-copy `409` carries `referencing` (§8.5).

  - **Pruning:** a prune without `keep` leaves the kept set as it is, and `[]` clears it; the answer is `{ "horizon" }`; a prune in a branch moves nothing; an E3 prune without `snapshot`, or with no archive configured, is `422` (§8.6).

  - **Also:** which headers quote ids; which writes carry `X-Namespace-Revision`; `/principal`'s `403` for a grant failing the `ns` check; raising the encryption level to `e2e` with public dependents is `409 in_use`; `not_offered` for `/gestures` and for epoch blob URLs outside sealed namespaces; blob `410` caching; `415` for resource `PATCH`; the branch-nonce `422`, and the unfreeze `422`'s `limit`; frozen namespaces still answer retries and refuse uploads, and a config-only batch works there; malformed `Blob-Nonce` is `400`; sealed namespaces use the public long-poll rules; blobs from a local `source` need unrestricted `read`.

- **v0.61:** the checklist items of §6–§8 move to CONFORMANCE.md, with the rule that the text governs and ids are never reused; the spec keeps the prose and the §12 registries.

- **v0.62:** answers for the cases left open after v0.60:

  - **Errors:** `415` is `unsupported_type`; the branch-field `422`s are `invalid` with `errors`, checked before the `*`-key guard; `invalid` covers any namespace-document or prune refusal without another code; sending both `If-Match` and `If-None-Match` is `400`; a local branch's creation with `If-Match` alone is `428`; a tombstoned resource's append and delete `410`s carry `head`, as a create's does.

  - **Retries:** the verb check of an idempotent retry applies only to `PATCH` with `If-Match` and batch items like it, so retried creates, deletes, config writes and branch creations answer `200`.

  - **Encryption levels** are ordered in §2.1, where "sealed" means E2 only; raising a namespace above a dependent's level is `409 in_use`.

  - **Event streams:** the namespace stream works as the resource stream does (ids, `Last-Event-ID`, `since`), and ends at `purge-ns`; a stream's `410` or `404` is decided before any event, and a prune that reaches a replay page not yet sent ends the stream.

  - **Batches** return the new `config` id; a frozen batch answers `409 frozen` like a single write; each read of another namespace uses a grant that allows that read.

  - **Blobs:** a copy ignores its own `Content-Type` and `Blob-Nonce`; a malformed `{bid}` in an upload URL is `400` before the body is read.

  - **Purge and prune:** `?force=1` under a grant that can't force is `403`; a resource purge's `412` carries `{ head }`, before `in_use`; a prune writes an entry when the horizon or the `keep` set changes, never moves the horizon below the current one, and at E3 answers `422` with the `horizon` to resend for when it would prune to another revision than the one requested; `snapshot` outside E3 is `422`; a branch prune ignores `keep`.

  - **Namespaces:** a purged namespace can't be named as `successor`, and the `successor` check applies only to writes that set or change it; namespace purges are listed among what still works when frozen; after a namespace purge `/rev/{ns_id}` is served as before and `/bundle` is `410`; invariant 6 notes §7.5's exceptions.

- **v0.63:** answers for 183 issues found by sweeping §1–§5, §9–§13 and every addendum, and for a review of those answers. Settled open questions are removed. The choices:

  - **Force:** an addendum an implementation claims binds it unless marked non-normative, as H still is; A and B no longer are. Branches can be refused only by refusing local creation (`403`).

  - **Core:** malformed ids are `400`, and so are noncharacters (§3.1); grant rules run before namespace rules at step 6, for every item of a batch first; a sealed `ETag`'s `.{e}` is left out of write preconditions; log entries carry `via`; `origin` is in the core `GET /`; JSON request bodies other than `application/json` are `415`; a schema revision is referenced only through `$schema` and its schema's `$ref` closure; sealed namespaces with `read: "grant"` cache as private.

  - **Grants (C):** Biscuit v3 is the only encoding; blocks are validated strictly (`401`); a key's `can` bounds role verbs; `grantSize` and `rulesPerGrant` are deployment limits checked before step 1; `/grants/{gid}` serves the authority block first recorded with that id; public reads ignore grants except at `/principal` and `POST /keys`; operator grants are revoked by ending the key's period.

  - **Encryption (E):** which key, epoch and `pl` seal each payload, the HPKE settings, the `/keys` answer and the `keyring` shape are defined; levels never go down (`422`), and raising to `e2e` starts an epoch; sealed revisions and namespace documents get `ETag: "{id}.{e}"`; new readers get keys from the epoch in force at their grant's `nbf`, or only the current one without `nbf`; `keyring` entries are wrapped in HPKE auth mode by an admin key named in `from`, and writers seal only under keys from a `from` they trust; content from before an `e2e` raise keeps its E2 keys.

  - **Services (A, B):** re-placing a deleted placement is checked against the roles it had; private listing URLs sit under the cookie's path; facet counts are defined; `x-index` collects only strings, numbers and booleans; query and `children` cursors are positions in the result, never sealed values; a grant in `Authorization` reads listings only at its own `gs` or `all`; whole-response sealing only where whole-namespace readers alone may read.

  - **Branches and releases (F):** `successor` may name a branch up the old branch's base chain; automation merges only fast-forwards or approved batches; the superseded check counts only batches by `merge.authors` or a branch `*` key; a branch is `e2e` only over an `e2e` base; `cleanup` isn't copied into branches; the plan shape for plan digests is defined, with no other members, and each `source.at` the branch's `ns_id` before approval froze it.

  - **Federation (G):** a bundle's digest is over its bytes, and its lines must be canonical; no snapshot mode at E3; remote branches meet the local-branch rules on read mode and level; encrypted archives are sealed bundles per resource, wrapped only to a per-resource key the server holds and purge destroys; mirrored schema namespaces are at least as protected as their source, and E3 remote branches import schemas instead; a registration retry answers `200` only while the registration is unexpired; the `/bundle` endpoint is dropped.

  - **Files (H):** a gateway counts as a user's own only what it recorded writing for that user; a gateway on its own grant doesn't serve trees with tree-derived access, and elsewhere hides what each user's narrowed grant can't read; a raw save always counts as stored with the uploaded value; `MOVE` or `COPY` onto a folder is `403`; with authentication disabled a user is an `X-Author`.

- **v0.64:** brevity, with no change in behaviour: restatements become references, and rationale, extra examples and wordy phrasing go. The spec is about 15% shorter.

- **v0.65:** answers for the issues found by the first cold sweep. The choices:

  - **Schemas:** `$schema` is a string, a revision path or the 2020-12 dialect, in stored documents too; an unknown `format` or a `$id` is `invalid`; `$dynamicRef` is same-document only; `$ref`s resolve at the schema's write; older stored schemas compile as before. Patterns are RE2, `\uXXXX` read as `\x{XXXX}`.

  - **Gate:** a write without a precondition has all three candidate verbs, so authorisation precedes `428`; `*`-key guards run first at step 6; `413` only for refusals before or while reading; a create applies to `null`; a rule failure's `path` points at the rule form.

  - **Responses:** a purged resource is `410` only past the read check; `/heads` is `{ "heads", "next"? }`; a taken branch name's `412` has no `head` or `config`; a branch's `purge` entry targets its own view; a malformed batch `source`, or a write without `X-Author` while authentication is disabled, is `400`; `keep` must name served revisions; public dependents don't block raising a level.

  - **Copies and imports:** a public sealed namespace ranks `public` as a target, `sealed` as a source.

  - **Grants (C):** root blocks need `can` unless they list `roles`, and keys need `can` (stored ones without allow nothing); `maxTtl` and `requireAt` use the root's times; a key's `sub` must match whole; values that don't narrow are ignored, except `"*"`; `readScope: "resource"` covers roles; a qualifying role may test a fixed `/resource`.

  - **Encryption (E):** sealed payloads are never compressed (an E3 `zip` is `422`); E3 patch sets use `K_r`; after a raise from `sealed` to `e2e`, older content keeps the last epoch and `pad`, its blobs keep epoch URLs, and no log page spans the raise.

  - **Services (A, B):** `sort=-{path}` sorts descending, without range filters; catalog read grants carry the roles that make an item visible, and visibility tests key rules with that role; listings skip `/g/{gs}` only when their whole combined checkpoint is public.

  - **Branches (F):** `superseded` accepts a successor purged after the freeze, unless sealed; releases on one catalog base share one namespace and merge lock.

- **v0.66:** four rules that kept contradicting themselves are each stated once, with references elsewhere: write authorisation (§C.2, with effective roles, qualifying roles and unrestricted `read` in §2.1), protection when content moves between namespaces (**Protection**, §2.1), raising encryption levels (Addendum E, **Levels**) and tree-derived access (§B.11.2, §B.11.4, §B.11.5). With answers for the second cold sweep's issues. The choices:

  - **Authorisation:** only effective roles count, and roles are alternatives at step 1 too; `*` in a block's `can` makes a grant invalid (`401`); every sub-step of step 2 runs for every batch item first; a rate-limited dry run is `429`; the creating operator grant passes the `*`-key guard; "same principal" is the same root `sub` and `kid`; `readScope` covers every grant that can allow `read`; a role that counts for a base's unrestricted `read` passes all its rules against a `read` envelope; a batch item's patch set restores only right after a `"delete"` step.

  - **Protection:** a mirror is `grant` unless its source is `public`; an upstream namespace counts as a target; a merger without unrestricted `read` copies blobs, or uploads them where the ranks refuse a copy; a key holder may seal any source that isn't `e2e` into an `e2e` target, and an `e2e` source goes only to a same-named target even under an override; ranks apply only between namespaces.

  - **Levels:** a namespace document holding a member its level refuses is `422`, so a raise removes them in the same write, `"nonce": "required"` included; `/keys`'s `nbf` window counts a `batch` entry's config change, starts at the first epoch where the namespace wasn't yet sealed, and bounds bases' epochs in a branch too; grants from before a raise from `sealed` stay sealed; a branch serves a raised base's earlier content as the base does, with its E2 keys, from an `at` no earlier than the raise; an importer refuses history from before an `e2e` raise.

  - **Tree access:** roots and an empty `to` need `catalog-admins`; a hidden node answers as a missing one, except to `catalog-admins` organising, and a dangling placement is judged as if its item were live; a caller's `sub` is a subject only if it starts with `user:`; powers a folder without `$access` takes from its parents are judged per subject; a key's `can` and `sub` scope decide which roles count, and a `sub` scope puts the caller's `sub` in `gs`; a rename is a move to the current parents; no widening covers folders; at a folder without `$access` a role has the powers it has at all its parents; the catalog's per-node roles are **roles at a node**, and effective roles are only a grant's.

  - **Also:** a purge skips branches with nothing under the name; a branch at an `at` below the base's horizon answers `410` (`pruned`) on its first write; with no matching `retention` rule everything is kept; I.2's alphabet rejection uses a 33-character id; the rendering of §H.1 binds tools that claim Addendum H (§I.10).

- **v0.67:** answers for the fourth cold sweep's issues, outside its security clusters. The choices:

  - **Rules:** at E3 a rule fails whole only when its outcome depends on `writes` or `/doc`; shifting array elements also writes the array; a rule's `schema` asserts formats; `$ref` fragments are percent-decoded.

  - **Limits:** `rulesPerNamespace` counts role and key-scope rules; nesting depth counts the root; a value above a lowered maximum is held to it; `batchSize` counts only items.

  - **HTTP:** `/catalogs` needs a `*` key; a precondition other than one strong tag or `If-None-Match: *` is `400`; a dry run reports a passing item as `201`; `text/*` blobs are served as UTF-8.

  - **Caching:** namespace documents and `/heads` pages carry `ns:{ns}`.

  - **Purge:** a branch created at an `at` before a purge sees the name purged; a retention rule needs a `keep`.

  - **Access:** a folder is visible through a role whose rules don't refer to `/resource`; a visible node with only hidden parents is a root; a move into the node's own subtree is `403`; the janitor checks that every change was merged.

  - **Encryption:** after a raise from `sealed`, a prune snapshot of older history uses the epoch it is served under, and `/keys` omits, not refuses, pre-raise keys a grant wouldn't get.

  - **Files:** a copied folder takes the destination's name; `COPY` onto a file saves into it; a writer's own bytes get a weak `ETag`; only UTF-8 bodies get a `text/` type; expired records count as evicted.

- **v0.68:** each security cluster states its invariant where its rule lives (Protection in §2.1, grant scope in §C.2, Levels in Addendum E, tree-derived access in §B.11), and a regression list of scenarios now passes against all four. The choices:

  - **Protection:** copying or taking a blob out of a sealed namespace needs a grant whose key window covers the blob's epoch, within one namespace too (`404` otherwise); a rebase never replays into a less protected successor.

  - **Grant scope:** a root block whose `can` lists a verb outside its key's fails the key's scope, a key `can` of `*` counting as every verb; a test under `not`, `any` or `if` never fixes `/resource`.

  - **Levels:** readers check `pl` and `kid` in full, accepting a base's `ns` only for content read through; only branch creation and a raise to `e2e` are checked against the base, so a remote branch left below its source can still rotate, freeze and switch; an `e2e` import target is refused on any `keyring` conflict.

  - **Tree access:** a restore needs the role both in the rows kept at deletion and at the placement now; a non-admin Move starts with a `test` of `/parents`; a deleted explicit placement still beats `$parents`; creating under a hidden node's name is `409`, as a create on an existing resource is; copying a folder out of an embargo is an open question (§B.12).

  - **Also:** Addendum B names the **catalog service**, a tree service that also issues grants, apart from catalog namespaces.

- **v0.69:** answers for the final sweep's issues; the regression scenarios (now 136) all pass but one stated open question. The choices:

  - **Core:** `400` for non-I-JSON covers request bodies, and a malformed grant block stays `401` (§C.8); an empty `since` on the namespace log means from the start; a branch's blob URL serves the base's blobs that the branch's view references, as well as its own; a branch created after a purge sees the name as purged only where it would read it through; a schema path into a private branch answers `schema_unavailable`, as any path the writer can't read; a referrer-opened schema revision is served to a grant that may read the referrer; a gestures listing's `after` naming an entry the reader can't read is `404`; a dry run reports an item a submit would answer as a retry as `200`.

  - **Protection:** blobs from an `e2e` source raised from `sealed` need the caller's keys too; the successor of a sealed public branch is created with `read: "grant"`.

  - **Levels:** a remote branch MUST raise its level when its source does; derived views are sealed under the epoch of the revision they come from.

  - **Grants:** unrestricted `read` requires the `read` verb.

  - **Indexes:** a `fields` path is judged by the schemas of documents the reader may see, and each `score` is computed only from those documents.

  - **Tree access:** the §B.11 invariant is judged at the grant's decision, so restores and re-places work; Move grants expire within the catalog's `maxLag`; a Place over a self-placement is checked for widening.

  - **Also:** a rebased write is re-signed whenever its original was signed (§11).

- **v0.70:** answers for the closing sweep's issues; the 153 regression scenarios all pass but two, left to one stated open question. The choices:

  - **Core:** core servers need the prune-archive bundle format; blob uploads skip the I-JSON check; JSON `Content-Type`s compare as media types; an `ifNoneMatch` item can't start with `"delete"`; `retryAfter` waits for every bucket; `schemaReads.for` never matches a branch; a propagated purge writes `purge` entries only in the branches it reaches.

  - **Protection:** a schema from a sealed namespace resolves only with keys for its epoch; a remote branch's `origin` can't be its own.

  - **Levels:** each level is optional, and a remote branch whose source rises to one its server lacks answers `502`; a remote branch raises its dependents first, and takes pre-raise keys' start times only from its source's origin; an E3 branch relays its bases' keyrings as of `at`, even after writing its own; E3 readers fold past a patch set that doesn't apply.

  - **Indexes:** a query before the first checkpoint is `503`; `facet`, `counts` and `sort` paths are judged as `fields` are; a `min` that the URL's `at` doesn't cover but the current checkpoint does redirects there; a tool keeps a `min` until a listing is answered `200` after its redirect.

  - **Tree access:** public-URL listings are unfiltered; a gateway starts from `roots` where `root` is hidden; Restore checks `read` before `409`; a Place over a purged placement is `410`; Move and Unplace answers carry `head`; §B.12 also covers a move onto an existing file.

  - **Also:** signed-URL grants reach the origin as cookies; a remote branch inherits only §7.4's `read` and level refusals; a re-import tombstones only live upstream documents; merge signatures stay verifiable until the branch is purged.

- **v0.71:** answers to the closing sweep; the 165 regression scenarios all pass but two, left to one stated open question. The choices:

  - **Core:** invariant 3 excuses `$ref` closures too; server-written entries are one per resource and namespace; branches see their base's prunes; retries look only in the namespace written; an `ifNoneMatch` item starting with `"delete"` is `428`; a refused batch `source` answers as a single write; a taken name's `412` has no `config`.

  - **Protection:** a local `source` takes no blobs a remote branch answers `502` for; a referrer-opened schema read's grant verifies under the referrer namespace's keys, public or not.

  - **Levels:** such a remote branch's local branches answer `502` too; remote branches' config writes meet §7.4's `public` and `e2e` refusals against the source's current document; E3 prune snapshots' epoch follows the newest content revision; E3 readers fold invalid revisions, flagged.

  - **Grants:** a root block's revocation id is its grant id; branches heed only their local bases' keys and revocations; qualifying roles' rules run once if no name is fixed; `/principal`'s empty lists are `[]`.

  - **Indexes:** an unopenable pinned schema counts as absent; a `/_refs` `min` for a purged namespace redirects.

  - **Tree access:** no folder takes a name a `parents` entry names; a purged item's `410` follows the read check in Restore, and a Place's the `403`s.

  - **Also:** an upstream namespace takes one origin's imports; a sealed branch's authors go with its purge; E3 raw files keep type and size in `sealed`.

- **v0.72:** answers to the closing sweep; all 176 regression scenarios pass but two, left to one open question. The choices:

  - **Core:** `in_use` follows the `*`-key guard; a repeated `"delete"` fails at step 2.5; batch bodies are cut off at 4 × max(`batchSize`, `documentSize`); purged namespaces refuse batches as single writes; prune preconditions are `428`; `definitions` is `$defs`, `$recursive*` unknown.

  - **Protection:** remote branches keep their source's `nonce` requirement.

  - **Levels:** a remote branch's `502` resources refuse writes, purges excepted; E3 declared blobs have no nonce; pre-raise prune horizons keep stored sealings.

  - **Grants:** at E3, `/writes` rules fail whole; `/events` streams end once reads fail or credentials expire; consumers and bundles take only local bases' keys; operator key history and `created` times aren't hash-chained; mirrored schemas copy the source's `nonce` under the creating grant.

  - **Indexes:** hits go by `sort`, else `score`, ties by name; namespaces without keys are `404`.

  - **Tree access:** catalog merges are checked as the approver's; widening ones need `catalog-admins`; broken parents give no tree power; item-request summaries lead with a purged namespace's `410`.

  - **Also:** only gateways take weak `ETag`s in `If-Match` (§H.1).

  - **After v0.71's entry:** §10 and §C.3.1 take only local bases' keys; an unjudgeable remote-branch config write is refused as creation is; E3 snapshots' `kid` defaults to the epoch in force.

  - **After the re-check:** a blob upload sending a precondition is `428` at check 4, as a prune is; a batch body's `413` names `batchSize`; §1's `502` for a remote branch comes first at step 2.1, before the retry lookup; an admin's dry run of a widening catalog merge is judged with that admin as caller.

- **v0.73:** answers to the closing sweep; all 181 regression scenarios pass but two, left to one open question. The choices:

  - **Core:** a branch creation with `If-Match` alone is `428`, never a retry; long-poll's `live` and `cursor` take only their defined values (`400`); only E3 prunes refuse a lowered horizon; a retention rule that can't apply keeps everything.

  - **Protection:** a sealed upstream namespace's patch sets carry fresh nonces.

  - **Levels:** a purged resource leaves a remote branch's `502` set; with no `nbf`, an E3 branch relays no base epoch the base has moved past; an E3 merge leaves unmerged a kept head with a blob a `sealed` op can't declare.

  - **Grants:** verifying edges forward cookies, from which the origin authorises and ends streams; `grantSize` and `rulesPerGrant` apply to every request that doesn't ignore the grant; `POST /edge-grants` with no grant is `401`.

  - **Tree access:** a hidden item in `/read-grants` is `403`, as an unplaced one; organising grants fix parents by `href`, `order` the writer's; end-to-end catalogs get no merge grants (`not_offered`).

  - **Also:** a gateway `MOVE`'s stale `If-Match` is `412`; full-history lines are §7.1 log entries, tombstones included; a merge's pair report is the merger's dry run, not the server's.

  - **After v0.72's entry:** only gateways take weak `ETag`s in `If-Match`.

  - **After the re-check:** an end-to-end catalog's widening merges go under a `catalog-admins` grant without the service's dry run; a `keep` past `keepPerResource` is `422` `limit`, not `invalid`; §12's registries are regenerated from the body.
