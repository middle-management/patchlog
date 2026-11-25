# Patch Log — Specification

Status: draft v0.90 · 2026-11-24. See Changes at the end, and CHANGELOG.md for the full history.

**Scope.** This document is the protocol: what a server stores, checks and answers. The core (§1–§10, §12, §13) specifies, implementation-neutrally, identity, validation, rules, the HTTP API with its filtered reads, caching, deletion, namespaces, atomic batches and branches for collaboratively edited JSON documents. Its addenda cover:

- **Addendum C (recommended):** capabilities and access.

- **Addendum E (optional):** encryption at rest, sealed delivery and end-to-end.

- **Addendum G (optional, except for the hooks §1 lists):** federation and portability: the bundle format, which pruning also archives to (§8.6).

- **Addendum I (normative):** test vectors for the byte-exact definitions, the companions' included.

**Companions.** Two documents describe services and tools built on this protocol's public API. A server needs nothing from them but the hooks §1 lists under Conformance. The three documents share one numbering, so a reference names its document by its number or letter:

| Document | Sections |
|---|---|
| this document | §1–§10, §12, §13, Addenda C, E (but §E.2.6) and I, and of Addendum G: §G.1, §G.4.1 and §G.5–§G.7 |
| SERVICES.md | **Addendum A (suggested):** indexing. **§E.2.6:** how services seal derived views |
| TOOLS.md | **§11 (non-normative):** client behaviour. **Addendum F (suggested):** working with branches: merge, rebase, cleanup and releases. **§G.2 and §G.4.2–§G.4.4 (suggested):** external consumers, export and import. **Addendum H (suggested, non-normative):** files: how file tools, such as WebDAV gateways and mounts, store files, folders and names to share a namespace. **Addendum J (suggested, non-normative):** streams: a proxy that keeps an upstream's streamed response, and shared agent sessions |

**Labels.** A *recommended* addendum is needed by every deployment outside development. An *optional* one may be left out, and §1 says how a server without it answers. A *suggested* one is a design for a service or tool: it binds whatever claims to implement it, and a deployment may use another design. A *non-normative* one binds nothing.

**Reading this spec.** MUST, SHOULD and MAY are used as in RFC 2119.

- Elsewhere in §1–§10, §12 and, for whatever implements them, the addenda not marked non-normative, in the companions too:

  - a statement of what a server, service or tool does or answers ("a purged base is `410`") is a requirement as strong as MUST;

  - tables are normative where they give statuses, codes, limits or shapes.

- §1 before its Conformance subsection, §11, §13 and sections marked non-normative or as examples are informative. The exception is the rendering of §H.1, which binds tools that claim Addendum H (§I.10).

- Lowercase "must" states a condition a check tests ("the grant must allow the action"). When it fails, the answer is that check's.

- Terms in §2 and §2.1 are defined there.

- Drafts promise no compatibility with data written under an earlier draft: a deployment may refuse or discard such data, and MUST NOT serve it under less protection than this draft gives that namespace's content, or where that would otherwise break one of this draft's invariants.

---

## 1. Overview

A **resource** is an **append-only log of patch sets**, not a stored document. Each entry is a **revision** whose id hashes its parent id and its patches (§3.3). The document is *derived* by folding the patch sets from the first revision.

Validation is **opt-in per document**: a document with `$schema` validates against the immutable schema revision it names (§6.1); one without isn't. Schemas are resources too, and `$schema`, being content, is hashed into each revision.

Writes are compare-and-append on the head (`If-Match`): a stale writer gets `412`, rebases its patches onto the new revisions and retries (§11).

Everything addressed by a revision id is immutable and long-cacheable; only the **head pointer** (a micro-cached redirect) and the **event stream** change.

An atomic **batch** changes several resources of one namespace. A **branch** is a namespace created from another at a point in its history: it reads through that snapshot, records only its own changes, and can later be applied to the original as one batch.

Large values are **blobs**: immutable bytes attached to a resource, served from their own immutable URLs and referenced by id (§7.8).

### Goals

- Multi-user editing with no silent overwrites.

- Every revision with a `$schema` is valid against it. Full history, independently verifiable.

- Schema-less documents are equally first-class for storage, caching and collaboration.

- CDN-first reads: the origin serves little beyond head pointers and writes.

- Minimal moving parts.

### Non-goals (for now)

- Character-level real-time merging (OT/CRDT). Conflicts are resolved by rebase and retry, optionally guarded by JSON Patch `test` ops.

- Transactions across namespaces. A namespace is the unit of atomicity (§7.5).

### Conformance

- **A core server** implements §1–§10 and §12. The core refers to an addendum only for features a deployment offers; a server without one degrades as follows:

  - **Addendum C** (grants) is how the core authenticates (§6.2 step 1). A server running `"auth": "grants"` implements all of it.

    - Without it, authentication is disabled (`"auth": "disabled"`, §7), for development only (§7.2). Every request counts as holding a `*` key, so config guards, forced purges and the creation of namespaces are open, and config writes skip namespace rules as `*`-key writes do (§6.4.3). Resource writes are still checked.

    - Namespace entries written on a request then record `"grant": null` (§7.4). Grant references recorded earlier are still served.

    - While `disabled`, an entry with `grant: null` matches checks that match `merge.authors` (§F.3, §F.6) on its author's `sub` alone, and the janitor's `*`-key checks for `abandoned` and `superseded` accept it. Under `grants`, such entries count for no one.

    - Entries without `grant` at all (§7.4) count for no one.

  - **Addendum E** (encryption) and each of its levels are optional.

    - A server without it refuses `encryption` in namespace documents, and one without a level refuses that level (`422`, `invalid`). The core's rules for levels it lacks are then vacuous.

  - **Filtered reads** (§7.9) are optional: a server without them answers partial readers as §C.5 says.

  - **Branches** (§7.6), and so draft schemas in branches (§6.1), are core. A server can refuse to create branches: `branch` is then `403`, after verification (§C.2), and absent from `/principal`'s `can` (§7.4), and §6.1's draft lookup finds no candidate.

  - **The companions** (SERVICES.md, TOOLS.md) describe services and tools on the public API, and Addendum G federation. A core server needs from them only the hooks the core defines:

    - `source` in batches and `GET /`;

    - the bundles that pruning archives to (§8.6: §G.4.1, and §G.5.1.1 where encrypted);

    - their namespace-document members (§12.3).

- **A service or tool** conforms to the sections of the companions, or of Addendum G, that it claims.

- **Byte-exact definitions,** such as ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9), padding buckets (§E.2.2) and long-poll phases (§7.7), MUST agree between implementations. A conforming implementation reproduces the test vectors of Addendum I for each part it implements; some are still to come (§I.28).

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **Namespace** (`ns`) | A group of resources sharing a namespace log, itself versioned: its **namespace document** holds its configuration (rules, keys, limits). |
| **Config revision** | A revision of the namespace document, with its own content-addressed id. |
| **Resource** | A named, versioned JSON document inside a namespace, addressed `{ns}/{name}` (§3.6). |
| **Patch set** | An ordered array of JSON Patch operations (RFC 6902). |
| **Gesture** | The revisions one user action produced, possibly across several saves and resources of a namespace, grouped by an id the client chooses (§7.2), for undo and redo (§11.2). |
| **Blob** | Immutable bytes attached to a resource, stored and served apart from its documents, which refer to it with a blob reference (§7.8). |
| **Revision** | A resource log entry with patches (§7.1). |
| **Head** | The latest entry in a resource's log. |
| **Genesis** | The first revision of a resource created from nothing, with an empty parent. |
| **Foreign parent** | The parent of the first entry, in a branch, of a resource it reads through: the base's head for that resource at the branch point (§3.3, §7.6). |
| **Tombstone** | A log entry, without patches, marking the resource as deleted. |
| **Purge** | Irreversible, administrative removal of a resource's content. |
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
| **Role** | A named set of verbs and rules in the namespace document, which grants refer to by name (§C.1.1). |
| **Grant** | A signed, narrowable capability token presented with a request (Addendum C). |
| **Namespace consumer** | A separate client that derives data from a namespace log, such as a search index (§10). |

### 2.1 Defined terms

-
**Dependents** of a namespace: the namespaces whose `base` is this namespace and that aren't purged.

-
**Edge prefix.** The scope of an edge grant (§C.5): `/r/{ns}/{name}`, `/r/{ns}`, `/ns/{ns}` or `/ns/{ns}/view/{view}` (§7.9), with names valid under §3.6 and `view` an id in text form (§3.2). A prefix, like a service's prefix under its own root (§C.5.3), **covers** its own URL and everything below it, segment by segment, as RFC 6265 path matching does.

-
**Effective roles** of a grant that carries roles, one with a block that lists `roles`: the roles its root block lists that every narrowing block listing `roles` keeps and that the configuration in force defines (§C.1.1).

-
**Encryption level** of a namespace: its `encryption.level` (Addendum E), ranked none (no `encryption`) < `at-rest` < `sealed` < `e2e`. A **sealed** namespace is one at `sealed` (E2) only; one at `e2e` (E3) is **end-to-end**, from its creation or never (Addendum E, Levels), and the spec names both where it means both.

-
**Protection** of a namespace, for content moved between namespaces:

  - As a **source**, a namespace is `e2e` at E3, `sealed` at E2 whatever its `read`, and otherwise `public` or `private` by its `read`. A source whose protection isn't known, such as one missing from a bundle's `access` (§G.5.1), counts as `private`.

  - As a **target**, a namespace has the same protection, except that a sealed namespace whose `read` is `public` is `public`.

  - They rank `public` < `private` = `sealed` < `e2e`.

**Invariant:** moving content never makes it readable, in the clear or by key, to anyone who couldn't read it at its source. The exceptions are a caller who can read it there writing it itself, as a merge does (§F.3), and an operator overriding one import. Reading a sealed source takes keys that open the content (§E.2.3).

  -
Within that bound, a move the caller's grants allow works within a namespace, between equal ranks and upward, except that:

    - only a key holder seals content into `e2e`;

    - an import keeps an `e2e` source's lines under its own name (§G.5.1).

  -
These never move content into another namespace that ranks below its source:

    - a blob copy (§7.8);

    - a rebase's replay into its successor, which the rebasing tool refuses (§F.5);

    - an import, which the importer refuses unless an operator overrides it for that import (§G.5.1).

The server refuses the first; to it the other two are ordinary batches.

  -
Nothing else is ranked:

    - branches follow §7.4;

    - a batch's local `source` makes blobs available whatever the ranks (§7.8);

    - a writer may write what it can read wherever its grants allow, as merges do (§F.3).

  -
From a sealed source, public or not, a blob copy or a batch's local `source` takes only a blob that opens:

    - under an epoch it is served under there to the grant that reads the source, fixed as that grant's request for the blob would fix one (§E.2.2);

    - with keys §E.2.3 gives there to the request's own grant or one in `Source-Authorization` (§7.5).

A copy of any other is `404`, and a local `source` doesn't make it available (§7.8).

-
**Fixes `/resource`.** A grant's rules fix `/resource` when a rule of its blocks or its key's scope, at top level or nested only in `all`s, tests `/resource` against:

  - one name: `value`, or `compare` with `eq` and a literal; or

  - a finite set: a `schema` of only `enum`, or a `compare` with `in` and a literal array.

Where several rules fix it, the names are those that satisfy all of them. The grant doesn't fix `/resource` if its set of names is empty, or if any literal of a fixing rule isn't a valid name (§3.6), even one the intersection drops. A key with `readScope: "resource"` (§C.4) requires every grant it signs that can allow `read` (§C.2 item 2) to fix it.

-
**Qualifying role** (for edge grants, §C.5): an effective role that:

  - lists `read`;

  - has rules that refer to `/resource` only if the grant fixes it, and none that refer to `/doc`;

  - has rules that pass now against a `read` envelope (§6.4.1) for the grant's principal, with `/resource` set to each name the grant fixes, or, if it fixes none, once without `/resource`.

-
**Refers to.** A rule refers to every pointer at, above or below a path that it, or a rule nested in it, tests or compares, so a rule on the whole envelope (`""`) refers to every pointer; a `writes` rule refers to `/writes`. It **refers only to** pointers when each such path is at or below one of them.

-
**Referrer** of a schema revision, in a namespace `N` that sets `schemaReads` (§6.1): an unpurged resource of a namespace that `schemaReads.for` lists, `N` included, whose head, or last live document if it is tombstoned, reaches the revision through `$schema` and the `$ref` closure. Only that namespace's own resources count, not what a branch reads through, and a schema document's own `$ref`s don't make it a referrer, as for the refusals of §6.1.

-
**Unrestricted read** of a namespace: a grant has it when:

  - it may `read` there (§C.2 item 2);

  - its key has no `readScope`;

  - no rule in its blocks or its key's scope refers to `/resource` or `/doc`;

  - if it carries roles, at least one effective role that lists `read` has no rule referring to `/resource`, `/doc` or `/now`.

Where a request needs it, only such roles count for `read`. Branching checks it at gate step 1 (§C.2 item 2).

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

- The leading `1` is a **version prefix**, outside the base32 alphabet, meaning *SHA-256 truncated to 160 bits, base32*. A future format gets a new prefix, and old and new ids coexist.

- Ids (about 2⁸⁰ collision resistance) are **identifiers, not signatures**. Anything that needs cryptographic binding (author signatures, §C.3) uses the full digest.

### 3.3 Revision id

```
bytes(id) = trunc160( sha256( bytes(parent) ‖ 0x0A ‖ canonical(patches) ) )
```

- `bytes(parent)` is the parent's 20 bytes; for genesis, empty (zero bytes).

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

- The chain hashes **ids only, never content**.

- Config changes and resource pointers share **one** chain, which fixes the configuration in force for each write (invariant 6).

### 3.6 Names

- Namespace names MUST match `^[a-z0-9][a-z0-9_-]{0,63}$`.

- Resource names MUST match `^[a-z0-9][a-z0-9._-]{0,127}$`. None is empty, which keeps each `K_r` apart from `K_n` (§E.2.1).

- Hierarchy is data, such as a document's folder field (§H.2), never part of a name.

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

- **Append-only.** Entries are never modified or removed, except that purge (§8.3, §8.5) and pruning (§8.6) remove content, keeping ids and parent links.

- **Linear.** Each resource has exactly one first entry: a genesis, or in a branch an entry with a foreign parent (§7.6). Within a resource, every entry has at most one child: a head only moves to a child of the previous head. The same holds for each namespace chain and namespace document chain.

- **Valid.** For every non-tombstone revision `r`: if `d = fold(genesis … r)` has a `$schema`, then `d`, without the members §6.2 step 5 leaves out, validates against the schema at that (immutable) reference. Re-validating any revision later gives the same answer, unless that schema revision, or one in its `$ref` closure, was purged (§6.1, §8.3) or pruned without a kept document (§8.6), or the revision or a schema it reaches was written under an earlier draft (Reading this spec). At E3 readers check this, not the gate (§E.3.2).

- **Verifiable.** Anyone holding the entries can recompute every id and check every parent link. Below a pruning horizon, ids can be checked only against the archive, and the horizon's document is trusted as a snapshot (§8.6).

- **Ordered namespace log.** Every mutating request that takes effect (`create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `prune`, or a batch) writes exactly one entry in the chain of the namespace it addresses, atomically with the change it records.

  - An idempotent retry answered from the log (§7.2) writes nothing.

  - Entries the server writes itself, such as propagated purges (§8.3), are one per resource and namespace affected.

  - Creating a branch writes its `branch` entry in the base's chain, atomically with the first `config` entry of the branch's own chain.

  - A batch writes one `batch` entry for all of its changes.

  - Blob uploads and copies (§7.8) write no entry.

- **Configuration in force.** A write is checked against the namespace configuration (rules, keys, revocations, limits, and in a branch its bases' current keys and revocations, §C.4) at the head of the namespace chain **at the moment it is inserted**. That configuration is the namespace document recorded by the nearest `config` entry, or `batch` entry with a config change, before the write's own entry, or for a batch's items as §7.5 says. A namespace's creation, and a write to its document that changes what one of its own bounds limits, are held to the bounds of the document they produce (§6.6).

- **Fixed base.** A branch's `base` is set when it is created and never changes. Reads through a branch see the base exactly as of `at`, except that purges in the base propagate (§8.3) and the base's pruning applies (§8.6).

- **Referenced blobs.** Every blob that a stored document references is available to its resource (§7.8), and is kept as long as that document is. At E3 the server relies on the writers' declarations (§E.3.1), which readers verify.

---

## 5. Storage requirements

The core does not prescribe a storage engine. An implementation MUST:

- persist, for each entry:

  - its id, parent and kind

  - `canonical(patches)` (until purged or pruned) in a form it is recovered from exactly

  - its author and `via`, the grant reference (Addendum C) and a creation time

  - the `gesture`, `undoes` and author signature it was written with, if any (§7.2, §C.3)

- persist an author, its `via` and a creation time for each namespace log entry, and the grant reference (§C.3) of each entry written on a request, with the grant's non-bearer form (none of these are part of its hash)

- persist each blob per resource with its type and nonce, and its uploader while it is pending, know which revisions reference it, and remove it on purge, after pruning, and when it stays unreferenced (§7.8). Blob bytes may live outside the database.

- enforce invariants 2, 5 and 6 atomically, including under concurrent writers and multiple processes

- serve the document at **any** revision id that isn't purged, or pruned without a kept document (§8.3, §8.6); in an end-to-end namespace, for a resource other than `keyring`, only the sealed snapshot a prune stored, where §7.1 says. Materialised head and intermediate snapshots are strongly recommended.

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
**Opting in.** A document opts in with a top-level `$schema`, which MUST be a string (`422`, `schema_ref`).

-
**Accepted forms.** `$schema` MUST match exactly

```
^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$
```

(a schema revision path on this service), or be the dialect URL `https://json-schema.org/draft/2020-12/schema`, which marks the document itself as a schema, validated against that dialect's meta-schema. Anything else is `422` (`schema_ref`); nothing is normalised.

-
**`$id`.** A schema document MUST NOT use `$id` in any subschema, nor `$schema` in any but its root (`422`, `invalid`). Validators MUST be registered and looked up **only** by revision path.

-
**`$ref`.** `$dynamicRef` MUST be a same-document fragment (`422`, `schema_ref`). `$ref` inside a schema MAY be one (`#…`), or a schema revision path in the form above, optionally with a fragment. Nothing else is resolved.

  - A fragment is percent-decoded. One then empty or starting with `/` is a JSON Pointer (RFC 6901, section 6). Any other is a plain name, which an `$anchor` or `$dynamicAnchor` of the schema it reaches must define.

  - A schema document's own `$ref`s resolve when it is written (§6.2 step 5). A fragment naming nothing in the schema it reaches makes the schema invalid (`422`, `invalid`).

-
**Never into a branch.** `$schema` and `$ref` MUST NOT name a branch namespace (§7.6; `422`, `schema_ref`). A path naming a branch in which the writer can't read the revision is `schema_unavailable` (below), as for a namespace that doesn't exist.

-
**Schemas follow their documents.** A namespace `N` MAY set `"schemaReads": { "for": [ … ] }`, matched as `drafts.for` is (§7.4) but never against a branch; `N` itself always counts. A schema revision in `N` then:

  - resolves for a write to a listed namespace, or to a branch of one at any depth, whose document pins it through `$schema` or its `$ref` closure, without the `read` that resolving otherwise needs (below);

  - may be read by revision path when the grant names a listed namespace, verifies under that namespace's keys and allows a read there of a **referrer** of the revision (§2.1, §C.2), even where its `read` is `public`.

    - This holds even under a grant that doesn't name `N`, or doesn't verify or can't read the revision there (§7).

    - A referrer in a listed namespace that is public, and neither sealed nor end-to-end, counts for every request, ignoring any grant, as for public reads (§7).

    - A read under a grant carries it in `Authorization` (no edge cookie's path covers `N`).

    - An edge that knows only prefixes forwards such a read to the origin unrefused, which serves it `private`.

That is all it opens: never the schema resource's head, log or other revisions, a non-schema document, or a draft in a branch (§7.6).

  - Ids aren't secrets (§C.5): anyone who may write to a listed namespace can pin such a revision, so keep nothing in such schemas that only `N`'s readers may see.

  - It is `422` in sealed and end-to-end namespaces (Addendum E, Levels).

-
**Drafts in branches.** In a write **to a branch**, a path `/r/N/R/rev/X` that `N` can't resolve for the writer (`N` lacks it, or the writer can't read it there) is looked up in the branches of `N` (§F.9):

  - The candidates are the branches of `N`, at any depth, that aren't end-to-end, each counting only revisions it wrote itself.

  - A candidate serves a write if the namespace written, or one in its `base` chain, is the candidate or is listed in the candidate's own `drafts.for` (§7.4), which its branches don't inherit.

  - The writer needs `read` on `R` in the candidate, checked as for reading other namespaces (§7.5); a revision it can't read there counts as not found.

  - Any candidate holding `X` will do (§3.3), and the whole `$ref` closure resolves the same way.

  - In a namespace that isn't a branch, paths resolve only in `N`, so documents using drafts merge into it only after their schemas (§F.9). A merge into a base that is itself a branch, as for a stacked release, may still resolve drafts. At E3 this rests on the merging client (§F.8.1).

  - Validating clients and consumers try `N`, then a release document's branches (§F.9), then those `GET /ns/{N}/branches` lists, recursively, as a best effort: only the server's check decides whether a write is accepted.

-
**Within a batch,** items may reference schema revisions created by earlier items (§7.5).

-
**Tombstoned schema resources.** Revisions of a tombstoned schema resource still resolve (§8.1), for new references too.

-
**Purged or unknown references.** A reference is `422` (`schema_unavailable`), with `path` the revision path that didn't resolve, if it:

  - is unknown, purged, pruned without a kept document (§8.6) or unreadable by the writer; or

  - names a tombstone, a non-schema document, or a revision in an end-to-end namespace (§E.3).

-
**Referenced schema revisions.** A schema revision is **referenced** when any of these names it by `$schema` or reaches it through that schema's `$ref` closure:

  - the head, or last live document if tombstoned (§8.2), of any unpurged resource in the deployment;

  - the head as of `at` of a resource a branch reads through, or its last live document then if tombstoned;

  - any revision a branch wrote, not only its head.

-
**Copies.** A reference is satisfied by a copy of the revision whose document is neither purged nor pruned, held:

  - in `N`; or

  - for a document in a branch, in a branch it may resolve drafts in, judged structurally by the candidate rules above, never by any one writer's grants.

A revision pruned in `N` counts as one `N` can't resolve.

-
**Refusals.** Unless forced (below), a server MUST refuse (`409`, `in_use`):

  - a purge, of a resource or a namespace, that would remove the last copy satisfying a reference, in any namespace it reaches, branches it propagates to included (§8.3);

  - a config write that would leave a reference without a copy, such as narrowing `drafts.for`.

The answer lists, as `referencing`, the referencing namespaces in which the caller may read anything, judged as for reading other namespaces (§7.5): the first `logPageSize` in byte order of name, with `"more": true` where it may read others. `dependents` (§7.4, §8.5) list the dependents alike. At E3 the server can't see references (§E.3.2).

-
**Forcing.** A refused purge can be forced by `?force=1` on the purge request, under a grant chained to:

  - a deployment operator key; or

  - for a purge of a branch or of a resource in one, a `*` key of that branch, inherited or its own.

Under any other grant, `?force=1` is `403` at step 1 of §6.2, whether or not the purge needs it. A forced purge's entries carry `forced: true` (§3.5).

-
**Read permission.** Resolving a `$schema` or `$ref` requires the writer to have `read` on the copy it resolves to, in the schema's namespace or the branch holding a draft (Addendum C). Where `schemaReads` opens the revision for the write (above), none of this bullet applies.

  -
Where that isn't the namespace written, `read` is judged as for reading other namespaces (§7.5).

  -
From a sealed namespace, public or not, resolving also takes keys §E.2.3 gives there, in the namespace written too:

    - for the epoch the revision is served under, fixed as a read of it would fix one (§E.2.2);

    - to the request's own grant or one in `Source-Authorization` (§7.5, §2.1 Protection).

Without them the revision is unreadable by the writer.

-
**Validator cache.** Compiled validators MAY be cached by revision path, forever and across namespaces, drafts included (§3.3).

### 6.2 On write

The order of checks at the gate is normative.

- Only request-shape errors, which no state influences, may come before step 1. They do come there, as the request's own answer, never a batch item's: malformed names or URLs, content types, header and body syntax, and the size of what is read (`400`, `413`, `415`, and a grant's request-shape `401`s of §C.2 item 1).

- This holds unless an endpoint fixes its own order, as blob uploads do (§7.8).

- A batch body cut off as §7.5 says, by the verified principal's `batchSize`, is `413` once the grant is verified, before its verbs are checked. A malformed body read then is `400` at that point.

Everything else follows this order:

-
**Authenticate and authorise** the request (Addendum C): `401` or `403`, covering the verbs and the grant, key-scope and role rules that refer only to `/action`, `/resource`, `/principal` or `/now` (§C.2). Rate limits (§6.6) come last in this step, only for requests that passed its other checks or ran out of `validationSteps` in them: `429`, else that `422` (`limit`).

-
**Precondition** (§7.2), in this order:

  -
the idempotent-retry lookup (§7.2), with its verb check (§C.2 item 2). It doesn't apply:

    - to a purged resource, which answers `410` (§8.3)

    - in a purged namespace, where every write is `410` (`purged`) at this point (§8.5)

  -
for a `PATCH` with `If-Match` (in a batch, an item whose first step is a patch set under `ifMatch`), settle the verb from the resource's state as the writer sees it:

    - a tombstoned head makes it a restore, a live one an append, and a resource with no head an append

    - a purged resource answers `410`, whichever the verb

    - in a branch, the state is the branch's view (§7.6): a resource read through settles by the base's head as of `at`, and a tombstone there makes the first write a restore, with that tombstone as its foreign parent

A settled verb that isn't a candidate (§C.2 item 2) is `403` here, before the `If-Match` comparison, and counts as failing authorisation in §7.5's failure report and dry run. So does a write to a resource with a head as the writer sees it, a `DELETE`, create, purge or prune included, by a grant that may `read` but whose read rules don't allow reading that head (§C.2 item 5). No later step then judges or names a head it can't read. A grant may `read` here as a partial reader may (§7.9, first two conditions): §C.2 item 2 allows it, no block or key-scope rule refers to `/now` and, if it carries roles, an effective role that lists `read` has no such rule.

  -
author signatures (§C.3.1): `422` (`signature`).

  -
a frozen namespace: `409` (§8.4)

  -
in this order:

    - in a batch, a `"delete"` that follows a `"delete"`: `422` (§7.5)

    - the precondition itself: `412`, or `410` on a tombstoned resource (§7.2), then `428`

    - a purge or prune of a resource that never existed is then `404`, never `412` (§7.2, §8.6)

-
**Apply** the patches to the parent's document, `null` for a create, with operation validation. A failing `test`, or a create whose `writes` (§6.4.1) are empty, is `422`. A delete skips steps 3–5. In a namespace that requires nonces, a resource create, append or restore is then checked for a fresh `$nonce` (§C.7): `422 nonce`.

-
**Limits** (§6.6) and **blob references** (§7.8), after these checks, each `422` (`invalid`, or `limit` for a limit such as `keepPerResource`):

  - the namespace document a config write or a branch's creation results in is validated (§7.4)

  - a prune's `horizon`, `keep`, `snapshot` and, at E3, archive are checked (§8.6)

Every reference in the resulting document must be well-formed and name a blob available to the resource (`422`).

-
**Schema.** If the **resulting** document has `$schema`, resolve it (§6.1) and validate it against JSON Schema draft 2020-12, with format assertions for the formats it defines:

  - `hostname` by RFC 1123 alone

  - `idn-hostname` and `idn-email` by RFC 5891's registration rules, contextual rules included, without UTS 46 mapping. In both formats, an all-ASCII label is valid, but an R-LDH one only as an A-label. An R-LDH label is an A-label whatever its case: if, lowercased, it is `xn--` followed by the Punycode of a valid U-label, as `XN--BCHER-KVA` is.

A schema naming any other `format` is invalid, as an unknown keyword is (§6.5). The instance validated is the document without its top-level `$schema`, `$nonce` of the fresh form (§6.4.1) and `$successor` of the form of §8.1. A `$nonce` or `$successor` of any other form is validated as data. Failure is `422` with `{ pointer, message }` errors, and work past `validationSteps` is `422` (`limit`, §6.6).

-
**Rules.** The `*`-key guard (§C.2), then a config write's `in_use` refusals (§6.1, §7.4), then grant, key and role rules (§C.2 item 4), then namespace rules (§6.4), evaluated against the configuration in force (invariant 6).

-
**Hash and insert** atomically, together with the namespace entry.

For a batch (§7.5), each step, and each sub-step of steps 2 and 6, runs for **every item** before the next starts, and step 7 inserts all items in one atomic operation.

**End-to-end namespaces (§E.3).** For `create`, `append` and `restore` in an `e2e` namespace, of any resource but `keyring` (§E.3.2):

- Step 3 accepts a patch set of one reserved `sealed` op that passes the checks of §E.3.1, or `[]` for a restore, and doesn't apply it. Anything else is `422` (`invalid`).

- Step 4 checks the blobs the op declares (§E.3.1).

- Step 5 is skipped.

- Any namespace, grant, key or role rule is evaluated in strong Kleene logic with `writes` predicates and `/writes` and `/doc` paths unknown, for a restore with `[]` too. A rule that comes out unknown fails as a whole for these writes (`422` or `403`).

Config, branch and prune writes are checked as usual. So is a delete, except that, with its `doc` null, a rule whose outcome depends on a `/doc` path fails as a whole for it too.

### 6.3 Changing type

- **Adding** `$schema` to an untyped document is an ordinary patch; the whole document must validate.

- **Changing** `$schema` is an ordinary `replace /$schema`, usually with the migration's data changes in the same patch set; the result must validate against the new schema.

- **Removing** `$schema` makes the document untyped from that revision on; a rule can forbid this (§6.4.4).

- Tombstones are not validated, nor is the document a delete removes, which rules see as `/doc` (§6.4.1).

### 6.4 Namespace rules

Rules are write-time policy, stored in the namespace document as `rules: [...]`. With no rules, anything goes.

#### 6.4.1 Change envelope

For every write, the server builds:

```
{
  "action":    "create" | "append" | "restore" | "delete" | "purge" | "config" | "read" | "branch" | "purge-ns" | "prune",
  "resource":  "name",                         // absent for config and purge-ns; the new namespace's name for branch
  "principal": { "id": "…", "groups": [ … ], "roles": [ … ], "attrs": { … },
                 "via": [ … ], "grant": "1…" },  // absent when auth is disabled
  "now":       "2026-10-04T18:02:11.482Z",     // server time at the gate
  "writes":    [ "/title", "/blocks/3" ],      // normative, see below
  "doc":       { … },                          // the resulting document; for delete, the document deleted; null for purge and purge-ns; { horizon, keep? } for prune, as sent; for read, below
  "patches":   [ … ]                           // canonical patch set; [] when there is none
}
```

-
**`writes`** is computed by the server. For each operation:

  - `add`, `replace`, `remove`, `copy` write `path`

  - `move` writes **both** `from` and `path`

  - `test` writes nothing

  - A root operation, a genesis `add ""` included, writes `""`.

  - A delete's `writes` and `patches` are `[]`, so `within` (§6.4.2) restricts neither deleting nor a restore with `[]`: limit both by verb (§C.6) or by rules on `/doc`.

  - An array append `…/-` is recorded with the resulting index.

  - An `add`, `copy` or `move` into an array at an index below its length, and a `remove` or `move` of an element that isn't its last, also write the array itself, whose later elements they shift.

  - In resource envelopes only, an `add` or `replace` at exactly `/$nonce` whose value is 26 base32 characters (`^[a-z2-7]{26}$`, a fresh nonce, §C.7) is left out. Any other operation at or below `/$nonce` is a write as usual.

Pointers are compared **segment by segment after RFC 6901 unescaping**, never as strings.

-
**`doc`** is the document as it will be stored if the write succeeds, except:

  - For a delete, it is the document being deleted: the resource's last live document as the target namespace sees it, read through its bases in a branch (§7.6), or, in a batch, the document after the item's earlier steps. A replay of a delete (§F.3, §G.4.4) is judged against the document the target has at that step.

  - For `branch`, it is the new branch's namespace document, and the envelope is evaluated in the **base** namespace (§7.6).

  - In an end-to-end namespace, `doc` is null for `create`, `append`, `restore` and `delete` of every resource but `keyring` (§E.3.2; for rules on it, §6.2).

-
**Batches** produce one envelope per patch set, with the ordinary actions. There is no `batch` action.

-
**`principal`** comes from the grant (§C.1):

  - `groups` and `attrs`, an object of issuer-asserted attributes, from its root block;

  - `roles` as its effective roles (§2.1).

A member the grant gives no value for is empty: `attrs` is `{}`, and `groups`, `roles` and `via` are `[]`. `roles` is `[]` for a grant without roles too.

-
**`now`** is the server's clock at the gate, read once per request, RFC 3339 UTC with millisecond precision.

-
**`read`** envelopes, used only to evaluate grant and role rules on reads (§C.2, item 5), carry only `action`, `resource`, `principal` and `doc`; rules that refer to `/now` are judged as that item says. With no writes, a `writes` predicate `within` holds there, and `covers` and `overlaps` don't.

  - `doc` is the document of the revision the read concerns: the head for `GET /r/{ns}/{name}` and the resource's other URLs that name no revision; for a blob, each stored document that references it (§7.8), the read passing where one does, or the head where none does; that revision for `/rev/{id}`; each entry's revision for a log, a stream or the gestures listing; each row's head for `/heads`. For a tombstone, it is the document the tombstone deleted.

  - It is `null` for purge entries, where the read concerns no revision or one whose document is no longer stored (purged, or pruned and not kept, §8.6), and in an end-to-end namespace, whose content the server never sees. Wherever it is `null`, a rule that refers to `/doc` fails as a whole, as one on `/now` does, except in the read check for a purged resource's `410` (§8.3, §8.5), which sets such rules aside, `all`s flattened.

-
The envelope holds no previous state: rules judge the resulting document and the change itself, or for a delete the document it removes.

-
**What rule failures reveal.** A failing rule on `/doc` reveals something about the document, even a deleted one; namespaces that care grant `delete` only with `read`. A `403` at §6.2 step 2.2 shows a writer whether a name it can't read exists. A grant without `read` learns from steps 3–5 (a `test`, a schema error) about any document it may write.

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

- A `schema` is a JSON Schema draft 2020-12 fragment, applied with format assertions as at step 5 of §6.2. Like a schema document, it is held to §6.1's `$id` ban, §6.5 and §6.6's regular expressions. It has no `$schema` keyword in any subschema, and its `$ref` and `$dynamicRef` are same-document fragments only. If a `schema` breaks any of these, a namespace document is `422` (`invalid`), and a grant invalid (`401`).

- With no writes, `within` is true, and `covers` and `overlaps` are false.

- **Path policy MUST use the `writes` predicates**, never patterns over `/patches/*/path`.

- **`compare`** relates an envelope value to a literal (`value`) or another envelope value (`path`).

  - `lt`, `le`, `gt`, `ge` compare two numbers, or two RFC 3339 `date-time` strings as instants, at the full precision of their fractional seconds; one with a leap second (`:60`), a lowercase `t` or `z`, or a space for `T` is of an unsupported type.

  - `eq` is RFC 6902 equality. `in` is true when the left value equals an element of the right-hand array, and false when the right-hand side isn't an array.

  - A missing path on either side makes `compare` false, and so do operands of different or unsupported types for `lt`, `le`, `gt` and `ge`.

#### 6.4.3 Evaluation

- Rules run at step 6 of §6.2, in order, and all must pass.

- A failing namespace rule is `422` with `{ "code": "rule", "rule": <index>, "path": <pointer> }`, where `path` points at the failing rule form in the namespace document, descending only through the first failing member of an `all` or a `then`. A failing grant, key or role rule is `403` (`forbidden`).

- Rules apply **only at write time**, and at read time for grant, key and role rules. Changing them never invalidates existing history.

- **Config writes are rule-checked too,** by namespace rules, except for principals whose grant chains to a key with `can: ["*"]`, and for a namespace's creation under the operator grant that creates it.

- **Operator overrides.** A purge or namespace purge forced past an `in_use` refusal under a deployment operator grant (§6.1) isn't judged by namespace rules either. A purge forced with a `*` key of the branch, inherited or its own, is still judged, and so is any purge while authentication is disabled (§1).

- **Except as above, rules see every action,** including `delete`, `purge`, `config`, `branch` and `purge-ns` (`doc` as in §6.4.1). Rules on a document's shape should exempt `delete`, or a document written under earlier rules can't be deleted.

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

**The pattern for fields that policy depends on.** Protect such a field by forbidding writes to it (`writes overlaps`, which also catches root replaces and `move`), not by comparing values.

- Every create writes `""`, which overlaps every path, so such rules exempt `create` and test the created document instead.

- A delete writes nothing, so decide deletes by testing `/doc`.

- A restore with a root replace also writes `""`. Exempt it only where a test of the resulting document is enough on its own. Keep restores under the overlap rule for ownership fields, as the example does, or a non-owner could restore someone else's document with itself as owner.

**Guarding fields that read rules test.** A namespace whose read rules test `/doc` (§C.2 item 5, §7.9) should guard those fields, else anyone who may edit a document, even one it can't read, may move it into its own view or another's. It should also require nonces (§C.7), as a `hidden` entry's id confirms a guessed change. Here only `librarian`s move documents between folders:

```
{ "if":   [{ "not": { "op": "test", "path": "/principal/roles", "schema": { "contains": { "const": "librarian" } } } },
           { "op": "test", "path": "/action", "schema": { "enum": ["append", "restore"] } }],
  "then": [{ "not": { "op": "writes", "overlaps": "/folder" } }] }
```

### 6.5 Reserved keys and extension keywords

-
**Reserved keys.** Top-level document keys starting with `$`, other than `$schema`, are reserved for conventions. The core stores them as data and never interprets them, except that a fresh `$nonce` is left out of `writes` (§6.4.1) and can be required (§C.7), and a well-formed `$successor` is read into a deleted resource's `410` (§8.1). Validation leaves both out (§6.2 step 5). Namespace rules may constrain them.

-
**`$blob`** is reserved at any depth: an object whose `$blob` member is a string is a blob reference (§7.8), and must be well-formed (`422`). Schema documents and namespace documents aren't searched for references.

-
**`x-*` keywords.** Schema keywords starting with `x-` are annotations for namespace consumers (e.g. `x-index`, Addendum A), ignored by the core validator. Any other unknown keyword makes a schema invalid, `dependencies`, `$recursiveAnchor` and `$recursiveRef` included; `definitions` holds subschemas, as `$defs` does. In a schema document, a top-level `$nonce` or `$successor` that step 5 of §6.2 leaves out isn't a keyword: it is left out before the document is checked against its dialect and compiled.

-
**`x-ref`** marks a string that references another resource, for tools such as exporters (§G.4.2) and reverse-reference indexes (§A.4).

```
"hero":    { "type": "string", "x-ref": { "pinned": true } },   // "/r/media/photo-12/rev/1q…": exactly that revision
"related": { "type": "array", "items": { "type": "string", "x-ref": {} } },  // "/r/matches/cup": whatever is the head
"trigger": { "type": "string", "x-ref": { "key": "/triggers" } }            // "/r/doors/layout-7#t-42": one entry of layout-7
```

  -
Its value is `{ "pinned"?: boolean, "key"?: pointer }`. A pinned reference is a revision path in the form of §6.1, a live one a resource path `/r/{ns}/{name}`.

  -
**Entries inside a document.** With `key`, a reference names one entry of the target document: `/r/{ns}/{name}#{id}`, or pinned `/r/{ns}/{name}/rev/{rev}#{id}`. `key` is a JSON Pointer into the target document, to either an array of objects with a string `id` member or an object whose member names are the ids. `{id}`, percent-encoded as a URI fragment, is matched against those ids, never against array positions. A reference whose entry doesn't exist is dangling, like one to a missing resource.

  -
**Finding references** is a static walk, not annotation collection during validation. Walk each document, without the members validation leaves out (§6.2 step 5), together with its schema. At every instance location, consider every subschema that could apply:

    - through `$ref`, `properties`, `patternProperties`, `additionalProperties`, `items` and `prefixItems`;

    - through **every** branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`;

    - through any other keyword that applies a subschema.

A string at a location where any of them carries `x-ref` is a reference if it has the form above, even if that subschema didn't validate.

  -
The core doesn't check the form; a schema can, with `pattern`.

### 6.6 Limits

-
**Configurable limits.** Every namespace has limits, set in the namespace document under `limits` (§12.2: keys, defaults, value formats). Config writes, a batch's `config` change and a branch's `patches`:

  - are held to the patch-set and document limits (`patchSetSize`, `opsPerSet`, `documentSize`, `nestingDepth`, `valueSize`, `pathSize`) as resource writes are. A namespace's creation counts as a create under the deployment's defaults, and a branch's under its base's limits.

  - have their bodies cut off as a resource `PATCH`'s are.

-
**Exceeding a limit** is `413` where a request is refused before or while it is read (below, §7.5, §C.8), or where §7.8 says so, and `422` otherwise. The refusal has `code: "limit"`, `limit` naming its key and, for sizes and counts, `measured` and `max`.

  - Where the server stopped reading an oversized body, `measured` is a lower bound in body bytes.

  - Before step 1 of §6.2, `max` is the deployment's.

  - `measured` is:

    - for `pathSize` and `valueSize`, the first value found too long, quotes included;

    - for `branchesPerNamespace`, the base's live branches with the new or unfrozen one;

    - for `blobPending`, the pending bytes with this blob;

    - for `validationSteps`, the steps taken where validation stopped, a lower bound;

    - for a blob without `Content-Length`, `blobSize` + 1.

  - Durations and rates give `limit` alone.

  - For a limit on the resulting document (`documentSize`, `nestingDepth`, `valueSize`, `pathSize`, `blobsPerDocument`, `validationSteps`), `measured` is left out for a grant that can't read the resource.

  - Bodies of endpoints without a limit of their own (prune, `/keys`) are `400` (`bad_input`) above 1 MiB.

  - A resource `PATCH` body more than four times the larger of the deployment maximums of `patchSetSize` and `documentSize` is `413` before parsing, naming `documentSize` with the deployment maximum.

  - A batch body cut off as §7.5 says names `batchSize`, with the verified principal's as `max`.

  - Clients tolerate a refusal without `measured`.

-
**Whole documents.** These patch sets may be as large as `documentSize` instead of `patchSetSize`:

  - that of a create;

  - that of an append or restore whose first operation other than `test` is a root `replace` or `add` (§8.2), further operations allowed after it.

At E3 every create and restore gets that bound, and appends stay within `patchSetSize`. In a batch they still count toward `batchSize`. Every other patch set stays within `patchSetSize`.

-
**Values.** These writes are `422` (`code: "limit"`, `limit: "patchSetSize"`, `measured` the left side and `max` the `patchSetSize`) unless, in the configuration they result in, `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize`:

  - a namespace's creation, a branch's included;

  - a config write that changes `limits`, or `encryption` other than its `epoch`.

This keeps every string, sealed or not, replaceable by one ordinary append with a `test` of its old value (§11). In a namespace that configuration makes E3, the left side adds `36 B × blobsPerDocument`, for the declared blob list (§E.3.1). Larger values belong in blobs (§7.8).

-
**Validation work.** Each document a write produces, each step of a batch item counting alone, gets at most `validationSteps` steps for its validation (§6.2 step 5) and its envelope's rule `schema` tests (§6.4.2), those of step 1, a key scope's `attrs` schema (§C.4) and every candidate verb's included (§C.2 item 2). A write that produces none, such as a delete or a blob upload (§7.8), gets one such budget.

  - A step is one schema or subschema applied to one value, a `$ref` or `$dynamicRef` target counting as one. Only the unit is defined: validators that try subschemas differently count differently, so counts agree across implementations only approximately.

  - Running out of a write's budget is `422` (`limit`), even inside a rule whose own failure is `403`. At step 1 it answers only if no check there fails outright, after the rate limits. It then checks and draws, a token each, only the buckets keyed by its principal that the write would draw on (none for an exempt write): its principal's or allowance's and its per-resource ones, never the namespace's or `blobRate`.

  - Candidate verbs (§C.2 item 2) and roles (§C.2 item 4) share the budget: a run-out in judging any of them is the whole check's, even where another would pass. An upload stops at the first candidate that passes. An outright failure in another check, or in another step of a batch item, still answers first.

  - In a batch a run-out at step 1 counts as failing authorisation (§7.5), reported as `422` (`limit`). A batch whose step-1 failures are all run-outs draws its items' cost (Cost), less the namespace's tokens; one with an item that fails step 1 outright draws nothing for its items.

  - Each read request, exchange and key request a grant is presented for gets one budget, a long-poll one for its whole wait, shared by every check it makes, in every namespace and for every name it covers. So does each read check a write makes (§6.1, §7.5, §7.6), one `referencing` or `dependents` list's judgments counting as one, each check an event stream repeats (§7.3), and each revision judged for a filtered read (§7.9) or item a service filters by a grant (SERVICES §A.4). Running out there fails that whole request or check, with its usual refusal, or leaves the item out.

  - A paged read that runs out after its first entry ends its page there instead (§7.1), and a long-poll that shows none answers `204` (§7.9 Long-poll). A list (§6.1) ends there, without `more`.

  - No deployment leaves `validationSteps` unbounded.

-
**Rate limits** are token buckets, refilled at the rate and holding at most the burst, checked at the end of step 1 of §6.2.

  - **Buckets are keyed by the root `sub` and the key that signed the root block** (`kid`, §C.1), never by `via`, which any holder can set in a narrowing block. Every bucket but `exchangeRate`'s is also the namespace's own, so a key listed in two namespaces has buckets in each. Bucket scopes are in §12.2.

  - **Exceeding one** is `429` with `Retry-After`, `code: "rate"`, `limit` naming a bucket that was hit (a §6.6 key, `allowance` or `allowance.blobRate`), and `retryAfter`, the wait in seconds, as a decimal number, until every bucket it draws on holds a token. `Retry-After` is whole seconds, rounded up.

  - **Dry runs** (§7.5) draw tokens as the submit would.

  - **Cost.** A request is admitted while every bucket it draws on holds at least one token. Its cost is then deducted, even below zero, in one atomic step with the check across every instance sharing the store. A write never commits without its deduction, and a request refused after admission keeps it, whether in step 2 of §6.2 (`412`, `410`, `428`, `409 frozen`, a settled verb's `403`) or later, as does an idempotent retry (§7.2).

    - A batch costs one token per resource it touches from each per-resource bucket, and one token per item from the principal and namespace buckets. Its `config` change, if any, costs what a config write does, drawn once the change passes its own step 1, even where an item then fails step 1. One that fails after step 1, whose error then answers the batch (§7.5), is exempt only under a `*` key.

    - A blob upload (§7.8) costs one token from the per-resource, principal and namespace buckets, and its size from the principal's `blobRate` bucket.

    - Any other write that isn't exempt costs one token from the principal and namespace buckets of the namespace whose chain records it, the base's for a branch's creation. Of these, a resource write or a prune costs one from its per-resource bucket too. A `PATCH /ns/{ns}` creation's `412` under any but an operator grant, one chained to a `*` key included, costs one from that grant's principal bucket in `{ns}`.

  - **Exempt:** config writes under a `*` key, config writes whose `writes` are non-empty and all at `/frozen`, `/successor` or `/merged` and whose resulting document has `frozen: true`, purges, a namespace's creation under an operator grant, its `412` included (§7.4), and entries the server writes itself (§7.4).

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

  - That principal's writes and uploads (§7.8) draw on the allowance's own bucket instead of the principal and namespace buckets. An allowance also replaces a key scope's lower `rate`. Per-resource buckets still apply, at the namespace's `ratePerResource`.

  - Its batches may be as large as the allowance says, and the allowance may also set `blobRate` and `blobPending` for that principal.

  - Allowances never exceed the deployment maximums: `bucket` that of `ratePerNamespace`, and the rest those of their own limits. One set above them is `422` (`code: "limit"`, `limit` naming that maximum's limit). One stored before a maximum was lowered is held to it.

  - While authentication is disabled (§1) there is no `kid`, so buckets are keyed by the author, and an allowance matches the author's `sub` alone. Either way, the first matching entry whose `until` hasn't passed applies.

  - `until` (optional) is an absolute RFC 3339 time: the allowance applies only while `now` (§6.4.1) is before it, and is ignored afterwards. Allowances for an import or a release should set one.

-
**Deployment defaults and maximums.** A deployment sets a default (§12.2's unless it says otherwise) and a maximum for every limit, and a minimum for the retry window.

  - A namespace may set any value up to the maximum, except for limits marked deployment only in §12.2.

  - A write that sets a value above the maximum, or a retry window below the minimum, is `422` (`limit`).

  - A value stored before the maximum was lowered is held to it. A write that leaves a value or allowance unchanged doesn't set it.

  - A namespace's own bound, such as a lowered `rulesPerNamespace`, holds as invariant 6 says. It holds even for a write that lowers a count still over it: that write is refused.

-
**Regular expressions** in rules, grants, key scopes and schemas MUST be evaluated with RE2 syntax and semantics, reading:

  - `\uXXXX` as `\x{XXXX}`, but not after an escaped backslash (`\\u`) or inside `\Q…\E`;

  - a surrogate pair of such escapes as the one code point it encodes;

  - a lone surrogate, or a surrogate written `\x{…}`, as a pattern RE2 doesn't accept.

The `regex` format asserts the same syntax. A pattern RE2 doesn't accept makes a schema or config `422` (`invalid`) when written, and a grant that carries one invalid (`401`).

---

## 7. HTTP API

- **URLs.** Resource URL: `/r/{ns}/{name}`. Namespace URL: `/ns/{ns}`.

  - A path other than `/` is `400` (`bad_input`) if it has an empty segment (`//`, or a trailing `/`), a `.` or `..` segment, or any percent-escape.

  - An id not in text form (§3.2) is `400` (`bad_input`), a request-shape error (§6.2), in:

    - a URL;

    - a write's precondition other than `If-None-Match: *`, a config write's included;

    - `Last-Event-ID`;

    - a request field such as `ifMatch`. One inside a namespace document is a validation error instead (§7.4).

  - In `ETag`, `If-Match`, `If-None-Match` and `If-Range`, an id is a quoted strong entity tag. A write's precondition is one such tag or `If-None-Match: *`. `If-Match: *`, a weak tag or a list is `400` (`bad_input`).

  - At E2, a sealed revision's, namespace document's or blob's `ETag` adds `.{e}`, the epoch it is sealed under (§E.2.2), which a write's precondition leaves out. An E3 snapshot's doesn't (§7.1).

  - In `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Log-Next` and `Last-Event-ID`, an id is unquoted.

- **`GET /`** answers `{ "origin": "https://cms.example", "spec": "0.90", "auth": "grants" }`: the deployment's canonical origin (§C.3), the spec version it implements, as dotted decimal numbers compared component by component, and whether authentication is on (`grants`) or `disabled` (§1). Addendum C adds `jwks_uri` (§C.4). A client, peer or tool MUST NOT refuse a deployment on the version alone; endpoints show what is offered (`404 not_offered` for an optional one, a plain `404` from an older server).

- **Answers,** a service's too, may carry members this spec doesn't define, which clients ignore.

- **Query parameters.** An endpoint accepts only the query parameters this spec defines for it, each at most once unless defined as repeatable (in the core, only `prefix` of `DELETE /edge-grants`, §C.5.4), and flags such as `force` and `dry-run` only the value `1`. Anything else is `400` (`bad_input`, not cached), a request-shape error (§6.2). An edge that verifies signed-URL grants (§C.5) strips their parameters and forwards the grant as the cookie it stands for (§C.5.3), which the origin verifies as any cookie.

**Browsers.**

- A deployment serving browsers:

  - answers CORS preflights, cached per URL, with `PATCH`, `PUT`, `POST` and `DELETE` allowed

  - allows the headers `Authorization`, `If-Match`, `Source-Authorization`, `Signature`, `Content-Type`, `Gesture`, `Undoes`, `Blob-Nonce`, `Blob-From`, `X-Author`, `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range` and `Last-Event-ID`

  - exposes `ETag`, `Location`, `Repr-Digest`, `Retry-After`, `Content-Range`, `Gesture`, `Undoes`, `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Cursor` and `X-Log-Next`

  - sets `Access-Control-Max-Age`.

- Responses that vary by origin carry `Vary: Origin`. A deployment that allows every origin, and names no credentialed origins (§C.5.2), sends `Access-Control-Allow-Origin: *` and its exposed headers on every response, with or without `Origin`.

- Clients should read public namespaces without `Authorization`, to avoid preflights (§7.7).

- SSE in browsers uses edge-grant cookies (§C.5), which need `Access-Control-Allow-Credentials` and a named origin, or a streaming `fetch`.

**Private namespaces and existence.** Requests are answered in this order, which hides whether a namespace exists (private ones: Addendum C):

- **Reads of a public namespace**, other than `GET /ns/{ns}/principal` (§7.4), `POST /ns/{ns}/keys` (§E.2.3) and reads under a view prefix (§7.9), ignore any grant and answer exactly as unauthenticated ones, with content or `404`. Only these, and the schema revisions a public referrer opens (§6.1), answer unauthenticated requests with content or `404`.

- **The `ns` check.** With a grant, the server reads `ns` from its blocks before looking up any key. If a namespace isn't named in `ns` by every block that carries `ns` (the root block always does; `"*"` names every namespace), it answers `403` without being consulted, whether or not it exists. The exception is a schema revision it opens with `schemaReads` (§6.1).

- **Verification.** Only then is the grant verified against that namespace's keys, or the deployment operator keys when the root `kid` names one (§C.4). Without valid credentials the answer is `401`, alike for a namespace that doesn't exist and one whose `read` isn't `public`. The exception is a request for a schema revision a referrer opens to it (§6.1), which this step and the next never refuse.

- **Resources.** Without `read`, a resource that exists and one that doesn't both answer `404`. Off resource URLs, a read a verified grant doesn't allow is `403` (§C.2), even under a grant limited to some resources.

Writes, `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`, reads under a view prefix, and every request to a namespace that isn't public or doesn't exist, keep the `403` and `401` answers of steps 2 and 3. Namespace names are not secret (§E.4).

### 7.1 Reads

| Request | Response | Cache-Control (public namespace, §9) |
|---|---|---|
| `GET /r/{ns}/{name}` | `302` with `Location: /r/{ns}/{name}/rev/{head}` and `ETag: "{head}"` | head pointer |
| same, never existed | `404` | short |
| same, tombstoned | `410` with `{ "tombstone": id, "last": lastRevisionId, "successor"? }` and `ETag: "{tombstone}"` (§8.1) | head pointer |
| same, purged | `410` | long |
| `HEAD /r/{ns}/{name}` | as `GET`, no body | as `GET` |
| `GET /r/{ns}/{name}/rev/{id}` | `200` with the document at `id` (at E3, only a stored snapshot, below), `ETag: "{id}"` (`"{id}.{e}"` at E2, §7), `X-Revision: {id}`, and the headers and `304` below | immutable |
| same, `id` is a tombstone, below a horizon too | `410` with `{ "tombstone": id, "last": its parent }` | immutable |
| same, unknown `id` | `404` | short |
| same, purged | `410` | long |
| same, below the horizon, without a kept document (§8.6) | `410` with `{ "code": "pruned", "horizon": id, "archive"?: url }` | pruned |
| `GET /r/{ns}/{name}/blob/{bid}` | `200` with the blob, `206` for a range; `404` if pending or unknown, `410` if pruned or purged (§7.8). In sealed namespaces, `302` to `…/blob/{bid}/e/{e}` (§E.2.2) | immutable (a `404` as short, a `410` as pruned, or as long where the resource is purged; the `302` as a head pointer) |
| `GET /r/{ns}/{name}/raw`, `GET /r/{ns}/{name}/rev/{id}/raw` | for a **raw** document (§7.8): `302` to `…/blob/{bid}`. Unknown, pruned, purged and tombstoned ids and heads answer as the matching document URL does; a document that isn't raw is `404` (`not_found`). In sealed or end-to-end namespaces, `404` with `code: "not_offered"`, after the read check (§7.8), whatever the document URL would answer but a purge's `410` (§8.3, §8.5) | as the document URL it stands for (head pointer or immutable), for its `302` and both `404`s, with its tags |
| `GET /r/{ns}/{name}/blob/{bid}/e/{e}` | sealed namespaces only: `200` with the blob sealed under epoch `e`, `206` for a range of the sealed bytes; `404` for an epoch it isn't served under, or `410` where §E.2.2 says. In other namespaces, `404` with `code: "not_offered"`, after the resource's read check (§7.8) | immutable (the epoch `404` `no-store` and its `410` as pruned, §E.2.2; the `not_offered` `404` as short) |
| `GET /r/{ns}/{name}/rev/{id}/log?since={a}` | `200` with the entries after `a` (exclusive) up to `id` (inclusive), paged as below; `404` and `410` as below | immutable (a `404` as short, a `410` as pruned, or as long where the resource is purged) |

**`GET /r/{ns}/{name}/rev/{id}`.**

- In a namespace that is neither sealed nor end-to-end, the `200` also carries `Last-Modified`, the revision's `created` as an HTTP date (to the second). There, without content coding, it also carries `Repr-Digest` (RFC 9530) of the document, served as canonical JSON (§3.1).

- It honours `If-None-Match` with `304`. It honours `If-Modified-Since` with `304` when `If-None-Match` is absent and `Last-Modified` is sent. Elsewhere `If-Modified-Since` is ignored (RFC 9110, section 13.1.3).

- **End-to-end namespaces.** The server never folds a resource other than `keyring` (§E.3.2).

  - A client learns each namespace's level, a base's included, from its configuration, the current namespace document, or else `/keys`' `level` (§E.2.3), and keeps the highest it has learnt, since levels never go down (Addendum E).

  - It refuses a claim below the level it holds, or one it doesn't know while it holds any, and learns no level from either, nor from a level it doesn't know. A document read by id is no claim: it teaches no level and isn't refused for its level.

  - Before it has learnt a level, only its configuration protects it, a configured level it doesn't know counting as `e2e` unless the client refuses that configuration when it starts.

  - It holds for a branch at least the level it holds for any base in the branch's `base` chain (Levels). A reader of a sealed branch needn't read its bases' namespace documents: the branch seals all it serves under its own keys (§E.2.5).

  - While it holds `sealed` or `e2e` for any namespace, it reads a namespace's current document, and those of the bases it names, before it accepts that namespace's first plaintext `200`. It takes `base`, which never changes (invariant 7), from any document of the namespace, one it refuses or reads by id included. A document its grant may not read (`403`, `404`) teaches nothing, one served sealed (§E.2.2) teaches `sealed`, and any other failure fails the read.

  - This floor holds against honest or misconfigured servers and caches, not hostile ones, which can hide a `base`: against those, only a level configured for the branch itself holds.

  - A reader that holds `sealed` or `e2e` for the namespace refuses a `200` here that isn't `application/jose`, except, at `e2e`, one for `keyring`.

  - In an `e2e` namespace, for any other resource:

    - `200` is served only where a prune stored a sealed snapshot (§8.6): at the horizon, or, where the horizon is a tombstone, at the tombstone's parent, its last live revision (§E.3.1), which the tombstone's `410` names as `last`. In a branch this includes a base's stored snapshot, whatever the branch has written since (§7.6).

    - A stored snapshot is served until a purge or a later prune that moves the horizon, whatever is restored from an archive (§8.6).

    - The body is the snapshot's JWE, as `application/jose`.

    - Any other `id` that would be `200` is `404` with `code: "not_offered"`, after the read check, cached as short.

      - The body carries the resource's `horizon`, as the namespace sees it, where it has one, and `last`, the tombstone's parent, where that horizon is a tombstone.

      - Readers fold the log up to `id` (below) from the revision that `last`, or else `horizon`, names, or from genesis where neither is given.

**`GET /r/{ns}/{name}/rev/{id}/log?since={a}`.**

- An empty or omitted `since` means from genesis. `since={id}` is an empty range.

- If `id` is unknown, or `a` is neither `id` nor an ancestor of it, the answer is `404`.

- If any revision after `a`, up to `id`, has its patch set pruned and not restored from an archive, the answer is `410`, as for a revision below the horizon. `a` itself may lie below the horizon.

**Paging.** A log range longer than the log page size (§6.6), or whose patch sets exceed `logPageBytes`, answers its first page only: a page ends before an entry that would take it past either bound, but always holds one. Pages are oldest first, with the header `X-Log-Next: {id}`: the last entry returned, the `since` of the next page, a range up to the same `id`. A client reads pages until the last entry it received, or the `since` of an empty range, is the URL's `id`; a missing `X-Log-Next` before that is an error.

- A page that reaches the URL's `id` needs no `X-Log-Next`. Every page is a correct prefix of its range. Filtered ranges (§7.9) may hold empty pages, and end as that section says.

- `404` and `410` are judged over the URL's whole range.

- The sealed snapshot of an E3 prune (§8.6) is served at a revision URL (above), never as a log entry.

- **Continuations.** Log ranges continue at `X-Log-Next` (the next `since`), `/heads` at its body's `next` (the next `after`), the gestures listing at `X-Log-Next` (the next `after`); a client passes the value back exactly as given.

- Long-poll answers (§7.7) use the same page limits but carry no `X-Log-Next`.

- Sealed pages (§E.2.2) carry their own bounds.

Log entry shape (patches in canonical form):

```
{ "id": "…", "parent": "…", "kind": "rev", "patches": [ … ], "author": "…", "via"?: [ … ], "created": "…", "grant"?: { "id", "sub", "kid" }, "signature"?: "…", "gesture"?: "…", "undoes"?: "…" }
{ "id": "…", "parent": "…", "kind": "tombstone", "author": "…", "via"?: [ … ], "created": "…", "grant"?: { "id", "sub", "kid" }, "signature"?: "…", "gesture"?: "…", "undoes"?: "…" }
```

A genesis's `parent` is `""`. `created` is the entry's creation time (§5), here and in namespace entries (§7.4), in RFC 3339 UTC with millisecond precision. `via` lists the grant's delegatees in order (§C.1), absent when there are none. `grant` is absent where none was recorded, including writes made while authentication was disabled, whose namespace entries say `"grant": null` (§7.4). All cursors are ids. Internal sequence numbers are never exposed.

### 7.2 Writes

Writes are **never** unconditional: a write without a precondition is `428`, and one with both `If-Match` and `If-None-Match` is `400` (`bad_input`), a request-shape error (§6.2). Pruning and blob uploads take none, and one sent is `428` where §8.6 and §7.8 say. Checks run in the order of §6.2, so **authorisation always comes before the precondition** (§6.2 step 2.2), and an unauthorised caller never learns whether its precondition matched or sees the head.

| Request | Precondition | Success | Failure |
|---|---|---|---|
| **Create:** `PATCH /r/{ns}/{name}`, `Content-Type: application/json-patch+json` | `If-None-Match: *` | `201` with `Location: …/rev/{id}` and `ETag: "{id}"` | `412` if the resource is live (body `{ head }`) · `410` (`gone`) if it is tombstoned, with `head` the tombstone (§8.1) · `422` · `410` if purged |
| **Append:** `PATCH /r/{ns}/{name}` | `If-Match: "{parent}"` | `201` with `Location` and `ETag` | `412` + `{ head }` if parent ≠ head · `422` · `410` (`gone`, with `head`) if tombstoned and `parent` ≠ tombstone · `403` if tombstoned and the grant can't restore (§6.2) · `410` if purged |
| **Restore:** `PATCH` on a tombstoned resource | `If-Match: "{tombstone}"` | `201`; the patches apply to the last live document (§8.2) | as for append |
| **Delete:** `DELETE /r/{ns}/{name}` | `If-Match: "{head}"` | `200` + `{ tombstone }` | `412` + `{ head }` · `410` (`gone`, with `head`) if already tombstoned |
| **Purge:** `POST /r/{ns}/{name}/purge` | `If-Match: "{head or tombstone}"` | `204` | `412` + `{ head }` · `404` for a resource that never existed, after a `428` · `409 in_use` (§6.1), after the precondition (§8.5) |
| **Upload a blob:** `PUT /r/{ns}/{name}/blob/{bid}` (§7.8) | none | `201` with `ETag: "{bid}"` | `400`, `401`, `403`, `404`, `409 frozen`, `410`, `413`, `415`, `422`, `428` and `429`, in the order of §7.8 |

-
**Content types.** A resource `PATCH` with any `Content-Type` other than `application/json-patch+json`, or none, is `415`, a request-shape error (§6.2), as is any other JSON body not sent as `application/json`. A JSON body's `Content-Type` is compared as a media type (RFC 9110, section 8.3.1), ignoring case and a `charset` parameter naming UTF-8; any other parameter is `415`.

-
**Authorization:** `Authorization: Bearer <grant>` (Addendum C). With authentication disabled, `X-Author` names the author; a write without it is `400` (`bad_input`).

-
**Author** is the verified principal id. `via` (Addendum C) is recorded with it.

-
**Gestures.** A write MAY carry `Gesture: <id>`, naming the user action it belongs to, and `Undoes: <id>`, naming the gesture it undoes (§11.2). Both are 26 base32 characters (`^[a-z2-7]{26}$`, 128 random bits the client chooses when the action starts), otherwise `400`.

  - They are stored as metadata, like the author: not part of the id (§3.3), and not seen by rules.

  - The id is the writer's own label, never verified (§11.2).

  - An idempotent retry answers with the entry as first recorded, whatever the retry carries, with the recorded `Gesture` and `Undoes` as headers.

  - A namespace-document write (§7.4) carries them the same way; a batch's `config` change carries none (§7.5).

-
**Idempotent retry.** Suppose the precondition fails, but the log already holds the entry this request would have produced **with that parent**:

  - for an append or restore, the revision id of §3.3 with `If-Match` as parent

  - for a create, the genesis id of §3.3 with an empty parent

  - for `DELETE`, the tombstone id of §3.4

The server then responds `200`, answered as its write was (`Location` and `ETag`, or `{ tombstone }`), instead of `412` (or a `410` on a tombstoned resource, or `409 frozen`), if both hold:

  - that entry was written by the **same principal**, the same root `sub` and `kid` (§6.6). While authentication is disabled, that is the same author. Under `grants`, an entry without a recorded grant matches no one (§1).

  - the retry passes the verb check of §C.2 item 2.

The lookup covers the resource's whole log in the namespace written. It doesn't cover entries a branch reads through (§7.6), nor a purged resource, whose answer is `410` (§6.2). Within the retry window (§6.6, §8.6) it always works.

-
**Frozen namespaces** refuse writes with `409` (`frozen`) as §8.4 says.

-
**Namespace revision.** Every successful write that records a namespace entry (invariant 5), purges and namespace purges included on their `204`, answers with `X-Namespace-Revision: {ns_id}`, that entry. An idempotent retry carries the entry that recorded the original write, a batch's included. Blob uploads and copies, a prune that changes nothing and a dry run write no entry and carry none.

-
**Caching.** Write responses are `Cache-Control: no-store`.

### 7.3 Events (Server-Sent Events)

`GET /r/{ns}/{name}/events?since={id}`, and `GET /ns/{ns}/events?since={ns_id}` for the namespace log. `Last-Event-ID` is also accepted, and wins over `since`. Without either, or with an empty `since`, the stream replays from genesis (§7.1), and for a resource with no entries yet it waits for the first.

-
The stream first replays entries after `since`, one log page (§7.1) per fetch, then streams live ones. Replay is judged as its log range is (§7.1), before any event is sent. A prune that reaches a page not yet sent ends the stream.

-
A resource stream's event types are:

  - `revision` and `tombstone`, whose data is the resource log entry (§7.1) and whose SSE `id:` field is its id

  - `purge` and `prune`, whose data is the namespace entry that records them (§7.4) without its `id` and `prev`, and which carry no `id:` field

A resource stream ends after its `purge` event. A namespace purge sends no `purge` event (§8.5): it ends the resource's streams. Replay carries only `revision` and `tombstone` events.

-
A namespace stream's events are its log entries as §7.4 serves them, with each entry's `id` as the `id:` field. It ends after its `purge-ns` event, or without it where log ranges are sealed (§8.5).

-
Responses are `Cache-Control: no-store`, and require `read`, unrestricted for a namespace stream (§2.1) except as §7.9 allows.

-
The stream repeats that read check before each log page it fetches (§7.1), replayed or live, and each keep-alive it sends, as for a request made then. It ends if the check fails.

-
It also ends, at the latest, when the grant or cookie it was admitted under expires (§C.2, §C.5.3).

### 7.4 Namespace

| Request | Response | Cache-Control |
|---|---|---|
| `GET /ns?after={name}` | `200` with `{ "namespaces": [ … ], "next"? }`, a page of the namespaces the API can address, for operators only, as below | `no-store` |
| `GET /ns/{ns}` | `302` with `Location: /ns/{ns}/rev/{ns_id}`, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}` | head pointer |
| `GET /ns/{ns}/rev/{ns_id}` | `200` with the namespace document in force at that point in the chain, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}`. An `ns_id` not in the chain is `404` here, and at its `/log` and `/heads` | immutable (a `404` as short) |
| `GET /ns/{ns}/rev/{ns_id}/log?since={a}` | `200` with an array of entries, shaped as below, following §3.5. `404` if `a` is neither `ns_id` nor earlier in its chain. Paged as in §7.1 | immutable |
| `GET /ns/{ns}/rev/{ns_id}/heads?after={name}` | `200` with `{ "heads": [ … ], "next"? }`, a page of `{ resource, kind, target, created?, size?, digest? }`, one per resource as of that revision, as below | immutable |
| `GET /ns/{ns}/events?since={ns_id}` | SSE of namespace entries (§7.3) | `no-store` |
| `GET /ns/{ns}/principal` | `200` describing the grant in `Authorization` here, with `X-Config-Revision`; body and checks below | `no-store` |
| `GET /ns/{ns}/gestures/{gesture}` | `400` or `404` as below; otherwise `200` with `[{ resource, id, kind, gesture?, undoes?, author, ns_id }]` | `no-store` |
| `GET /ns/{ns}/grants/{gid}` | `200` with `{ id, root, stored }`, served as §C.3.1 says | immutable (`private` at E3) |
| `GET /ns/{ns}/branches?after={name}` | `200` with `{ "branches": [ … ], "next"? }`, a page of `{ name, at, frozen, purged, successor?, drafts? }` for the namespace's direct branches, as below. Requires unrestricted `read` (§2.1) | head pointer |

**`GET /ns?after={name}`.** For operators and admin tools.

-
It answers operator grants only (§C.4), checked in this order:

  - the request-shape checks of §C.2 item 1;

  - a grant whose blocks that carry `ns` don't all name `"*"` is `403`;

  - a grant that fails verification is `401`, as is one whose root `kid` names no operator key in its period, and a request without credentials, but one its operator key's scope doesn't allow is `403` (§C.2 item 1);

  - a grant that carries roles, or has a block that carries `can` without `config` or carries non-empty `rules`, is `403`.

While authentication is disabled (§1), it answers everyone.

-
Each row is `{ name, created, base?, frozen, purged }`.

  - `created` is that of the entry that created the namespace: the base's `branch` entry for a branch, otherwise its chain's first.

  - `base` is the namespace document's (§7.6).

  - `frozen` is as in §8.4, and `purged` whether it is purged (§8.5).

-
Rows are in ascending byte order of name, strictly after `after`, a plain bound, and paged by `logPageSize`. `next` is for the following page, absent on the last.

-
With `prefix`, a namespace name, only names that start with it are listed. Any other `prefix` is `400` (`bad_input`), a request-shape error (§6.2).

-
It is `Cache-Control: no-store`.

**`GET /ns/{ns}/branches?after={name}`.** Rows are in ascending byte order of name, strictly after `after`, a plain bound, and paged by `logPageSize`. `next` is for the following page, absent on the last.

**`GET /ns/{ns}/rev/{ns_id}/log?since={a}`.**

- Each entry is `{ id, prev, kind, resource?, name?, at?, target?, schema?, entries?, source?, forced?, author, via?, grant?, gesture?, undoes?, gestures?, created }`. `prev` is the previous entry's id, `""` on the chain's first.

- `schema`, on a `head` entry, a batch's included, is the `$schema` of its revision's document (§6.1), absent where it has none and at E3. It is recorded when the entry is written, kept through pruning and purge, and not hashed, in a batch's `entries` either (§3.5), so it is a hint: a consumer that verifies what it fetches (§10, §G.2) checks it against the revision before relying on it. Entries written before the server recorded it lack it.

- `gesture` and `undoes` are those of a single write. `gestures` maps each resource of a batch to a list of `{ "gesture"?, "undoes"? }`, one per step (§7.2). None of them is hashed.

- `grant` is `{ "id", "sub", "kid" }`: the grant id (§C.3) in text form, and its root `sub` and `kid`.

  - A branch's creation records the creator's grant on both its entries, and a namespace's genesis the operator's.

  - `grant` and `via` are absent from entries the server writes itself (propagated and followed purges, §8.3, §G.1, its own prunes, §8.6, and its own rotations, §E.2.1).

  - `grant` is `null` on other entries written while authentication is disabled.

  - How these count in `merge.authors` and claim checks (§F.3, §F.6) is §1's.

- An empty or omitted `since` means from the chain's first entry.

**`GET /ns/{ns}/rev/{ns_id}/heads?after={name}`.**

- Each row's `kind` and `target` are those of the resource's latest `head`, `tombstone` or `purge` entry (§3.5). For one purged since (§8.3), `kind` is `purge`, with that `target`.

- Rows include resources a branch reads through.

- Rows are in ascending byte order of name, strictly after `after`, a plain bound that needn't name an existing resource. `next` is for the following page, absent on the last.

- With `prefix`, only names that start with it are listed. `prefix` must be a resource name (§3.6); otherwise the answer is `400` (`bad_input`), a request-shape error (§6.2).

- `created`, `size` and `digest`:

  - In a namespace that is neither sealed nor end-to-end, judged by the namespace serving the page, `created` is the target entry's. There, for a live head of a resource that isn't purged, `size` is the length of its canonical document in bytes, and `digest` the `Repr-Digest` value of it uncoded (`sha-256=:…:`).

  - At E2 and E3, all three are absent.

  - All three are optional, and readers MUST NOT rely on them.

- Pages carry the tag `heads:{ns}` (§8.3).

**`GET /ns/{ns}/principal`.** The body is `{ "principal", "kid", "key", "operator", "can", "roles", "writer": { "frozen": bool, "successor"?, "nonce": "optional" | "required", "signatures": "optional" | "required", "level"?: "at-rest" | "sealed" | "e2e", "limits" } }`.

- `principal` is that of §6.4.1.

- `kid` names the key that verified the root block. `key` is the RFC 7638 SHA-256 thumbprint, base64url without padding, of the key as a JWK: `{"crv":"Ed25519","kty":"OKP","x":<pub>}` for a namespace key, the published JWK for an operator key.

- `operator` is true for an operator grant (§C.4), whose `can` is its blocks' verbs and `roles` `[]`.

- Otherwise:

  - `can` is the verbs its blocks and key allow; where it carries roles, only those an effective role lists.

  - `roles` is its effective roles only, each exactly `{ "name", "can", "rules" }` as the configuration of `X-Config-Revision` defines it (`rules` `[]` if none). So a grant an issuer made (§C.5.1) shows what it may do.

- In `writer`:

  - `nonce` is `required` where the namespace document requires nonces or the namespace is sealed at E2, otherwise `optional`.

  - `level` is absent without `encryption`.

  - `limits` gives every §6.6 limit in force, at the namespace's value or else the deployment's default, deployment-only ones at the deployment's values, without allowances or a key scope's `rate`.

- Only the `ns` check (§7, `403`) and verification (§C.2 item 1, key scope included) apply, with no verb check and no rule (§C.5). Without a usable grant the answer is `401`, even in a public namespace.

- While authentication is disabled (§1), it answers `200` without `principal`, `kid` and `key`, with `operator: false`, `can` every verb the server allows and `roles` `[]`. For a namespace that doesn't exist it then answers `404`.

- It draws no rate token.

**`GET /ns/{ns}/gestures/{gesture}`.**

- If `{gesture}` isn't of the form of §7.2, or `after` isn't of the form below, the answer is `400` (`bad_input`), a request-shape error (§6.2).

- Otherwise the endpoint is optional, and not offered in sealed or end-to-end namespaces. Where not offered, it answers `404` with `code: "not_offered"`, after the `read` check.

- The `200` has one row per revision or tombstone written with that gesture or undoing it, oldest first, leaving out purged resources.

- It is paged by `logPageSize`:

  - A full page carries `X-Log-Next: {resource}/{id}` (its last row).

  - The next page is `?after=` that value.

  - An `after` that names no row this listing would give the caller is `404`.

  - A page without `X-Log-Next` is the last.

- It answers any reader, and `403` to a grant that may `read` nothing there (§C.2 items 2 and 5), listing only revisions its grant may read (§C.2 item 5).

**Namespace writes.** The namespace document is edited like a resource, with a JSON Patch on its own URL:

| Request | Precondition | Success | Failure |
|---|---|---|---|
| `PATCH /ns/{ns}`, `Content-Type: application/json-patch+json` | `If-Match: "{config_id}"` (the value of `X-Config-Revision`, quoted), or `If-None-Match: *` to create | `201` with `X-Config-Revision: {new config_id}`, `X-Namespace-Revision: {ns_id}` and `Location: /ns/{ns}/rev/{ns_id}`, the namespace entry the write produced, and body `{ "config": new config_id, "ns_id" }`. An idempotent retry (§7.2) answers `200` with the same headers and body; when a batch wrote the config change, `ns_id` is the batch's entry | `412` + `{ config }`, without `config` for a creation under a taken name · `422` · `428` · `401`/`403` |

- **`If-Match` takes the config id,** not the `ETag`.

- **Envelope.** Config writes are checked with a `config` envelope (§6.4.1). Key-scope and grant rules apply to them.

- **Keys, roles, revocations, limits and exposure.** Writes covering or overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption`, `/signatures`, `/nonce` or `/schemaReads`, and writes that set `read` to `public`, need a `*` key (§C.2).

- **Validation.** The namespace document is validated against the built-in namespace-document schema of the deployment's version. Rules and patterns must be well-formed and within limits. The members this spec defines are validated strictly:

  - **Members.** Those of the core and of Addendum F are listed in §12.3 with their shapes.

  - **`x-` members.** Any other top-level member must start with `x-` (case-sensitive) and is stored as data. So may members inside the addenda's objects (§12.3). Role entries are open: the core reads `can` and `rules` and ignores the rest, for consumers (§C.1.1). Other nested objects, such as key entries, are strict.

  - **Errors.** Anything else is `422` with `code: "invalid"` and `errors: [{ "pointer", "message" }]`.

  - **Versions.** A tool that reads another deployment's namespace documents ignores members it doesn't define. A tool that copies a document into a namespace refuses one that holds such a member, unless it starts with `x-`, as a config write does.

- **Content types.** Other `PATCH` content types are `415`.

- **Logging.** A config change appends a `config` entry to the namespace chain. Namespace events use the entry's `kind` (§3.5) as their event type.

- **Branch fields.** Their `422`s are validation errors (`invalid`, with `errors`, above).

  - Only a branch's creation sets `base` (§7.6), which never changes (`422`).

  - A config write to a branch MUST NOT remove or change a key entry with the `kid` and `pub` of a `*` key in one of its bases (`422`, §7.6).

  - `frozen` and `successor` have the meaning of §8.4, in any namespace. A namespace's creation other than a branch's can't set `successor` (`422`).

  - A write that sets or changes `successor` MUST name another namespace that exists and isn't purged (`422`):

    - for a branch, a branch of the same base or of a namespace further up this branch's `base` chain, at any `at` (§F.4, §F.5)

    - for a namespace that isn't a branch, one that isn't a branch

  - A branch of a namespace whose `read` isn't `public` MUST NOT become `public` (`422`, §7.6).

  - A branch MUST NOT break the level rules of Addendum E (Levels, `422`), nor turn off a `nonce` requirement its base has (`422`, §C.7).

  - `drafts: { "for": [ … ] }` (optional) lists, as names or prefixes ending in `*`, the other namespaces whose writes, and their branches', may resolve schema paths into this branch (§6.1); a bare `"*"` serves every namespace. `drafts` is `422` in a namespace that isn't a branch, or that is end-to-end.

  - A namespace with public dependents can't stop being public (`409`, `code: "in_use"`, with `dependents`).

  - A namespace can't start requiring nonces while a dependent doesn't (`409`, `code: "in_use"`, with `dependents`, §C.7), nor raise its level above a dependent's (Addendum E, Levels). Both are set in the branches first, leaves first.

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
**Items.** Each item names one resource, at most once per batch, with exactly one precondition as in §7.2 (none is `428`). A resource named twice, an item with both `ifMatch` and `ifNoneMatch`, or one without steps is `400` (`bad_input`), a request-shape error (§6.2). An item's `steps` apply in order, each chained on the previous one:

  - a patch set appends a revision, or restores if the previous entry is a tombstone

  - `"delete"` appends a tombstone. As an item's first step under `ifNoneMatch` it is `428`, at step 2.5 of §6.2, like a `DELETE` with `If-None-Match: *` (§12.1); after another `"delete"` with no patch set between them, `422` (`invalid`), also at step 2.5.

A step may also be an object with exactly one of `"patches": [ … ]` or `"delete": true`, plus optional `gesture` and `undoes` (§7.2) and `signature`, the step's author signature in the form of the `Signature` header (§C.3.1). An item or the whole batch may carry `gesture` and `undoes` as defaults, which a step's own override. The batch may send them as `Gesture` and `Undoes` headers instead; one sent both ways is `400` (`bad_input`).

Resource purge is never part of a batch.

-
**Checks.** Every step is checked with its own envelope, following §6.2 across the whole batch.

  - `items` may be empty or absent when `config` is present; a batch with neither is `400` (`bad_input`), a request-shape error (§6.2).

  - The optional `config` change runs steps 1–6 **first**, as a config write (§7.4), its `*`-key guard included (§C.2).

  - The items are then checked against the configuration it produces, except that `frozen` (§8.4) and the batch limits (§6.6) always come from the current configuration.

  - Batch limits can depend on the principal, through an allowance (§6.6). The server stops reading, at once (`413`), a body more than four times the larger of the verified principal's `batchSize` and the deployment maximum of `documentSize`, as for a resource `PATCH` (§6.6). Item counts, and the total size of the items' canonical patch sets against `batchSize`, are checked at step 4, before any item's own limits.

  - Items may reference schema revisions created by earlier items (§6.1), and blobs uploaded or copied before the batch or, with a local `source`, taken from it (§7.8).

-
**Success.** `201` with `{ "ns_id": …, "config"?: …, "items": [{ "resource": …, "ids": [ … ] }] }` and `X-Namespace-Revision`, with `config` and `X-Config-Revision` the new config id when the batch has a `config` change. One `batch` entry is appended (§3.5).

-
**Failure.** Nothing is written.

  - The status is that of the earliest failing step of §6.2. Where items fail it with different statuses, it is that of the first of them in request order, an item that ran out of `validationSteps` at step 1 counting after every item that failed step 1 outright (§6.6).

  - The body is `{ "code": "batch", "items": [{ "index", "status", "code", … }] }` for the items that failed at that step. If any item fails authorisation (§6.2 steps 1 and 2.2), only those items are reported.

  - A failing `config` change is answered as that config write would be (§7.4), without `items`.

  - These are answered as for a single write, without `items`: a purged (§8.5) or frozen (§8.4) namespace, a rate limit, `itemsPerBatch` or `batchSize` (§6.6), and a refused `source` (below).

-
**Dry run.** `?dry-run=1` runs steps 1–6 for the `config` change, if any, and every item, as a submit would, and writes nothing.

  - Items are checked against the configuration the change would produce, or the current one if the change fails after step 1.

  - An unavailable blob is reported, and later steps run as if it were available.

  - It returns `200` with `{ "items": [{ "index", "status", "code"?, "ids"?, … }], "config"? }`.

    - `items` holds a report for every item: its `status` `201` if it would pass, or `200` for each item when a submit would be an idempotent retry (below). Every report carries any `signature` failure and, with `201` or `200`, the ids a submit would produce.

    - `config` holds the `config` change's report, `{ "status", "code"?, "config"?, … }`, its `config` the config id a submit would produce.

  - It answers as a submit would instead (Failure) where the `config` change fails step 1, where any item fails authorisation (§6.2 steps 1 and 2.2), or for a rate limit, a purged or frozen namespace, `itemsPerBatch` or `batchSize`, or a refused `source`.

-
**Idempotent retry.** The answer is `200` with an earlier batch, as in §7.2, if both hold:

  - that batch's `batch` entry is by the same principal and contains exactly the entries this batch would produce, its config entry included, with the `config` change's `ifMatch` as that revision's parent (§7.4)

  - every item passes the retry's verb check (§C.2 item 2)

Only `batch` entries match, so a batch with only a `config` change matches one holding just that config entry. If any item's resource has been purged since, the retry is `410`, as a single write's (§6.2), before any other precondition, with the `batch` body listing those items (`code: "gone"`, §8.3).

-
**Reading other namespaces.** Some checks read a namespace other than the one the request names: a batch's local `source` (below), a blob copy's source (§7.8), and a schema revision in another namespace, a draft in a branch included (§6.1). Each tries the request's own grant and every grant in the repeatable `Source-Authorization` header. The first that names that namespace, verifies under its keys (§C.2) and allows that check's read serves. A public namespace needs no grant (§7). If none serves, the check fails as that section says, revealing nothing about the namespace.

-
**`source`** is recorded in the batch entry.

  - For a local source and a caller with unrestricted `read` on `source.ns` (§2.1, by the rule above), the server checks that `source.at` is in the chain of `source.ns` (`422`, `code: "source"`). It does so at step 4 of §6.2, after the batch limits and before any item's own checks.

  - For a local source and any other caller, it is recorded unchecked and makes no blobs available.

  - A source in another deployment carries `origin` and is recorded unchecked (§G.4.4). An `origin` equal to this deployment's own is `422` (`source`) for any caller, at the same step.

  - Nothing verifies that the items correspond to the source.

-
**Scope.** A batch never spans namespaces, and there is no other way to change several namespaces atomically.

-
**Events.** Each resource's event stream carries its new entries as usual; the namespace stream carries one `batch` event.

### 7.6 Branches

A branch (§2) is a namespace created from a **base** namespace at a namespace revision `at`. Addendum F describes merging, rebasing and cleanup.

**Creating a branch:**

```
POST /ns/{base}/branches
If-None-Match: *
{ "name": "release-7", "at": "1k…", "patches": [ … ] }     // `at` defaults to the base's current head
```

- **Request.** `patches` defaults to `[]`.

  - `at` defaults to the latest `ns_id` of the base's chain when the branch entry is inserted.

  - `If-None-Match: *` is required. `If-Match` alone is `428` too, at step 2.5 of §6.2, and never answered as a retry.

- **Result** of a branch's creation: `201` with `Location: /ns/{name}`, and `X-Namespace-Revision` for the `branch` entry appended to the base's log (§3.5).

  - A taken name, even one taken by a purged namespace, is `412`, with no `head` or `config`.

  - A retry by the same principal with the same `at` and `patches` gets `200`, as in §7.2, until the branch is purged, and `412` after. One that omits `at` counts as naming the `at` recorded for that branch.

  - An `at` that isn't in the base's chain is `422`. A purged base is `410` with `code: "purged"` (§8.5).

- **Configuration.** The branch's namespace document starts as a copy of the base's **current** document.

  - `frozen`, `successor`, `merged`, `abandoned`, `cleanup`, `drafts` and `schemaReads` are removed, `base: { "ns": base, "at": at }` is added, and then `patches` are applied.

  - The branch's configuration chain starts with one entry, the genesis patch set `[{ "op": "add", "path": "", "value": <that document> }]`, where `<that document>` is the document after `patches` are applied; it is the `target` of the base's `branch` entry (§3.5).

  - A branch's rules, roles and read mode are its own from then on. Its **keys follow the base** (§C.4).

- **Authorisation** of a branch needs `branch` and unrestricted `read` (§2.1) on the base, checked as §C.2 item 2 says. Bases whose read access is decided per document (§C.5.1) should grant `branch` only to a branching service (§F.8).

  - The `*`-key guard (§C.2) applies to `patches`, with a `*` key **of the base**. Every `*` key of the base is kept in the branch and can't be removed from it.

  - The base's rules evaluate a `branch` envelope whose `resource` is the new namespace's name, `doc` the new namespace document, and `writes` from `patches`.

  - Failures answer as for other writes (§6.2, §C.2).

- **A branch is a copy.** Whoever can read the branch can read the base as it was at `at`, under the branch's own configuration. A branch of a namespace that isn't public MUST NOT be public (§7.4).

- **Nesting and number.** A branch may itself be a base, within the branch-depth and branches-per-namespace limits (§6.6).

- **Across deployments,** content moves by export and import (§G.4); full-history imports keep ids.

**Reading through.** For a resource with no entries of its own in the branch, the branch answers as the base did at `at`, recursively through bases of bases:

- a `302` with `Location: /r/{branch}/{name}/rev/{id}` and `ETag: "{id}"`, where `id` is the head as of `at`

- a `410` if it was tombstoned then

- a `404` if it didn't exist then

Everything is served under the branch's own URLs. Changes in the base after `at` are never seen, except purges (§8.3) and the base's pruning (§8.6).

**History.** `/r/{branch}/{name}/rev/{id}` serves any id in the resource's ancestry as seen from the branch, including base revisions up to the foreign parent. `…/log?since=` crosses the foreign parent. `/r/{branch}/{name}/blob/{bid}` serves as §7.8 Reading says.

**First write.** The first write to a read-through resource checks its precondition against the base's head as of `at`, and takes that head as its **foreign parent**, whether it appends, deletes or restores. If the document it builds on, or for a delete the one it deletes, is pruned (§8.6), the write is `410` (`pruned`) once its precondition passes. Creating a name that didn't exist in the base at `at` is an ordinary create.

**Logs.** The branch's namespace log contains only its own entries; its creation is the base's `branch` entry (§10).

**Branch names are visible to the base's readers,** in its log and listing. Bases that must hide what their branches are about can require opaque names with a rule on the `branch` envelope's `resource` (§6.4.1).

### 7.7 Live reads by long-poll

SSE (§7.3) suits a few clients, but holds an origin connection for each. For many clients following one log, a **long-poll** read lets the CDN collapse their identical waiting requests into one:

```
GET /ns/{ns}/log?since={ns_id}&live=long-poll&cursor={c}
GET /r/{ns}/{name}/log?since={id}&live=long-poll&cursor={c}
```

- **Answer.**

  - If there are entries after `since` (empty or missing: from the beginning), the server answers `200` at once with them, up to one log page (§7.1), in the shapes of §7.1 and §7.4. `X-Namespace-Revision` (resource logs: `X-Revision`) names the last entry returned.

  - Otherwise it waits until an entry arrives or the current **interval** ends. The timeout answer is `204`, with the same header naming `since`, or without it when `since` is empty.

  - Both answers carry `X-Cursor`.

  - A `since` not in the chain is `404`, and a pruned range `410`, as in §7.1.

  - A resource with no entries waits as for an empty `since`.

  - A namespace log needs unrestricted `read` (§2.1), except as §7.9 allows, and a resource log `read` on that resource.

  - Without `live`, these URLs answer `302`, cached as a head pointer (§9), to the immutable range `…/rev/{head}/log?since=…`, and a resource with no entries `404`, cached as short.

- **Intervals and cursors.**

  - The server divides time into fixed intervals, each a positive whole number of milliseconds (default 20 seconds), counted for each log from a fixed epoch plus the log's **phase**: the first 8 bytes of the SHA-256 of its long-poll path as built from its names and `view` (`/ns/{ns}/log`, `/r/{ns}/{name}/log` or `/ns/{ns}/view/{view}/log`, no query), as an unsigned big-endian integer, modulo the interval in milliseconds. Interval `n` starts at epoch + phase + `n` × interval. The cursor is the interval number, in decimal. Origin instances SHOULD keep their clocks synchronised to well within an interval.

  - On `200`, the response cursor is the current interval number.

  - On `204`, the response cursor is the greater of the current interval number and the request's cursor plus one, with no jitter, so the same `since` never repeats a URL.

  - A wait ends at the latest at the interval boundary.

  - A cursor more than one hour's worth of intervals ahead of or behind the server's is `400` (behind: the client then omits it).

  - A request without a cursor, or with one behind the server's by less, is answered at once: with the entries after `since` if there are any, otherwise `204` with the current cursor in `X-Cursor`.

  - One ahead by an hour's worth or less waits as a current one does.

  - A cursor carried by a redirect to another log (§7.9 URLs) is judged by that log's intervals.

- **Caching.**

  - The cache key is the path plus `since`, `live` and `cursor`. Any other query parameter, a `live` other than `long-poll`, or a `cursor` that isn't a decimal number, `live` or not, is `400` (§7).

  - `200`: `public, max-age=0, s-maxage={interval}`.

  - `204`: `public, max-age=0, s-maxage=2` (§9).

  - Private namespaces follow §9, with these lifetimes at the edge.

  - Tags are those of the log (`ns:{ns}`, and `r:{ns}/{name}` for resource logs).

- **Clients** echo `X-Cursor` as `cursor` in the next request, take the returned revision as the next `since`, and poll again at once after a `200`.

- **Several logs at once.** Each followed log holds a connection for a whole wait, so serve long-poll over HTTP/2 or later. No combined URL is defined, as it would defeat collapsing; a service can follow many logs and publish one feed.

### 7.8 Blobs

Large values are stored as **blobs** (§2), served from their own immutable URLs; strings in documents are limited by `valueSize` (§6.6).

-
**References.** A document refers to a blob with an object whose `$blob` member is a string, at any depth:

```
"hero": { "$blob": "1m4…", "type": "image/jpeg", "size": 1843302 },
"scan": { "$blob": "1p7…", "type": "application/pdf", "size": 412977, "nonce": "k3q…" }   // a private namespace
```

  - `$blob` is the blob id (§3.7), `type` its media type and `size` its length in bytes. `nonce` is present exactly when the blob has one. No other members are allowed, except `sealed` at E3 (§E.3.1). At a raw document's root (below), the top-level members validation leaves out aren't part of the reference.

  - References are found by walking the document, whether or not it has a `$schema`. A malformed one is `422` (`code: "blob"`, §6.5).

  - Schema documents, whose `$schema` is a dialect URL (§6.1), contain no references.

-
**Attachments.** A blob belongs to a resource in a namespace through an **attachment**:

  - **Pending:** after an upload or a copy, until a revision references it.

    - The **uploader** is the root `sub` and `kid`, as for rate limits (§6.6), so after a key rotation a writer uploads its pending blobs again.

    - A pending blob is invisible: reads answer `404`, and only its uploader can reference it.

    - Each uploader has its own pending entry, even for bytes already stored. It counts toward its `blobPending`, at least 4 KiB per blob.

    - A pending entry is deleted once older than `blobGrace`; uploading it again restarts that time.

    - A write whose document references the blob ends every pending entry for it in that resource, whoever uploaded it.

  - **Attached:** at step 7 of §6.2, a write attaches every blob its resulting document references to its own resource, in the same transaction as the revision.

  - An attachment lasts while a document still stored for the resource references the blob: the documents at or after the horizon (§8.6), the horizon's and other kept documents, and the last live document of a tombstoned resource.

    - When pruning removes the last such document, the attachment ends and its bytes are deleted.

    - The same bytes in two resources are two attachments, which storage may keep once. It then removes only this attachment's reference, and the bytes go when nothing holds them.

    - Purge ends every attachment of the resource (§8.3).

-
**Availability.** A write may reference only blobs **available** to its resource:

  - attached to that resource in this namespace

  - pending there, if the writer uploaded or copied it

  - in a branch, attached to the same resource in a base and referenced by a document in the resource's history as the branch sees it (§7.6)

  - in a batch with a local `source` whose `source.at` the server has checked (§7.5), attached to the same resource in `source.ns`, or in a base it reads through, and referenced by a document in that resource's history as `source.ns` sees it at `source.at` (§7.6)

    - whatever the ranks, but from a sealed `source.ns` only blobs the caller's keys open (§2.1)

A reference to a blob that isn't available, or that doesn't match the blob's `type`, `size` or `nonce`, is `422` with `code: "blob"`, at step 4 of §6.2.

-
**Uploading.**

```
PUT /r/{ns}/{name}/blob/{bid}
Content-Type: image/jpeg
Blob-Nonce: k3q…              (optional: 26 base32 characters)

```

The checks run in this order:

  - **Authorisation** at step 1 of §6.2, with `create`, `append` and `restore` as candidates (§C.2 item 2), then the rate limits (§6.6), then `422` (`limit`) if its rules ran out of `validationSteps`. Rules beyond step 1 never see an upload.

  - A purged resource is `410`, and any upload to a purged namespace `410` with `code: "purged"` (§8.5). A tombstoned resource accepts uploads.

  - A frozen namespace is `409` (§8.4).

  - A media type that can't be parsed, or a `Blob-Nonce` that isn't 26 base32 characters (`^[a-z2-7]{26}$`, §3.7), an empty one included, is `400` (`bad_input`). A writer whose blob has an empty nonce sends no `Blob-Nonce`.

    - In an E3 namespace, any type other than `application/vnd.patchlog.sealed-blob` is `415` (§E.3.1).

    - Check 4 answers these `400`s first, then a precondition's `428` (below), then this `415`.

  - A body larger than `blobSize`, or one that would take the uploader's pending blobs in the namespace past `blobPending`, is `413`.

  - The server recomputes the id over the body (§3.7), with the `Blob-Nonce` as its nonce, empty without one. A mismatch is `422` with `code: "blob_mismatch"`.

Errors in the URL and its query parameters (§7), a malformed `{bid}` included (`400`, `bad_input`), come before check 1. Any other request-shape error of an upload, in its headers, is `400` (`bad_input`) at check 4, and a copy's come where Copying says.

  - **No precondition.** An upload takes none (§7.2), one sent being `428` at check 4 (§12.1), and writes no namespace entry (invariant 5). It is idempotent: the answer is `201` with `ETag: "{bid}"` whether or not the bytes were already stored.

  - **Copying.** With an empty body and `Blob-From: /r/{ns2}/{name2}/blob/{bid}`, naming the same `bid`, the server copies a blob within the deployment:

    - Checks 1–3 run first, for the target. Then come, in this order and before any body is read:

      - `400` for a request whose headers announce a body, a `Blob-From` that can't be parsed, or a header error of check 4 outside `Content-Type` and `Blob-Nonce`

      - a precondition `428`

      - `422` (`code: "blob"`) for a different `bid`

    - The source is then checked as a read of `/r/{ns2}/{name2}`, judged as for reading other namespaces (§7.5). A grant whose blocks name both namespaces, signed by a key they share, serves for both. Any failure of this check, including the `401` and `403` cases of §C.2, answers `404`.

    - A copy also answers `404` if it goes into another namespace that ranks below its source (§2.1), if Reading (below) wouldn't serve the blob at the source, or if the caller's keys don't open a blob from a sealed source (§2.1).

    - The copy is then checked like an upload of the source's type, nonce and size (checks 4 and 5), whatever `Content-Type` and `Blob-Nonce` it carries. It costs a token like an upload, and nothing from `blobRate`. A batch with a local `source` carries `Source-Authorization` in the same way.

-
**Files.** A document whose root is a blob reference, with no other members than the top-level ones that validation leaves out (§6.2 step 5: `$schema`, a fresh `$nonce`, a `$successor`), is **raw**. It stands for a file, served at `…/raw` (§7.1) with the blob's type.

  - The read check of `…/raw` is its document's, and of `…/blob/{bid}` as Reading says. A `schemaReads` referrer (§6.1) opens revision paths only.

  - `size` in `/heads` (§7.4) is the reference's length, not the file's.

-
**Reading.** Every response to a blob URL, errors included, carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`.

  -
The one exception: a stored `type` of exactly `application/pdf`, in a `200` or `206`, may go without the sandbox, still with `nosniff`. A deployment serves PDFs with `Content-Disposition: attachment` unless it opts into inline display.

  -
`GET /r/{ns}/{name}/blob/{bid}` answers `200` with the bytes, `Content-Type` its stored type (§3.7), with `; charset=utf-8` for a `text/*` type, `ETag: "{bid}"` and `Accept-Ranges: bytes`, and `206` for a range, with the same `ETag` and `Accept-Ranges`. One range keeps the `Content-Type` and adds `Content-Range`; several are `multipart/byteranges` (RFC 9110, section 14.6). Sealed namespaces answer as in §E.2.2 instead.

  -
Whoever may read a stored document that references a blob may read the blob (§C.5, §6.4.1).

  -
It serves the blobs attached to the resource and, in a branch, the base's blobs that the branch's view references (§7.6). Pending and unknown blobs are `404`. A tombstoned resource keeps serving its blobs, like its history (§8.1). A blob whose attachment pruning ended is `410` as in §7.1, and every blob of a purged resource is `410`.

  -
Caching is immutable, with the resource's tags (§9). In sealed namespaces the URL also names an epoch (§E.2.2).

-
**Encryption.** In sealed namespaces, and in those that require nonces, writers MUST give the blobs they create a nonce (§C.7); the server doesn't check it. Blobs carried over from another namespace keep their ids, nonce or not. The server seals blobs on delivery (§E.2.2), and at E3 clients encrypt them (§E.3.1).

### 7.9 Filtered reads

Optional. A server that implements it gives **partial readers** a namespace's own reads, filtered: narrowing a grant's read rules (§C.1), as with a rule on `/doc/$schema` or a `/resource` pattern, is how a consumer filters a namespace's log. One that doesn't answers them as §C.5 says.

-
**Where.** While authentication is on (§1), in a namespace that is neither a branch (§7.6) nor end-to-end, public and sealed ones included (below). Elsewhere these URLs answer `403`, or `401` without a grant or cookie that verifies, in §7's order.

  - In a public namespace a grant filters rather than restricts, but where sealed it decides the keys its holder gets (§E.2.3). Only URLs under a view prefix take it; every other read ignores it (§7 step 1), so none redirects to a filtered form. Answers under the prefix are cached as a private namespace's (§9).

-
**Partial reader:** a caller for whom all hold:

  - its grant verifies in `{ns}` and allows `read` there (§C.2 items 1 and 2);

  - no block or key-scope rule refers to `/now` and, if it carries roles, it has an effective role that lists `read` without one (§C.2 item 5);

  - it lacks unrestricted `read` (§2.1): its read rules refer to `/resource` without fixing it, or to `/doc`, as `{ "op": "test", "path": "/doc/team", "value": "a" }` does.

Unrestricted readers keep the unfiltered URLs; at filtered ones their grant in `Authorization` is `403`, and a `/ns/{ns}` cookie (§2.1) reads every revision, its answers `private, no-store`, `no-store` at the edge too (§9), and never shared with that view's readers.

-
**Visible.** A revision is visible when the reader's blocks, key scope and roles, counted as §C.2 item 5 counts them, allow `read` with that revision's `read` envelope (§6.4.1).

-
**Answers** to a partial reader: `GET /ns/{ns}` is the head pointer of §7.4; `/heads`, log ranges, long-poll and events are filtered (below); a resource's URLs and the gestures listing (§7.4) serve visible revisions only (§C.2 item 5), logs as below. Other reads, such as `GET /ns/{ns}/rev/{ns_id}`, `/grants/{gid}` and `/branches`, answer as without this section (`403`).

-
**Log entries** keep their shapes; only the set changes, and nothing is stored for it.

  - A `head` is shown when its revision is visible, and a `tombstone` when the document it deleted is. One not shown whose resource's previous `head` or `tombstone` entry was shown as itself is shown in its place as `{ "id", "prev", "kind": "hidden", "resource" }`, or, in a batch, as `{ "kind": "hidden", "resource" }` among its `entries`. Any other is dropped.

  - A `prune` is shown when its `target`'s document is visible. A `purge` is shown when the grant's rules that don't refer to `/doc`, `all`s flattened, allow `read` of its resource, so to every partial reader whose `/resource` rules allow the name.

  - `config` and `purge-ns` are shown always, and `branch` never.

  - A `batch` shows only its shown `entries`, and its `gestures` and `source.ids` only for items shown as `head` or `tombstone`, each left out if empty. One with nothing shown is dropped, or kept as `config`-only if it has a config entry.

  - A resource's own log, long-poll and event stream show its visible revisions, without `patches` where the parent, or the document a tombstone parent deleted, is hidden, and as `{ "id", "parent", "kind": "hidden" }` (event type `hidden`) each hidden one whose parent is visible; its `purge` and `prune` events as the namespace log shows them.

  - A filtered log isn't chain-verifiable (§10): batch ids don't hash what is served, and `prev` and `parent` name unseen entries. After a `hidden` entry, or on first seeing a resource mid-history, a reader fetches the next visible revision's document (§7.1) instead of folding.

-
**Log ranges** are paged as §7.1 says, a batch counting as its shown items and a dropped entry as one, so a page may show none. A range ends at the URL's `at`, which answers carry as `X-Namespace-Revision`. Every page but the last carries `X-Log-Next`, naming its last entry, shown or not.

-
**`/heads`** lists a row only where its head revision is visible, a tombstone as its deleted document and a purge as its entry is shown, in pages filled to `logPageSize`; `next`, the last row returned, is on every full page and no other.

-
**Long-poll.** Only shown entries answer `200` or end a wait. A wait may also end `204` at once after a bounded scan of at least one page, or where its budget runs out (§6.6). `X-Namespace-Revision` (resource logs: `X-Revision`) names the newest entry scanned, after a run-out the last one judged whole, or a revision that alone runs out a fresh budget, which counts as hidden, so a follower moves past dropped ones; a `since` or `Last-Event-ID` may name one.

-
**Events** carry only shown entries, with each read check §7.3 repeats, the cookie check below included.

-
**Cost (SHOULD).** A server judges each revision's visibility at most once per view and keeps the answer, even once pruning drops the document (§8.6). An answer judged without a stored document needn't be kept: the revision is hidden until an archive restores its document (§8.6). Waiting followers of a view share it.

-
**URLs.** Ranges are at `/ns/{ns}/view/{view}/at/{ns_id}/heads` and `…/log`, `ns_id` an entry of `{ns}`. Long-poll and events are at `/ns/{ns}/view/{view}/log` and `/ns/{ns}/view/{view}/events`.

  - **Content.** A resource's immutable URLs are served under the prefix too: `/ns/{ns}/view/{view}/r/{name}/rev/{id}`, its `/raw`, `/r/{name}/blob/{bid}` and its `/e/{e}`, answered as their own forms (§7.1, §7.8), sealed ones as the same bytes, for a visible revision, or a blob a visible revision references (sealed: one of epoch `e`, the `302` naming the latest such `e`), and as a read-rule failure otherwise. They are immutable and tagged as their own forms (§9), so a view's readers share them at the CDN.

  - A `view` or `ns_id` not in text form (§3.2) is `400` (`bad_input`), a request-shape error (§6.2).

  - Ranges are tagged as their unfiltered forms (§9), and immutable but for later purges, which clear them (§8.3), and archive restores, which needn't clear them (Cost).

  - A URL under the prefix without `at` (a `…/log` without `live`, §7.7), and a partial reader's request at an unfiltered URL, answer `302`, `private, no-store`, to the filtered form, a range at the current `at`, a long-poll or stream with its query.

  - A grant in `Authorization` reads only at its own `view` (`403` elsewhere).

-
**`view`** is `text(trunc160(sha256(canonical(subjects))))`, `subjects` an array in byte order of UTF-8 of:

  - the string `scope:{digest}`, where `digest` covers the rules that limit the grant's `read` in `{ns}` (of its blocks, its key's scope and each effective role that lists `read`, §2.1) and the values at the `/principal` paths they test or compare. A grant §C.5.2 would give `/ns/{ns}` has none;

  - the string `key:{text(trunc160(sha256(canonical([kid, pub]))))}` of the key that verified the grant's root block, `pub` as its key entry gives it.

Readers with the same rules share a view and its cache entries. Implementations needn't agree on `digest`. The origin keeps, per namespace and view, the rules and `/principal` values its digest covers, and judges visibility under a cookie from those, never from a grant the request doesn't carry. A cookie whose `view` it keeps nothing for is `401`.

Every cookie of a view is `403`, at every URL, once an entry after its exchange changes those rules, the key its `key:` string names, a key they came from or any role that lists `read`, even where a later entry undoes the change, whoever's exchange made it. No exchange revives it, and a cookie the origin can't tell from such a one is `403` too. Streams judge this at the current entry, and end when it fails (§7.3).

-
**Edge grants.** The origin's exchange (§C.5.2) gives a partial reader the prefix `/ns/{ns}/view/{view}`, with a cookie that never outlasts its grant. For it, §C.5.2's refusals concerning `/resource` and `/doc` rules and qualifying roles don't apply, and its check that rules pass now covers only block and key-scope rules that refer to neither, which Visible judges per revision. A partial reader reads heads at their own URLs with its grant in `Authorization` (§9), and revisions and blobs under its prefix.

-
**Sealed namespaces (E2).** A partial reader's only key is its view's `K_view` (§E.2.3). Its filtered answers are sealed under that key, and carry the keys of the visible revisions they name and of those revisions' blobs (§E.2.2). It opens those revisions and blobs at their own URLs or under its prefix, comparing their `pl` with the URL without the prefix. Holding `sealed` for the namespace (§7.1), it refuses a filtered `200` that isn't `application/jose`, and event data that isn't one JWE. To a reader with a `/ns/{ns}` cookie they are sealed under `K_n` instead, with `keys` `[]`: it derives them from `K_e` (§E.2.1).

-
**Purged namespaces** answer these URLs as §8.5 answers their unfiltered forms, once the URL's read check passes, its `view` included and rules on `/doc` set aside (§6.4.1); a partial reader's unfiltered `/heads` is then `410`, without the `302`.

-
**Accepted leaks** (§C.6): that hidden writes happen, and when (the namespace head, `X-Namespace-Revision`, long-poll wake-ups, a batch's `author`, `grant` and `created`); hidden ids (`prev`, `parent`, `X-Log-Next`, a `hidden` entry's, a `purge`'s `target`); when a document left a view (`hidden`); the names of purged resources a reader's `/resource` rules allow; who changed the configuration, and when.

---

## 8. Deletion and purge

### 8.1 Tombstone (delete)

- `DELETE` with `If-Match: head` appends a tombstone to the resource log **and** a `tombstone` entry to the namespace log, atomically.

- **Moves.** A move is recorded in content: the resource's last revision before its tombstone sets the top-level `$successor` (§6.5) to the resource that replaces it.

  - For one in the same namespace, `$successor` is a bare name, resolved against the namespace that serves the `410`.

  - For one in another, it is `/r/{ns2}/{name2}`.

  - Names are valid under §3.6. Either form is well-formed wherever the document is, whatever `ns2` names.

  - Within one namespace a move is one batch: create the new one, then append `$successor` to the old one and delete it, its blobs copied first with `Blob-From` (§7.8). Across namespaces it is two writes.

  - `$successor` is otherwise ordinary content for the chain, signatures, rules, merges and imports (§6.5).

- The head pointer then returns `410`, with `successor` copied from the last document's `$successor` if well-formed, in a namespace that is neither sealed nor end-to-end (§11). It is whatever the last document names: a namespace that cares protects `/$successor` by rule (§6.4.1, `/doc` for deletes). A restore keeps `$successor` (§8.2). Earlier `/rev/{id}` URLs and the resource's blobs (§7.8) keep returning `200`.

- Further `PATCH` requests other than a restore (`If-Match: "{tombstone}"`), and `DELETE`s, answer as §7.2 says.

### 8.2 Restore / recreate

- The chain continues from the tombstone; its first revision applies its patches to the last live document.

- `[]` restores the document exactly as it was, `$successor` included (§8.1); where nonces are required (§C.7), just a fresh `$nonce` does.

- To recreate from scratch, restore with a root `replace`, if namespace rules allow it (§6.4.4).

### 8.3 Purge

- **Effect.** The resource's content (patches, snapshots and blobs, §7.8) and the view keys stored for its revisions (§E.2.2) are removed and the resource marked purged; storage that keeps identical content once removes only this resource's references to it (§7.8, §8.5). Its archived history (§8.6) is deleted too, or made unreadable by destroying its key, and restoring from an archive MUST skip purged resources.

- **Namespace entry.** A `purge` entry is appended to the namespace log. Consumers MUST drop the resource and purge their derived data and cache tags (§10).

- **Responses.** All `/r/{ns}/{name}/…` URLs then return `410`, before a `not_offered` as in §8.5. They do so once the caller passes the read check for that URL, its rules on `/doc` set aside (§6.4.1 `read`), or, for a write, step 1 of §6.2. Until then a read answers as for a resource the caller can't read (§7 step 4).

- **CDN.** The CDN is purged by tag (§9), `heads:{ns}` included (§7.4), and `ns:{ns}` once a view of the namespace has been served (§7.9), never by id, in each branch a purge reaches too, or by the base's tags where §9 Branches allows.

- **Branches.** A purge propagates to the **same name in every branch** of the namespace, recursively, successor generations included, whether the branch reads it through or has its own chain for it.

  - A branch that sees no entry for the name is skipped, though its own branches aren't.

  - A branch created later, at an `at` before the purge, sees the name as purged where it would read an entry for it through (§7.6). It answers `410` for it, and its `/heads` lists it as `purge`, with its head as of `at` as `target`.

  - In each branch it reaches, frozen or not, the resource is purged and a `purge` entry appended to that branch's log.

  - Purges never propagate upwards.

- **Limits of purge.** Purge can't recall copies in caches the operator doesn't control (§9), keeps the `schema` of `head` entries (§7.4), and does **not** remove hashes: ids of low-entropy content, and `/heads` digests already served (§7.4), can be confirmed by guessing, which required nonces prevent (§C.7). Copies of a blob in other resources (`Blob-From`, §7.8) stay until those resources are purged too.

### 8.4 Freezing a namespace

- **Freezing.** A config write sets `"frozen": true`, and `false` unfreezes.

  - Resource writes, batches with items, and blob uploads and copies (§7.8) are then `409` with `code: "frozen"`, and `successor` if set.

  - This check is at step 2.4 of §6.2 (check 3 of §7.8 for uploads), after the idempotent-retry lookup (§7.2).

  - Unfreezing a branch whose base already has `branchesPerNamespace` live branches is `422` (`code: "limit"`, `limit: "branchesPerNamespace"`, §6.6), `max` being the base's value.

- **What still works:**

  - reads, events and namespace consumers

  - config writes

  - resource purges, and namespace purges, which require it (§8.5)

  - creating branches from it

  - pruning (§8.6)

- **`successor`** optionally names the namespace that replaces this one, as §7.4 constrains it. Clients SHOULD move to it (§11).

- **Freezing is the namespace's tombstone:** reversible, unlike namespace purge (§8.5).

### 8.5 Purging a namespace

-
**Request.** `POST /ns/{ns}/purge` with `If-Match: "{ns_id}"`, the namespace head. `204` on success; `428`, and `412` with the current `{ head }`, as for any write (§7.2).

-
**Requirements**, checked in this order (§6.2), all before rules (step 6); a purged namespace is `410` at step 2.1 (table below):

  - the `purge-ns` verb (Addendum C), distinct from `purge` (step 1)

  - the namespace is frozen (step 2.4): otherwise `409` with `code: "not_frozen"`

  - the precondition (`412`, then `428`)

  - no **dependents** (§2.1): otherwise `409` with `code: "in_use"` and `dependents` (§6.1); cleanup proceeds leaves first

  - it would remove no last copy of a schema revision (§6.1) referenced from another namespace (its own documents are purged with it): otherwise `409` with `code: "in_use"` and `referencing` (§6.1)

-
**Effect.**

  - Every resource is purged as in §8.3, without individual entries, and one `purge-ns` entry is appended, the log's last: purges propagated from a base (§8.3) or followed from an origin (§G.1), and retention prunes (§8.6), skip a purged namespace.

  - What §5 retains after a namespace purge is kept.

  - The name stays reserved.

  - The CDN is purged by the tag `ns:{ns}` (§9).

-
**Answers afterwards.** Every `410` here has `code: "purged"` and `head`, the `ns_id` of the `purge-ns` entry.

| Request | Answer |
|---|---|
| `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…`, `/ns/{ns}/keys`, `/ns/{ns}/principal`, `/ns/{ns}/branches`, and `/heads` at any revision | `410`, as soon as the full read check for that URL (below) passes, and before any other answer to a well-formed request, `not_offered` included |
| `/ns/{ns}` and `/ns/{ns}/rev/{ns_id}`, logs, events and long-poll included | served as before, except events and long-poll from the `purge-ns` entry, `410`; where sealed, `410` (below) |
| Any write to it: resource writes, batches, blob uploads and copies (§7.8), purges, prunes, config writes and branching from it (§7.6) | `410` at step 2.1 of §6.2 |
| Creating a namespace or a branch under its name (a creation, not a write to it, §7.6), and a branch creator's retry once the branch is purged | `412` |
| Edge-grant issuance for a grant naming it (§C.5.2) | `410` as §C.5.2 says |

The full read check of the first row is the grant's rules, those on `/doc` set aside (§6.4.1 `read`), unrestricted `read` where the URL needs it, a partial reader passing at `/heads` (§7.9), any `read` for the gestures listing, §E.2.3's test for `/keys`, and for `/principal` verification alone.

**Sealed namespaces.** Where namespace documents and log ranges are sealed (§E.2.2), the purge destroys the namespace's epoch keys (§E.2.1), from which their `K_n` derive, and those reads, events and long-poll included, answer `410` too. `GET /ns/{ns}` still redirects, to a revision that is `410` where it is sealed.

-
**Shared storage.** Storage that keeps identical entries of several namespaces once removes only this namespace's references.

-
**Forcing.** An `in_use` refusal for schema references can be forced as §6.1 says; one for dependents can't.

-
**Irreversible.** There is no restore.

### 8.6 Pruning and retention

Pruning bounds the storage of long histories **without changing any id**.

-
**Horizon.** Pruning a resource below a horizon revision `H` drops the patch sets of the revisions before `H`, and the attachments of blobs that only the dropped documents referenced (§7.8), which the archive carries.

  - **Kept:**

    - every id, parent link, author, grant reference, creation time, `gesture` and `undoes` (§C.3)

    - the ids of the blobs whose attachments it ends (§7.8)

    - `H`'s document

    - the protected documents (below)

    - if `H` is a tombstone, the last live document (§8.2)

-
**Request.** `POST /r/{ns}/{name}/prune` with `{ "horizon": id, "keep"?: [ids], "snapshot"?: sealed }` returns `200` with `{ "horizon": id }`, the effective horizon.

  - It needs the `prune` verb and is checked with a `prune` envelope (§6.4.1). It takes no precondition (§7.2): one sent is `428`, at step 2.5 of §6.2.

  - `horizon` MUST be the head or an ancestor of it (`422`). The server lowers it to the oldest protected revision if needed, never below the current horizon, giving the effective horizon.

  - Two kinds of prune need a grant chained to a `*` key: going below what `retention` keeps for the resource, which is everything where no rule matches it, and pruning where no archive is configured. Applying a retention rule that says `"archive": false`, within what it keeps, needs only `prune`.

  - `keep` lists extra revisions whose documents stay available, up to `keepPerResource` (§12.2).

    - Outside a branch, each `keep` id MUST be a revision of the resource whose document is still served rather than `410` (`pruned`), or the prune is `422`.

    - A prune that sends `keep` replaces the resource's earlier `keep` set (`[]` clears it). One without `keep` leaves it.

    - `keep` is `422` in an E3 namespace.

  - A `prune` entry `{ resource, kind: "prune", target }`, `target` the effective horizon, is appended to the namespace log only if the prune moved the horizon or changed the `keep` set.

-
**Protected revisions.** The horizon never passes:

  - anything newer than the **retry window** (§6.6)

  - the resource's head as of the `at` of every unpurged branch, frozen or not (§7.6)

-
**Protected documents,** kept below the horizon:

  - schema revisions referenced (§6.1) from any namespace of the deployment. At E3 the server can't see references; protect schemas with `retention` (below).

  - the revisions listed in `keep`

-
**Branches don't prune.** A branch's own entries are protected until it is purged (§8.5), and only the base prunes the history the branch reads through. A prune in a branch, once its checks pass, moves no horizon: it answers `200` with the resource's current horizon as the branch sees it, or its genesis id where it has none, ignores `keep`, and writes nothing, an archive included: only namespaces that aren't branches have archives.

-
**Archive.** Before pruning, the server writes the pruned history as a full-history bundle (§G.4.1), with `"authors": true` and grant lines, to a destination configured by the operator or in `retention`, and MUST NOT write anywhere else. It holds that resource's pruned revisions alone, with the blobs they reference. It has no dependency closure (§G.4.2), an exception to §G.4.3's Modes close downward, and no `external`. Its `docs` names only that resource, and its `requires` the parent of its first revision unless its first revision is genesis. Outside a branch, only two prunes go without one: under a `*` key where no destination is configured (Request), and applying a retention rule that says `"archive": false` (Retention policy).

  - In encrypted namespaces (Addendum E), archives are sealed bundles (§G.5.1.1), one per resource. Each one's only recipient is a key the server holds for that resource, which never leaves the deployment and which purge destroys (§E.1): only the server opens such an archive, to restore from it. Each line is padded (§E.2.2) where the namespace sets `pad`.

  - At E3 a key-holding client supplies `H`'s document (the last live one when `H` is a tombstone) as `snapshot`, sealed like a patch set (§E.3.1).

    - A prune there without `snapshot`, or, outside a branch, where no archive is configured, is `422` (`invalid`), even under a `*` key.

    - A `snapshot` outside an E3 namespace is `422` (`invalid`) under any grant.

    - At E3, a prune whose effective horizon moves the horizon but isn't `H` is `422` (`invalid`) with it as `horizon`, for the client to resend with that revision's document.

  - So the server skips E3 namespaces when it applies retention. A key-holding janitor, a client with `read`, `prune` and the epoch keys, applies it there, sending each `snapshot`.

-
**Retention policy.** The namespace document may declare rules that the server, or a janitor with `prune`, applies periodically:

```
"retention": [
  { "select": { "prefix": "telemetry-" }, "keep": { "revisions": 50, "age": "PT10M" } },
  { "keep": { "age": "P2Y" }, "archive": "s3://archive/matches/" } ]
```

  - The first rule whose `select` matches a resource applies. `select` is a name `prefix`, or a list of `names`. A missing `select` matches everything.

  - `keep` keeps whichever is longer: the last `revisions`, or everything newer than `age`. A rule without `keep`, or whose `keep` has neither, is `422` (`invalid`, §7.4).

  - `archive` is the rule's archive destination, by default the operator's. A rule with neither applies only if it says `"archive": false`; otherwise the resources it selects keep everything. Any `"archive": false` is `422` in an E3 namespace.

-
**The namespace log is never pruned.**

-
**Pruning is not purge.** Cached and consumers' copies stay; purge (§8.3) removes content, archives included.

-
**Verification.** A client verifying through logs (§G.2) starts from the archive (invariant 4), in an encrypted namespace from what the server restores from it, or from a revision at or after `H` that it has already verified.

-
**Merges, branches and exports.** Classification by ancestry (§F.3) works across a horizon. Fast-forward and replay need the patch sets after the common ancestor, which protected revisions keep for branches; otherwise an item whose needed history was pruned is a conflict. A full-history export (§G.4.3) from before the horizon needs the archive, in an encrypted namespace restored first.

---

## 9. Caching

**Public namespaces:**

| Response | Cache-Control | Tag (`Cache-Tag` / `Surrogate-Key`) |
|---|---|---|
| Head pointer (resource or namespace `302`, head `410`) | `public, max-age=0, s-maxage=1, stale-while-revalidate=5` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Immutable (`/rev/{id}`, `/rev/{id}/log`, `/ns/{ns}/rev/{ns_id}`, its `/heads` pages (also tagged `heads:{ns}`, §7.4), namespace log ranges (sealed ones may be sealed again with other bytes, §E.2.2), `/ns/{ns}/grants/{gid}` (`private` at E3, §C.3.1), `/blob/{bid}`, `/blob/{bid}/e/{e}` and their ranges) | `public, max-age=86400, s-maxage=31536000, immutable` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Short (unknown id `404`; at E3 a `not_offered` `/rev/{id}`, §7.1) | `public, max-age=5` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Long (`410` of a purged resource or namespace, on a URL that isn't `no-store`, §8.3, §8.5) | `public, max-age=86400, s-maxage=31536000` | `ns:{ns}`, and `r:{ns}/{name}` for resources |
| Pruned (`410` below a horizon) | `public, max-age=3600` | `r:{ns}/{name}`, `ns:{ns}` |
| Live long-poll (§7.7) | `200`: `public, max-age=0, s-maxage={interval}` · `204`: `public, max-age=0, s-maxage=2` | as the log |
| Writes, batches, dry runs, SSE | `no-store` | — |

-
**Browsers keep immutable content for a day, the CDN for a year.**

-
**Serving stale.** An edge MAY keep serving immutable responses while the origin is unreachable; a purge still removes them. Head pointers are served stale only within their `stale-while-revalidate`. Live long-poll answers (§7.7), `200` and `204` alike, MUST NOT be served stale: they carry no `stale-*` directive, and an edge MUST NOT apply stale-if-error or grace defaults to them.

-
**Empty long-poll answers.** A CDN that doesn't cache `204` by default SHOULD be configured to cache the long-poll `204` (§7.7) for its lifetime.

-
**Tags** are `{kind}:{value}`, where `kind` is a lowercase word (§12.8) and `value` is namespace and resource names (§3.6) joined by `/`. `Cache-Tag` lists a response's tags separated by commas, and `Surrogate-Key` the same tags separated by spaces. A purge names whole tags, never part of one. How purges reach the CDN is deployment-specific; a self-hosted CDN might take `PURGE` with the tags, space-separated, in `X-Purge-Tags`.

-
**Branches** are cached like any namespace, under their own URLs and tags, which purges propagated to them (§8.3) purge too.

  - **Base tags.** A branch's response for a resource it reads through MAY also carry `r:{base}/{name}` for each base in its `base` chain, down to the one it reads from, and its `/heads` pages `heads:{base}` for each base. A branch's reader may not know its base, so the origin, or a service, adds them only where every response reaches clients through caches that strip `Cache-Tag` and `Surrogate-Key`.

  - Once no cache its purges reach holds a branch's response without them, those cached before it began adding them included, a deployment MAY satisfy a propagated purge by the base's tags alone, `heads:{base}` standing for every `/heads` page of the branch, except `r:{branch}/{name}` of a branch with its own chain for the name.

**Sealed namespaces** (Addendum E) are cached by their `read` mode, like any other.

**Private namespaces** (Addendum C §C.5):

- **Downstream** responses carry `Cache-Control: private`, with a `max-age` no longer than their public class's.

- **Edge caching needs an edge that verifies an edge grant on every request** (§C.5):

  -
**With a verifying edge**, the origin gives edge lifetimes with `CDN-Cache-Control` (RFC 9213) or `Surrogate-Control`, at the values for public namespaces, only to a read the edge verified itself, as its two headers say (§C.5.3). That holds only with:

    - both present, each one line without a comma

    - the secret matching

    - the prefix covering the URL

    - no other credential (`Authorization`, `Source-Authorization` or signed-URL parameters)

The origin still authorises the read itself, from the forwarded cookie or grant (§C.5.3). The headers decide only the lifetimes, never when an event stream ends (§7.3).

  -
**Everything else private is `CDN-Cache-Control: no-store`** (and `Surrogate-Control: no-store`), with or without an edge: reads with a grant in `Authorization`, a `/ns/{ns}` cookie's reads at view URLs (§7.9), schema revisions opened by a referrer (§6.1), and reads the edge only relayed.

  -
**Without one** (no CDN, or a CDN that doesn't verify grants), every private response is therefore `no-store`. The origin is configured with which deployment it is in.

- **Making a namespace private**, or raising it to sealed, requires the origin to purge the tag `ns:{ns}`, which every tagged response of the namespace carries, with the configuration write. Copies already in browsers remain until their `max-age` expires.

---

## 10. Namespace consumers

A **namespace consumer** (§2) uses only the public API, with no private access to storage. It works as follows:

- **Checkpoint.** A consumer stores the last `ns_id` it has fully processed. `""` means from the beginning.

- **Catch up.** `GET /ns/{ns}` gives the current `ns_id`, and `GET /ns/{ns}/rev/{current}/log?since={checkpoint}` the entries in between, page by page (§7.1), cacheably.

- **Follow.** `GET /ns/{ns}/events?since={checkpoint}` streams new entries. Where many consumers or pages follow the same namespace, long-poll `GET /ns/{ns}/log?since={checkpoint}&live=long-poll` instead (§7.7). In a private namespace, long-poll with an edge-grant cookie, since only reads under an edge grant collapse (§9, §C.5).

- **Coalesce.** Within a range of entries, only the latest `head`, `tombstone` or `purge` entry per resource matters, inside batches too. A new consumer that needs only current state lists `GET /ns/{ns}/rev/{current}/heads` (§7.4; `410` once purged, §8.5), or scans the log once and fetches each resource's last revision, then follows from `current`.

- **Fetch content** from immutable URLs: `/r/{ns}/{name}/rev/{id}`, schema revisions and blobs (§7.8). At E3, where `/rev/{id}` is `404` (`not_offered`), fold its log as §7.1 says.

- **Handle every kind of entry:**

  - `head` → process the document

  - `tombstone` → drop the resource

  - `purge` → drop the resource **and purge derived data and cache tags**

  - `config` → the configuration changed, including `frozen` and `successor`

  - `batch` → process its entries **as one unit**, so derived data never shows half a batch

  - `purge-ns` → drop everything from the namespace, and purge derived data and cache tags. Where log ranges are sealed, a `410` `purged` stands for it (§8.5).

  - `hidden` → in a filtered log only (§7.9): drop the resource, which left the reader's view

  - `branch` → a branch was created, which consumers that follow branches start following (below).

  - `prune` → usually ignored. A consumer that fetches a pruned revision gets `410 pruned` (§8.6) and fetches the head instead; if the head is pruned too, as a branch's read-through one can be (§7.6), it treats the resource as absent until a later entry.

- **Advance the checkpoint** only after the entries are durably processed. Processing is idempotent.

- **Verifying grants.** Consumers that verify grants presented to them (Addendum C, §C.6) MUST check keys and revocations as of the namespace **head**, and in a branch as of its bases' heads too (§C.4), not as of their checkpoint. Grants recorded with entries are verified as §C.3.1 says.

- **Filtered logs** (§7.9) aren't chain-verifiable: a consumer that verifies chains needs unrestricted `read`. A partial reader follows the filtered URLs, which cover no branch and carry no `branch` entries (`GET /ns/{ns}/branches` is `403` for it). A document entering its view arrives as a `head`, and one leaving it as `hidden`. A change of the rules gives it another view, from whose `/heads` it starts again.

- **Consumers elsewhere**, in another network or organisation, record their checkpoint as `(origin, ns, ns_id)` and verify what they fetch as §G.2 says.

- **Branches.**

  - **Discovery.** A consumer that follows branches learns of them from `branch` entries with `name` in the logs it already follows, recursively, and, if it started from `/heads` (step 4), of earlier ones from `GET /ns/{ns}/branches` (§7.4).

  - **Contents.** A consumer can't reuse its own view of the base: it starts from the branch's `/heads` listing at the branch's first `ns_id`, which includes read-through resources, then follows the branch's own log. So too for a branch it is told to follow directly, such as one named in a release document (§F.9).

  - **Access.** It needs unrestricted `read` on the branch (§2.1), and skips a branch it may not read.

- **The core derives nothing:** no indexing, search or organising. Addendum A describes a consumer that does.

---

## 11. Client behaviour (non-normative)

In TOOLS.md.

## 12. Registries

§12.1 (errors), §12.2 (limits) and §12.3 (namespace-document members) define what they list; where a §12.3 row states no shape, or only names a structure, the cited section gives it. The other registries are indexes: the cited section governs, and a row adds no requirement, so which query parameters an endpoint accepts is decided by §7 and the section defining the endpoint.

### 12.1 Errors

```
{ "code": "…", "ns": "…", "head": "…", "tombstone": "…", "last": "…", "horizon": "…", "archive": "…", "limit": "…", "measured": 0, "max": 0, "retryAfter": 0, "min": [ … ], "config": "…", "successor": "…", "dependents": [ … ], "referencing": [ … ], "more": true, "items": [ … ], "rule": 0, "path": "/…", "errors": [{ "pointer": "/blocks/1/type", "message": "must be equal to one of the allowed values" }] }
```

| `code` | Status | Meaning |
|---|---|---|
| `bad_input` | 400 | Any `400` (examples below the table) |
| `unauthenticated` | 401 | No usable grant: missing, malformed, badly signed, revoked, expired or not yet valid (§7, §C.2, §C.4), or a view's cookie whose `view` the origin keeps nothing for (§7.9) |
| `forbidden` | 403 | The grant doesn't allow the request: its `ns`, verbs, key scope or rules (§6.2, §6.4.3, §7), or the key it needs, such as a `*` key (§6.1, §C.2). Or the server refuses branches (§1), or §7.9 doesn't cover a filtered URL's namespace |
| `not_found` | 404 | Unknown, or not readable by the caller; `…/raw` of a document that isn't raw (§7.1); a refused blob copy (§7.8) |
| `in_use` | 409 | A purge or config write refused for references or dependents (cases below the table) |
| `frozen` | 409 | A resource write, a batch with items, or a blob upload or copy in a frozen namespace (§8.4; `successor` included, if set) |
| `not_frozen` | 409 | Namespace purge of a namespace that isn't frozen (§8.5) |
| `batch` | as the earliest failing step | One or more batch items failed; `items` lists them (§7.5) |
| `gone` | 410 | A tombstone, or a purged resource (cases below the table) |
| `purged` | 410 | A `410` of §8.5's table, or a service's for a purged namespace (§A.4). `head` names the purged namespace's `purge-ns` entry. Where a request named several namespaces, `ns` names that namespace |
| `stale` | 412 | Precondition failed; `head` or `config` where the request's section gives one and there is one |
| `limit` | 413 / 422 | A limit of §6.6 was exceeded (§8.4, §C.8 included), or set beyond the deployment's bounds; `limit` names it, with `measured` and `max` as §6.6 gives them |
| `unsupported_type` | 415 | A body whose `Content-Type` the endpoint doesn't take: a `PATCH` other than JSON Patch (§7.2, §7.4), another JSON request body not sent as `application/json` (§7.2, §C.5.2), or an upload other than the sealed-blob type at E3 (§7.8) |
| `invalid` | 422 | Patch application or `test` failed (at E3, a refused patch set, `sealed` op or `keyring` document, §E.3.1, §E.3.2), or `$schema` validation failed. Or any other `422` without a code of its own, such as a refused namespace document (§7.4), prune (§8.6) or branch `at` (§7.6) |
| `schema_ref` | 422 | A `$schema`, `$ref` or `$dynamicRef` of a form §6.1 doesn't accept, or naming a branch namespace (§6.1) |
| `schema_unavailable` | 422 | A schema revision path that doesn't resolve for the writer: unknown, purged, pruned without a kept document, a tombstone, not a schema, in an end-to-end namespace, or unreadable (§6.1); `path` names it |
| `rule` | 422 | A namespace rule failed; `rule` and `path` locate it (§6.4.3) |
| `precondition_required` | 428 | No precondition, or not the one the request takes (§7.2, §7.5, §7.6); any at all on a prune or blob upload (§7.8, §8.6) |
| `behind` | 503 | A service hasn't caught up with what a query or exchange needs (§A.4, §A.5), or with a `min` (§A.5). Or it can't yet fetch the keys a view needs (§E.2.6). Or an exchange has no `exp` left for its cookie (§C.5.2). Or the origin would seal past a key's message bound (§E.2.1). `Retry-After` is set |
| `upstream` | 502 | A service couldn't read a namespace document a grant names (§A.4) |
| `rate` | 429 | A rate limit of §6.6 was exceeded; `limit`, `retryAfter` and `Retry-After` as §6.6 gives them |
| `pruned` | 410 | Pruning removed what the request needs (cases below the table) |
| `blob` | 422 | A blob reference is malformed (§6.5), names a blob that isn't available, or doesn't match it. Or a copy names another id (§7.8). Or an E3 declared list has duplicates, or a blob not of the sealed type or with a nonce (§E.3.1) |
| `blob_mismatch` | 422 | An uploaded blob doesn't hash to its id (§7.8) |
| `signature` | 422 | An author signature failed verification, or is missing where the namespace requires one (§C.3.1) |
| `nonce` | 422 | A resource write whose resulting document lacks a fresh-form `$nonce` differing from the previous document's, in a namespace that requires one, or a sealed one whose server enforces it (§C.7, §E.2.5) |
| `not_offered` | 404 | An optional endpoint or feature this namespace or deployment doesn't offer. Examples: `/gestures` or `…/raw` in a sealed namespace (§7.1, §7.4), `/keys` in one that is neither sealed nor end-to-end (§E.2.3), or `/edge-grants` with authentication disabled (§C.5). At E3, a `/rev/{id}` the server would have to fold, with `horizon` and `last` (§7.1) |
| `source` | 422 | A batch's local `source.at` isn't in the chain of `source.ns`, for a caller with unrestricted `read` on it, or a `source.origin` that is this deployment's own (§7.5) |

**`bad_input`.** Examples of a `400`:

- not I-JSON (§3.1)

- a malformed `source` (§3.5)

- a non-canonical name or URL, or an unknown, repeated or malformed query parameter, or a malformed id or precondition (§7, §7.7)

- an oversized body without a limit of its own (§6.6)

- the request-shape `400`s of writes (§7.2, §7.4), batches (§7.5), uploads and copies (§7.8), signatures (§C.3.1) and edge grants (§C.5)

**`in_use`.** The cases:

- purge of the last copy of a referenced schema revision, or of a namespace with dependents or such revisions (§8.5)

- a config write leaving a reference without a copy, such as narrowing `drafts.for` (§6.1, `referencing` included)

- making a namespace with public dependents non-public, raising its level above a dependent's (Addendum E, Levels), or requiring nonces while one doesn't (§7.4, `dependents` included)

**`gone`.** The cases:

- a tombstoned head, with `tombstone`, `last` and, outside sealed and end-to-end namespaces, `successor` if its last document's `$successor` is well-formed (§7.1, §8.1)

- a create, append or delete on a tombstoned resource, with `head` the tombstone (§7.2, §8.1)

- a revision URL that names a tombstone, with `tombstone` and `last` (§7.1)

- a purged resource (§8.3)

**`pruned`.** The cases:

- the revision is below the horizon without a kept document, or a revision of the log range has its patch set pruned (§7.1, §7.3, §7.7, §8.6), with `horizon` and `archive` as §7.1 gives them

- pruning ended a blob's attachment (§7.8), or removed every revision that served it under an epoch (§E.2.2)

- a branch's first write builds on a pruned document (§7.6)

### 12.2 Limits

The limits of §6.6, with their keys in a namespace document's `limits` and their defaults:

| Limit | Key in `limits` | Default |
|---|---|---|
| patch set size | `patchSetSize` | 256 KiB |
| operations per set | `opsPerSet` | 1,000 |
| document size | `documentSize` | 1 MiB (deployment maximum typically 4 MiB) |
| largest string in a document, member names included, as canonical JSON (Values, §6.6) | `valueSize` | 64 KiB |
| longest JSON Pointer to any value in a document, as canonical JSON | `pathSize` | 2 KiB |
| nesting depth: the arrays and objects on the longest path from the root to a value, the root included (`{"a":[1]}` has 2) | `nestingDepth` | 64 |
| validation steps per document a write produces and per read request or check (§6.6), in `$schema` and rule `schema`s: one schema or subschema applied to one value (§6.2, §6.6), deployment only | `validationSteps` | 5,000,000 |
| rules in the namespace document: in `rules`, roles and key scopes | `rulesPerNamespace` | 256 |
| rules per grant chain, in its blocks, deployment only | `rulesPerGrant` | 32 |
| grant size, deployment only | `grantSize` | 8 KiB |
| items per batch | `itemsPerBatch` | 1,000 |
| batch size (all items' patch sets) | `batchSize` | 16 MiB |
| bytes of patch sets per log page, sealed ones as served (§7.1, §7.3, §7.7), at least one entry per page, deployment only | `logPageBytes` | 16 MiB |
| log page size, in resource entries, a batch entry counting as its items, for log ranges (§7.1), `/heads`, `/branches` and `GET /ns` pages and gesture listings (§7.4), event-stream catch-up (§7.3) and long-poll answers (§7.7), deployment only | `logPageSize` | 1,000 entries |
| branch depth (bases of bases), deployment only | `branchDepth` | 8 |
| direct branches per namespace that are live: neither frozen nor purged (§F.6) | `branchesPerNamespace` | 100 |
| writes and blob uploads per resource, per principal | `ratePerResource` | 10/s, burst 20 |
| writes and blob uploads per principal | `ratePerPrincipal` | 50/s, burst 100 |
| writes and blob uploads per namespace | `ratePerNamespace` | 500/s, burst 1,000 |
| retry window (history always kept, §8.6), at least the deployment minimum | `retryWindow` | `PT5M` |
| documents kept through `keep`, per resource in total (§8.6) | `keepPerResource` | 100 |
| blob size (§7.8) | `blobSize` | 64 MiB |
| blob references per document | `blobsPerDocument` | 1,000 |
| bytes of pending blobs, per uploader and namespace, at least 4 KiB per blob | `blobPending` | 256 MiB |
| age at which a pending blob is deleted; at least `retryWindow` (`422`, `code: "limit"`, otherwise) | `blobGrace` | `PT24H` |
| blob bytes uploaded per principal, as `{ "rate", "burst" }` in bytes | `blobRate` | 8 MiB/s, burst 256 MiB |
| edge-grant exchanges and key requests per principal (§C.5, §E.2.3), deployment only | `exchangeRate` | 10/s, burst 100 |

A namespace document that sets a limit marked deployment only is `422` (`invalid`, §7.4). Sizes are integers in bytes, counts are integers (`rulesPerNamespace` and `rulesPerGrant` count every rule form, those nested in `all`, `any`, `not`, `if` and `then` included), durations are ISO 8601 durations as in `retention` (§8.6), and rates are `{ "rate": <per second>, "burst": <bucket size> }`.

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
| `encryption` | `{ "level": "at-rest" | "sealed" | "e2e", "epoch"?, "pad"?, "historyEpochs"? }`: `epoch` an integer ≥ 1 (default 1), `pad` a boolean (default false), `historyEpochs` an integer ≥ 0 (no cap without it). The last three only at `sealed` and `e2e` | Addendum E |
| `base` | `{ "ns", "at" }` | §7.4, §7.6 |
| `frozen`, `successor` |  | §7.4, §8.4 |
| `drafts` | `{ "for": [names or prefixes] }` | §6.1, §7.4 |
| `signatures` | `"optional"` | `"required"` | §C.3.1 |
| `nonce` | `"optional"` | `"required"` | §C.7 |
| `schemaReads` | `{ "for": [names or prefixes] }` | §6.1 |
| `merge` (Addendum F) | `{ "authors": [{ "sub", "kid" }] }` | §F.3 |
| `merged` (Addendum F) | `{ "at" }`, `at` an `ns_id` of the base in text form (§3.2) | §F.3, §F.6 |
| `cleanup` (Addendum F) | `{ "merged"?, "superseded"?, "abandoned"? }`, as ISO 8601 durations | §F.6 |
| `abandoned` (Addendum F) | boolean | §F.6 |

Addendum F's members may appear in any namespace; they mean something in branches, and a base's own `cleanup` sets its branches' minimums (§F.6). The core validates their shapes, guards `/merge` (§7.4) and removes `merged`, `abandoned` and `cleanup` from a new branch's document (§7.6); it otherwise acts on none of them.

### 12.4 Query parameters

On the core server, its filtered URLs included (§7.9). Services of the addenda define their own (§A.4).

| Parameter | Endpoints | Value | Defined in |
|---|---|---|---|
| `since` | resource and namespace log ranges, event streams and long-poll URLs | an id or `ns_id`, or empty for genesis | §7.1, §7.3, §7.4, §7.7 |
| `live` | long-poll URLs | `long-poll` | §7.7 |
| `cursor` | long-poll URLs | an `X-Cursor` value | §7.7 |
| `after` | `/heads`, `/branches` and `GET /ns` pages; gesture listings | a name; an `X-Log-Next` value | §7.4 |
| `dry-run` | `POST /ns/{ns}/batch` | flag, `1` | §7.5 |
| `force` | `POST /r/{ns}/{name}/purge`, `POST /ns/{ns}/purge` | flag, `1` | §6.1, §8.5 |
| `prefix` | `/heads` and `GET /ns` pages; `DELETE /edge-grants` (repeatable) | a name; an edge prefix | §7.4, §C.5.4 |

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
| `X-Namespace-Revision` | response to a write that records a namespace entry, long-poll answers, and filtered answers at an `at` | §7.2, §7.4, §7.5, §7.6, §7.7, §7.9 |
| `X-Config-Revision` | response | §7.4, §7.5 |
| `X-Cursor` | response: long-poll | §7.7 |
| `X-Log-Next` | response: paged logs and listings | §7.1, §7.4 |
| `Last-Modified`, `Repr-Digest` | response: plaintext reads | §7.1 |
| `Retry-After` | response: `429`, and a service's `503` | §6.6, §12.1, §A.5 |
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
| `prune` | pruning a resource's history | §8.6 |
| `*` | keys only | §C.1, §C.4 |

### 12.7 Entry kinds

A resource log's entries are of kind `rev` or `tombstone` (§7.1), or `hidden` in a filtered one (§7.9), and its event stream's events of type `revision`, `tombstone`, `purge` or `prune` (§7.3), or `hidden` in a filtered one. Namespace entry kinds (§3.5), also the namespace event types (§7.4):

| Kind | Written by | Defined in |
|---|---|---|
| `head` | a create, append or restore | §3.5, §7.2 |
| `tombstone` | a delete | §8.1 |
| `purge` | a resource purge or its propagation | §8.3 |
| `config` | a namespace-document write | §7.4 |
| `batch` | a batch | §7.5 |
| `branch` | creating a branch | §7.6 |
| `purge-ns` | a namespace purge | §8.5 |
| `prune` | pruning | §8.6 |
| `hidden` | never written: stands, in filtered logs, for an entry the reader can't read | §7.9 |

### 12.8 Cache-tag kinds

Tags are `{kind}:{value}` (§9).

| Tag | On | Defined in |
|---|---|---|
| `ns:{ns}` | every response of the namespace that §9's table tags, and filtered reads at its `at` | §9, §7.9 |
| `r:{ns}/{name}` | responses for the resource, and those of a branch that reads it through `{ns}`, where §9 Base tags allows | §9 |
| `heads:{ns}` | `/heads` pages, filtered ones included, and those of a branch with `{ns}` as a base, where §9 Base tags allows | §7.4, §9, §7.9 |
| `idx:{ns}` | index answers (Addendum A) | §A.4 |

### 12.9 Reserved keys and schema keywords

| Name | Where | Defined in |
|---|---|---|
| `$schema` | top level of a document | §6.1 |
| `$nonce` | top level of a document | §6.4.1, §C.7 |
| `$successor` | top level of a document | §8.1 |
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

- **Create conflicts:** a create's `412` or `410` (`gone`), and a batch dry run's per-item preconditions, show the existing head to a holder that may have only `create`. Ids aren't secrets (§C.5), but should they omit it?

- **E3 document size:** sealing grows a whole-document create or restore by about half; should `documentSize` allow for it at E3, as `patchSetSize` does, or clients check the sealed size (§6.6)?

- **Blobs:** resumable or chunked uploads for very large blobs? A sealed-blob format whose ranges decrypt alone (§E.2.2)?

- **Scoped branches:** read-through limited to the resources the creator could read at `at`, so editors limited to some documents could branch without a service (§F.8)?

- **Server-written entries:** what `author`, which §5 persists, do entries the server writes itself carry (propagated and followed purges, its own prunes and rotations, §7.4): the causing purge's, a deployment identity, or none?

- **Contended documents:** a write applied to the current head, guarded by its own `test`s, the schema and the rules instead of `If-Match` on the exact head, with a retry key of its own (TOOLS §11.1)?

- **Auth:** see the open questions of Addendum C.

- **From the companions:** server features asked about in §F.10 and §H.9: grants covering a namespace and its branches, a stable alias that follows `successor`, server-side three-way diffs, and a tentative delete or atomic content replace.

---

# Addendum C — Capabilities and access (recommended)

How authority is carried and checked, filling the core's hooks: the `principal`, `writes` and `read` envelopes (§6.4.1), the gate order (§6.2) and a grant reference per revision (§5). **Writes can be fine-grained, reads are per revision:** writes are checked at the gate against the full envelope, reads against a `read` envelope holding the revision's document (§C.2 item 5), or by grants issued per document (§C.5.1).

Policy combines **roles** named in the namespace document (§C.1.1), **attributes** of the principal, the document and the time (§C.1.2, §6.4.2), and **relationships**: a service that derives access from them and issues grants (§C.5.1).

## C.1 Grants

A **grant** is a signed token presented as `Authorization: Bearer <grant>`. It consists of a **root block**, signed by a key listed in the namespace document, and zero or more **narrowing blocks**, each chained to the previous one's signature:

```
// root block, signed by key "kid"
{ "kid": "ops-2026", "sub": "user:bob", "groups": ["match-desk"],
  "roles": ["desk"], "attrs": { "regions": ["se", "no"] },
  "ns": ["matches", "docs"], "can": ["read", "append"],
  "nbf": "2026-10-04T08:00:00Z", "exp": "2026-10-05T00:00:00Z",
  "rules": [] }
// narrowing block (delegation to a service)
{ "via": "svc:translator", "can": ["append"], "exp": "2026-10-04T20:00:00Z",
  "rules": [ { "op": "writes", "within": ["/i18n/sv"] } ] }
```

-
**Fields:**

  - `kid`: the signing key's id in the namespace document

  - `sub`, `groups`: the principal's identity, taken from the **root block only**

  - `roles`: role names (§C.1.1), giving the grant its effective roles (§2.1)

  - `attrs`: the principal's issuer-asserted attributes (§C.1.2), taken from the **root block only**

  - `ns`: namespaces the grant applies to

  - `can`: `read`, `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `prune`, or `*` for keys only (in a block, `401`). A root block without `can` MUST list `roles` (`401`), and takes its verbs only from them.

  - `nbf`, `exp`: **absolute** RFC 3339 times. The block is valid from `nbf` (optional) until `exp`.

  - `rules`: rule forms of §6.4.2

  - `via`: in narrowing blocks only, the delegatee; the principal's `via` lists them in block order

  - `signers`: in the root block only, the principal's signing keys (§C.3.1)

  - `enc`: in the root block only, the principal's X25519 public key that keys are wrapped to (§E.2.3); one of another form is `401`

-
**Narrowing only restricts.** A narrowing block may reduce `ns`, `can` and `roles`, set a later `nbf` or an earlier `exp`, and add `rules` and a `via`. It carries no other member, and one it leaves out restricts nothing. A root block MUST carry `kid`, `sub`, `ns` and `exp`, and only members listed above for it. A block that breaks this makes the grant invalid (`401`); values that don't narrow, other than `"*"`, restrict nothing more (§C.2). In `ns`, `"*"` is `401` in a narrowing block, an operator grant's included, and in a root block no operator key signs (§C.4).

-
**Format.** Grants are Biscuit v3 tokens (§C.8).

-
**Verification** needs only published keys: the namespace's, its bases' and the deployment's operator keys (§C.4), so consumers verify grants too.

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
**Expanded at the gate,** against the configuration in force when the request is checked (invariant 6), so changing a role's definition changes at once what every outstanding grant naming it can do. Unknown names grant nothing, so removing a role revokes it. `roles: []` grants no verb (§C.2); a grant without role checks leaves `roles` out.

-
**Combination.** Roles are alternatives, everything else is conjunctive (§C.2 items 2 and 4).

-
**Issuers are bounded** by the key scope `roles` (§C.4).

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

- **Principal attributes.** The root block's `attrs` carries issuer-asserted facts, such as region or clearance, bounded by the key scope `attrs` (§C.4).

- **Relations** between attributes use `compare` (§6.4.2); §6.4.4 has a worked rule.

- **Time windows.** `nbf` and `exp` bound when a grant is valid; rules on `/now` bound what may be written when, such as deadlines, and fail for reads (§C.2 item 5).

## C.2 Checking requests

**Invariant.** A request is allowed only through what every block, the key's scope and, if the grant carries roles, at least one effective role allow together, and a grant its key's scope doesn't allow allows nothing. No role, verb or namespace a narrowing block drops counts, and "unrestricted read", "qualifying role" and "fixes `/resource`" (§2.1) are judged so that no grant reads more than its rules permit. Members that widen exposure or touch keys change only under a `*` key, or the operator grant that creates the namespace.

Grants are checked at step 1 of §6.2 (items 1–3 and the first part of item 4), at step 2 (item 2's retry check and settling), at step 6 (the `*`-key guard, then item 4), and on every read (item 5):

-
**Verify the chain:**

  -
first, without verifying anything, these request-shape errors (§6.2), in this order and before the `401` cases below:

    - `grantSize` (`413`, §C.8);

    - blocks that can't be parsed or break the forms of §C.1 and §C.8 (`401`);

    - `rulesPerGrant` (`413`);

    - a rule that isn't valid (§6.4.2, `401`);

    - then the `ns` check of §7 (`403`).

Reads of a public namespace ignore the grant, except as §7 says.

  -
the root signature by a key in the configuration in force

  -
every block's signature

  -
`nbf` ≤ now < `exp` for every block

  -
revocation (§C.4)

  -
the key's scope, including `can`, `sub`, `maxTtl`, `groups`, `roles`, `attrs` and `readScope`, in that order. A grant that fails any of them, as one that breaks `readScope` (§2.1 Fixes `/resource`) does, is `403` on every request that doesn't ignore the grant, writes included, but `404` for a read of a resource in a private namespace (§7 step 4)

Failures are `401` when there is no usable grant: missing, malformed, badly signed, revoked, expired, or not yet valid (`nbf`). They are `403` when a valid grant doesn't allow the request.

-
**Check the verbs.** A verb is allowed when `ns` and `can` (the intersection over all blocks), and the key's `can` for a namespace key, allow it, and, if the grant carries roles, an effective role (§2.1) lists it. A request checks its action's verb (§6.4.1), except as follows:

  -
**Several verbs.** Some writes check more than one verb:

    - A resource `PATCH` under `If-Match`, and a batch item whose first step is a patch set under `ifMatch`, check `append` and `restore`.

    - Either of these without a usable precondition, and a blob upload (§7.8), check `create`, `append` and `restore`.

The write's **candidate verbs** are those for which this item and item 4's step-1 rules pass, with `/action` set to the verb and only roles that list it counting. The write passes if it has one.

  -
**Settling.** §6.2 step 2.2 settles the verb of such a `PATCH` or item, refusing a non-candidate. An idempotent retry of one (§7.2, §7.5) answers `200` only if the recorded entry's verb (a restore when its parent is a tombstone, else an append) is a candidate. Any other retry has its one verb.

  -
**Later steps** of a batch item have the verb the request gives them, checked like `"delete"`: a patch set whose previous step is a `"delete"` is a restore, any other an append.

  -
**Unrestricted `read`.** Branching (§7.6) also checks unrestricted `read` (§2.1) of the namespace it names as base, public or not. For this check:

    - A key-scope or block rule that refers to `/now` fails it, as for any read (item 5).

    - Key-scope and block rules that refer only to `/action` or `/principal` must pass with `/action` set to `read`, against the write's own envelope, the rest being left to step 6.

    - A role that counts for `read` must pass all its rules against a `read` envelope, as in item 5.

  -
**Operator grants** (§C.4) check `config` for a namespace's creation, `purge` or `purge-ns` for a forced purge (§6.1), and `config` for `GET /ns` (§7.4).

-
**Build the principal:** `{ id: root sub, groups: root groups, roles: effective roles, attrs: root attrs, via: [...], grant: grant id }`.

-
**Rules** of the key scope, the blocks and the roles:

  - At step 1, those that refer only to `/action`, `/resource`, `/principal` or `/now`, with `/action` set to the verb checked.

  - At step 6, all of them, with the write's verb, as settled where it had candidates, then the namespace rules (§6.2).

  - Roles are alternatives: if the grant carries roles, at least one effective role that lists the verb must pass the role rules evaluated.

  - A failing grant, key or role rule is `403`.

-
**Reads** evaluate the key-scope, block and role rules against a `read` envelope (§6.4.1), roles as in item 4, **per revision**: its `doc` is the document of the revision the read concerns. A revision and a grant's rules never change, so whether they allow reading it never changes while its document is stored. This holds for every read, filtered (§7.9) or not: a grant whose rules test that `/doc/team` is `"a"` can't read a head whose revision says `"b"`, by URL either, answered as any read-rule failure (below). A read that serves several revisions, such as a resource's log range or event stream, passes only where each does, and each entry's parent too, as patches show it (`test` values, removed paths), except as §7.9 filters it. Such an envelope has no `now`: wherever rules are evaluated for a read, one that refers to `/now` (§2.1), a rule on the whole envelope included, fails as a whole. So a role with such a rule doesn't count for `read`, and a read's time window is its grant's `nbf` and `exp`. A grant with one in its blocks or key scope is refused every read that doesn't ignore the grant (§7 step 1), `GET /ns/{ns}/principal` excepted (§7.4), as §7 refuses a read: `404` at a resource's URLs, `403` elsewhere.

**`*` keys.** These writes need a grant chained to a key with `can: ["*"]`:

- A config write (§7.4, §7.5) covering or overlapping one of the members §7.4 lists, or setting `read` to `public`. For a namespace's creation, the operator grant that creates it (§C.4) may be used instead.

- A branch's `patches` that cover or overlap one of those members, with a `*` key of the base (§7.6).

- The prunes §8.6 names.

This guard runs first at step 6, after any namespace-document validation (§7.4). If it fails, the answer is `403` (`forbidden`). Forcing a purge has its own guard, at step 1 (§6.1).

## C.3 Attribution and signatures

- **Grant per revision.** Each revision stores its grant's id, `trunc160(sha256(canonical(root block)))`.

- **Stored grant form.** The server stores each grant in a **non-bearer** form that no longer verifies as a credential (§C.8).

- **Optional author signatures.** A client MAY sign `sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖ 0x0A ‖ bytes(parent) ‖ 0x0A ‖ canonical(patches))` with its own key and send `Signature: <alg>:<kid>:<sig>`. `origin` is the deployment's canonical origin in RFC 6454 ASCII serialisation (`scheme://host[:port]`, the scheme `https` or `http`, lowercase, default port omitted), as published at `GET /` (§7).

  - The input is the **full** digest.

  - Signatures are stored **alongside** revisions, never inside ids, and served in logs.

### C.3.1 Signer keys and verification

A signature is checked along one chain against the keys in force when the revision was written, every link immutable or in a hash-chained log except the operator key history (§C.4) and `created` times (§5):

- the revision's `Signature`, `<alg>:<kid>:<sig>`;

- an entry with that `kid` in the `signers` of the root block of the grant it was written under, named by its grant reference (§C.3);

- the key that signed that root block, one of:

  - a key of the configuration the write was checked against, which is the namespace document in force at its namespace log entry, after the config change of a batch that makes one (§6.2, §7.5). In a branch, that is its own keys and those its bases had at the entry's `created` (§C.4);

  - or a deployment operator key in force at its `created` time (§C.4);

- the namespace log for a namespace key, or the deployment's operator key history (§C.4) for an operator key.

- **Signer keys live in grants.** A root block may list `signers: [{ "kid", "alg", "pub" }]`, with `alg: "Ed25519"` and `pub` the public key in base64url.

  - `kid`s are unique within `signers` and contain no `:`. `pub` and the `<sig>` of a signature are base64url without padding (43 and 86 characters). An entry that breaks these rules, or has any other member or `alg`, makes the grant invalid (`401`).

  - Issuers MUST list a key only after the principal has proved possession of it, and MUST NOT list one `pub` for two subjects.

  - Narrowing blocks MUST NOT carry `signers` (`401`), and namespace documents can't list them, so bots too get grants with `signers`.

- **Tombstones** are signed over the same input with the ASCII bytes `tombstone` in place of `canonical(patches)`, as their ids are (§3.4).

- **At the gate.** When a write carries a signature whose `kid` its grant's `signers` list, the server MUST verify it at §6.2 step 2.3; a bad one is `422` with `code: "signature"`, and so is one whose `alg` isn't that signer's. A signature with any other `kid` is stored unverified, and readers treat it as unattributed.

  - **The parent** in the input is the one the write's precondition names: its `If-Match` id, empty for a create, and in a batch the item's `ifMatch` (empty with `ifNoneMatch`) for its first step and the previous step's id for each later one. A write without a usable precondition isn't checked here.

  - A `Signature` header or step member that isn't `<alg>:<kid>:<sig>` with an 86-character base64url `<sig>` is `400` (`bad_input`), as a request-shape error.

  - **Retries.** An idempotent retry (§7.2) answers the entry as first recorded, whatever well-formed signature it carries or lacks, even after `required` was turned on.

  - At E3 the input covers the sealed patch set as sent (§E.3.1).

  - In a batch, each step carries its own `signature` (§7.5). The `Signature` header covers only a single `PATCH` or `DELETE` of a resource, and is `400` (`bad_input`) on any other write.

- **Requiring signatures.** A namespace document may set `"signatures": "required"` (default `"optional"`). Every revision and tombstone written to such a namespace then needs a valid signature by a signer of its grant (`422 signature` otherwise, at the same point of the gate). A batch's items are judged under the configuration its config change produces (§7.5); if that change fails, only a replay can still succeed, answered as first recorded.

  - Namespace documents aren't signed. Revisions written before it was turned on, and those a branch reads through from its base, aren't covered, so a reader relying on it checks the log position, not only the current document.

  - Merges, replays and imports (§F.3, §G.4.4) write new revisions, so a step's `signature` is always the writer's own; original signatures aren't re-sent, and stay verifiable through the batch's `source`: a bundle's for an import, a branch's until it is purged (§F.6).

  - Services that write to such a namespace need root grants of their own (above, §C.6). While authentication is disabled (§1), every resource write to it fails.

- **Reading grants.** `GET /ns/{ns}/grants/{gid}` answers `{ "id", "root", "stored" }`. `stored` is the non-bearer form (§C.8) of the first token recorded with that id: its authority block, a protobuf `SignedBlock` in base64url without padding. A verifier checks its signature under the key `root.kid` names, that its one `grant_block` string equals `canonical(root)` byte for byte, and that `id` is `text(trunc160(sha256(that string)))`.

  - It serves the grants recorded by namespace log entries of this namespace and, in a branch, of its bases up to their `at`, recursively; any other is `404`. It needs unrestricted `read` on the namespace, and is immutable. In a purged namespace it is `410` (§8.5).

  - As everyone has unrestricted `read` of a public namespace, issuers keep the `groups` and `attrs` of grants for public namespaces to what may be public.

  - Sealed namespaces seal it as §E.2.2 says, a grant recorded only by a branch's base under the branch's current epoch. End-to-end namespaces serve it in the clear (§E.4), with `Cache-Control: private` instead of the immutable class (§9), and `no-store` for shared caches (`CDN-Cache-Control`, `Surrogate-Control`).

- **Verifiers** follow the chain with the namespace document's history, and in a branch its bases' too (from their logs, or the key entries a bundle carries) and the operator key history. Verifiers don't check `revoked` (§C.4): a later revocation doesn't unsign history. A signature that fails, or whose chain can't be completed, is reported as such, and says nothing about the content (invariant 4).

## C.4 Keys, scopes and revocation

-
**Keys.** The namespace document lists `keys`. Each entry has:

  - `kid`, unique within `keys`;

  - `alg: "Ed25519"`;

  - `pub`, the public key in base64url without padding (43 characters);

  - `can`;

  - optionally, the scope fields below, with `maxTtl` as an ISO 8601 duration.

An entry stored without `can` allows no verb. Changing keys and scopes needs a `*` key (§7.4).

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

-
**Revocation.**

  - Grants should be short-lived and refreshed by their issuer.

  - For immediate revocation, add a **revocation id** to `revoked: [...]` in the namespace document. A root block's revocation id is its grant id in text (§C.3), and a narrowing block's is `text(trunc160(sha256(its signature)))`. A chain containing any revoked block is rejected.

  - Revocation is per namespace. Issuers revoke in every namespace a grant lists.

  - **In a branch**, a chain is also rejected if any of its blocks is revoked in any of the branch's bases.

-
**Keys follow the base.** A branch accepts its base's **current** keys as well as its own. A `kid` the branch shares with its base is the base's, accepted only while the base has it with the same `pub`. If the base later adds a `kid` the branch added itself (§7.6), only the base's entry is accepted until the base removes it again, when the branch's own applies once more. A `kid` copied from the base at creation never falls back. This applies recursively through every base. Keys added only to a branch, with a base `*` key (§7.6), are its own. A branch can't refuse a base key.

-
**Bootstrapping.** Creating a namespace needs a deployment-level operator key configured outside the system. A grant for a namespace that doesn't exist yet names it in `ns`, or uses `"*"`, which only a root block signed by an operator key may do (`401` otherwise, §C.1). Branches are the exception: they are created with a `branch` grant on their base (§7.6).

-
**Operator grants**, with the verb each action needs (§C.2), authorise exactly:

  - creating a namespace with its genesis document;

  - forcing a purge or namespace purge (§6.1);

  - listing the deployment's namespaces (`GET /ns`, §7.4).

Any other request under one, at the origin or another service (§C.6), is `401`, as for a key the namespace doesn't list, and at a file gateway `403` (§H.7), with three exceptions:

  - Requests that ignore any grant, such as public reads, `GET /` and `DELETE /edge-grants`, ignore it too (§7, §C.5.4).

  - An index's `GET /_refs` and the URLs it redirects to answer as without it (§A.4).

  - `GET /ns/{ns}/principal` describes it (§7.4).

A grant whose root `kid` names both an operator key and a key of the namespace document is verified against the namespace's key first. It is a namespace grant when that key verifies it.

Under an operator grant, a forced purge and `GET /ns/{ns}/principal` answer `404` for a namespace that doesn't exist. The `ns` check (§7) still answers `403` first, and a purged namespace `410`.

-
**Operator key history.** A deployment publishes its operator keys as a JWK Set (RFC 7517) at the `jwks_uri` it gives at `GET /` (§7), by default `/.well-known/patchlog-keys`; verifiers take the URI from `GET /` rather than guess. Only a `200` whose body is a JWK Set with a `keys` array is a read of the history; anything else is a failed read, never an empty history.

  - Each key is an OKP Ed25519 JWK with `kid` and `use: "sig"`, plus `"patchlog": { "from", "until"? }`, the RFC 3339 period it was in force. The set is served as `application/jwk-set+json`, publicly cached for minutes, e.g. `public, max-age=300`.

  - `from` MUST be no later than the first entry written under a grant the key signed; a deployment publishing a key it already used gives the time it was configured, or else of the deployment's first entry. A key authorises only within its period: grants it signed are refused (`401`) before its `from` and after its `until`, and verify only for revisions created within it. An operator grant is revoked everywhere only by ending its key's period with `until`, so operator grants are kept short.

  - It is a history, not a current set: keys are never removed, and `kid`s never reused.

  - It lists no namespace keys.

  - Trust in it rests on TLS and the origin, unless a verifier pins operator keys obtained out of band.

## C.5 Reading

- **Read modes.** A namespace document declares `"read": "public" | "grant"`, by default `"grant"`. Independently, it may be **sealed** (Addendum E): content may then be served publicly, and only key holders decrypt it.

  - **Public:** cached publicly (§9).

  - **Grant:** served with the grant in `Authorization` (§9), or through CDN edge grants, signed cookies (or signed URLs, where a deployment's edge verifies them) that the origin issues in exchange for a verified grant with `read` (§C.5.2–§C.5.4). The edge grant is not part of the cache key.

- **Per document, not per field.** Never filter fields per reader; keep sensitive fields in a separate resource in a private namespace, and link to it.

- **Ids are not secrets.** Ids leak through logs, referrers and parent links: defence in depth, never access control.

- **The stream is metadata.** Reads of `/ns/{ns}` and everything under it, its events stream and long-poll included, require **unrestricted** `read` (§2.1), while a resource's own URLs, its events included, need `read` on that resource.

  -
**Four exceptions:**

    - filtered reads (§7.9);

    - three answered by the origin with the grant in `Authorization`, `no-store`:

      - the gestures listing, filtered per revision (§7.4);

      - `GET /ns/{ns}/principal` (§7.4);

      - `POST /ns/{ns}/keys` (§E.2.3).

Otherwise a reader limited to some documents follows them through a filtering proxy (§C.6).

### C.5.1 Reads decided by content

- **Two ways.** Read rules may test `/doc`: the origin judges them per revision (§C.2 item 5), and a reader they limit follows the namespace through §7.9. Or an **issuer** that follows the namespace evaluates the policy per document and issues grants fixed to the resources that pass, with `nbf`/`exp` for time windows, which edges can serve from cache (§C.5.2). "Readers see matches in their own regions" becomes a role rule `{ "op": "compare", "path": "/doc/region", "in": { "path": "/principal/attrs/regions" } }`, or issued grants:

```
{ "kid": "access-01", "sub": "user:li", "attrs": { "regions": ["se"] },
  "ns": ["matches"], "can": ["read"],
  "nbf": "2026-10-04T18:00:00Z", "exp": "2026-10-04T18:15:00Z",      // embargo lifts at 18:00
  "rules": [ { "op": "test", "path": "/resource", "value": "derby" } ] }
```

- **Consequence.** An issued grant lags the content by up to the issuer's lag plus the grant's lifetime. Where that is too slow, test `/doc` instead, move the sensitive part into its own resource, or seal it (Addendum E) and revoke by rotating keys.

### C.5.2 Issuing edge grants

-
**Scope.** An edge grant is scoped to the **smallest edge prefix** (§2.1) the grant allows:

  - `/r/{ns}/{name}`, one per name, when its rules fix `/resource` (§2.1) and none refer to `/doc`

  - otherwise `/r/{ns}` and `/ns/{ns}`, or, to a partial reader where §7.9 applies, `/ns/{ns}/view/{view}` in their place

-
**Request.** `POST /edge-grants` on the origin, with the grant in `Authorization`, or several grants as `{ "grants": [ … ] }` in the body, with `Content-Type: application/json`. It issues, for each grant, for every namespace that all its blocks carrying `ns` name.

-
**Answer.** `200` with `{ "prefixes": [ … ], "exp" }` and one `Set-Cookie` per prefix.

  - Each cookie has no `Domain` attribute. It has `Path` set to the prefix, `Secure`, `HttpOnly`, and `SameSite=None` when the deployment names credentialed origins, `Lax` otherwise. It is named per prefix (§C.5.3).

  - Cookies last until the earliest `exp` among the grant's blocks or 15 minutes, whichever is sooner, less any whole seconds a minter MAY take off so that no cookie shares its `exp` with a `403` cookie for the same prefix (§7.9 `view`); live ones may share one, as they become `403` together.

  - Where no `exp` is left, as every future whole second a cookie may get is past its grant or that of a `403` cookie for the same prefix, the answer is `503` (`behind`) with `Retry-After`, setting no cookie. The request has then drawn its `exchangeRate` tokens (Rate).

  - A prefix several grants give gets one cookie, lasting as long as the longest.

  - The body's `exp` is the earliest, as an RFC 3339 time.

-
**Refusals,** with a body sent with `Authorization` (`400`) checked before one that isn't `application/json` (`415`), and both before `401`:

| Condition | Answer |
|---|---|
| Authentication is disabled (§1) | `404`, `code: "not_offered"`, before the body is read |
| A body that isn't `application/json` | `415` |
| Neither `Authorization` nor a body | `401` |
| A body with no grants or more than 50, or together with `Authorization` | `400` (`bad_input`) |
| A namespace a grant names doesn't exist, or the grant fails verification there | `401` or `403`, as for any request (§7, §C.2) |
| The grant has no `read` there; the rules of its blocks or key scope refer to `/doc`, or to `/resource` where the grant doesn't fix it (§2.1) | `403` |
| The grant carries roles and none is a qualifying role (§2.1) | `403` |
| The rules of the grant's blocks or key scope don't pass now against a `read` envelope (§6.4.1) for its principal, with `/resource` set to each name it fixes, if any | `403` |
| A namespace a grant names is purged | `410`, `code: "purged"`, if the grant verifies in it (§8.5) |
| More than 100 distinct prefixes | `400` (`bad_input`), once nothing other than the `429` below is refused |
| A body larger than 50 grants of `grantSize` can be | `400` (`bad_input`), before it is parsed; a single grant over `grantSize` is `413` once decoded |
| A principal's `exchangeRate` bucket is empty | `429`, `code: "rate"`, `limit: "exchangeRate"`, once nothing else is refused, the prefix cap's `400` included (Rate) |

**All or nothing.** The answer covers every grant and namespace sent, never skipping a refused one:

  - `401` if any refusal is `401`;

  - else `403` if any is `403`;

  - and `410` only when every namespace refused is purged and the grant verifies in each. Only this `410` carries `ns` and `head`, naming the first refused one in the order the grants and their root blocks list them.

-
**Rate.** Once nothing is refused, the prefix cap's `400` included, the request draws one token from the `exchangeRate` bucket (§6.6) of each distinct principal among its grants, however many grants it carries. The buckets are keyed by root `sub` and the verifying key's thumbprint (`key`, §7.4), across namespaces, since a `kid` is unique only within one. The request draws from no write bucket.

-
**Browsers.** Credentialed responses to a page on another origin name that origin from the deployment's list, with `Access-Control-Allow-Credentials: true` and `Vary: Origin`, never `*` and never an echoed `Origin` (§7, browsers).

-
**What a cookie authorises:** only `GET` and `HEAD` under its prefix, which its minter's key vouches for (§C.5.3).

-
**Many documents.** Browsers keep about 150–180 cookies per host, so a reader of many documents is better served by a namespace-wide grant, if it may read the whole namespace, or by a proxy (§C.6).

### C.5.3 Edge-grant format and checks

-
**Format.** The cookie's format is the deployment's; the default is:

  - the name is `__Secure-pl-eg-` followed by the first 8 bytes of `sha256(prefix)` in lowercase hex;

  - the value is `base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))`, without padding, where `c` is the canonical JSON (§3.1) of `{ "kid", "p": prefix, "exp": <seconds since the epoch> }`, those three members exactly. A value whose `c` has other members, or isn't canonical byte for byte, is ignored; a minter that needs more uses a format of its own;

  - `kid` names the key, which the minter and the edges hold.

-
**Keys.** Each key vouches only for its own prefixes:

  - the origin's for the core edge prefixes (§2.1);

  - a service's for prefixes under a root of its own, which never overlaps `/r/` or `/ns/`.

Origins and edges SHOULD accept several keys at once and mint with the newest. A key is rotated by adding the next one, to edges before the minter, and dropping the old one once its cookies have expired.

-
**Service-minted grants.** A service behind the same edge can mint edge grants for output derived from documents, with a key the origin never holds. It mints one only after checking that the reader may read every document the output derives from, lets it expire no later than the earliest of those reads, and withdraws its own cookies (§C.5.4).

-
**What an edge MUST check** on every request, cache hits included, before serving it or forwarding it as verified:

  - the method is `GET` or `HEAD`, and there is no `Authorization` header field, even an empty one;

  - the path has no empty, `.` or `..` segment and no percent-escape, `/` itself excepted;

  - a cookie whose name is derived from its own `p`, as above; others are ignored;

  - `c` in the format above, a `kid` it holds that vouches for `p`, and a valid MAC;

  - `exp` is in the future;

  - `p` covers the path segment by segment: the path is `p` or starts with `p/` (§2.1).

-
**Forwarding.** A request that passes is forwarded, on a cache miss, with:

  - its cookies, from which the origin still authorises it and takes the `exp` that ends an event stream (§7.3);

  - the edge's verification headers (§9): by default `X-Edge-Verified` carrying the secret it shares with the origin, and `X-Edge-Prefix` the `p` it checked. Each is exactly one header line without a comma. Both are stripped from incoming requests.

One covering cookie is enough. A request that fails any check is forwarded without the verification headers, and the origin answers it as it would without an edge. An edge MAY answer a failure of check 2 itself; the origin answers `400` either way (§7).

-
**Without the edge.** A cookie the edge didn't verify, because no verifying edge is in front or the request went around it, is verified by the origin, which answers with `CDN-Cache-Control: no-store` (§9). A cookie counts only on a request that passes check 1 above.

-
**Attribution.** Cookie reads have no principal, so a deployment that logs reads attributes them to the prefix.

-
**Revocation** reaches an edge only when a cookie expires, since a cookie carries no grant id and `DELETE /edge-grants` clears only the calling browser (§C.5.4).

### C.5.4 Withdrawing edge grants

`DELETE /edge-grants?prefix=…`, `prefix` repeatable and taken from the `prefixes` issuance returned, answers `204`, `no-store`, with an expired `Set-Cookie` of the same name and attributes for each prefix named, once even if it is named twice.

- A request without `prefix`, or with one that isn't an edge prefix (§2.1), is `400` (`bad_input`).

- It needs no grant, ignores any it is sent, and answers the same while authentication is disabled (§1).

- Only `DELETE` withdraws, and its preflight is allowed only for the credentialed origins of issuance.

- A client calls it at sign-out, or before another user signs in on the same browser. It removes the browser's copies only: a copied cookie stays valid until it expires.

## C.6 Consumers and plug-in services

-
**Services verify as the origin does.** A service that verifies grants locally applies keys, scopes, revocations, `grantSize` and `rulesPerGrant` exactly as §C.2 does, `readScope` included.

-
**Least privilege.**

  - A service gets `read` for what it follows.

  - A service that writes back gets a narrowing block with `writes within` its own paths, and without `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns` or `prune`.

  - A service that **proposes** changes can write to a branch (Addendum F) for a person to review and merge, needing no write access to the base.

-
**Upstream failures.** A service's `502` (`upstream`) carries nothing of the answer that caused it.

-
**Filtering proxies.** Where the origin doesn't filter itself (§7.9), a service serving a namespace's `/ns/{ns}/…` view filtered per document can hide names and content but not timing: the namespace revision, `X-Namespace-Revision` and long-poll wake-ups move on edits the reader can't see. It pages and derives cursors itself, such as for `/heads`, and never passes upstream ones on. Content whose timing must be hidden goes in its own namespace.

-
**Services that re-publish content MUST enforce reader permissions.** Search results and other derived output are filtered by the reader's verified grant, per revision as §C.2 item 5 judges reads. Private results are cached per `view` (§7.9, §A.4), not per request, and never with embedded bearer URLs.

## C.7 Private content and guessable hashes

- **Guessing from ids.** A revision id hashes its parent id and its patch set. The parent id is public, and no encryption level hides it (§E.4). So anyone can confirm a guess of a low-entropy patch set, such as an email address, against the next id, even if genesis carried a nonce.

- **A nonce in every patch set.** In private namespaces with guessable content, every patch set SHOULD `add` `/$nonce` with 128 fresh random bits, base32 (26 characters). Such a write is left out of `writes` (§6.4.1), and validation doesn't see the key (§6.2).

- **Requiring it.** A namespace MAY set `"nonce": "required"` (default `"optional"`). Then, at gate step 3 (§6.2), the document a resource create, append or restore results in MUST have a top-level `$nonce` of the fresh form that differs from the parent's, or from the last live document's for a restore. Otherwise the write is `422` with `code: "nonce"`. The sealed-namespace rule (§E.2.5) is the writer's. A server that enforces it as well answers `422 nonce` at the same point. A failed `test` or patch application is still reported first, as `invalid`.

  -
Deletes, and config, branch and prune writes, are exempt. A restore that would be `[]` sends just a fresh nonce, and so does a step that keeps a document unchanged.

  -
The check applies to every patch set, whatever its origin. History written where nonces weren't required, such as a branch made before the setting or a full history from another deployment, enters such a namespace only re-authored with a fresh `$nonce` per step or imported as a snapshot. It is never fast-forwarded or imported in full. Set it when the namespace is created. Merge tools add a fresh `$nonce` to a resolution or squash set (§F.3) where required.

  -
Three rules of §7.4 apply. A branch copies it and can't turn off one its base has. A base can't start requiring it while a dependent doesn't. Setting or changing it needs a `*` key. It is `422` in an end-to-end namespace (Addendum E, Levels).

  -
The upstream namespace of a snapshot import (§G.4.4) takes its target's setting.

  -
A writer without unrestricted `read` (§2.1) of the namespace document learns the setting from `GET /ns/{ns}/principal` (§7.4); one that doesn't ask adds a fresh `$nonce` to every patch set in a private namespace.

- **Blobs.** A blob id is a hash of its bytes (§3.7), so the same applies. In private namespaces with guessable blobs, uploads SHOULD carry a `Blob-Nonce`; §7.8 requires one in sealed namespaces and where nonces are required.

- **Encryption:** sealed namespaces refresh `$nonce` in every patch set (§E.2.5). At E3 ids are over ciphertext with a random IV, so no nonce is needed.

## C.8 Encoding: Biscuit v3

Grants are Biscuit v3 tokens: chains of signed blocks to which any **holder** can add a narrowing block offline, but from which nobody can remove or alter one.

- **One block, one fact.** Each block of §C.1 is one Biscuit block containing exactly one fact, `grant_block(<string>)`, whose string is the block's canonical JSON (§3.1). The string MUST be I-JSON and equal to its own canonical form (`401` otherwise). The authority block carries the root block; each appended block carries one narrowing block, in order.

  - A block with anything else (other facts, rules, checks, scopes, public keys, a non-empty context, or a symbol it adds that its own fact doesn't use), a third-party block, or a signature not over Biscuit's version 1 payload makes the token invalid (`401`).

  - Biscuit's Datalog is not evaluated. The server verifies the signature chain with a Biscuit library, extracts the JSON blocks and applies §C.2 to them, with validity times from the blocks' `nbf` and `exp`.

- **Keys.** Every signature in the token is Ed25519, including the ephemeral keys that sign narrowing blocks, verified strictly (RFC 8032, with `S < L`). A token using any other algorithm is `401`. The root key is named by `kid` inside the root block, not by Biscuit's numeric `rootKeyId`. A wrong `kid` fails verification like any bad signature.

- **Revocation ids** (§C.4) of narrowing blocks are over the block's Biscuit signature.

- **Sealed tokens** are accepted.

- **Stored form** (§C.3). The server stores the authority block with its signature and next key, without the other blocks or the token's `proof`. Its signature can still be checked.

- **Transport.** `Authorization: Bearer <token>`, the token as Biscuit's URL-safe base64, with or without the `biscuit:` prefix. Any other `Authorization` field is a malformed grant (`401`). `grantSize` (§6.6), counted in decoded bytes, and `rulesPerGrant` are `413` (`code: "limit"`), checked as §C.2 item 1 orders them on every request that doesn't ignore the grant (§7).

## C.9 Open questions

- Should revocation lists be shared across unrelated namespaces, e.g. per issuer? A base's already reach its branches (§C.4).

- Should role definitions be shareable across namespaces, e.g. as a resource referenced by immutable revision, like `$schema`?

---

# Addendum E — Encryption (optional)

Each level is defined by **who is trusted with plaintext**, and trades features for confidentiality:

| Level | Who can read plaintext | What keeps working | Main use |
|---|---|---|---|
| **E1 · At rest** | origin | everything | protects disks, backups, database dumps |
| **E2 · Sealed for delivery** | origin + key holders | everything, **plus** public caching of ciphertext | confidential content that must scale through the CDN |
| **E3 · End-to-end** | key holders only | ordering, preconditions, ids, verb-level grants | content the operator must not be able to read |

The levels are cumulative in intent; E3 clients seal in E2's JWE format (§E.3.1).

**Levels.** A namespace declares its level in its namespace document, `"encryption": { "level": "at-rest" | "sealed" | "e2e", … }`, ranked as in §2.1.

-
**Invariant.**

  - Levels never go down.

  - A namespace is end-to-end from its creation or never.

  - No namespace is raised above a dependent.

  - A branch never serves what it reads through at a weaker level than its base serves it.

  - An epoch key, or a key derived from it, reaches only grants whose window covers that epoch (§E.2.3).

  - A sealed payload's `pl` and `kid` bind where and in which epoch it was sealed. Readers compare them in full with what they fetched, accepting a base's `ns` only in an E3 `sealed` op read through (§E.3.1).

-
**Changing it.** These writes are `422` (`invalid`):

  - a write that lowers or removes the level, or raises it to `e2e`;

  - a write whose namespace document holds a member its level refuses (§6.1, §7.4, §8.6, §C.7), whichever member it changes. So a raise removes such members in the same write.

A namespace that should become end-to-end is imported into a new `e2e` one, under a new name, by a client that holds the new one's keys (§G.5.1). The origin purges the namespace's cache tag with a raise to `sealed` (§9).

-
**Branches and dependents.** A branch is at least at its base's level, and `e2e` exactly when its base is. A branch's creation that breaks this is `422`, as a branch field (§7.4). Config writes don't check it. Raising a namespace above a dependent's level is `409` (`in_use`, with `dependents`), so levels rise leaves first.

-
**After a raise,** `Last-Modified`, `Repr-Digest`, `/heads` fields, caching, `…/raw` and the gestures listing follow the new level (§7.1, §7.4, §9), and content stored before a raise to `sealed` is served as §E.2.2 says for content from before the namespace was sealed.

## E.1 At rest

- **What it is.** The origin encrypts stored patches, snapshots and grants with keys from a key management service (KMS), e.g. SQLite page-level encryption or a per-row AEAD.

- **What it doesn't change:** anything else in this spec. It protects storage media and backups, not the CDN or readers.

- **Purge becomes cryptographic.** With a key per resource, purging destroys the key, which also makes backups unreadable.

- **Stored digests.** A server storing `/heads` `size` and `digest` (§7.4) keeps a plaintext sha-256 of each head's document: like ids (§C.7), a dump or backup, even from before a purge, confirms a guess of a document without a `$nonce`. The fields are optional (§7.4): at rest it leaves them out, computes them at read time, or keeps them under the resource's key.

## E.2 Sealed for delivery

The origin keeps plaintext, so validation, rules, `writes`, idempotent retry, consumers and services work unchanged. What leaves the origin for a sealed namespace is **encrypted** (§E.2.2), so caches, the CDN included, hold only ciphertext, and a `public` sealed namespace is readable only by key holders.

### E.2.1 Keys

-
**Epoch keys.** The namespace has a sequence of **epoch keys** `K_e` (256-bit random), each identified by `kid = "{ns}#{e}"`; the current epoch is the namespace document's `encryption.epoch`. Key material is never in the document or the log; the origin holds it, backed by a KMS.

-
**Per-resource keys** are derived one way:

```
K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name), 32 bytes
```

`K_r` opens only that resource's content of epoch `e`, and yields neither `K_e` nor `K_n`.

-
**Per-revision, per-blob and per-view keys.** At E2 the origin seals a resource's revisions and blobs under keys derived from its `K_r`, and filtered answers (§7.9) under a key per view (§E.2.2):

```
K_rev  = HKDF-SHA256(ikm = K_r, salt = "patchlog-e2-rev",  info = id), 32 bytes
K_log  = HKDF-SHA256(ikm = K_r, salt = "patchlog-e2-log",  info = id), 32 bytes
K_blob = HKDF-SHA256(ikm = K_r, salt = "patchlog-e2-blob", info = bid), 32 bytes
K_view = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2-view", info = ns ‖ 0x0A ‖ view), 32 bytes
```

`id` is a revision's or tombstone's id, `bid` a blob's id (§3.7) and `view` a view (§7.9), each in text form (§3.2). Each is one way: a `K_rev`, `K_log` or `K_blob` yields no sibling and no `K_r`, and a `K_view` yields no other key. A holder of `K_e` derives every `K_view`, and of `K_r` its `K_rev`s, `K_log`s and `K_blob`s. E3 has none of them: clients seal under `K_r` (§E.3.1).

-
**Namespace key.** What is sealed for the namespace rather than for a resource (§E.2.2) is sealed under

```
K_n = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A), 32 bytes
```

Its `info` is no `K_r`'s, as a resource name is never empty (§3.6). `K_e` itself seals nothing. `/keys` never returns `K_n`: a holder of `K_e` derives it (§E.2.3).

-
**Rotation.** A config write that increments `encryption.epoch` starts a new epoch, under which revisions written from then on are sealed; **old revisions keep their epoch forever,** as their URLs and cached bytes are immutable. In a namespace already at `sealed` or `e2e`, a write may change `epoch` only by adding one (`422`, `invalid`). Such writes need a `*` key (§7.4).

-
**Rotation schedule.** Rotate on a schedule (e.g. daily) and whenever read access is revoked.

-
**Message bound.** IVs are 96 random bits, so no key this spec seals under, a sealed bundle's `K_b` included (§G.5.1.1), seals 2³² values or more (NIST SP 800-38D). Keys that only encrypt storage (§E.1) are left to the implementation.

  - The origin counts its sealings per key, reserving what may still be sealed under an epoch after it ends (§E.2.2). Its counts may exceed the sealings made, stored or not, but never fall short of them; how it reserves is its choice.

  - A holder of a `*` key rotates before any key of the current epoch reaches the bound. At E2 the origin MAY instead rotate by itself, frozen or not (§8.4), in a config entry it writes itself (§7.4).

  - Until then, a request that would need a sealing past the bound is `503` (`behind`), with `Retry-After`.

  - At E3 only clients seal under `K_r`, and the origin need not count. Each writer counts the sealings under a `K_r` that it knows of, the log's and its own, and seals none past the bound; the key holder that rotates (§E.3.2) rotates before any count it knows of reaches the bound.

### E.2.2 Sealed representation

Sealed payloads are JWEs (RFC 7516) in compact serialization, each served alone as `Content-Type: application/jose`. An unfiltered resource log range or resource long-poll answer is a canonical JSON array (§3.1) of its entries' JWEs, served as `application/json`, and an SSE event's `data` is one JWE.

-
**Algorithms:** `alg: "dir"` and `enc: "A256GCM"`.

-
**Protected header:** `{ "alg": "dir", "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { … } }` as canonical JSON (§3.1), with `pl` as below. Ids in `pl` are in text form, and an empty one is `""`.

  - The `pl` claims are integrity-protected as AAD, so a ciphertext can't be replayed under another resource, revision or epoch. Readers MUST compare `pl`, and the namespace that `kid` names, with what they fetched; a filtered answer's `view` with the URL's, or, where the URL names none, with the `view` of the key `/keys` gave the grant the request carried (§E.2.3). At E3 they accept in both a base's `ns` for a `sealed` op a branch reads through, up to the resource's foreign parent (§2, §E.3.1). In a chain of branches, each base's `ns` is accepted only up to the foreign parent of the nearest branch below it with entries of its own for the resource. Where they can't place such a parent, as where a document or `/heads` page that places it is unreadable to them, the ops it bounds fail the check and the read goes on (§E.3.2). At E2 a branch seals all it serves under its own keys (§E.2.5).

-
**What gets sealed,** each under the key, epoch and `pl` given here:

| Payload | Key | Epoch | `pl` |
|---|---|---|---|
| `/rev/{id}` document | its `K_rev` (§E.2.1) | the revision's | `{ "ns", "name", "id", "kind": "doc" }` |
| resource log entry (§7.1), in a range or as a `revision` or `tombstone` event | its revision's `K_log` | the revision's | `{ "ns", "name", "id", "kind" }`, `kind` the entry's (`rev` or `tombstone`) |
| resource `purge` or `prune` event, unfiltered | `K_r` | current when sealed | `{ "ns", "name", "kind" }`, `kind` the event type |
| namespace document at `ns_id` | `K_n` | in force at `ns_id` | `{ "ns", "id": ns_id, "kind": "doc" }` |
| namespace log range or long-poll answer | `K_n` | current when sealed | `{ "ns", "range": [since, last] }`: the bounds of the page actually served (§7.1), `[since, id]` for an empty page |
| namespace event (§7.3) | `K_n` | current when sealed | `{ "ns", "event": id }`, `id` its entry's |
| grant (§C.3.1) | `K_n` | in force at the first namespace log entry recording it | `{ "ns", "grant": gid }` |
| blob, in a binary form (Sealed blobs, below) | its `K_blob` | each epoch it is served under | as in Sealed blobs |
| filtered answer (§7.9): a log range, long-poll answer, `/heads` page or event | its view's `K_view`, `K_n` for a `/ns/{ns}` cookie (§7.9) | current when sealed | its unfiltered form's, with `view` added: a resource's range or long-poll answer `{ "ns", "view", "name", "range": [since, last] }`, a `/heads` page `{ "ns", "view", "at", "after" }`, `after` `""` on the first page, a `hidden` event's `kind` `hidden`; `last` is the last entry the answer covers, shown or not: a page's `X-Log-Next`, else its range's end, or a long-poll answer's `X-Namespace-Revision` or `X-Revision` (§7.9) |
| a view's keys for a revision (Filtered answers, below) | that view's `K_view` | the revision's | `{ "ns", "view", "name", "id", "kind": "keys" }` |

Each plaintext above but a blob's is canonical JSON (§3.1), before any padding (below). A resource log entry's is the whole §7.1 entry. A namespace log range's or long-poll answer's is the JSON array of its §7.4 entries, `[]` for an empty page, and a namespace event's is its one entry. Filtered answers and a view's keys are below.

The epoch in force at a namespace entry is the `encryption.epoch` of the namespace document in force there. A revision's epoch is the current one when it is first sealed (Epochs, below), and so is that of a namespace document or grant from before the namespace was sealed, or of a grant only a base records (§C.3.1).

-
**What stays in the clear:** everything else, such as URLs (so names and ids), status codes, headers, error and `410` bodies, unfiltered `/heads` and `/branches` pages, live timing and padded sizes. But the exact `created` of each revision, a document's length and its digest aren't sent outside the sealed logs (§7.1, §7.4).

-
**Stored once, served forever.** Sealed bytes for a revision, a document, a resource log entry or a grant are produced once, stored, and served identically forever, so `304`s and caching work as without sealing. A sealed revision or namespace document has `ETag: "{id}.{e}"`, as a sealed blob does (§7).

  - Namespace log ranges (§7.4) are the exception. A deployment MAY keep only some, oldest evicted first, and seal an evicted range again on request, with fresh bytes, under the `K_n` and `pad` setting current then, from the same plaintext.

  - Readers accept either copy and MUST NOT rely on one.

  - A range's `ETag`, if any, is weak.

  - Resource `purge` and `prune` events and namespace events need not be stored: each may be sealed again, with fresh bytes, whenever it is sent, and every sealing counts (§E.2.1).

  - Filtered answers are never stored (§7.9): each is sealed when it is produced, readers accept any copy, and a range's `ETag`, if any, is weak. A view's keys for a revision are sealed once and stored, so what an ended epoch's `K_view` seals stays bounded (§E.2.1).

-
**Filtered answers** (§7.9). At E2 a filtered answer's plaintext is `{ "body", "keys" }`:

  - `body` is the answer as §7.9 gives it: the array of its entries, `[]` for an empty page, the `/heads` body, or the event's data (§7.3). A resource log entry it shows with `patches`, to a partial reader only where the keys it carries for that revision hold `log`, is there as its stored JWE (above), so content stays under its revision's epoch, and every other entry as plain JSON;

  - `keys` holds, as JWEs in the order the body first names their revisions, a view's keys for each revision of the namespace it names that is visible (§7.9), tombstones and revisions of purged resources excepted, `[]` if none.

A view's keys for a revision are `{ "key", "log"?, "blobs" }`, each key in base64url: `key` its `K_rev`, `log` its `K_log` only where §7.9 shows its entry with `patches`, and `blobs` an object holding, by id, the `K_blob` of each blob its document references, `{}` if none or the document is no longer stored, all of the revision's epoch. They are sealed under that epoch's `K_view`, so a reader opens those of the epochs its window covers (§E.2.3) and no others. Carrying them fixes the revision's epoch as serving it would (Epochs, below). The reader fetches the blobs at `…/blob/{bid}/e/{e}` for that epoch (§7.9).

-
**Compression.** Sealed payloads are never compressed and carry no `zip` header: a document mixes several authors' content (CRIME/BREACH).

-
**Padding (optional).** A namespace MAY set `"pad": true` in its `encryption` object. Then every JWE sealed for it, by the server at E2 and by clients at E3 (§E.3.1), pads its plaintext to a size bucket before encryption:

  - **Format.** The plaintext is the UTF-8 JSON that would otherwise be sealed, followed by ASCII spaces (`0x20`) up to the padded length. A blob is padded with zero bytes instead, inside its sealed form (below).

  - **Buckets.** For a plaintext of `L` bytes, the padded length is 256 for `L` ≤ 256, otherwise `padmé(L)`, where `E = ⌊log₂ L⌋`, `S = ⌊log₂ E⌋ + 1`, and `padmé(L)` rounds `L` up to a multiple of `2^(E − S)`.

  - **Scope.** Each JWE is padded as a whole, including every JWE of a log range. Turning `pad` on or off affects only what is sealed afterwards, a log range sealed again after eviction (above) included.

  - **At E3** the server can't check padding. Readers with keys SHOULD flag, like a failed validation (§E.3.2), a patch set not padded to its bucket when `pad` was on at that revision.

    - Whether `pad` was on is judged by the namespace document in force at the revision's namespace log entry. For a batch that changes the configuration, it is judged by the configuration it produces (§7.5).

    - Revisions written while `pad` was off are never flagged.

-
**Sealed blobs.** Blobs (§7.8) use a binary form rather than a JWE, `application/vnd.patchlog.sealed-blob`:

```
"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(plaintext) ‖ tag
plaintext = size ‖ bytes ‖ padding
```

  - `len` is the length of `header` as a 4-byte big-endian integer, and `header` is canonical JSON. `iv` is 12 random bytes, and the tag is 16 bytes. The additional data is everything before `iv`.

  - `size` is the length of `bytes` as an 8-byte big-endian integer. `padding` is zero bytes, present only with `pad`, up to the bucket of `size ‖ bytes`. Readers check that it is all zeros.

  - **At E2** the header is `{ "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "blob": bid } }`, and the key is the blob's `K_blob` of epoch `e` (§E.2.1).

  - **Epochs.** In a sealed namespace, `…/blob/{bid}` answers `302` (head-pointer caching) to `…/blob/{bid}/e/{e}` for the latest served epoch; a reader holding only older epochs asks for one of those.

    -
**Served epochs** are those of the revisions here whose documents are still stored, that reference the blob and that the request may read (§C.2 item 5), so no reader learns the epoch of a revision hidden from it (§7.9). Other epochs are `404`, with `no-store`. An epoch whose referencing revisions were all pruned answers `410` as in §7.1 where the server recorded it when pruning and the request may read one of them, one judged without its document being hidden unless a kept answer shows it (§7.9 Cost), and `404` otherwise.

    -
**A revision's epoch** is fixed by its first stored sealing:

      - when it is written;

      - or, for one read through from a base or written before the namespace was sealed, when it is first served or a check first judges by its epoch (§2.1, §6.1).

A request or such a check for a blob none of whose referencing revisions it may read has an epoch yet first fixes the newest of those under the current epoch. A refused request fixes no epoch.

    -
**Stored once.** Each epoch's sealing of a blob, like a revision's, is produced once and stored. When two instances seal at once, the first one stored wins. Only the stored bytes are served, unchanged, with `ETag: "{bid}.{e}"` and the sealed type as `Content-Type` (the blob's own type is in its reference).

    -
**In a branch,** stored sealings of a base's blobs are its own: pruning in the base doesn't delete them (§8.6), but the branch stops serving them, answers as above, and MAY delete them.

    -
**Clients** open sealed blobs only in namespaces whose namespace document says they are sealed or end-to-end, or after the epoch redirect.

  - Range requests are served over the sealed bytes, so a download can resume but a range can't be decrypted alone; media that must stream in ranges belongs in an unsealed namespace, or in several blobs.

### E.2.3 Getting keys

```
POST /ns/{ns}/keys
Authorization: Bearer
{ "epochs": [3, 4], "resources": ["derby"] }      // resources only for per-resource grants
```

- **What a grant gets** at E2, never more than one kind:

  - A grant that reads the namespace unrestricted (§2.1) gets epoch keys `K_e`.

  - A grant whose rules fix `/resource` (§2.1, `readScope: "resource"`) and whose read rules (§7.9 `view`) don't refer to `/doc` gets **per-resource keys** `K_r` for the names in `resources`, by default every name it fixes. A name it doesn't fix, or may not read, is `403`.

  - A partial reader (§7.9) gets, where §7.9 applies, a **view key**: only the `K_view` of its own `view` (§E.2.1), which opens nothing for a copy or schema resolution (§2.1, §6.1).

  - Any other grant is `403`, in a public namespace too (§C.2). `resources` is ignored but for per-resource keys.

- **Which epochs:** those in `epochs`, by default all, within a window; others are left out.

  - **From** the current epoch if no block has `nbf` or authentication is disabled. Otherwise:

    - from the epoch in force (§E.2.2) at the last namespace entry created at or before the latest `nbf` among the grant's blocks, a `batch` entry's config change included;

    - or from the namespace's first epoch where there is no such entry, or the namespace wasn't yet sealed or end-to-end there.

  - **To** the current epoch, and where `encryption.historyEpochs` is set, no more than the current one and that many before it.

  - A reader then lacking the epoch a grant is sealed under (§E.2.2) reports the signatures naming it as unverifiable (§C.3.1).

- **At E3,** `/keys` relays to a `read` grant whose rules pass for a read (§C.2 item 5) the `keyring` entries (§E.3.2) whose `to` is its `enc`'s thumbprint, without a read of `keyring` itself:

  - the namespace's own, for the epochs above;

  - in a branch, also those of its bases' keyrings as of `at` (§F.8.1), whether or not it has written its own `keyring` since, for each base's epochs up to `at`. `epochs` doesn't select among them.

    - They start, as above, from the epoch that base had in force at the latest `nbf`, or at `at` if that is earlier.

    - Where no block has `nbf`, they start from the epoch that base has in force now, so there are none once it has moved past its epoch at `at`.

    - They reach back no more than that base's `historyEpochs` at `at` before its epoch there.

- **Wrapping.** Keys are wrapped to `enc` with HPKE's single-shot Seal and Open (RFC 9180, section 6.1).

  - `enc` is an X25519 public key as a JWK of only `kty: "OKP"`, `crv: "X25519"` and `x`, its 32 bytes in base64url without padding (43 characters), in the grant's root block. An `enc` of another form, or in a narrowing block, is `401` (§C.1). A grant without one is answered as **Responses** says.

  - HPKE runs in base mode (auth mode for `keyring` entries, §E.3.2), with the suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, and an empty `aad`.

  - The plaintext is the key's 32 bytes, and the `info` is `"patchlog-key-v1" ‖ 0x0A ‖ kid ‖ 0x0A ‖ name`, with `name` empty for `K_e` and `view:{view}` for a `K_view`, which no resource name can be (§3.6).

  - `wrapped` is HPKE's 32-byte encapsulated key followed by the ciphertext.

  - A public key's thumbprint is its JWK's RFC 7638 SHA-256 thumbprint.

  - Both `wrapped` and the thumbprint are base64url without padding.

- **Responses** are `{ "epoch", "level", "pad", "keys": [{ "kid", "name"?, "view"?, "from"?, "wrapped" }] }`, `Cache-Control: no-store`.

  - `name` is there for a `K_r`, `view` for a `K_view`, and `from` for a keyring entry (§E.3.2).

  - `epoch` is the current epoch.

  - At E2, a grant without `enc` gets each key in base64url as `key`, in place of `wrapped`. At E3 such a grant is `422` (`invalid`).

  - In a namespace that is neither sealed nor end-to-end, `/keys` is `404` with `code: "not_offered"`.

  - A request draws a token from `exchangeRate` (§6.6), as `/edge-grants` does.

### E.2.4 Revocation, honestly

- **Future content.** Revoking or narrowing read access means rotating the epoch of the namespace and, recursively, of its branches, which the base's `*` keys can do (§7.6); the revoked reader gets no keys for the new epochs, so can't read what is written afterwards.

- **Past content.** What was sealed under epochs the reader already held stays readable to them, from their copies or the CDN's.

- **Reducing past exposure:** shorter epochs; per-resource and view keys (§E.2.3), so each reader holds only what they were granted; purge, which removes content, its at-rest and view keys (§E.1, §8.3) and, for a namespace, its epoch keys (§8.5), though keys already delivered still open copies.

### E.2.5 Interaction with the rest of the spec

- **Caching (§9)** follows the `read` mode: a public sealed namespace is cached publicly, keys alone deciding who reads it, but for its view prefixes (§7.9); with `read: "grant"`, edge grants also hide **metadata** (names, sizes, timing).

- **Ids (§3).** Ids are still computed over plaintext canonical patches. Sealed namespaces MUST refresh `$nonce` in every patch set (§C.7).

- **Consumers and addenda:** derived views are sealed as §E.2.6 says.

- **Schemas** may live in a sealed namespace, but every writer and consumer then needs its keys.

- **Branches (Addendum F).** At E2 a branch has its own epoch keys, and the server seals read-through content under keys derived from them when it is first served (§E.2.2). At E3 its `/keys` relays its bases' keys (§E.2.3); merging is §F.8.1's.

### E.2.6 Derived views

How services seal what they derive from sealed and end-to-end namespaces: in SERVICES.md.

## E.3 End-to-end

The origin never sees plaintext: clients encrypt patch sets before sending them and decrypt what they read, and the server becomes an **ordered, access-controlled log of opaque entries**.

### E.3.1 Wire format

-
**Patch sets.** A write's body is `[{ "op": "sealed", "value": "<JWE compact>" }]`: a one-element patch set with a reserved `sealed` op. It is sealed under the resource's `K_r` (§E.2.1) of the epoch its `kid` names. Its JWE protected header (§E.2.2) carries `kid` and `pl: { ns, name, parent }`. At step 3 of §6.2 the server checks, `422` (`invalid`) otherwise, that:

  - the op has no members but `op`, `value` and `blobs`;

  - the header is canonical JSON with no members but `alg`, `enc`, `kid` and `pl` (§E.2.2);

  - `pl` names this namespace, the resource and the parent a signature would bind (§C.3.1);

  - `kid` names this namespace's epoch in force (invariant 6).

Readers check `pl` too, accepting a base's `ns` for content read through, up to the resource's foreign parent (§E.2.2, §F.8).

-
**Snapshots.** A prune's `snapshot` (§8.6) is one such op, holding the document of the requested `horizon` (§8.6), with `pl: { ns, name, id }` naming this namespace and that revision, or the tombstone's parent where it is a tombstone, which the tombstone's `410` names as `last` (§7.1). Its `kid` names this namespace and an epoch set by the newest revision in the horizon's chain that isn't a tombstone and whose patch set isn't `[]`:

  - the epoch of that revision's `sealed` op, where the op is this namespace's own (its `pl.ns` names it), not a base's;

  - or, below an earlier horizon, the epoch of that horizon's `snapshot`, where its `kid` names this namespace;

  - otherwise this namespace's epoch in force.

The server checks `pl` and `kid` (`422`, `invalid`).

-
**Ids.** The server hashes it like any patch set (§3.3), so ids are **over ciphertext**.

-
**Retries.** A client MUST keep the exact ciphertext until the write is acknowledged, so that a retry reproduces the same id (§7.2).

-
**Namespace documents stay plaintext,** for the server to read keys, rules and limits.

-
**Blobs.** A client encrypts each blob under a fresh random 256-bit key, in the sealed-blob form of §E.2.2 with the header `{ "enc": "A256GCM" }`, and uploads it with `Content-Type: application/vnd.patchlog.sealed-blob`, so its id is over ciphertext and needs no nonce. The key goes into the reference, inside the sealed document:

```
{ "$blob": "1m4…", "type": "application/vnd.patchlog.sealed-blob", "size": 1843363,
  "sealed": { "key": "", "type": "image/jpeg", "size": 1843302 } }
```

`sealed.type` and `sealed.size` describe the plaintext.

-
**Declared blobs.** The `sealed` op lists, in plaintext, the id of every blob the resulting document references: `[{ "op": "sealed", "value": "<JWE compact>", "blobs": ["1m4…"] }]`.

  - Writers omit the member when the list is empty, and otherwise sort it by the ids' binary form (§3.2).

  - The server accepts an empty list either omitted or as `[]`, and a list in any order. Readers compare lists as sets.

  - A list with duplicates is `422` (`code: "blob"`), and so is a declared blob whose type isn't the sealed type or that has a nonce.

  - A restore with `[]` keeps the list of the last live document. A sealed empty set that keeps a document unchanged (§F.3) repeats its list.

  - The list is part of the hashed patch set. The server keeps it with the revision's skeleton after pruning.

  - The server checks its length against `blobsPerDocument` and that the blobs are available (§7.8). It uses the lists for unreferenced blobs, pruning, purge and bundles.

  - Readers MUST compare the list with the decrypted document, and flag a revision whose list differs, like a failed validation (§E.3.2).

  - A prune's sealed `snapshot` needs no list (§8.6): the server has that of the revision whose document it is.

-
**Merges keep blobs.** Re-sealing a patch set for another namespace leaves its blob references, and the blobs' ciphertext and ids, unchanged (§F.8.1).

### E.3.2 What the server can and cannot do

| Feature | E3 |
|---|---|
| Ordering, `If-Match`, `412`, idempotent retry | ✅ |
| Ids, chain verification | ✅ over ciphertext |
| Grants and roles on verbs, `/resource`, `/action`, `/now` and the principal | ✅ |
| `$schema` validation | ❌ moves to clients |
| Rules on `/doc` (including role rules), `writes` path policy | ❌ the server cannot see paths, so a rule whose outcome depends on them fails resource writes as a whole (§6.2) |
| Search, derived listings | only in services that hold keys |
| Caching of content | ✅ by `read` mode (§9), as ciphertext |
| Limits on documents (`documentSize`, `valueSize`, `pathSize`, `nestingDepth`) | ❌ checked by clients (`blobsPerDocument` by the server, on the declared list) |
| Blob references | declared in plaintext by writers, verified by readers (§E.3.1) |

- **Validation moves to clients.**

  - Every client MUST validate the decrypted document against its `$schema` before writing, and SHOULD verify it on read, leaving out the same members as the server (§6.2 step 5).

  - A revision that fails validation on read is **flagged** but still folded, and its author, recorded as usual, is accountable. One whose patch set doesn't open, fails the `pl` or `kid` check, or doesn't apply to its parent's document, a failing `test` included, is flagged too, and readers fold on from the parent's document as if it were `[]`.

  - Invariant 3 becomes a property checked by readers rather than enforced by the gate.

- **Path-level permissions** (e.g. translators only touching `/i18n`) need a separate resource per permission boundary.

- **Keys.** Key distribution uses §E.2.3, except that the server only relays **wrapped** keys.

  - Epoch keys are wrapped per recipient public key by a key-holding admin client, as in §E.2.3 but in HPKE auth mode under the admin's X25519 key. They are stored in the namespace's `keyring` resource.

    - Its document is `{ "keys": [{ "kid": "{ns}#{e}", "to", "from", "wrapped" }] }`, with no other members but a `$nonce` (§C.7), new random bits on every write that carries one; the server checks only its form.

    - Each entry has only these members: `kid` naming this namespace and an epoch no later than `encryption.epoch`, `to` and `from` the thumbprints (§E.2.3) of the recipient and of the admin's key, and `wrapped` 80 bytes (§E.2.3).

    - No two entries are for one `kid` and `to`. A document that breaks this or the two rules above is `422` (`invalid`), so a branch's first `keyring` write drops the entries it reads through.

    - A client opens and seals only under a key whose `from` it trusts to distribute keys, configured out of band with that key's public key: anyone can wrap to a thumbprint, the server included.

    - The `keyring` is written in plaintext, and checked and pruned as outside E3, without `snapshot` (§6.2, §8.6). Rules on `/resource` (§6.4) decide who may write it.

  - Adding a reader means wrapping the current epoch key for them. Revoking means rotating the epoch and re-wrapping for the remaining readers, done by a key holder, never by the server, taking the readers from its own configuration, never from stored `to` members.

## E.4 Metadata that no level hides

- **What remains visible:**

  - resource and namespace names (in URLs)

  - ids, parent links and the shape of the namespace log

  - sizes, padded where `pad` is set, and blob counts

  - edit timing; at E3 also past revisions' exact `created` (§7.1); to operators, each namespace's creation time (§7.4)

  - authors and their grants (§7.4; at E3 served in the clear to readers, §C.3.1); at E3 also gesture ids (§7.2), which clients that must hide the grouping keep inside their sealed content, and whom the `keyring` wraps each epoch to and from

  - query strings of derived views (§E.2.6); at E2, under view prefixes (§7.9), which revisions and blobs each view reads

  - at E3, which revisions reference which blobs; at E2, which epochs a blob is served under; whether a blob carried over without a nonce matches a guess (§C.7)

- **Mitigations:**

  - opaque names (e.g. random slugs)

  - padding (`pad`, §E.2.2)

  - edge grants, hiding existence from non-readers; only operators list namespaces (§7.4); nothing hides from the operator who writes when

## E.5 Open questions

- Should E3 let clients reveal a **plaintext `writes` list** beside the sealed patch set, for the server to enforce path policy on and readers to check against the decrypted patches?

- Should `view` digests (§7.9) be fixed byte for byte, so that an index could seal a whole response for a partial reader under a key its `K_view` gives, aggregates included (§E.2.6)?

---

# Addendum G — Federation and portability (optional)

Ids hash content, not location, so a history has the same ids in every deployment. This addendum uses that to move content between deployments, such as staging and production, a partner, an offline site or a new operator:

- **Bundles** carry documents in a file, with or without their history (§G.4). Pruning archives to them too (§8.6).

- **External consumers** read another deployment's namespaces (§G.2, in TOOLS.md).

- **Export and import** are tools on the public API (§G.4.2–§G.4.4, in TOOLS.md). A full-history import keeps ids, so history can move back and forth, incrementally (`requires`, §G.4.1).

Its hooks in the core are in §3.5, §6.5, §7, §7.5 and §8.6.

## G.1 Principles

- **Every deployment has one canonical origin,** published at `GET /` (§7).

- **Ids travel, trust doesn't.** Anyone can verify content that comes **with its history** by recomputing ids (invariant 4) from an `ns_id` or revision id obtained from the source itself, however it was delivered. Snapshots, headers and listings that ids don't cover are only as trustworthy as their channel.

- **A deployment boundary is a trust boundary.** Each deployment's gate applies its own grants, rules and schemas to everything arriving from elsewhere.

- **Nothing is atomic across deployments,** as across namespaces (§1, §7.5).

- **Copies can't be recalled.** In another operator's hands, a purge is a request, not a guarantee: treat any read grant for a private namespace as disclosure.

- **Names are stable across environments.** Keep them the same everywhere (§11.1), and let the origin say which environment it is.

**Purges follow imports.** A namespace imported from another deployment, as full history or snapshots, records that deployment's origin in its import batches' `source` (§7.5, §G.4.4). Its operator may trust that origin and name the principals that import from it. Any writer can assert a `source` (§7.5), so only import batches by such a principal count, whenever written, under a grant that may `purge` the names they write (§C.2). Its deployment SHOULD then follow that origin's namespace log from the first such batch's `source.at`, and apply each `purge` there of a name such a batch wrote, and each `purge-ns` to every such name, as §8.3 does locally: its own chains for the name, its upstream namespace's (§G.4.4), its branches and its cache tags. It writes these entries itself (§7.4); one that §6.1 refuses as `in_use` waits for an operator.

## G.2 External consumers

In TOOLS.md.

## G.4 Bundles

A bundle carries selected documents between deployments as a file, e.g. for promotion, fixtures, handovers or a partial backup. Exporting is a consumer (§G.2), and importing a client of the batch API (§7.5).

### G.4.1 Format

Newline-delimited JSON (`application/vnd.patchlog.bundle+jsonl`): each line is canonical JSON (§3.1) followed by one `0x0A`, and a bundle with any other line is rejected. So is one with a member this section doesn't define, in a line or in an object whose members it lists, unlike namespace documents (§7.4, Versions). The first line is the header, followed by one line per entry:

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

- **Full-history lines** are resource log entries (§7.1), of kind `rev` or `tombstone`, with `ns` and `resource`, and with authorship members only as below, in chain order per resource. Every id is recomputed, and the last line per resource MUST be that document's `docs[…].head`.

  - Every `docs` entry MUST have lines, and every line naming a resource a `docs` entry; any mismatch rejects the whole bundle.

  - A chain starts at genesis or right after its `requires` id. Chains exported from a branch include the base's entries back to genesis, or name in `requires` the foreign parent: the resource's head as the branch's `/heads` lists it at the branch's first `ns_id` (§10). `ns` is always the exporting namespace.

- **Snapshot lines** carry the document and its source id as provenance: one per `snapshot` document, whose `snapshot` MUST be its `docs[…].head`. A document tombstoned at the source is `{ …, "snapshot": <tombstone id>, "deleted": true }`, without its document. The dependency closure (§G.4.2) doesn't follow successors (§8.1).

- **Blob lines** carry every blob an exported document references, from any exported revision of a `full` document or from a snapshot.

  - A blob line comes once per resource, with `nonce` if the blob has one, before the first line that **mentions** the blob.

  - A line mentions a blob when its patches carry the blob's id as a `$blob` member or as the value of an operation whose path ends in `/$blob`, when its snapshot document references it, or when its declared list (§E.3.1) names it.

  - `data` is the bytes in base64url without padding; readers accept either.

  - The importer recomputes each id (§3.7), and a mismatch rejects the bundle.

  - An incremental bundle MAY leave out blobs that the history up to `requires` already references.

- **`requires`** applies only to `full` documents. `requires[r]` MUST be in the target's chain for `r`. If the target has moved on along another line, `r` is a conflict.

- **Authors, `via`, grant ids, author signatures, creation times, `gesture` and `undoes`** are included only with `"authors": true`.

  -
History lines then carry `grant: gid` (the id only, not §7.1's object).

  -
The bundle then has one grant line `{ "ns", "grant": gid, "root", "stored", "key"?: { "kid", "alg", "pub" } }` per grant they name, before the first line that does. Its `ns` is the namespace whose entry first recorded the grant, in the form of `written` below.

  -
An exporter that can't fetch a grant leaves `grant` off the lines that would name it.

  -
Any of these rejects the bundle: a line naming a grant with no earlier grant line, a second grant line for one grant, a grant line whose `grant` isn't the id of its `root`, whose `stored` block's `grant_block` isn't `canonical(root)` (§C.3.1, Reading grants), or whose `key` has a `kid` other than `root.kid` or doesn't verify the `stored` block, or, in a bundle without `"authors": true`, a grant line or a history line with `author`, `via`, `grant`, `signature`, `created`, `gesture`, `undoes` or `written`.

  -
**`written`.** A line for a revision written in a namespace other than the exporting one, such as one a branch reads through, also carries `written`: that namespace's name. Verifiers use it in the signing input (§C.3). An exporter that can't determine it, because no log it can read records the revision, writes the line without `written` and `grant`, so its signature reports as unverifiable.

  -
**`key`** is the key entry the grant's root block verified against at the source (§C.3.1). It is either:

    - a key of the namespace document in force at the first entry that recorded the grant (in a branch, or of its bases' then), or else

    - an operator key in force at the `created` of the first revision naming the grant (§C.4)

An exporter that can find neither leaves it out. `key` is attested by the exporter, not proven (Trust, below).

  -
Bundle tools SHOULD verify signatures through §C.3.1's chain against the header's `origin`. A tool holding the source's namespace log, or its operator key history, checks `key` at the revision's position; otherwise it reports the signature as attested, not verified. An importer signs its own steps (§C.3.1); the original signatures stay in the bundle, which its batches' `source` names (§G.4.4).

- **Never exported:** purged content.

- **Consistency.** Each namespace is exported as of its own `at`, taken when the export starts.

- **Digest.** A bundle's digest, recorded as `source.bundle` (§G.4.4), is `text(trunc160(sha256(b)))`, where `b` is the bundle's bytes as written (§I.9).

- **Trust.** Until signed bundles exist (§G.7), headers and snapshot lines are only as trustworthy as their channel (§G.1). Sealing (§G.5.1) hides a bundle from all but its recipients, but anyone with their public keys can seal one.

### G.4.2 to G.4.4 Selection, history or snapshot, importing

In TOOLS.md.

## G.5 Encryption (Addendum E)

- **Obligations a source can't enforce:** an importer's checks (§G.5.1); a `read` grant entrusts them (§G.1).

### G.5.1 Bundles

- **`access`** in the header gives each exporting namespace's protection as a source (§2.1): `"public"`, `"private"`, `"sealed"` or `"e2e"`. Exporters MUST include it, and so does the server in a prune's archive (§8.6).

- **Importing.** At step 1 (§G.4.4), the importer refuses a bundle that would put a namespace's lines into a target, or into that target's upstream namespace, that ranks below that namespace (§2.1), unless an operator explicitly overrides this for that import. It also refuses a target or upstream namespace whose protection it can't read and, override or not, a bundle with a `sealed` op in a line of a namespace that `access` doesn't give as `e2e`.

  - An importer that holds an `e2e` target's keys MAY import a source that isn't `e2e` into it by sealing each patch set client-side, encrypting each blob as in §E.3.1 and rewriting its references to the new blob ids. A source resource named `keyring` goes in under another name, as the target's is its key ring (§E.3.2). The ids change, so pins to them, incremental documents and later imports are handled as for a renamed import (§G.4.4).

  - An `e2e` source goes only into an `e2e` target **with the same namespace name**, override or not (§E.3.1). Lines carry the ciphertext and the plaintext `keyring` (§E.3.2) verbatim, and ids verify as usual.

    - At step 1 the importer refuses a bundle with a blob line that lacks the sealed type or has a nonce (§E.3.1).

    - At step 1 it also refuses a bundle with a `rev` line, other than the `keyring`'s, whose `patches` are neither one `sealed` op whose `pl.ns` and `kid` name the line's `ns` nor a restore's `[]`.

    - Such history, as read through from a base, and an import under another name, are carried over as a merge, with new ids, by a client that holds both sets of keys. An exporter writes no line of such history but the `keyring`'s, exported whole under the branch's `ns`: it names the foreign parent in `requires` (§G.4.1), or refuses that document.

    - A target created for the import starts at the bundle's lowest epoch, and is moved up one epoch at a time as its keyring lines arrive. So the importer needs `config` on it, with a `*` key (§7.4).

    - An existing target is moved up the same way. It is refused at step 1 if its `keyring` would conflict with the bundle's (step 2), or if its epoch is below the bundle's lowest or above that of a sealed line it lacks (§E.3.1).

- **No snapshots at E3.** Documents of an `e2e` source are exported `full`, and an importer refuses snapshot documents for an `e2e` target at step 1 (§G.4.4, §F.8.1).

- **Plaintext of protected sources.** A bundle with lines from a `private` or `sealed` namespace holds plaintext, and SHOULD be delivered as a sealed bundle. Exporters SHOULD refuse to write it unsealed unless asked to.

#### G.5.1.1 Sealed bundles

A sealed bundle (`application/vnd.patchlog.sealed-bundle+jsonl`) encrypts a bundle line by line. The envelope is canonical JSON (§3.1), each line is followed by one `0x0A`, and a sealed bundle with any other line, a blank one included, is rejected:

```
{ "sealedBundle": 1, "id": "",
  "recipients": [ { "kid": "", "suite": "hpke-base-0x0020-0x0001-0x0002", "wrapped": "" } ] }

…
```

-
**Envelope line.** `id` is 128 random bits, base64url without padding. The content key `K_b` is 256 random bits, wrapped for each recipient as keys are in §E.2.3, but with the `info` `"patchlog-bundle-v1" ‖ 0x0A ‖ id`, `id` as its 22 ASCII characters. A recipient's `kid` is its thumbprint (§E.2.3).

-
**Lines.** Each following line is a JWE compact under `K_b` whose protected header is `{ "alg": "dir", "enc": "A256GCM", "pl": { "bundle": id, "line": n, "last"?: true } }` as canonical JSON, with `last` on the last line only. The plaintext of line `n` is bundle line `n` (header = 0) as canonical JSON, without its newline. Lines are never compressed.

-
**Checks.** A reader MUST reject the whole sealed bundle if any of these holds:

  - any line fails to decrypt

  - a line's protected header isn't canonical JSON or, `pl` included, has other members

  - `pl.bundle` differs from `id`

  - line numbers are not 0, 1, 2… in order, or reach 2³² − 1 (§E.2.1)

  - no line says `last`, or a line follows it

The decrypted bundle is then checked as in §G.4.1.

-
**Digest.** `source.bundle` is the digest of the decrypted bundle (§G.4.1).

-
**What stays visible:** the number of lines, their sizes and the recipients' thumbprints. Padding (§E.2.2) MAY be applied to each line's plaintext, and is removed before the checks and the digest.

## G.6 Multi-region (outlook)

A read-only mirror is a namespace kept current by incremental full-history imports (§G.4), which keep ids, and that follows its origin's purges (§G.1). Multi-primary writes are out of scope.

## G.7 Open questions

- Should bundles carry namespace configuration (roles, rules, limits, `schemaReads`), so a renamed import (§G.4.4) can clone a set of namespaces with its policy?

- Absolute pinned references, in `$schema` (§13) and `x-ref`, so a bundle can point back at its origin instead of carrying schemas.

- Signed bundles, covering the header and every line.

- A namespace flag such as `export: false`, a policy statement that well-behaved deployments respect.

---

# Addendum I — Test vectors (normative)

Values that §1 requires implementations to agree on byte for byte, each computed by the reference implementation and recomputed independently from the text, unless its section says it awaits the reference's confirmation. IVs and other random values are fixed for reproducibility. Byte strings are hex unless marked otherwise, and JSON is in canonical form (§3.1). A conforming implementation reproduces every value here for each part it implements, and rejects every input marked as rejected. An input marked illustrative or as a test only, such as I.9's lines, is a byte input only, not content a conforming deployment writes or accepts.

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
| `"\ud800"`, `"\udc00"`, `"\ud800A"` (lone surrogates) | `400` | — |
| `{"a":1e400}`, `{"a":-1e400}` | `400` | — |
| `{"a":1e-400}`, `{"a":-1e-400}` (underflow) | accept | `{"a":0}` |
| `{"a":1e20}`, `{"a":-1e16}` | `400` | — |
| `{"a":9007199254740992.0}`, `{"a":9.007199254740992e15}` | `400` | — |

Members sort by UTF-16 code units: `{"b":1,"a":2,"ä":3}` is `{"a":2,"b":1,"ä":3}`, and keys with characters above U+FFFF sort by their surrogate pairs.

Noncharacters are `400`, raw or escaped: U+FDD0 (raw, the bytes `efb790`), U+FDEF, U+FFFE, U+FFFF, U+1FFFE and U+10FFFF. U+FDCF, U+FDF0 and U+FFFD are accepted, raw or escaped: as `t` in `[{"op":"add","path":"","value":{"t":…}}]`, they give the genesis ids `1sxrx3wwzxwyahs7khilka36c6selzwrb`, `1jkaabmuivygpelkeuncgmiatzunwp5zw` and `137ielgcxtgdymhcykw5flzgaml4d6kbx`.

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

Text ids are exactly 33 characters, `1` then 32 of `a–z2–7`; 160 bits fill them exactly, with no padding bits. Rejected: `1L2GI2HHM3VT72LS2OUFQPKQPSH6UVMLL` (uppercase), `1l2gi2hhm3vt72ls2oufqpkqpsh6uvml` (32 characters), `1l2gi2hhm3vt72ls2oufqpkqpsh6uvml1` (`1` isn't in the alphabet), `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlla` (34 characters), `2l2gi2hhm3vt72ls2oufqpkqpsh6uvmll` (unknown version prefix), `l2gi2hhm3vt72ls2oufqpkqpsh6uvmll` (no prefix) and the empty string. `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm`, the bytes of `g` with the last one `6c`, is valid.

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

An edge ignores: claims with a fourth member; claims that aren't canonical byte for byte, such as the same members reordered; a MAC that verifies only over re-encoded claims, not the value as received; a name that doesn't match its `p`; an `exp` in the past; a `p` that covers the path only as a string prefix (`/r/demo` for `/r/demox`).

## I.6 Padding buckets (§E.2.2)

| `L` | Padded | `L` | Padded |
|---|---|---|---|
| 1 | 256 | 513 | 544 |
| 255 | 256 | 1000 | 1024 |
| 256 | 256 | 4096 | 4096 |
| 257 | 272 | 1000000 | 1015808 |
| 300 | 304 | 1048576 | 1048576 |
| 511 | 512 | 67108864 | 67108864 |

Rounding errors show just above powers of two (257, 513).

## I.7 Derived keys (§E.2.1)

For `K_e` the bytes `00 01 … 1f`, `ns` `demo` and `name` `derby`, 32 bytes out:

```
K_r = 37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25
K_n = b2d9864bdf7f562d58e3638e08ec2e97e553c74995edbcef110ee9adfed62b4c
```

From that `K_r`, with `info` I.2's ids and I.3's blob id, and from `K_e` with `info` `demo` ‖ `0x0A` ‖ I.8's `view`, all in ASCII:

```
K_rev(g) = cd871b109456a65f5a8fd3ed2d388530f48fbc564aab663b97c8dcbf899a4520
K_rev(c) = 862174c8254b0e713e89114a8ec5a08f5449425a83161bf9885aff737f7f4e4f
K_log(g) = 9abce0db7ac06d4b5f78bc5b049031bc1cc0ce3a6678e65ba7cff3ba0241ac90
K_log(c) = 81167117c493c3099541f3e98fa6273b77d2caf66aa2a8e055127ea3402943b0
K_log(t) = 438c584a2e28de744187018066861363e84f14a63e3b95d4eb1ea52d59b15f20      (t: the tombstone of c)
K_blob   = 5dfd0d03c4d8133d358deaa8f76733e86966efdf30a9523bfbab147f2044d74d      (bid 1m5jj344d7tz7cicfmq53ayhmwuubpmyt)
K_view   = 253c74b74bb46bdccd4b05348fbb1c07be9090c3c0b7d179c922a048b90e1db4      (view 17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm)
```

A tombstone has no document, so only its `K_log` seals anything.

## I.8 Views and combined checkpoints (§7.9, §A.4)

The subject strings and the two `ns_id`s of I.2 serve as inputs only.

```
subjects = ["group:match-desk","user:anna"]      view = 17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm
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

With escapes, `{"esc":"\"\\\/\b\f\n\r\t\u0000\u001f\u007f\u2028\ud83d\ude00\u00e9","\u00fcn\u00ef":true}` renders as 70 bytes (sha-256 `25a705341cb21ebb8a4fe6b4a4059fcf16d8ef3eeaed137094ba0f9dfc2f3c65`), with `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, `\u0000` and `\u001f` kept, `\/` as `/`, and the rest raw, U+007F and U+2028 included.

## I.11 Regular expressions (§6.6)

| Pattern | Matches | Doesn't match |
|---|---|---|
| `^\u00e9$` | `é` | `e`, the six characters `\u00e9` |
| `^\ud83d\ude00$` | `😀` | — |
| `^[\u00e0-\u00ff]+$` | `àéÿ` | `a` |
| `^\\u0041$` (an escaped backslash) | the six characters `\u0041` | `A` |

`\ud800`, `\udc00`, `\ud83dA` and `\x{D800}` are refused. Patterns and strings are shown as characters, not JSON; in JSON, the last row's pattern is `"^\\\\u0041$"`.

## I.12 Wrapped keys (§E.2.3, §E.3.2, §G.5.1.1)

X25519 keys and their JWK thumbprints:

| Private key | `x` | Thumbprint |
|---|---|---|
| `20 21 … 3f`, recipient | `NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ` | `5_RYhfysTyU1BDBnv9LSpAGNHJ_A1_UesBCKoRG370E` |
| `40 41 … 5f`, admin | `eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo` | `YKbZ9qRn_duml9RTz_7p5FNztMst4VCEVI2fzJCu4TE` |
| `60 61 … 7f`, ephemeral | `Z13VdO13iTELPS52gfN5C0ZsdzsVIf7PNld5WDcepS8` | — |

HPKE seals to the recipient with the ephemeral key, `enc` `675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f`, and in auth mode under the admin's key; the plaintexts are I.7's `K_e`, `K_r` and `K_view`, `kid` `demo#3`:

| Wrapped | `info` | Ciphertext after `enc` |
|---|---|---|
| `K_e`, base mode | `"patchlog-key-v1\ndemo#3\n"` | `13386e84aa77fad0af82e2a04ab738043314aabaf00288d5a7b19d2e51a286199487aff2c4b39fdd308fff2138fce511` |
| `K_r`, base mode | `"patchlog-key-v1\ndemo#3\nderby"` | `44df8b2081f0cd07201259e95859d355b4eb54fb127b63baa5008415035156c0e6edbdc1ce1e3e7f2b8d1a12bef36044` |
| `K_view`, base mode | `"patchlog-key-v1\ndemo#3\nview:17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm"` | `84e146c9c1e73365e83dec3586b5779b7e3b68b034ba9fc0ff1cf49119d67e2a8df3fc06872979f87646026dd7560841` |
| `K_e`, auth mode | `"patchlog-key-v1\ndemo#3\n"` | `43cec1d61c3e0101e1b5c9ff5d87ffbf3b88c348d886ee56d4ac596b3d896a5e9d2f5ed1c215a94f4c9ac0b9a63d854c` |

`wrapped` is `enc` followed by the ciphertext, and the auth-mode one opens under no other sender. A `keyring` entry without `kid` or `wrapped`, or with a `from` that isn't a thumbprint (`"admin"`), is `422` (§E.3.2). This sealed-bundle envelope wraps `K_b` `dbe5882e2579683432c1bfc525454add0cd87274d67084caaf0e0d36c8496db7` to the recipient:

```
{"id":"auZ4P0-96RtuuItzpI7SRw","recipients":[{"kid":"5_RYhfysTyU1BDBnv9LSpAGNHJ_A1_UesBCKoRG370E","suite":"hpke-base-0x0020-0x0001-0x0002","wrapped":"qOEsrFfQ5Y0IhiuiliORWAQzhGlJcMKuQw90ZdV851fEb8UlPgrdP1U8de6PBjNaodTtMiXXXGFcMBEQ3tDUBPy8Q4SkD88eVuu5cHhiB_U"}],"sealedBundle":1}
```

An Ed25519 key with seed `a0 a1 … bf` has `pub` `T9CZzNR9eJPf6ewkQU7LDZtUICMqrTDZHEZb4zy-ZcQ` and `/principal` `key` (§7.4) `7c_8cf3VPZjtkqQSzpjXvbhEeMBVVWow5j-JOgj_uu8`.

## I.13 Sealed payloads and blobs (§E.2.2, §E.3.1)

With I.7's keys, `kid` `demo#3`, the IV `c0 c1 … cb`, and protected headers and plaintexts in canonical form, the document of `g` (I.2) seals under `K_rev(g)` as

```
header = {"alg":"dir","enc":"A256GCM","kid":"demo#3","pl":{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"doc","name":"derby","ns":"demo"}}
JWE    = base64url(header) "..wMHCw8TFxsfIycrL.Phlvrjb-VTs3mn8RXc8xX40b3qg5WY-9dCNY._Y5aruVU4bSOaU-64iXJBA"
```

and padded to 256 bytes has the tag `r4lkevRuwdj3KQnE_8nRbA`. Others, unpadded:

| Payload | Key | `pl` | Plaintext | Tag |
|---|---|---|---|---|
| grant (§C.3.1) | `K_n` | `{"grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","ns":"demo"}` | the `{ id, root, stored }` of I.14's token | `sAMGTdYa8kLrAP_ZfHvxCA` |
| E3 patch set | `K_r` | `{"name":"derby","ns":"demo","parent":""}` | `patches₁` | `fWUF3aRPE9iH4t3VjKOypA` |
| E3 prune snapshot | `K_r` | `{"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","name":"derby","ns":"demo"}` | the document at `c` | `e0EUoxYNQi0Z75xSLBdZ0Q` |

The E3 write `[{"blobs":["12cpfgvfvu3goo36nr6agtphftlh7zktj"],"op":"sealed","value":<the E3 patch set's JWE>}]` has the genesis id `1ptb7hgvw5g5msprod2l5d2pp5b2mtppz`.

I.3's blob sealed under its `K_blob` with the header `{"enc":"A256GCM","kid":"demo#3","pl":{"blob":"1m5jj344d7tz7cicfmq53ayhmwuubpmyt","name":"derby","ns":"demo"}}` is these 168 bytes, and 401 padded:

```
504c42310000006d7b22656e63223a224132353647434d222c226b6964223a2264656d6f2333222c22706c223a7b22626c6f62223a22
316d356a6a3334346437747a37636963666d7135336179686d77757562706d7974222c226e616d65223a226465726279222c226e7322
3a2264656d6f227d7dc0c1c2c3c4c5c6c7c8c9cacb55c032b23b8b9a1cae367c49b2dd276fcedfdd1ec139aa46c026482d5c459f330a
47045d9ea3e9
```

At E3, under the key `e0 e1 … ff` with the header `{"enc":"A256GCM"}`, it is these 76 bytes, with blob id `1chzlyccn2qkoz6mobtbzvzm4s6h7pbi6`:

```
504c4231000000117b22656e63223a224132353647434d227dc0c1c2c3c4c5c6c7c8c9cacbcc88d40f44c1d0d6e50c8ca401981a60
7fc1775e65261b295105e89abdd9fb3efc9d159ad6e9f0

{"$blob":"1chzlyccn2qkoz6mobtbzvzm4s6h7pbi6","sealed":{"key":"4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8","size":15,"type":"text/plain"},"size":76,"type":"application/vnd.patchlog.sealed-blob"}
```

## I.14 Biscuit grants (§C.4, §C.8)

With the root key of seed `00 01 … 1f` (`pub` `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`), this token carries I.4's root block and the narrowing block `{"can":["read"],"via":"svc:reader"}`, with Biscuit's version 1 signature payloads:

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpA8F--Z-0pJdeRlyhAqVvLMmB_GniPzob9JmjQ
7YO0D3Q2C3CKHXITLKHBjp3DfkQNccX2F8XKmGJl-6o7fmuICSgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
```

Its revocation ids are `15swdvi5nbnlkv76v7y6k77h52atov6ru`, the grant id, and `1chpmwycvsbh7sqmzckzhe7hk6obtra72`.

## I.15 Plan digests (§F.9)

`release` names a revision of `/r/releases/release-7`, whose genesis document `{"branches":{"matches":{"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"matches-r7"}},"name":"release-7"}` has the id `1bx3m7usot3btfia44al7op7h4tbzwprh`. I.2's `ns_id`s serve as `source.at` inputs only.

```
plan₁ = {"batches":[{"items":[{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","resource":"derby","steps":[[{"op":"replace","path":"/views","value":1}]]}],"ns":"matches","source":{"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"matches-r7"}}],"release":"/r/releases/release-7/rev/1bx3m7usot3btfia44al7op7h4tbzwprh"}
digest  1pjgzny3luqmeyoud4lqoqh4qkmfazvmc
```

As submitted, `plan₂`'s first step for `derby` starts with `add /$nonce "abcdefghijklmnopqrstuvwxyz"`, `final`'s root `add` value has `"$nonce":"zyxwvutsrqponmlkjihgfedcba"`, and the restore of `derby` is `[{"op":"replace","path":"/$nonce","value":"zyxwvutsrqponmlkjihgfedcba"}]`. These fresh nonces are left out; `semi`'s `$nonce`, not of the fresh form, stays:

```
plan₂ = {"batches":[{"config":{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"add","path":"/x-release","value":"release-7"}]},"items":[{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","resource":"derby","steps":[[{"op":"replace","path":"/views","value":1}],"delete"]},{"ifNoneMatch":"*","resource":"final","steps":[[{"op":"add","path":"","value":{"title":"Final"}}]]}],"ns":"cat-season","source":{"at":"1vmctae4vewju6nvxi374rkrkmyzpdrif","ns":"cat-season-r7"}},{"config":{"ifMatch":{"batch":0},"patches":[{"op":"remove","path":"/x-release"}]},"items":[{"ifMatch":{"batch":0,"item":0},"resource":"derby","steps":[[]]},{"ifMatch":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"semi","steps":[[{"op":"add","path":"/$nonce","value":"not-a-fresh-nonce"}]]}],"ns":"cat-season","source":{"at":"1vmctae4vewju6nvxi374rkrkmyzpdrif","ns":"cat-season-r7"}}],"release":"/r/releases/release-7/rev/1bx3m7usot3btfia44al7op7h4tbzwprh"}
digest  1gb5opshmkfmbtlbfl6r757kmn6ghg523
```

With the fresh nonces kept, the digest would be `14cecare46eelmff7a4i5ozpsy34ibprk`, which is wrong.

## I.16 More file renderings (§H.1)

| Document | Rendering | sha-256 |
|---|---|---|
| `{"$successor":"derby-2","title":"Old"}` | 21 bytes, `$successor` left out | `95c95285328c1d56eaf7e4dd8b1ba60c392bfaa53761355ccea198833ae5fe31` |
| `{"$successor":"/r/archive/derby","title":"Old"}` | 21 bytes, `$successor` left out | `95c95285328c1d56eaf7e4dd8b1ba60c392bfaa53761355ccea198833ae5fe31` |
| `{"$successor":"Derby-2","title":"Old"}` | 48 bytes, kept: `Derby-2` isn't a name (§8.1) | `04a1f8ba82d0d49bf9a8a149076965e8866a27f0b3df19f44bbb45c6746bb717` |
| `{"$nonce":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","a":{"$nonce":"abcdefghijklmnopqrstuvwxyz"}}` | 102 bytes, both kept: the top one isn't of the fresh form, the other is nested | `c67746c9019b8773dc1c558a3b9049db759c7a1fdb16b0aa6fa68d5b33026f0a` |
| `{"$nonce":"abcdefghijklmnopqrstuvwxy","title":"x"}` | 60 bytes, kept: 25 characters | `8bd15ae28c23567141a8a5fe4f34285c8d8e0e1a951ba1873abcef928fe76a78` |
| `[{"$nonce":"abcdefghijklmnopqrstuvwxyz"},1,[],{}]` | 72 bytes, an array root: nothing left out | `d137603b109205bf00928b0a7464c301028cc2b06cdc4dce4b88442da439110a` |
| `{"a":1e21,"b":1E-7,"c":-0.0000015,"d":123e-20,"e":1e300,"f":5e-324}` | 96 bytes, numbers as below | `ce6c041baed107608b8fa6cf79598a0ef01e43843a1ea631f46d91ede1507e04` |

The last renders as these 96 bytes, each line followed by `0a`:

```
{
  "a": 1e+21,
  "b": 1e-7,
  "c": -0.0000015,
  "d": 1.23e-18,
  "e": 1e+300,
  "f": 5e-324
}
```

## I.17 Sealed bundles (§G.5.1.1)

These values were recomputed from the text alone in v0.85; the reference reproduces them.

I.12's envelope wraps `K_b` `dbe5882e2579683432c1bfc525454add0cd87274d67084caaf0e0d36c8496db7` to I.12's recipient, the X25519 key `20 21 … 3f` with thumbprint `5_RYhfysTyU1BDBnv9LSpAGNHJ_A1_UesBCKoRG370E`. Under `K_b`, with I.13's IV, it seals the three lines of I.20's accepted bundle (`"authors": false`), with the headers

```
{"alg":"dir","enc":"A256GCM","pl":{"bundle":"auZ4P0-96RtuuItzpI7SRw","line":0}}
{"alg":"dir","enc":"A256GCM","pl":{"bundle":"auZ4P0-96RtuuItzpI7SRw","line":1}}
{"alg":"dir","enc":"A256GCM","pl":{"bundle":"auZ4P0-96RtuuItzpI7SRw","last":true,"line":2}}
```

The sealed bundle, the envelope line and these three lines, each followed by `0a`, is 1580 bytes (sha-256 `64540cd81c52da8d150e9db78e5255f8aee5b9e4c3ef1e568fbf15204976655b`):

```
eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxpbmUiOjB9fQ..
wMHCw8TFxsfIycrL.1je8c_l5IqsDIj3qKwSOkse7U10vRPoDkyjcMe3-rxdk85yQi4WAWXnlssEuQ2dDtASsNN7c05xpxSNgFCw3xjQJMbF
Rct5zWoJjzaQb7slY5USwwc92EZfDdW9S0wcoaEM9uSE7FrwpzH9RPxnuNdZb4G118X996yihe9vJkznmKTMyLdQ31DnpMXIfDhJlnyicX96
K7yo-E7hiAe9oGc8I2phtQZRhpWf--3WF0fWsfp1ueq8VUgphdgZ5OEuXANkL6BneOHm8e5n7GUohAWgFRT0fXsvAmYRhh6WPguXuG47aTxU
dYdKNtlo9oOyY8SaBlPdo6N_VF7XIgD4e1y_NSwSsx8cnIJm3.RybvCcTQ8coZcrNsotjdug

eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxpbmUiOjF9fQ..
wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfA
ELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2
EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.zJJLhqznyED1wpuSl5sA3Q

eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxhc3QiOnRydWUs
ImxpbmUiOjJ9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lSYTGgc1GRgcDtQ0twHORDgDDWMf6w4Vow9Y2Gy5KXUDq988IiXiFbrBeuMJqQl4h
uwTMjUnMy2CYHLfAELI95X8VtxLxfpJMf5FSqhN9_DI6YbGkWw1E9O0A7unxpH7g323sCaFWydZgavipk5G56oXfwa9Gg3ja4aTw4O_JjkG-
4Yi0NEmo30n6QEofb4mYsVKJwV6AiCt1Ly5g9Gdw-wjD-4XWX2qLkP8k_OfoZAkxof0s3.9nAggSbYpBD7B_F6uSf_wQ
```

Decrypted, it is I.20's accepted bundle, which §G.4.1 accepts, and its digest is that bundle's, `1wmmkh2s4kkveocf5yh4uzoookxmrzptr`; that of the sealed bytes, `1mrkazwa4klni2fiotw3y4usv7cxolope`, is not `source.bundle`.

Padded (§E.2.2), each line's plaintext is followed by spaces to its bucket, 272, 256 and 256 bytes, and the lines' tags are `1iIYtbZyZy2yof46mGghnQ`, `seB2BjFUe7yaCu_nktvOVA` and `xrIfbpvxGdlXILIiZ8Mbtw`. That file is 1789 bytes (sha-256 `33985a4988eeb73818522d110b966dd66cedaec008775344e0876d7e4d86bd30`), and decrypts to the same bundle once the spaces are removed.

Each of these changes to the unpadded file rejects it whole, by the rule of §G.5.1.1 given:

| Change | sha-256 of the file | Rule |
|---|---|---|
| line 2's `pl` members out of order | `8bedffe110d76287ba43de22a7d71c2bf2ce7ca4fbf64284820d2e8f1aeb2f41` | a line's protected header isn't canonical JSON |
| line 2's header with a space after `"pl":` | `1d45a5a65c6deb2352a0f22239b9924cbcef0c585cb5f26846943b903534d3dc` | a line's protected header isn't canonical JSON |
| line 2's `pl` with `"ns":"matches"` added | `810c72ca2a3fdf048ae4d887f6d3b48f1880f36eab45237c46b1e5096a3492d0` | `pl` included, has other members |
| line 2's `pl.bundle` `AAAAAAAAAAAAAAAAAAAAAA` | `28c709a56f132218637250ac5e8da68e092d984b596957da5fb743a6b4f2a437` | `pl.bundle` differs from `id` |
| line 2 numbered 3 | `315705d09ae62e77b5acb14c34f1a6b4412e1a1573331874f532d8db67f5db70` | line numbers are not 0, 1, 2… in order |
| line 2 without `last` | `6bfaaaaff95646852e1fa4be7055cb19584800d3547b75096fab3981b7b32bc8` | no line says `last`, or a line follows it |
| line 0 with `last` | `3d2a7f635416701defee2ed48a9e9e4646b798cbd9d6fea7b9b92d237ee7bba8` | no line says `last`, or a line follows it |
| `0d 0a` after the envelope line | `1f345cb4553e1b91b228fb1d45a02033a1ca2c60ae688b5d46072274c08c833b` | each line is followed by one `0x0A` |
| `0d 0a` after the last line | `8cfe78bf7d9b381dbc7dbdad4f1aa4e0d8fcd4b9660eee1da74610c06eb50641` | each line is followed by one `0x0A` |
| the last `0a` removed | `b34b1b3728b128d1299aef08321db03326ce163179353675e8a43a89b1fa05a7` | each line is followed by one `0x0A` |
| a blank line added at the end | `7602a14e188a68c2e17e7e48efaf6bfdf852d199d4f15e095284c1fc8e07e30a` | a blank one included |
| line 2's last character `Q` made `A` | `f69e76d711dec63dd3d892b5dc9b6073587ce8b4f624aafb4627ac137fb54613` | any line fails to decrypt |

## I.18 Hostnames (§6.2 step 5)

| Instance | `hostname` | `idn-hostname` |
|---|---|---|
| `"ab--cd"` | accept | `422`: `--` in positions 3–4 without `xn--` |
| `"·"` (U+00B7) | `422` | `422`: CONTEXTO without `l` on both sides |
| `"l·l"` | `422` | accept |
| `"XN--BCHER-KVA"`, `"xn--bcher-kva"` | accept | accept |

## I.19 Sealed log entries, namespace documents and ranges (§E.2.2)

With I.7's keys, I.13's `kid` and IV, these illustrative plaintexts, which no deployment could write as given, seal as below:

```
entry_g  = {"author":"user:bob","created":"2026-10-04T12:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}]}
entry_c  = {"author":"user:bob","created":"2026-10-04T12:05:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","parent":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"replace","path":"/views","value":1}],"via":["svc:translator"]}
entry_t  = {"author":"user:bob","created":"2026-10-04T12:10:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq","kind":"tombstone","parent":"1sywh54kpo3c4ezn2znktvl3avge4zl5d"}
nsdoc    = {"encryption":{"epoch":3,"level":"sealed"},"keys":[{"alg":"Ed25519","can":["*"],"kid":"ops-2026","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}],"read":"public"}
nsentry₁ = {"author":"user:bob","created":"2026-10-04T11:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1vmctae4vewju6nvxi374rkrkmyzpdrif","kind":"config","prev":"","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
nsentry₂ = {"author":"user:bob","created":"2026-10-04T12:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","kind":"head","prev":"1vmctae4vewju6nvxi374rkrkmyzpdrif","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
```

`nsentry₁` and `nsentry₂` rehash to I.2's `ns_id₁` and `ns_id₂`.

| Key | `pl` | Plaintext | Tag | Padded |
|---|---|---|---|---|
| `K_log(g)` | `{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","name":"derby","ns":"demo"}` | `entry_g` | `yfH2leZO8n6cjMECUyyH0w` | `Cg07e1dKHUMl2OYuEpdkSw` |
| `K_log(c)` | `{"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","name":"derby","ns":"demo"}` | `entry_c` | `OwyEAM7T4CfqJF3xn8GEUg` | `jS361xdyARKseb0gclHqRQ` |
| `K_log(t)` | `{"id":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq","kind":"tombstone","name":"derby","ns":"demo"}` | `entry_t` | `EY1dwq_IW1TRlQ5byJICtw` | `syUJgGok3oXkkZH16gYrEw` |
| `K_n` | `{"id":"1vmctae4vewju6nvxi374rkrkmyzpdrif","kind":"doc","ns":"demo"}` | `nsdoc` | `g9GNuYsEUxQIUflrD4Pgrg` | `y3m-vOgPYKJ_ng0H3nB7WA` |
| `K_n` | `{"ns":"demo","range":["","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"]}` | `[nsentry₁,nsentry₂]` | `3CUwPfA7GtS8GLr7bQFbuQ` | `iwW5mt5KJ1sbvzneqrT6PA` |
| `K_n` | `{"ns":"demo","range":["1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"]}` | `[]` | `gFdn5cMoLtKWpkGcZKvRcg` | `81hR8mEqKtouAa1XtJCNqQ` |

`entry_g` seals as

```
eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsiaWQiOiIxbDJnaTJoaG0zdnQ3MmxzMm91ZnFwa3Fw
c2g2dXZtbGwiLCJraW5kIjoicmV2IiwibmFtZSI6ImRlcmJ5IiwibnMiOiJkZW1vIn19..wMHCw8TFxsfIycrL.L4p9srPTK8kfVFYYWc6us
y3emYKt299y0itdBeyuLrpQ-67Z6tcNFDOMUIGkLOXPxz6TAUIOfXfqZUyvG7DmknXFq9ADXKKszznqLj5n9E3g45WXrthe2ZmTPUbT5A_-i
4RcQspLxNE6whYY3aJr9_ZwAs3bmBgnF8XPSPo6eGEULPma8kllMXUhsD_tn78LAW_TuE05gq0IekdE3wLxlQ1yzozin8PGXGCG312Bw7TC0
McmXEtFnNm7iTGOYMKAfY7rQDt-ZwPUQJmO-KkNWQYlAjwTFmKpdSe-EIfFxPwTS4hSxTILH5vBFsyrqKmHcKYEMcYW5FvISfkgyYvmKxdBE
QOIq2JCG1l9RlzKKzBA0sSO531e_g.yfH2leZO8n6cjMECUyyH0w
```

and the resource log range from `g` to `c`, the array of `entry_g`'s and `entry_c`'s JWEs, is 1247 bytes, sha-256 `0a85cba9eca3bb3ba7a4845c62c6012725de2414df30803788f3639d4e470459`.

## I.20 Full-history lines with `via` (§G.4.1)

This bundle exports `matches/derby` in full, `c` written through a delegatee. `stored` is the authority block of I.14's token, and `key` its root key:

```
{"access":{"matches":"private"},"at":{"matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"},"authors":true,"bundle":1,"created":"2026-10-04T14:00:00Z","docs":{"matches/derby":{"head":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","history":"full"}},"origin":"https://staging.example"}
{"grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","key":{"alg":"Ed25519","kid":"ops-2026","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},"ns":"matches","root":{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"},"stored":"CqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xBRUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgB"}
{"author":"user:bob","created":"2026-10-04T12:00:00.000Z","grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}
{"author":"user:bob","created":"2026-10-04T12:05:00.000Z","grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","ns":"matches","parent":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"replace","path":"/views","value":1}],"resource":"derby","via":["svc:translator"]}
```

It is 1543 bytes, digest `1hywrrzishsfdu5qs4tinxvnb3rs2tcv5`. Rejected (sha-256): without the grant line, `5d0f3f9233e8681d63ffdcb4659049f0c7617bff5eeb1c2ecf3f4d5fe82b2bfc`; with `"authors":false`, `71b8a5ad487898f1b63aaf3aaabc4cc5009328818d2d1c47ee6fbc037660f95a`. With `"authors":false`, no grant line and the history lines without `author`, `via`, `grant` and `created`, it is accepted (631 bytes, digest `1wmmkh2s4kkveocf5yh4uzoookxmrzptr`), and rejected if `c`'s line keeps its `via` (`0721b8e6915c6921de2650a7f2d26732c5426ab6faf5be5a421b64ed711ea18e`).

## I.21 Biscuit tokens refused (§C.8)

Each is I.14's token with one change, from the same keys (root seed `00 01 … 1f`, next keys `40 41 … 5f` and `60 61 … 7f`, the last the proof) and version 1 payloads unless stated. A changed authority block moves the narrowing block's string to the next free symbol. Each is `401`, at decoding or at verification.

The authority block has a second fact, `other("x")`.

```
Eq0CCsABCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
CgVvdGhlcgoBeBgDIgoKCAiACBIDGIEIIgoKCAiCCBIDGIMIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0aQEl7OJMN
mq894Ni30iWMke5cJ2OqiI5RA1fzkgw21X8klE_8_3reMOmR2k_MGsxYK4Bk-H0efPf3oD5coDCY2QMoARqfAQozCiN7ImNhbiI6WyJyZWFk
Il0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIQIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQCnsv-5R
KUfz0GfMcWyyUR9AQAzbAbR0dMCVcCMEEAG5h-VUhEoOdyLnHYdCP8KSmtszEiXDCFmUSjVQYzyzIgkoASIiCiBgYWJjZGVmZ2hpamtsbW5v
cHFyc3R1dnd4eXp7fH1-fw
```

It has a rule, `r($x) <- grant_block($x)`.

```
ErMCCsYBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
CgFyCgF4GAMiCgoICIAIEgMYgQgqFAoICIIIEgMIgwgSCAiACBIDCIMIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0a
QEMeFlIWVhD2Mtcln82NbVdrUASHXczfAbe6BXbNL-ckjiXV9DLdJoQJ0krlHDLOcuswj2ybY1-rZyTd0EwQYwEoARqfAQozCiN7ImNhbiI6
WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIQIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9Ua
QHUztUGasSvrO7Suj4TG5Di4dlZ0CwHYkDRcLbNbo7Ic4R1nnfc-DgZWMoDVsns4AbFfexyrRKsMabEAhK26uwkoASIiCiBgYWJjZGVmZ2hp
amtsbW5vcHFyc3R1dnd4eXp7fH1-fw
```

It has a check, `check if grant_block($x)`.

```
EqwCCr8BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
CgF4GAMiCgoICIAIEgMYgQgyEAoOCgIIGxIICIAIEgMIgggSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAR1-NRajf
ujomdVRR4Y7NEys6r2hBj27PmGzcByaALHhXdUPyl3STVkPivhgE9-X9YMP1tDCRiHSL7PccL97aCSgBGp8BCjMKI3siY2FuIjpbInJlYWQi
XSwidmlhIjoic3ZjOnJlYWRlciJ9GAMiCgoICIAIEgMYgwgSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAuDzGw1w6
nvkKUnXJwODHwG0Txr4xMtmWR5jkVbm9dW6HJXkzPSFugR6_qP0d0oM6h8GgrjTcocmRhTV9TgZBBigBIiIKIGBhYmNkZWZnaGlqa2xtbm9w
cXJzdHV2d3h5ent8fX5_
```

It has a scope (`previous`, field 7), block version 4.

```
EpsCCq4BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAQiCgoICIAIEgMYgQg6AggBEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0aQCPImRRGP2qQCBEvD5UGJjcOC4U6XgOr
cDpuBHq0wKgnZTnmeZ5ZhKYTOuNMh2hkDKHi5NyYLjZg7qwnw-rZ5QwoARqfAQozCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFk
ZXIifRgDIgoKCAiACBIDGIIIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQDniuBfVIBOgnCxj2ylpuYG6c3iWjnOi
ZZoXyNGhTSDLHPAlxlFinctu8ojYx5olBu9SItvPqqjzoD0WcXWx2w4oASIiCiBgYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw
```

It has a public key (field 8, the Ed25519 key of seed `80 81 … 9f`), block version 4.

```
Er0CCtABCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAQiCgoICIAIEgMYgQhCJAgAEiDNFLN_lW6VMZT_f7c7PYHcxWHWGnU4CUt8PhpkPuXzqhIkCAASICVDuS_xCVURR2rcg2nbbdyTNmWhGXjd
oUBO4QZsqVWdGkByv1Hig7-CrVs2aXKwUSJGYV0hZsZbaehLhuUC8F6jtzvMjjZN7z84L-sHbAmV7qw77Vpwrgmq2Fsi2rY3hf0BKAEanwEK
MwojeyJjYW4iOlsicmVhZCJdLCJ2aWEiOiJzdmM6cmVhZGVyIn0YAyIKCggIgAgSAxiCCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5
W31DpjSCmT_VGkA4kg3TCo-O4gUJ5XiGUJf3JuP7ZY-84tILst34mtgIENMEG5R2eWad-hVFgGG-aGSRgDj7DB3t2qQSrpb5W-wPKAEiIgog
YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8
```

It has the context `"x"`.

```
EpoCCq0BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSAXgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAUPmaULUy5RF5lG2FHxaVvzrhUae6iNmH
nh55uMN5YQCOQxJJzkWjjQ3o3I-OITfeit0zhNSYQ0XnlV-GVVGOBygBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRl
ciJ9GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAmp68almcrK-Mzu0DEEM6ZUD6N8idRK88
JCiz1Zx1Q06hmUb6Gz8P24LcWpuJIO2qITvk52VILDtW67NMEu0sCCgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
```

It adds a symbol it doesn't use, `"unused"`.

```
Ep8CCrIBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
CgZ1bnVzZWQYAyIKCggIgAgSAxiBCBIkCAASICVDuS_xCVURR2rcg2nbbdyTNmWhGXjdoUBO4QZsqVWdGkABHkzjKHlk1FObwQnJLmA_JaFW
9ERQ3WbPKZEy-zknWU06zOjg7nKgoScjeO9saJceXIrNQXZ8p2du2V8eIMcOKAEanwEKMwojeyJjYW4iOlsicmVhZCJdLCJ2aWEiOiJzdmM6
cmVhZGVyIn0YAyIKCggIgAgSAxiDCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5W31DpjSCmT_VGkCF05c_PmlYcjFsYplLVcsM-81k
RpSfC7VuDJL0MUjmln8LMpY-0jvZ3JHTZ1RTC6wN26iAz74ycJQWysl9xU0HKAEiIgogYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9
fn8
```

It adds the narrowing block's string as a third symbol, which only the narrowing block uses (adding none, its fact `grant_block` of symbol 1026).

```
ErwCCs8BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
CiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIEIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2h
QE7hBmypVZ0aQNLkziAVYiQ9Kse5KI3wTLTk0O9IqxEkkhj9-2QHU9jXtI9A0cT45WdWauYECQwPCzvRBwIoL7ThM9ai-xXOYAQoARp6Cg4Y
AyIKCggIgAgSAxiCCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5W31DpjSCmT_VGkD073dRSsrJFv-DLYHazlyPesuHGJFEdxAHBaIV
06Hmnpl9XshSYxTVZk1dqUF9DfIZns-MgOJZ5I6NqFMOLrENKAEiIgogYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8
```

The narrowing block is a third-party block, signed by the key of seed `80 81 … 9f`.

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGpYCCkAKC2dyYW50X2Jsb2NrCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6
InN2YzpyZWFkZXIifRgFIgoKCAiACBIDGIEIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQNbQ-oX6pQ79jfsayswb
-rCyc2lrufPqxcB0jaOiWsmZ-rJRDa4pNUo082MJgyBlIsJxzMBYpCHvTofJ3By8OwUiaApAMepp01be37N-SFI_cZG0PhW2GwwAQi1s5TUb
Ozd21YFEcPHuA4TqU8g1cDKZo2u4z9hJyRQ4LprOd2nPrifWDhIkCAASIM0Us3-VbpUxlP9_tzs9gdzFYdYadTgJS3w-GmQ-5fOqKAEiIgog
YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8
```

The authority block is signed over the version 0 payload, without `version`.

```
EpUCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAR390ES6m124CT6-KfW2uw4Dz91xj3lHTZ2wi
GCUREGUqs3kk7wCcinN8DPoiBXLEX7PoVBedXK_PoFGVIzKGABqfAQozCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgD
IgoKCAiACBIDGIIIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQHIVW_i9u7EX4ZcJWY7KitWIGP4iXhkBNLMlaeGh
u40nYiYCSwC8Th4q7ykp_Ra6FZqi5MijSY5f95vf7ZoZ5g4oASIiCiBgYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw
```

So is the narrowing block.

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp0BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAcA3tGSSm6ajG_NROGP6AFsVAKl3cr85rtTGG
kGEuLIYZx_xGlNa3SHvsSTqPbayA-5_XuAMkQx0BprCDi6z8CCIiCiBgYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw
```

The root block's string isn't canonical (`sub` first).

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsic3ViIjoidXNlcjpib2IiLCJjYW4iOlsicmVhZCIsImFwcGVuZCJdLCJleHAiOiIyMDI2LTEwLTA1
VDAwOjAwOjAwWiIsImdyb3VwcyI6WyJtYXRjaC1kZXNrIl0sImtpZCI6Im9wcy0yMDI2IiwibnMiOlsibWF0Y2hlcyJdLCJydWxlcyI6W119
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAcl6tmCuIQr0Sf8VOrjwrXfu5dML1lbYTZoGY
Ft3bUFjx0_Ubf-ngNMynTpbJNv_NnyFEnJuWdAsksz79PWAgBSgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpA_HTtOWbEtTXzBQQpwi8l-P65addwtyDxQAoI
xFGVFhdAcZkw7Jeknj2qBTmHjTtDt4OQKBWnOfcXMZh7eAeZDSgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
```

It isn't I-JSON (`can` twice).

```
EqYCCrkBCgtncmFudF9ibG9jawqbAXsiY2FuIjpbInJlYWQiXSwiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQw
MDowMDowMFoiLCJncm91cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJz
dWIiOiJ1c2VyOmJvYiJ9GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAjGh-c7mWOMteDUc5
GfxjQIwXZIie-JZKwXHwH_4dxFgGDSOq8uN9jmYRVcirj1EL9GLN3ZCFIIMMMUCK0xP4DygBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlh
Ijoic3ZjOnJlYWRlciJ9GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpApGaErwqXXddS9gqB
eZNppXDuAIkS8OhiIZYLzilPtOcb8y3HRkSM8XWq8s_qZEGH0oJyT9yVGaVxVA7i-wmNCygBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2
d3h5ent8fX5_
```

The narrowing block's string isn't canonical (`via` first).

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp8BCjMKI3sidmlhIjoic3ZjOnJlYWRlciIsImNhbiI6WyJyZWFkIl19
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAVmrKLY4WSXy7s6htcC8ZlgHUk27hc6QU-d86
-AbaHeqvEYEk3ojYPQHHtkBUiNwA-i8Iektt8lUzk3Kn7zP5BigBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
```

The narrowing block is signed with P-256 (scalar `40 41 … 5f`, the authority's next key; RFC 6979, DER).

```
EpgCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJQgBEiEDaOx88IzUEG5DsU3olUJlIr0KRRUMAn5Fx5U0NNdH57oaQHqHeWsBki_VRw5_8nE22sfRBPmpIuiY5eck
pKxrRRpEmrz_6jBY1QWYWZby29V0EsfPmL932WIyUZwYa012gwMoARqnAQozCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIi
fRgDIgoKCAiACBIDGIIIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaSDBGAiEAoajS-Qur0ZnLwOeRJaVyop_4vsQ7
-KcdWOcI0HT8XYUCIQC6FhLr9EruwScelqszavV4ejXoGcqtywOBF80k-sFX6igBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8
fX5_
```

The authority signature has `S + L` in place of `S`.

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
RUsBNE2XF1SKISXZ8li1rcyHXtpv1sYSQLSXob_gozBFMAKwFCgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAmkL2iVmnS3RAE2GyQOA7eDsLWGSE_QwUzTtk
YqyO9-v3sqKclQiVM6vMbvfMbHuT7XqCedi7XnYN_K1hia5PBCgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
```

The root block names `kid` `ops-2027` (grant id `1d7hzis4zva7kl5aa3hi7cr3lxslua25j`), where the namespace lists `ops-2026` with I.14's `pub` and `ops-2027` with `Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc` (seed `20 21 … 3f`).

```
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNyIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAu-gwaE_qNuMT-3TIHQFkGRx28PgT3Qs7xmmq
oUovqFTdPPtiiFR-X8ktpRvWwc0xN_KLRHaI5fMfNGNtnF3vDSgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAtiLICY5OX_83a517DhTHhIr8RhXN-poWBLls
DeMRPJ9006SE3zvfK3OOuEskZ1vQyqu9d1opOlc2yImulUkuDCgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
```

## I.22 Sealed events (§E.2.2)

With I.19's keys, `kid` and IV, and `pl` as §E.2.2's table gives it. A resource event's plaintext is its namespace entry without `id` and `prev` (§7.3), and a namespace event's is its one entry, here I.19's `nsentry₂`:

```
purge = {"author":"user:bob","created":"2026-10-04T13:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"kind":"purge","resource":"derby","target":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq"}
prune = {"author":"user:bob","created":"2026-10-04T13:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"kind":"prune","resource":"derby","target":"1sywh54kpo3c4ezn2znktvl3avge4zl5d"}
```

| Payload | Key | `pl` | Plaintext | Tag | Padded |
|---|---|---|---|---|---|
| resource `purge` event | `K_r` | `{"kind":"purge","name":"derby","ns":"demo"}` | `purge` | `2Lr0YlsnReKv3Vu1vzww6w` | `o6qg_FLKKyVd-bUUDCd0WA` |
| resource `prune` event (horizon `c`) | `K_r` | `{"kind":"prune","name":"derby","ns":"demo"}` | `prune` | `DQW969cxsNvKvMFoLcdwHw` | `UqL8Ockwt491woTRn4ov6w` |
| namespace event for `ns_id₂` | `K_n` | `{"event":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"demo"}` | `nsentry₂` | `IegL6XMQn_6bp6mbVNkAhQ` | `zxVQ6oolCdXa4Bl6cJIlXA` |

The namespace event in full:

```
eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsiZXZlbnQiOiIxcGEybmg2aXcyeWQyZGpxZnkyd3Jz
emQ1a2dsZnB4dm0iLCJucyI6ImRlbW8ifX0..wMHCw8TFxsfIycrL.u8c251n3WG3uDvexX6uwqBTPKeBvMQlL6b6hdn6BXzGasJsQYlzR2i
Rxzmt6VvZnsT23l0wx0KocOYbmfx5u4j-_DQ2xvuhBRCpvZdadGJoEhHO6FLSfwwSaX5egIQARrBBTZhH59ABtgAByLNLCl2cC0zdgCD3pmc
nL3myyHmW8yaZ9F4RPBKS2IfqEh_aB-24mj6LA_qpnyYuKX00RfNsEhfpHqjcOjWbhoDTEtkSho4uTVjf1EIE6uhwDUOG9gsFVNNxGxBQ7zy
-sK8GKTQhfGPj8HQjolLe_9BL_VXgVkluBiUrdBKvgVi7KwsftAmzaDQA6QAU480SWSSXikQ_OZWFgwxOlaTanElMLFFvBhO-Gj-jZqqEFhV
vVl4U7mOFcLW3Br1jngs0h7PKg5HU.IegL6XMQn_6bp6mbVNkAhQ
```

A namespace event whose `pl` is a `range` of its one entry, `{"ns":"demo","range":["1vmctae4vewju6nvxi374rkrkmyzpdrif","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"]}`, is rejected. A resource event's `pl` is `{ "ns", "name", "kind" }`, as above.

## I.23 View keys and per-entry sealing (§E.2.6)

An index on its own origin serves `demo` (epoch 3) at I.8's `view`, an input only here, and `ns_id₂`, for the query `q` = `a b`, `sort` = `/title`. Its canonical query (§A.5) is `q=a%20b&sort=%2Ftitle`, so

```
pl.view = /demo/view/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle
```

With `info` the `pl.view`'s ASCII bytes, the hit for `derby`, derived from `c`, is sealed per entry under

```
HKDF-SHA256(K_rev(c), "patchlog-view", pl.view) = f231f91356f7a5eee6952ea1624301f401d1e4463003d2e2d414148c88da845e
```

with `kid` `demo#3` and the hit's sealed values as plaintext:

```
header    = {"alg":"dir","enc":"A256GCM","kid":"demo#3","pl":{"name":"derby","ns":"demo","view":"/demo/view/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle"}}
plaintext = {"/title":["Hello"],"score":1.5}

eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibmFtZSI6ImRlcmJ5IiwibnMiOiJkZW1vIiwidmll
dyI6Ii9kZW1vL3ZpZXcvMTdpMnJxenN2M28yaTV2bGZoc2tsbzZmdTIyam5xd3RtL2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xm
cHh2bT9xPWElMjBiJnNvcnQ9JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.JEoIQh93GokwDDDeQSC2gv82Afnn0Gz5BnVdULrflr0.4uHvip
x5sQzxapkGKQhWNQ
```

Padded, its tag is `9dxFzhfRfphN2T4yqrc6Kw`. The hit is served as `{"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"derby","sealed":"<that JWE>","url":"/r/demo/derby/rev/1sywh54kpo3c4ezn2znktvl3avge4zl5d"}`.

A JWE whose `pl.view` is the same target with `+` for the space, lowercase hex (`%2ftitle`) or the parameters in another order, or with a scheme and host, doesn't match the URL fetched, and the reader rejects it. No `pl.view` has a `min`: a `200` is never served at a URL with one (§A.5).

## I.24 Bundles refused (§G.4.1)

Each of these changes to I.20's bundle rejects it whole:

| Change | sha-256 of the bundle | Rule |
|---|---|---|
| the grant line's `grant`, and both history lines', is `1d7hzis4zva7kl5aa3hi7cr3lxslua25j`, the id of I.21's `ops-2027` root block | `0ec81821b866aa5c02558212e4bb1b84640841cfba2457d594eab0730fb0bfcf` | a grant line whose `grant` isn't the id of its `root` |
| the grant line's `stored` is the authority block of I.21's token whose root block string isn't canonical (`sub` first), validly signed | `027a5892e6e75752703a253d24a4b8e6bb4db92a91bb46fad0c95cb6035a2278` | a grant line whose `stored` block's `grant_block` isn't `canonical(root)` |
| the header with `"x-note":"hi"` | `eff926c75ff1a289375536562a090a02c1fabb11c921abfe43a5b95735548954` | a member §G.4.1 doesn't define |
| the grant line's `key.kid` is `ops-2027` | `59dd09cd7d6913eaf8bfc58025bb02f5b27468b757ee351b64d90457ded62920` | a grant line whose `key` has a `kid` other than `root.kid` |
| the grant line's `key.pub` is `Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc`, the key of seed `20 21 … 3f` (§I.21's `ops-2027`) | `44e7aa12dfb273be81818819f8f53cefb404d031da212971847afd8bdd8b0910` | a grant line whose `key` doesn't verify the `stored` block |

## I.25 Long-poll phases (§7.7)

At the default 20 s interval, a path's phase is the first 8 bytes of its SHA-256, big-endian, modulo 20,000 ms:

| Path | First 8 bytes | Phase |
|---|---|---|
| `/r/docs/a/log` | `c6b6521efdba5aa1` | 15,777 ms |
| `/r/docs/b/log` | `d88ca141ae2485cf` | 1,327 ms |
| `/ns/docs/log` | `7a75dc61743845ce` | 18,318 ms |
| `/ns/matches/view/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/log` | `e0ffbec41992c73a` | 12,058 ms |

The last path's `view` is I.8's.

## I.26 Whole responses sealed at an index `view` (§E.2.6, §7.9)

An index on its own origin serves private `demo` (epoch 3) to a reader whose grant `demo`'s key `ops-2026`, with I.14's `pub`, verifies, and who would be issued a namespace-wide edge grant there. Its `key:` string (§7.9) and `view`, the hash of the one-subject array holding it (a grant with unrestricted `read` has no `scope:` subject), are

```
key:{text(trunc160(sha256(canonical(["ops-2026","A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"]))))} = key:1gorsoawpfk76fdd6bdqtgqkial3qgvl4
view   = text(trunc160(sha256(canonical([key:…])))) = 1h3svqdgo2zzbsi4ue4judyzylpexfd6q
```

so, for the query of §I.23 at `ns_id₂`,

```
view = /demo/view/1h3svqdgo2zzbsi4ue4judyzylpexfd6q/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle
HKDF-SHA256(K_n, "patchlog-view", view) = a762431d29f898ca1cdba66ac808b8b64af1ccbab978bdcd4fac1acccb0ae920
```

The whole response, sealed under that key with `kid` `demo#3`:

```
header    = {"alg":"dir","enc":"A256GCM","kid":"demo#3","pl":{"ns":"demo","view":"/demo/view/1h3svqdgo2zzbsi4ue4judyzylpexfd6q/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle"}}
plaintext = {"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","hits":[{"/title":["Hello"],"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"derby","score":1.5,"url":"/r/demo/derby/rev/1sywh54kpo3c4ezn2znktvl3avge4zl5d"}]}

eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibnMiOiJkZW1vIiwidmlldyI6Ii9kZW1vL3ZpZXcv
MWgzc3ZxZGdvMnp6YnNpNHVlNGp1ZHl6eWxwZXhmZDZxL2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xmcHh2bT9xPWElMjBiJnNv
cnQ9JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.ys5PdxEUYtMTUlo_a0x1PNC2piNeOoWo7smYW_yMwImTYzdRGZO9krVWt-ViRzLa6PhbNJ
R1ebCWMxR_iG34Yj6Z3blPniiIz2PVoE4FulnSqSYpCZMKADxv_2Jh0G7aClOuE-Aia6OVYPO9tSKbJh11NOplqJjCdOMYXav0qPi-_-RynP
yUmUx13hjaurqx05tRp35vkHbAnufZUgP2uxEY_x-wYtM11eEoDyW3wzdlrVsrjwNblVT2e0TzjUhDZCW7iw1fhFhvg7LU.17d3wcDoXnGWN
qWPQhKDxw
```

Padded (§E.2.2), its plaintext is that canonical JSON (204 bytes) followed by ASCII spaces to its bucket, 256 bytes:

```
eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibnMiOiJkZW1vIiwidmlldyI6Ii9kZW1vL3ZpZXcv
MWgzc3ZxZGdvMnp6YnNpNHVlNGp1ZHl6eWxwZXhmZDZxL2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xmcHh2bT9xPWElMjBiJnNv
cnQ9JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.ys5PdxEUYtMTUlo_a0x1PNC2piNeOoWo7smYW_yMwImTYzdRGZO9krVWt-ViRzLa6PhbNJ
R1ebCWMxR_iG34Yj6Z3blPniiIz2PVoE4FulnSqSYpCZMKADxv_2Jh0G7aClOuE-Aia6OVYPO9tSKbJh11NOplqJjCdOMYXav0qPi-_-RynP
yUmUx13hjaurqx05tRp35vkHbAnufZUgP2uxEY_x-wYtM11eEoDyW3wzdlrVsrjwNblVT2e0TzjUhDZCW7iw1fhFhvg7LUp4zI4vCW5lNaGx
73Mwh4tnxEF90csI7DJbTA0D4zi-9mrokDprtP0ktnAXaIEuWJNdLq9g.CFAbY8nEhgY4BCDiILDI5A
```

## I.27 Filtered answers sealed for a view (§E.2.2, §7.9)

With I.7's keys, I.13's `kid` and IV, and I.19's plaintexts, a partial reader at I.8's `view` to whom `g` is visible gets this view's keys for `g`, which carry `log` as `g` is a genesis, sealed under `K_view`:

```
pl        = {"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"keys","name":"derby","ns":"demo","view":"17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm"}
plaintext = {"blobs":{},"key":"zYcbEJRWpl9aj9PtLTiFMPSPvFZKq2Y7l8jcv4maRSA","log":"mrzg23rAbUtfeLxbBJAxvBzAzjpmeOZbp8_zugJBrJA"}

eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsiaWQiOiIxbDJnaTJoaG0zdnQ3MmxzMm91ZnFwa3Fw
c2g2dXZtbGwiLCJraW5kIjoia2V5cyIsIm5hbWUiOiJkZXJieSIsIm5zIjoiZGVtbyIsInZpZXciOiIxN2kycnF6c3YzbzJpNXZsZmhza2xv
NmZ1MjJqbnF3dG0ifX0..wMHCw8TFxsfIycrL.G9qYPG2P5kgFb6NPdjCXL92jG_YeqcWVoZk-a-BsyOX1zRH5cfUJw3g5oScs8M0BiY261H
TBszsvuPBUnEAUwwJspXCt6yeg0OKs2CYT3eXMzOFBD_SlGoNCMP8jww-S8wCiqBMNTEjqe5MwH1SfShF2AaA.doJf0LKbEdi3nddN40sPsw
```

Padded, its tag is `SVTajqyH3aFAdBHVAOriRQ`. Had `g`'s document referenced I.3's blob, the plaintext would be `{"blobs":{"1m5jj344d7tz7cicfmq53ayhmwuubpmyt":"Xf0NA8TYEz01jeqo92cz6Glm798wqVI7-6sUfyBE100"},"key":"zYcbEJRWpl9aj9PtLTiFMPSPvFZKq2Y7l8jcv4maRSA","log":"mrzg23rAbUtfeLxbBJAxvBzAzjpmeOZbp8_zugJBrJA"}`, with the tag `SR6Ls0us2dqMfX7ybh-iug`, and `Dyljyuz9iPShvEj0AzHeeg` padded. These keys open I.13's document of `g` and sealed blob, and I.19's `entry_g`.

Filtered answers under that `K_view`, each with the plaintext `{"body":…,"keys":[<that keys JWE>]}`:

| Answer | `pl` | `body` | Tag | Padded |
|---|---|---|---|---|
| namespace range from the start | `{"ns":"demo","range":["","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"],"view":"17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm"}` | `[nsentry₁,nsentry₂]` | `BC994v4RbPBI-2-qZV1xIA` | `4ibwPewPWhMU_P60BZ-Cmg` |
| first `/heads` page at `ns_id₂` | `{"after":"","at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"demo","view":"17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm"}` | `{"heads":[{"kind":"head","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}]}` | `PFEu95UTVra3D5QI04B8JQ` | `PFEu95UTVra3D5QI04B8JQ` |

The range's plaintext is 1016 bytes, and its JWE 1604 bytes, sha-256 `debb556bb5f1af30fa8b6b6deefe460b7ca946f9062f6774797b2d1d5114c562`. The `/heads` plaintext is 544 bytes, a bucket size, so padding adds nothing.

Rejected: the range's JWE with the unfiltered range's `pl`, without `view`, in its header; and any of these JWEs opened under `K_n` or `K_r`.

## I.28 Still to come

Still missing: a sealed Biscuit token accepted (§C.8).

---

## Changes

The full history is in CHANGELOG.md, and the conformance checklist in CONFORMANCE.md. Since v0.89:

- **v0.90:** the reference's 17 notes on v0.88–v0.89 answered, eight inconsistencies a conformance audit found fixed, and two additions.

  - **Filtering a namespace.** A consumer filters by narrowing its grant with read rules (`/resource` patterns, `/doc/$schema`, …); the narrowed grant gets a `view` whose pages every consumer with the same rules shares (§7.9). Filtered reads now apply in public namespaces too: there a grant is a filter, taken only under the view prefix, and view answers are cached as a private namespace's. In a public sealed namespace such a grant now gets its view's `K_view`, and so opens the revisions its rules allow, where v0.89 refused it keys. Namespace log `head` entries carry the revision's `schema` (unhashed; absent without `$schema` and at E3), so the shared log can be filtered by schema on the client.

  - **Views and keys.** Only a `403` cookie's seconds are skipped for `exp`; a move during an exchange is retried before `503`; a filtered answer under `K_n` has `"keys": []`; filtered answers carry no keys for purged resources' revisions; a purge clears `ns:{ns}` once a view of the namespace has been served.

  - **Audit fixes.** A blob's served epochs are only those of referencing revisions the request may read, closing a leak of hidden revisions' epochs. `"*"` in a narrowing block's `ns` is `401`. Any key-scope failure on a private resource read answers as `readScope` does. The prefix cap's `400` comes before `exchangeRate`'s `429`. An end-to-end snapshot's `ETag` and §E.2.4's purge cite agree with the rest. A partial reader passes §8.5's `/heads` check.

  - **Other notes.** A long-poll keeps one budget for its wait and, run out, answers `204` naming the last entry judged whole. An index treats a branch whose bases it doesn't follow as unfollowed (`404`, no cookie). An import refuses `sealed` ops in a namespace `access` doesn't give as `e2e`. Replanning a release keeps step 3's live, unset documents and reports the rest.

  - **The reference changes:** public views, `schema` on head entries, the blob epoch rule, the `ns:{ns}` purge for views, the long-poll run-out, the index's unfollowed bases, the import check, and replanning.
