# Patch Log — Conformance checklist

Status: against spec v0.73. Each item restates what the spec requires as a checkable statement, naming in parentheses the passages it restates (the bold lead-ins of the section's bullets, or "table" for its request table). The spec's text governs: an item that says more or less than its passage, or seems to disagree with it, is an error here. Ids are never renumbered or reused; an item that is dropped keeps its id, marked "retired in v0.NN". Items marked **[vectors]** are byte-exact and covered by Addendum I of the spec.

Suggested conformance profiles (not in the spec; proposed):

| Profile | Contains |
|---|---|
| **Core-minimal** | §1–§10, §12 except: branches (§7.6, refused with `403` per §1), blobs (§7.8), pruning (§8.6) |
| **Core-full** | all of §1–§10, §12 |
| **Auth** | Addendum C |
| **Encryption** | Addendum E, per level (E1, E2, E3) |
| **Federation** | Addendum G |
| Services (A, B), merge tooling (F), file tools (H) | separate checklists below |

## §1 Overview

- [ ] **CONF-1** (Conformance: Addendum C) A server running `"auth": "grants"` implements all of Addendum C. Otherwise authentication is disabled (`"auth": "disabled"`), and then:
  - every request counts as holding a `*` key, so config guards, forced purges and the creation of namespaces and remote branches are open;
  - config writes skip namespace rules, as `*`-key writes do, and resource writes are still checked;
  - namespace entries record `"grant": null`, and grant references recorded earlier are still served;
  - checks that match `merge.authors` (§F.3, §F.6) match an entry with `grant: null` on its author's `sub` alone, and the janitor's `*`-key checks for `abandoned` and `superseded` accept such an entry.

  Under `grants`, entries with `grant: null` count for no one. Entries without `grant` count for no one.
- [ ] **CONF-2** (Conformance: Addendum E) A server without Addendum E refuses `encryption` in namespace documents, and one without a level refuses that level (`422`, `invalid`). A remote branch whose source is raised to a level its server lacks:
  - answers for every resource its source had at `at`, read through or written on since, and not purged since (§8.3), as for a failed fetch (`502`, `upstream`);
  - refuses writes to those resources other than purges the same way, at step 2.1 of §6.2, and at check 2 of §7.8 for uploads and copies.

  So does each branch on that server whose base chain reaches that remote branch, for those resources it reads through or has written on since. A batch's local `source` takes no blobs from any of these resources.
- [ ] **CONF-3** (Conformance: Branches) A server that refuses to create local branches answers `branch` with `403`, after verification (§C.2), never lists `branch` in `/principal`'s `can`, and finds no candidate in §6.1's draft lookup. Remote registration (§G.3) is unaffected.
- [ ] **CONF-4** (Conformance: Addenda A, B, F, G and H) A core server has the hooks the core defines for these addenda: `remote` branch entries, the `export` verb, `source` in batches, `GET /`, the bundles that pruning archives to (§G.4.1, and §G.5.1.1 where encrypted), their namespace-document members (§12.3) and `/principal`'s `catalog`. A server without remote branches refuses a remote `base` with `422`.
- [ ] **CONF-5** (Conformance: Byte-exact definitions) Byte-exact definitions, among them ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9) and padding buckets (§E.2.2), agree between implementations. For each part it implements, a conforming implementation reproduces the test vectors of Addendum I. **[vectors I]**

## §2 Terminology

### §2.1 Defined terms

- [ ] **TERM-1** (Dependents) A namespace's dependents are the namespaces whose `base` is that namespace and that aren't purged.
- [ ] **TERM-2** (Edge prefix) An edge prefix is `/r/{ns}/{name}`, `/r/{ns}` or `/ns/{ns}`, with names valid under §3.6. It covers its own URL and everything below it, segment by segment, as RFC 6265 path matching does. A service's prefix under its own root covers in the same way.
- [ ] **TERM-3** (Effective roles) A grant carries roles when one of its blocks lists `roles`. Its effective roles are the roles its root block lists that every narrowing block listing `roles` keeps and that the configuration in force defines.
- [ ] **TERM-4** (Encryption level) A namespace's encryption level is its `encryption.level`, ranked none (no `encryption`) < `at-rest` < `sealed` < `e2e`. A sealed namespace is one at `sealed` (E2) only; one at `e2e` (E3) is end-to-end.
- [ ] **TERM-5** (Protection) Moving content never makes it readable, in the clear or by key, to anyone who couldn't read it at its source, unless a caller who can read it there writes it itself, or an operator overrides one import. Reading a sealed source takes keys that open the content. Within that bound, a move the caller's grants allow works within a namespace, between equal ranks and upward, except that only a key holder seals content into `e2e`, and an import keeps an `e2e` source's lines under its own name. Ranks:
  - as a source, a namespace is `e2e` at E3, `sealed` at E2 whatever its `read`, and otherwise `public` or `private` by its `read`; a source whose protection isn't known counts as `private`;
  - as a target it is the same, except that a sealed namespace whose `read` is `public` is `public`;
  - `public` < `private` = `sealed` < `e2e`.

  A blob copy, a remote branch's schema mirror, a rebase's replay into its successor and, unless an operator overrides it for that import, an import never move content into another namespace that ranks below its source. Nothing else is ranked: branches follow §7.4, a batch's local `source` makes blobs available whatever the ranks, and a writer may write what it can read wherever its grants allow.
- [ ] **TERM-6** (Protection: sealed sources) From a sealed source, public or not, and from an `e2e` source for a blob from before a raise from `sealed`, a blob copy or a batch's local `source` takes only a blob that opens under an epoch it is served under there, fixed as a request for the blob would fix one, with keys §E.2.3 gives there to the request's own grant or one in `Source-Authorization`. A copy of any other blob is `404`, and a local `source` doesn't make it available.
- [ ] **TERM-7** (Fixes `/resource`) A grant fixes `/resource` when a rule of its blocks or its key's scope, at top level or nested only in `all`s, tests `/resource` against one name (`value`, or `compare` with `eq` and a literal) or against a finite set (a `schema` of only `enum`, or `compare` with `in` and a literal array). The fixed names are those that satisfy every fixing rule. An empty set, or any literal of a fixing rule that isn't a valid name (§3.6), even one the intersection drops, means the grant doesn't fix `/resource`. A key with `readScope: "resource"` requires every grant it signs that can allow `read` (§C.2 item 2) to fix `/resource`.
- [ ] **TERM-8** (Qualifying role) A role qualifies for edge grants when it is an effective role that lists `read`, and its rules don't refer to `/now`, refer to `/resource` only if the grant fixes it, and pass now against a `read` envelope for the grant's principal, with `/resource` set to each name the grant fixes, or, if it fixes none, once.
- [ ] **TERM-9** (Referrer) In a namespace `N` that sets `schemaReads`, a referrer of a schema revision is an unpurged resource of a namespace that `schemaReads.for` lists, `N` included, whose head, or last live document if it is tombstoned, reaches the revision through `$schema` and the `$ref` closure. Only that namespace's own resources count, not what a branch reads through, and a schema document's own `$ref`s don't make it a referrer.
- [ ] **TERM-10** (Unrestricted read) A grant has unrestricted `read` of a namespace when it may `read` there (§C.2 item 2), its key has no `readScope`, no rule in its blocks or its key's scope refers to `/resource`, and, if it carries roles, an effective role that lists `read` has no rule referring to `/resource`. Where a request needs it, only such roles count for `read`. Branching and remote registration check it at gate step 1.

## §3 Identity

- [ ] **ID-1** (Input) All JSON the API accepts is I-JSON (RFC 7493). A request body other than a blob upload's that contains what I-JSON forbids is `400`. That includes invalid UTF-8, duplicate object keys, lone surrogates and Unicode noncharacters. Grants are judged by §C.8 instead. These numbers are also `400`:
  - numbers that overflow an IEEE 754 double;
  - numbers whose JCS canonical form is an integer literal outside ±(2⁵³−1) (integral values with 2⁵³ ≤ |v| < 10²¹), however they are written.

  Numbers whose canonical form has an exponent are accepted. A number that underflows is read as the nearest double (`1e-400` is `0`). **[vectors I.1]**
- [ ] **ID-2** (Canonical form, What is stored) `canonical(v)` is JCS (RFC 8785), encoded as UTF-8. The server stores, serves and hashes `canonical(patches)`, never the bytes as received. **[vectors I.1]**
- [ ] **ID-3** (Id format) An id's binary form is 20 bytes, and that form is what is hashed and stored. Its text form is used in URLs, headers and JSON, and is 33 characters long: the version prefix `1`, meaning SHA-256 truncated to 160 bits, then the bytes in RFC 4648 base32, lowercase (`a–z2–7`), without padding. **[vectors I.2]**
- [ ] **ID-4** (Revision id, Foreign parents, Tombstone id, Namespace revision id, Blob id) Revision, tombstone, namespace revision and blob ids follow the formulas of §3.3, §3.4, §3.5 and §3.7 exactly. `trunc160` keeps the first 20 bytes of the digest. Also:
  - a genesis's `bytes(parent)` is empty;
  - in a branch, the first entry of a resource it reads through has a foreign parent, with the formula unchanged;
  - a tombstone's parent is the head being deleted, which may be a foreign parent;
  - `bytes(prev_ns_id)` is empty for a namespace's first entry;
  - config revision ids use the revision formula over the namespace document's own chain.

  **[vectors I.2, I.3]**
- [ ] **ID-6** (Namespace revision id: `forced`, `purge` target, Branch entries, `source`, Batch entries) Namespace entries have exactly the shapes of §3.5, with the ids inside them in text form.
  - `forced: true` is present only on a purge that overrode an `in_use` refusal. It is then on every entry that purge writes, propagated ones included.
  - A `purge` entry's `target` is the resource's head or tombstone as seen by the namespace the entry is written in. In a branch, that view includes what the branch reads through.
  - `branch` entries are written in the base's chain. A local branch's entry has `target` set to the branch's config genesis id.
  - `source` is hashed with its entry.
    - `origin` is present only for a source in another deployment. It is that deployment's canonical origin, in the form of §C.3.
    - `ids` has at most one member per batch item, named by the item's resource.
    - A `source` of any other shape is `400` (`bad_input`), a request-shape error.
  - A `batch` entry lists the batch's config entry first, if there is one. Then it has one `head` or `tombstone` entry per resource, in request order, each with the resource's final entry.
  - Config entries and resource pointers share one chain.
- [ ] **ID-5** (Names) Namespace names match `^[a-z0-9][a-z0-9_-]{0,63}$`, and resource names match `^[a-z0-9][a-z0-9._-]{0,127}$`. URLs use names verbatim, and percent-escapes are `400`.
- [ ] **ID-7** (Blob id) The parts of a blob id:
  - `type` is the upload's `Content-Type`, lowercased and without parameters, as `type/subtype`. A type that is missing or can't be parsed is `400`.
  - `nonce` is empty, or 26 base32 characters hashed as ASCII.
  - `bytes` are the blob's bytes as stored: the plaintext, or at E3 the client's ciphertext.

  The server doesn't check that text blobs are UTF-8. The text form is that of §3.2. **[vectors I.3]**

## §4 Invariants

- [ ] **INV-1** (Append-only, Linear) Entries are never modified or removed, except by purge and pruning. Both remove content and keep ids and parent links. Each resource has exactly one first entry: a genesis, or in a branch an entry with a foreign parent. Within a resource, every entry has at most one child, and a head only moves to a child of the previous head. The same holds for each namespace chain and each namespace document chain.
- [ ] **INV-2** (Valid) Take any non-tombstone revision whose folded document has `$schema`. That document, without the members §6.2 step 5 leaves out, validates against the schema revision it names. Re-validating it later gives the same answer, unless that schema revision, or one in its `$ref` closure, was purged, or pruned without a kept document. At E3, readers check this instead of the gate.
- [ ] **INV-5** (Verifiable) Anyone holding the entries can recompute every id and check every parent link. Below a pruning horizon, ids can be checked only against the archive.
- [ ] **INV-3** (Ordered namespace log) Every mutating request that takes effect writes exactly one entry in the chain of the namespace it addresses, atomically with the change it records. The requests are `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `export`, `purge-ns`, `prune` and batches.
  - An idempotent retry answered from the log writes nothing.
  - Entries the server writes itself, such as propagated purges, are one per resource and namespace affected.
  - Creating a branch of a local base writes its `branch` entry in the base's chain, atomically with the first `config` entry of the branch's own chain.
  - Creating a remote branch also writes the schema histories it mirrors.
  - A batch writes one `batch` entry for all of its changes.
  - Blob uploads and copies write no entry.
- [ ] **INV-4** (Configuration in force) A write is checked against the namespace configuration at the head of the namespace chain at the moment the write is inserted. The configuration covers rules, keys, revocations and limits, and in a branch also its local bases' current keys and revocations. It is the namespace document recorded by the nearest `config` entry, or `batch` entry with a config change, before the write's own entry; a batch's items are checked as §7.5 says. A namespace's creation, and a write to its document that changes what one of its own bounds limits, are held to the bounds of the document they produce.
- [ ] **INV-6** (Fixed base) A branch's `base` is set when the branch is created and never changes. Reads through a branch see the base exactly as of `at`, with two exceptions: purges in the base propagate, and the base's pruning applies. For a base in another deployment, the branch's deployment applies purge notices as it sees them.
- [ ] **INV-7** (Referenced blobs) Every blob that a stored document references is available to its resource, and is kept as long as that document is. At E3 the server relies on the writers' declarations.

## §5 Storage requirements

- [ ] **STO-1** (list, items 1–3) The implementation persists:
  - for each entry: its id, parent and kind; `canonical(patches)`, until purged or pruned, in a form it can be recovered from exactly; its author and `via`, grant reference and creation time; and the `gesture`, `undoes` and author signature it was written with, if any;
  - for each namespace log entry: an author, its `via` and a creation time. For each such entry written on a request, it also persists the grant reference, with the grant's non-bearer form. None of these are part of the entry's hash.
  - for each blob, per resource: its type and nonce, and its uploader while it is pending.

  It knows which revisions reference each blob. It removes the blob on purge, after pruning, and when the blob stays unreferenced.
- [ ] **STO-2** (list, items 4, 5, 8 and 9)
  - Invariants 2, 5 and 6 are enforced atomically, including under concurrent writers and multiple processes.
  - The document at any revision id can be served, unless it is purged or pruned without a kept document. In end-to-end namespaces this is required only for revisions from before a raise to `e2e`, and for a prune's sealed snapshot.
  - A batch is applied atomically, holding invariants 2, 5 and 6 across all of its items.
  - For branches, `base` is persisted. The implementation answers "what was this resource's head as of namespace revision `n`?" for any resource and any `n` in a base's chain.
- [ ] **STO-3** (list, items 6, 7 and 10) After a purge, the implementation retains ids, parent links and namespace entries, and nothing else of the resource's content. After pruning, it retains what §8.6 keeps. After a namespace purge, it retains the namespace document chain, the namespace log, and every resource's ids and parent links.
- [ ] **STO-4** (closing paragraph) Storage choices, compression and encryption included, change nothing observable. Reads serve the exact canonical bytes, and ids and limits are computed over them.

## §6 Validation and rules

### §6.1 Schema references

- [ ] **SCH-1** (Opting in, Accepted forms) A document opts in by carrying a top-level `$schema`, which is a string (`422`, `schema_ref`). `$schema` matches exactly `^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$`, or is the dialect URL `https://json-schema.org/draft/2020-12/schema`, which marks the document as a schema, validated against that dialect's meta-schema. Anything else, head URLs, absolute URLs to this host, dot segments, query strings and percent-encoding included, is `422` (`schema_ref`). No normalisation is applied. A schema stored under an earlier version is compiled as that version did.
- [ ] **SCH-2** (`$id`, `$ref`) A schema document uses the `$id` keyword in no subschema, and `$schema` in none but its root (`422`, `invalid`); validators are registered and looked up only by revision path. `$dynamicRef` is a same-document fragment (`422`, `schema_ref`). `$ref` inside a schema resolves only a same-document fragment (`#…`), or a schema revision path in the accepted form, optionally with a fragment. A fragment that is empty or starts with `/` is percent-decoded and read as a JSON Pointer; any other is a plain name, which an `$anchor` or `$dynamicAnchor` of the schema it reaches must define. Nothing else is resolved. A schema document's own `$ref`s resolve when it is written, at step 5 of §6.2, and one whose fragment names nothing in the schema it reaches makes the schema invalid (`422`, `invalid`).
- [ ] **SCH-3** (Never into a branch, Drafts in branches) `$schema` and `$ref` never name a branch namespace (`422`, `schema_ref`); a path naming a branch in which the writer can't read the revision is `422` (`schema_unavailable`), as for a namespace that doesn't exist. In a write to a branch, a path `/r/N/R/rev/X` that `N` can't resolve for the writer (`N` lacks it, or the writer can't read it there) is looked up in the candidates: the local branches of `N`, branches of branches included, that aren't end-to-end, counting in each only the revisions it wrote itself. A candidate serves writes to itself and its own branches, and to the namespaces its own `drafts.for` lists and their branches (the namespace written, or one in its `base` chain, is listed); branches of a candidate don't inherit its `drafts.for`. The writer needs `read` on `R` in the candidate, checked as for reading other namespaces (§7.5), and a revision it can't read there counts as not found. Any candidate holding `X` serves, and the whole `$ref` closure resolves the same way. In a namespace that isn't a branch, paths resolve only in `N`.
- [ ] **SCH-4** (Schemas follow their documents) With `schemaReads.for` set in `N` (names, or prefixes ending in `*`, matched as `drafts.for` is but never against a branch; `N` itself always counts), a schema revision in `N` whose own `$schema` is a dialect URL:
  - resolves, without `read`, for a write to a listed namespace, or to a local branch of one, branches of branches included, whose document pins it through `$schema` or its `$ref` closure;
  - may be read by revision path, even under a grant that doesn't name `N`, or doesn't verify or can't read the revision there, when the grant may read a referrer of it (§2.1) in a listed namespace the grant names, verifying under that namespace's keys and allowing a read of that referrer, even where that namespace's `read` is `public`. A referrer in a listed namespace that is public, and neither sealed nor end-to-end, counts for every request, and a grant is then ignored. An edge that knows only prefixes forwards such a read to the origin, never refusing it, and the origin serves it `private`.

  It opens nothing else: not the schema resource's head, log or other revisions, a document that isn't a schema, or a draft in a branch. `schemaReads` is `422` in sealed and end-to-end namespaces.
- [ ] **SCH-5** (Within a batch, Tombstoned schema resources, Purged or unknown references) Batch items may reference schema revisions created by earlier items. Revisions of a tombstoned schema resource still resolve, for new references too. A reference that is unknown, purged, pruned without a kept document or unreadable by the writer, or that names a tombstone, a document that isn't a schema, or a revision written while its namespace was end-to-end, is `422` (`schema_unavailable`), with `path` the revision path that didn't resolve.
- [ ] **SCH-6** (Referenced schema revisions, Copies, Refusals) A schema revision is referenced when it is named by `$schema`, or reached through that schema's `$ref` closure, from: the head, or the last live document if tombstoned, of any unpurged resource in the deployment; the head as of `at` of a resource a branch reads through, or its last live document then if it was tombstoned; or any revision a branch wrote. A reference is satisfied by a copy whose document is neither purged nor pruned, in `N`, or, for a document in a branch, in a branch it may resolve drafts in, judged by the candidate rules and never by any one writer's grants; a revision pruned in `N` counts as one `N` can't resolve. Unless forced, a purge of a resource or a namespace that would remove the last copy satisfying a reference, in any namespace it reaches, branches it propagates to included, and a config write that would leave a reference without a copy, are `409` (`in_use`), listing as `referencing` the referencing namespaces in which the caller may read anything, judged as for reading other namespaces (§7.5).
- [ ] **SCH-8** (Forcing) A refused purge is forced with `?force=1` on the purge request, under a grant chained to a deployment operator key, or, for a purge of a branch or of a resource in one, to a `*` key of that branch, inherited or its own. Under any other grant, `?force=1` is `403` at step 1 of §6.2, whether or not the purge needs it. A forced purge's entries carry `forced: true`.
- [ ] **SCH-7** (Read permission) Resolving a `$schema` or `$ref` requires the writer's `read` on the copy it resolves to, in the schema's namespace or in the branch holding a draft, judged as for reading other namespaces (§7.5) where that isn't the namespace written, unless that namespace opens it with `schemaReads`. From a sealed namespace, public or not, and from an end-to-end one for a revision from before a raise from `sealed`, it also takes keys that §E.2.3 gives there, for the epoch the revision is served under, fixed as a read of it would fix one, to the request's own grant or one in `Source-Authorization`, in the namespace written too; without them the revision is unreadable by the writer (`422`, `schema_unavailable`).

### §6.2 On write

- [ ] **GATE-1** (intro) Checks run in the order of §6.2. Only errors in a request's own shape, which no state influences, may come before step 1: malformed names or URLs, content types, header and body syntax, and the size of what is read (`400`, `413`, `415`), unless an endpoint fixes its own order, as blob uploads do. A batch body cut off as §7.5 says, by the verified principal's `batchSize`, is `413` once the grant is verified, before its verbs are checked.
- [ ] **GATE-2** (Authenticate and authorise) Step 1 authenticates and authorises the request (`401` or `403`), covering the verbs and the grant, key-scope and role rules that refer only to `/action`, `/resource`, `/principal` or `/now`, as §C.2 says. Rate limits are checked last in this step, only for requests that passed it (`429`).
- [ ] **GATE-3** (Precondition) Step 2 runs in this order:
  1. The idempotent-retry lookup, with its verb check (§C.2 item 2). It doesn't apply to a purged resource, which answers `410`; nor in a purged namespace, where every write is `410` (`purged`) here, before any later check; nor to a resource that §1 has a remote branch, or a branch whose base chain reaches one, answer `502` for, whose writes other than purges are `502` here.
  2. For a `PATCH` with `If-Match`, or a batch item whose first step is a patch set under `ifMatch`, the verb is settled from the resource's state as the writer sees it: a tombstoned head makes a restore, a live head or none an append, a purged resource answers `410` whichever the verb, and in a branch a read-through resource settles by the base's head as of `at`, a tombstone there making the first write a restore with that tombstone as its foreign parent. A settled verb that isn't a candidate is `403`, before the `If-Match` comparison, and counts as failing authorisation for §7.5's failure report and dry run.
  3. Author signatures (`422`, `signature`), which need no head: the signed parent is the one the precondition names.
  4. A frozen namespace (`409`).
  5. The precondition itself: `428`, `412`, or `410` on a tombstoned resource, and in a batch `422` for a `"delete"` that follows a `"delete"`.
- [ ] **GATE-4** (Apply, Limits, Schema) Step 3 applies the patches to the parent's document, `null` for a create, with operation validation, a failing `test` being `422`; a delete skips steps 3–5. In a namespace that requires nonces, a resource create, append or restore is then checked for a fresh `$nonce` (`422`, `nonce`). At step 4, the namespace document a config write or a branch's creation results in is first validated as §7.4 says, and a prune's `horizon`, `keep` and `snapshot`, and at E3 its archive, are checked as §8.6 says (`422`, `invalid`, or `limit` for a limit such as `keepPerResource`); then the limits of §6.6 are checked, and that every blob reference in the resulting document is well-formed and names a blob available to the resource (`422`). At step 5, if the resulting document has `$schema`, it is resolved (§6.1) and validated against JSON Schema draft 2020-12, with format assertions for the formats that draft defines, a schema naming any other `format` being invalid; the instance is the document without its top-level `$schema`, a top-level `$nonce` of the fresh form and a top-level `$successor` of the form of §8.1, while a `$nonce` or `$successor` of any other form is validated as data. Failure is `422` with `{ pointer, message }` errors.
- [ ] **GATE-5** (Rules, Hash and insert) Step 6 evaluates the `*`-key guard, then a config write's `in_use` refusals (§6.1, §7.4), then grant, key and role rules, then namespace rules, against the configuration in force; in a batch, each of these for every item before the next for any. Step 7 hashes and inserts atomically, together with the namespace entry. In a batch each step, and each sub-step of step 2, runs for every item before the next starts, and step 7 inserts all items in one atomic operation.
- [ ] **GATE-6** (End-to-end namespaces) For `create`, `append` and `restore` in an `e2e` namespace, of any resource but `keyring`, step 3 accepts a patch set of one reserved `sealed` op that passes the checks of §E.3.1, or `[]` for a restore, without applying it; anything else is `422` (`invalid`). Step 4 checks the blobs the op declares, and step 5 is skipped. Any namespace, grant, key or role rule whose outcome depends on a `writes` predicate, or on a `/writes` or `/doc` path, fails as a whole for these writes (`422` or `403`); one that passes, or fails, whatever they would give is decided as usual. Config, branch and prune writes are checked as usual, and so is a delete, except that its `doc` is null, so a rule whose outcome depends on a `/doc` path fails as a whole for it.

### §6.3 Changing type

- [ ] **TYP-1** (Adding, Changing, Removing) Adding `$schema` to an untyped document, or changing it with `replace /$schema`, is an ordinary patch, and the resulting document must validate against the schema it then names. Removing `$schema` makes the document untyped from that revision on. Tombstones aren't validated, nor is the document a delete removes.

### §6.4 Namespace rules

- [ ] **RUL-1** (`writes`) The server computes `writes`:
  - `add`, `replace`, `remove` and `copy` write `path`; `move` writes both `from` and `path`; `test` writes nothing;
  - a root operation, a genesis `add ""` included, writes `""`;
  - a delete's `writes` and `patches` are `[]`;
  - an array append `…/-` is recorded with the resulting index;
  - an `add`, `copy` or `move` into an array at an index below its length, and a `remove` or `move` of an element that isn't its last, also write the array itself;
  - in resource envelopes only, an `add` or `replace` at exactly `/$nonce` whose value matches `^[a-z2-7]{26}$` is left out, while any other operation at or below `/$nonce` is a write.

  Pointers are compared segment by segment after RFC 6901 unescaping, never as strings.
- [ ] **RUL-2** (Change envelope, `doc`, Batches, `principal`, `now`, `read`) Every write is checked against an envelope of `action`, `resource`, `principal`, `now`, `writes`, `doc` and `patches` (canonical, `[]` when there is none).
  - `resource` is absent for `config`, `purge-ns` and `export`, and is the new namespace's name for `branch`. `principal` is absent when authentication is disabled.
  - `doc` is the document as it will be stored if the write succeeds. For a delete it is the resource's last live document as the target namespace sees it, read through its bases in a branch, or in a batch the document after the item's earlier steps; a replayed delete is judged against the document the target has at that step. For `config` it is the resulting namespace document; for `branch` the new branch's namespace document, the envelope being evaluated in the base. It is null for `purge` and `purge-ns`, `{ remote, at }` for `export`, and `{ horizon, keep? }` as sent for `prune`. In an end-to-end namespace it is null for `create`, `append`, `restore` and `delete` of every resource but `keyring`.
  - A batch produces one envelope per patch set, with the ordinary actions; there is no `batch` action.
  - `principal` takes `groups` and `attrs` from the grant's root block, and `roles` lists its effective roles (§2.1). `attrs` is `{}` when there are none, and `groups`, `roles` and `via` are `[]` when there are none, `roles` for a grant without roles too.
  - `now` is the server's clock at the gate, RFC 3339 UTC with millisecond precision, read once per request.
  - `read` envelopes carry `action`, `resource`, `principal` and `now`, and no `writes`, `doc` or `patches`.
- [ ] **RUL-6** (Rule forms, Path policy, `compare`) Every rule form of §6.4.2 is implemented, and path policy uses the `writes` predicates, never patterns over `/patches/*/path`.
  - A `test` with `value` is RFC 6902 equality. A missing path fails `value` and `schema` tests and satisfies `exists: false`.
  - A `schema` is a JSON Schema draft 2020-12 fragment, applied with format assertions as at step 5 of §6.2, held to §6.1's `$id` ban, §6.5 and §6.6 like a schema document, with no `$schema` keyword in any subschema, and whose `$ref` and `$dynamicRef` are same-document fragments only; otherwise a namespace document is `422` (`invalid`), and a grant invalid (`401`).
  - `within` is true when there are no writes, and `covers` and `overlaps` are false.
  - `lt`, `le`, `gt` and `ge` compare two numbers, or two RFC 3339 `date-time` strings as instants at the full precision of their fractional seconds, a `date-time` with a leap second (`:60`) being of an unsupported type. `eq` is RFC 6902 equality. `in` is true when the left value equals an element of the right-hand array, and false when the right side isn't an array. A missing path on either side makes `compare` false, and so do operands of different or unsupported types for `lt`, `le`, `gt` and `ge`.
  - When all `if` rules pass, all `then` rules must pass.
- [ ] **RUL-3** (Evaluation) Rules run at step 6 of §6.2, in order, and all must pass. A failing namespace rule is `422` with `code: "rule"`, `rule` (its index) and `path`, which points at the failing rule form in the namespace document, descending only through the first failing member of an `all` or a `then`. A failing grant, key or role rule is `403` (`forbidden`). Rules apply only at write time, and at read time for grant, key and role rules, and changing them never invalidates existing history.
- [ ] **RUL-4** (Config writes are rule-checked too, Operator overrides, Except as above) Namespace rules see every action, `delete`, `purge`, `config`, `branch` (evaluated in the base) and `purge-ns` included, except a `config` write under a grant that chains to a key with `can: ["*"]` (as every request counts while authentication is disabled, §1), a namespace's creation under the operator grant that creates it, and a purge or namespace purge forced past an `in_use` refusal under a deployment operator grant. A purge forced with a `*` key of the branch, inherited or its own, is still judged, and so is any purge while authentication is disabled.

### §6.5 Reserved keys and extension keywords

- [ ] **RUL-5** (Reserved keys, `$blob`, `x-*` keywords) Top-level keys starting with `$`, other than `$schema`, are stored as data and never interpreted, except that a fresh `$nonce` is left out of `writes` and can be required (§C.7), and a well-formed `$successor` is read into a deleted resource's `410` (§8.1); validation leaves both out (§6.2 step 5). `$blob` is reserved at any depth: an object whose `$blob` member is a string is a blob reference, and must be well-formed (`422`); schema documents and namespace documents aren't searched for references. Schema keywords starting with `x-` are ignored by the core validator, and any other unknown keyword makes a schema invalid, `dependencies`, `$recursiveAnchor` and `$recursiveRef` included; `definitions` holds subschemas, as `$defs` does. In a schema document, a top-level `$nonce` or `$successor` that step 5 leaves out is left out before the document is checked against its dialect and compiled.
- [ ] **RUL-7** (`x-ref`, Entries inside a document, Finding references) For tools that find references:
  - an `x-ref` value is `{ "pinned"?: boolean, "key"?: pointer }`. A pinned reference is a revision path in the form of §6.1, a live one a resource path `/r/{ns}/{name}`.
  - With `key`, a reference names one entry of the target document, `/r/{ns}/{name}#{id}` or pinned `/r/{ns}/{name}/rev/{rev}#{id}`. `key` points into the target at an array of objects with a string `id` member, or an object whose member names are the ids. `{id}` is matched against those ids, never against array positions, and is percent-encoded as a URI fragment. A reference whose entry doesn't exist is dangling.
  - References are found by a static walk of each document, without the members validation leaves out, together with its schema. At every instance location it considers every subschema that could apply: through `$ref`, `properties`, `patternProperties`, `additionalProperties`, `items` and `prefixItems`, every branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, and any other keyword that applies a subschema. A string at a location where any of them carries `x-ref` is a reference if it has the form above, even if that subschema didn't validate.

  The core doesn't check `x-ref`.

### §6.6 Limits

- [ ] **LIM-1** (Configurable limits, Exceeding a limit) Every namespace has the limits of §12.2, set under `limits`. Config writes, a batch's `config` change and a branch's `patches` are held to the patch-set and document limits as resource writes are, a namespace's creation counting as a create, and their bodies are cut off as a resource `PATCH`'s are.
  - Exceeding a limit is `413` where a request is refused before or while it is read, or where §7.8 says so, and `422` otherwise, with `code: "limit"`, `limit` naming its key, and, for sizes and counts, `measured` and `max`. Durations and rates give `limit` alone.
  - Where the server stopped reading an oversized body, `measured` is a lower bound in body bytes, and before step 1 of §6.2 `max` is the deployment's. `measured` is, for `pathSize` and `valueSize`, the first value found too long, quotes included; for `branchesPerNamespace`, the base's live branches with the new or unfrozen one; for `blobPending`, the pending bytes with this blob, each counted as at least 4 KiB; and for a blob without `Content-Length`, `blobSize` + 1. For `documentSize`, `nestingDepth`, `valueSize`, `pathSize` and `blobsPerDocument`, `measured` is left out for a grant that can't read the resource.
  - Bodies of endpoints with no limit of their own (prune, `/keys`) are `400` (`bad_input`) above 1 MiB. A resource `PATCH` body more than four times the larger of the deployment maximums of `patchSetSize` and `documentSize` is `413` before parsing, naming `documentSize` with the deployment maximum. A batch body cut off as §7.5 says names `batchSize`, with the verified principal's as `max`.
- [ ] **LIM-2** (Whole documents, Values) The patch set of a create, and of an append or restore whose first operation other than `test` is a root `replace` or `add`, further operations allowed after it, may be as large as `documentSize` instead of `patchSetSize`. At E3 every create and restore may, and appends stay within `patchSetSize`. Every other patch set, one starting with a root `copy`, `move` or `remove` included, stays within `patchSetSize`. In a batch they still count toward `batchSize`. A namespace's creation, a branch's included, and a config write that changes `limits` or `encryption` are `422` (`code: "limit"`, `limit: "patchSetSize"`, `measured` the left side, `max` the `patchSetSize`) unless, in the configuration they result in, `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize`, the left side adding `36 B × blobsPerDocument` where that configuration is E3.
- [ ] **LIM-3** (Rate limits) Rate limits are token buckets, checked at the end of step 1 of §6.2.
  - Buckets are keyed by the root `sub` and the key that signed the root block (`kid`), never by `via`. The per-resource bucket is per resource and principal, and the namespace bucket bounds all writers together.
  - A request is admitted while every bucket it draws on holds at least one token, and its cost is then deducted, even below zero, in one atomic step across every instance sharing the store, and with the write where there is one. A request refused after admission keeps its deduction. Dry runs draw as the submit would.
  - A batch costs one token per resource it touches from each per-resource bucket, one per item from the principal and namespace buckets, and one from those for its non-exempt `config` change. A blob upload costs one token from the per-resource, principal and namespace buckets, and its size from the principal's `blobRate` bucket. Any other non-exempt write costs one token from the principal and namespace buckets of the namespace whose chain records it, the base's for a branch's creation, and a resource write or a prune one from its per-resource bucket too.
  - Exempt: config writes under a `*` key; config writes whose `writes` are non-empty and all at `/frozen`, `/successor` or `/merged` and whose resulting document has `frozen: true`; purges; and entries the server writes itself.
  - Exceeding one is `429` with `Retry-After` in whole seconds, rounded up, `code: "rate"`, `limit` naming a bucket that was hit (a §6.6 key, `allowance` or `allowance.blobRate`), and `retryAfter`, the wait in seconds as a decimal number until every bucket the request draws on holds a token.
  - A key scope may lower the per-principal rate for the grants it signs.
- [ ] **LIM-4** (Allowances) An allowance gives a principal, matched by root `sub` and signing `kid`, its own bucket for its writes and uploads, in place of the principal and namespace buckets and of a key scope's lower `rate`; per-resource buckets still apply. That principal's batches may be as large as the allowance says, and it may also set `blobRate` and `blobPending`. An allowance never exceeds the deployment maximums, `bucket` that of `ratePerNamespace` and the rest those of their own limits: one set above them is `422` (`code: "limit"`), and one stored before a maximum was lowered is held to it. With `until`, an allowance applies only while `now` is before it. While authentication is disabled, buckets are keyed by the author and an allowance matches the author's `sub` alone. Either way, the first matching entry whose `until` hasn't passed applies.
- [ ] **LIM-5** (Deployment defaults and maximums) A deployment sets a default and a maximum for every limit, and a minimum for the retry window. A namespace may set any limit up to the maximum, except limits marked deployment only. A write that sets a value above the maximum, or a retry window below the minimum, is `422` (`limit`), and a value stored before the maximum was lowered is held to it. A namespace's own bound holds its creation and every write that changes what it bounds, a write that lowers a count still over the bound being refused; other writes, freezes included, still pass a document an earlier release stored over it.
- [ ] **LIM-6** (Regular expressions) Regular expressions in rules, grants, key scopes and schemas are evaluated with RE2 syntax and semantics, reading `\uXXXX` as `\x{XXXX}`, a surrogate pair of such escapes as the one code point it encodes, and a lone surrogate as a pattern RE2 doesn't accept; the `regex` format asserts the same syntax. A pattern RE2 doesn't accept, such as one with backreferences or lookaround, makes a schema or config `422` (`invalid`) when written, and a grant that carries one invalid (`401`).

## §7 HTTP API

- [ ] **HTTP-1** (URLs, Query parameters) The resource URL is `/r/{ns}/{name}` and the namespace URL `/ns/{ns}`. A path other than `/` with an empty segment (`//`, or a trailing `/`), a `.` or `..` segment, or any percent-escape is `400` (`bad_input`). An id that isn't in text form (§3.2) is `400` (`bad_input`), a request-shape error (§6.2), when it appears in any of these:
  - a URL;
  - a write's precondition other than `If-None-Match: *`;
  - `Last-Event-ID`;
  - a request field such as `ifMatch` outside a namespace document.

  In `ETag`, `If-Match`, `If-None-Match` and `If-Range` an id is quoted as a strong entity tag. A write's precondition is one such tag or `If-None-Match: *`. `If-Match: *`, a weak tag or a list is `400` (`bad_input`). A sealed `ETag` adds `.{e}` (§E.2.2), which a write's precondition leaves out. In `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Log-Next` and `Last-Event-ID` an id is unquoted.

  An endpoint accepts only the query parameters this spec defines for it, each at most once unless defined as repeatable (in the core, only `prefix` of `DELETE /edge-grants`). Flags such as `force` and `dry-run` take only the value `1`. Anything else, a repeated parameter included, is `400` (`bad_input`, not cached), a request-shape error. An edge that verifies signed-URL grants (§C.5) strips their parameters before forwarding, and passes the grant on as the cookie it stands for (§C.5.3), which the origin verifies as any cookie.
- [ ] **HTTP-2** (`GET /`) `GET /` answers `{ "origin", "spec", "auth" }`:
  - `origin`: the deployment's canonical origin (§C.3);
  - `spec`: the spec version it implements, as dotted decimal numbers compared component by component;
  - `auth`: `"grants"` or `"disabled"` (§1).

  Addendum C adds `jwks_uri` (§C.4). A client, peer or tool MUST NOT refuse a deployment on the version alone. An optional endpoint that isn't offered answers `404 not_offered`.
- [ ] **HTTP-66** (Browsers) A deployment serving browsers answers preflights:
  - allowing the methods `PATCH`, `PUT`, `POST` and `DELETE`;
  - allowing the headers `Authorization`, `If-Match`, `Source-Authorization`, `Signature`, `Content-Type`, `Gesture`, `Undoes`, `Blob-Nonce`, `Blob-From`, `X-Author`, `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range` and `Last-Event-ID`;
  - exposing `ETag`, `Location`, `Repr-Digest`, `Retry-After`, `Content-Range`, `Gesture`, `Undoes`, `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Cursor` and `X-Log-Next`;
  - setting `Access-Control-Max-Age`.

  Responses that vary by origin carry `Vary: Origin`. A deployment that allows every origin, and names no credentialed origins (§C.5.2), sends `Access-Control-Allow-Origin: *` and its exposed headers on every response, with or without `Origin`.
- [ ] **HTTP-3** (Private namespaces and existence, Reads of a public namespace, The `ns` check, Verification, Resources) Requests are answered in this order:
  1. Reads of a public namespace, other than `GET /ns/{ns}/principal` and `POST /ns/{ns}/keys` (§E.2.3), ignore any grant and answer exactly as unauthenticated ones, with content or `404`. Only these, and the schema revisions a public referrer opens (§6.1), answer unauthenticated requests with content or `404`.
  2. With a grant, the server reads `ns` from its blocks before looking up any key. A namespace not named in `ns` by every block that carries `ns` answers `403` without being consulted, whether or not it exists. The root block always carries `ns`, and `"*"` names every namespace. The exception is a schema revision the namespace opens with `schemaReads`.
  3. Only then is the grant verified, against that namespace's keys, or the deployment operator keys when the root `kid` names one (§C.4). Without valid credentials the answer is `401`, alike for a namespace that doesn't exist and one whose `read` isn't `public`. The exception is a request for a schema revision a referrer opens to it (§6.1), which steps 3 and 4 never refuse.
  4. Without `read`, a resource that exists and one that doesn't both answer `404`.

  Writes, `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`, and every request to a namespace that isn't public or doesn't exist keep the `403` and `401` answers of steps 2 and 3.

### §7.1 Reads

- [ ] **HTTP-4** (table) `GET /r/{ns}/{name}` answers:
  - `302` with `Location: /r/{ns}/{name}/rev/{head}` and `ETag: "{head}"`;
  - for a resource that never existed, `404`;
  - for a tombstoned resource, `410` with `{ "tombstone": id, "last": lastRevisionId, "successor"? }` and `ETag: "{tombstone}"` (§8.1);
  - for a purged resource, `410`.

  `HEAD /r/{ns}/{name}` answers as `GET`, without a body.

  `GET /r/{ns}/{name}/rev/{id}` is `200` with the document at `id`, `ETag: "{id}"` (`"{id}.{e}"` when sealed) and `X-Revision: {id}`. In a namespace that is neither sealed nor end-to-end it also carries:
  - `Last-Modified`, the revision's `created` as an HTTP date to the second;
  - without content coding, `Repr-Digest` (RFC 9530) of the document, served as canonical JSON.

  Sealed and end-to-end reads carry neither. It honours `If-None-Match` with `304`, and also `If-Modified-Since` when `If-None-Match` is absent and `Last-Modified` is sent; elsewhere `If-Modified-Since` is ignored. For that URL:
  - an `id` that is a tombstone is `410`;
  - an unknown `id` is `404`;
  - a purged resource is `410`;
  - an `id` below the horizon without a kept document (§8.6) is `410` with `{ "code": "pruned", "horizon": id, "archive"?: url }`.

  In a public namespace (§9) these are cached as follows:
  - the `302` and the tombstoned `410` as a head pointer;
  - `HEAD` as `GET`;
  - the `404`s as short;
  - the purged `410`s as long;
  - the revision `200` and the tombstone-id `410` as immutable;
  - the below-horizon `410` as pruned.
- [ ] **HTTP-16** (table) For a raw document (§7.8), `GET /r/{ns}/{name}/raw` and `GET /r/{ns}/{name}/rev/{id}/raw` are `302` to `…/blob/{bid}`.
  - Unknown, pruned, purged and tombstoned ids and heads answer as the matching document URL does.
  - A document that isn't raw is `404` (`not_found`).
  - In sealed or end-to-end namespaces they are `404` with `code: "not_offered"`, after the read check, which is the document's.

  The `302` and both `404`s are cached as the document URL they stand for (head pointer or immutable), with its tags.
- [ ] **HTTP-17** (table) `GET /r/{ns}/{name}/blob/{bid}` answers:
  - `200` with the blob, or `206` for a range;
  - `404` if the blob is pending or unknown;
  - `410` if it is pruned or purged (§7.8);
  - in sealed namespaces, and at E3 for blobs from before a raise from `sealed`, `302` to `…/blob/{bid}/e/{e}` (§E.2.2).

  It is cached as immutable, a `404` as short, a `410` as pruned, or as long where the resource is purged, and the `302` as a head pointer.

  `GET /r/{ns}/{name}/blob/{bid}/e/{e}` serves sealed namespaces, and at E3 blobs from before a raise from `sealed`, only. There it answers:
  - `200` with the blob sealed under epoch `e`, or `206` for a range of the sealed bytes;
  - `404` for an epoch it isn't served under;
  - `410` where §E.2.2 says.

  In other namespaces, and for other blobs at E3, it is `404` with `code: "not_offered"`, after the resource's read check. It is cached as immutable, the epoch `404` as `no-store`, its `410` as pruned, and the `not_offered` `404` as short.
- [ ] **HTTP-18** (table) `GET /r/{ns}/{name}/rev/{id}/log?since={a}` is `200` with the entries after `a` (exclusive) up to `id` (inclusive). An empty or omitted `since` means from genesis, and `since={id}` is an empty range. It answers:
  - `404` if `id` is unknown, or `a` is neither `id` nor an ancestor of it;
  - `410`, as for a revision below the horizon, if any revision after `a`, up to `id`, has its patch set pruned and not restored from an archive. `a` itself may lie below the horizon.

  It is paged. It is cached as immutable, a `404` as short, and a `410` as pruned, or as long where the resource is purged.
- [ ] **HTTP-5** (Paging) A log range answers its first page only when any of these holds:
  - it is longer than the log page size (§6.6), a batch entry counting as its items;
  - its patch sets exceed `logPageBytes`;
  - it spans an `e2e` raise.

  A page ends before an entry that would take it past either bound or across the raise, but always holds one. At E2, `logPageBytes` counts each entry's sealed bytes as served. Pages are oldest first, with `X-Log-Next: {id}`: the last entry returned, which is the `since` of the following page. A page that reaches the URL's `id` needs no `X-Log-Next`. Every page is a correct prefix of its range. `404` and `410` are judged over the URL's whole range.
- [ ] **HTTP-19** (Paging, Continuations) Every paged answer names how to continue:
  - log ranges in `X-Log-Next` (the next `since`);
  - `/heads` in its body's `next` (the next `after`);
  - the gestures listing in `X-Log-Next` (the next `after`).

  Long-poll answers (§7.7) use the same page limits and carry no `X-Log-Next`. The sealed snapshot of an E3 prune (§8.6) is served as `/rev/{H}`, never as a log entry, except where `H` is from before a raise to `e2e`, which is served as before.
- [ ] **HTTP-20** (Log entry shape) A resource log entry is `{ "id", "parent", "kind": "rev", "patches", "author", "via"?, "created", "grant"?, "signature"?, "gesture"?, "undoes"? }`, with `patches` in canonical form. A tombstone entry is the same with `kind: "tombstone"` and no `patches`.
  - `grant` is `{ "id", "sub", "kid" }`. It is absent where none was recorded, including writes made while authentication was disabled.
  - `created` is the entry's creation time, here and in namespace entries, in RFC 3339 UTC with millisecond precision.
  - `via` lists the grant's delegatees in order, and is absent when there are none.

  All cursors are ids; internal sequence numbers are never exposed.

### §7.2 Writes

- [ ] **HTTP-6** (Writes, table, Content types) A write without a precondition is `428`. One with both `If-Match` and `If-None-Match` is `400` (`bad_input`), a request-shape error. Pruning (§8.6) and blob uploads (§7.8) take none, and one sent is `428`: for a prune at step 2.5 of §6.2, for an upload at check 4 of §7.8. Checks run in the order of §6.2, authorisation before the precondition; for a `PATCH` with `If-Match`, authorisation completes at step 2, when the verb is settled.

  A resource `PATCH` with any `Content-Type` other than `application/json-patch+json`, or none, is `415`, a request-shape error. So is any other JSON body not sent as `application/json`. A JSON body's `Content-Type` is compared as a media type (RFC 9110, section 8.3.1), ignoring case and a `charset` parameter naming UTF-8; any other parameter is `415`.

  - **Create** (`PATCH /r/{ns}/{name}`, `If-None-Match: *`): `201` with `Location: …/rev/{id}` and `ETag: "{id}"`. It fails with `412` and `{ head }` if the resource is live; `410` (`gone`), with `head` the tombstone, if it is tombstoned; `422`; or `410` if purged.
  - **Append** (`If-Match: "{parent}"`): `201` with `Location` and `ETag`. It fails with `412` and `{ head }` if parent ≠ head; `422`; `410` (`gone`, with `head`) if tombstoned and `parent` ≠ tombstone; `403` if tombstoned and the grant can't restore; or `410` if purged.
  - **Restore** (`PATCH` on a tombstoned resource, `If-Match: "{tombstone}"`): `201`, the patches applying to the last live document (§8.2). It fails as an append does.
  - **Delete** (`DELETE /r/{ns}/{name}`, `If-Match: "{head}"`): `200` with `{ tombstone }`. It fails with `412` and `{ head }`, or `410` (`gone`, with `head`) if already tombstoned.
  - **Purge** (`POST /r/{ns}/{name}/purge`, `If-Match: "{head or tombstone}"`): `204`. It fails with `412` and `{ head }`, or `409 in_use` (§6.1), after the precondition.
  - **Blob upload** (`PUT /r/{ns}/{name}/blob/{bid}`, no precondition): `201` with `ETag: "{bid}"`. Its failures come in the order of §7.8.
- [ ] **HTTP-21** (Authorization, Author) A grant is sent as `Authorization: Bearer <grant>`. With authentication disabled, `X-Author` names the author, and a write without it is `400` (`bad_input`). The author is the verified principal id, and `via` is recorded with it.
- [ ] **HTTP-22** (Gestures) A write may carry `Gesture: <id>` and `Undoes: <id>`, each 26 base32 characters (`^[a-z2-7]{26}$`), otherwise `400`. They are stored with the revision or tombstone as metadata. They are not part of its id (§3.3), not seen by rules, and never verified. A namespace-document write (§7.4) carries them the same way; a batch's `config` change carries none.
- [ ] **HTTP-7** (Idempotent retry, Gestures) When the precondition fails, the answer is `200` with the entry instead of `412` (or a `410` on a tombstoned resource, or `409 frozen`), when all of these hold:
  - the log already contains the entry the request would have produced, recorded with that parent: for an append or restore, the revision id of §3.3 with `If-Match` as parent; for a create, the genesis id with an empty parent; for `DELETE`, the tombstone id of §3.4;
  - that entry was written by the same principal: the same root `sub` and `kid`, or, while authentication is disabled, the same author;
  - the retry passes the verb check of §C.2 item 2.

  The `200` is answered as the write succeeded (`Location` and `ETag`, or `{ tombstone }`), with the entry as first recorded, whatever the retry carries, and the recorded `Gesture` and `Undoes` as headers. The check looks anywhere in the resource's log in the namespace written, not only at the head, but not at entries a branch reads through (§7.6), nor in a purged resource, whose answer is `410` (§6.2). Within the retry window (§6.6, §8.6) it always works. A different principal sending identical patches gets `412`.
- [ ] **HTTP-23** (Frozen namespaces) In a frozen namespace, resource writes, batches with items, and blob uploads and copies (§7.8) are `409` with `code: "frozen"` and any `successor`. This comes after authorisation and the idempotent-retry lookup (§6.2, §8.4).
- [ ] **HTTP-8** (Namespace revision, Caching) Every successful write that records a namespace entry answers with `X-Namespace-Revision: {ns_id}`, naming that entry. These writes are:
  - creates, appends, restores and deletes;
  - purges and namespace purges, on their `204`;
  - config writes;
  - batches;
  - branch creation and remote registration;
  - a prune that moved the horizon or changed `keep`.

  An idempotent retry carries the entry that recorded the original write, a batch's included. Blob uploads and copies, a prune that changes nothing and a dry run carry none. Write responses are `Cache-Control: no-store`.

### §7.3 Events (Server-Sent Events)

- [ ] **HTTP-9** (Events) `GET /r/{ns}/{name}/events?since={id}` and `GET /ns/{ns}/events?since={ns_id}` first replay the entries after `since`, one log page (§7.1) per fetch, then stream live ones.
  - `Last-Event-ID` is also accepted, and wins over `since`.
  - Without either, or with an empty `since`, the stream replays from genesis. For a resource with no entries yet, it waits for the first.
  - Replay is judged as its log range is, before any event is sent: a `since` not in the log is `404`, and a revision to replay whose patch set is pruned is `410`.
  - A prune that reaches a page not yet sent ends the stream.

  Responses are `Cache-Control: no-store`. They require `read`, unrestricted for a namespace stream (§2.1). Before each event, the stream judges that read check again, as for a request made then, and ends instead if it fails. It also ends, at the latest, when the grant or cookie it was admitted under expires.
- [ ] **HTTP-24** (Events) A resource stream has four event types:
  - `revision` and `tombstone`: the data is the resource log entry (§7.1), and the `id:` field is its id;
  - `purge` and `prune`: the data is the namespace entry that records them (§7.4) without its `id` and `prev`, and there is no `id:` field.

  A resource stream ends after its `purge` event. A namespace purge sends no `purge` event and ends the resource's streams. Replay carries only `revision` and `tombstone` events. A namespace stream's events are its log entries as §7.4 serves them, each entry's `id` as the `id:` field. It ends after its `purge-ns` event, or at once when `since` names that entry.

### §7.4 Namespace

- [ ] **HTTP-10** (table) `GET /ns/{ns}` is `302` with `Location: /ns/{ns}/rev/{ns_id}`, `ETag: "{ns_id}"` and `X-Config-Revision: {config_id}`, cached as a head pointer. `GET /ns/{ns}/rev/{ns_id}` is `200` with the namespace document in force at that point in the chain, `ETag: "{ns_id}"` (`"{ns_id}.{e}"` when sealed) and `X-Config-Revision: {config_id}`, immutable. An `ns_id` not in the chain is `404` there, cached as short, and also `404` at its `/log` and `/heads`. `GET /ns/{ns}/events?since={ns_id}` is an SSE stream of namespace entries (§7.3), `no-store`.
- [ ] **HTTP-25** (table) `GET /ns/{ns}/rev/{ns_id}/log?since={a}` is `200`, immutable, paged as in §7.1. It answers an array of `{ id, prev, kind, resource?, name?, remote?, at?, target?, entries?, source?, forced?, author, via?, grant?, gesture?, undoes?, gestures?, created }`, following §3.5:
  - `gesture` and `undoes` are those of a single write.
  - `gestures` maps each resource of a batch to a list of `{ "gesture"?, "undoes"? }`, one per step. None of these are hashed.
  - `grant` is `{ "id", "sub", "kid" }`: the grant id (§C.3) in text form, and its root `sub` and `kid`.

  Some entries record a particular grant:
  - a local branch's creation, the creator's, on both its entries;
  - a namespace's genesis, the operator's;
  - a janitor's prune, the janitor's;
  - the schema namespaces a remote branch mirrors at creation, the creating operator's.

  `grant` is absent from entries the server writes itself: propagated purges, purges applied from a remote base, and its own prunes. It is also absent from entries written before v0.37, unless it can be recovered from their revisions. It is `null` on entries written while authentication is disabled. An empty or omitted `since` means from the chain's first entry. It is `404` if `a` is neither `ns_id` nor earlier in its chain.
- [ ] **HTTP-26** (table) `GET /ns/{ns}/rev/{ns_id}/heads?after={name}` is `200`, immutable, with `{ "heads": [ … ], "next"? }`. That is a page of `{ resource, kind, target, created?, size?, digest? }`:
  - one row per resource as of that revision, including resources a branch reads through;
  - `kind` and `target` those of its latest `head`, `tombstone` or `purge` entry;
  - in ascending byte order of name, strictly after `after`, which needn't name an existing resource.

  `next` names the following page, and is absent on the last. In a namespace that is neither sealed nor end-to-end, judged by the namespace serving the page:
  - `created` is the target entry's;
  - for a live head of a resource that isn't purged, `size` is the length of its canonical document in bytes, and `digest` the `Repr-Digest` value of it uncoded (`sha-256=:…:`).

  At E2 and E3 all three are absent. Readers MUST NOT rely on the three; a page once served never gains them. Pages carry the tag `heads:{ns}`, purged with every resource purge in the namespace. It is `410` once the namespace is purged (§8.5).
- [ ] **HTTP-27** (table) `GET /ns/{ns}/principal` is `200`, `no-store`, with `X-Config-Revision` and `{ "principal", "kid", "key", "operator", "can", "roles", "writer": { "frozen", "successor"?, "nonce", "signatures", "level"?, "limits" }, "catalog"?: { "trust", "files"? } }`, for the grant in `Authorization`:
  - `principal` is as in §6.4.1.
  - `kid` names the key that verified the root block.
  - `key` is the RFC 7638 SHA-256 thumbprint, base64url without padding, of that key as a JWK: `{"crv":"Ed25519","kty":"OKP","x":<pub>}` for a namespace key, the published JWK for an operator key.
  - `operator` is true for an operator grant, whose `can` is its blocks' verbs and `roles` `[]`.
  - Otherwise `can` is the verbs its blocks and key allow, where it carries roles only those an effective role lists, and `roles` its effective roles. `can` never lists `branch` where the server refuses local branches.

  `writer` gives these:
  - `frozen` and `successor`;
  - `nonce`: `required` where the namespace document requires nonces or the namespace is sealed at E2, otherwise `optional`;
  - `signatures`: `optional` or `required`;
  - `level`: `at-rest`, `sealed` or `e2e`, absent without `encryption`;
  - every §6.6 limit in force, at the namespace's value or else the deployment's default, and deployment-only ones at the deployment's values, without allowances or a key scope's `rate`.

  For a catalog namespace, `catalog` gives `trust` (`[]` when absent) and `files` (§B.6, §H.2). A grant without unrestricted `read` of the catalog gets `files` without its `x-` members, and in place of `trust` only `trusted`, whether `files.ns` is trusted.
- [ ] **HTTP-28** (table) For `GET /ns/{ns}/principal`, only the `ns` check (§7) and verification (§C.2 item 1, key scope included) apply, with no verb check and no rule. It answers:
  - to an operator grant, `404` for a namespace that doesn't exist;
  - to a grant that fails the `ns` check, `403`;
  - to one that can't be used, or none, `401`, even in a public namespace;
  - while authentication is disabled, `200` without `principal`, `kid` and `key`, with `operator: false`, `can` every verb the server allows and `roles` `[]`, and `404` for a namespace that doesn't exist;
  - for a purged namespace, `410` once the grant verifies (§8.5).

  It draws no rate token.
- [ ] **HTTP-29** (table) `GET /ns/{ns}/gestures/{gesture}` is `400` (`bad_input`), a request-shape error, for a `{gesture}` not of the form of §7.2. Otherwise:
  - It is optional, and not offered in sealed or end-to-end namespaces. Where it isn't offered, it is `404` with `code: "not_offered"`, after the `read` check.
  - It is `200`, `no-store`, with `[{ resource, id, kind, gesture?, undoes?, author, ns_id }]`, one per revision or tombstone written with that gesture or undoing it, oldest first. It leaves out purged resources, and lists only entries for resources the reader's grant may read.
  - It is paged by `logPageSize`. A full page carries `X-Log-Next: {resource}/{id}`, its last row, and the next page is `?after=` that value. An `after` that names no such entry of a resource the grant may read is `404`. A page without `X-Log-Next` is the last.
- [ ] **HTTP-30** (table) `GET /ns/{ns}/grants/{gid}` is `200` with `{ id, root, stored }` for a grant recorded by an entry of this namespace, or, in a local branch, of its bases up to their `at`, in its non-bearer form (§C.3.1). It is `404` for any other. It requires unrestricted `read` (§2.1). It is sealed in sealed namespaces and `private` in end-to-end ones. It is cached as immutable, `private` at E3.
- [ ] **HTTP-31** (table) `GET /ns/{ns}/branches` is `200`, cached as a head pointer. It lists `[{ name, at, frozen, purged, successor?, drafts? }]` for the namespace's direct branches, and `{ remote, at, ns_id, expires }` for remote branches whose registration hasn't expired (§G.3). It requires unrestricted `read` (§2.1), and is `410` once the namespace is purged (§8.5).
- [ ] **HTTP-11** (Namespace writes, table, Content types) `PATCH /ns/{ns}`, with `Content-Type: application/json-patch+json`, takes as its precondition `If-Match: "{config_id}"` (the value of `X-Config-Revision`, quoted), or `If-None-Match: *` to create. It answers:
  - on success, `201` with `X-Config-Revision: {new config_id}`, `X-Namespace-Revision: {ns_id}` and `Location: /ns/{ns}/rev/{ns_id}`, naming the namespace entry the write produced, and the body `{ "config": new config_id, "ns_id" }`;
  - on an idempotent retry (§7.2), `200` with the same headers and body; when a batch wrote the config change, `ns_id` is the batch's entry;
  - on failure, `412` with `{ config }`, or without `config` for a creation under a taken name; `422`; `428`; `401`; or `403`.

  Other `PATCH` content types are `415`.
- [ ] **HTTP-32** (Envelope) Config writes are checked with a `config` envelope (§6.4.1), and key-scope and grant rules apply to them.
- [ ] **HTTP-33** (Keys, roles, revocations, limits and exposure) These writes need a `*` key (§C.2):
  - writes covering or overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption`, `/signatures`, `/nonce`, `/schemaReads`, `/catalogs` or `/maxLag`;
  - writes that set `read` to `public`.

  Making `read` stricter needs no `*` key.
- [ ] **HTTP-34** (Validation, Members, `x-` members, Errors) The namespace document is validated against the built-in namespace-document schema of the deployment's version.
  - Rules and patterns must be well-formed and within limits.
  - The members of §12.3, the core's and those of Addenda B and F, are validated strictly.
  - Any other top-level member must start with `x-` (case-sensitive), and is stored as data. So may members inside the addenda's objects (§12.3), except as keys of `catalogs`.
  - Role entries are open: the core reads `can` and `rules` and ignores the rest.
  - Other nested objects, such as key entries, are strict.

  Anything else is `422` with `code: "invalid"` and `errors: [{ "pointer", "message" }]`.
- [ ] **HTTP-35** (Documents stored under an earlier version, Versions) Take a member this version doesn't define, or such a field in a key entry. A write keeps it if it leaves it unchanged, and may remove it. The write is `422` only if it adds or changes one, and a `move` to an `x-` name renames it. Creating a branch of a namespace holding such a member is `422` until it is renamed. A deployment that reads another's namespace documents ignores members it doesn't define. Only a tool that copies a document into a namespace refuses one that holds such a member, unless it starts with `x-`; none refuses on the spec version alone.
- [ ] **HTTP-36** (Logging) A config change appends a `config` entry to the namespace chain. Namespace events use the entry's `kind` as their event type: `head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns` and `prune`.
- [ ] **HTTP-37** (Branch fields) The `422`s below are validation errors (`invalid`, with `errors` pointing at the member):
  - `base` is set when a branch is created and can never change (`422`). A namespace created with `PATCH` may set only a remote `base` (§G.3), and one without `origin` is `422`.
  - A config write to a branch MUST NOT remove or change a key entry that is a `*` key in one of its bases (`422`).
  - A write that sets or changes `successor` MUST name another namespace that exists and isn't purged (`422`). For a branch, that is a branch of the same base, or of a namespace further up its `base` chain, whose `at` may differ. For a namespace that isn't a branch, it is another namespace that isn't a branch.
  - A branch of a namespace whose `read` isn't `public` MUST NOT become `public` (`422`).
  - A branch MUST NOT break the level rules of Addendum E (Levels, `422`), nor turn off a `nonce` requirement its base has (`422`).
- [ ] **HTTP-38** (Branch fields) `drafts: { "for": [ … ] }` is optional. It lists, as names or prefixes ending in `*`, the other namespaces whose writes, and those of their branches, may resolve schema paths into this branch (§6.1).
  - A bare `"*"` serves every namespace. Without `drafts`, a branch's drafts serve only itself and its own branches.
  - Narrowing it is subject to the `in_use` rule of §6.1.
  - `drafts` is `422` in a namespace that isn't a local branch, or that is end-to-end.

  Two changes are `409` with `code: "in_use"` and `dependents`: making a namespace with public dependents stop being public, and making a namespace require nonces while a dependent doesn't. Nor can a namespace raise its level above a dependent's (Addendum E, Levels).

### §7.5 Batches

- [ ] **HTTP-12** (Items, Scope) `POST /ns/{ns}/batch` writes to several resources of that one namespace, all or nothing. A batch never spans namespaces. Each item names one resource, at most once per batch, with exactly one precondition as in §7.2. A missing one is `428`. These are `400` (`bad_input`), a request-shape error (§6.2):
  - a batch that names a resource twice;
  - an item with both `ifMatch` and `ifNoneMatch`;
  - an item without steps.

  An item's `steps` are applied in order, each chained on the previous one:
  - A patch set appends a revision, or restores if the previous entry is a tombstone.
  - `"delete"` appends a tombstone. A `"delete"` that is the first step of an item under `ifNoneMatch` is `428`, at step 2.5 of §6.2. One that follows another `"delete"` with no patch set between them is `422` (`invalid`), also at step 2.5.

  Resource purge is never part of a batch.
- [ ] **HTTP-39** (Items) A step may also be an object with exactly one of `"patches": [ … ]` or `"delete": true`. It may add `gesture` and `undoes` (§7.2), and `signature`: the step's author signature in the form of the `Signature` header (§C.3.1). An item, or the whole batch, may carry `gesture` and `undoes` as defaults, which a step's own values override. The whole batch may carry them as `Gesture` and `Undoes` headers instead; one sent both ways is `400` (`bad_input`).
- [ ] **HTTP-40** (Checks) Every step is checked with its own envelope, following §6.2 across the whole batch.
  - `items` may be empty or absent when `config` is present. A batch with neither is `400` (`bad_input`), a request-shape error.
  - The optional `config` change runs steps 1–6 first, as a config write (§7.4), its `*`-key guard included (§C.2).
  - The items are then checked against the configuration it produces, except that `frozen` and the batch limits (§6.6) always come from the current configuration.
  - `frozen` refuses items only, so a batch with no items works in a frozen namespace.
- [ ] **HTTP-41** (Checks) Batch limits can depend on the principal, through an allowance (§6.6).
  - The server stops reading, at once (`413`), a body more than four times the larger of the verified principal's `batchSize` and the deployment maximum of `documentSize`.
  - Item counts, and the total size of the items' canonical patch sets against `batchSize`, are checked at step 4, before any item's own limits.
  - Items may reference schema revisions created by earlier items (§6.1). They may reference blobs uploaded or copied before the batch, or, with a local `source`, taken from it (§7.8).
- [ ] **HTTP-42** (Success) A successful batch appends one `batch` entry (§3.5). It answers `201` with `{ "ns_id": …, "config"?: …, "items": [{ "resource": …, "ids": [ … ] }] }` and `X-Namespace-Revision`. When the batch has a `config` change, `config` and `X-Config-Revision` give the new config id.
- [ ] **HTTP-43** (Failure) A failed batch writes nothing.
  - Its status is that of the earliest failing step of §6.2. Where items fail that step with different statuses, it is that of the first of them in request order.
  - Its body is `{ "code": "batch", "items": [{ "index", "status", "code", … }] }` for the items that failed at that step. If any item fails authorisation, only those items are reported.
  - A `config` change that fails is answered as that config write would be (§7.4), without `items`.
  - A purged namespace (§8.5), a frozen namespace (§8.4), a rate limit, `itemsPerBatch` or `batchSize` (§6.6), and a refused `source` are answered as for a single write, without `items`.
- [ ] **HTTP-44** (Dry run) `?dry-run=1` runs steps 1–6 for the `config` change, if any, and for every item, as a submit would, and writes nothing.
  - The items are checked against the configuration the change would produce, or against the current one if the change fails after step 1.
  - A blob that isn't available is reported, and the later steps run as if it were.
  - It answers `200` with `{ "items": [{ "index", "status", "code"?, "ids"?, … }], "config"? }`. `items` is the report for every item, with `status` `201` for one that would pass, or `200` for each item when a submit would be answered as an idempotent retry. It includes the ids a submit would produce and any `signature` failure.
  - `config` is the report for the `config` change, with the config id a submit would produce.
  - If the `config` change fails step 1, the dry run answers as that config write would. Otherwise, if any item fails authorisation (§6.2 steps 1 and 2.2), it answers `401` or `403`, reporting only those items.
  - A rate limit, a purged or frozen namespace, `itemsPerBatch` or `batchSize`, and a refused `source` are answered as for a submit.
- [ ] **HTTP-45** (Idempotent retry) The answer is `200` with an earlier batch, as in §7.2, when both of these hold:
  - one earlier `batch` entry by the same principal already contains exactly the entries this batch would produce, its config entry included, with the `config` change's `ifMatch` as that revision's parent;
  - every item passes the retry's verb check (§C.2 item 2).

  Only `batch` entries match a batch's retry, so a batch with only a `config` change retries an earlier `batch` entry that holds just that config entry. If the resource of any item has been purged since, the retry fails with `410`, before any other precondition, with the `batch` body listing those items (`code: "gone"`).
- [ ] **HTTP-46** (Reading other namespaces) Some checks read a namespace other than the one the request names: a batch's local `source`, a blob copy's source (§7.8), and a schema revision in another namespace, a draft in a branch included (§6.1). Each tries the request's own grant and every grant in `Source-Authorization` headers, which may be repeated.
  - The first grant that names that namespace, verifies under its keys (§C.2) and allows that check's read serves.
  - A public namespace needs no grant.
  - If none serves, the check fails as its own section says, revealing nothing about the namespace.
- [ ] **HTTP-47** (`source`) `source` is recorded in the batch entry.
  - For a local source and a caller with unrestricted `read` on `source.ns`, judged as for reading other namespaces, the server checks that `source.at` is in the chain of `source.ns` (`422`, `code: "source"`). It does so at step 4 of §6.2, after the batch limits and before any item's own checks.
  - For any other caller, the source is recorded unchecked and makes no blobs available.
  - A source in another deployment carries `origin` and is recorded without checks. An `origin` equal to this deployment's own is `422` (`source`), for any caller, at the same step.
- [ ] **HTTP-48** (Events) Each resource's event stream carries its new entries, and the namespace stream carries one `batch` event.

### §7.6 Branches

- [ ] **HTTP-13** (Request, Result) `POST /ns/{base}/branches` with `{ "name", "at"?, "patches"? }` creates a branch, and `patches` defaults to `[]`. For a local branch:
  - `at` defaults to the base's latest `ns_id` when the branch entry is inserted.
  - `If-None-Match: *` is required; `If-Match` alone is `428` too, at step 2.5 of §6.2, and never answered as a retry.
  - Success is `201` with `Location: /ns/{name}` and `X-Namespace-Revision` for the `branch` entry appended to the base's log (§3.5).
  - A taken name is `412`, with no `head` or `config`, including one taken by a purged namespace.
  - A retry by the same principal with the same `at` and `patches` gets `200`, as in §7.2, until the branch is purged, and `412` after that. A retry that omits `at` counts as naming the `at` recorded for that branch.
  - An `at` that isn't in the base's chain is `422`, and a purged base is `410` with `code: "purged"`.

  A remote branch's registration (§G.3) uses this endpoint too, and renews with `If-Match`.
- [ ] **HTTP-49** (Configuration) The branch's namespace document starts as a copy of the base's current document. `frozen`, `successor`, `merged`, `abandoned`, `cleanup`, `drafts` and `schemaReads` are removed, `base: { "ns": base, "at": at }` is added, and then `patches` are applied. Its configuration chain starts with one entry, the genesis patch set `[{ "op": "add", "path": "", "value": <that document> }]`, where `<that document>` is the document after `patches`. That entry is the `target` of the base's `branch` entry. The branch's rules, roles and read mode are its own from then on, and its keys follow the base (§C.4).
- [ ] **HTTP-50** (Authorisation) Creating a local branch needs `branch` and unrestricted `read` (§2.1) on the base, checked as §C.2 item 2 says. The `*`-key guard (§C.2) applies to `patches`, with a `*` key of the base. Every `*` key of the base is kept in the branch and can't be removed from it. The base's rules evaluate a `branch` envelope whose `resource` is the new namespace's name, whose `doc` is the new namespace document, and whose `writes` come from `patches`. Failures answer as for other writes (§6.2, §C.2).
- [ ] **HTTP-51** (A branch is a copy, Nesting and number) Whoever can read the branch can read the base as it was at `at`, under the branch's own configuration. A branch of a namespace that isn't public MUST NOT be public. A branch may itself be a base, within the branch-depth and branches-per-namespace limits (§6.6).
- [ ] **HTTP-52** (In another deployment) A remote branch has `base: { "origin", "ns", "at", "chain" }`. It is a new namespace, created with the deployment operator key as §C.4 bootstrapping requires (§G.3). Four rules don't reach across deployments: keys following the base, revocation in bases, purge propagation, and dependents blocking a namespace purge.
- [ ] **HTTP-53** (Reading through) For a resource with no entries of its own in the branch, the branch answers as the base did at `at`, recursively through bases of bases:
  - `302` with `Location: /r/{branch}/{name}/rev/{id}` and `ETag: "{id}"`, where `id` is the head as of `at`;
  - `410` if the resource was tombstoned then;
  - `404` if it didn't exist then.

  Everything is served under the branch's own URLs. Changes in the base after `at` are never seen, except purges (§8.3) and the base's pruning (§8.6).
- [ ] **HTTP-54** (History) `/r/{branch}/{name}/rev/{id}` serves any id in the resource's ancestry as seen from the branch, including base revisions up to the foreign parent. `…/log?since=` crosses the foreign parent. `/r/{branch}/{name}/blob/{bid}` serves the base's blobs that the branch's view references, as well as the branch's own (§7.8 Reading).
- [ ] **HTTP-55** (First write) The first write to a read-through resource checks its precondition against the base's head as of `at`, and takes that head as its foreign parent, whether it appends, deletes or restores. If the document it builds on is pruned (§8.6), or for a delete the document it deletes, the write is `410` (`pruned`) once its precondition passes. Creating a name that didn't exist in the base at `at` is an ordinary create.
- [ ] **HTTP-56** (Logs) The branch's namespace log contains only the branch's own entries. Its creation is recorded in the base's log as a `branch` entry.

### §7.7 Live reads by long-poll

- [ ] **HTTP-57** (Answer) This item covers `GET /ns/{ns}/log?since={ns_id}&live=long-poll&cursor={c}` and `GET /r/{ns}/{name}/log?since={id}&live=long-poll&cursor={c}`.
  - If there are entries after `since` (empty or missing: from the beginning), the server answers `200` at once with them, up to one log page (§7.1), in the shapes of §7.1 and §7.4. `X-Namespace-Revision` (resource logs: `X-Revision`) names the last entry returned.
  - Otherwise it waits until an entry arrives or the current interval ends. The timeout answer is `204`, with the same header naming `since`, or without it when `since` is empty.
  - Both answers carry `X-Cursor`.
  - A `since` not in the chain is `404`, and a pruned range `410`, as in §7.1. A resource with no entries waits as for an empty `since`.
  - A namespace log needs unrestricted `read` (§2.1), and a resource log `read` on that resource.
  - Without `live`, these URLs answer `302`, cached as a head pointer, to `…/rev/{head}/log?since=…`. Without `live`, a resource with no entries is `404`, cached as short.
- [ ] **HTTP-14** (Intervals and cursors, Clients)
  - Time is divided into fixed intervals (default 20 seconds) counted from a fixed epoch. The cursor is the interval number, in decimal.
  - On `200`, the response cursor is the current interval number. On `204`, it is the greater of the current interval number and the request's cursor plus one.
  - A wait ends at the latest at the interval boundary.
  - A cursor more than one hour's worth of intervals ahead of or behind the server's is `400`.
  - A request without a cursor, or with one behind the server's by less, is answered at once: with the entries after `since` if there are any, otherwise `204` with the current cursor in `X-Cursor`.
  - A cursor ahead by an hour's worth or less waits as a current one does, until this server's interval boundary at the latest, and its `204` carries the request's cursor plus one.
  - Clients echo `X-Cursor` as `cursor` in the next request, and take the returned revision as the next `since`.
- [ ] **HTTP-58** (Caching) The cache key is the path plus `since`, `live` and `cursor`. The page size is fixed by the deployment, not chosen by the client. Any other query parameter, a `live` other than `long-poll`, or a `cursor` that isn't a decimal number, is `400`. A `200` is `public, max-age=0, s-maxage={interval}`, and a `204` is `public, max-age=0, s-maxage=2`. Private namespaces follow §9, with these lifetimes at the edge. Tags are those of the log: `ns:{ns}`, and `r:{ns}/{name}` for resource logs.

### §7.8 Blobs

- [ ] **HTTP-15** (References) A blob reference is an object, at any depth, whose `$blob` member is a string. `$blob` is the blob id (§3.7), `type` its media type and `size` its length in bytes. `nonce` is present exactly when the blob has one. No other members are allowed, except `sealed` at E3 (§E.3.1). At a raw document's root, the top-level members validation leaves out aren't part of the reference. References are found by walking the document, whether or not it has a `$schema`. A malformed one is `422` (`code: "blob"`). Schema documents, whose `$schema` is a dialect URL, contain no references.
- [ ] **HTTP-59** (Attachments, Pending, Attached)
  - After an upload or a copy, a blob is pending until a revision references it.
  - The uploader is the root `sub` and `kid` (§6.6).
  - A pending blob is invisible: reads answer `404`, and only its uploader can reference it.
  - Each uploader has its own pending entry, even for bytes already stored. An entry counts toward its uploader's `blobPending`, at least 4 KiB per blob. It is deleted once older than `blobGrace`, and uploading it again restarts that time.
  - A write whose document references the blob ends every pending entry for it in that resource, whoever uploaded it.
  - At step 7 of §6.2, a write attaches every blob its resulting document references to its own resource, in the same transaction as the revision.
  - An attachment lasts while a document still stored for the resource references the blob. Those documents are the ones at or after the horizon, the horizon's and other kept documents, and the last live document of a tombstoned resource.
  - When pruning removes the last such document, the attachment ends and its bytes are deleted. Where storage keeps identical bytes once, only this attachment's reference is removed, and the bytes go when nothing holds them.
  - Purge ends every attachment of the resource.
- [ ] **HTTP-60** (Availability) A write may reference only blobs available to its resource:
  - blobs attached to that resource in this namespace;
  - blobs pending there, if the writer uploaded or copied them;
  - in a branch, blobs attached to the same resource in a base and referenced by a document in the resource's history as the branch sees it. The write attaches them to the branch's own resource;
  - in a batch with a local `source` whose `source.at` the server has checked (§7.5), blobs attached to the same resource in `source.ns`, or in a base it reads through, and referenced by a document in that resource's history as `source.ns` sees it at `source.at`. This holds whatever the ranks. From a sealed `source.ns`, and for an `e2e` one's blobs from before a raise from `sealed`, only blobs the caller's keys open (§2.1) are available.

  A reference to a blob that isn't available is `422` (`code: "blob"`), at step 4 of §6.2. So is one that doesn't match the blob's `type`, `size` or `nonce`.
- [ ] **HTTP-61** (Uploading, No precondition) `PUT /r/{ns}/{name}/blob/{bid}` runs its checks in this order:
  1. authorisation at step 1 of §6.2, with `create`, `append` and `restore` as candidates (§C.2 item 2), then the rate limits (§6.6). No rule beyond step 1 sees an upload.
  2. A purged resource is `410`, and any upload to a purged namespace is `410` (`purged`). A tombstoned resource accepts uploads.
  3. A frozen namespace is `409`.
  4. A media type that can't be parsed is `400` (`bad_input`), and so is a `Blob-Nonce` that isn't 26 base32 characters, an empty one included. In an E3 namespace any type other than `application/vnd.patchlog.sealed-blob` is `415`.
  5. A body larger than `blobSize` is `413`, and so is one that would take the uploader's pending blobs in the namespace past `blobPending`.
  6. The id recomputed over the body (§3.7) must match, else `422` (`blob_mismatch`). It uses the `Blob-Nonce` as nonce, or an empty nonce without one.

  Errors in the URL and its query parameters, a malformed `{bid}` included (`400`, `bad_input`), come before check 1. Any other request-shape error in an upload's headers is `400` (`bad_input`) at check 4, and a copy's come where Copying says. An upload takes no precondition: one sent is `428`, at check 4. An upload writes no namespace entry. It is idempotent: the answer is `201` with `ETag: "{bid}"` whether or not the bytes were already stored, and every uploader is charged for its own pending entry.
- [ ] **HTTP-62** (Copying) An upload with an empty body and `Blob-From: /r/{ns2}/{name2}/blob/{bid}`, naming the same `bid`, copies a blob within the deployment.
  - Checks 1–3 run first, for the target.
  - Then a request with a body, or a `Blob-From` that can't be parsed, is `400`, before any body is read. A different `bid` is `422` (`blob`).
  - The source is then checked as a read of `/r/{ns2}/{name2}`, judged as for reading other namespaces (§7.5). A grant whose blocks name both namespaces, signed by a key they share, serves for both. Any failure of this check, its `401` and `403` cases included, answers `404`.
  - A copy also answers `404` in each of these cases, each on its own:
    - it goes into another namespace that ranks below its source (§2.1);
    - Reading wouldn't serve the blob at the source;
    - the blob comes from a sealed source, or from an `e2e` one from before a raise from `sealed`, and the caller's keys don't open it (§2.1).
  - The copy is then checked like an upload of the source's type, nonce and size (checks 4 and 5), whatever `Content-Type` and `Blob-Nonce` it carries.
  - It costs a token like an upload, and nothing from `blobRate`.

  A batch with a local `source` carries `Source-Authorization` in the same way.
- [ ] **HTTP-63** (Files) A document is raw when its root is a blob reference with no other members than the top-level ones validation leaves out (`$schema`, a fresh `$nonce`, a `$successor`). It is served at `…/raw` (§7.1) with the blob's type. The read check of both `…/raw` and `…/blob/{bid}` is the document's own; a `schemaReads` referrer (§6.1) opens revision paths only. Its `size` in `/heads` (§7.4) is the reference's length, not the file's.
- [ ] **HTTP-64** (Reading)
  - Every response to a blob URL, errors included, carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`. The one exception: a `200` or `206` for a stored `type` of exactly `application/pdf` may go without the sandbox, still with `nosniff`. A deployment serves PDFs with `Content-Disposition: attachment` unless it opts into inline display.
  - `GET /r/{ns}/{name}/blob/{bid}` answers `200` with the bytes, and `206` for a range. The `200` carries `Content-Type` its stored type (§3.7), with `; charset=utf-8` for a `text/*` type, `ETag: "{bid}"` and `Accept-Ranges: bytes`.
  - Sealed namespaces answer as in §E.2.2 instead, and so do blobs from before a raise from `sealed` at E3.
  - Whoever may read `/r/{ns}/{name}` may read its blobs.
  - It serves the blobs attached to the resource and, in a branch, the base's blobs that the branch's view references. Pending and unknown blobs are `404`.
  - A tombstoned resource keeps serving its blobs. A blob whose attachment pruning ended is `410`, as in §7.1, and every blob of a purged resource is `410`.
  - Caching is immutable, with the resource's tags (§9). In sealed namespaces, and for those blobs at E3, the URL also names an epoch (§E.2.2).
- [ ] **HTTP-65** (Encryption) In sealed namespaces, and in those that require nonces, writers MUST give the blobs they create a nonce (§C.7); the server doesn't check it. Blobs carried over from another namespace keep their ids, nonce or not.

## §8 Deletion and purge

### §8.1 Tombstone (delete)

- [ ] **DEL-1** (Tombstone (delete), Moves)
  - `DELETE` with `If-Match: head` appends a tombstone to the resource log and a `tombstone` entry to the namespace log, atomically.
  - A move is recorded in content: the resource's last revision before its tombstone sets the top-level `$successor` to the resource that replaces it. That is a bare name for one in the same namespace, resolved against the namespace that serves the `410`, or `/r/{ns2}/{name2}` for one in another, with names valid under §3.6. Either form is well-formed wherever the document is, whatever `ns2` names. Validation leaves it out (§6.2 step 5).
  - The head pointer then returns `410`. Only in a namespace that is neither sealed nor end-to-end does that `410` carry `successor`, copied from the last document's `$successor` if well-formed.
  - Earlier `/rev/{id}` URLs and the resource's blobs keep returning `200`.
  - Further `PATCH` requests return `410` unless they restore (`If-Match: "{tombstone}"`). That `410`, and a `DELETE`'s, has `code: "gone"` and `head`, the tombstone.
  - A `PATCH` with `If-Match` under a grant without `restore` gets `403` instead (§6.2 step 2.2).

### §8.2 Restore / recreate

- [ ] **DEL-2** (Restore / recreate) The chain continues from the tombstone. The first revision after it applies its patches to the last live document. `[]` restores the document exactly as it was, `$successor` included. Where nonces are required (§C.7), a fresh `$nonce` on its own does the same. A restore with a root `replace` recreates the document from scratch, if namespace rules allow it.

### §8.3 Purge

- [ ] **DEL-3** (Effect, Namespace entry, Responses, CDN, Branches)
  - A purge removes the resource's content (patches, snapshots and blobs) and marks the resource purged. Storage that keeps identical content once removes only this resource's references to it.
  - Its archived history (§8.6) is deleted too, or made unreadable by destroying its key. Restoring from an archive MUST skip purged resources.
  - Ids, parent links and namespace entries are kept.
  - A `purge` entry is appended to the namespace log. Consumers MUST drop the resource and purge their own derived data and cache tags (§10).
  - All `/r/{ns}/{name}/…` URLs then return `410`, before a `not_offered`. They do so once the caller passes the read check for that URL, or, for a write, step 1 of §6.2. Until then, a read answers as for a resource the caller can't read.
  - The CDN is purged by tag, `heads:{ns}` included, never by id.
  - A purge propagates to the same name in every branch of the namespace, recursively, whether the branch reads it through or has its own chain for it. Successor generations and chains the branch created itself are included. In each branch the propagation reaches, the server purges the resource and appends a `purge` entry to that branch's namespace log.
  - A branch that sees no entry for the name, read through or its own, is skipped, but its own branches aren't.
  - Consider a branch created later, at an `at` before the purge, that would read an entry for the name through. It answers `410` for the name, and its `/heads` lists it as `purge`, with its head as of `at` as `target`.
  - Purges never propagate upwards.
- [ ] **DEL-7** (Limits of purge) Copies of the resource's blobs in other resources (`Blob-From`, §7.8) stay until those resources are purged too.

### §8.4 Freezing a namespace

- [ ] **DEL-4** (Freezing, What still works, `successor`)
  - A config write sets `"frozen": true`, and `false` unfreezes.
  - In a frozen namespace, resource writes, batches with items, and blob uploads and copies are `409` with `code: "frozen"`, and `successor` if set. The check is at step 2.4 of §6.2 (check 3 of §7.8 for uploads), after the idempotent-retry lookup, so a retry of a write recorded before the freeze still answers `200`.
  - A batch with no items is a config write.
  - Unfreezing a branch whose base already has `branchesPerNamespace` live branches is `422` (`code: "limit"`, `limit: "branchesPerNamespace"`), with `max` the base's value.
  - These still work in a frozen namespace: reads, events and namespace consumers, config writes, resource purges, namespace purges, creating branches from it, and pruning.
  - `successor` is optional, and §7.4 constrains it.

### §8.5 Purging a namespace

- [ ] **DEL-5** (Request, Requirements) `POST /ns/{ns}/purge` with `If-Match: "{ns_id}"` is `204` on success. As for any write, it is `428` without a precondition and `412` with the current `{ head }`. The checks run in this order, all before rules (step 6):
  1. the `purge-ns` verb, distinct from `purge` (step 1);
  2. a purged namespace's `410` (step 2.1);
  3. the namespace must be frozen, otherwise `409` with `code: "not_frozen"` (step 2.4);
  4. the precondition (`428`, `412`);
  5. no dependents (§2.1), otherwise `409` with `code: "in_use"` and `dependents`;
  6. no last copy removed of a schema revision (§6.1) referenced from another namespace, its own documents not counting, otherwise `409` with `code: "in_use"` and `referencing`.
- [ ] **DEL-8** (Effect)
  - Every resource is purged as in §8.3, without individual entries. One `purge-ns` entry is appended, as the log's last.
  - Purges propagated from a base (§8.3, §G.3) and retention prunes skip a purged namespace.
  - The namespace document chain, the namespace log with its authors, and every resource's ids and parent links are kept.
  - The name stays reserved.
  - The CDN is purged by the tag `ns:{ns}`.
- [ ] **DEL-9** (Answers afterwards, table) Every `410` of §8.5 has `code: "purged"` and `head`, the `ns_id` of the `purge-ns` entry.
  - These URLs answer `410`: `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…`, `/ns/{ns}/keys`, `/ns/{ns}/principal`, `/ns/{ns}/branches`, and `/heads` at any revision. They do so as soon as the full read check for that URL passes, and before any other answer to a well-formed request, `not_offered` included. The read check is:
    - the grant's rules;
    - unrestricted `read`, where the URL needs it;
    - any `read`, for the gestures listing;
    - §E.2.3's test, for `/keys`;
    - verification alone, for `/principal`.
  - `/ns/{ns}` and `/ns/{ns}/rev/{ns_id}`, logs, events and long-poll included, are served as before, except where sealed (DEL-11).
  - Any write to the namespace is `410`, after authorisation and rate limits and before any other check (§6.2 step 2.1). That covers resource writes, batches, blob uploads and copies, purges, prunes, config writes, branching from it, and remote registration.
- [ ] **DEL-10** (table)
  - Creating a namespace or a branch under a purged namespace's name is `412`. So is a branch creator's retry once the branch is purged.
  - Creating a remote branch whose base on A is purged, or whose chain holds a purged base, is `410` for any `at`, before `at` is checked. Its `ns`, `head` and `origin` name the first purged namespace found, A's before its bases'.
  - Edge-grant issuance for a grant naming a purged namespace is `410` only if every namespace refused is purged and the grant verifies there. Its `ns` and `head` name the first.
- [ ] **DEL-11** (Sealed namespaces) Where namespace documents and log ranges are sealed (§E.2.2), the purge destroys the epoch keys that seal them. Those reads, events and long-poll included, then answer `410`. `GET /ns/{ns}` still redirects, to a revision that answers `410` where it is sealed.
- [ ] **DEL-12** (Shared storage, Forcing, Irreversible) Storage that keeps identical entries of several namespaces once removes only this namespace's references. An `in_use` refusal for schema references can be forced as §6.1 says. An `in_use` refusal for dependents can't be forced. A purged namespace can't be restored.

### §8.6 Pruning and retention

- [ ] **DEL-6** (Pruning and retention, Horizon, Kept) Pruning changes no id. A revision below the horizon without a kept document answers `410` (`pruned`), with a link to the archive if there is one (§7.1). Pruning below a horizon revision `H` drops the patch sets of the revisions before `H`. It also drops the attachments of blobs that only the dropped documents referenced. It keeps:
  - every id, parent link, author, grant reference, creation time, `gesture` and `undoes`;
  - the ids of the blobs whose attachments it ends;
  - `H`'s document, and the protected documents;
  - if `H` is a tombstone, the last live document.
- [ ] **DEL-13** (Request) `POST /r/{ns}/{name}/prune` with `{ "horizon": id, "keep"?: [ids], "snapshot"?: sealed }` returns `200` with `{ "horizon": id }`, the effective horizon.
  - It needs the `prune` verb and is checked with a `prune` envelope whose `doc` is `{ horizon, keep? }` as sent. It works in frozen namespaces too.
  - It takes no precondition, and one sent is `428`, at step 2.5 of §6.2.
  - `horizon` MUST be the head or an ancestor of it (`422`). If needed, the server lowers it to the oldest protected revision, but never below the current horizon. The result is the effective horizon.
  - Two kinds of prune need a grant chained to a `*` key:
    - going below what `retention` keeps for the resource, which is everything where no rule matches it;
    - pruning where no archive is configured.
  - Applying a retention rule that says `"archive": false`, within what it keeps, needs only `prune`.
- [ ] **DEL-14** (Request)
  - `keep` lists extra revisions whose documents stay available, up to `keepPerResource`.
  - Outside a branch, each `keep` id MUST be a revision of the resource whose document is still served rather than `410` (`pruned`), or the prune is `422`.
  - A prune that sends `keep` replaces the resource's earlier `keep` set, and `[]` clears it. A prune without `keep` leaves the set as it is.
  - `keep` is `422` in an E3 namespace.
  - The prune appends a `prune` entry `{ resource, kind: "prune", target }` to the namespace log, with `target` the effective horizon, only if it moved the horizon or changed the `keep` set. Otherwise it writes nothing.
- [ ] **DEL-15** (Protected revisions, Protected documents, Branches don't prune) The horizon never passes:
  - any revision newer than the retry window;
  - the resource's head as of the `at` of every unpurged local branch, frozen or not;
  - the resource's head as of the `at` of every remote branch whose registration hasn't expired.

  Below the horizon, these keep their documents: schema revisions referenced (§6.1) from any namespace of the deployment, and the revisions listed in `keep`. A branch's own entries are protected until it is purged. A prune in a branch, once its checks pass, moves no horizon, ignores `keep` and writes nothing. It answers `200` with the resource's current horizon as the branch sees it, or with its genesis id where it has none.
- [ ] **DEL-16** (Archive) Before pruning, the server writes the pruned history as a full-history bundle (§G.4.1), with `"authors": true` and grant lines. It writes it to a destination configured by the operator or in `retention`, and MUST NOT write anywhere else. Only two prunes go without an archive: one under a `*` key where no destination is configured, and one that applies a retention rule saying `"archive": false`. In encrypted namespaces, archives are sealed bundles (§G.5.1.1), one per resource. A bundle's only recipient is a key the server holds for that resource, and purge destroys that key.
- [ ] **DEL-19** (Archive)
  - At E3, a prune carries `snapshot`, sealed like a patch set (§E.3.1). It holds `H`'s document, or the last live one when `H` is a tombstone.
  - At E3, a prune without `snapshot`, or one where no archive is configured, is `422` (`invalid`), with or without a `*` key.
  - A `snapshot` outside E3 is `422` (`invalid`).
  - At E3, if the effective horizon moves the horizon but isn't `H`, the prune is `422` (`invalid`), with the effective horizon as `horizon`.
  - The server skips E3 namespaces when it applies retention itself.
- [ ] **DEL-17** (Retention policy) The namespace document may declare `retention` rules, which the server, or a janitor with `prune`, applies periodically.
  - The first rule whose `select` matches a resource applies. `select` is a name `prefix` or a list of `names`, and a missing `select` matches everything.
  - `keep` keeps whichever is longer: the last `revisions`, or everything newer than `age`. Protected revisions always stay.
  - A rule without `keep`, or whose `keep` has neither, is `422` (`invalid`).
  - `archive` is the rule's archive destination, by default the operator's. A rule with neither applies only if it says `"archive": false`, which is `422` in an E3 namespace; otherwise the resources it selects keep everything, as where no rule matches.
  - Changing `/retention` requires a `*` key.
- [ ] **DEL-18** (The namespace log is never pruned) The namespace log is never pruned.
- [ ] **DEL-20** (Merges, branches and exports) Classification by ancestry (§F.3) uses ids only, and works across a horizon. When a fast-forward or replay needs pruned patch sets after the common ancestor, that item is a conflict. A full-history export (§G.4.3) from before the horizon needs the archive.

## §9 Caching

- [ ] **CACHE-1** (table) In a public namespace, responses carry these `Cache-Control` values and tags. Where a class names no other tags, the tags are `ns:{ns}`, plus `r:{ns}/{name}` for resources.

  | Class | `Cache-Control` | Tags |
  |---|---|---|
  | Head pointer (resource or namespace `302`, head `410`) | `public, max-age=0, s-maxage=1, stale-while-revalidate=5` | default |
  | Immutable (`/rev/{id}`, `/rev/{id}/log`, `/ns/{ns}/rev/{ns_id}`, its `/heads` pages, namespace log ranges, `/ns/{ns}/grants/{gid}`, `/blob/{bid}`, `/blob/{bid}/e/{e}`, and their ranges) | `public, max-age=86400, s-maxage=31536000, immutable`, except that `/ns/{ns}/grants/{gid}` is `private` at E3 | default; `/heads` pages also `heads:{ns}` |
  | Short (unknown-id `404`) | `public, max-age=5` | default |
  | Long (`410` of a purged resource or namespace, on a URL that isn't `no-store`) | `public, max-age=86400, s-maxage=31536000` | default |
  | Pruned (`410` below a horizon) | `public, max-age=3600` | `r:{ns}/{name}` and `ns:{ns}` |
  | Live long-poll `200` | `public, max-age=0, s-maxage={interval}` | as the log |
  | Live long-poll `204` | `public, max-age=0, s-maxage=2` | as the log |
  | Writes, batches, dry runs, SSE, a `502` (§G.3) | `no-store` | none |
- [ ] **CACHE-4** (Serving stale) An edge that keeps serving immutable responses while the origin is unreachable still removes them when they are purged. Head pointers are served stale only within their `stale-while-revalidate`. Live long-poll answers, `200` and `204` alike, MUST NOT be served stale. They carry no `stale-*` directive, and an edge MUST NOT apply stale-if-error or grace defaults to them.
- [ ] **CACHE-2** (Tags, Branches, Making a namespace private) A tag is `{kind}:{value}`, where `kind` is a lowercase word (§12.8) and `value` is namespace and resource names joined by `/`. `Cache-Tag` lists a response's tags separated by commas, and `Surrogate-Key` the same tags separated by spaces. A purge names whole tags, never part of one. Branches are cached under their own URLs and tags, and purges propagated to them (§8.3) purge those too. Making a namespace private, or raising it to sealed or end-to-end, requires a purge of the tag `ns:{ns}`, which the origin issues with the configuration write.
- [ ] **CACHE-5** (Sealed namespaces) A sealed namespace is cached by its `read` mode, under the public or the private rules, like any other namespace.
- [ ] **CACHE-3** (Private namespaces) In a private namespace, downstream responses carry `Cache-Control: private`, with a `max-age` no longer than their public class's. The origin gives edge lifetimes, with `CDN-Cache-Control` or `Surrogate-Control` at the values for public namespaces, only to a read the edge verified itself. That needs all of these:
  - both of the edge's verification headers are present;
  - each is one line without a comma;
  - the secret matches;
  - the prefix covers the URL;
  - the request carries no `Authorization`, `Source-Authorization` or signed-URL parameters.

  The origin still authorises the read itself, from the cookie or grant, which the edge forwards (§C.5.3). The headers decide only the lifetimes, never when an event stream ends (§7.3). Every other private response is `CDN-Cache-Control: no-store` (and `Surrogate-Control: no-store`), with or without an edge. That includes reads with a grant in `Authorization`, schema revisions opened by a referrer (§6.1), reads the edge only relayed, and every private response where no verifying edge is deployed.

## §10 Namespace consumers

- [ ] **CONS-2** (Checkpoint, Catch up, Follow, Fetch content, Consumers elsewhere) A namespace consumer works as follows:
  - It stores as its checkpoint the last `ns_id` it has fully processed, with `""` meaning from the beginning.
  - It catches up with `GET /ns/{ns}`, which gives the current `ns_id`, and then `GET /ns/{ns}/rev/{current}/log?since={checkpoint}`, page by page.
  - It follows with `GET /ns/{ns}/events?since={checkpoint}`, or by long-poll (§7.7).
  - It fetches content from immutable URLs.

  A consumer in another network or organisation records its checkpoint as `(origin, ns, ns_id)` and verifies what it fetches as §G.2 says.
- [ ] **CONS-1** (Handle every kind of entry, Advance the checkpoint) A namespace consumer handles each kind of entry:
  - `head`: it processes the document.
  - `tombstone`: it drops the resource.
  - `purge`: it drops the resource and purges its derived data and cache tags.
  - `batch`: it processes the entries as one unit.
  - `purge-ns`: it drops everything from the namespace and purges its derived data and cache tags. Where log ranges are sealed, a `410` `purged` stands for this entry.
  - `branch` with `remote`: it never fetches from it.

  A consumer that fetches a pruned revision gets `410` (`pruned`) and fetches the head instead. If the head is pruned too, it treats the resource as absent until a later entry. It advances its checkpoint only after the entries are durably processed, and its processing is idempotent.
- [ ] **CONS-3** (Verifying grants) A consumer that verifies grants presented to it MUST check keys and revocations as of the namespace head, and in a branch as of its local bases' heads too, not as of its checkpoint. It verifies grants recorded with entries as §C.3.1 says.
- [ ] **CONS-4** (Branches: Discovery, Contents, Access) A consumer that follows branches learns of them from `branch` entries with `name` in the logs it already follows, recursively. If it started from `/heads`, it learns of earlier branches from `GET /ns/{ns}/branches`. For such a branch, or one it is told to follow directly, it starts from the branch's `/heads` listing at the branch's first `ns_id`, which includes read-through resources, and then follows the branch's own log. It needs unrestricted `read` on the branch (§2.1), and skips a branch it may not read.

## §12 Registries

### §12.1 Errors

- [ ] **ERR-1** (§12.1 table) An error answer carries the `code` of the §12.1 row for its case, with that row's status, in the body shape of §12.1, and the members that row names.

### §12.2 Limits

- [ ] **ERR-2** (§12.2, closing paragraph) A namespace document that sets a limit marked deployment only is `422` (`invalid`). In `limits`, sizes are integers in bytes and counts are integers. `rulesPerNamespace` and `rulesPerGrant` count every rule form, including those nested in `all`, `any`, `not`, `if` and `then`. Durations are ISO 8601 durations, and rates are `{ "rate": <per second>, "burst": <bucket size> }`.

## Addendum A — Indexing service

### §A.1 Following the namespace

- [ ] **SVC-5** (A.1) The index service follows each namespace as in §10, with one checkpoint per namespace. It stores the checkpoint in the same transaction as the index writes. For each coalesced `head` entry, it fetches `/r/{ns}/{name}/rev/{id}`:
  - A document without `$schema` has any rows for the resource removed.
  - A schema document, whose `$schema` is a dialect URL (§6.1), is indexed against that dialect's meta-schema. `schema=` with the dialect URL lists schema documents. The revision paths of `$ref` keywords at schema positions, with the fragment dropped, count as references.
  - Any other document has its annotated fields and its references indexed with the schema revision it pins. A schema revision answering `403`, `404` or `410`, or one the service can't open for want of keys, leaves the document indexed as one without `$schema`.

  A `tombstone` removes the resource's rows. A `purge` also purges `idx:{ns}` from the service's own cache and drops kept results. A `config` entry on which §9 purges `ns:{ns}` purges `idx:{ns}` too.

### §A.2 What gets indexed: `x-index`

- [ ] **SVC-2** (A.2, `facet`, `sort`, References) `x-index` is `"text"`, `"facet"` or `"sort"`, or an array of them. Only strings, numbers and booleans are collected, by the walk that finds references and only through the keywords that mark a path (§A.4).
  - **`facet`:** arrays expand to one value per element. A value matches and counts as its string form: a string as itself, and a number or boolean as its canonical JSON (§3.1).
  - **`sort`:** it orders ascending, or descending with `sort=-{path}`. In either direction a document sorts by its least value at the path: numbers before strings before booleans, numbers by value, strings by UTF-8 bytes, and `false` before `true`. Documents without a value sort last in either direction.
  - **References** need no `x-index`. Each document is walked with the schema revision it pins, not the schema's head, and the references §6.5's walk finds are stored. Each target is stored as `{ ns, name }`, with the revision of a pinned reference and the entry of an `#id` one. Its path is stored too: the full instance pointer, array indices included.
  - `x-index` rows name the field, without indices. References in untyped documents aren't found, and text isn't scanned for paths.

### §A.4 Query API

- [ ] **SVC-6** (table, Bounded redirects, unfollowed and purged namespaces, plain document URL) `GET /{ns}?…` answers `302`, cached as a head pointer, to `/{ns}/at/{checkpoint ns_id}?…`, or for a private namespace to `/{ns}/g/{gs}/at/…`. A redirect that adds `/g/{gs}` is `private, no-store`.
  - `GET /{ns}/at/{ns_id}?…` answers `200` with `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", … }] }`. It is cached as immutable and tagged `idx:{ns}`, plus `r:{ns}/{name}` for every hit.
  - For an `ns_id` the service no longer keeps results for, it answers `302` to the current checkpoint, cached as a head pointer.
  - Kept results are keyed by what the reader reads whole too, and those computed before reads narrowed are dropped.
  - A query of a namespace the service doesn't follow, or of a sealed or end-to-end one whose keys it lacks, is `404`. A query of a purged one is `410` (`purged`).
  - Until the service has a checkpoint for a namespace it follows, a query of it is answered, once the reader's grant verifies, `503`, `no-store`, with `code: "behind"` and `Retry-After`.
  - Hits carry the plain document URL `/r/{ns}/{name}/rev/{id}`, which the search service never serves.
- [ ] **SVC-7** (`schema`, `ref`, `refs`, order and paging, Branches) `schema` filters by an exact `$schema` reference, or by a schema's resource path `/r/{ns}/{name}` to match all its revisions. `ref` finds the documents of `{ns}` that reference a resource, combined with the other filters:
  - `?ref=/r/{ns2}/{name}` matches references to it in any form: live, pinned or to an entry.
  - `?ref=/r/{ns2}/{name}/rev/{id}` matches only those pinned to that revision.
  - `?ref=/r/{ns2}/{name}%23{entry}` matches only those naming that entry, pinned or not.
  - `?ref=/r/{ns2}/{name}/rev/{id}%23{entry}` matches only those naming that entry and pinned to that revision.

  Each hit of a `ref` query carries `refs: [{ "path", "ref" }]`, the locations and the strings that matched, as written. Hits of other queries don't. A document that references itself is a hit of its own query, with `"self": true`.

  Hits come in `sort` order where it is given. Otherwise, for a query with `q`, they come by descending `score`, and otherwise by resource name. Ties go by resource name. Every query pages as `/_refs` does, with `after` a bare resource name, or, for a query with `q` or `sort`, the opaque value its `next` gives.

  In a branch's preview index, `ref` matches targets as written, naming the base, and hits are the branch's versions of the referrers.
- [ ] **SVC-8** (Across namespaces, `gs`, `min`) `GET /_refs?to=<reference>`, with `to` in any `ref` form, redirects to `/_refs/g/{gs}/at/{at}?to=…`. Here `at` is the combined checkpoint (§B.5) over only the followed namespaces the reader may see, and the path always has `/g/{gs}`.
  - `gs` is computed, and its URLs served, as in §B.11.5, over these markers:
    - `reads:{ns}` for each followed namespace that isn't public and where the reader's grant would be issued a namespace-wide edge grant (§C.5.2);
    - `reads:{ns}:scope:{digest}` for one where the grant allows `read` otherwise. `digest` covers the rules that limit it there (those of its blocks, its key's scope and each effective role that lists `read`) and the `/principal` values they refer to.
  - A namespace where those rules refer to `/now` counts as unreadable.
  - Readers with no marker, and requests with neither a grant nor a cookie, share the empty set's `gs`.
  - It takes `?min={ns}:{ns_id}`, repeatable. A `min` for a namespace the reader can't see, or that the service doesn't follow, is `400`, purged ones excepted (§A.5).
- [ ] **SVC-9** (Answers, Coverage, tags) `/_refs` answers are `{ "at", "namespaces": { ns: ns_id, … }, "hits": [ … ], "next"? }`, with `namespaces` listing what `at` covers.
  - Hits carry `ns` beside the fields of a `ref` hit. They are filtered per item by those rules as catalog listings are (§B.11.5), and come in byte order of `ns`, then resource name.
  - A page holds at most `limit` hits, and a `limit` above the service's maximum is `400`. The hits are strictly after `after`, which is given as `{ns}/{name}` and compared as the pair (`ns`, name), split at its first `/`. `next` is the following page's `after`, and is absent on the last page.
  - Hits from sealed and end-to-end namespaces are sealed per entry (§E.2.6), never as a whole response.
  - The answer includes branch previews. It leaves out namespaces the service hasn't reached yet, purged ones, and sealed or end-to-end ones whose keys it lacks. A `min` naming one of those, purged ones excepted, is `400`.
  - Only a reader who may see none of the namespaces gets `401` or `403`. If the service can't read the namespace document of one the grant names, the answer is `502`. Any other namespace whose document it can't read is left out.
  - Answers are tagged `idx:{ns}` for every namespace in `at`, and `r:{ns}/{name}` per hit.
- [ ] **SVC-10** (Fields in hits) Hits carry their facet and `sort` values, each as `"<path>": [values]`, a list even for one value. A path marked both `facet` and `sort` shows its facet values.
  - `fields=/a,/b` also returns those indexed fields, `text` ones included.
  - `counts=/a,/b` adds `counts`, `{ "<path>": { "<value>": <hits> } }`, over every hit, not only the page.
  - A `fields` path that no schema indexed in `{ns}` for a document the reader may see marks with `x-index` is `400`. So is a `facet[…]` or `counts` path that none of those schemas marks `facet`, and a `sort` path that none of them marks `sort`.
  - A schema marks a path when an `x-index` is reachable from its root along that path, whatever the data. It is reached through `$ref`, `$dynamicRef`, `properties`, `patternProperties`, `additionalProperties`, `dependentSchemas`, `items`, `prefixItems` and `contains`, and every branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`. It is never reached through `not`, `propertyNames` or `unevaluated*`. Array items count at their array's path.
  - A marked path that a hit has no values at is left out of that hit.
- [ ] **SVC-11** (Private namespaces, Sealed and end-to-end namespaces) Results over a private namespace are served at `/{ns}/g/{gs}/at/{ns_id}?…`, with `gs` and its URLs as for `/_refs`. Hits are filtered as there, over `{ns}` alone, and each `score` is computed only from documents the reader may see. A reader with no marker for `{ns}` gets `401` or `403`. Results over sealed and end-to-end namespaces are sealed as in §E.2.6.

### §A.5 Consistency

- [ ] **SVC-1** (A.5, Read-your-writes, `min` always redirects) Every response states `at`, the `ns_id` it reflects.
  - `?min={ns_id}`, once, on a query of one namespace, or `?min={ns}:{ns_id}`, repeatable, for a service that follows several namespaces, waits (bounded) until the checkpoint is at or past `min`. Otherwise it answers `503`, `no-store`, with `code: "behind"` and `Retry-After`.
  - A URL with `min` is answered with a `302` that drops it: to the current checkpoint, or, on an `…/at/{at}/…` URL whose `at` already includes every `min`, to the same URL without it.
  - A service that can't tell whether `at` includes them redirects to the current checkpoint, in one hop. That is the case when it no longer keeps that `at`'s per-namespace checkpoints, or when `min` names a namespace that the URL's `at` doesn't cover but the current checkpoint does, and that the reader may see.
  - A `min` naming any other namespace is `400`, and the body's `min` lists the ones refused.
  - On `/_refs` and tree listings, a `min` naming a purged namespace redirects to the current checkpoint without a read check.
  - A `200` is never served at a URL with `min`.
- [ ] **SVC-12** (Read-your-writes, `min` always redirects) A client takes `min` from `X-Namespace-Revision` on its own write. A tool keeps each `min` from its own writes until a listing that carried it has been answered `200` after its redirect, for ten minutes at most, and drops those a `400` lists.
- [ ] **SVC-13** (Canonical URLs) A service's redirects give the query in one form: parameters sorted by name, then value, comparing their decoded UTF-8 bytes, and every byte other than ALPHA, DIGIT, `-`, `.`, `_` and `~` percent-encoded in uppercase hex. Index and tree services answer `200` only at that form, and redirect other forms to it. Repeatable parameters, such as `min`, are sets, sorted like the rest. A parameter the service doesn't define, or a non-repeatable one given twice, is `400`. A list whose order matters, such as `fields=/name,/title`, is one value.

### §A.6 Operations

- [ ] **SVC-14** (Access control) The index service MUST enforce the namespace's read permissions by verifying the reader's grant locally (§C.6).

## Addendum B — Organising documents

### §B.2 Catalog namespaces: folders and placements

- [ ] **SVC-15** (table, `parents`, `order`) A node whose name has no dot is a folder. A node named `{ns}.{name}` is the placement of the item `/r/{ns}/{name}`: its name splits at the first dot, and there is no `item` field. An item can be placed only where `{ns}.{name}` has at most 128 characters. Each `parents` entry is a live link to a folder of the same catalog, with its own optional `order`. No `parents`, or `[]`, makes a root. A folder's children sort by the `order` on their edge to it, compared by UTF-8 bytes. Unordered siblings sort after ordered ones, and siblings with equal or no `order` sort by node name.

### §B.3 Links

- [ ] **SVC-16** (B.3, Referential integrity) A link is a live (`/r/{ns}/{name}`) or pinned (`/r/{ns}/{name}/rev/{id}`) path on this service, with names valid under §3.6. Referential integrity isn't enforced. These are dangling: a placement whose item is deleted, and a `parents` entry naming a missing folder or anything but a live link to a folder of this catalog. The tree service drops a dangling one from traversals and reports it.

### §B.4 Manifests (pinned snapshots)

- [ ] **SVC-17** (B.4, Creation, Shared items) A manifest's links are all pinned. The tree service generates a manifest for a subtree as of a catalog `ns_id`. In a DAG, an item reached along several paths has one entry per path, each with that path and the order of its last edge.

### §B.5 Tree service

- [ ] **SVC-3** (B.5) For each coalesced `head` of a node, the tree service replaces that node's outgoing edges from its `parents`. `tombstone` and `purge` remove them. It also follows the content namespaces the catalog trusts. It marks dangling a placement whose item is gone, or is in a namespace the catalog doesn't trust.
- [ ] **SVC-18** (Query API) The query API is served on the tree service's own origin, or under a root of its own.
  - Listings answer `302`, cached as a head pointer, to `/{catalog}/at/{at}/…` or `/{catalog}/g/{gs}/at/{at}/…`, as §B.11.5 says.
  - `at` is the combined checkpoint, `text(trunc160(sha256(canonical({ ns: ns_id, … }))))`, over the catalog and the content namespaces the service follows.
  - A listing at an `at` uses the immutable class. It is tagged `r:{ns}/{name}` for every item it shows, and `ns:{ns}` for every namespace in the checkpoint. A service whose cache the origin's purges don't reach purges these tags itself.
  - The service answers `200` at an `at` only if that `at` is current or that exact result was stored, and `302` to the current one otherwise.
  - `?min={ns}:{ns_id}`, repeatable, gives read-your-writes (§A.5).
  - A service that follows several catalogs keeps a combined checkpoint per catalog. It judges `?min` against the checkpoint of the catalog in the URL, even for a content namespace that other catalogs follow too. **[vectors I.8]**
- [ ] **SVC-19** (table, Parameters) Parameters name a node by its node name, and an item as `/r/{ns}/{name}`. A node or item not in this catalog is `404`, and so is one hidden from the reader. The requests return:
  - `children?of=`: the direct children, folders and items, ordered and paginated as `/_refs` is, with an opaque `next` and with `total`, the number of visible children. Each node carries `born`, the `created` of its first revision, sealed per entry in a sealed or end-to-end catalog.
  - `lookup?path=`: the node that a path of titles, joined with `/`, names. The path starts from the folder `root` of a file tree, or, where `root` is hidden from the reader, from the visible roots of its subject set. It is filtered like `children`. Titles compare after NFC and Unicode simple case folding, and a numbered or escaped display name doesn't resolve. Where siblings share a title, it answers the earliest `born`, then the node name. A path that doesn't resolve to a visible node is `404`. In a catalog without `files`, or a sealed or end-to-end one, `lookup` is `404` with `code: "not_offered"`.
  - `ancestors?of=`: every path to a root.
  - `subtree?of=&depth=`: a nested listing.
  - `roots`: the nodes without parents.
  - `orphans`: the cyclic nodes, and the nodes with parents that are all gone, dangling or cyclic.
  - `problems`: the cycles, dangling items and dangling parents.
  - `where?item=`: the item's placement and paths in this catalog.
  - `manifest?of=`: a manifest for the subtree, pinned as of the checkpoint.
- [ ] **SVC-20** (Fresh listings after a write) A client relisting right after its own write adds `?min` (§A.5), not `no-store`.
- [ ] **SVC-21** (Behind) Until the service has caught up with the catalog and every namespace it follows, it answers listings `503` once the reader's grant verifies, with `no-store`, `code: "behind"` and `Retry-After`. It names the namespace it waits for, as `ns`, only to a reader with unrestricted `read` (§2.1) of the catalog. It never serves a listing whose placements dangle for want of data.
  - Caught up means reaching the head it read when catch-up started (§10), not a first checkpoint. A restart on the same store doesn't wait again.
  - It doesn't wait for a namespace it can't follow as configured: one that is purged, has refused it or is unknown, or one that is sealed or end-to-end without keys it can have. That namespace's placements dangle.
  - It does wait after a fetch that failed for the moment: a transport error, `5xx` or `429`.
- [ ] **SVC-22** (Items in listings) Items in listings carry their content URL and current head, and, in a file tree, `file` (§H.3). Where the catalog's `catalog` object sets `"title"` to a JSON Pointer, listings copy the string at that pointer in each item's head as `title`, for items in namespaces that aren't sealed or end-to-end. A placement's own `title` wins over the item's.
- [ ] **SVC-23** (Cycles) Every node on a cycle is cyclic: a strongly connected set of more than one node, or a node that is its own parent. A cyclic node and all its edges, edges to parents off the cycle included, are left out of traversals, listings and access. `/problems` lists each cycle as its set of nodes, and `/orphans` lists them too. Walks are bounded at depth 64, and deeper paths are flagged.
- [ ] **SVC-24** (Shared nodes in DAGs, `mode`) `subtree`, `ancestors` and `where` show a node with several parents under each of them. The service MUST bound a response by the depth limit and a per-response node limit, and report when a response was cut. A `tree` catalog whose rules allow several parents is served as a DAG.
- [ ] **SVC-25** (Previews of a release) A tree service previewing a release follows the branches its release document lists in place of their bases, with `checkpoints` holding those branches. It resolves a placement to the release's branch of its item's namespace, if the release lists one. It shows a viewer only branches the viewer can read, serves previews only, and issues no grants. A long-running preview service follows the release document's own log, so a new revision of it takes effect without a restart.

### §B.7 Lifecycle

- [ ] **SVC-26** (Create and place, Deleting content, Deleting a placement, Deleting a folder, Restoring)
  - A placement naming an item that doesn't exist yet dangles until it does.
  - A deleted item's placements dangle, drop out of listings and access immediately, and are reported for cleanup.
  - Deleting a placement removes the item from this catalog only.
  - Deleting a folder doesn't cascade: its children appear under `/orphans`.
  - Restoring a folder or placement re-attaches everything that pointed at it.

### §B.9 Self-placing documents (optional shortcut)

- [ ] **SVC-27** (B.9, Not accepted by default) A tree service configured to accept `$parents` for a trusted namespace treats a content document's `$parents` as an implicit placement. An explicit placement for the same item wins, whether it is live, deleted or purged. The catalog derives no access from self-placements unless the content namespace's rules protect `/$parents` as strictly as the catalog protects placements. Where it does, a Place of a self-placed item also needs `move` on each folder of its `$parents`, and no widening (§B.11.4).

### §B.10 Access control

- [ ] **SVC-28** (Services that list content) A service that lists content MUST enforce read permissions for every node and item it lists, titles and structure included.

### §B.11.1 `$access` and roles

- [ ] **SVC-29** (`$access`, role meaning, tree powers, Placements) The catalog service reads `$access` from folders and placements. `$access` maps subjects (`group:…` or `user:…`) to role names, applied to the items below the folder. A role's verbs and rules come from the content namespace's `roles`, and a namespace that doesn't define a role grants nothing through it. The catalog namespace's `roles` define the tree powers: `move`, moving nodes out of or into a folder, and `place`, placing new items directly into a folder.

### §B.11.2 Effective access

- [ ] **SVC-30** (Subjects, Walk up, Where a path stops)
  - A caller's subject set is its `sub`, if that starts with `user:`, plus `group:{g}` for each of its groups.
  - A subject's roles at a node are the union, over every path from the node up to a root, of the role names `$access` gives that subject along the path, the node's own included. An item's roles are those at its placement, and a caller's are the union over its subjects.
  - A path stops collecting after a node with `inherit: false`. A path that reaches a tombstoned, purged, dangling or cyclic node ends there, and that node contributes nothing.
  - A dangling placement grants nothing. The exceptions are for an item in a namespace the catalog trusts: `create` for an item that has never existed, and `restore` for an item that is tombstoned and not purged. `restore` goes to those of the roles it had when it was deleted that it would have now if live.
- [ ] **SVC-31** (Through the key) In a content namespace, a role counts for a verb when the namespace defines it with that verb and the catalog's key there may grant it to the caller. That holds when:
  - the key's `can` lists the verb;
  - its `roles` scope allows the role;
  - its `sub` scope, if it has one, matches the caller's `sub`;
  - the role was collected through the caller's `sub`, or through a group its `groups` scope allows.
- [ ] **SVC-32** (Across catalogs, Allow-only) Each catalog the item's namespace trusts issues grants from its own computation, and an item's total access is their union. There are no denies.
- [ ] **SVC-33** (Tree powers) `move` and `place` apply only at the folder where a role granting them is assigned. Where the folder's `$access` sets `"inheritPowers": true`, roles collected on the walk up from it grant them there too. Powers count only at a live folder that isn't cyclic, and only through subjects the catalog's key in the catalog may assert. At a folder without `$access` but with parents, a subject's role has a power when that subject's role has it at every one of them. Each `parents` entry counts, and a tombstoned, purged, dangling or cyclic parent gives none.

### §B.11.4 Issuing grants

- [ ] **SVC-4** (Resolve, Sign a root grant, Read-your-writes, `checkpoint`)
  - For an item, `POST /grants` resolves the caller's subjects, looks up its roles at the item at the current checkpoint, and keeps only those that count there for a wanted verb (§B.11.2).
  - It signs a root grant for exactly that resource, carrying those role names, with an absolute `exp` within `maxTtl`. It doesn't evaluate the roles' rules.
  - `POST /grants` and `POST /read-grants` accept `?min={ns}:{ns_id}`, repeatable. They decide at a checkpoint at or past every `min`, or answer `503` as listings do.
  - Answers carry `checkpoint`, `{ ns: ns_id, … }`: the `ns_id`s, as of the decision, of every namespace whose state the decision read. Those are the catalog, each named item's namespace, and, for decisions that read roles or `includes` elsewhere, those content namespaces too.
  - `checkpoint` goes beside each grant, never inside it, and beside refusals decided at it (`403`, `404`, `409`, `410`). A refusal from state it doesn't pin has none. The grants' own `at` is the catalog's `ns_id` alone.
  - `POST /grants` answers `200` with `{ "grant", "checkpoint", "parents"?, "head"? }`. `parents` comes with a Move grant that pins them, and `head`, the node's head revision as decided, with a Move or an Unplace or delete.
  - `POST /read-grants` answers `200` with `{ "items": [{ "item", "grant"?, "public"?, "keys"?, "keysWithheld"?, "status"?, "code"? }], "checkpoint" }`: one entry per item in request order, with `status` and `code` for an item refused or undecided.
- [ ] **SVC-34** (Sign a root grant) Item requests other than Place and Create are refused as Restore's are, in order:
  1. in a purged namespace, `410`;
  2. `404`;
  3. for a purged item, `403` without a role that counts for `read` at its placement, computed as for a live item, and `410` otherwise;
  4. then `403` when no role is kept.
- [ ] **SVC-35** (organising requests) Organising requests yield grants for the catalog namespace, without `roles`, each with the verb its write needs unless a request gives another: `create` for Place and Create a folder, `append` for Move, and `delete` for Unplace or delete a folder. Each grant fixes `/resource` to the node name and `/doc/parents` to exactly the requested target set, compared by `href`: each entry's `order` is the writer's (§B.2).
  - Unless a request gives its own answers, they are, in order:
    1. `400` for a malformed request;
    2. `404` for a `node`, a new folder's excepted, that isn't an untombstoned node of this catalog; for a `to` entry that isn't a live folder of it; or, to a caller not in `catalog-admins`, for either one hidden from it, a new folder's name excepted;
    3. `403` for a requirement that fails, or an `item` in a namespace the catalog doesn't trust;
    4. then `409`.
  - In an end-to-end catalog the service issues no organising grants (`404`, `not_offered`).
  - A caller in `catalog-admins` needs no tree power. Any other caller also needs a non-empty `to` in a request that takes one. It can't move, unplace or delete a node without parents, or one with a parent hidden from it.
- [ ] **SVC-36** (Place, Unplace or delete a folder, Create a folder)
  - Place (`{ "item", "want": ["place"], "to" }`) requires that the caller is in the content namespace's `catalogs.{catalog}.place` list, and that it has a role with `place` on every folder in `to`.
  - If an earlier placement of the item was deleted, the grant carries only `restore`, and restores the placement with a root replace, which must not widen. If the placement is live again when that grant is used, the write is an append, refused at step 2.
  - A Place of an item whose placement is live is `409`, and one whose placement was purged is `410`, both after the `400`, `404` and `403` answers.
  - Unplace or delete (`want: ["delete"]` on a node) requires a role with `move` on every current parent, and its grant fixes `/doc/parents` to exactly those parents, compared by `href`: each entry's `order` is the writer's (§B.2).
  - Folders are restored only by `catalog-admins`, under grants of their own: the service answers a request naming a tombstoned folder `404`.
  - Create a folder (`{ "node", "want": ["create"], "to" }`) needs `node` to be a folder name (`400` otherwise) that no node has or had, and that no `parents` entry or accepted `$parents` names, hidden ones included (`409` otherwise). It also needs a role with `move` on every folder in `to`.
- [ ] **SVC-37** (Move, No widening)
  - Move (`{ "node", "want": ["move"], "to" }`) requires a role with `move` on every current parent the node leaves and on every folder in `to`, and no widening. A `to` entry that is the node or below it is `403`.
  - A Move grant may also change the node's other members, `$access` excepted. A rename is a move to the node's current parents.
  - Unless the caller is in `catalog-admins`, a Move grant also requires its patch set to begin with a `test` of `/parents` against the node's parents as decided, which the answer gives as `parents`.
  - No widening: unless the caller is in `catalog-admins`, for every subject, the roles of every node after the write are a subset of those before.
  - For a move, both sides are roles at a node, computed as for live items, even for an item that is deleted or not yet created.
  - For re-placing a placement or restoring an item, the item's roles from its placement after the write are compared with its frozen rows.
  - A role counts as present before if it, or a role that includes it, was. `includes` is transitive, is read from the item's own content namespace, and is trusted as declared. A folder's roles compare by name.
- [ ] **SVC-38** (Create) Create (`{ "item", "want": ["create"] }`) resolves the caller's roles at the item's placement, keeps those that count for `create`, and signs a grant fixed to that name with `can: ["create"]`. The answers, in order:
  1. in a purged namespace, `410`;
  2. `409` for a name that exists or existed in the content namespace;
  3. then `403` for a caller whose item has no placement in this catalog, or who has no role kept.
- [ ] **SVC-39** (Restore) Restore (`{ "item", "want": ["restore"] }`) resolves the caller's roles at the item from the `effective` rows kept when the service saw the item's tombstone. It keeps those that count for `restore` both there and at the item's placement now, computed as for a live item. It signs a grant fixed to that name with `can: ["restore"]`.
  - If the item is live when the grant is used, the write is an append, refused at step 2.
  - The item must still have a placement in this catalog. The frozen rows stay those of its deletion, even if it was unplaced and placed again.
  - The answers, in order:
    1. in a purged namespace every name is `410`, for restores and creates alike;
    2. a name that never existed is `404`;
    3. a caller without a role that counts for `read` on the item gets `403`. The role must count both at the item's placement now, computed as for a live item, and, if the item is deleted, in its frozen rows;
    4. then a purged item is `410`, and a live item `409`;
    5. then `403` for a caller without a role kept, one whose item has no placement, or one whose restore would widen.

### §B.11.5 Reads and listings

- [ ] **SVC-40** (Listing URLs carry the subject set)
  - A listing whose combined checkpoint has only public namespaces is served unfiltered at `/{catalog}/at/{at}/…`, while they stay public. Any other listing is served at `/{catalog}/g/{gs}/at/{at}/…`.
  - `gs` is `all`, or `text(trunc160(sha256(canonical(subjects))))`. `subjects` is an array without duplicates, in UTF-8 byte order, of the caller's `group:` entries. It adds the caller's `sub` only if the catalog has direct entries for that user, or the catalog's key in a content namespace it trusts has a `sub` scope.
  - A listing URL without `at` is under the prefix too, with the `gs` the exchange's `prefixes` gives. The grant in `Authorization` redirects one without `/g/{gs}` to its `…/g/{gs}/at/{at}/…` URL, `private, no-store`.
  - A grant in `Authorization` reads only at its own `gs`, or at `all` where it qualifies, and is `403` elsewhere. A request that needs `/g/{gs}` and carries neither a grant nor a cookie the service verifies is `401`. A tree service without §B.11 serves only `all` (`403` otherwise).
  - The edge admits a request only with an edge grant bound to that exact `gs`. That is a cookie the service mints with a key of its own for the prefix `/{catalog}/g/{gs}`, after resolving the caller's subjects. It mints it at an exchange endpoint of its own that follows §C.5's issuance rules, `application/json`, `415` and credentialed CORS included.
  - The service applies §9 to its own origin, and keeps which subjects each `gs` stands for. It applies `exchangeRate` (§6.6) to its exchanges, with buckets shared across its instances.
  - A `gs` cookie other than `all` authorises listings of that subject set only. `problems`, `orphans` and manifests are `403` under it. Listings are cached per (listing, subject set, `at`). **[vectors I.8]**
- [ ] **SVC-41** (Listings are filtered by their subject set)
  - A node is visible to a subject set when the walk up from it collects a role that counts for `read` (§B.11.2). The caller's `sub` is taken to be that of the set's `user:` subject, and a set without one fails a `sub` scope.
  - The role's own rules and the key's scope `rules` must pass as a read would evaluate them, with `/principal` holding only the groups the key may assert and, as `roles`, that role.
  - For an item, the role is one of its own content namespace, with `/resource` the item's name. For a folder, it is a role of some trusted content namespace whose rules don't refer to `/resource`, through a key whose scope `rules` refer only to `/principal/groups` and `/principal/roles`.
  - A rule that refers to `/now`, or to anything in `/principal` but `groups` and `roles`, makes the role not count.
  - The roles, their definitions and the keys are those as of the content namespaces' `ns_id`s in the listing's combined checkpoint.
  - `children`, `subtree`, `roots`, `ancestors` and `where` show visible nodes only, and only paths through visible folders, with nothing about a hidden node, not even a count. A visible node whose parents are all hidden is a root for that subject set: `roots` lists it, and paths end at it.
  - A request that names a hidden node is answered as one naming a node not in this catalog (`404`). That covers listings, a catalog node in `/read-grants`, and, from a caller not in `catalog-admins`, organising requests, where a dangling placement is judged as if its item were live. The exceptions are a new folder's name and a Place of an item whose placement is live, which are `409`.
  - Response limits, cut markers and pagination apply to the visible nodes. `/read-grants` uses the same test for catalog nodes and their keys.
- [ ] **SVC-42** (unfiltered listings, `g/all`)
  - `problems`, `orphans` and `manifest` are unfiltered, and need unrestricted `read` (§2.1) on the catalog and on the content namespaces they cover; `403` otherwise. For a manifest, those are the namespaces of the items it pins. For `problems` and `orphans`, they are every one in the combined checkpoint. A public namespace counts as read unrestricted.
  - The service issues an edge grant bound to `all` only after checking every namespace in its combined checkpoint that isn't public: for each, the reader's grants would have to be issued a namespace-wide edge grant (`/r/{ns}` and `/ns/{ns}`, §C.5.2). The `all` grant expires with the earliest of those grants.
  - Under such a cookie, the service answers `403` at an `at` that includes a namespace that wasn't in its combined checkpoint at issuance.
  - A service that mints with the default format takes the issue time as `exp` less 15 minutes, unless it recorded the issue.
  - Without edge grants, `g/all` listings are served `private`, with a `max-age` no longer than such a cookie's lifetime.
- [ ] **SVC-43** (Listings never embed signed URLs, Every item at once) Listings never embed signed URLs. `POST /read-grants { "items": [...] }` answers `no-store`, with short-lived grants carrying the roles that make each item visible, fixed to exactly `/r/{ns}/{name}` and `/r/{ns}/{name}/…`.
  - An item in a public namespace that isn't sealed comes back as `"public": true` instead of a grant.
  - A catalog node, or an item in a public sealed namespace, comes back with its key alone. A sealed item in a private namespace comes back with a grant and its key.
  - An item is refused as `POST /grants` refuses an item request, only the roles that make it visible counting, so a hidden item is answered as one without a placement (`403`), as Restore's read check answers it. A catalog node is `400` in a catalog that is neither sealed nor end-to-end, and otherwise `404` if hidden.
  - An item answered with a `4xx` status is refused, and one with a `5xx` status is undecided.
  - Where a service caps the items of one request, a request above the cap is `400`.
- [ ] **SVC-44** (Keys, Which keys, Checked like grants, Which epochs, `keysWithheld`)
  - For sealed items, and nodes of sealed or end-to-end catalogs, `/read-grants` also returns per-resource keys `K_r` (§E.2.1), wrapped to the caller's public key in the §E.2.3 format. It returns them only for items that pass the same role check as the grants, items in public sealed namespaces included.
  - A content item in a sealed (E2) namespace gets its own `K_r`, and one in an E3 namespace gets none. When the catalog is sealed or E3, the item's placement node also gets its `K_r`. A catalog node named in `items` and visible to the caller gets its `K_r` and no grant.
  - Keys cover the current epoch and the `encryption.historyEpochs` before it, or every epoch the service holds if the namespace sets no cap.
  - A caller whose grant carries no public key gets its grants, with `"keysWithheld"` and the reason in place of keys.

### §B.11.7 Catalog storage

- [ ] **SVC-45** (Maintenance, Role definitions, Deleted items, Consistency)
  - A change to a node's `$access` or `parents`, a tombstone, or an item's deletion or restore recomputes `effective` for the affected subtree. A change to `/roles` in a content namespace recomputes the listing visibility it affects.
  - A deleted item keeps its rows in `effective` as they were when the tombstone was seen, marked tombstoned and no longer recomputed. A deleted placement's rows are kept apart the same way, until it is placed again. Restores and re-placings are checked against these rows for no widening.
  - The checkpoints are stored in the same transaction as `effective`. Their catalog `ns_id` is the `at` of every grant issued from it.

### §B.11.8 Staleness and revocation

- [ ] **SVC-46** (Overtaken decisions) A Move grant's `exp` is at most the catalog's `maxLag` (§7.4) after its decision.

## Addendum C — Capabilities and access

### §C.1 Grants

- [ ] **AUTH-1** (Fields, Narrowing only restricts, Format, Verification) A grant is presented as `Authorization: Bearer <grant>`. It consists of a root block, signed by a key listed in the namespace document, and zero or more narrowing blocks, each chained to the previous one's signature. Grants are Biscuit v3 tokens (§C.8). Verifying one needs only published keys: the namespace's, its local bases' and the deployment's operator keys.
  - `sub`, `groups` and `attrs` are taken from the root block only. `signers` and `enc` appear in the root block only, and an `enc` of another form makes the grant invalid (`401`). `via` appears in narrowing blocks only.
  - `roles` gives the grant its effective roles (§2.1).
  - `can` lists verbs among `read`, `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export` and `prune`. `*` is for keys only; in a block it makes the grant invalid (`401`). A root block without `can` MUST list `roles` (`401`), and its verbs then come only from the roles.
  - `nbf` and `exp` are absolute RFC 3339 times, and a block is valid from `nbf` (optional) until `exp`. `at` is an `ns_id` of the namespace itself, or `{ "ns", "id" }` for another namespace, and is optional unless the key has `requireAt`.
  - A narrowing block may reduce `ns`, `can` and `roles`, set a later `nbf` or an earlier `exp`, add `rules` and add a `via`. It carries no other member, and a member it leaves out restricts nothing.
  - A root block MUST carry `kid`, `sub`, `ns` and `exp`, and only the members listed for it. A block that breaks these rules makes the grant invalid (`401`). Values that don't narrow, other than `"*"`, restrict nothing more.
  - The effective principal is always the root `sub`, `groups` and `attrs`, with `via` listing the delegatees in order.

### §C.1.1 Roles

- [ ] **AUTH-3** (Roles, Expanded at the gate, Combination, Issuers are bounded) Grants carry role names, never their contents. Names are expanded at the gate, against the configuration in force when the request is checked, so a changed definition changes at once what every outstanding grant naming it can do. Unknown names grant nothing, and `roles: []` grants no verb. Roles are alternatives, and everything else is conjunctive (§C.2 items 2 and 4). Issuers are bounded by the key scope's `roles` (§C.4).

### §C.1.2 Attributes and time

- [ ] **AUTH-10** (table, Principal attributes) Rules find these attributes:
  - the principal's at `/principal/attrs/…`, `/principal/groups` and `/principal/roles`, as the grant's issuer sets them, with the root block's `attrs` bounded by the key scope's `attrs`;
  - the document's at `/doc/…`;
  - the request's at `/action`, `/resource` and `/writes`, set by the server;
  - the environment's at `/now`, from the server's clock.

### §C.2 Checking requests

- [ ] **AUTH-2** (intro, Verify the chain) Grants are checked:
  - at step 1 of §6.2 (items 1–3 and the first part of item 4);
  - at step 2 (item 2's retry check and settling);
  - at step 6 (the `*`-key guard, then item 4);
  - and on every read (item 5).

  The `ns` check of §7 comes first, without verifying anything, and answers `403` before any `401` below; a token whose blocks can't be parsed at all is `401`. Reads of a public namespace ignore the grant, except as §7 says. The server then checks:
  - the root signature, by a key in the configuration in force;
  - every block's signature;
  - `nbf` ≤ now < `exp` for every block;
  - revocation (§C.4);
  - the key's scope, including `can`, `sub`, `maxTtl`, `groups`, `roles`, `attrs`, `requireAt`/`maxLag` and `readScope`.

  A grant that can allow `read`, from a key with `readScope: "resource"`, that doesn't fix `/resource` (§2.1) fails the scope. That is `403` on every request that doesn't ignore the grant, writes included, and `404` for a read of a resource in a private namespace. Failures are `401` when there is no usable grant (missing, malformed, badly signed, revoked, expired, or not yet valid), and `403` when a valid grant doesn't allow the request.
- [ ] **AUTH-11** (Check the verbs, Several verbs, Settling, Later steps, Unrestricted `read`, Operator grants) A verb is allowed when `ns` and `can`, intersected over all blocks, and the key's `can` for a namespace key allow it, and, if the grant carries roles, an effective role lists it. A request checks the verb of its action, with these exceptions:
  - **Several verbs.** A resource `PATCH` under `If-Match`, and a batch item whose first step is a patch set under `ifMatch`, check `append` and `restore`. Either one without a usable precondition, and a blob upload, check `create`, `append` and `restore`.
  - **Candidate verbs** are those for which this check and the step-1 rules of item 4 pass, with `/action` set to the verb and only roles that list it counting. The write passes if it has one, and a `PATCH` or item without a usable precondition then gets `428` at step 2.5 of §6.2.
  - **Settling.** Step 2.2 settles the verb of a `PATCH` under `If-Match`, or of such a batch item, and refuses one that isn't a candidate. An idempotent retry of one answers `200` only if the recorded entry's verb is a candidate: a restore when its parent is a tombstone, an append otherwise. Any other retry has its one verb.
  - **Later steps** of a batch item are checked with the verb the request gives them: a patch set whose previous step is a `"delete"` is a restore, and any other is an append.
  - **Unrestricted `read`.** Branching and remote registration also check `read` on the namespace they name as base, which the grant must read unrestricted (§2.1), public or not. Its key-scope and block rules that refer only to `/action`, `/principal` or `/now` must pass with `/action` set to `read`; the rest are left to step 6, against the write's own envelope. A role that counts for `read` must pass all its rules against a `read` envelope.
  - **Operator grants** check `config` for a namespace's creation and for a remote branch's, including the schema histories it mirrors, and `purge` or `purge-ns` for a forced purge.
- [ ] **AUTH-12** (Build the principal, Rules, Reads) The principal is `{ id: root sub, groups: root groups, roles: effective roles, attrs: root attrs, via: [...], grant: grant id }`.
  - At step 1, the key-scope, block and role rules that refer only to `/action`, `/resource`, `/principal` or `/now` are evaluated, with `/action` set to the verb checked.
  - At step 6, all of them are evaluated, with the write's verb as settled where it had candidates, and then the namespace rules.
  - If the grant carries roles, the role rules evaluated must pass for at least one effective role that lists the verb.
  - A failing grant, key or role rule is `403`.
  - Reads evaluate the key-scope, block and role rules against a `read` envelope (§6.4.1), with roles counted in the same way.
- [ ] **AUTH-13** (`*` keys) These need a grant chained to a key with `can: ["*"]`, or, for a namespace's creation, the operator grant that creates it:
  - a config write, a batch's `config` change included, that covers or overlaps one of the members §7.4 lists, or sets `read` to `public`;
  - a branch's `patches` that cover or overlap one of those members, which need a `*` key of the base;
  - the prunes §8.6 names.

  This guard runs first at step 6, after any namespace-document validation, and is `403` (`forbidden`) otherwise. Forcing a purge has its own guard, at step 1 (§6.1).

### §C.3 Attribution and signatures

- [ ] **AUTH-4** (Grant per revision, Stored grant form; §C.3.1 Reading grants) Each revision stores its grant's id, `trunc160(sha256(canonical(root block)))`. The server stores each grant in a non-bearer form that no longer verifies as a credential (§C.8).
  - `GET /ns/{ns}/grants/{gid}` answers `{ "id", "root", "stored" }`. `stored` is the non-bearer form of the first token recorded with that id: its authority block, a protobuf `SignedBlock` in base64url without padding. Its signature verifies under the key `root.kid` names, its one `grant_block` string equals `canonical(root)` byte for byte, and `id` is `text(trunc160(sha256(that string)))`.
  - It serves the grants recorded by namespace log entries of this namespace and, in a local branch, of its bases up to their `at`, recursively. Any other is `404`, and in a purged namespace it is `410`.
  - It needs unrestricted `read` on the namespace, and is immutable.
  - Sealed namespaces seal it as §E.2.2 says. A grant recorded only by a branch's base is sealed under the branch's current epoch.
  - End-to-end namespaces serve it in the clear, or sealed if it is from before a raise from `sealed`. They serve it with `Cache-Control: private` instead of the immutable class, and with `no-store` in `CDN-Cache-Control` and `Surrogate-Control`.

  **[vectors I.4]**
- [ ] **AUTH-5** (Optional author signatures; §C.3.1 Signer keys live in grants, Tombstones) An author signature is over `sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖ 0x0A ‖ bytes(parent) ‖ 0x0A ‖ canonical(patches))`.
  - `origin` is the deployment's canonical origin in RFC 6454 ASCII serialisation (`scheme://host[:port]`, lowercase, default port omitted), as published at `GET /`. A tombstone's signature uses the ASCII bytes `tombstone` in place of `canonical(patches)`.
  - It is sent as `Signature: <alg>:<kid>:<sig>`, stored alongside the revision, never inside its id, and served in logs.
  - A root block may list `signers: [{ "kid", "alg", "pub" }]`, with `alg: "Ed25519"` and `pub` the public key in base64url. `kid`s are unique within `signers` and contain no `:`. `pub` and `<sig>` are base64url without padding, 43 and 86 characters.
  - An entry that breaks these rules, or has any other member or `alg`, makes the grant invalid (`401`), and so do `signers` in a narrowing block.
  - Issuers MUST list a key only after the principal has proved possession of it, and MUST NOT list one `pub` for two subjects.

  **[vectors I.4]**

### §C.3.1 Signer keys and verification

- [ ] **AUTH-14** (At the gate, The parent, Retries) When a write carries a signature whose `kid` its grant's `signers` list, the server MUST verify it at step 2.3 of §6.2.
  - A bad signature, or one whose `alg` isn't that signer's, is `422` with `code: "signature"`. A signature with any other `kid` is stored unverified, and readers treat it as unattributed.
  - The parent in the input is the one the write's precondition names: its `If-Match` id, empty for a create, and in a batch the item's `ifMatch` (empty with `ifNoneMatch`) for its first step and the previous step's id for each later one. A write without a usable precondition isn't checked here, and gets `428` at step 2.5.
  - A `Signature` header or step member that isn't `<alg>:<kid>:<sig>` with an 86-character base64url `<sig>` is `400` (`bad_input`), as a request-shape error.
  - In a batch, each step object carries its own `signature`. The `Signature` header covers a single `PATCH` or `DELETE` of a resource, and is `400` (`bad_input`) on any other write.
  - An idempotent retry answers the entry as first recorded, whatever well-formed signature it carries or lacks, even after `required` was turned on.
  - At E3 the input covers the sealed patch set as sent.
- [ ] **AUTH-15** (Requiring signatures) A namespace document may set `"signatures": "required"`; the default is `"optional"`.
  - Every revision and tombstone written to such a namespace then needs a valid signature by a signer of its grant, or is `422 signature` at the same point of the gate.
  - A batch's items are judged under the configuration its config change produces. If that change fails, only a replay can still succeed, answered as first recorded.
  - Revisions written before it was turned on, and those a branch reads through from its base, aren't covered.
  - In merges, replays and imports (§F.3, §G.4.4), a step's `signature` is always the writer's own, and original signatures aren't re-sent.
  - While authentication is disabled (§1), every resource write to such a namespace fails.
- [ ] **AUTH-16** (chain, Verifiers) A verifier checks a signature against the keys in force when the revision was written, along one chain:
  1. the revision's `Signature`;
  2. the entry with that `kid` in the `signers` of the root block of the grant named by its grant reference;
  3. the key that signed that root block: either a key of the configuration the write was checked against, or a deployment operator key in force at the entry's `created` time. The configuration is the namespace document in force at its namespace log entry, after the config change of a batch that makes one, and in a branch it adds the keys its local bases had at the entry's `created`;
  4. the namespace log for a namespace key, or the operator key history for an operator key.

  In a branch, verifiers follow its local bases' namespace document histories too, from their logs or the key entries a bundle carries. Verifiers don't check `revoked`. A signature that fails, or whose chain can't be completed, is reported as such.

### §C.4 Keys, scopes and revocation

- [ ] **AUTH-6** (Keys, Key scope; §C.1.2 Principal attributes) The namespace document lists `keys`.
  - **Entries.** Each entry has a `kid`, unique within `keys`; `alg: "Ed25519"`; `pub`, the public key in base64url without padding (43 characters); and `can`. It may add the scope fields, with `maxTtl` and `maxLag` as ISO 8601 durations. An entry stored without `can` allows no verb.
  - Root blocks must be signed by one of the keys. Changing keys and scopes is a config write requiring a `*` key.
  - **Scope.** A key entry's scope restricts every grant it signs:
    - `can`: the verbs its grants may contain, every verb for `*`. A root block whose `can` lists any other verb fails the scope, and verbs from roles are bounded by it;
    - `maxTtl`: the longest remaining lifetime of the root block, `exp − max(now, nbf)`;
    - `sub`: a regular expression (§6.6) that the whole root `sub` must match;
    - `groups` and `roles`: `{ "allow": [...] }` or `{ "deny": [...] }` on the asserted groups and roles;
    - `attrs`: a JSON Schema the asserted `attrs` must validate against, held to the rules of a rule's `schema` (§6.4.2);
    - `rules`: conditions added to every grant;
    - `readScope: "resource"`: every grant it signs that can allow `read` must fix `/resource` (§2.1);
    - `rate`: a lower per-principal write rate for its grants, `{ "rate", "burst" }` as in `limits`. Their `ratePerPrincipal` bucket takes the smaller rate and the smaller burst of the two, and its `429` names `ratePerPrincipal`;
    - `maxLag`: a stricter `maxLag` for `at`.
  - **`requireAt`.**
    - With `true`, `at` must be an `ns_id` in the chain of the namespace the grant is checked in, also for a base's key in a branch. With a namespace name, it must be in that namespace's chain.
    - Either way, `at` must not have been superseded in that chain more than `maxLag` before the grant was issued. The issue time is the later of the root block's `nbf` and `exp − maxTtl`, of those that exist; with neither `nbf` nor a `maxTtl`, the grant fails the scope.
    - `maxLag` is the smaller of the key's own and the one set by the namespace document of the namespace `at` belongs to (default 60 seconds).
- [ ] **AUTH-17** (Revocation, In a branch; §C.8 Keys, Revocation ids) A namespace document's `revoked` lists revocation ids. A root block's revocation id is its grant id in text (§C.3). A narrowing block's is `text(trunc160(sha256(its signature)))`, over the block's Biscuit signature.
  - A chain containing any revoked block is rejected, so revoking a root block revokes every token minted from it and everything narrowed from it.
  - Revocation is per namespace. In a branch, a chain is also rejected if any of its blocks is revoked in any of the branch's local bases.
- [ ] **AUTH-18** (Keys follow the base) A branch accepts its base's current keys as well as its own.
  - A key added to the base after the branch was created works in the branch too, and one removed or replaced in the base stops working in every branch.
  - A key the branch shares with its base (same `kid`) is the base's, accepted only while the base has it with the same `pub`.
  - If the base later adds a `kid` the branch added itself, only the base's entry is accepted. If the base removes it again, the branch's own entry applies once more. A `kid` copied from the base at creation never falls back.
  - In nested branches this applies recursively, through every local base.
  - A branch can't refuse a base key.
- [ ] **AUTH-19** (Bootstrapping, Operator grants) Creating a namespace needs a deployment-level operator key, configured outside the system.
  - A grant for a namespace that doesn't exist yet names it in `ns`, or uses `"*"`, which only grants signed by an operator key may do (`401` otherwise).
  - A branch is created with a `branch` grant on its base.
  - Operator grants, with the verb each action needs, authorise exactly: creating a namespace with its genesis document; creating a remote branch, including the schema histories it mirrors and their `nonce` settings; and forcing a purge or namespace purge.
  - Any other request under an operator grant is `401`. Requests that need no grant ignore it, such as public reads, `GET /` and `DELETE /edge-grants`, and `GET /ns/{ns}/principal` describes it.
  - A grant whose root `kid` names both an operator key and a key of the namespace document is verified against the namespace's key first, and is a namespace grant when that key verifies it.
  - Under an operator grant, a forced purge and `GET /ns/{ns}/principal` answer `404` for a namespace that doesn't exist. The `ns` check still answers `403` first, and a purged namespace answers `410`.
- [ ] **AUTH-20** (Operator key history) A deployment publishes its operator keys as a JWK Set (RFC 7517) at the `jwks_uri` it gives at `GET /`, by default `/.well-known/patchlog-keys`. The set is served as `application/jwk-set+json` and publicly cached for minutes.
  - Each key is an OKP Ed25519 JWK with `kid`, `use: "sig"` and `"patchlog": { "from", "until"? }`, the RFC 3339 period it was in force. `from` MUST be no later than the first entry written under a grant the key signed.
  - A key authorises only within its period: grants it signed are refused (`401`) before its `from` and after its `until`, and verify only for revisions created within it.
  - Keys are never removed, `kid`s are never reused, and the set lists no namespace keys.
  - Verifiers take the URI from `GET /`. Only a `200` whose body is a JWK Set with a `keys` array is a read of the history; anything else is a failed read, never an empty history.

### §C.5 Reading

- [ ] **AUTH-21** (Read modes, Public, Grant, The stream is metadata, Three exceptions) A namespace document declares `"read": "public" | "grant"`, by default `"grant"`.
  - Public namespaces are cached publicly.
  - A `grant` namespace is served with the grant in `Authorization`, or through edge grants that the origin issues in exchange for a verified grant with `read`. The edge grant isn't part of the cache key, and downstream caching is `private`.
  - Reads of `/ns/{ns}` and everything under it, its events stream and long-poll included, require unrestricted `read` (§2.1). A resource's own URLs, its events included, need `read` on that resource.
  - Three exceptions are answered by the origin with the grant in `Authorization`, `no-store`: the gestures listing, filtered per resource; `GET /ns/{ns}/principal`; and `POST /ns/{ns}/keys`.

### §C.5.2 Issuing edge grants

- [ ] **AUTH-7** (Scope, Request, Answer, Browsers, What a cookie authorises) `POST /edge-grants` on the origin takes the grant in `Authorization`, or several grants as `{ "grants": [ … ] }` in a body with `Content-Type: application/json`. It issues, for each grant, for every namespace that all its blocks carrying `ns` name.
  - **Scope.** An edge grant is scoped to the smallest edge prefix the grant allows: `/r/{ns}/{name}`, one per name, when its rules fix `/resource` (§2.1), and otherwise `/r/{ns}` and `/ns/{ns}`.
  - **Answer.** Success is `200` with `{ "prefixes": [ … ], "exp" }` and one `Set-Cookie` per prefix. Each cookie has no `Domain` attribute, `Path` set to the prefix, `Secure` and `HttpOnly`, and `SameSite=None` when the deployment names credentialed origins, `Lax` otherwise. It is named per prefix (§C.5.3).
  - **Lifetime.** A cookie lasts until the earliest `exp` among the grant's blocks or 15 minutes, whichever is sooner. A prefix several grants give gets one cookie, lasting as long as the longest, and the body's `exp` is the earliest, as an RFC 3339 time.
  - **Browsers.** Credentialed responses name the calling origin from the deployment's list, with `Access-Control-Allow-Credentials: true` and `Vary: Origin`, never `*` and never an echoed `Origin`.
  - **What a cookie authorises.** Only `GET` and `HEAD` under its prefix. Cookies the origin mints never cover a service's URLs, and a service's never cover core ones.
- [ ] **AUTH-22** (Refusals, table, All or nothing, Rate) `POST /edge-grants` refuses:
  - with authentication disabled: `404` (`not_offered`), before the body is read;
  - a body that isn't `application/json`: `415`;
  - neither `Authorization` nor a body: `401`;
  - a body with no grants or more than 50, or together with `Authorization`: `400` (`bad_input`);
  - a body larger than 50 grants of `grantSize` can be: `400` (`bad_input`), before it is parsed; a single grant over `grantSize` is `413` once decoded;
  - a namespace a grant names that doesn't exist, or a grant that fails verification there: `401` or `403`, as for any request;
  - a grant without `read` there, or one whose block or key-scope rules refer to `/resource` without fixing it (§2.1), or to `/now`: `403`;
  - a grant that carries roles, none of which is a qualifying role (§2.1): `403`;
  - a grant whose block or key-scope rules don't pass now, against a `read` envelope for its principal with `/resource` set to each name it fixes, if any: `403`;
  - a purged namespace: `410` with `code: "purged"`, if the grant verifies in it;
  - more than 100 distinct prefixes: `400` (`bad_input`), once nothing else is refused;
  - a principal whose `exchangeRate` bucket is empty: `429` with `code: "rate"` and `limit: "exchangeRate"`, once nothing else is refused.

  The answer covers every grant and namespace sent, never skipping a refused one. It is `401` if any refusal is `401`, else `403` if any is `403`. It is `410` only when every namespace refused is purged and the grant verifies in each, with `ns` and `head` naming the first refused one, in the order the grants and their root blocks list them. Once nothing is refused, the prefix cap's `400` included, the request draws one token, however many grants it carries, from the `exchangeRate` bucket of each distinct principal among them, keyed as write buckets are, and from no write bucket.

### §C.5.3 Edge-grant format and checks

- [ ] **AUTH-8** (Format, Keys, What an edge MUST check, Forwarding, Without the edge, Attribution) In the default format, a cookie's name is `__Secure-pl-eg-` followed by the first 8 bytes of `sha256(prefix)` in lowercase hex.
  - Its value is `base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))`, without padding. `c` is the canonical JSON (§3.1) of `{ "kid", "p": prefix, "exp": <seconds since the epoch> }`, those three members exactly. A value whose `c` has other members, or isn't canonical byte for byte, is ignored.
  - Each key vouches only for its own prefixes: the origin's for the core edge prefixes, and a service's for prefixes under a root of its own, which never overlaps `/r/` or `/ns/`.
  - On every request, cache hits included, before serving it or forwarding it as verified, an edge MUST check that:
    1. the method is `GET` or `HEAD`, with no `Authorization`;
    2. the path has no empty, `.` or `..` segment and no percent-escape, `/` itself excepted;
    3. a cookie's name is derived from its own `p` (other cookies are ignored);
    4. `c` is in the format, with a `kid` the edge holds that vouches for `p`, and a valid MAC;
    5. `exp` is in the future;
    6. `p` covers the path segment by segment: the path is `p` or starts with `p/`.
  - **Forwarding.** A request that passes is forwarded, on a cache miss, with its cookies, from which the origin still authorises it and takes the `exp` that ends an event stream (§7.3), and with the edge's verification headers: by default `X-Edge-Verified`, carrying the secret the edge shares with the origin, and `X-Edge-Prefix`, the `p` it checked. Each is exactly one header line without a comma, and both are stripped from incoming requests. One covering cookie is enough.
  - A request that fails any check is forwarded without the headers, and the origin answers it as it would without an edge. A failure of the path check is `400` from the origin either way.
  - **Without the edge.** A cookie the edge didn't verify is verified by the origin, which answers with `CDN-Cache-Control: no-store`. A cookie counts only on a request without `Authorization`.
  - A deployment that logs reads attributes cookie reads to the prefix.

  **[vectors I.5]**
- [ ] **AUTH-23** (Service-minted grants) A service that mints edge grants for output derived from documents does so with a key the origin never holds. It mints one only after checking that the reader may read every document the output derives from, lets it expire no later than the earliest of those reads, and withdraws its own cookies.

### §C.5.4 Withdrawing edge grants

- [ ] **AUTH-24** (§C.5.4 and its bullets) `DELETE /edge-grants?prefix=…`, `prefix` repeatable, answers `204`, `no-store`. It sends an expired `Set-Cookie`, of the same name and attributes, for each prefix named, once even if a prefix is named twice.
  - A request without `prefix`, or with one that isn't an edge prefix (§2.1), is `400` (`bad_input`).
  - It needs no grant, ignores any it is sent, and answers the same while authentication is disabled.
  - Only `DELETE` withdraws, and its preflight is allowed only for the credentialed origins of issuance.

### §C.6 Consumers and plug-in services

- [ ] **AUTH-25** (Least privilege) A service gets `read` for what it follows. A service that writes back gets a narrowing block with `writes within` its own paths, and without `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export` or `prune`.
- [ ] **AUTH-26** (Services verify as the origin does, Filtering proxies, Services that re-publish content MUST enforce reader permissions)
  - A service that verifies grants locally applies keys, scopes, `readScope` included, and revocations exactly as §C.2 does.
  - A filtering proxy serving a namespace's `/ns/{ns}/…` view per document pages and derives cursors itself, such as for `/heads`, and never passes upstream ones on.
  - A service that re-publishes content MUST enforce reader permissions: search, tree and catalog results are filtered by the reader's verified grant. Private results are cached per `gs`, not per request, and never with embedded bearer URLs.

### §C.7 Private content and guessable hashes

- [ ] **AUTH-9** (A nonce in every patch set, Requiring it) A write that `add`s `/$nonce` of the fresh form is left out of `writes` (§6.4.1), and validation doesn't see the key (§6.2). A namespace MAY set `"nonce": "required"` (default `"optional"`).
  - Then, at step 3 of §6.2, the document a resource create, append or restore results in MUST have a top-level `$nonce` of the fresh form that differs from the parent's, or for a restore from the last live document's. Otherwise the write is `422` with `code: "nonce"`.
  - A failed `test` or patch application is still reported first, as `invalid`.
  - A server that also enforces the sealed-namespace rule (§E.2.5) answers `422 nonce` at the same point.
  - Deletes, and config, branch and prune writes, are exempt. The check applies to every patch set, whatever its origin.
- [ ] **AUTH-27** (Requiring it)
  - A branch copies the setting and can't turn off one its base has. A base can't start requiring it while a dependent doesn't. Setting or changing it needs a `*` key (all §7.4).
  - It is `422` in an end-to-end namespace (Addendum E, Levels).
  - A remote branch of a base whose current namespace document requires nonces when the branch is created MUST be created requiring them too (`422` otherwise).
  - Schema namespaces created to mirror for a remote branch start `optional`. They take their source's setting with a config write once their history is in, under the operator grant that creates the remote branch, as part of its creation, and stay `optional` if the source's namespace document can't be read.
  - The upstream namespace of a snapshot import takes its target's setting.
  - Merge tools that build a resolution or squash set add a fresh `$nonce` to it where required.
- [ ] **AUTH-28** (Blobs, Encryption) In sealed namespaces, and where nonces are required, writers give the blobs they create a nonce (§7.8). Sealed namespaces refresh `$nonce` in every patch set (§E.2.5).

### §C.8 Encoding: Biscuit v3

- [ ] **AUTH-29** (One block, one fact, Keys, Sealed tokens, Stored form, Transport) Each block of §C.1 is one Biscuit v3 block containing exactly one fact, `grant_block(<string>)`. The string is the block's canonical JSON, and MUST be I-JSON and equal to its own canonical form (`401` otherwise).
  - The authority block carries the root block, and each appended block one narrowing block, in order.
  - A block with anything else (other facts, rules, checks, scopes), or a third-party block, makes the token invalid (`401`).
  - Biscuit's Datalog is not evaluated. The server verifies the signature chain, extracts the JSON blocks and applies §C.2 to them, with validity times from the blocks' `nbf` and `exp`.
  - Every signature in the token is Ed25519, the ephemeral keys that sign narrowing blocks included, verified strictly (RFC 8032, with `S < L`), and a token using any other algorithm is `401`. The root key entry says `alg: "Ed25519"`.
  - The root key is named by `kid` inside the root block, not by Biscuit's `rootKeyId`, and is looked up in the configuration in force. A wrong `kid` fails verification.
  - Sealed tokens are accepted.
  - The stored form is the authority block with its signature and next key, without the other blocks or the token's `proof`.
  - The token is sent as `Authorization: Bearer <token>`, in Biscuit's URL-safe base64, with or without the `biscuit:` prefix. `grantSize`, counted in decoded bytes, and `rulesPerGrant` are checked before step 1 of §6.2, and on any other request that doesn't ignore the grant (§7) before its `ns` check, as request-shape errors (`413`, `code: "limit"`).

## Addendum E — Encryption

- [ ] **ENC-8** (Levels, Changing it, After a raise) A namespace declares its level in its namespace document as `encryption.level`: `at-rest`, `sealed` or `e2e`. A write that lowers or removes the level is `422` (`invalid`), and so is one that raises `sealed` to `e2e` without starting a new epoch (§E.2.1). A namespace document holding a member its level refuses (§6.1, §7.4, §8.6, §C.7) is `422` (`invalid`) whichever member the write changes. The origin purges the namespace's cache tag with a raise to `sealed` or `e2e`. After a raise, `Last-Modified`, `Repr-Digest`, `/heads` fields, caching, `…/raw` and the gestures listing follow the new level. After a raise to `sealed`, content stored before it is served as §E.2.2 says for content from before the namespace was sealed.
- [ ] **ENC-9** (After a raise) After a raise to `e2e`, the following are served as at the level before: the revisions, resource log entries, namespace documents and log ranges from before the raise, the grants first recorded before it, and the blobs those revisions reference. That is in the clear, or, after a raise from `sealed`, sealed as §E.2.2 says, with the last epoch and `pad` setting before the raise in place of the current ones; sealed blobs keep their epoch URLs under those revisions' epochs only. `/keys` gives the keys of epochs before the raise as at E2 (§E.2.3), leaving out, rather than answering `403`, those a grant wouldn't get there. No log page spans the raise. In a log, the raise lies before the namespace entry (`config` or `batch`) that made the namespace end-to-end; in a resource log, before the first entry written with or after it.
- [ ] **ENC-10** (Branches and dependents, Branches of a raised base)
  - A branch's creation that leaves it below its base's level, or at `e2e` over a base that isn't, is `422`, as a branch field (§7.4). So is a config write that raises a branch to `e2e` over a base that isn't. Other config writes aren't checked against the base's level.
  - A write that raises a namespace above a dependent's level is `409` (`in_use`, with `dependents`).
  - A branch of a base raised to `e2e` can't be created, or raised to `e2e`, with an `at` before that raise (`422`, as a branch field).
  - Such a branch serves what it reads through from before the raise as the base serves it. Its `/keys` gives the base's keys for it as at E2, `K_r` derived with the base's `ns`, for the base epochs §E.2.3 selects; a remote branch fetches them from its source with its own grant. Readers accept the base's `ns` in that content's `pl` and `kid`.

### §E.1 At rest

- [ ] **ENC-1** (What it is, What it doesn't change, Purge becomes cryptographic, Stored digests) At E1 the origin encrypts stored patches, snapshots and grants with keys from a KMS, and nothing else in this spec changes. With a key per resource, purging destroys that key. A server that stores `/heads` `size` and `digest` (§7.4) at E1 leaves them out, computes them at read time, or keeps them under the resource's key.

### §E.2.1 Keys

- [ ] **ENC-11** (Epoch keys, Per-resource keys) Epoch keys `K_e` are 256-bit random, each identified by `kid = "{ns}#{e}"`. The current epoch is the namespace document's `encryption.epoch`. Key material is never in the namespace document or the log. Per-resource keys are `K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name)`, 32 bytes. **[vectors I.7]**
- [ ] **ENC-12** (Rotation) A config write that increments `encryption.epoch` starts a new epoch, recorded in the namespace chain, and needs a `*` key (§7.4). In a namespace already at `sealed` or `e2e`, a write that changes `epoch` other than by adding one is `422` (`invalid`). Revisions written from then on are sealed under the new epoch; old revisions keep their epoch.

### §E.2.2 Sealed representation

- [ ] **ENC-2** (intro, Algorithms, Protected header, What gets sealed, table) In a sealed namespace, each payload below is sealed as a JWE (RFC 7516) in compact serialization.
  - The JWE has `alg: "dir"`, `enc: "A256GCM"` and the protected header `{ "alg", "enc", "kid": "{ns}#{e}", "pl" }`. Ids in `pl` are in text form, and an empty one is `""`.
  - Each JWE served alone is `Content-Type: application/jose`. A resource log range or resource long-poll answer is a JSON array of its entries' JWEs, served as `application/json`. An SSE event's `data` is one JWE.

  Each payload's key, epoch and `pl`:
  - `/rev/{id}` document: `K_r`, the revision's epoch, `pl: { "ns", "name", "id", "kind": "doc" }`.
  - Resource log entry (patches, author, `via`, grant, signature), in a range or as a `revision` or `tombstone` event: `K_r`, the revision's epoch, `pl: { "ns", "name", "id", "kind" }`, with `kind` the entry's (`rev` or `tombstone`).
  - Resource `purge` or `prune` event: `K_r`, the current epoch, `pl: { "ns", "name", "kind" }`, with `kind` the event type.
  - Namespace document at `ns_id`: `K_e`, the epoch in force at `ns_id`, `pl: { "ns", "id": ns_id, "kind": "doc" }`.
  - Namespace log range, namespace long-poll answer, or namespace event: `K_e`, the current epoch, `pl: { "ns", "range": [since, last] }`. The bounds are those of the page actually served, `[since, id]` for an empty page. An event is sealed as a range of its one entry, `[prev, id]`, whose plaintext is the entry.
  - Grant (§C.3.1): `K_e`, the epoch in force at the first namespace log entry recording it, `pl: { "ns", "grant": gid }`.

  The epoch in force at a namespace entry is the `encryption.epoch` of the namespace document in force there. A revision's epoch is the current one when it is first sealed. So is the epoch of a namespace document or grant from before the namespace was sealed, and of a grant only a base records.
- [ ] **ENC-13** (What stays in the clear, Stored once, served forever) In a sealed namespace:
  - A revision's exact `created`, a document's length and its digest aren't sent outside the sealed logs.
  - Sealed bytes for a revision, a document, a resource log entry or a grant are produced once, stored, and served identically on every later request.
  - A sealed revision has `ETag: "{id}.{e}"`, and a sealed namespace document `ETag: "{ns_id}.{e}"`.
  - Sealed namespace log ranges are the exception. A deployment MAY keep only some, oldest evicted first, and seal an evicted range again on request, with fresh bytes, under the epoch key and `pad` setting current then. A range's `ETag`, if any, is weak.
- [ ] **ENC-14** (Protected header, Stored once, served forever; readers)
  - Readers MUST compare `pl`, and the namespace that `kid` names, with what they fetched. In both they accept a base's `ns` for content a branch reads through.
  - Readers accept either copy of a namespace log range sealed again, and MUST NOT rely on one.
  - Readers accept sealed bytes with or without fields that a later version adds.
  - Grants recovered for entries written before v0.37 that are missing from the sealed bytes don't count in the janitor's checks (§F.6).
- [ ] **ENC-15** (Compression, Padding (optional)) Sealed payloads are never compressed and carry no `zip` header. In a namespace with `"pad": true` in `encryption`, every JWE sealed for it, by the server at E2 and by clients at E3, pads its plaintext before encryption:
  - the plaintext is the UTF-8 JSON that would otherwise be sealed, followed by ASCII spaces (`0x20`) up to the padded length; a blob is padded with zero bytes inside its sealed form instead;
  - for a plaintext of `L` bytes the padded length is 256 for `L` ≤ 256, otherwise `padmé(L)`: `L` rounded up to a multiple of `2^(E − S)`, where `E = ⌊log₂ L⌋` and `S = ⌊log₂ E⌋ + 1` **[vectors I.6]**;
  - each JWE is padded as a whole, each JWE of a log range included;
  - turning `pad` on or off affects only what is sealed afterwards, including a log range sealed again after eviction.
- [ ] **ENC-3** (Sealed blobs) In a sealed namespace, blobs are served as `application/vnd.patchlog.sealed-blob`: `"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(size ‖ bytes ‖ padding) ‖ tag`.
  - `len` is the length of `header` as a 4-byte big-endian integer, and `header` is canonical JSON. At E2 the header is `{ "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "blob": bid } }`, and the key is the resource's `K_r` of epoch `e`.
  - `iv` is 12 random bytes and the tag 16 bytes; the additional data is everything before `iv`.
  - `size` is the length of `bytes` as an 8-byte big-endian integer. `padding` is zero bytes, present only with `pad`, up to the bucket of `size ‖ bytes`.
  - Readers check that the padding is all zeros. Clients open sealed blobs only in namespaces whose namespace document says they are sealed or end-to-end, or after the epoch redirect.
- [ ] **ENC-16** (Sealed blobs: Epochs, ranges) In a sealed namespace, and at E3 for blobs from before a raise from `sealed`:
  - `…/blob/{bid}` answers `302`, cached as a head pointer, to `…/blob/{bid}/e/{e}` for the latest served epoch.
  - The epochs served are those of the revisions in this namespace whose documents are still stored and reference the blob.
  - A revision's epoch is fixed by its first stored sealing: when it is written, or, for one read through from a base or written before the namespace was sealed, when it is first served. A request for a blob none of whose referencing revisions has an epoch yet first fixes the newest of them under the current epoch.
  - Other epochs are `404`, with `no-store`. An epoch whose referencing revisions were all pruned is `410` as in §7.1 where the server recorded it when pruning, and `404` otherwise.
  - Pruning in a base doesn't delete a branch's stored sealings of the base's blobs, but the branch stops serving them and answers as above.
  - Each epoch's sealing is produced once and stored; when two instances seal at once, the first one stored wins. Only the stored bytes are served, unchanged, with `ETag: "{bid}.{e}"` and the sealed type as `Content-Type`.
  - Range requests are served over the sealed bytes.

### §E.2.3 Getting keys

- [ ] **ENC-4** (What a grant gets, Which epochs, Responses) `POST /ns/{ns}/keys` takes `{ "epochs"?, "resources"? }`:
  - At E2, a grant whose rules fix `/resource` (§2.1) gets per-resource keys `K_r` for the names in `resources`, by default every name it fixes. A name it doesn't fix, or may not read, is `403`.
  - At E2, any other `read` grant gets epoch keys `K_e` if it reads the namespace unrestricted (§2.1), and is `403` otherwise; `resources` is ignored.
  - The epochs given are those in `epochs`, by default all, within a window. The window starts at the epoch in force (§E.2.2) at the last namespace entry created at or before the latest `nbf` among the grant's blocks, a `batch` entry's config change included. Where there is no such entry, or the namespace wasn't yet sealed or end-to-end there, it starts at the namespace's first epoch. With no `nbf` in any block, it is the current epoch only. The window ends at the current epoch, and where `encryption.historyEpochs` is set, it covers no more than the current epoch and that many before it. Other epochs are left out.
  - A reader that lacks the epoch a grant is sealed under reports the signatures naming that grant as unverifiable.
  - The answer is `{ "epoch", "level", "pad", "keys": [{ "kid", "name"?, "from"?, "wrapped" }] }` with `Cache-Control: no-store`. `epoch` is the current epoch, `name` is present for a `K_r`, and `from` for a keyring entry. At E2, a grant without `enc` gets each key in base64url as `key` in place of `wrapped`.
  - In a namespace that is neither sealed nor end-to-end, the answer is `404` with `code: "not_offered"`.
  - A request draws a token from `exchangeRate` (§6.6), as `/edge-grants` does.
- [ ] **ENC-17** (At E3) At E3, `/keys` relays to a `read` grant the keyring entries whose `to` is the thumbprint of its `enc`, without a read of `keyring` itself:
  - those of the namespace's `keyring` for the epochs ENC-4 selects;
  - in a branch, also those of its bases' keyrings as of `at`, whether or not the branch has written its own `keyring` since. These cover the bases' epochs up to `at`, starting from the epoch each base had in force at the latest `nbf`, or at `at` if that is earlier, and, where no block has `nbf`, from the epoch that base has in force now, so none once it has moved past its epoch at `at`. `epochs` doesn't select among them.
- [ ] **ENC-18** (Wrapping) Keys are wrapped to `enc`, an X25519 public key in the grant's root block:
  - `enc` is a JWK of only `kty: "OKP"`, `crv: "X25519"` and `x`, its 32 bytes in base64url without padding (43 characters); `401` otherwise.
  - Wrapping uses HPKE (RFC 9180) in base mode (auth mode for `keyring` entries), with the suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, and an empty `aad`.
  - The plaintext is the key's 32 bytes, and the `info` is `"patchlog-key-v1" ‖ 0x0A ‖ kid ‖ 0x0A ‖ name`, with `name` empty for `K_e`.
  - `wrapped` is HPKE's 32-byte encapsulated key followed by the ciphertext.
  - A public key's thumbprint is its JWK's RFC 7638 SHA-256 thumbprint. `wrapped` and thumbprints are base64url without padding.

### §E.2.5 Interaction with the rest of the spec

- [ ] **ENC-5** (Caching, Ids, Branches) A sealed namespace is cached by its `read` mode (§9). Ids are computed over plaintext canonical patches, and sealed namespaces MUST refresh `$nonce` in every patch set (§C.7). At E2 a branch has its own epoch keys, and the server seals read-through content under them when it is first served.

### §E.2.6 Derived views

- [ ] **ENC-19** (Getting keys, What gets sealed, Aggregates) A service serving views derived from sealed or end-to-end namespaces:
  - fetches epoch keys through §E.2.3 with its own key pair and a grant with `read`. At E3, a service whose public key isn't a recipient in the namespace's `keyring` skips the namespace, says so in its status, and MUST NOT index or list ciphertext as if it were content;
  - seals every value a view derives from such a namespace's content. Names, ids, URLs and heads, and the view's own structure (`at`, `ns`, order and pagination cursors), stay in the clear. A cursor never encodes a sealed value;
  - serves values that combine several resources only in whole-response form, and refuses them (`400`) to a reader that would get per-entry sealing.
- [ ] **ENC-20** (Whole-response sealing, Per-entry sealing, `view`, Values of another resource) Here `view` is the request target, path and query, of the `…/at/{at}/…` URL the response is served at, exactly as the service's redirect gave it.
  - **Whole response.** The service MAY serve the whole response as one JWE only when all three hold:
    - every sealed value in it, values of another resource excepted, comes from one namespace that isn't public;
    - every reader its URL admits may read that namespace whole (`g/all`, §B.11.5, or an index `gs` with `reads:{ns}`, §A.4);
    - every such value derives from revisions served under one epoch.

    The JWE is in the §E.2.2 format, under that epoch's `K_e`, with `Content-Type: application/jose` and `pl: { "ns", "view" }`.
  - **Per entry.** Otherwise the response is JSON, and each entry that carries sealed values replaces them with `"sealed": "<JWE compact>"`. The key is the `K_r` of the entry's own resource, `kid` names the epoch the revision it derives from is served under (§E.2.2), and `pl` is `{ "ns", "name", "view" }`. Folders and placements from a sealed or end-to-end catalog namespace are entries of that namespace.
  - **Another resource.** A value an entry carries that derives from another resource is sealed in place as `{ "sealed": "<JWE compact>" }`. The key is that resource's `K_r`, `kid` the epoch the revision it derives from is served under, and `pl` is `{ "ns", "name", "view" }`, naming that resource and the response's `view`; its namespace's padding applies. It nests inside a whole-response JWE where the rest is sealed whole. While that namespace's keys can't be fetched, the service answers `503`.
- [ ] **ENC-21** (Stored once, served forever, Caching, Local storage, `view`)
  - A view at a given `at` is sealed once, under the epochs of the revisions its values derive from, and then served unchanged. A stored view is keyed by its URL and the shape of the reader's keys.
  - Padding follows the source namespace; whole-response sealing pads only when every source is padded.
  - A view is cached publicly only when all its sources are public, and is otherwise a private result (§C.6).
  - The service keeps what it derives from a sealed or end-to-end namespace in storage encrypted as at E1, with keys held outside that storage.
  - A purge of the source, or the destruction of its keys, MUST remove the derived data: rows deleted and freed pages overwritten, stored sealed views deleted, cached keys forgotten.
  - Readers MUST compare `pl` with the URL they fetched.

### §E.3.1 Wire format

- [ ] **ENC-6** (Patch sets, Ids, Namespace documents stay plaintext) In an end-to-end namespace, a write's body is a one-element patch set `[{ "op": "sealed", "value": "<JWE compact>", "blobs"? }]`. It is sealed under the resource's `K_r` of the epoch its `kid` names, and its JWE protected header carries `kid` and `pl: { ns, name, parent }`.
  - At step 3 of §6.2 the server checks four things, and otherwise the write is `422` (`invalid`):
    - the op has no members but `op`, `value` and `blobs`;
    - `pl` names this namespace, the resource and the parent a signature would bind (§C.3.1);
    - `kid` names this namespace's epoch in force;
    - the header has no `zip`.
  - A prune's `snapshot` is one such op, with `pl: { ns, name, id }` naming the revision whose document it is. Its `kid` is set by the newest revision in that revision's chain that isn't a tombstone and whose patch set isn't `[]`:
    - this namespace's epoch of that revision's `sealed` op, where the op is its own, not a base's;
    - the epoch that revision is served under, where it is from before a raise from `sealed`;
    - otherwise this namespace's epoch in force.

    The server checks both `pl` and `kid` (`422`, `invalid`).
  - The server hashes the op like any patch set, so ids are over ciphertext. Namespace documents stay plaintext.
- [ ] **ENC-22** (Blobs, Declared blobs; server) In an end-to-end namespace:
  - The server accepts an empty `blobs` list either omitted or as `[]`, and a list in any order. A list with duplicates is `422` (`code: "blob"`), and so is a declared blob whose type isn't the sealed type or that has a nonce.
  - A restore with the empty patch set `[]` keeps the list of the last live document.
  - The list is part of the hashed patch set, and is kept with the revision's skeleton after pruning. Its length is checked against `blobsPerDocument`. The server checks that the declared blobs are available (§7.8), and uses the lists for unreferenced blobs, pruning, purge and bundles. A prune's sealed `snapshot` needs no list.
- [ ] **ENC-23** (Patch sets, Retries, Blobs, Declared blobs; clients and readers) In an end-to-end namespace:
  - A client MUST keep the exact ciphertext of a write until it is acknowledged.
  - A client encrypts each blob under a fresh random 256-bit key, in the sealed-blob form of §E.2.2 with the header `{ "enc": "A256GCM" }`, and uploads it as `application/vnd.patchlog.sealed-blob`. It puts the key in the reference as `sealed: { "key", "type", "size" }`, where `type` and `size` describe the plaintext.
  - Writers list in `blobs` the id of every blob the resulting document references. They omit the member when the list is empty, and otherwise sort it by the ids' binary form (§3.2). A sealed empty set that keeps a document unchanged repeats its list.
  - Readers check `pl`, accepting a base's `ns` for content read through. Readers MUST compare the declared list with the decrypted document, as sets, and flag a revision whose list differs.

### §E.3.2 What the server can and cannot do

- [ ] **ENC-24** (Validation moves to clients) In an end-to-end namespace:
  - Every client MUST validate the decrypted document against its `$schema` before writing, leaving out the members §6.2 step 5 leaves out.
  - A revision that fails validation on read is flagged but still folded.
  - A revision whose patch set doesn't apply to its parent's document, a failing `test` included, is flagged too, and readers fold on from the parent's document as if its patch set were `[]`.
- [ ] **ENC-25** (Keys) In an end-to-end namespace, the server only relays wrapped keys.
  - The `keyring` resource's document is `{ "keys": [{ "kid": "{ns}#{e}", "to", "from", "wrapped" }] }`. `to` and `from` are the thumbprints (§E.2.3) of the recipient and of the wrapping admin's X25519 key. It has no other members but a `$nonce`.
  - Two entries for one `kid` and `to` are `422` (`invalid`).
  - The keyring is written in plaintext and checked as outside E3 (§6.2).
  - Entries are wrapped as in §E.2.3, in HPKE auth mode under the admin key. A client seals only under a key whose `from` it trusts.
  - Rotating the epoch and re-wrapping for the remaining readers is done by a key holder, never by the server.

### §E.4 Metadata that no level hides

- **ENC-7** Retired in v0.73: §E.4 requires nothing a tester can check.

## Addendum F — Branches, merge and rebase

### §F.3 Merge

- [ ] **MRG-1** (step 1 Collect, step 2 Classify, table, step 3 Dry run, step 4 Resolve, step 5 Submit, Conflicts inside arrays) A merge is one batch into the base. The merger collects the resources the branch changed from its namespace log, and classifies each by ancestry of ids, comparing the base's current head `B` with the branch's head `H`:
  - `B` = `H` gives no item.
  - `B` an ancestor of `H` (the foreign parent included, and "absent in the base" for a resource the branch created) gives a fast-forward: the branch's entries after `B`, with `ifMatch: B` (or `ifNoneMatch: *`). Its resulting ids are identical to the branch's. At E3 it is a re-sealed replay instead (§F.8.1).
  - `H` an ancestor of `B` gives no item.
  - Neither gives a replay of the branch's entries after their latest common ancestor onto `B`, with new ids, and it is always reviewed. It conflicts if the two sides' `writes` overlap, the branch's counting the `from` of each `copy` too, or if history it needs was pruned.
  - A resource purged in the base or the branch gives no item, and is reported.

  For merge and rebase, a write whose last segment addresses an array element (an index or `-`) counts as a write to the whole array. The batch is dry-run (`?dry-run=1`), and each conflicting resource's steps are replaced by one resolution set against `B`. It is submitted with `source: { ns: <branch>, at }`, `at` being the branch revision step 2 classified from, not a later one. Items that fail with `412` because the base moved are classified again and resubmitted.
- [ ] **MRG-6** (step 2) A `"delete"` step reproduces a tombstone. Two cases always need a person, however they classify: deleting a document the base has since changed, and changing one the base has since deleted.
- [ ] **MRG-2** (step 6 Freeze the branch, and its sub-bullets) A merged branch is frozen with a config write that also records `"merged": { "at": <the base's ns_id> }`, or kept working and merged again later.
  - After a replayed merge, each earlier merge batch from the same branch is treated as a common ancestor, and a second merge replays only what the branch changed since. Per resource, the pair (the branch revision as of the batch's `source.at`, the base revision from the batch's entries) comes from the most recent such batch that has an entry for it.
  - A resource deliberately kept at the base's version is recorded in the batch with a revision of identical content: an empty step `[]`, or a fresh `$nonce` add where nonces are required or the namespace is sealed, or a sealed empty set at E3.
  - Only a live base head can be recorded so. A resource whose base head is a tombstone or absent stays unmerged, and is offered again, and so does one at E3 whose base head references a blob that a `sealed` op can't declare, such as one from before a raise to `e2e` (§E.3.1).
  - Only batches count that have no `origin`, whose `source.ns` is the branch, whose `source.at` is in the branch's chain (which the merger checks itself), and whose recorded grant has a root `sub` and `kid` listed in the base's current `merge.authors`. Removing an author withdraws its earlier batches. Changing `/merge` needs a `*` key (§7.4).
  - The merger's dry-run report lists, per resource, which batch and author its pair came from.
- [ ] **MRG-7** (Blobs, Nonces, Configuration is never merged implicitly, Authorisation, Attribution)
  - **Blobs.** A merger with unrestricted `read` on the branch copies no blobs within the deployment, since the batch's `source` makes the branch's blobs available. Any other merger copies them first, or uploads them where the ranks refuse a copy (§2.1). A merge from another deployment uploads them.
  - Tools that diff documents for a merge or a review leave out a fresh `$nonce`.
  - A config change meant for the base goes in the batch's `config`.
  - The batch is checked in the base under the merger's grant: the merger needs the base's verbs for every item, and the base's rules apply.
  - Merged revisions, fast-forwarded or replayed, record the merger as author. Where signatures are required, the merger signs its own steps.

### §F.5 Rebase: a successor branch

- [ ] **MRG-3** (steps 1–5, Previews) A rebase creates a successor branch from the base at its current head, with `patches` that give it the old branch's `read`, or `"grant"` where that would rank it below the old branch (§2.1). A rebase never replays into a successor that ranks below the old branch. It replays the old branch's changes into the successor with batches carrying `source: { ns: <old branch>, at }`, classified as in §F.3 but against the new branch. Resources the base didn't change since the old `at` fast-forward and keep the same ids, except at E3.
  - When replaying resumes, batches in the successor without `origin` whose `source.ns` is the old branch count as earlier merges (§F.3), whoever wrote them, even without `merge.authors`.
  - The switch is one config write on the old branch, `"frozen": true, "successor": <new branch>`. Whatever the old branch received after the replay is then replayed too.
  - Previews follow the `successor` chain.

### §F.6 Lifecycle and cleanup

- [ ] **MRG-8** (Cleanup, A janitor service) `cleanup` is data in the branch's namespace document, and the core doesn't enforce it. Without it, the janitor never purges the branch. A janitor purges a branch only when:
  - it is frozen, and merged, superseded or abandoned;
  - its cleanup period has passed: the member of its `cleanup` for the state it is purged as (without one, it isn't purged as that state), counted from the last config write that froze it or set `merged`, `successor` or `abandoned`;
  - any minimums the base sets in its own `cleanup` have passed too;
  - it has no dependents.

  It needs `purge-ns` on branches only, never on bases.
- [ ] **MRG-4** (The janitor MUST verify claims, and the closing rules) Before purging, the janitor MUST verify the claims `merged`, `successor`, `abandoned` and `cleanup`, holding `cleanup` to the base's minimums. It checks:
  - **merged:** the base's log has a batch without `origin`, by a principal listed in the base's current `merge.authors`, whose `source.ns` is the branch and whose `source.at` is in the branch's chain. The branch's log has no `head`, `tombstone` or `batch` entry after `source.at`; entries of other kinds are allowed. A remote branch merged back with `origin` never passes.
  - **superseded:** the successor is still one §7.4 allows, or was until a purge after the branch was frozen (not for a sealed successor). Its log has a batch without `origin` whose `source.ns` is the branch, whose `source.at` is in the branch's chain, and whose recorded grant either has a root `sub` and `kid` in the base's current `merge.authors` or chains to a current `*` key of the branch. The branch's log has no `head`, `tombstone` or `batch` entry after that `source.at`.
  - **abandoned:** the branch's document has `"abandoned": true`, set by a config write whose recorded grant chains to a current `*` key of the branch, inherited or its own. A flag whose entry records no grant doesn't count.
  - At E3, entries for the branch's `keyring` resource after `source.at` are allowed in the merged and superseded checks, and a batch counts only if it has other items.
  - In the merged and superseded checks, every resource with a `head`, `tombstone` or `batch` entry of the branch's own up to `source.at`, other than its `keyring` at E3, also has an entry in a batch that counts there, or a head that the head of the batch's namespace equals or descends from.
  - A branch with no `head`, `tombstone` or `batch` entry of its own, other than for its `keyring` at E3, counts as merged.

### §F.7 Merge service

- [ ] **MRG-9** (Automation) A merge service automates only two things: rebasing branches in which every resource fast-forwards, or at E3 is re-sealed onto an unchanged base; and submitting at a set time a batch a person approved. Anything else, any replay a person hasn't approved included, waits for a person.

### §F.8 Access, encryption, catalogs and indexes

- [ ] **MRG-10** (Catalogs) A catalog service MUST issue content grants only from the catalog it follows as the base.
  - Merging a catalog branch goes through the catalog service, which for an end-to-end catalog issues no merge grants and checks no catalog batch (`404`, `not_offered`), as for organising requests (§B.11.4). It checks every change in the batch as §B.11.4 checks organising requests, with the person who approved the plan as the caller, resolved from that person's own grant as §B.11.4 resolves one, and with no widening whoever approved. It then issues one grant covering exactly that batch.
  - That grant's rules allow exactly the batch's pairs of `/resource` and `/action`, and it expires within minutes. It is signed with a key used for nothing else, which can neither assert admin groups nor write `$access`, with root `sub` the merge service's and `attrs.approvedBy` the person who approved the plan.
  - It is handed to nobody but the merge service, which submits exactly the batch that was checked.
  - A catalog batch that changes `$access`, or moves or re-places so as to widen (§B.11.4), is checked by the catalog service in a dry run, except in an end-to-end catalog, with the person in `catalog-admins` whose grant it goes under as the caller. It is submitted under that grant, through the merge service, which adds a narrowing block with its own `via`.
  - The catalog base lists in `merge.authors` the merge service's `sub` with the merge key's `kid`, and each such admin.
- [ ] **MRG-11** (Editors limited to some documents, Indexes) A service that branches a base for editors limited to some documents records the creation with `via`, creates the branch with `read: "grant"`, and issues them grants on it fixed to the resources their base grants cover. The main index follows only the base, and search over a branch is a separate preview index.

### §F.8.1 Merging and rebasing at E3

- [ ] **MRG-12** (Keys, Classification, Re-sealing an entry, Blobs) At E3 a merge or rebase is carried out by a client that holds keys, and submitted as an ordinary batch sealed for the target.
  - **Keys.** Read-through content in a branch keeps the base's ciphertext and `kid`. A client asks the namespace it is reading for keys first, and the `kid`'s namespace only if that fails. The branch's own writes carry the branch's `kid`s, and a branch's `keyring` is never merged.
  - **No fast-forwards.** Where `B` is an ancestor of `H`, the branch's entries after `B` are re-sealed onto `B` in order, with new ids and no conflict check. Where neither is, they are replayed with the conflict check of §F.3.
  - **Re-sealing.** The merger decrypts the patch set and checks its `pl` against where it was read: the branch (or the base, for read-through content), the resource, and the entry's parent. It seals the same plaintext patches under the target's current epoch, with a fresh IV, the target's `pad` and `pl: { ns: target, name, parent }`. `parent` is `B` for the first entry, and after that the id the previous entry of the same item produces. The merger computes each new id itself.
  - A tombstone isn't sealed: its id follows from its new parent.
  - Blobs keep their ciphertext and ids, and each re-sealed op keeps its `blobs` list.
- [ ] **MRG-13** (Conflicts, Validation, Retries, Rebases)
  - The merger finds conflicts from the `writes` of the decrypted patch sets, compared as in §F.3, arrays included.
  - Before submitting, it folds every item and validates each resulting document against its `$schema`, resolved as the target's gate would resolve it. A document that fails is reported as a conflict of kind `invalid`.
  - It keeps the sealed batch byte for byte until it is acknowledged. Classifying again after a `412`, or changing a resolution, seals the affected items again.
  - Rebases re-seal in the same way, with the successor as the target, and remote branches are merged in the same way, with the target's keys.
- [ ] **MRG-14** (Later merges and the janitor) At E3 a second merge finds its common ancestors in earlier merge batches (§F.3). Without such a batch, every resource the branch changed conflicts, except one the merger counts as merged because the target's and the branch's head documents are equal as decrypted plaintext.

### §F.9 Releases across namespaces

- [ ] **MRG-15** (Where it lives, Starting, Cleanup) Every tool acting on a release document checks for itself, under its own authority, what it is about to do. Each branch's own `at` is authoritative over the document's `at`. The janitor purges a release's draft branch after its other branches, and the release document never authorises a purge.
- [ ] **MRG-16** (Reading) In a release preview, items in a content branch the viewer can't read are hidden, not shown from the base. A viewer who can't read the catalog branch gets `403`.
- [ ] **MRG-5** (Merging) A release merges as one batch per branch.
  - **Checks.** Before approval, the merge service checks that each listed branch's `base` is the namespace it is keyed by, or, for a release built on another, that release's branch for the same key where it lists one. It also checks that the branch isn't frozen or purged. On resuming, it accepts the freeze its own approval made.
  - **Digest.** A person approves the plan's digest, `text(trunc160(sha256(canonical(plan))))`. `plan` is `{ "release": <the release document's revision path>, "batches": [{ "ns", "source", "config"?, "items": [{ "resource", "ifMatch" | "ifNoneMatch", "steps" }] }] }`, and has no other members:
    - the batches are in submission order, with their members as §7.5 sends them but before any sealing;
    - each step is its plaintext patch set, without fresh `$nonce` ops and without a fresh top-level `$nonce` in the value of a root operation, or `"delete"`;
    - a precondition on an earlier batch's result is written `{ "batch", "item" }`, or `{ "batch" }` for its config id, with indices from 0, in place of an id.
  - **Approval.** It fails if planning again doesn't give the same digest. Approving freezes every listed branch. Each `source.at` stays the branch's `ns_id` before that freeze, and unfreezing a branch invalidates the plan.
  - Each step is classified again, with a dry run, right before it is submitted, and stops for a new approval if it differs from the approved plan.
- [ ] **MRG-17** (Merging, steps 1–4) Batches are ordered in four steps:
  1. Schema resources, by fast-forward only, in `$ref` order. A schema resource the base changed since `at` is a conflict.
  2. Catalog changes that narrow access. A change goes here when, for every subject, the roles at every node afterwards are a subset of those before, judged by the test of §B.11.4 on the step-2 batch as a whole, whoever merges, `catalog-admins` included. A folder the release creates goes here too, with its own `$access`, when a narrowing move needs it; the subset test then applies to the items moved into it, not to the folder itself.
  3. Content branches, in any order.
  4. Catalog changes that widen access: new placements, and the remaining moves and `$access` edits.

  A branch that holds both schemas and content merges its schema resources in step 1 and its content in step 3. An end-to-end schema namespace isn't branched for a release.
- [ ] **MRG-18** (Merging, reported conflicts) Before submitting anything, the merge service reports these as conflicts for a person:
  - a catalog node whose change narrows access for some subjects and widens it for others, resolved with two resolution sets, one narrowing for step 2 and one widening for step 4;
  - a content item that step 3 creates or restores and that a placement in the catalog base already names, unless step 2 removes that placement, or the release keeps it unchanged and its approver accepts that;
  - a pinned `x-ref` or manifest entry naming a revision of another listed branch that the merge replays rather than fast-forwards;
  - a document resolving a draft in a branch the release doesn't list.
- [ ] **MRG-19** (Merging, stored plan) The merge service stores the whole plan, both halves of every split node included, before it submits step 2. A merge that stops part-way resumes from that plan and never reverts, and until the step-4 batch the stored plan, not classification, decides what is left of a split node. Catalog batches are submitted by authors the catalog base lists in `merge.authors`. Every branch records `merged` only after step 4, with `at` the target's `ns_id` after the last batch into it.
- [ ] **MRG-20** (Several releases, The merge lock) The merge service merges one release per catalog base at a time, under the lock `merge-lock.{catalog}` in the release namespace. Releases on one catalog base keep their documents in one namespace.
  - The lock's document is `{ "holder": <the merge service's sub>, "plan"?: <plan digest> }` while held, and `{}` while free.
  - It is taken by compare-and-append, each take setting `holder`: the first take is a create with `If-None-Match: *`, and later ones an append with `If-Match` on a free head.
  - The holder sets `plan` with a further compare-and-append once the plan is stored, and releases the lock with an append back to `{}`.
  - A resuming service replaces `holder` with its own `sub`, by compare-and-append, only if the lock's `plan` is the digest of the plan it stored. Any other held lock is released by a person.
- [ ] **MRG-21** (Rebasing, Abandoning) Rebasing a release creates a successor of each branch and lists them in a new revision of the release document.
  - The schema successor is created with `drafts.for` naming the other successors, in its creation `patches`, and is replayed first.
  - A resource whose entries reference a draft that had to be replayed is squashed into one resolution set against its new base.
  - An abandoned release's branches are frozen with `abandoned: true` by an administrator.

## Addendum G — Federation and portability

### §G.1–§G.2 Principles and external consumers

- [ ] **FED-1** (One canonical origin, Checkpoint, Verification, Access) Every deployment has one canonical origin, published at `GET /`. An external consumer stores its checkpoint as `(origin, ns, ns_id)`. It verifies revisions through their log (`/r/{ns}/{name}/rev/{id}/log`), by recomputing ids back to a revision already verified, and the namespace chain entry by entry from the checkpoint; it MUST verify when it fetches through a cache or mirror it doesn't control. Private namespaces need a `read` grant from the source deployment.

### §G.3 Remote branches

- [ ] **FED-2** (Creating one) A remote branch on B is a new namespace, created with B's deployment operator key by `PATCH /ns/{name}` with `If-None-Match: *` and a genesis that sets the remote `base: { origin, ns, at, chain }`.
  - Its namespace document is B's own, with nothing copied from A's configuration, and MUST require nonces if A's does (`422` otherwise). No `branch` entry is written on B.
  - B checks that `origin` isn't its own, that `at` is in A's chain, verifies A's namespace log up to it, and checks that `chain` names A's namespace, then its base, and so on, as of `at`; `422` otherwise.
  - If A's namespace, or a base in its chain, is purged, creation is `410 purged` (§8.5). If A's deployment doesn't answer, or answers `5xx`, creation is `502` (`upstream`).
- [ ] **FED-6** (Schemas, at creation) Unless the source is end-to-end, B at creation reads A's `/ns/{ns}/rev/{at}/heads` once, collects the `$schema` and `$ref` closure of every resource, and mirrors each schema resource's history, up to the referenced revisions, into the namespace of the same name on B.
  - A referenced revision that doesn't resolve in its own namespace fails creation with `422` `schema_unavailable`.
  - B creates a missing namespace with the genesis document `{ "read": "public" }` if its source is `public` (§2.1), and `{ "read": "grant" }` otherwise. A mirror, created or existing, that ranks below its source (§2.1) is `422`.
  - If that namespace on B is a branch, or holds a resource at one of those paths whose chain neither contains A's nor is a prefix of it, creation is `409 name_conflict`; if it refuses the history, creation fails with that refusal.
- [ ] **FED-7** (Reading through) B answers for untouched resources as A did at `at`, under its own URLs, and resolves a read-through `$successor` on B.
  - It uses only A's immutable URLs (`/ns/{ns}/rev/{ns_id}` and its `/log` and `/heads`, `/r/{ns}/{name}/rev/{id}` and its `/log`, `/r/{ns}/{name}/blob/{bid}` or the `…/e/{e}` URL it redirects to), and `POST /ns/{ns}/keys` for an E2 source, or for an E3 one's epochs from before its raise.
  - B verifies each listed head against A's namespace log up to `at`, each revision through its log, and each blob against its id, using the reference that names it. Where A's namespace is itself a branch, B verifies each read-through head against the log of the base that wrote it, following `base` and `at` recursively, and can't create the remote branch (`422`) if it can't read those bases.
  - Clients reading an E3 remote branch accept read-through ciphertext whose `pl.ns` is in `chain`.
  - A lazy fetch that fails is `502` (`upstream`) for that resource.
- [ ] **FED-8** (Registration) B may register the branch on A with `POST /ns/{ns}/branches`, `{ "remote": { "origin", "ns" }, "at" }` and `If-None-Match: *`, which is `412` only while an unexpired registration of the same `remote` exists.
  - A renewal sends `If-Match` with the `ns_id` of the latest entry for that `remote`, expired or not (`412` otherwise), and the same `at` (`422` otherwise). Success is `201` with `X-Namespace-Revision`.
  - A retry by the same principal, whose `If-Match` names the entry before the latest, or with `If-None-Match: *` where the latest is its own, unexpired, with the same `at`, gets `200` with the latest.
  - Registration needs unrestricted `read` and `export` on A, and is evaluated as an `export` envelope whose `doc` is `{ "remote": { "origin", "ns" }, "at" }`.
  - `origin` MUST be an `https` origin, or `http` for a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), and `at` MUST be in A's chain (`422` for either).
- [ ] **FED-9** (Registration, Registrations expire) A appends a `branch` entry with `remote` for each registration and renewal, and lists it in `/branches` as `{ remote, at, ns_id, expires }` only, `expires` as an RFC 3339 time. Remote entries don't count toward `branchesPerNamespace`. Consumers, janitors and merge services MUST NOT fetch from a `remote` entry automatically. A registration protects A's history from pruning only for `remoteRegistration`, counted from its latest `remote` entry.
- [ ] **FED-10** (Purges) On a `purge` in A's namespace log, B MUST apply §8.3 locally: its own chains for that name, its own branches and its cache tags; on `purge-ns`, the same for every name A had at `at`. Purges in A's schema namespaces don't reach the schemas B mirrored.
- [ ] **FED-11** (Merging back, Rebasing) Merging back is a batch on A, classified by ancestry as in §F.3 and submitted by a principal with a grant on A, with `source: { origin: <B's origin>, ns: <branch>, at }`, recorded as asserted. A's gate checks every item, and fast-forwards reproduce B's ids.
  - Schema revisions created on B are exported to A first, as a full-history bundle, or items referencing them fail with `schema_unavailable`.
  - Blobs that B's revisions reference and A doesn't have are uploaded to A first by the principal that submits the batch.
  - Rebasing is §F.5 on B, with the new branch based on A's current head.

### §G.4 Bundles

- [ ] **FED-3** (Format, Full-history lines, Digest) A bundle is newline-delimited JSON (`application/vnd.patchlog.bundle+jsonl`): each line is canonical JSON followed by one `0x0A`, and a bundle with any other line is rejected. The first line is the header, followed by one line per entry.
  - Full-history lines are resource log entries (§7.1), of kind `rev` or `tombstone`, with `ns` and `resource`, and with authorship members only as Authors (below) allows. They come in chain order per resource. Every id is recomputed, and the last line per resource MUST be that document's `docs[…].head`.
  - Every `docs` entry MUST have lines, and every line naming a resource MUST have a `docs` entry; any mismatch rejects the whole bundle.
  - A chain starts at genesis or right after its `requires` id. Chains exported from a branch include the base's entries back to genesis, or name the foreign parent in `requires`. `ns` is always the exporting namespace.
  - A bundle's digest is `text(trunc160(sha256(b)))`, `b` its bytes as written.

  **[vectors I.9]**
- [ ] **FED-12** (Snapshot lines, Blob lines) A snapshot line carries the document and its source id, one per `snapshot` document, and its `snapshot` MUST be that document's `docs[…].head`. A document tombstoned at the source is `{ …, "snapshot": <tombstone id>, "deleted": true }`, without its document.
  - Blob lines carry every blob that an exported document references, from any exported revision of a `full` document or from a snapshot, each once per resource, with `nonce` if it has one, before the first line that mentions it: one whose patches carry its id as a `$blob` member or as the value of an operation whose path ends in `/$blob`, whose snapshot document references it, or whose declared list names it.
  - `data` is written in base64url without padding; readers accept either. The importer recomputes each blob id, and a mismatch rejects the bundle. An incremental bundle MAY leave out blobs that the history up to `requires` already references.
- [ ] **FED-13** (`requires`, Authors, `written`, `key`) `requires` applies only to `full` documents, and `requires[r]` MUST be in the target's chain for `r`; if the target has moved on along another line, `r` is a conflict.
  - Authors, `via`, grant ids, author signatures, creation times, `gesture` and `undoes` are included only with `"authors": true`. History lines then carry `grant: gid`, and the bundle carries one grant line `{ "ns", "grant": gid, "root", "stored", "key"? }` per grant its lines name, before the first line that does, its `ns` the namespace whose entry first recorded the grant, in the form of `written`.
  - An exporter that can't fetch a grant leaves `grant` off the lines that would name it. A line naming a grant with no earlier grant line, a second grant line for one grant, or a grant line in a bundle without `"authors": true` rejects the bundle.
  - A line for a revision written in a namespace other than the exporting one carries `written`, that namespace's name or `{ "origin", "ns" }`. An exporter that can't determine it writes the line without `written` and without `grant`.
  - `key` is `{ "kid", "alg", "pub" }`, the key entry the grant's root block verified against at the source: a key of the namespace document in force at the first entry that recorded the grant (in a branch, or of its local bases' then), or else an operator key in force at the `created` of the first revision naming the grant; an exporter that can find neither leaves it out. A tool that holds the source's namespace log, or its operator key history, checks `key` at the revision's position; otherwise it reports the signature as attested, not verified.
- [ ] **FED-14** (Never exported, Consistency) Purged content is never exported. Each namespace is exported as of its own `at`, taken when the export starts.
- [ ] **FED-15** (Selection and dependencies) The dependency closure always includes the `$schema` of every exported revision, the `$ref` inside those schemas, and the blobs those revisions reference. A reference to a schema revision existing only in a branch can't be exported (`schema_unavailable`), unless that schema's namespace is declared `external`.
  - It also includes fields marked `x-ref` in the documents' schemas: a pinned reference needs that exact revision, and a live one the head as of the export's `at`.
  - Dependencies left out with `external` are checked by the importer to exist in the target, by id for pinned references and by name for live ones.
  - The closure doesn't follow `$successor`.
- [ ] **FED-16** (History or snapshot, table) A `full` document carries every revision, or those after `requires`, and keeps its source ids; a `snapshot` document carries the head document only. Schemas are always `full`. Everything a `full` document reaches through `$schema`, `$ref` or a pinned `x-ref` MUST also be `full`, and a pinned reference to a revision other than a document's head forces `full` for that document.
- [ ] **FED-4** (step 1 Check the bundle, step 2 Classify) An import first checks the bundle, `requires` and `external` included against the target, and writes nothing if this fails. Full-history documents are classified by ancestry:
  - missing in the target: created with the whole chain, keeping its ids;
  - the target has an ancestor: a fast-forward;
  - the target already has it, or has moved beyond it: nothing;
  - a different history: a conflict;
  - purged in the target: nothing, reported.
- [ ] **FED-17** (step 3 Import snapshot documents through an upstream namespace) Snapshot documents are imported through `{ns}-upstream`, one per source namespace, written only by imports from one origin. A name that breaks §3.6, or a bundle from another origin than the imports that wrote it, is refused at step 1.
  - Each import appends to each snapshot document there one revision, `diff(previous snapshot, new snapshot)`, or a genesis the first time. For a deleted document it appends a tombstone where the upstream document is live, and otherwise writes nothing. An empty diff writes nothing, and diffs ignore `$nonce`.
  - Where the target or the upstream namespace is sealed, or the upstream namespace requires nonces as its target does, each generated patch set carries a fresh `$nonce`.
  - The first time, the target fast-forwards from upstream, or conflicts if it already has the document. Later, the base is the upstream revision recorded in the previous import batch's `source.ids`, and the upstream revisions after it are replayed onto the target's head, conflicting where they overlap the target's own changes (the array rule of §F.3); a deletion conflicts if the target changed the document.
  - Pinned references in snapshot documents that point at other snapshot documents are rewritten to the matching `/r/{ns}-upstream/{name}/rev/{id}`, keeping any `#{id}` fragment. The dry run lists undeclared strings that have the form of a revision path.
- [ ] **FED-18** (step 4 Dry run, step 5 Order, Rewriting waits for its targets, Partial failure) Conflicts are resolved as in §F.3: skip the document, take the bundle's version, or replay. Batches that change existing dependencies are dry-run first; appends to an upstream namespace don't count as such.
  - A batch goes once every batch holding a revision it pins, schemas included, has committed; live references order nothing; batches that write the same resource chain through `ifMatch` and go in order.
  - A document's references are rewritten only after the batches of its dependencies have committed, using the ids they returned.
  - For a promotion that changes existing dependencies and isn't submitted as one batch, the tool dry-runs each later batch that moves heads the target had, reports as deferred any failure that wouldn't occur once the earlier batches are written, and skips a batch that continues a chain an earlier one cuts.
- [ ] **FED-19** (Size, Blobs first, Missing namespaces) An import tool paces its batches, dry runs included, at a fraction of the lower of the namespace's and its own principal's rate, or, under an allowance, at most at the allowance's full rate, counting dry runs, per-resource buckets still applying. With several batches in flight, a request is paced as drawing at the moment it is sent.
  - The blobs a batch's steps' values mention are uploaded before it by the importer, or copied with `Blob-From` within one deployment, unless the batch's local `source` already makes them available. An import that will submit uploads a batch's blobs before that batch's dry run, and one that only dry-runs uploads none. A snapshot document's blobs go to both its upstream resource and its target.
  - Under authentication, missing namespaces, upstream ones included, are created by the operator before step 1.
- [ ] **FED-20** (Renaming) An import that maps source namespaces to new names (`src=dst`) rewrites every reference to a mapped namespace: `$schema`, `$ref`, pinned and live `x-ref` values, a `$successor` of the form `/r/{src}/…` and the value of an `add` or `replace` at `/$successor` in a history line, and pins to revisions, which take the new ids.
  - Documents of unmapped namespaces in the bundle that reference a renamed one are rewritten too, and a reference that only a later revision's schema declares is rewritten in that revision by an added `replace`.
  - A full-history document's rewritten steps are submitted one by one with new ids, never fast-forwarded, and `source.ids` records the source ids. Catalog placement names aren't renamed. The dry run lists undeclared strings naming a mapped namespace.
  - A renamed namespace's snapshot documents go through `{dst}-upstream`.
  - Mapping onto a branch whose `base` chain reaches `src` keeps references and ids.
  - Refused at step 1: an incremental document that would change, whose `requires` names a source id; a full-history document's pin whose new id isn't known, because its target is `external`, left out, or a snapshot document's revision.
  - Where nonces are fresh, a re-run recognises its earlier writes by the import batches' `source.ids`.
- [ ] **FED-21** (Source, step 6 Today's rules judge old history, Authors) Each import batch's `source` is `{ "origin", "ns", "at", "bundle": <digest>, "ids": { name: upstream or source id } }`, without `origin` when the bundle's `origin` is the target's own, and the importer is recorded as author and signs its own steps. A full-history import replays every step through the target's current gate, as the importer, at the current `now`.

### §G.5 Encryption

- [ ] **FED-5** (`access`, Importing) Exporters MUST include `access` in the header, giving each exporting namespace's protection as a source (§2.1): `"public"`, `"private"`, `"sealed"` or `"e2e"`.
  - At step 1 the importer refuses a bundle that would put a namespace's lines into a target, or into that target's upstream namespace, that ranks below that namespace (§2.1), unless an operator explicitly overrides this for that import.
  - An importer that holds an `e2e` target's keys MAY import a source that isn't `e2e` into it by sealing each patch set client-side, encrypting each blob as in §E.3.1 and rewriting its references to the new blob ids; pins to them, incremental documents and later imports are then handled as for a renamed import (§G.4.4).
- [ ] **FED-22** (Importing, No snapshots at E3) An `e2e` source goes only into an `e2e` target with the same namespace name, override or not. Its lines carry the ciphertext and the plaintext `keyring` verbatim, and ids verify as usual.
  - At step 1 the importer refuses a bundle with a blob line that lacks the sealed type or has a nonce, or with a `rev` line other than the `keyring`'s whose `patches` are neither one `sealed` op whose `pl.ns` and `kid` name the line's `ns` nor a restore's `[]`.
  - A target created for the import starts at the bundle's lowest epoch and is moved up one epoch at a time as its keyring lines arrive, so the importer needs `config` on the target, with a `*` key. An existing target is moved up the same way, and is refused at step 1 if its `keyring` would conflict with the bundle's, or if its epoch is below the bundle's lowest or above that of a line it lacks.
  - Documents of an `e2e` source are exported `full`, and an importer refuses snapshot documents for an `e2e` target at step 1.
- [ ] **FED-23** (Sealed bundles: Envelope line, Lines, Checks, Digest, What stays visible) A sealed bundle (`application/vnd.patchlog.sealed-bundle+jsonl`) starts with `{ "sealedBundle": 1, "id", "recipients": [{ "kid", "suite", "wrapped" }] }`.
  - `id` is 128 random bits in base64url without padding. The 256-bit content key `K_b` is wrapped for each recipient as in §E.2.3, but with the `info` `"patchlog-bundle-v1" ‖ 0x0A ‖ id`, `id` as its 22 ASCII characters. Each recipient's `kid` is its thumbprint.
  - Each following line is a JWE compact under `K_b` with `alg: "dir"` and `enc: "A256GCM"`, whose protected header carries `pl: { "bundle": id, "line": n, "last"?: true }`, `last` on the last line only, and whose plaintext is bundle line `n` (header = 0) as canonical JSON without its newline. Lines are never compressed.
  - A reader MUST reject the whole sealed bundle if any line fails to decrypt, if `pl.bundle` differs from `id`, if line numbers are not 0, 1, 2… in order, or if no line says `last` or a line follows it, and then checks the decrypted bundle as in §G.4.1.
  - Padding applied to a line's plaintext is removed before these checks and the digest. `source.bundle` is the digest of the decrypted bundle.
- [ ] **FED-24** (Remote branches, E2 sources, E3 sources, Epoch start times) B MUST refuse (`422`) to create a remote branch whose `read` or level §7.4 would refuse for a local branch of its source, or whose source's namespace document it can't read.
  - B likewise refuses a config write that makes the remote branch `public`, raises it to `e2e` or turns off a `nonce` requirement its source has, judged by its source's current namespace document, read for that write, and refused as creation is where it can't be read (§G.3).
  - B MUST raise its level when it sees its source do so in the log it follows, as far as Levels allow, raising its own dependents first, leaves first.
  - For an E2 source, B fetches keys from A with its own key pair and grant, mirrors the plaintext, and seals what it serves under the branch's own epoch keys.
  - For an E3 source, B mirrors ciphertext and the `keyring` verbatim, verifies ids over the ciphertext, and skips §G.3's schema step. The branch's name MUST NOT be in `base.chain` (`422`). Read-through content keeps the source's name in `pl.ns`, and B relays the source's keys from the mirrored keyring through `POST /ns/{branch}/keys`.
  - B chooses which epochs it relays to a grant (§E.2.3) by the epochs of the source's namespace documents and the start times its namespace log gives them. For the keys B hands out itself, those of a source's epochs from before its `e2e` raise, B reads the start times only from A's origin or caches A controls, never from a mirror or other intermediary.

## Addendum H — Files

### §H.1 What a file is

- [ ] **FILE-1** (Raw files, table, Which kind a new file is, Empty files) Every file other than a JSON file is a raw document, its bytes kept exactly. Its `type` is taken from the file name's extension, in any letter case, by the table; for an extension the table lacks, or none, from the upload's `Content-Type`, parameters dropped, if it is given and isn't `application/octet-stream`, `binary/octet-stream`, `application/x-www-form-urlencoded` or `multipart/*`; otherwise, for an existing file, the type it has, and for a new one `application/octet-stream`. At E3 the reference's `sealed` member holds the file's `type` and `size`, and its own are the sealed blob's. A `text/` type needs a body in UTF-8, a leading BOM allowed; any other body gets `application/octet-stream`. A new file whose name ends in `.json` (in any case) and whose body is I-JSON, which here is what §3.1 accepts (a leading UTF-8 BOM dropped), is a JSON file, and any other new file is raw. An existing file keeps its kind: a JSON file accepts only I-JSON, a leading BOM dropped (`400` otherwise), and a raw file any bytes. An empty body makes or truncates a 0-byte raw file, except over a JSON file (`400`) and under a new `.json` name; that, and a `LOCK` of a new name, is held by the gateway as a placeholder, listed as a 0-byte file, until a body arrives and decides its kind.
- [ ] **FILE-7** (JSON files) A JSON file's rendering is the canonical JSON text of the document without a top-level `$nonce` of the fresh form and without a top-level `$successor` of the form of §8.1, laid out as ECMAScript `JSON.stringify(value, null, 2)` lays it out: every member and element on its own line, indented two spaces per level, `": "` after member names, `,` at line ends, empty objects and arrays as `{}` and `[]`, LF line ends, and one final LF; tokens, member order included, are exactly JCS's. Its type is `application/json`. **[vectors I.10]**
- [ ] **FILE-8** (Writer's bytes, Nonces, Identity) Every tool shows a document as the same rendering. A gateway that serves a writer its own bytes back serves them under the weak `ETag` `W/"{id}"`, which a gateway takes like the strong one in any `If-Match`, as a save's base (§H.4) and as a delete's or move's precondition (§H.5). Where nonces are required or the namespace is sealed, a JSON file's root must be an object carrying `$nonce`, and a gateway refuses any other root there (`422`, saying why); a raw file's root carries `$nonce` beside the reference, and its blob a `Blob-Nonce`. A file's `ETag` is its item's head revision id. A raw save is always stored with the uploaded value, and a JSON save when the stored document's rendering parses to it. After a save the gateway merged with others' edits, the next `GET`, `HEAD` or `PROPFIND` of the file is answered in full, whatever validators it carries.

### §H.2 Trees

- [ ] **FILE-2** (A file tree is a catalog, Folders, Files, Untrusted namespaces, Shape) A file tree is a catalog `C` whose `catalog` object carries `"files": { "ns", "root", "folder"?, "placement"? }`: `ns`, the content namespace new files are created in; `root`, the node name of the folder whose children are the tree's top level, created without parents; `folder` and `placement`, schema revision paths that new folder and placement nodes carry as `$schema`. A gateway takes any item in `files.ns` to be placed only in this tree, and doesn't also serve `files.ns` as a writable flat folder. Folders are folder nodes with opaque names without a dot, named in the tree by their `title`; files are placements named `{ns}.{item}`, named by the placement's `title`. A node without a non-empty string `title` is shown by its item's name, or a folder by its node name. A file tree doesn't set `catalog.title`; where one does, tools read titles from the placement documents, never from listings. Placements of items in namespaces `C` doesn't trust are left out, whether a tool lists through the tree service or from the node documents. File trees set `catalog.mode: "tree"`: a file or folder has exactly one parent, inside the `root` subtree, and new nodes get an `order` after their last sibling.
- [ ] **FILE-9** (Titles) Titles are Unicode in NFC, 1 to 255 bytes of UTF-8, never `.` or `..`, and without `/`, `\`, NUL, characters of the categories `Cc`, `Zl` and `Zp`, or U+202A–U+202E and U+2066–U+2069; other `Cf` characters are allowed. A gateway converts names it receives in NFD to NFC, refuses a trailing space or dot on create and rename for every client, and shows an existing one escaped. A title that breaks these rules is shown with each offending character, a trailing space or dot, and a whole `.` or `..` percent-encoded as UTF-8, the stem shortened so the name stays within 255 bytes; an escaped name never takes the name of a real title, and is numbered as a duplicate instead, within 255 bytes.
- [ ] **FILE-10** (Siblings) Files and folders in one folder share one set of names, compared after NFC and, unless the gateway is set to be case-sensitive, after Unicode simple case folding. Tools refuse to create a name a visible sibling has; the source of a `MOVE` isn't its sibling, so a rename that only changes case is allowed. A `PUT`, `COPY` or `MOVE` to a name that matches a sibling only under another case is `409`, naming the sibling, and sets a guard, unless the request carries a tag or the user read or wrote that file under this spelling; `MKCOL` under another case is `405`, and a folder in the middle of a path matches whatever its case. A duplicate left by a race is shown as `name (2).ext`, `name (3).ext`, … in order of the nodes' `born`, then node name, the first keeping its name, a number that would collide with a real title skipped, and the stem shortened so the name stays within 255 bytes.
- [ ] **FILE-11** (Access) In a catalog with tree-derived access, a user's rights to read, place and move come from the catalog's grants and `/read-grants`, not from a grant on the content namespace.
- [ ] **FILE-12** (Flat view) In the flat view, a namespace is one directory whose file names are resource names: a raw document as its name, any other document as `{name}.json`. If a raw resource `x.json` and a document `x` both exist, the raw file keeps its name and the document is shown by the duplicate rule. The flat view has §3.6's names and no folders, and a rename is a copy and a delete. A new file whose resource is tombstoned, where §H.6 doesn't restore it, restores it with a root `replace`, except one whose last revision has a `$successor`, which is `409`, naming the new path. A new file whose resource is a live document shown under another file name is `409`, naming that file.

### §H.3 Listings

- [ ] **FILE-13** (In a tree, A folder too large to list whole, A tree service that is behind, Read-your-writes) In a tree, a folder is listed from the tree service's `children` listing, with `total`, the top level from `roots` where `root` is hidden from the user, and a path of titles resolved with its `lookup`; a case-sensitive gateway lists the folder instead when the answer's title differs in case. A tree service following a file tree adds to each placement of an item in a namespace the catalog trusts `file: { "size", "type", "modified"? }` from the item's head (for a raw file the blob reference's `size` and `type`, for a JSON file the length of its rendering and `application/json`, and `modified` the head's `created` where known), sealed as a value of another resource for items in sealed namespaces, or `{ "absent": "e2e" }` for an end-to-end item and `{ "absent": "pending" }` for a head it hasn't read yet, which a tool reads from the core. A folder too large to list whole is refused (`403`, saying why), never listed cut short; a path inside it still resolves by `lookup`, or is `403` in a sealed or end-to-end catalog. A tool passes on a tree service's `503 behind` and deletes nothing on the strength of a listing meanwhile. A tool sends the `X-Namespace-Revision` of each of its writes, the catalog's and the content namespace's, as `?min` on later listings, kept and dropped as §A.5 says.
- [ ] **FILE-14** (In the flat view, Where times are absent, Sealed and end-to-end catalogs) In the flat view, a directory is listed from the `head` rows of `/heads`, tombstones and purges left out, with `ETag` from `target` and the time from `created`; a JSON file's size is its rendering's, not `/heads`' `size`, and a raw file's the blob reference's `size`, at E3 its `sealed.size`. Rows without `created` take `Last-Modified` from the document read for the size; in sealed and end-to-end namespaces a gateway with keys takes times from the logs. A gateway without a sealed or end-to-end catalog's keys doesn't offer the tree.

### §H.4 Saving a file

- [ ] **FILE-15** (Names before writes) Before any write, a tool checks the names it resolved from a listing against the node documents, found through the catalog's `/heads`: each node still in its folder under that name, and no node under a name the listing lacked; where they disagree, it resolves the path from the node documents. A folder's emptiness is taken only from the node documents. A grant that can't read them keeps the listing's view for names, and deletes no folder (`403`). A name the tree service's filtered listing lacks is never revealed or edited: a `PUT` onto a name only a hidden sibling has creates a new file.
- [ ] **FILE-3** (The base, Records, Several records, The reload) The base of a `PUT` is the revision named by the client's `If-Match` (its first value, `W/` dropped) or, failing that, its `If` header (the first tag of the first list that applies to this resource and isn't negated with `Not`); an older tag is the starting point of a rebase, not a failed precondition. `If-Match: *` asks only that the file exist, and the head is the base. A tag naming a revision where the path holds no file is `412`, and one naming a revision of a flat resource another user has since deleted is `409`. An unknown revision is `412`, and a pruned one `409`, as is a recorded base below a horizon or a pruned range between base and head; a read that fails fails the save (`503`, `502`), never taking the head as the base. Without a tag, a gateway that keeps records keeps them per user and path, records nothing for a `304`, `HEAD` or `PROPFIND`, counts a save that changed nothing as no write, and keeps them for a day, a path whose records expired counting as evicted; a save at a path that now names another document, or none, is `409`, and a `GET` of the path is the reload; the user's own `DELETE` or `MOVE` forgets the path, except a move to a scratch name; when the budget is full the oldest records other than the first and the latest write go first, and a path whose records were evicted is `409`, while one never recorded takes the head as its base. A JSON save is checked against every recorded version, each taken as the base, and is `409`, naming the paths, if any two would give different documents, except that a save without a tag that sets back a value someone else changed is merged, keeping the other value. The reload a `409` asks for is a full read by the refused token (`200`, not `304`), which becomes the path's only record, and a refusal re-arms nothing for the user's other tokens; after a `409` because someone else deleted the file, the `404` is the reload and the next save restores the file as §H.6 does, except one whose last revision has a `$successor`, where the save is `409`, naming the new path. With no base at all, the head is the base.
- [ ] **FILE-16** (Others' writes, JSON files, Raw files) `theirs` is the writes of the log entries between base and head by other users, leaving out the user's own; a value changed and changed back is still a conflict. A JSON file is saved as a patch set from the base's rendering to the new file, parsed, keeping the base's `$successor`, with `add /$nonce` carrying a fresh value where §C.7 asks for one; a write anywhere inside an array counts for the whole outermost array. A patch set over `opsPerSet` or `patchSetSize` becomes a root `replace` carrying the fresh `$nonce` and any `$successor` if the base is the head and the namespace isn't end-to-end, and is `413` otherwise. A raw save conflicts only if someone else changed the bytes, or deleted or restored the file, after any version the user had; the body is uploaded as a blob (`413` above `blobSize`, before any upload) and the reference's members set one by one with `add`, `replace` or `remove` (`/$blob`, `/type`, `/size`, `/nonce`, and at E3 `/sealed`), with a fresh `/$nonce` where nonces apply, never the root; a `412` retry reuses the pending blob; bytes are compared by blob id.
- [ ] **FILE-17** (New files, Partial writes) A new file in a tree is created only where `C` trusts `files.ns`. Where grants come from the catalog, the tool places first, then uploads the blob of a raw file and creates the item with `If-None-Match: *`, deleting the placement if the create fails; otherwise it dry-runs the placement as a one-item batch before any upload, then uploads, creates the item and places it, and removes the item at once if the placement fails. Nobody else deletes an unplaced item younger than `blobGrace`. A `PUT` with `Content-Range` is `400`, and so is a body cut short; nothing is written. `POST` to a file is `405`, with `Allow`.
- [ ] **FILE-18** (Answers, table) A gateway answers: a save stored with the uploaded value, `201` or `204` with the new revision as `ETag`, even where the rendering's bytes differ from the upload's; one merged with others' edits, `201` or `204`, no `ETag`; an overlap with others' edits since the base, a delete or restore by another user between base and head, a pruned base, records that disagree or were evicted, a path that now names another file, or a file moved away, `409`, naming the paths; `If-None-Match: *` on a live file (but see the move-aside), `If-Match` naming an unknown revision or where the path holds no file (a flat resource another user deleted excepted), or `Overwrite: F` on an existing target, `412`; a new name that breaks the title rules or ends in a space or dot, or that isn't a resource name in the flat view, or a new file where `C` doesn't trust `files.ns`, `403`, saying why; a `422`, `401` or `403` of the core or the tree service, that answer with its message, or `502` naming the service where the user can't fix it; a frozen namespace, `403` naming the successor, never `423`; purged, `410`; rate limited or a service behind for longer than a client waits, `503` with `Retry-After`; a tree service that can't be reached, `502`; a limit exceeded (the core's `413`, or `422` with `code: "limit"`), `413` as `too large: {limit} {measured} > {max} (§6.6): {message}`, a limit without sizes named alone, and a `413` that names no limit keeping the core's text; a bound of the gateway's own, `413` in the same shape naming its setting, `measured` a lower bound where reading stopped; the gateway's memory for scratch files or locks full, `507`.

### §H.5 Deleting, renaming, moving and copying

- [ ] **FILE-4** (Delete a file, Delete a folder) Deleting a file deletes its placement, then, where the tree owns the item and the grant allows `delete` there, the item; otherwise the item stays. The delete carries `If-Match` on the head the tool read: a client's `If-Match` that isn't the head is `412`, and the gateway's own delete finding the head moved since its read is `409`. A folder is deleted only without visible children, taken from the node documents, and is `409` otherwise, naming those children and nothing hidden from the caller. Dangling placements aren't contents: the gateway deletes those it can first, and the rest, like placements the user can't see, don't stop the delete and become orphans.
- [ ] **FILE-19** (Rename or move within a tree, Move onto an existing file, Moves that copy, Move to a scratch name, Across trees or namespaces, Copy) A rename or move within a tree is one append to the node's `title` or `parents`, with `If-Match`, beginning, under a Move grant from the catalog, with the `test` of `/parents` it requires, after checking that the node's document still has the name and parent the path named (`404` otherwise); the new parent must be inside the `root` subtree, and not the node itself or a descendant of it (`403`). On any `MOVE`, a client's `If-Match` names the source, and one that isn't its head is `412`, as for a delete. A move onto an existing file (`Overwrite: T`, or absent; `F` is `412`) is a save of the source's content into the target, its base taken as §H.4 says, though never from `If-Match`, which names the source, then a delete of the source. A `MOVE` or `COPY` onto an existing folder, or of a folder onto a file, is `403` (`412` with `Overwrite: F`). Moves that copy check first that the source can be deleted, then copy, then delete the source with `If-Match` naming the revision copied; a source that changed since is `409` and stays, and a delete that fails anyway leaves the copy. After a move to a scratch name the file stays live, and the next create-only `PUT` of the original path by the same user within 30 seconds is accepted once as an edit, its base taken as for any untagged save. When the item goes to another namespace, its last revision before the tombstone carries `$successor`, unless it is a JSON file whose root isn't an object. A copy is a new item with the source's current content and a placement for it; a `COPY` onto an existing file (`Overwrite: T`) is instead a save of the source's content into the target, as for a move onto it. A folder is copied, or moved to another tree, as a new folder node titled with the destination's last segment, without the source's `$access`, its visible children then copied or moved into it one by one (`Depth: 0` copies the folder alone), and a moved folder deleted once empty; a failure part-way leaves what was done, with no rollback, and is answered as that child's request would be. A raw file's blob is copied with `Blob-From` where §7.8 allows it, and otherwise its bytes are uploaded again: decrypted with the reference's key from an `e2e` source, and encrypted under a fresh key, with a new id, into an `e2e` target.

### §H.6 Clients as they are

- [ ] **FILE-5** (Scratch files, Delete, then write) Files named `.DS_Store`, `._*`, `Thumbs.db`, `Icon` followed by CR, `~$*`, `.~lock.*#`, `*.swp`, `*.swo`, `*.swx`, `4913`, `*~`, `#*#`, `*___jb_tmp___`, `*___jb_old___`, `.goutputstream-*`, or `sed` followed by six letters or digits, and folders named `(A Document Being Saved By …)`, `.Trashes`, `.Trash`, `.Trash-*`, `.Spotlight-V100`, `.fseventsd`, `.DocumentRevisions-V100` or `.TemporaryItems`, are kept by the gateway in bounded memory, never written to the core; no other folder is scratch, and an existing node with such a name is a real file. Copy names such as `x copy.txt` and `x (1).txt` are real names in a tree, and in the flat view scratch only as `COPY` destinations, a plain `PUT` of one being `403`. A write to a path the same user deleted within the last 30 seconds restores that file (its placement, then its item) rebased on its last live document, as a whole-document `replace` when its patch set would exceed `opsPerSet` or `patchSetSize` and its base is the last live document; if the restore is refused (`403`, `410`), the write creates a new file or is refused as such a write would be; a file whose item has `$successor` is never restored this way. If such a write is refused, the user's delete, never one older than 30 seconds, is undone where it can be. A refused `PUT` or `COPY`, a refused move onto a file, or a refused case variant sets a guard: that user's `DELETE` of that path within the next 10 seconds is `409`, once per refusal; a `DELETE` with `If-Match` passes and leaves the guard; a refused plain move sets none, two refusals never share one guard, a guard ends only by time, and none is set after an undo.
- [ ] **FILE-20** (Locks, Dead properties, Listings, Headers, Status codes) Locks are kept by the gateway, per user, bounded, and never sent to the core; a `DELETE` drops the user's locks on the path and below, and a `MOVE` or `COPY` sent with the source's lock token isn't `412` for want of a lock on the destination. Dead properties are refused, or kept by the gateway per user and scope up to a bound past which the least recently set path's are dropped, moved with a `MOVE` and dropped with a `DELETE`; never acknowledged and kept nowhere. A `PROPFIND` of `Depth: infinity` is `403` (`propfind-finite-depth`), and one without `Depth` is `1`. A gateway serves raw files itself, under the revision's `ETag`, never as a cross-origin redirect, and every response it gives carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, PDFs excepted from the sandbox as in §7.8. `423` and `507` are used only for what they mean.

### §H.7 Access and encryption

- [ ] **FILE-6** (Grants, Users) A gateway either passes each user's grant through as the bearer of every core request, or holds its own grant and narrows it per user with `via`; a gateway with its own grant doesn't serve a tree with tree-derived access, and in other trees hides from each user what that user's narrowed grant can't read. A user is the root `sub` with the `key` that verified the root block, from `GET /ns/{ns}/principal`; a user's own entries are those whose `grant` has its `sub` and a `kid` that named its `key` when written, and, in a tree with tree-derived access, those in content namespaces whose `grant` has its `sub` and a `kid` that named the catalog's key there. With authentication disabled, a user is an `X-Author`, and its entries those with that `author`. Operator grants are never users of a gateway (`403`). With a narrowed gateway grant, the user is the one the gateway named in `via`, and a user's own entries are only those the gateway recorded writing for it. A gateway that uses one bearer for everyone is one user, and programs sharing one grant count as one.
- [ ] **FILE-21** (What a user's tokens share, Re-checking) Guards, the user's own deletes, move-aside marks and records are per user. Scratch files, placeholders, locks with their owners and dead properties are kept per user and scope (the root block without `kid`, `sub`, `nbf`, `exp`, `at`, `enc` and `signers`, and the narrowing blocks without `nbf` and `exp`, with `ns`, `can`, `roles` and `groups` compared as sets), and served only to a token of that scope whose grant names the namespace. Caches of what was read are per token. Each kind of per-user state is bounded per user; a new scope when content scopes are full is `503` with `Retry-After`, never a drop of one holding content. A gateway creates state for a grant only after the core has accepted it, bounds the users it keeps state for, re-checks a grant at least every five minutes, relies on a `writer` block for 30 seconds at most and reads it again after `409 frozen`, `422 nonce` or a limit refusal, and stops serving a token the core refuses, keeping the user's state for the user's other tokens, each re-checked at its next request.
- [ ] **FILE-22** (Limited grants, Catalog writes, Sealed and end-to-end namespaces) A grant limited to some resources lists only in a tree with tree-derived access, through the tree service, and the gateway learns what it needs to write, and the tree's settings, from `GET /ns/{ns}/principal`. Catalog writes carry a fresh `$nonce` where the catalog requires nonces or is sealed. A gateway without keys doesn't offer sealed or end-to-end namespaces, and never shows their files as writable empty files.

## Addendum I — Test vectors

### §I.1 Canonical JSON (§3.1)

- [ ] **VEC-1** (table, member order) An implementation of §3.1:
  - accepts `{"a":1,"b":2.0}`, `{"a":1e2}`, `{"a":9007199254740991}`, `{"a":1000000000000000000000}`, `{"a":1e21}`, `{"a":1e300}` and `{"a":0.1}`, with the canonical forms I.1 shows;
  - answers `400` to `{"a":9007199254740992}`, `{"a":-9007199254740992}` and `{"a":1,"a":2}`;
  - sorts members by UTF-16 code units, so `{"b":1,"a":2,"ä":3}` becomes `{"a":2,"b":1,"ä":3}`, and keys with characters above U+FFFF sort by their surrogate pairs.

### §I.2 Ids (§3.2–§3.5)

- [ ] **VEC-2** (table, namespace chain) An implementation of §3.2–§3.5:
  - reproduces the text forms and bytes I.2 gives for the genesis `g` of `patches₁`, its child `c` by `patches₂`, and the tombstone of `c`;
  - reproduces `ns_id₁` for `entry₁` with an empty previous id, and `ns_id₂` for `entry₂` after `ns_id₁`;
  - rejects the four text ids I.2 marks rejected.

### §I.3 Blob ids (§3.7)

- [ ] **VEC-3** (table) An implementation of §3.7 gives the 15 bytes `hello patchlog\n` of type `text/plain` the id `1m5jj344d7tz7cicfmq53ayhmwuubpmyt` without a nonce, and `1hdwkfub2zymqzgc75snybxosfk67633s` with the nonce `aaaaaaaaaaaaaaaaaaaaaaaaaa`.

### §I.4 Grant ids and author signatures (§C.3, §C.3.1)

- [ ] **VEC-4** (root block, signing input, signature) An implementation of §C.3 and §C.3.1:
  - gives I.4's root block the grant id `15swdvi5nbnlkv76v7y6k77h52atov6ru`;
  - computes the signing input for origin `https://cms.example`, `ns` `matches`, `name` `derby`, parent `g` and `patches₂` as `43bba3f8e86bdd96435153ddb0d704cab7e5e9459087f3fd78c157b6a7102c54`;
  - verifies I.4's signature `Ed25519:key-1:…` under the public key `RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM`, listed under `kid` `key-1` in a grant's `signers`. The signature is Ed25519 (RFC 8032), over the 32 raw bytes of that digest.

  A tombstone's signing input uses the ASCII bytes `tombstone` in place of `canonical(patches)`.

### §I.5 Edge-grant cookies (§C.5.3)

- [ ] **VEC-5** (cookie, rejected claims) Take an implementation of §C.5.3's default format, with I.5's key and a clock before `exp`. It gives the claims `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}` the name `__Secure-pl-eg-4390e78526d94754` and the value I.5 shows. An edge using that format ignores:
  - claims with a fourth member;
  - claims that aren't canonical byte for byte;
  - a MAC that verifies only over a re-encoding of the claims;
  - a name that doesn't match its `p`;
  - an `exp` in the past;
  - a `p` that covers the path only as a string prefix.

### §I.6 Padding buckets (§E.2.2)

- [ ] **VEC-6** (table) An implementation of §E.2.2's padding pads a plaintext of `L` bytes to the length I.6 gives:
  - 1, 255 and 256 to 256;
  - 257 to 272;
  - 300 to 304;
  - 511 to 512;
  - 513 to 544;
  - 1000 to 1024;
  - 4096 to 4096;
  - 1000000 to 1015808;
  - 1048576 to 1048576;
  - 67108864 to 67108864.

### §I.7 Per-resource keys (§E.2.1)

- [ ] **VEC-7** (derivation) An implementation of §E.2.1 derives the 32-byte `K_r` `37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25` for `K_e` the bytes `00 01 … 1f`, `ns` `demo` and `name` `derby`.

### §I.8 Subject sets and combined checkpoints (§B.5, §B.11.5)

- [ ] **VEC-8** (subject set, combined checkpoint) A service implementing §B.5 and §B.11.5:
  - gives the subjects `["group:match-desk","user:anna"]` the `gs` `17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm`;
  - gives the checkpoints `{"cat":"1vmctae4vewju6nvxi374rkrkmyzpdrif","matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"}` the combined checkpoint `1vwnfnoyshruyx4lul4a25rtctooiph5v`.

### §I.9 Bundle digests (§G.4.1)

- [ ] **VEC-9** (digest) An implementation of §G.4.1 gives the two lines of I.9, each followed by one LF, the digest `1b3a64kkqf3o6f3rglkgi6ok5hgldbne6`.

### §I.10 File renderings (§H.1)

- [ ] **VEC-10** (rendering) A tool that claims Addendum H renders I.10's document as the 118 bytes shown, with sha-256 `c7e8bfb3ff3fed1b111dda8cce06b4f2c1b7615565e828f4777ebf63055e887c`. The fresh `$nonce` is left out, and `"10"` comes before `"2"`.

## Security regression scenarios

These are end-to-end security cases, each a setup, a request and the expected answer, with the passages that decide it. The spec's text governs: a case that disagrees with it is an error here.

### Protection: content moving between namespaces

**Invariant.** Content never becomes readable, in the clear or by key, to a reader who couldn't read it at its source. Within one namespace, between equal ranks, or upward, a move that a writer's grants allow must work. Only a key-holding importer, or an operator override for one import, may move content downward or across levels.

1. Private source, public target → `PUT …/blob/{bid}` with `Blob-From` → `404` (§2.1 Protection, §7.8 Copying)
2. Private source, sealed target with `read: "public"` (ranks `public` as a target) → `Blob-From` copy → `404` (§2.1, §7.8)
3. Sealed source with `read: "public"` (ranks `sealed` as a source), plain public target → `Blob-From` copy → `404` (§2.1, §7.8)
4. Two resources of one sealed namespace with `read: "public"`, a caller whose grant gets keys for an epoch the blob is served under → `Blob-From` between them → `201` (ranks apply only between namespaces); a caller without such keys → `404` (§2.1, §7.8)
5. Private source, private target, a caller that may read the source resource → `Blob-From` copy → `201`, checked as an upload of the source's type, nonce and size (§7.8)
6. A caller that fails the source's read check, `401` and `403` cases included → `Blob-From` copy → `404`, revealing nothing (§7.5 Reading other namespaces, §7.8)
7. Merger with unrestricted `read` on the branch → merge batch with a local `source` referencing the branch's blobs → `201`, no copy needed (§7.8 Availability, §F.3 Blobs)
8. Merger that reads the branch only per resource → merge batch without copying first → the blob references are `422 blob`. Copying first with `Blob-From` → `201` (§7.5 `source`, §F.3 Blobs)
9. Private branch, public base, merger → copy a branch blob into the base → `404`. Uploading the bytes again → `201`, since a merge publishes on purpose (§F.3 Blobs, §2.1)
10. Batch with a local `source` whose caller lacks unrestricted `read` on `source.ns` → batch referencing the source's blobs → source recorded unchecked, no blob available, `422 blob` (§7.5 `source`, §7.8)
11. Remote branch on B, A's private `schemas` → mirror into an existing public `schemas` on B → creation `422` (§G.3 step 3, §2.1)
12. A's `schemas` sealed with `read: "public"`, missing on B → remote-branch creation → mirror created `{ "read": "grant" }`, and creation succeeds (§G.3 step 3)
13. A's `schemas` public and unsealed, missing on B → remote-branch creation → mirror created `{ "read": "public" }` (§G.3)
14. Bundle with `access: { "matches": "private" }` → import into a public target, or into its public `{ns}-upstream` → refused at step 1, unless an operator overrides it for that import (§G.5.1, §2.1)
15. Bundle whose `access` lacks a namespace → import → that namespace counts as `private` (§2.1, §G.5.1)
16. `sealed` source, sealed target with `read: "public"` → import → refused at step 1. Into a sealed target with `read: "grant"` → accepted (§2.1, §G.5.1)
17. `e2e` source → import into a non-`e2e` target, or into an `e2e` target with another name, override or not → refused (§G.5.1)
18. Public source, `e2e` target, importer holding the target's keys → import → allowed, each patch set sealed client-side, blobs re-encrypted, ids change (§G.5.1)
19. `PATCH /ns/{name}` with `If-None-Match: *` and a genesis setting a `base` without `origin` → `422`, so no namespace reads a local base through without a `branch` entry and the base's checks (§7.4 Branch fields)
20. Gateway copying a raw file within a tree → blob → `Blob-From` where the ranks allow it, otherwise the bytes are uploaded again (§H.5 Copy)
21. A sealed namespace with `read: "public"`. A writer in an unsealed private namespace knows a blob id and a resource name, holds no grant for the source, and so gets no keys → `Blob-From` copy → `404` (a sealed source needs a grant that §E.2.3 would give the resource's key)
22. Same sealed source with `read: "public"` → batch with a local `source` naming it, by a caller without keys → its blobs are not made available, `422 blob` (§7.8 Availability)
23. Sealed source with `read: "grant"`. A reader may read the resource, but no served epoch of the blob is one its grant gets keys for (`nbf` window, `historyEpochs`) → `Blob-From` into an unsealed private namespace → `404` (§7.8, §E.2.3)
24. Private branch `release-7` of a public base → rebase per §F.5 step 1 (successor created with `patches: []`), then replay → the successor gets the old branch's `read`, and a replay into a successor that ranks below the old branch is refused (§F.5, §2.1)
25. Grant fixed to `old` and `new` with `create`, `append` and `delete` only, and `old` has blobs → in-namespace move (`Blob-From`, then the batch) → the copy is `404`, so such a move also needs `read` on `old` (§7.8 Copying, §8.1 Moves)
26. A public, private or sealed source, full history → import into a sealed target, whose writers must refresh `$nonce` in every patch set → history without fresh nonces can't be replayed, so it goes in snapshot mode (§G.4.4 step 6, §E.2.5)
27. Namespace raised `sealed` → `e2e`, a caller with unrestricted `read` whose `/keys` window starts after the raise → batch in a public namespace with a local `source` naming it, referencing a nonce-less blob from before the raise → not made available, `422 blob` (§2.1, §7.8 Availability)
28. Sealed base `matches` with `read: "public"`, branch `release-7` created without a `read` patch (so sealed, `read: "public"`, ranking `sealed` as a source) → rebase per §F.5 step 1 → successor created with `read: "grant"`, and the replay works. With `read: "public"` (ranking `public` as a target) the replay is refused (§F.5, §2.1)
29. E3 branch, merger who reads it per resource → `Blob-From` copy of a branch blob into the `e2e` base before the merge batch → `201`: equal ranks, and only an import's lines stay under their own name (§2.1, §F.3 Blobs, §F.8.1)
30. Sealed branch with `read: "grant"` → rebase into a successor that the base's current document leaves unsealed, given `read: "grant"` → replay allowed: `private` = `sealed` (§2.1, §F.5)
31. Import under an operator override into a lower-ranked target in the same deployment → `Blob-From` of the source's blobs → `404`, since the override is the tool's, not the server's. The importer uploads them, or a caller with unrestricted `read` on the source names it as the batch's local `source` (§7.8, §G.4.4 Blobs first)
32. Gateway `COPY` of a raw file from an `e2e` namespace into one that isn't, or into an `e2e` namespace from one that isn't → `Blob-From` is `404` (ranks) or the upload `415` (check 4) → the gateway uploads the file's plaintext, decrypted with the reference's key, or, into `e2e`, encrypted under a fresh key with a new id (§H.5, §E.3.1)
33. Private source, public target, a caller who may read the source resource, whose blob Reading serves there → `Blob-From` copy → `404`, each condition of §7.8 Copying refusing on its own (§2.1, §7.8)
34. Base `N`: name `x` created after `n5`, purged at `n9`. Branch `L` created afterwards at `n5`, by a creator whose branch readers can't read `N` → `GET /r/L/x` → `404`, as for a branch at `n5` that existed before the purge, and `L`'s `/heads` doesn't list `x` (§8.3, invariant 7)
35. Deployment B, `PATCH /ns/{name}` with `If-None-Match: *` and a genesis whose remote `base` has B's own `origin` → creation → `422`, so no namespace reads a local base through without a `branch` entry and the base's checks (§G.3, §7.4)
36. Public sealed `schemas` (`read: "public"`, E2); a writer in `docs` with no grant for `schemas`, or with one whose key window starts after revision `X`'s epoch → write in `docs` whose `$schema` is `/r/schemas/match/rev/X` → `422 schema_unavailable`, with no validation errors from `X` (§6.1 Read permission, §2.1)
37. Remote branch `B` on deployment D, whose server lacks `sealed`, of source `N` on A, raised to `sealed` after `at`; a caller with unrestricted `read` of `B` → batch into public `pub` on D with local `source: { "ns": "B", … }`, referencing a blob of a resource `B` now answers `502` for → not made available, `422 blob` (§1 Conformance, §7.8 Availability, §2.1)
38. Remote branch `R` on B of A's private `matches`, created with `read: "grant"` → a config write on B setting `read: "public"`, under a `*` key → `422`, as for a local branch. The same for a remote branch created while A was public, once A's current namespace document is private (§G.5.2, §7.4)
39. Remote branch `R` on B of A's `matches`, created with `read: "grant"`; A unreachable, or B's grant on A expired → a config write on B setting `read: "public"` → `502` (`upstream`) or `422`, never applied (§G.5.2, §G.3)
40. Remote branch `R` on B of A's `matches`, which requires nonces, so `R` was created requiring them → a config write on B setting `"nonce": "optional"` → `422`, as for a local branch, judged by A's current namespace document (§G.5.2, §7.4, §C.7)
41. Sealed source `matches`; snapshot import into a private unsealed target `matches` through a sealed `matches-upstream` (ranks `sealed` = `private`, so step 1 accepts it) → each generated upstream patch set carries a fresh `$nonce`, so upstream ids can't confirm guessed content (§G.4.4 step 3, §E.2.5)

### Tree-derived access (§B.11, used by Addenda A and H)

**Invariant.** No request widens any subject's roles at any node, as judged at its grant's decision, except one by `catalog-admins`. A hidden node is indistinguishable from a missing one to every request but a `catalog-admins` organising one, except where the text names `409` because names aren't secrets. Only a role that counts through the catalog's key (its `can`, `roles`, `groups`, `sub` and `rules`) grants, shows or powers anything. A listing URL serves a reader only the subject set its credentials prove.

Personas and folders are those of the §B.11 worked example:
- **Folders:** `season-2026` (`match-desk: desk`, `translators: translator`, `fan-club` and `user:li`: `reader`), and TR, the "Transfer rumours" folder (`inherit: false`, `editors-in-chief: desk`).
- **Content:** `matches.derby` is placed in `season-2026`.
- **Roles:** `desk` lists `create` and `restore`.

1. desk (bob) → Create a folder `previews`, `to: [season-2026]` → grant: the new name is exempt from the `404`, and bob has `move` at `season-2026`. The same with `to: [TR]` → `404`, since TR is hidden from him (§B.11.4 Create a folder)
2. Folder F without `$access`, parents P1 (`group:a: desk`) and P2 (`group:b: desk`), a caller only in `a` → Place into F → `403`, since powers are judged per subject (§B.11.2 Tree powers)
3. Caller not in `catalog-admins` → Create a folder or Place with `to: []`, or Move, rename, unplace or delete a node without parents that it can see → `403`. The same for a root hidden from it, such as the example's `root` → `404` (§B.11.4 answers, §B.11.5)
4. Caller in `catalog-admins` → the same requests → granted, with no tree power needed. A hidden or orphaned node can be named (§B.11.4, §B.11.5)
5. Reader → `children`, `ancestors`, `subtree`, `where`, `manifest` or `lookup` naming a hidden node → the same `404` as a node not in the catalog. Nothing about it appears, not even as a count (§B.5 Parameters, §B.11.5)
6. desk → unplace a dangling placement whose item doesn't exist yet → judged as if the item were live, so it is visible, and `move` at `season-2026` passes → grant (§B.11.5, §B.11.4)
7. desk → delete folder `previews` (no `to`) → grant fixing `/doc/parents` to its current parents (§B.11.4 Unplace or delete)
8. Non-admin → delete a cyclic folder → `404`, since a cyclic node is left out of access and so hidden. Any caller → ask the catalog service to restore a folder → `404`, as for any tombstoned node; `catalog-admins` restore folders under grants of their own (§B.5 Cycles, §B.11.4)
9. Place of an item in a namespace the catalog doesn't trust → `403`. An existing placement of such an item dangles and grants no `create` or `restore` (§B.11.4, §B.5, §B.11.2)
10. Caller with `move` at both `season-2026` and TR → Move `derby` into TR → `403`, since `group:editors-in-chief` would gain `desk`: no widening (§B.11.4)
11. `derby`'s placement was deleted → a caller who sees TR, has `place` there and is in the place list (an editor-in-chief also in `match-desk`) asks to Place it into TR → `403` (it widens against the frozen rows); bob, from whom TR is hidden → `404`. Into `season-2026` → restore-only grant. If the placement is live again when used, the write is an append, refused at step 2 (§B.11.4 Place, §B.11.7)
12. `derby` deleted → anna (translators) → Restore `derby` → `403`, since `translator` doesn't count for `restore`. With `derby` live → `409`, after the read check she passes (§B.11.4 Restore)
13. desk → Move `derby` to its current parents (a rename) → grant that may change other members, `$access` excepted (§B.11.4 Move, §B.11.3)
14. Identity provider issues `sub: "group:editors-in-chief"` → `POST /grants` → that `sub` is not a subject, so the group's roles aren't collected (§B.11.2 Subjects)
15. Content namespace whose catalog key lacks `read` in `can`, or whose key scope `rules` admit only `/resource` matching `^pub-` → listing → the items the key can't grant `read` for are hidden, titles and heads included (§B.11.2 Through the key, §B.11.5)
16. Content key with `rules: [/principal/roles minItems 1]` → a catalog grant carrying no `roles` → `403` at the gate. Listing visibility evaluates that rule with the tested role as `/principal/roles`, so items stay visible (§B.11.3, §B.11.5)
17. Public catalog whose combined checkpoint includes a private namespace or a `read: "grant"` preview branch → listing → served under `/g/{gs}`, never at the public `/{catalog}/at/…`. A tree service without §B.11 serves only `g/all`, and `403` otherwise (§B.11.5, §B.5)
18. A grant in `Authorization` at another subject set's `/g/{gs}` → `403`. A request needing `/g/{gs}` with neither a grant nor a verified cookie → `401` (§B.11.5)
19. `g/all` exchange → only public namespaces are exempt from the namespace-wide check. A `g/all` cookie at an `at` that includes a namespace absent from the checkpoint at issuance → `403` (§B.11.5)
20. Index: two readers without block rules, roles `pub-reader` (`^pub-`) and `news-reader` (`^news-`) → `GET /_refs` → different `gs`, since the digest covers effective role rules (§A.4)
21. `POST /read-grants` naming a catalog node → `400` in a catalog that is neither sealed nor end-to-end, and `404` if the node is hidden (§B.11.5)
22. File gateway on its own grant, narrowed per user with `via` → a tree with tree-derived access → not served. In other trees it hides from each user what that user's narrowed grant can't read (§H.7 Grants)
23. desk → Create a folder whose name a hidden folder has or had → `409`, since names are not secrets. The same holds for a Place of an item whose placement is live but hidden (§B.11.4)
24. Self-placing item (`$parents` naming a wide folder) kept in a narrow folder by an explicit placement → a caller with `move` there deletes the placement → no widening: a deleted explicit placement still wins over `$parents` (§B.9, §B.11.2)
25. `derby` is deleted, then its placement is moved into TR, or `match-desk` is removed from `season-2026` → bob → Restore → `403`. A role counts only if it counts both in the frozen rows and at the placement now (§B.11.4 Restore)
26. bob holds a Move grant for `derby` from `season-2026` to a new folder `cup`, and an editor-in-chief then moves `derby` into TR → bob sends the move → refused, since the grant pins the parents it was judged from (§B.11.4 Move)
27. anna (translators, whose `translator` role has a `writes within` rule) → `children?of=season-2026` → listed, since the role's rules don't refer to `/resource` (§B.11.5)
28. li, whose only visible folders sit under a hidden `root` → `roots`, `ancestors?of=matches.derby` → `season-2026` is listed as a root for li's subject set, and paths end there (§B.11.5)
29. desk → Move `cup` under its own descendant `cup/sub` → `403` (§B.11.4 Move)
30. Organising grants → `POST /grants` for Place, Move, Unplace → `can` of `create`, `append` or `delete`, with no `roles` (§B.11.4)
31. A reader of TR with `move` at `season-2026` → §H.5 `COPY` of TR into `season-2026` → the copy carries no `$access`, so `fan-club` can read the embargoed content (§H.5) — open: §B.12
32. Folder `leaks` (no `$access`) under `season-2026` holds `derby`; bob holds a Move grant for `derby` from `leaks` to `cup`; an editor-in-chief who also has `move` at `season-2026` then moves `leaks` into TR (a narrowing, allowed) → bob sends the move → its `test` of `/parents` passes and `derby` leaves TR's subtree for `cup`, readable by `fan-club` again: an overtaken judgement, stated in §B.11.8 and bounded by a Move grant's `exp` within `maxLag` of its decision (§B.11 Invariant, §B.11.8)
33. Catalog that derives access from `$parents` in `matches`; `derby` self-placed in TR, no explicit placement → bob, in the place list, with `place` at `season-2026`, to whom `derby` is hidden → Place `derby` into `season-2026` → `404`, as for an item not in the catalog. An editor-in-chief also in `match-desk` and the place list → the same Place → `403`: judged as a Move from its `$parents`, it widens (§B.9, §B.11.4, §B.11.5)
34. Same catalog; `derby`'s explicit placement in TR is purged by an operator not in `catalog-admins`, and `derby`'s `$parents` names `season-2026` → listings and grants → `derby` stays out of `season-2026`; the purged placement still wins (§B.9)
35. `desk` in `matches` has a rule `not /resource ^secret-`, so every folder is hidden from bob, who still has `move` at `season-2026` → bob asks to unplace `derby` (visible to him) → `403`, naming nothing (§B.11.4, §B.11.5)
36. Index over a private `matches`; a reader whose rules limit it to `^pub-` → `q=transfer` → the scores of its hits don't change when a hidden `secret-x` gains the word. `fields=/salary`, marked only by the schema of hidden documents → `400`, as for a path no schema marks (§A.4)
37. Catalog `cat-pub` and every content namespace it follows `read: "public"`, unsealed → `GET /cat-pub/at/{at}/children?of=season-2026` without credentials → every child listed, unfiltered. In a public sealed catalog, a node's `K_r` still comes from `/read-grants` only through the role check (§B.11.5)
38. TR file `x`, `season-2026` file `y`; a caller who reads `x` and may append to `y` → `MOVE x` onto `y` (`Overwrite: T`) → `y` holds TR's content, readable by `fan-club`, and `x` is deleted (§H.5 Move onto an existing file) — open: §B.12
39. li, to whom `root` is hidden → gateway `PROPFIND /`, `Depth: 1` → the top level is `roots` for li's subject set (`season-2026`), and `lookup` resolves `Season 2026/…` from there; a new top-level file (`to: [root]`) → `404` (§H.3, §B.5, §B.11.5)
40. Index over a private `matches`; a reader whose rules limit it to `^pub-` → `facet[/salary]=x`, `counts=/salary` or `sort=/salary`, where `/salary` is marked only by the schema of hidden documents → `400`, as for a path no schema marks (§A.4 Fields in hits)
41. A `catalog-admins` member writes placement `matches.derby` with `parents: [{ "href": "/r/cat-season/ghost" }]`, where `ghost` never existed, so the parent dangles and `derby` has no roles → bob (`move` at `season-2026`) → Create a folder `ghost`, `to: [season-2026]` → `409`, as for a name a node has or had. Otherwise the dangling edge re-attaches and `fan-club` and li gain `reader` on `derby`, `match-desk` gains `desk` (§B.11.4 Create a folder, §B.11 Invariant, §B.3)
42. Private `matches`; `derby` purged; its placement remains in `season-2026` → a caller with no role at that placement → `POST /grants { "item": "/r/matches/derby", "want": ["restore"] }`, or `want: ["append"]` → `403`, as the core answers anyone who doesn't pass the read check (§8.3). A `reader` there → `410` (§B.11.4 Restore)
43. Placement `matches.derby` purged in `cat-season` → a caller not in `catalogs.cat-season.place` → Place `derby` into `season-2026` → `403`; a caller who passes the place checks → `410` (§B.11.4 Place)
44. Catalog branch `cat-season-r7` moves `derby` from TR into `season-2026`, so `fan-club` and li gain `reader` on it. The plan's approver isn't in `catalog-admins` → the merge goes through the catalog service → refused (`403`), as that person's own Move would be. An approver in `catalog-admins` → the batch is submitted under a `catalog-admins` member's own grant, never under a merge-key grant (§F.8, §B.11.4, §B.11 Invariant)
45. Release step 4 places the new `matches.final` into `season-2026`. The approver isn't in `matches`'s `catalogs.cat-season.place`, or has no `place` at `season-2026`. Or the release's catalog batch deletes a placement in a folder where the approver has no `move` → catalog service → `403`, as for that person's own Place or Unplace (§F.8, §B.11.4)
46. Folder F has no `$access`. Its parents are P1 (`group:a: desk`) and P2 (`group:b: desk`). A member of `b` with `move` at P2's parents deletes P2 → a caller only in `a` asks to Place into F, or to Move a node out of F → `403`, as before the delete: a tombstoned parent gives no power, so deleting a node never widens (§B.11.2 Tree powers)
47. `derby` is placed only in TR, so it is hidden from bob. `opener` exists in `matches` but has no placement in `cat-season`. bob → `POST /read-grants { "items": ["/r/matches/derby", "/r/matches/opener"] }` → both items are refused alike (`403`), so the answer doesn't show that `derby` is placed (§B.11.5, §B.11.4, §B.11 Invariant)
48. End-to-end catalog `cat-season`; a catalog branch `cat-season-r7` moves `derby` → the merge service asks the catalog service to check the batch and issue a merge grant → `404`, `not_offered`, as for organising requests in an end-to-end catalog. No merge grant is issued (§F.8, §B.11.4)

### Encryption levels and epochs

**Invariant.** An epoch key reaches only grants whose window covers that epoch. Content sealed at one level is never later served under a weaker level or a newer key. Levels never go down: a namespace is raised only above dependents already raised, and a branch never reads below its base (a remote one once it sees the raise) or across a raise. A sealed payload binds its namespace, resource, revision or parent and epoch, and readers check that binding.

1. Config write lowering or removing `encryption.level`, or raising `sealed` to `e2e` without incrementing `epoch` → `422 invalid` (Addendum E Levels, §E.2.1)
2. Raise to `sealed` while `schemaReads` is set, or to `e2e` while `drafts`, `"nonce": "required"` or a `retention` rule with `"archive": false` is set → `422` unless the same write removes them (Levels)
3. Raise of a base above a live or frozen dependent's level → `409 in_use` with `dependents`. Public base whose public branch was raised to `sealed` first → raising the base to `sealed` → allowed (§7.4, Levels)
4. Base `N` raised `sealed` → `e2e` at `n8` → branch created at `n7` → `422`. At `n9` → `201` (Levels, Branches of a raised base)
5. Branch `Z` at `n9`, reader with unrestricted `read` → `POST /ns/Z/keys` → `N`'s pre-raise epochs as at E2, `K_r` derived with `N`'s `ns`, within the reader's `nbf` window. Readers accept `N`'s `ns` in `pl` and `kid`. A remote branch fetches the same keys from A's `/keys` with its own grant (Levels, §F.8.1, §G.3 Reading through)
6. Namespace raised `sealed` → `e2e` → pre-raise revisions, log entries, namespace documents and log ranges (evicted ones sealed again), grants and blobs → served sealed under the last pre-raise epoch and `pad`, and blobs keep their `…/e/{e}` URLs. Raised from `at-rest` → served in the clear, with no epoch redirect (Levels, §7.8 Reading)
7. Raise to `e2e` made by a batch's `config` → namespace log range or resource log range across it → no page spans it. It ends before the `batch` entry, or in a resource log before the first entry written with or after it (Levels)
8. After an `e2e` raise → an append keeping a plaintext pre-raise blob → `422` (only sealed blobs are declared). A restore with `[]` → keeps the last live document's list, plain blobs included (Levels Later writes, §E.3.1)
9. Grant first recorded before a raise from `sealed` → `GET /ns/{ns}/grants/{gid}` at E3 → sealed. One first recorded after → in the clear, `private` (§C.3.1, §E.4)
10. `/keys` at E2: grant `nbf` after a rotation made by a batch's config change → window starts at that batch's epoch. `nbf` before the namespace was sealed → its first epoch. No `nbf` → the current epoch only (§E.2.3 Which epochs)
11. E3 branch → `/keys` → relays the base keyrings' entries for base epochs up to `at`, each starting at the epoch that base had in force at the latest `nbf` (or at `at` if earlier), never by `epochs` (§E.2.3 At E3)
12. Writer grant first recorded in epoch 3, reader window starting at 6 → reader verifies a signature → reported unverifiable, never an error about the content (§E.2.3, §C.3.1)
13. Grant recorded only by a branch's base → branch serves `/grants/{gid}` → sealed under the branch's current epoch (§E.2.2 table, §C.3.1)
14. Public sealed namespace, grant failing the `ns` check or unusable → `POST /ns/{ns}/keys` → `403` or `401`, never ignored like a public read (§7)
15. E3 `keyring` entry wrapped by the server or an untrusted admin, or two entries for one `kid` and `to` → client fetches keys → seals only under a key whose `from` it trusts. The duplicate write → `422` (§E.3.2 Keys)
16. Root block `enc` with a member besides `kty`, `crv` and `x` (e.g. a private `d`) → any request → `401` (§C.1, §E.2.3)
17. E3 write whose `sealed` op's `kid` isn't the epoch in force, whose header carries `zip`, or whose `pl` names another namespace, resource or parent → `422 invalid`. The op is sealed under `K_r` (§E.3.1, §E.2.2 Compression)
18. E3 prune in a branch whose chain's newest `sealed` op is a base's → `snapshot` with the base's `kid` → `422`. It must carry the branch's own epoch (§E.3.1)
19. `e2e` bundle → import with a plaintext pre-raise `rev` line, an unsealed or nonced blob line, or into an existing target whose epoch is below the bundle's lowest or above a line it lacks → refused at step 1, before anything is written (§G.5.1)
20. Remote branch of an E3 source → creation → §G.3's schema step skipped. A branch name that is in `base.chain` → `422` (§G.5.2)
21. E3 writer limited to some resources (no unrestricted `read`, no fixed names) → `/keys` → `200` with the keyring entries wrapped to its `enc`, without reading `keyring` (§E.2.3 At E3)
22. E3 branch reader → read-through ciphertext of another revision of the same resource and epoch, served under `/r/{branch}/{name}/rev/{id}` → rejected: `pl` is compared in full, and only a base's `ns` is accepted (§E.2.2)
23. Namespace raised from `sealed`, resource chain wholly from before the raise → E3 prune `snapshot` → `kid` is the pre-raise epoch the revision is served under, so a reader whose window starts after the raise still can't open `H` (§E.3.1)
24. Namespace raised `sealed` → `e2e`, writer whose `/resource` rules don't fix names → `/keys` → `200` with its keyring entries, leaving out the pre-raise keys it wouldn't get at E2 (Levels, §E.2.3)
25. Remote branch `R2`, `sealed` at `n5`, after A raises to `e2e` at `n8` → epoch rotation, freeze or switch to a successor on `R2` → `201`. Only creation, and a raise to `e2e`, are checked against the base's level (Levels, §G.5.2)
26. Existing `e2e` target `matches` with its own keyring entry for `matches#5`, and a bundle from another deployment carrying a different `matches#5` → import → refused at step 1 (§G.5.1)
27. `e2e` branch → full-history bundle (read-through lines bound to the base's `pl.ns`) → same-named target → refused at step 1 (§G.5.1, §G.4.1)
28. Key-holding importer seals a source that isn't `e2e` into an `e2e` target → later pins, incremental `requires` and re-imports → handled as for a renamed import (§G.5.1, §G.4.4 Renaming)
29. Remote branch B relays epochs to a grant → epoch start times taken from A's namespace log `created` times, unverified, so they decide only which wrapped keyring entries it receives; keys B hands out itself: line 34 (§G.5.2)
30. Public namespace whose `/ns/{ns}/rev/{ns_id}` documents and `/heads` pages are CDN-cached → raise to `sealed` or `e2e` → the `ns:{ns}` purge removes them (§9, Levels)
31. Remote branch `R1`, at-rest at `n2` → A raises `N` to `sealed` → B raises `R1` to `sealed` once it sees the raise in A's log, so `R1` stops serving `N`'s content in the clear (Levels, §G.5.2)
32. Sealed namespace with `historyEpochs: 0`, rotated from epoch 3 to 6, head of `derby` last written in epoch 3; reader whose grant gets keys for epoch 6 only → search hit or catalog entry for `derby` → its sealed values are under epoch 3, so the reader can't open them, as it can't open `derby`'s head (§E.2.6, §E.2.3)
33. Remote branch `R1` on B, at-rest at `n2`, with a local at-rest branch `R1-x` of `R1` on B → A raises `N` to `sealed` → B raises `R1-x`, then `R1`, to `sealed`, so neither serves `N`'s content in the clear (Levels, §G.5.2, §7.4)
34. E3 remote branch `R` of A's `N`, raised `sealed` → `e2e`; B reads A's namespace log through a mirror that shifts `created` times; a reader on B whose latest `nbf` falls after `N`'s rotation to epoch 5 → `POST /ns/R/keys` → no pre-raise key of an epoch before 5, since B takes those start times only from A's origin (§G.5.2, Levels, §E.2.3)
35. E3 branch `Z` of E3 base `N`, whose own `keyring` has since been written to add `Z`'s epochs; a reader that `N`'s keyring wraps to, whose latest `nbf` is before `at` → `POST /ns/Z/keys` → `N`'s entries for `N`'s epochs up to `at`, as before `Z`'s first keyring write (§E.2.3 At E3, §F.8.1)
36. Remote branch on B, whose server lacks Addendum E (or lacks `sealed`), source `N` on A raised to `sealed` after `at` → read of a read-through resource on B, or of one the branch appended to since → not served in the clear: `502 upstream`. On a server offering only `at-rest`, a config write setting `"level": "sealed"` → `422 invalid` (§1 Conformance, Levels, §G.5.2)
37. Namespace raised `sealed` → `e2e`; `derby` last written before the raise, in epoch 3, then tombstoned after it, or tombstoned and restored with `[]` → E3 prune with `H` that tombstone or restore → `snapshot` `kid` is epoch 3, the epoch its pre-raise document is served under, so a reader whose window starts after the raise still can't open it (§E.3.1, Levels)
38. Remote branch `R1` on B, whose server lacks `sealed`, with a local branch `R1-x` of `R1` on B → A raises `N` to `sealed` → read on `R1-x` of a resource it reads through from `N`, or has written on since → `502 upstream`, as on `R1`, never in the clear (§1 Conformance, Levels)
39. Remote branch `R2` on B, `sealed`, of A's `sealed` `N` → a config write on B raising `R2` to `e2e` → `422`, as a branch field (Levels, §G.5.2)
40. Remote branch `R` on B, whose server lacks `sealed`, of source `N` on A, raised to `sealed` after `at`; a writer on B with `append` → `PATCH` of a resource `R` mirrored before the raise, whose patch set is one `test` op probing a value, or a batch item doing the same → `502 upstream` at step 2.1 of §6.2, never `201` or `422`. A purge of that resource → `204` (§1 Conformance, Levels)
41. Namespace raised `sealed` → `e2e`. `derby`'s revision `H` was written in epoch 3 before the raise and served as `/rev/{H}` with `ETag: "{H}.3"`. → E3 prune with horizon `H` and a client's `snapshot` → `/rev/{H}` keeps serving its stored E2 sealing, unchanged, with `pl` `{ ns, name, id, kind: "doc" }`; the same holds if `H` was never served before (Levels, §E.2.2 Stored once, served forever, §7.1)
42. E3 branch `Z` of E3 base `N`, created at `at` while `N` was at epoch 4; `N` has since rotated to 5. A reader of `Z` whose grant has no `nbf` in any block → `POST /ns/Z/keys` → only `Z`'s entries for `Z`'s current epoch, and none of `N`'s, since `N` has moved past its epoch at `at`. A reader whose latest `nbf` is before `at` gets `N#4` too (§E.2.3 At E3, Levels)

### Grant scope

**Invariant.** A request is allowed only through what every block, the key's scope and at least one effective role allow together. No role, value or block a narrowing step dropped counts. "Unrestricted", "qualifying" and "fixes `/resource`" are judged so that nothing reads more than its rules permit. Members that widen exposure or touch keys move only under a `*` key, or the operator grant that creates the namespace.

1. Root `roles: ["reader", "scoped"]` (`scoped` has a `/resource` rule), narrowed to `["scoped"]` → branch the namespace, or `POST /edge-grants` → `403`: only effective roles count, so there is no unrestricted `read` and no qualifying role for `/r/{ns}` (§2.1)
2. Roles `B` (a `/now` office-hours rule, no `/resource` rule) and `A` (`not /resource = "secret"`), out of hours → `GET /ns/{ns}/log` → `403`. Only roles without `/resource` rules count where unrestricted `read` is needed, and `B` fails (§2.1 Unrestricted read)
3. Roles `A` (office hours) and `B` (no rules), both listing `append`, at night → append → passes, since roles are alternatives at step 1 too (§C.2 items 2 and 4)
4. Grant whose read role has a `/doc` rule → `POST /ns/{base}/branches` → `403`, since a role that counts for `read` passes all its rules against a `read` envelope (§C.2 Unrestricted `read`)
5. Batch item `steps: ["delete", [p1], [p2]]` under a grant with `delete` and `restore`, no `append` → `p2` is an append → `403` (§C.2 Later steps)
6. Key with `readScope: "resource"` signs a roles-only grant (`roles: ["reader"]`, no `can`, no `/resource` rule) → `GET /r/matches/x` → `404`. `GET /ns/matches/log` → `403`. Any write → `403` (§2.1 Fixes `/resource`, §C.2 item 1)
7. `POST /edge-grants`: a grant fixing `{a, b}` with a block rule `not /resource = "b"` → `403` for the whole request, since the rules run per fixed name. A block rule `/action = "read"` → issued, against a `read` envelope (§C.5.2 refusals)
8. `POST /edge-grants`, roles `reader` (no rules) and `desk` (a `/now` rule) → `200`: row 5 checks only block and key-scope rules, and `reader` qualifies (§C.5.2, §2.1)
9. `/read-grants` grant fixed to `derby`, carrying a role whose rule tests `/resource` → `POST /edge-grants` → `200`, since a qualifying role may test a fixed `/resource` (§2.1 Qualifying role)
10. Root block with neither `can` nor `roles`, a block whose `can` lists `*`, or a narrowing block with `ns: ["*"]` → any request → `401`. A narrowing block listing `can: ["read", "delete"]` under a root `can: ["read"]` → a read → `200`, restricting nothing more (§C.1)
11. Config write adding a key with a duplicate `kid`, `alg: "ES256"`, or a `pub` that isn't 43 base64url characters → `422 invalid`. A stored key without `can` → its grants allow no verb (§C.4 Keys)
12. Key with `maxTtl: "PT15M"`, root `exp` a year ahead, and a narrowing block with `exp` 10 minutes ahead → any request → `403`, since `maxTtl` uses the root block. Edge cookies last until the earliest `exp` among the blocks (§C.4, §C.5.2)
13. Key scope `sub: "user:"`, root `sub: "svc:x-user:y"` → `403`: the whole `sub` must match (§C.4)
14. Base key with `requireAt: true`, used in a branch, `at` a base `ns_id` → `403`, since `at` must be in the chain where the grant is checked. Issued at 18:00 with `exp` 18:10 under `maxTtl: "PT15M"`, `at` written at 17:59:30 → passes (§C.4 `requireAt`)
15. Grant with one block rule `{ "all": [ …500 rules ] }` → any request that doesn't ignore it (§7) → `413` (`rulesPerGrant`) before step 1, or before a read's `ns` check, since nested forms count (§12.2, §C.8)
16. Catalog key whose `can` lacks `delete`, grant role `desk` listing `delete` → delete → `403`, since the key's `can` bounds role verbs (§C.2 item 2)
17. Config write overlapping `/keys` that also fails a namespace rule, under a non-`*` grant → `403 forbidden`: the guard runs first at step 6. A namespace's creation under the operator grant whose genesis covers `/keys` → passes the guard (§6.2 step 6, §C.2 `*` keys)
18. `prune` grant without a `*` key → prune below what `retention` keeps (everything, where no rule matches), or where no archive is configured → `403` at the step-6 guard (§8.6, §C.2)
19. Operator grant, or an expired namespace grant, sent to `DELETE /edge-grants` or `GET /` → ignored: `204`, `200` (§C.4 Operator grants, §C.5.4)
20. Key removed from a base, or a block revoked in a base → a request to its branch, or a consumer of the branch verifying a presented grant → `401` at once (§C.4 Keys follow the base, §10)
21. Purged resource, a caller without `read` on it → `GET /r/{ns}/{name}` → `404`, not `410`. A write → the step-1 answer first (§8.3 Responses)
22. Retry of a recorded write under the same root `sub`, but a grant from a rotated `kid` → `412`, not `200` (§7.2)
23. Key with `readScope: "resource"`, grant block rule `{ "not": { "all": [ /resource = "derby" ] } }` → `GET /ns/{ns}/log` → `403`, since a negated `all` doesn't fix `/resource` (§2.1)
24. Key `can: ["read"]`, root block `can: ["read", "append"]` → `GET` → `403`, since the root block fails the key's scope (§C.4)
25. Key scope `attrs` whose schema has `$ref: "/r/schemas/…/rev/…"` or an unknown keyword → config write → `422 invalid`, held to a rule `schema`'s limits (§C.4, §6.4.2)
26. Config write adding a subject to `catalogs.{catalog}.place`, under a grant with `config` but no `*` key → `403` (§7.4 Keys, roles…)
27. A batch whose `config` change revokes a block, or removes a key → the next write under that grant → `401` (invariant 6)
28. Operator creates a namespace whose genesis `rules` require `/principal/groups` to contain `ops` → creation → rules skipped, as for a `*` key (§6.4.3)
29. Audit consumer verifying the grant references of history after a key rotation or revocation → judged at the time of writing, never by today's `revoked` (§C.3.1, §10)
30. Writer in `docs` whose document pins `/r/schemas/…`, with a grant that names `schemas` but isn't signed by a `schemas` key → write → `422 schema_unavailable`, judged as for reading other namespaces (§6.1 Read permission, §7.5)
31. Grant with `can: ["append"]`, no roles and no rules, in a private namespace → `GET /ns/{ns}/grants/{gid}`, `GET /ns/{ns}/branches`, or the namespace log → `403`: unrestricted `read` needs the `read` verb (§2.1, §C.5)
32. Private `schemas` with `schemaReads: { "for": ["docs"] }`, and private `docs` whose document `d` pins `/r/schemas/match/rev/X`. A grant naming `docs` and `schemas`, signed by a `docs` key, that may read `d` → `GET /r/schemas/match/rev/X` with it in `Authorization` → `200`, `private`, judged as a read of `d` (§6.1, §7 step 3)
33. A reader of `matches` whose grant fixes `/resource` to `derby`, who knows gesture `G` and an id `X` of hidden resource `secret` → `GET /ns/matches/gestures/G?after=secret/X` → `404`, as for an entry that doesn't exist (§7.4, §7 step 4)
34. Private branch `x`, which the writer can't read → write in `docs` whose `$schema` is `/r/x/a/rev/1…` → `422 schema_unavailable`, as for a name that doesn't exist (§6.1, §7)
35. Root block with `can: ["read", "append"]` and no `roles`, narrowing block `roles: ["reader"]` → any request → `403`. Effective roles are only those the root lists, here none, and a grant that carries roles needs one that lists the verb (§2.1 Effective roles, §C.2 item 2)
36. Branch writer with `config` but no `*` key → config write setting `abandoned: true` and `frozen: true` → janitor → not purged as abandoned, since the flag counts only if its write's grant chains to a current `*` key of the branch (§F.6 abandoned)
37. Author in a successor, not in the base's `merge.authors` and without a `*` key of the old branch → batch in the successor with `source: { ns: <old branch>, at }`, then a config write on the old branch setting `successor` and `frozen` → janitor → not purged as superseded. The rebase tool counts that batch as an earlier merge (§F.5 step 3), but the janitor doesn't (§F.6 superseded)
38. Merger whose base grant allows `append` but not `restore`, and a fast-forward item whose base head `B` is a tombstone the branch restored → merge batch → `403` at step 2.2, reported as an authorisation failure, since the settled verb `restore` isn't a candidate (§C.2 Settling, §6.2 step 2.2, §F.3 Authorisation)
39. Branch config writer without `*` key → config write setting `merged: { at }` and `frozen: true`, with no merge batch in the base, or with one by a `merge.authors` principal whose `source.at` isn't in the branch's chain → janitor → not purged as merged (§F.6 merged)
40. Private `schemas` with `schemaReads: { "for": ["docs*"] }`; a user with `branch` on public `sandbox` creates branch `docs-x` of it → write in `docs-x` pinning `/r/schemas/match/rev/X`, and an unauthenticated `GET /r/schemas/match/rev/X` → `422 schema_unavailable`, and `401` as for any private revision: a branch never matches `schemaReads.for` (§6.1, §7)
41. Private namespace behind a verifying edge; a reader with a signed-URL edge grant for `/r/{ns}/{name}` → `GET` → the edge strips the parameters and forwards. The origin authorises the read itself from the grant, passed on as its cookie, and answers `200` with edge lifetimes. A request with the verification headers but no credential gets no content (§7 Query parameters, §9 Private namespaces, §C.5.3)
42. Private `schemas` with `schemaReads: { "for": ["docs"] }`; `docs` public and sealed (E2), with `d` pinning `/r/schemas/match/rev/X`; a self-made, unsigned token with `ns: ["docs"]` → `GET /r/schemas/match/rev/X` → `401`, as for any private revision, since only a grant that verifies under `docs`'s keys and may read `d` opens it (§6.1, §7 step 3)
43. Role `reader` (`can: ["read"]`, rule `/principal/attrs/clearance ≥ 3`); grant `roles: ["reader"]`, `attrs.clearance: 1`, no `/resource` rule → `POST /edge-grants` → `403`: no qualifying role (§2.1, §C.5.2)
44. Remote branch `R` on B, of A's `N`. A key that is in `N`'s current document on A but not in `R`'s, and a block revoked only in `N`'s `revoked` on A → a request to `R` under a grant signed by that key → `401`. A grant signed by a key of `R` with that block revoked only on A → accepted, since revocation is per namespace and B judges only its own and its local bases' `revoked` (§C.4, §7.6, invariant 6)
45. An issuer signs root block `R` twice (same claims; grant id `G`), and both tokens are used, the first one recorded first. The second leaks, and an admin adds to `revoked` the revocation id of `stored` from `GET /ns/{ns}/grants/G` → a request with the leaked token → `401`: revoking the grant id a log names refuses every token minted from it (§C.4 Revocation)
46. `e2e` namespace; role `translator` (`can: ["read", "append"]`, rule `{ "op": "test", "path": "/writes", "schema": { "items": { "pattern": "^/i18n" } } }`) → append of a `sealed` op → `403`: a rule whose outcome depends on `/writes` fails as a whole at E3, as a `writes` predicate does (§6.2 End-to-end namespaces, §E.3.2)
47. Private namespace with a live branch; a grant with `config` but no `*` key → config write setting `encryption.level` to `sealed`, or `"nonce": "required"` → `403` (`forbidden`) at the `*`-key guard, never `409 in_use` with `dependents` (§6.2 step 6, §C.2, §7.4)
48. A reader opens `GET /r/matches/derby/events` on private `matches` under a grant with `read`. Then its root block is added to `revoked`, its `exp` passes, or its only role loses `read`. Or the stream was opened without credentials while `matches` was public, and `matches` then turns `read: "grant"` → the next revision of `derby` → not sent, and the stream ends; a reconnect with `Last-Event-ID` gets the step-3 or step-4 answer (§7.3, §C.2 item 5, §C.4 Revocation)
49. Remote branch `R` on B of A's `N`; a grant signed by a key of `N` on A that B doesn't list → presented to a consumer of `R` that verifies grants (§C.6) → `401`, as at B's origin: only local bases' keys and revocations count (§10, §C.1 Verification, §C.4, invariant 6)
50. Private `matches` behind a verifying edge. A browser opens `EventSource` on `/r/matches/derby/events` with an edge cookie for `/r/matches/derby` whose `exp` is `t` → the edge checks it and forwards the request with the cookie, `X-Edge-Verified` and `X-Edge-Prefix` → the origin authorises from the cookie, and the stream ends at `t` at the latest. An edge that forwards only its headers, without the cookie → no stream, since the origin has no credential (§7.3, §9 Private namespaces, §C.5.3 Forwarding)
