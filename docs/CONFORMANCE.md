# Patch Log — Conformance checklist

Status: against spec v0.87, which is three documents sharing one numbering: SPEC.md (§1–§10, §12, §13, Addenda C, E, G and I), SERVICES.md (Addendum A, §E.2.6) and TOOLS.md (§11, Addenda F, H and J, §G.2, §G.4.2–§G.4.4). A server is checked against the sections for SPEC.md; a service or tool against those it claims. Items restate spec requirements as checkable statements; parentheses name the passages restated (bold lead-ins of the section's bullets, or "table"). The spec's text governs: an item that says more or less than its passage, or seems to disagree, is an error here. Ids are never renumbered or reused; a dropped item keeps its id, marked "retired in v0.NN". **[vectors]** items are byte-exact, covered by Addendum I.

Suggested conformance profiles (not in the spec; proposed):

| Profile | Contains |
|---|---|
| **Core-minimal** | §1–§10, §12 except: branches (§7.6, refused with `403` per §1), blobs (§7.8), filtered reads (§7.9), pruning (§8.6) |
| **Core-full** | all of §1–§10, §12 |
| **Auth** | Addendum C |
| **Encryption** | Addendum E, per level (E1, E2, E3) |
| **Federation** | Addendum G |
| Services (A), merge tooling (F), file tools (H) | separate checklists below |

## §1 Overview

- [ ] **CONF-1** (Conformance: Addendum C) `"auth": "grants"` implements all of Addendum C. Otherwise (`"disabled"`): every request counts as a `*` key; config writes skip namespace rules, resource writes are still checked; entries written on a request record `"grant": null`, earlier grant references still served; `merge.authors` checks (§F.3, §F.6) match such an entry on its author's `sub` alone, and janitor's `*`-key checks for `abandoned`/`superseded` accept it. Under `grants`, entries with `grant: null` or no `grant` count for no one.
- [ ] **CONF-2** (Conformance: Addendum E) Without Addendum E, `encryption` in namespace documents: `422` (`invalid`); likewise a level the server lacks.
- [ ] **CONF-3** (Conformance: Branches) A server refusing branches answers `branch` `403` after verification (§C.2), never lists it in `/principal`'s `can`, finds no candidate in §6.1's draft lookup.
- [ ] **CONF-4** (Conformance: Filtered reads, The companions) A core server has hooks for the companions and Addendum G: batch `source`, `GET /`, pruning's archive bundles (§G.4.1; §G.5.1.1 encrypted), their namespace-document members (§12.3). Filtered reads (§7.9) are optional: a server without them answers partial readers as §C.5 says (AUTH-21).
- [ ] **CONF-5** (Conformance: Byte-exact definitions) Ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9), padding buckets (§E.2.2) and long-poll phases (§7.7) agree across implementations; each implemented part reproduces Addendum I. **[vectors I]**
- [ ] **CONF-6** (Reading this spec) Drafts promise no compatibility with data written under an earlier draft: a deployment may refuse or discard it, and MUST NOT serve it under less protection than this draft gives that namespace's content, or where that would otherwise break one of this draft's invariants.

## §2 Terminology

### §2.1 Defined terms

- [ ] **TERM-1** (Dependents) A namespace's dependents: unpurged namespaces whose `base` it is.
- [ ] **TERM-2** (Edge prefix) `/r/{ns}/{name}`, `/r/{ns}`, `/ns/{ns}` or `/ns/{ns}/view/{view}` (§7.9) (names per §3.6, `view` an id in text form, §3.2); covers its URL and all below, segment-wise as RFC 6265 path matching; likewise a service's prefix under its root.
- [ ] **TERM-3** (Effective roles) A grant carries roles when a block lists `roles`. Effective roles: those its root block lists that every narrowing block listing `roles` keeps and configuration in force defines.
- [ ] **TERM-4** (Encryption level) `encryption.level`: none < `at-rest` < `sealed` < `e2e`. Sealed means `sealed` (E2) only; `e2e` (E3) is end-to-end, from creation or never (Addendum E, Levels).
- [ ] **TERM-5** (Protection) Moving content never makes it readable to anyone who couldn't read it at its source, unless a caller who can read it there writes it itself or an operator overrides one import. Allowed moves work within a namespace, between equal ranks and upward; only a key holder seals into `e2e`; an import keeps an `e2e` source's lines under its own name. Ranks `public` < `private` = `sealed` < `e2e`: source is `e2e` at E3, `sealed` at E2 whatever `read`, else `public`/`private` by `read` (unknown: `private`); target is the same but sealed with `read` `public` is `public`. A blob copy, rebase replay into its successor and (barring operator override) an import never move content to a lower-ranked namespace; the server refuses the first. Nothing else is ranked (branches: §7.4; batch local `source`; a writer's own writes).
- [ ] **TERM-6** (Protection: sealed sources) From a sealed source (public or not), a blob copy or batch local `source` takes only a blob that opens under an epoch it is served under there (fixed as for a request for the blob), with keys §E.2.3 gives there to the request's own grant or one in `Source-Authorization`. Other copies: `404`; a local `source` doesn't make them available.
- [ ] **TERM-7** (Fixes `/resource`) A grant fixes `/resource` when a rule of its blocks or key scope (top level or nested only in `all`s) tests `/resource` against one name (`value`, or `compare` `eq` with a literal) or a finite set (`schema` of only `enum`, or `compare` `in` with a literal array); fixed names satisfy every such rule. An empty set, or any such literal not a valid name (§3.6), even one the intersection drops, means not fixed. A key with `readScope: "resource"` requires each grant it signs that can allow `read` (§C.2 item 2) to fix it.
- [ ] **TERM-8** (Qualifying role) Qualifies for edge grants: an effective role listing `read` whose rules refer to `/resource` only if grant fixes it, refer to no `/doc`, and pass now against a `read` envelope for grant's principal with `/resource` set to each fixed name (if none, once without `/resource`).
- [ ] **TERM-11** (Refers to) A rule refers to every pointer at, above or below a path it, or a rule nested in it, tests or compares: a rule on the whole envelope (`""`) to every pointer, a `writes` rule to `/writes`. It refers only to pointers when each such path is at or below one of them.
- [ ] **TERM-9** (Referrer) In `N` setting `schemaReads`, a referrer of a schema revision is an unpurged resource of a namespace `schemaReads.for` lists (`N` included) whose head, or last live document if tombstoned, reaches the revision through `$schema` and the `$ref` closure; only that namespace's own resources count, not what a branch reads through, and a schema document's own `$ref`s don't make it one.
- [ ] **TERM-10** (Unrestricted read) Unrestricted `read` of a namespace: grant may `read` there (§C.2 item 2), its key has no `readScope`, no rule in its blocks or key scope refers to `/resource` or `/doc`, and, if it carries roles, at least one effective role listing `read` has no rule referring to `/resource`, `/doc` or `/now` (where a request needs it, only such roles count). Branching checks it at gate step 1.

## §3 Identity

- [ ] **ID-1** (Input) All JSON accepted is I-JSON (RFC 7493): a request body (not a blob upload) containing what it forbids is `400` (grants: §C.8). Also `400`: numbers overflowing an IEEE 754 double, and numbers whose JCS canonical form is an integer literal outside ±(2⁵³−1), however written. Numbers whose canonical form has an exponent are accepted; underflow reads as the nearest double. **[vectors I.1]**
- [ ] **ID-2** (Canonical form, What is stored) `canonical(v)` is JCS (RFC 8785) in UTF-8; server stores, serves and hashes `canonical(patches)`, never received bytes. **[vectors I.1]**
- [ ] **ID-3** (Id format) 20 bytes binary; text form (URLs, headers, JSON) is 33 characters: prefix `1` (SHA-256 truncated to 160 bits) then lowercase RFC 4648 base32 (`a–z2–7`), unpadded. **[vectors I.2]**
- [ ] **ID-4** (Revision id, Foreign parents, Tombstone id, Namespace revision id, Blob id) Ids follow §3.3, §3.4, §3.5, §3.7 exactly; `trunc160` keeps the first 20 bytes. Genesis `bytes(parent)` is empty; a branch's first entry of a read-through resource has a foreign parent; a tombstone's parent is the head deleted; `bytes(prev_ns_id)` is empty for a namespace's first entry; config revision ids use the revision formula over namespace document's own chain. **[vectors I.2, I.3]**
- [ ] **ID-6** (Namespace revision id: `forced`, `purge` target, Branch entries, `source`, Batch entries) Namespace entries have exactly §3.5's shapes, ids in text form.
  - `forced: true` only on a purge that overrode an `in_use` refusal, then on every entry it writes (propagated included).
  - A `purge` entry's `target` is the resource's head or tombstone as namespace written in sees it (branch: including what it reads through).
  - `branch` entries go in base's chain; a branch's `target` is its config genesis id.
  - `source` is hashed with its entry; `origin` only for another deployment, as its canonical origin (§C.3); `ids` at most one member per batch item, named by its resource; any other shape: `400` (`bad_input`).
  - A `batch` entry lists the config entry first, if any, then per resource, in request order, one `head` or `tombstone` entry with its final entry.
  - Config entries and resource pointers share one chain.
- [ ] **ID-5** (Names) Namespace names match `^[a-z0-9][a-z0-9_-]{0,63}$`, resource names `^[a-z0-9][a-z0-9._-]{0,127}$`, so never empty, which keeps each `K_r` apart from `K_n` (§E.2.1). URLs use names verbatim; percent-escapes are `400`.
- [ ] **ID-7** (Blob id) `type`: upload `Content-Type` lowercased without parameters, `type/subtype`; missing or unparseable is `400`. `nonce`: empty or 26 base32 characters hashed as ASCII. `bytes`: as stored (E3: client ciphertext). Text blobs aren't UTF-8-checked. **[vectors I.3]**

## §4 Invariants

- [ ] **INV-1** (Append-only, Linear) Entries are never modified or removed except by purge and pruning. One first entry per resource (genesis; in a branch, foreign parent); at most one child per entry; a head moves only to a child of the previous head. Likewise namespace and namespace-document chains.
- [ ] **INV-2** (Valid) A non-tombstone revision whose folded document has `$schema` validates, without the members §6.2 step 5 leaves out, against the schema revision it names; re-validating later agrees unless that revision or one in its `$ref` closure was purged or pruned without a kept document, or the revision or a schema it reaches was written under an earlier draft (Reading this spec, CONF-6). At E3 readers check this, not the gate.
- [ ] **INV-5** (Verifiable) Entries suffice to recompute every id and check every parent link; below a pruning horizon, ids check only against archive.
- [ ] **INV-3** (Ordered namespace log) Every mutating request that takes effect (`create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `prune`, batches) writes exactly one entry in the addressed namespace's chain, atomically with its change. An idempotent retry answered from the log, and blob uploads and copies, write none. Server-written entries are one per resource and namespace affected. A branch's creation writes its `branch` entry in base's chain atomically with first `config` entry of its own chain. A batch writes one `batch` entry.
- [ ] **INV-4** (Configuration in force) A write is checked against configuration (rules, keys, revocations, limits; in a branch also its bases' current keys and revocations) at chain head when the write is inserted: namespace document of the nearest `config` entry, or `batch` entry with a config change, before the write's own entry; a batch's items as §7.5 says. A namespace's creation, and a document write changing what one of its own bounds limits, are held to the bounds of the document produced.
- [ ] **INV-6** (Fixed base) `base` never changes. Reads through a branch see base as of `at`, except that purges in base propagate and base's pruning applies.
- [ ] **INV-7** (Referenced blobs) Every blob a stored document references is available to its resource and kept as long as document is; at E3 server relies on writers' declarations.

## §5 Storage requirements

- [ ] **STO-1** (list, items 1–3) Persisted: per entry, id, parent, kind, exactly recoverable `canonical(patches)` (until purged or pruned), author, `via`, grant reference, creation time, any `gesture`, `undoes`, author signature; per namespace log entry, author, `via`, creation time and, if written on request, grant reference with its non-bearer form (none hashed); per blob and resource, type, nonce, and, while pending, uploader. A blob is removed on purge, after pruning, and when unreferenced.
- [ ] **STO-2** (list, items 4, 5, 8 and 9)
  - Invariants 2, 5, 6 are enforced atomically, under concurrent writers and multiple processes too; a batch applies atomically, holding them across all items.
  - The document at any revision id can be served unless purged or pruned without a kept document (end-to-end namespaces, resources other than `keyring`: only the sealed snapshot a prune stored, where §7.1 says).
  - `base` is persisted; "this resource's head as of namespace revision `n`" is answerable for any resource and any `n` in a base's chain.
- [ ] **STO-3** (list, items 6, 7 and 10) After purge: ids, parent links, namespace entries, nothing else of the resource's content. After pruning: what §8.6 keeps. After a namespace purge: namespace document chain, namespace log, every resource's ids and parent links.
- [ ] **STO-4** (closing paragraph) Storage choices change nothing observable: reads serve exact canonical bytes; ids and limits are computed over them.

## §6 Validation and rules

### §6.1 Schema references

- [ ] **SCH-1** (Opting in, Accepted forms) A document opts in with top-level `$schema` string (`422`, `schema_ref`): exactly `^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$`, or dialect URL `https://json-schema.org/draft/2020-12/schema` (a schema, validated against the dialect's meta-schema). Anything else: `422` (`schema_ref`); no normalisation.
- [ ] **SCH-2** (`$id`, `$ref`) A schema document uses `$id` in no subschema and `$schema` in none but its root (`422`, `invalid`); validators are registered and looked up only by revision path. `$dynamicRef` is same-document fragment (`422`, `schema_ref`). `$ref` resolves only same-document fragment (`#…`) or schema revision path in accepted form, optionally with fragment; percent-decoded fragment empty or starting with `/` is JSON Pointer, otherwise a plain name an `$anchor` or `$dynamicAnchor` of target must define. A schema's own `$ref`s resolve when written (step 5 of §6.2); one naming nothing in its target makes schema invalid (`422`, `invalid`).
- [ ] **SCH-3** (Never into a branch, Drafts in branches) `$schema` and `$ref` never name branch namespace (`422`, `schema_ref`); path naming branch where writer can't read revision: `422` (`schema_unavailable`). In a write to a branch, a path `/r/N/R/rev/X` that `N` can't resolve for writer (lacks it, or writer can't read it there) is looked up in candidates: `N`'s branches (branches of branches included) not end-to-end, counting only revisions each wrote itself. A candidate serves writes to itself and its own branches, and to namespaces its `drafts.for` lists and their branches (namespace written, or one in its `base` chain, is listed); its branches don't inherit `drafts.for`. Writer needs `read` on `R` in candidate (as §7.5), else revision counts as not found. Any candidate holding `X` serves, and the whole `$ref` closure resolves likewise. In a non-branch namespace, paths resolve only in `N`.
- [ ] **SCH-4** (Schemas follow their documents) With `schemaReads.for` set in `N` (names or prefixes ending `*`, matched as `drafts.for`, never against branch; `N` always counts), schema revision in `N` whose own `$schema` is dialect URL:
  - resolves without `read` for write to listed namespace, or branch of one (branches of branches included), whose document pins it through `$schema` or its `$ref` closure;
  - may be read by revision path, even under grant that doesn't name `N`, doesn't verify or can't read it there, when grant may read referrer of it (§2.1) in listed namespace it names, verifying under that namespace's keys and allowing that read, even where its `read` is `public`. A referrer in listed namespace that is public and neither sealed nor end-to-end counts for every request, grant ignored. An edge knowing only prefixes forwards such read to origin; origin serves it `private`.

  Nothing else opens (resource head, log, other revisions; non-schema documents; branch drafts). `schemaReads`: `422` in sealed and end-to-end namespaces.
- [ ] **SCH-5** (Within a batch, Tombstoned schema resources, Purged or unknown references) Batch items may reference revisions created by earlier items; revisions of tombstoned schema resource still resolve, for new references too. A reference that is unknown, purged, pruned without a kept document, unreadable by writer, or names tombstone, non-schema document, or revision in an end-to-end namespace, is `422` (`schema_unavailable`), `path` the revision path that didn't resolve.
- [ ] **SCH-6** (Referenced schema revisions, Copies, Refusals) Referenced: schema revision named by `$schema`, or reached through that schema's `$ref` closure, from head (or last live document if tombstoned) of any unpurged resource in deployment, head as of `at` (or last live document then) of resource branch reads through, or any revision branch wrote. A reference is satisfied by a copy whose document is neither purged nor pruned, in `N` or, for a document in a branch, in a branch it may resolve drafts in (candidate rules, never one writer's grants); pruned in `N` counts as unresolvable there. Unless forced, `409` (`in_use`): purge of resource or namespace removing last satisfying copy in any namespace it reaches (branches it propagates to included), and config write leaving reference without copy; `referencing` lists referencing namespaces in which caller may read anything (as §7.5): the first `logPageSize` in byte order of name, with `"more": true` where it may read others.
- [ ] **SCH-8** (Forcing) A refused purge is forced with `?force=1` under grant chained to deployment operator key or, for purge of branch or resource in one, to a `*` key of that branch (inherited or own); under any other grant `?force=1` is `403` at step 1 of §6.2, needed or not. A forced purge's entries carry `forced: true` (ID-6).
- [ ] **SCH-7** (Read permission) Resolving a `$schema` or `$ref` needs writer's `read` on copy resolved to, in schema's namespace or branch holding draft (as §7.5 where not the namespace written). From sealed namespace (public or not), it also needs keys as in TERM-6, for the epoch a read of the revision would fix, in namespace written too; without them revision is unreadable (`422`, `schema_unavailable`). Where `schemaReads` opens the revision for the write, none of this applies.

### §6.2 On write

- [ ] **GATE-1** (intro) Checks run in §6.2's order. Only errors in a request's own shape, which no state influences, may precede step 1, as the request's own answer, never a batch item's: malformed names or URLs, content types, header and body syntax, size of what is read (`400`, `413`, `415`, a grant's request-shape `401`s of §C.2 item 1), unless an endpoint fixes its own order (blob uploads). A batch body cut off by the verified principal's `batchSize` (§7.5, LIM-1) is `413` once the grant is verified, before its verbs are checked; a malformed body read then is `400`.
- [ ] **GATE-2** (Authenticate and authorise) Step 1 authenticates and authorises (`401`/`403`): verbs and grant, key-scope and role rules referring only to `/action`, `/resource`, `/principal`, `/now` (§C.2). Rate limits come last in step 1, only for requests that passed its other checks or ran out of `validationSteps` in them: `429`, else that `422` (`limit`, LIM-7).
- [ ] **GATE-3** (Precondition) Step 2, in order:
  1. Idempotent-retry lookup, with its verb check (§C.2 item 2). Not applied to purged resource (`410`); nor in purged namespace, where every write is `410` (`purged`) here, before any later check.
  2. For a `PATCH` with `If-Match`, or batch item whose first step is patch set under `ifMatch`, verb is settled from resource's state as writer sees it: tombstoned head → restore; live head or none → append; purged → `410`; in branch read-through resource settles by base's head as of `at` (a tombstone there: restore, with it as foreign parent). A settled verb that isn't a candidate: `403`, before `If-Match` comparison, counting as failing authorisation for §7.5's failure report and dry run. So does a write to a resource with a head, a `DELETE` or create included, by a grant that may `read` but whose read rules don't allow reading that head (AUTH-31): `403` here, so steps 3–5 never judge a document it can't read.
  3. Author signatures (`422`, `signature`); signed parent is the one precondition names.
  4. Frozen namespace (`409`).
  5. In batch, `422` for a `"delete"` following a `"delete"`; then precondition: `412`, or `410` on tombstoned resource, then `428`. A purge or prune of resource that never existed: `404`, never `412`.
- [ ] **GATE-4** (Apply, Limits, Schema) Step 3 applies patches to parent's document (`null` for create); operation validation, failing `test`, or create whose `writes` (§6.4.1) are empty: `422`. A delete skips steps 3–5. In namespace requiring nonces, create, append or restore is checked for a fresh `$nonce` (`422`, `nonce`). Step 4 validates namespace document config write or branch creation yields (§7.4) and prune's `horizon`, `keep`, `snapshot` (E3: archive too; §8.6) (each `422`, `invalid`, or `limit`), then §6.6's limits, then that every blob reference in resulting document is well-formed and names blob available to resource (`422`). Step 5: if resulting document has `$schema`, resolves it (§6.1) and validates the document against draft 2020-12 with format assertions for formats it defines, `hostname` per RFC 1123 alone, `idn-hostname`/`idn-email` per RFC 5891's registration rules, contextual rules included, without UTS 46 mapping; in both formats an all-ASCII label is valid, an R-LDH one only as an A-label, case ignored (A-label if, lowercased, it is `xn--` then the Punycode of a valid U-label, as `XN--BCHER-KVA` is); schema naming any other `format` is invalid. The instance omits top-level `$schema`, fresh `$nonce` and `$successor` of §8.1's form; other forms are validated as data. Failure: `422` with `{ pointer, message }` errors; work past a document's `validationSteps`: `422` (`limit`, §6.6, LIM-7). **[vectors I.18]**
- [ ] **GATE-5** (Rules, Hash and insert) Step 6 evaluates `*`-key guard, then config write's `in_use` refusals (§6.1, §7.4), then grant, key and role rules, then namespace rules, against configuration in force. Step 7 hashes and inserts atomically with namespace entry. In batch each step (step 6: each of these), and each sub-step of step 2, runs for every item before the next; step 7 inserts all items in one atomic operation.
- [ ] **GATE-6** (End-to-end namespaces) For `create`, `append`, `restore` in an `e2e` namespace, any resource but `keyring`: step 3 accepts one reserved `sealed` op passing §E.3.1's checks, or `[]` for restore, without applying it; anything else: `422` (`invalid`). Step 4 checks blobs op declares; step 5 is skipped. Rules use strong Kleene logic with `writes` predicates and `/writes`, `/doc` paths unknown (restore with `[]` too): unknown outcome fails as a whole (`422`/`403`), any other is decided as usual. Config, branch and prune writes are checked as usual, and so is delete, but with `doc` null (RUL-2), so rule depending on a `/doc` path fails as a whole.

### §6.3 Changing type

- [ ] **TYP-1** (Adding, Changing, Removing) Adding `$schema` to untyped document, or changing it with `replace /$schema`, is an ordinary patch; result must validate against schema it then names. Removing it makes document untyped from that revision on. Tombstones, and document delete removes, aren't validated.

### §6.4 Namespace rules

- [ ] **RUL-1** (`writes`) Server computes `writes`:
  - `add`, `replace`, `remove`, `copy` write `path`; `move` writes `from` and `path`; `test` nothing;
  - a root operation, genesis `add ""` included, writes `""`;
  - a delete's `writes` and `patches` are `[]`;
  - an array append `…/-` is recorded with resulting index;
  - an `add`, `copy` or `move` into array below its length, and a `remove` or `move` of non-last element, also write array itself;
  - in resource envelopes only, an `add` or `replace` at exactly `/$nonce` with value matching `^[a-z2-7]{26}$` is left out; any other operation at or below `/$nonce` is write.

  Pointers compare segment-wise after RFC 6901 unescaping.
- [ ] **RUL-2** (Change envelope, `doc`, Batches, `principal`, `now`, `read`) Every write is checked against an envelope of `action`, `resource`, `principal`, `now`, `writes`, `doc`, `patches` (canonical; `[]` when none).
  - `resource` is absent for `config`, `purge-ns`, and new namespace's name for `branch`. `principal` is absent when authentication is disabled.
  - `doc` is document as it will be stored. Delete: resource's last live document as target namespace sees it (read through bases in branch; in batch, after item's earlier steps); a replayed delete is judged against target's document at that step. `config`: resulting namespace document. `branch`: new branch's namespace document, evaluated in base. Null for `purge`, `purge-ns`, and in end-to-end namespace for `create`, `append`, `restore`, `delete` (not `keyring`); `{ horizon, keep? }` as sent for `prune`.
  - A batch yields one envelope per patch set; there is no `batch` action.
  - `principal`: `groups`, `attrs` from root block, `roles` its effective roles (§2.1); a member the grant gives no value for is empty: `{}` for `attrs`, `[]` for `groups`, `roles` (a grant without roles too), `via`. `now`: server clock at gate, RFC 3339 UTC, millisecond precision, read once per request.
  - `read` envelopes carry only `action`, `resource`, `principal`, `doc` (RUL-8); rules referring to `/now` fail as §C.2 item 5 says.
- [ ] **RUL-8** (`read` envelopes: `doc`) A `read` envelope's `doc` is the document of the revision the read concerns:
  - the head for `GET /r/{ns}/{name}` and the resource's other URLs naming no revision; that revision for `/rev/{id}`; each entry's revision for a log, a stream or the gestures listing; each row's head for `/heads`;
  - for a blob, each stored document referencing it (§7.8): the read passes where one does, or, where none does, judged on the head;
  - for a tombstone, the document it deleted;
  - `null` for purge entries, where the read concerns no revision or one whose document is no longer stored (purged, or pruned and not kept, §8.6), and in a sealed or end-to-end namespace. Wherever it is `null`, a rule referring to `/doc` fails as a whole, as one on `/now` does.
- [ ] **RUL-9** (Guarding fields that read rules test) Under §6.4.4's example rule, an `append` or `restore` by a grant without the `librarian` role whose `writes` overlap `/folder` fails it (`422`, `rule`); a `librarian`'s passes. A namespace whose read rules test `/doc` should guard those fields and require nonces (§C.7).
- [ ] **RUL-10** (What rule failures reveal) A failing rule on `/doc` reveals something about the document, even a deleted one. A `403` at step 2.2 (GATE-3) shows a writer whether a name it can't read exists. A grant without `read` learns from steps 3–5 (a `test`, a schema error) about any document it may write.
- [ ] **RUL-6** (Rule forms, Path policy, `compare`) Every rule form of §6.4.2 is implemented; path policy uses `writes` predicates, never patterns over `/patches/*/path`.
  - `test` with `value` is RFC 6902 equality. A missing path fails `value` and `schema` tests and satisfies `exists: false`.
  - A `schema` is draft 2020-12 fragment with format assertions, checked like schema document (§6.1 `$id` ban, §6.5, §6.6's regular expressions), with no `$schema` in any subschema and only same-document `$ref`/`$dynamicRef`; otherwise namespace document: `422` (`invalid`), grant invalid (`401`).
  - `within` is true when there are no writes; `covers` and `overlaps` are false.
  - `lt`, `le`, `gt`, `ge` compare numbers, or RFC 3339 `date-time` strings as instants at full fractional precision (leap second `:60`, lowercase `t`/`z`, space for `T`: unsupported type); `eq` is RFC 6902 equality; `in` is true when the left value equals element of the right-hand array, false if the right isn't array. A missing path, or different or unsupported types for `lt`, `le`, `gt`, `ge`, makes `compare` false.
  - When all `if` rules pass, all `then` rules must pass.
- [ ] **RUL-3** (Evaluation) Rules run at step 6 of §6.2, in order; all must pass. Failing namespace rule: `422`, `code: "rule"`, `rule` (index), `path` (failing rule form, descending only through first failing member of an `all`/`then`). Failing grant, key or role rule: `403` (`forbidden`). Rules apply only at write time (read time too for grant, key, role rules); changing them never invalidates history.
- [ ] **RUL-4** (Config writes are rule-checked too, Operator overrides, Except as above) Namespace rules see every action (`delete`, `purge`, `config`, `branch` (evaluated in base), `purge-ns` included), except: a `config` write under grant chained to a `can: ["*"]` key (as does every request when authentication is disabled, CONF-1); namespace's creation under operator grant that creates it; purge or namespace purge forced past `in_use` under deployment operator grant. A purge forced with branch `*` key (inherited or own), or any purge while authentication is disabled, is still judged.

### §6.5 Reserved keys and extension keywords

- [ ] **RUL-5** (Reserved keys, `$blob`, `x-*` keywords) Top-level keys starting with `$` other than `$schema` are stored as data, never interpreted, except a fresh `$nonce` is left out of `writes` and can be required (§C.7), and well-formed `$successor` is read into deleted resource's `410` (§8.1); validation leaves both out (GATE-4; any other form is data; in a schema document also before its dialect check and compilation). `$blob` is reserved at any depth: object with a string `$blob` member is blob reference and must be well-formed (`422`); schema and namespace documents aren't searched for references. Schema keywords starting `x-` are ignored by core validator; any other unknown keyword makes schema invalid (`dependencies`, `$recursiveAnchor`, `$recursiveRef` included); `definitions` holds subschemas.
- [ ] **RUL-7** (`x-ref`, Entries inside a document, Finding references) An `x-ref` value is `{ "pinned"?: boolean, "key"?: pointer }`; pinned is revision path (§6.1), live resource path `/r/{ns}/{name}`. With `key`, reference names one entry of target (`/r/{ns}/{name}#{id}`, pinned `/r/{ns}/{name}/rev/{rev}#{id}`), `key` pointing into target at an array of objects with a string `id` or an object keyed by id; `{id}` matches those ids, never array positions, percent-encoded as URI fragment; a missing entry is dangling. References are found by a static walk of each document (without members validation leaves out) with its schema over every subschema that could apply at each location; a string where any carries `x-ref` is reference even if that subschema didn't validate. Core doesn't check `x-ref`.

### §6.6 Limits

- [ ] **LIM-1** (Configurable limits, Exceeding a limit) Every namespace has §12.2's limits under `limits`. Config writes, batch's `config` change and branch's `patches` are held to patch-set and document limits (`patchSetSize`, `opsPerSet`, `documentSize`, `nestingDepth`, `valueSize`, `pathSize`) as resource writes are (a namespace's creation: deployment defaults; a branch's: its base's limits), with bodies cut off as resource `PATCH`'s are.
  - Exceeding limit: `413` where request is refused before or while read, or where §7.8 says so, else `422`; `code: "limit"`, `limit` its key, and for sizes and counts `measured` and `max`; durations and rates give `limit` alone.
  - Where reading stopped, `measured` is a lower bound in body bytes, and before step 1 `max` is the deployment's. `measured`: for `pathSize`, `valueSize` the first value too long, quotes included; for `branchesPerNamespace` the base's live branches with the new or unfrozen one; for `blobPending` pending bytes with this blob, each at least 4 KiB; for `validationSteps` the steps taken where validation stopped, a lower bound; for a blob without `Content-Length`, `blobSize` + 1. It is left out for `documentSize`, `nestingDepth`, `valueSize`, `pathSize`, `blobsPerDocument`, `validationSteps` under a grant that can't read the resource.
  - Bodies of endpoints without limit of their own (prune, `/keys`) above 1 MiB: `400` (`bad_input`). A resource `PATCH` body over 4× the larger deployment maximum of `patchSetSize` and `documentSize`: `413` before parsing, naming `documentSize` with the deployment maximum. A batch body cut off by `batchSize` (§7.5) names it, verified principal's as `max`.
- [ ] **LIM-2** (Whole documents, Values) A create's patch set, and append's or restore's whose first operation other than `test` is root `replace` or `add` (more may follow), may be as large as `documentSize` instead of `patchSetSize`; at E3 every create and restore may, appends stay within `patchSetSize`. Every other patch set (even one starting with root `copy`, `move` or `remove`) stays within `patchSetSize`; in a batch all still count toward `batchSize`. A namespace's creation (a branch's included), and config write changing `limits` or `encryption` other than `epoch`, is `422` (`code: "limit"`, `limit: "patchSetSize"`, `measured` the left side, `max` the `patchSetSize`) unless, in resulting configuration, `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize`, the left side adding `36 B × blobsPerDocument` at E3.
- [ ] **LIM-7** (Validation work) Each document a write produces (each step of a batch item counting alone) gets at most `validationSteps` steps (deployment only, default 5,000,000, §12.2) for its validation (§6.2 step 5) and its envelope's rule `schema` tests (§6.4.2), those of step 1 and every candidate verb's included (§C.2 item 2); a write that produces none (a delete, a blob upload, §7.8) gets one such budget. A step is one schema or subschema applied to one value, a `$ref` or `$dynamicRef` target counting as one. Only the unit is defined; counts agree across implementations only approximately.
  - Running out of a write's budget: `422` (`limit`), even inside a rule whose own failure is `403`. At step 1 it answers only if no check there fails outright, after the rate limits (`429` first, GATE-2), drawing only buckets keyed by its principal; in a batch it counts as failing authorisation (§7.5).
  - Each read, exchange and key request a grant is presented for, each read check a write makes (§6.1, §7.5, §7.6), and each revision judged for a filtered read (§7.9) or item a service filters by a grant (§A.4) gets its own budget. Running out there fails that whole check, with its usual refusal, or leaves the item out.
  - No deployment leaves `validationSteps` unbounded.
- [ ] **LIM-3** (Rate limits) Token buckets checked at end of step 1 of §6.2, keyed by root `sub` and root-block `kid`, never `via`; per-resource bucket is per resource and principal, namespace bucket bounds all writers together. A request is admitted while every bucket it draws on holds at least one token; cost is then deducted (even below zero) atomically across instances sharing store, never committing write without it. A request refused after admission keeps its deduction, whether in step 2 of §6.2 (`412`, `410`, `428`, `409` frozen, a settled verb's `403`) or later, as does an idempotent retry (§7.2); dry runs draw as submit would.
  - Cost: batch, one per touched resource from each per-resource bucket and one per item from principal and namespace buckets, plus one from those for its `config` change unless exempt (one failing after step 1, whose error then answers the batch (§7.5): only under a `*` key); blob upload, one from per-resource, principal and namespace buckets plus its size from `blobRate`; other non-exempt write, one from principal and namespace buckets of namespace whose chain records it (a branch's creation: base's), plus per-resource for resource writes and prunes; a `PATCH /ns/{ns}` creation's `412` under any but an operator grant: one from that grant's principal bucket in `{ns}`.
  - Exempt: config writes under a `*` key, or whose non-empty `writes` all lie at `/frozen`, `/successor` or `/merged` with resulting `frozen: true`; purges; a namespace's creation under an operator grant, its `412` included (§7.4); server-written entries (§7.4).
  - Exceeding: `429`, `Retry-After` in whole seconds rounded up, `code: "rate"`, `limit` a bucket hit (§6.6 key, `allowance`, `allowance.blobRate`), `retryAfter` (decimal seconds until every bucket drawn on holds a token). A key scope may lower per-principal rates.
- [ ] **LIM-4** (Allowances) An allowance gives principal (matched by root `sub` and signing `kid`) its own bucket for writes and uploads, replacing principal and namespace buckets and key scope's lower `rate`; per-resource buckets still apply, at namespace's `ratePerResource`. Its batches may be as large as it says, and it may set `blobRate` and `blobPending`. It never exceeds deployment maximums (`bucket`: `ratePerNamespace`'s): above is `422` (`code: "limit"`, `limit` naming that maximum's limit); one stored before a maximum was lowered is held to it. With `until`, it applies only while `now` is before it. While authentication is disabled, buckets are keyed by author and allowance matches author's `sub` alone. The first matching entry whose `until` hasn't passed applies.
- [ ] **LIM-5** (Deployment defaults and maximums) A deployment sets default and maximum for every limit and minimum for retry window; namespace may set any limit up to maximum, except those marked deployment only. A write setting value above maximum, or retry window below minimum, is `422` (`limit`); a stored value is held to lowered maximum; write leaving value or allowance unchanged doesn't set it. A namespace's own bound holds its creation and every write changing what it bounds (one lowering count still over bound is refused).
- [ ] **LIM-6** (Regular expressions) Regular expressions in rules, grants, key scopes and schemas use RE2 syntax and semantics, reading `\uXXXX` as `\x{XXXX}` (not after escaped backslash `\\u`, nor inside `\Q…\E`); surrogate pair of such escapes is one code point, a lone surrogate or one written `\x{…}` is a pattern RE2 doesn't accept; `regex` format asserts the same syntax. A pattern RE2 doesn't accept makes schema or config `422` (`invalid`), grant invalid (`401`). **[vectors I.11]**

## §7 HTTP API

- [ ] **HTTP-1** (URLs, Query parameters) URLs `/r/{ns}/{name}`, `/ns/{ns}`. A path other than `/` with an empty segment (`//`, trailing `/`), a `.` or `..` segment, or any percent-escape: `400` (`bad_input`). An id not in text form (§3.2): `400` (`bad_input`), request-shape (§6.2), in: a URL; a write's precondition other than `If-None-Match: *`, a config write's included; `Last-Event-ID`; a request field such as `ifMatch` (inside a namespace document: a validation error instead, §7.4).
  - `ETag`, `If-Match`, `If-None-Match`, `If-Range`: id is a quoted strong tag. A write's precondition is one such tag or `If-None-Match: *`; `If-Match: *`, a weak tag or a list: `400` (`bad_input`). Sealed `ETag` adds `.{e}` (§E.2.2), omitted in a write's precondition. `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Log-Next`, `Last-Event-ID`: unquoted.
  - Query: only parameters defined for the endpoint, each at most once unless repeatable (core: only `prefix` of `DELETE /edge-grants`); flags (`force`, `dry-run`) only `1`. Else, repeats included: `400` (`bad_input`, not cached), request-shape.
  - An edge verifying signed-URL grants (§C.5) strips their parameters and forwards the grant as its cookie (§C.5.3).
- [ ] **HTTP-2** (`GET /`) `GET /` answers `{ "origin", "spec", "auth" }`: canonical origin (§C.3); implemented version (dotted decimals, compared component-wise); `"grants"`/`"disabled"` (§1). Addendum C adds `jwks_uri` (§C.4). A client, peer or tool MUST NOT refuse a deployment on version alone. An optional endpoint not offered: `404 not_offered`.
- [ ] **HTTP-67** (Answers) Answers, a service's too, may carry undefined members; clients ignore them.
- [ ] **HTTP-66** (Browsers) A deployment serving browsers answers preflights allowing methods `PATCH`, `PUT`, `POST`, `DELETE` and headers `Authorization`, `If-Match`, `Source-Authorization`, `Signature`, `Content-Type`, `Gesture`, `Undoes`, `Blob-Nonce`, `Blob-From`, `X-Author`, `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range`, `Last-Event-ID`; exposing `ETag`, `Location`, `Repr-Digest`, `Retry-After`, `Content-Range`, `Gesture`, `Undoes`, `X-Revision`, `X-Namespace-Revision`, `X-Config-Revision`, `X-Cursor`, `X-Log-Next`; setting `Access-Control-Max-Age`. Origin-varying responses carry `Vary: Origin`. A deployment allowing every origin and naming no credentialed origins (§C.5.2) sends `Access-Control-Allow-Origin: *` and its exposed headers on every response, with or without `Origin`.
- [ ] **HTTP-3** (Private namespaces and existence, Reads of a public namespace, The `ns` check, Verification, Resources) Order:
  1. Reads of a public namespace, other than `GET …/principal` and `POST …/keys` (§E.2.3), ignore any grant and answer as unauthenticated: content or `404`. Only these and schema revisions a public referrer opens (§6.1) answer unauthenticated requests so.
  2. With a grant, `ns` is read from its blocks before any key lookup; a namespace not named by every block carrying `ns`: `403`, existing or not. Root block always carries `ns`; `"*"` names all. Exception: `schemaReads`-opened schema revision.
  3. Then the grant is verified against that namespace's keys, or the operator keys when the root `kid` names one (§C.4). No valid credentials: `401`, alike for a nonexistent namespace and one whose `read` isn't `public`. Exception: referrer-opened schema revision (§6.1), never refused at steps 3, 4.
  4. Without `read`, existing and nonexistent resource both `404`. Off resource URLs, read a verified grant doesn't allow: `403` (§C.2), even under grant limited to some resources.

  Writes, `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`, and any request to a non-public or nonexistent namespace keep steps 2, 3's `403`, `401`.

### §7.1 Reads

- [ ] **HTTP-4** (table and the row's lead-in under it) `GET /r/{ns}/{name}`: `302`, `Location: /r/{ns}/{name}/rev/{head}`, `ETag: "{head}"`; never existed `404`; tombstoned `410` `{ "tombstone": id, "last": lastRevisionId, "successor"? }`, `ETag: "{tombstone}"` (§8.1); purged `410`. `HEAD` as `GET`, no body.

  `GET …/rev/{id}`: `200` (at E3 only a stored snapshot, HTTP-68), `ETag: "{id}"` (`"{id}.{e}"` sealed), `X-Revision: {id}`. Neither sealed nor end-to-end: also `Last-Modified` (revision `created`, HTTP date to the second) and, without content coding, `Repr-Digest` of the canonical JSON document; neither on sealed or end-to-end. `If-None-Match`: `304`; likewise `If-Modified-Since` when `If-None-Match` is absent and `Last-Modified` sent, else ignored. Tombstone `id`, below a horizon too: `410` `{ "tombstone": id, "last": its parent }`; unknown `id` `404`; purged resource `410`; `id` below the horizon without a kept document (§8.6) `410` `{ "code": "pruned", "horizon": id, "archive"?: url }`.
- [ ] **HTTP-68** (End-to-end namespaces) Server never folds a resource other than `keyring` (§E.3.2). A client learns each namespace's level, a base's included, from its configuration, the current namespace document (not one read by id), or else `/keys`' `level` (§E.2.3), keeping the highest it has learnt (levels never go down); it refuses a claim below the level it holds, or one it doesn't know while it holds any, and learns nothing from either, nor from a level it doesn't know; before it has learnt a level, only its configuration protects it, a configured level it doesn't know counting as `e2e`; it holds for a branch at least the level it holds for any base in the branch's `base` chain (Levels), and a reader of a sealed branch needn't read its bases' namespace documents, the branch sealing all it serves under its own keys (§E.2.5); a reader expecting end-to-end refuses any other resource's `200` that isn't `application/jose`. For any other resource, `GET …/rev/{id}`:
  - `200` only where a prune stored a sealed snapshot (§8.6): at the horizon, or, horizon a tombstone, at the tombstone's parent, its last live revision, which the tombstone's `410` names as `last`; in a branch, a base's stored snapshot included, whatever the branch has written since. Body the snapshot's JWE, `application/jose`.
  - A stored snapshot is served until a purge or a later prune that moves the horizon, whatever is restored from an archive (§8.6).
  - Any other `id` that would be `200`: `404` `code: "not_offered"`, after the read check, cached as short; body carries the resource's `horizon` as the namespace sees it, where it has one, and `last`, the tombstone's parent, where that horizon is a tombstone.
  - Readers fold the log up to `id` from the revision `last`, else `horizon`, names; from genesis where neither is given.
- [ ] **HTTP-16** (table) Raw document (§7.8): `GET …/raw`, `GET …/rev/{id}/raw` `302` to `…/blob/{bid}`. Unknown, pruned, purged, tombstoned ids and heads answer as the document URL; non-raw `404` (`not_found`); sealed or end-to-end `404` `code: "not_offered"`, after the document's read check, whatever the document URL would answer but a purge's `410` (§8.3, §8.5).
- [ ] **HTTP-17** (table) `GET …/blob/{bid}`: `200`, `206` for a range; pending or unknown `404`; pruned or purged `410` (§7.8); sealed namespaces: `302` to `…/blob/{bid}/e/{e}` (§E.2.2). `GET …/blob/{bid}/e/{e}` serves only those: `200` sealed under epoch `e`, `206` for a range; `404` for an epoch not served; `410` per §E.2.2. Elsewhere: `404` `code: "not_offered"`, after the resource's read check. Epoch `404`: `no-store`.
- [ ] **HTTP-18** (table and the row's lead-in under it) `GET …/rev/{id}/log?since={a}`: `200`, entries after `a` (exclusive) up to `id` (inclusive); empty or omitted `since` from genesis; `since={id}` empty. `404` if `id` unknown or `a` neither `id` nor an ancestor. `410`, as below the horizon, if any revision after `a` up to `id` has its patch set pruned and not restored from an archive (`a` itself may lie below it).
- [ ] **HTTP-5** (Paging) A log range answers its first page only if longer than the log page size (§6.6; a batch entry counts as its items), or over `logPageBytes` of patch sets. A page ends before an entry that would pass a bound, but holds at least one; filtered ranges (§7.9) may hold empty pages, and end as that section says. At E2, `logPageBytes` counts each entry's sealed bytes as served. Oldest first, `X-Log-Next: {id}` (last entry returned = next `since`); a page reaching the URL's `id` needs none. `404`, `410` are judged over the whole range.
- [ ] **HTTP-19** (Paging, Continuations) Every paged answer names how to continue: log ranges in `X-Log-Next` (next `since`), `/heads` and `/branches` in body's `next` (next `after`), gestures listing in `X-Log-Next` (next `after`). Long-poll answers (§7.7) use the same page limits and carry no `X-Log-Next`. An E3 prune's sealed snapshot (§8.6) is served at a revision URL (HTTP-68), never as a log entry.
- [ ] **HTTP-20** (Log entry shape) Resource log entry `{ "id", "parent", "kind": "rev", "patches", "author", "via"?, "created", "grant"?, "signature"?, "gesture"?, "undoes"? }`, `patches` canonical; a tombstone entry has `kind: "tombstone"`, no `patches`. A genesis's `parent` is `""`. `grant` `{ "id", "sub", "kid" }`, absent where none recorded (auth-disabled writes included). `created` RFC 3339 UTC, millisecond precision (namespace entries too). `via` the grant's delegatees in order, absent when none.

### §7.2 Writes

- [ ] **HTTP-6** (Writes, table, Content types) No precondition `428`. Both `If-Match` and `If-None-Match` `400` (`bad_input`), request-shape. Pruning (§8.6) and blob uploads (§7.8) take none; one sent `428` (prune: step 2.5 of §6.2; upload: check 4 of §7.8). Checks run in §6.2 order (authorisation before precondition); a `PATCH` with `If-Match` completes authorisation at step 2.

  Resource `PATCH` with `Content-Type` other than `application/json-patch+json`, or none: `415`, request-shape; likewise any other JSON body not sent as `application/json`. JSON `Content-Type` compared as a media type (RFC 9110, section 8.3.1), ignoring case and a `charset` parameter naming UTF-8; any other parameter `415`.

  - **Create** (`PATCH /r/{ns}/{name}`, `If-None-Match: *`): `201`, `Location: …/rev/{id}`, `ETag: "{id}"`. Fails: live `412` `{ head }`; tombstoned `410` (`gone`), `head` the tombstone; `422`; purged `410`.
  - **Append** (`If-Match: "{parent}"`): `201`, `Location`, `ETag`. Fails: parent ≠ head `412` `{ head }`; `422`; tombstoned and `parent` ≠ tombstone `410` (`gone`, `head`); tombstoned and grant can't restore `403`; purged `410`.
  - **Restore** (`PATCH` on tombstoned, `If-Match: "{tombstone}"`): `201`, patches apply to the last live document (§8.2). Fails as append.
  - **Delete** (`DELETE`, `If-Match: "{head}"`): `200` `{ tombstone }`. Fails: `412` `{ head }`; tombstoned `410` (`gone`, `head`).
  - **Purge** (`POST …/purge`, `If-Match: "{head or tombstone}"`): `204`. Fails: `412` `{ head }`; never existed `404`, after a `428`; `409 in_use` (§6.1), after the precondition.
- [ ] **HTTP-21** (Authorization, Author) `Authorization: Bearer <grant>`. Authentication disabled: `X-Author` names the author; a write without it `400` (`bad_input`). Author is the verified principal id, `via` recorded with it.
- [ ] **HTTP-22** (Gestures) A write may carry `Gesture: <id>`, `Undoes: <id>`, each `^[a-z2-7]{26}$`, else `400`. Stored with the revision or tombstone; not in its id (§3.3), not seen by rules, never verified. Namespace-document writes (§7.4) carry them likewise; a batch's `config` change none.
- [ ] **HTTP-7** (Idempotent retry, Gestures) On a failed precondition the answer is `200` with the entry, instead of `412` (or `410` on tombstoned, or `409 frozen`), if all hold:
  - the log holds the entry the request would have produced (append, restore: §3.3 id, `If-Match` as parent; create: genesis id, empty parent; `DELETE`: §3.4 tombstone id);
  - the same principal wrote it: same root `sub` and `kid`, or, authentication disabled, same author; under `grants`, an entry without recorded grant matches no one;
  - the retry passes the verb check of §C.2 item 2.

  `200` as for success (`Location`, `ETag`, or `{ tombstone }`), the entry as first recorded whatever the retry carries, recorded `Gesture`, `Undoes` as headers. The lookup covers the whole resource log in the namespace written, not entries a branch reads through (§7.6); a purged resource: `410` (§6.2). Always works within the retry window (§6.6, §8.6). Different principal, identical patches: `412`.
- [ ] **HTTP-23** (Frozen namespaces) Frozen namespace: resource writes, batches with items, blob uploads and copies (§7.8) `409`, `code: "frozen"`, any `successor`, after authorisation and the idempotent-retry lookup (§6.2, §8.4).
- [ ] **HTTP-8** (Namespace revision, Caching) Every successful write recording a namespace entry answers `X-Namespace-Revision: {ns_id}` naming it: creates, appends, restores, deletes; purges and namespace purges (on `204`); config writes; batches; branch creation; a prune that moved the horizon or changed `keep`. An idempotent retry carries the original's entry. Blob uploads and copies, a no-change prune, a dry run: none. Write responses `Cache-Control: no-store`.

### §7.3 Events (Server-Sent Events)

- [ ] **HTTP-9** (Events) `GET /r/{ns}/{name}/events?since={id}`, `GET /ns/{ns}/events?since={ns_id}` replay entries after `since`, one log page (§7.1) per fetch, then stream live.
  - `Last-Event-ID` wins over `since`. Neither, or empty `since`: from genesis; no entries yet: waits for the first.
  - Replay judged as its log range, before any event: `since` not in the log `404`; a revision to replay with pruned patch set `410`. A prune reaching a page not yet sent ends the stream.
  - `Cache-Control: no-store`. Requires `read`, unrestricted for a namespace stream (§2.1) except as §7.9 allows, re-judged before each log page fetched and each keep-alive; the stream ends if it fails, and when the grant or cookie it was admitted under expires.
- [ ] **HTTP-24** (Events) Resource stream event types: `revision`, `tombstone` (data the resource log entry (§7.1), `id:` its id); `purge`, `prune` (data the recording namespace entry (§7.4) without `id`, `prev`; no `id:`); in a filtered stream also `hidden` (HTTP-71). Ends after its `purge` event. A namespace purge sends no `purge` event and ends the resource's streams. Replay carries only `revision`, `tombstone`. Namespace stream events: its log entries as §7.4 serves them, `id:` the entry's `id`; ends after its `purge-ns` event, or without it where log ranges are sealed; a `since` naming that entry `410`.

### §7.4 Namespace

- [ ] **HTTP-69** (`GET /ns?after={name}`) Operator grants only, in order: §C.2 item 1 shape checks; blocks carrying `ns` not all `"*"` `403`; failing verification, not verified by an operator key in its period, or no credentials, `401`, but one its operator key's scope doesn't allow `403` (§C.2 item 1); a grant carrying roles, or a block carrying `can` without `config` or carrying non-empty `rules`, `403`. Auth disabled answers everyone. Rows of the namespaces the API can address, `{ name, created, base?, frozen, purged }`: `created` of the creating entry (base's `branch` entry for a branch, else the chain's first); `base` as in the namespace document; `frozen` (§8.4), `purged` (§8.5). Ascending byte order strictly after `after` (a plain bound), paged by `logPageSize`, `next` absent on the last page; `prefix` a namespace name, else `400` (`bad_input`). `no-store`.
- [ ] **HTTP-10** (table) `GET /ns/{ns}`: `302`, `Location: /ns/{ns}/rev/{ns_id}`, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}`; head pointer. `GET …/rev/{ns_id}`: `200`, document in force at that chain point, `ETag: "{ns_id}"` (`"{ns_id}.{e}"` sealed), `X-Config-Revision: {config_id}`; immutable. `ns_id` not in the chain `404` (short), also at its `/log` and `/heads`.
- [ ] **HTTP-25** (table and the row's lead-in under it) `GET …/rev/{ns_id}/log?since={a}`: `200`, immutable, paged (§7.1), array of `{ id, prev, kind, resource?, name?, at?, target?, entries?, source?, forced?, author, via?, grant?, gesture?, undoes?, gestures?, created }` per §3.5; `prev` the previous entry's id, `""` on the chain's first. `gesture`, `undoes` of a single write; `gestures` maps each batch resource to a list of `{ "gesture"?, "undoes"? }`, one per step; none hashed. `grant` `{ "id", "sub", "kid" }`: grant id (§C.3) in text form, root `sub`, `kid`.
  - `grant` recorded for: branch creation (creator's, both entries); namespace genesis (operator's).
  - `grant`, `via` absent from server-written entries (propagated and followed purges, §8.3, §G.1, its own prunes and its own rotations, §E.2.1); `grant` `null` on other entries written while authentication is disabled.
  - Empty or omitted `since`: from the chain's first entry; `404` if `a` is neither `ns_id` nor earlier in its chain.
- [ ] **HTTP-26** (table and the row's lead-in under it) `GET …/rev/{ns_id}/heads?after={name}`: `200`, immutable, `{ "heads": [ … ], "next"? }`, page of `{ resource, kind, target, created?, size?, digest? }`: one row per resource as of that revision, read-through ones included; `kind`, `target` of its latest `head`, `tombstone` or `purge` entry, or `purge` with that `target` if purged since (§8.3); ascending byte order of name, strictly after `after` (needn't name a resource); with `prefix` (a resource name, §3.6; else `400`, `bad_input`, request-shape, §6.2), only names starting with it. `next` names the following page, absent on the last. Neither sealed nor end-to-end, judged by the serving namespace: `created` the target entry's; for a live head of an unpurged resource, `size` canonical document byte length, `digest` its uncoded `Repr-Digest` value (`sha-256=:…:`). At E2, E3: all three absent. Readers MUST NOT rely on them. `410` once purged (§8.5).
- [ ] **HTTP-27** (table and the row's lead-in under it) `GET /ns/{ns}/principal`: `200`, `no-store`, `X-Config-Revision`, `{ "principal", "kid", "key", "operator", "can", "roles", "writer": { "frozen", "successor"?, "nonce", "signatures", "level"?, "limits" } }`, for the grant in `Authorization`:
  - `principal` per §6.4.1; `kid` the key that verified the root block; `key` the RFC 7638 SHA-256 thumbprint, base64url unpadded, of that key as JWK `{"crv":"Ed25519","kty":"OKP","x":<pub>}` (namespace key) or the published JWK (operator key).
  - `operator` true for an operator grant: `can` its blocks' verbs, `roles` `[]`. Otherwise `can` the verbs its blocks and key allow (role-carried: only those an effective role lists), `roles` its effective roles only, each exactly `{ "name", "can", "rules" }` as configuration of `X-Config-Revision` defines it (`rules` `[]` if none). `can` never lists `branch` where branches are refused.
  - `writer`: `frozen`, `successor`; `nonce` `required` where the document requires nonces or the namespace is sealed at E2, else `optional`; `signatures` `optional`/`required`; `level` `at-rest`/`sealed`/`e2e`, absent without `encryption`; `limits` every §6.6 limit in force (namespace value, else deployment default), without allowances or a key scope's `rate`.

  **[vectors I.12]**
- [ ] **HTTP-28** (table and the row's lead-in under it) `GET /ns/{ns}/principal` applies only the `ns` check (§7) and verification (§C.2 item 1, key scope included); no verb check, no rule. Operator grant, nonexistent namespace `404`; grant failing `ns` check `403`; grant unusable or none `401`, even in a public namespace; authentication disabled `200` without `principal`, `kid`, `key`, with `operator: false`, `can` every verb the server allows, `roles` `[]`, nonexistent namespace `404`; purged namespace `410` once the grant verifies (§8.5). Draws no rate token.
- [ ] **HTTP-29** (table and the row's lead-in under it) `GET /ns/{ns}/gestures/{gesture}`: `400` (`bad_input`), request-shape, for `{gesture}` not of §7.2's form or `after` not `{resource}/{id}`. Sealed or end-to-end namespaces: `404` `code: "not_offered"`, after the `read` check. `200`, `no-store`, `[{ resource, id, kind, gesture?, undoes?, author, ns_id }]`, one per revision or tombstone written with or undoing that gesture, oldest first, omitting purged resources, listing only revisions the grant may read (§C.2 item 5, AUTH-31); `403` to a grant that may `read` nothing there (§C.2 items 2 and 5). Paged by `logPageSize`: a full page carries `X-Log-Next: {resource}/{id}` (its last row), the next page is `?after=` that; `after` naming no row this listing would give the caller `404`; no `X-Log-Next` is the last page.
- [ ] **HTTP-30** (table) `GET /ns/{ns}/grants/{gid}`: `200` `{ id, root, stored }` for a grant recorded by an entry of this namespace, or, in a branch, of its bases up to their `at`, in non-bearer form (§C.3.1); else `404`. Needs unrestricted `read` (§2.1). Sealed in sealed namespaces, `private` in end-to-end ones; cached immutable (`private` at E3).
- [ ] **HTTP-31** (table and the row's lead-in under it) `GET /ns/{ns}/branches?after={name}`: `200` (head pointer), `{ "branches": [ … ], "next"? }`, a page of `{ name, at, frozen, purged, successor?, drafts? }` for direct branches; rows in ascending byte order of name, strictly after `after` (a plain bound), paged by `logPageSize`, `next` for the following page, absent on the last. Needs unrestricted `read` (§2.1); `410` once purged (§8.5).
- [ ] **HTTP-11** (Namespace writes, table, Content types) `PATCH /ns/{ns}`, `application/json-patch+json`; precondition `If-Match: "{config_id}"` or `If-None-Match: *` to create. Success `201`, `X-Config-Revision: {new config_id}`, `X-Namespace-Revision: {ns_id}`, `Location: /ns/{ns}/rev/{ns_id}`, body `{ "config": new config_id, "ns_id" }`. Idempotent retry (§7.2) `200`, same headers and body (config change written by a batch: `ns_id` the batch's entry). Failure `412` `{ config }` (no `config` for creation under a taken name); `422`; `428`; `401`; `403`. Other content types `415`.
- [ ] **HTTP-32** (Envelope) Config writes are checked with a `config` envelope (§6.4.1); key-scope and grant rules apply.
- [ ] **HTTP-33** (Keys, roles, revocations, limits and exposure) Need a `*` key (§C.2): writes covering/overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption`, `/signatures`, `/nonce`, `/schemaReads`; writes setting `read` to `public`. Making `read` stricter: none.
- [ ] **HTTP-34** (Validation, Members, `x-` members, Errors) The namespace document is validated against the built-in schema of the deployment's version: rules and patterns well-formed and within limits; §12.3 members (core, Addendum F) strict; any other top-level member must start with `x-` (case-sensitive) and is stored as data, as may members inside the addenda's objects (§12.3); role entries open (core reads `can`, `rules`); other nested objects (key entries) strict. Else `422`, `code: "invalid"`, `errors: [{ "pointer", "message" }]`.
- [ ] **HTTP-35** (Versions) Tools reading another deployment's namespace documents ignore undefined members; a tool copying a document into a namespace refuses one holding such a member (unless `x-`), as a config write does; none refuses on spec version alone.
- [ ] **HTTP-36** (Logging) A config change appends a `config` entry to the namespace chain. Namespace event type is the entry's `kind` (`head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns`, `prune`).
- [ ] **HTTP-37** (Branch fields) `422` (`invalid`, `errors` pointing at the member):
  - setting or changing `base` other than by a branch's creation (§7.6), a `PATCH`-created namespace's `base` included;
  - a branch config write removing or changing a key entry with the `kid` and `pub` of a `*` key in a base (MUST NOT);
  - `successor` at a creation other than a branch's;
  - setting or changing `successor` to anything but another existing, unpurged namespace (MUST): for a branch, a branch of the same base or of a namespace further up its `base` chain (`at` may differ); else another non-branch;
  - a branch of a non-public namespace becoming `public` (MUST NOT);
  - a branch breaking Addendum E's level rules (Levels) or turning off its base's `nonce` requirement (MUST NOT).
- [ ] **HTTP-38** (Branch fields) `drafts: { "for": [ … ] }` optional: names or `*`-ending prefixes of other namespaces whose writes, and their branches', may resolve schema paths into this branch (§6.1). Bare `"*"` serves all; without `drafts`, only the branch and its own branches. Narrowing: §6.1's `in_use` rule. `drafts` `422` in a namespace that isn't a branch or is end-to-end. `409` `code: "in_use"` with `dependents`: making a namespace with public dependents non-public; making a namespace require nonces while a dependent doesn't. A namespace can't raise its level above a dependent's (Addendum E, Levels).

### §7.5 Batches

- [ ] **HTTP-12** (Items, Scope) `POST /ns/{ns}/batch` writes several resources of one namespace, all or nothing. Each item names one resource, at most once per batch, with exactly one precondition as §7.2; missing `428`. `400` (`bad_input`), request-shape (§6.2): a resource named twice; an item with both `ifMatch` and `ifNoneMatch`; an item without steps. `steps` apply in order: a patch set appends, or restores if the previous entry is a tombstone; `"delete"` appends a tombstone. A first-step `"delete"` under `ifNoneMatch`: `428`; a `"delete"` after a `"delete"` with no patch set between: `422` (`invalid`); both at step 2.5 of §6.2. Resource purge is never part of a batch.
- [ ] **HTTP-39** (Items) A step may be an object with exactly one of `"patches": [ … ]`, `"delete": true`, optionally `gesture`, `undoes` (§7.2), `signature` (author signature, `Signature` header form, §C.3.1). An item or the batch may carry `gesture`, `undoes` as defaults, which a step's own override; the batch may carry them as `Gesture`, `Undoes` headers instead; both ways `400` (`bad_input`).
- [ ] **HTTP-40** (Checks) Every step is checked with its own envelope (§6.2). `items` may be empty or absent when `config` is present; neither: `400` (`bad_input`), request-shape. The optional `config` change runs steps 1–6 first as a config write (§7.4), `*`-key guard included (§C.2); items are then checked against the configuration it produces, except `frozen` and the batch limits (§6.6), from the current one. `frozen` refuses items only: an item-less batch works in a frozen namespace.
- [ ] **HTTP-41** (Checks) A body over four times the larger of the verified principal's `batchSize` and the deployment maximum of `documentSize` stops being read at once (`413`). Item counts, and the items' total canonical patch-set size against `batchSize`, are checked at step 4, before any item's own limits. Items may reference schema revisions created by earlier items (§6.1); blobs: HTTP-60.
- [ ] **HTTP-42** (Success) Success appends one `batch` entry (§3.5): `201`, `{ "ns_id": …, "config"?: …, "items": [{ "resource": …, "ids": [ … ] }] }`, `X-Namespace-Revision`. With a `config` change, `config` and `X-Config-Revision` give the new config id.
- [ ] **HTTP-43** (Failure) A failed batch writes nothing.
  - Status: the earliest failing step of §6.2; items failing it with different statuses: the first in request order.
  - Body `{ "code": "batch", "items": [{ "index", "status", "code", … }] }` for the items failing at that step; if any item fails authorisation (§6.2 steps 1 and 2.2), only those.
  - A failing `config` change: as that config write (§7.4), without `items`.
  - Purged (§8.5) or frozen (§8.4) namespace, rate limit, `itemsPerBatch`, `batchSize` (§6.6), refused `source`: as a single write, without `items`.
- [ ] **HTTP-44** (Dry run) `?dry-run=1` runs steps 1–6 for the `config` change, if any, and every item, as a submit would, writing nothing.
  - Items checked as in HTTP-40 (current configuration if the change fails after step 1). An unavailable blob is reported, later steps run as if available.
  - `200` `{ "items": [{ "index", "status", "code"?, "ids"?, … }], "config"? }`: every item, `status` `201` if it would pass, `200` for each when a submit would be an idempotent retry; every report carries any `signature` failure and, with `201` or `200`, the ids a submit would produce. `config`: `{ "status", "code"?, "config"?, … }`, the id a submit would produce.
  - `config` change fails step 1: answered as that config write. Else any item failing authorisation (§6.2 steps 1, 2.2): `401`/`403`, only those items.
  - Rate limit, purged or frozen namespace, `itemsPerBatch`, `batchSize`, refused `source`: answered as a submit.
- [ ] **HTTP-45** (Idempotent retry) `200` with an earlier batch, as §7.2, when one earlier `batch` entry by the same principal contains exactly the entries this batch would produce, config entry included, with the `config` change's `ifMatch` as its parent, and every item passes the retry's verb check (§C.2 item 2). Only `batch` entries match: a config-only batch retries an earlier `batch` entry holding just that config entry. A purged resource among the items: `410` before any other precondition, `batch` body listing those items (`code: "gone"`).
- [ ] **HTTP-46** (Reading other namespaces) Checks reading a namespace other than the request's (a batch's local `source`, a blob copy's source (§7.8), a schema revision elsewhere, a branch draft included (§6.1)) try the request's grant and every `Source-Authorization` grant (repeatable). The first grant that names that namespace, verifies under its keys (§C.2) and allows that read serves; a public namespace needs none. If none serves, the check fails as its own section says, revealing nothing about the namespace.
- [ ] **HTTP-47** (`source`) `source` is recorded in the batch entry. Local source, caller with unrestricted `read` on `source.ns` (as HTTP-46): `source.at` must be in `source.ns`'s chain (`422`, `code: "source"`), at step 4 of §6.2, after the batch limits and before any item's checks. Local source, any other caller: recorded unchecked, no blobs available. Source in another deployment carries `origin`, recorded unchecked; an `origin` equal to this deployment's own: `422` (`source`), any caller, same step.
- [ ] **HTTP-48** (Events) Each resource's event stream carries its new entries; the namespace stream one `batch` event.

### §7.6 Branches

- [ ] **HTTP-13** (Request, Result) `POST /ns/{base}/branches` `{ "name", "at"?, "patches"? }` (`patches` defaults `[]`):
  - `at` defaults to the base's latest `ns_id` at entry insertion.
  - `If-None-Match: *` required; `If-Match` alone `428`, at step 2.5 of §6.2, never answered as a retry.
  - `201`, `Location: /ns/{name}`, `X-Namespace-Revision` of the `branch` entry appended to the base's log (§3.5).
  - Taken name (a purged namespace's included): `412`, no `head` or `config`.
  - Retry by the same principal with the same `at` and `patches` (omitted `at` counts as the recorded one): `200` as §7.2 until the branch is purged, then `412`.
  - `at` not in the base's chain `422`; purged base `410` `code: "purged"`.
- [ ] **HTTP-49** (Configuration) The branch's document starts as a copy of the base's current one; `frozen`, `successor`, `merged`, `abandoned`, `cleanup`, `drafts`, `schemaReads` removed, `base: { "ns": base, "at": at }` added, then `patches` applied. Its configuration chain starts with one entry, genesis patch set `[{ "op": "add", "path": "", "value": <document after patches> }]`, the `target` of the base's `branch` entry. Rules, roles, read mode are then the branch's own; keys follow the base (§C.4).
- [ ] **HTTP-50** (Authorisation) Creating a branch needs `branch` and unrestricted `read` (§2.1) on the base, per §C.2 item 2. The `*`-key guard (§C.2) applies to `patches`, with a `*` key of the base; every `*` key of the base stays in the branch, unremovable. The base's rules evaluate a `branch` envelope: `resource` the new name, `doc` the new document, `writes` from `patches`. Failures as other writes (§6.2, §C.2).
- [ ] **HTTP-51** (A branch is a copy, Nesting and number) Whoever can read the branch can read the base as of `at`, under the branch's configuration. A branch of a non-public namespace MUST NOT be public. A branch may be a base, within the branch-depth and branches-per-namespace limits (§6.6).
- **HTTP-52** Retired in v0.87: remote branches are removed; a `base` is set only by a branch's creation (HTTP-37), and content moves between deployments by export and import (§G.4).
- [ ] **HTTP-53** (Reading through) A resource with no entries of its own in the branch answers as the base did at `at`, recursively through bases: `302`, `Location: /r/{branch}/{name}/rev/{id}`, `ETag: "{id}"`, `id` the head as of `at`; tombstoned then `410`; nonexistent then `404`. Base changes after `at` are never seen, except purges (§8.3) and the base's pruning (§8.6).
- [ ] **HTTP-54** (History) `/r/{branch}/{name}/rev/{id}` serves any id in the resource's ancestry as seen from the branch, base revisions up to the foreign parent included; `…/log?since=` crosses the foreign parent; `…/blob/{bid}` serves the branch's own blobs and the base's that the branch's view references.
- [ ] **HTTP-55** (First write) The first write to a read-through resource checks its precondition against the base's head as of `at` and takes it as foreign parent, whether appending, deleting or restoring. If the document built on (for a delete, the one deleted) is pruned (§8.6): `410` (`pruned`) once the precondition passes. A name nonexistent in the base at `at`: ordinary create.
- [ ] **HTTP-56** (Logs) The branch's namespace log holds only its own entries.

### §7.7 Live reads by long-poll

- [ ] **HTTP-57** (Answer) `GET /ns/{ns}/log?since={ns_id}&live=long-poll&cursor={c}`, `GET /r/{ns}/{name}/log?since={id}&live=long-poll&cursor={c}`:
  - Entries after `since` (empty or missing: from the beginning): `200` at once, up to one log page (§7.1), in §7.1, §7.4 shapes; `X-Namespace-Revision` (resource logs: `X-Revision`) names the last entry returned.
  - Else waits for an entry or the end of the current interval; timeout `204`, same header naming `since` (omitted when `since` is empty); both answers carry `X-Cursor`.
  - `since` not in the chain `404`; pruned range `410` (§7.1). A resource with no entries waits as for empty `since`.
  - Namespace log needs unrestricted `read` (§2.1), except as §7.9 allows; resource log `read` on the resource.
  - Without `live`: `302` (head pointer) to `…/rev/{head}/log?since=…`; a resource with no entries `404` (short).
- [ ] **HTTP-14** (Intervals and cursors, Clients)
  - Fixed intervals (default 20 seconds), counted for each log from a fixed epoch plus the log's phase: the first 8 bytes of the SHA-256 of its long-poll URL's path (`/ns/{ns}/log`, `/r/{ns}/{name}/log` or `/ns/{ns}/view/{view}/log`, no query), unsigned big-endian, modulo the interval in milliseconds; interval `n` starts at epoch + phase + `n` × interval. Cursor is the decimal interval number.
  - Response cursor: `200` current interval number; `204` the greater of that and request cursor plus one.
  - Cursor more than an hour's worth of intervals ahead of or behind the server's: `400`.
  - No cursor, or behind by less: answered at once, entries after `since` if any, else `204` with current cursor in `X-Cursor`.
  - Ahead by an hour's worth or less: waits as a current one, to this server's interval boundary at the latest; `204` carries request cursor plus one.
  - Clients echo `X-Cursor` as `cursor` in the next request and take the returned revision as the next `since`.

  **[vectors I.25]**
- [ ] **HTTP-58** (Caching) Cache key: path plus `since`, `live`, `cursor`; page size is the deployment's, not the client's. Any other query parameter, a `live` other than `long-poll`, or a non-decimal `cursor` (`live` or not): `400`. `200` `public, max-age=0, s-maxage={interval}`; `204` `public, max-age=0, s-maxage=2`. Private namespaces follow §9 with these lifetimes at the edge. Tags `ns:{ns}`, and `r:{ns}/{name}` for resource logs.

### §7.8 Blobs

- [ ] **HTTP-15** (References) A blob reference is an object, at any depth, whose `$blob` is a string: `$blob` blob id (§3.7), `type` media type, `size` byte length, `nonce` present exactly when the blob has one; no other members, except `sealed` at E3 (§E.3.1). At a raw document's root, top-level members validation leaves out aren't part of the reference. Found by walking the document, with or without `$schema`. Malformed: `422` (`code: "blob"`). Schema documents (`$schema` a dialect URL) contain none.
- [ ] **HTTP-59** (Attachments, Pending, Attached)
  - After upload or copy a blob is pending until a revision references it. Uploader: root `sub` and `kid` (§6.6). Pending blobs: reads `404`; only the uploader can reference them.
  - Each uploader has its own pending entry, even for bytes already stored, counted toward its `blobPending` (at least 4 KiB per blob), deleted once older than `blobGrace`; uploading again restarts that time.
  - A write whose document references the blob ends every pending entry for it in that resource.
  - At step 7 of §6.2 a write attaches every blob its resulting document references to its own resource, in the revision's transaction.
  - An attachment lasts while a document still stored for the resource references the blob: those at or after the horizon, the horizon's and other kept documents, a tombstoned resource's last live document. When pruning removes the last, the attachment ends and its bytes are deleted (where identical bytes are stored once, only this reference is removed; bytes go when nothing holds them). Purge ends every attachment of the resource.
- [ ] **HTTP-60** (Availability) A write may reference only blobs available to its resource:
  - attached to it in this namespace;
  - pending there, if the writer uploaded or copied them;
  - in a branch: attached to the same resource in a base and referenced by a document in its history as the branch sees it (the write attaches them to the branch's resource);
  - in a batch with a local `source` whose `source.at` is checked (§7.5): attached to the same resource in `source.ns`, or a base it reads through, and referenced by a document in that resource's history as `source.ns` sees it at `source.at`, whatever the ranks. From a sealed `source.ns`: only blobs the caller's keys open (§2.1).

  An unavailable blob, or a reference not matching its `type`, `size` or `nonce`: `422` (`code: "blob"`), at step 4 of §6.2.
- [ ] **HTTP-61** (Uploading, No precondition) `PUT …/blob/{bid}` checks in order:
  1. Authorisation at step 1 of §6.2, `create`, `append`, `restore` as candidates (§C.2 item 2), then rate limits (§6.6), then `422` (`limit`) if its rules ran out of `validationSteps` (LIM-7). No rule beyond step 1 sees an upload.
  2. Purged resource `410`; any upload to a purged namespace `410` (`purged`). Tombstoned resource accepts uploads.
  3. Frozen namespace `409`.
  4. Unparsable media type `400` (`bad_input`); likewise a `Blob-Nonce` not 26 base32 characters, empty included. E3: any type other than `application/vnd.patchlog.sealed-blob` `415`. Order: these `400`s, a precondition's `428`, this `415`.
  5. Body over `blobSize` `413`; likewise one taking the uploader's pending blobs in the namespace past `blobPending`.
  6. Id recomputed over the body (§3.7), `Blob-Nonce` as nonce or empty, must match, else `422` (`blob_mismatch`).

  URL and query errors, malformed `{bid}` included (`400`, `bad_input`), precede check 1. Other request-shape errors in upload headers `400` (`bad_input`) at check 4 (a copy's: see Copying); a precondition: `428`, at check 4. Idempotent: `201`, `ETag: "{bid}"` whether or not the bytes were stored; each uploader is charged for its own pending entry.
- [ ] **HTTP-62** (Copying) An upload with empty body and `Blob-From: /r/{ns2}/{name2}/blob/{bid}`, naming the same `bid`, copies a blob within the deployment.
  - Checks 1–3 first, for the target.
  - Then, before any body is read: a request whose headers announce a body, an unparsable `Blob-From`, or a check-4 header error outside `Content-Type`, `Blob-Nonce` `400`; then a precondition `428`; then a different `bid` `422` (`blob`).
  - Source then checked as a read of `/r/{ns2}/{name2}`, as HTTP-46; a grant whose blocks name both namespaces, signed by a key they share, serves for both. Any failure, `401` and `403` included: `404`.
  - Also `404`, each alone: the copy goes into another namespace ranking below its source (§2.1); Reading wouldn't serve the blob at the source; the blob is from a sealed source and the caller's keys don't open it.
  - Then checked as an upload of the source's type, nonce and size (checks 4, 5), whatever `Content-Type`, `Blob-Nonce` it carries.
  - Costs a token like an upload, nothing from `blobRate`.
- [ ] **HTTP-63** (Files) A document is raw when its root is a blob reference with no members other than the top-level ones validation leaves out (`$schema`, a fresh `$nonce`, a `$successor`). Served at `…/raw` (§7.1) with the blob's type. The read check of `…/raw` is its document's, and of `…/blob/{bid}` as HTTP-64 says; a `schemaReads` referrer (§6.1) opens revision paths only. Its `size` in `/heads` (§7.4) is the reference's length.
- [ ] **HTTP-64** (Reading)
  - Every blob URL response, errors included: `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`. Exception: `200`/`206` for a stored `type` of exactly `application/pdf` may omit the sandbox, keeping `nosniff`. PDFs: `Content-Disposition: attachment` unless the deployment opts into inline display.
  - `200` carries `Content-Type` the stored type (§3.7), plus `; charset=utf-8` for `text/*`, `ETag: "{bid}"`, `Accept-Ranges: bytes`; `206` for a range, same `ETag` and `Accept-Ranges`: one range keeps `Content-Type` and adds `Content-Range`, several are `multipart/byteranges` (RFC 9110, section 14.6). Sealed namespaces answer as §E.2.2.
  - Whoever may read a stored document that references a blob may read the blob (`doc` as RUL-8 gives it); served: blobs attached to the resource and, in a branch, the base's that the branch's view references. A tombstoned resource keeps serving its blobs. Cached immutable, with the resource's tags (§9).
- [ ] **HTTP-65** (Encryption) In sealed namespaces and those requiring nonces, writers MUST give blobs they create a nonce (§C.7); the server doesn't check. Blobs carried over from another namespace keep their ids, nonce or not.

### §7.9 Filtered reads

- [ ] **HTTP-70** (intro, Where, Partial reader, Answers) Optional (CONF-4). Only while authentication is on, in a namespace that is neither a branch, public, sealed nor end-to-end; elsewhere the filtered URLs answer `403`, or `401` without a grant or cookie that verifies, in §7's order. A partial reader's grant verifies in `{ns}` and allows `read` there; no block or key-scope rule refers to `/now` and, if it carries roles, an effective role listing `read` has none; and it lacks unrestricted `read` (§2.1): its read rules refer to `/resource` without fixing it, or to `/doc`.
  - Unrestricted readers keep the unfiltered URLs; at filtered ones their grant in `Authorization` is `403`, and a `/ns/{ns}` cookie counts as that view's cookie.
  - To a partial reader: `GET /ns/{ns}` is §7.4's head pointer; `/heads`, log ranges, long-poll and events are filtered (HTTP-71, HTTP-72); a resource's URLs and the gestures listing serve visible revisions only (AUTH-31); `GET /ns/{ns}/rev/{ns_id}`, `/grants/{gid}`, `/branches` and other reads answer as without §7.9 (`403`).
- [ ] **HTTP-71** (Visible, Log entries) A revision is visible when the reader's blocks, key scope and roles, counted as §C.2 item 5 counts them, allow `read` with that revision's `read` envelope (RUL-8). Entries keep their shapes; only the set changes, and nothing is stored for it:
  - a `head` is shown when its revision is visible, a `tombstone` when the document it deleted is; one not shown whose resource's previous `head` or `tombstone` entry was shown as itself (a `hidden` stand-in doesn't count) is shown in its place as `{ "id", "prev", "kind": "hidden", "resource" }`, or, in a batch, `{ "kind": "hidden", "resource" }` among its `entries`; any other is dropped;
  - a `prune` is shown when its `target`'s document is visible; a `purge` when the grant's rules that don't refer to `/doc`, `all`s flattened, allow `read` of its resource;
  - `config` and `purge-ns` always, `branch` never;
  - a `batch` shows only its shown `entries`, and its `gestures` and `source.ids` only for items shown as `head` or `tombstone`, each left out if empty; one showing nothing is dropped, or kept as `config`-only if it has a config entry;
  - a resource's own log, long-poll and event stream show its visible revisions, without `patches` where the parent is hidden, and `{ "id", "parent", "kind": "hidden" }` (event type `hidden`) for each hidden one whose parent is visible; its `purge` and `prune` events as the namespace log shows them.
- [ ] **HTTP-72** (Log ranges, `/heads`, Long-poll, Events, Cost)
  - Log ranges page as §7.1, a batch counting as its shown items and a dropped entry as one, so a page may show none. A range ends at the URL's `at`, carried as `X-Namespace-Revision`; every page but the last carries `X-Log-Next`, naming its last entry, shown or not.
  - `/heads` lists a row only where its head revision is visible, a tombstone as its deleted document and a purge as its entry is shown; pages filled to `logPageSize`, `next` (the last row returned) on every full page and no other.
  - Long-poll: only shown entries answer `200` or end a wait; a wait may also end `204` at once after a bounded scan of at least one page; `X-Namespace-Revision` names the newest entry scanned, and a `since` or `Last-Event-ID` may name a dropped one.
  - Events carry only shown entries, with each read check §7.3 repeats, the cookie check (HTTP-74) included.
  - SHOULD: each revision's visibility judged at most once per view and kept, even once pruning drops the document (§8.6); waiting followers of a view share it.
- [ ] **HTTP-73** (URLs) Ranges at `/ns/{ns}/view/{view}/at/{ns_id}/heads` and `…/log`, `ns_id` an entry of `{ns}`; long-poll at `/ns/{ns}/view/{view}/log`, events at `/ns/{ns}/view/{view}/events`.
  - A `view` or `ns_id` not in text form: `400` (`bad_input`), request-shape.
  - Ranges immutable but for purges since (§8.3), tagged as their unfiltered forms (§9).
  - A URL under the prefix without `at` (a `…/log` without `live`), and a partial reader's request at an unfiltered URL: `302`, `private, no-store`, to the filtered form: a range at the current `at`, a long-poll or stream with its query.
  - A grant in `Authorization` reads only at its own `view` (`403` elsewhere).
- [ ] **HTTP-74** (`view`) `view` = `text(trunc160(sha256(canonical(subjects))))`, `subjects` in byte order of UTF-8: `scope:{digest}`, `digest` covering the rules limiting the grant's `read` in `{ns}` (blocks, key scope, each effective role listing `read`) and the values at the `/principal` paths they test or compare, absent for a grant §C.5.2 would give `/ns/{ns}`; and `key:{text(trunc160(sha256(canonical([kid, pub]))))}` of the key that verified the root block. Implementations needn't agree on `digest`.
  - The origin keeps, per namespace and view, the rules and `/principal` values its digest covers, and judges visibility under a cookie from those, never from a grant the request doesn't carry; a cookie whose `view` it keeps nothing for: `401` (`unauthenticated`).
  - Every cookie of a view is `403`, at every URL, once an entry after its exchange changes those rules, the key its `key:` string names, a key they came from or any role that lists `read`, even where a later entry undoes it, whoever's exchange made it; no exchange revives it; a cookie indistinguishable from such a one is `403` too. Streams judge this at the current entry and end when it fails.

  **[vectors I.8]**
- [ ] **HTTP-75** (Edge grants, Purged namespaces) The origin's exchange (§C.5.2) gives a partial reader the prefix `/ns/{ns}/view/{view}`, its cookie never outlasting the grant; §C.5.2's refusals concerning `/resource` and `/doc` rules and qualifying roles don't apply to it, and its pass-now check covers only block and key-scope rules referring to neither. A partial reader reads documents at their own URLs with its grant in `Authorization` (§9: `no-store` at the CDN).
  - Purged namespace: these URLs answer as §8.5 answers their unfiltered forms, once the URL's read check passes, its `view` included; a partial reader's unfiltered `/heads` is then `410`, without the `302`.

- [ ] **HTTP-76** (Content) A resource's immutable URLs are served under the view prefix: `/ns/{ns}/view/{view}/r/{name}/rev/{id}`, its `/raw`, `/r/{name}/blob/{bid}`; answered as their own forms for a visible revision or a blob a visible revision references, else as a read-rule failure; immutable, tagged as their own forms. A partial reader's `Authorization` request at the unfiltered revision URL is `302` to it; heads stay at their own URLs.
## §8 Deletion and purge

### §8.1 Tombstone (delete)

- [ ] **DEL-1** (Tombstone (delete), Moves)
  - `DELETE` with `If-Match: head` appends tombstone to resource log and a `tombstone` entry to namespace log, atomically.
  - Move: last revision before tombstone sets top-level `$successor`, bare name (resolved against namespace serving the `410`) or `/r/{ns2}/{name2}`, names valid under §3.6; either form is well-formed wherever the document is, whatever `ns2` names. Validation leaves it out (§6.2 step 5).
  - Head pointer then `410`; only in namespace neither sealed nor end-to-end does it carry `successor`, copied from last document's `$successor` if well-formed.
  - Earlier `/rev/{id}` URLs and blobs keep `200`.
  - Further `PATCH` `410` unless restoring (`If-Match: "{tombstone}"`). That `410`, and a `DELETE`'s: `code: "gone"`, `head` tombstone.
  - `PATCH` with `If-Match` under grant without `restore`: `403` (§6.2 step 2.2).

### §8.2 Restore / recreate

- [ ] **DEL-2** (Restore / recreate) First revision after tombstone applies its patches to last live document. `[]` restores it exactly, `$successor` included; where nonces are required (§C.7), fresh `$nonce` alone does. A root `replace` recreates from scratch, if namespace rules allow.

### §8.3 Purge

- [ ] **DEL-3** (Effect, Namespace entry, Responses, CDN, Branches)
  - Removes resource's content (patches, snapshots, blobs), marks it purged; shared storage loses only this resource's references.
  - Archived history (§8.6) deleted or made unreadable by destroying its key. Restoring from archive MUST skip purged resources.
  - `purge` entry appended to namespace log; consumers MUST drop resource and purge derived data and cache tags (§10).
  - All `/r/{ns}/{name}/…` URLs then `410`, before `not_offered`, once caller passes read check for that URL (writes: step 1 of §6.2); until then reads answer as for unreadable resource.
  - CDN purged by tag, `heads:{ns}` included, never by id, in each branch a purge reaches too, or by the base's tags where §9 Base tags allows (CACHE-6).
  - Propagates to same name in every branch of namespace, recursively, read through or own chain, successor generations and branch-created chains included: purge it, append a `purge` entry to that branch's namespace log.
  - Branch with no entry for name skipped; its own branches aren't.
  - Branch created later at an `at` before purge that would read an entry through: `410`; `/heads` lists it as `purge`, `target` its head as of `at`.
  - Never propagates upwards.
- [ ] **DEL-7** (Limits of purge) Copies of resource's blobs in other resources (`Blob-From`, §7.8) stay until those are purged.

### §8.4 Freezing a namespace

- [ ] **DEL-4** (Freezing, What still works, `successor`)
  - Config write `"frozen": true`; `false` unfreezes.
  - Frozen: resource writes, batches with items, blob uploads and copies `409`, `code: "frozen"`, plus `successor` if set. Checked at step 2.4 of §6.2 (check 3 of §7.8), after idempotent-retry lookup, so a retry of write recorded before freeze is still `200`.
  - Batch with no items is config write.
  - Unfreezing a branch whose base already has `branchesPerNamespace` live branches: `422`, `code: "limit"`, `limit: "branchesPerNamespace"`, `max` base's value.
  - Still work: reads, events, consumers, config writes, resource and namespace purges, creating branches from it, pruning.

### §8.5 Purging a namespace

- [ ] **DEL-5** (Request, Requirements) `POST /ns/{ns}/purge` with `If-Match: "{ns_id}"`: `204`; `428` without precondition; `412` with current `{ head }`. Checks in order, all before rules (step 6):
  1. `purge-ns` verb, distinct from `purge` (step 1);
  2. purged namespace `410` (step 2.1);
  3. not frozen: `409`, `code: "not_frozen"` (step 2.4);
  4. precondition (`412`, then `428`);
  5. dependents (§2.1): `409`, `code: "in_use"`, `dependents`, the first `logPageSize` by name, with `"more": true` if there are others;
  6. last copy of schema revision (§6.1) referenced from another namespace (own documents not counting): `409`, `code: "in_use"`, `referencing` (SCH-6).
- [ ] **DEL-8** (Effect)
  - Every resource purged as in §8.3, no individual entries; one `purge-ns` entry appended, log's last. CDN purged by tag `ns:{ns}`.
  - Purges propagated from base (§8.3) or followed from an origin (§G.1, FED-26), and retention prunes, skip a purged namespace.
  - Kept: namespace document chain, namespace log with authors, every resource's ids and parent links.
- [ ] **DEL-9** (Answers afterwards, table) Every `410` of §8.5: `code: "purged"`, `head` the `ns_id` of the `purge-ns` entry.
  - `410` URLs: `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…`, `/ns/{ns}/keys`, `/ns/{ns}/principal`, `/ns/{ns}/branches`, `/heads` at any revision. As soon as full read check passes, before any other answer to well-formed request, `not_offered` included. Read check: grant's rules plus unrestricted `read` where the URL needs it (any `read` for gestures; §E.2.3's test for `/keys`; verification alone for `/principal`).
  - `/ns/{ns}` and `/ns/{ns}/rev/{ns_id}`, logs, events, long-poll served as before, except events and long-poll from the `purge-ns` entry are `410`, and except where sealed (DEL-11).
  - Any write to namespace `410`, after authorisation and rate limits, before any other check (§6.2 step 2.1): resource writes, batches, blob uploads and copies, purges, prunes, config writes, branching from it.
- [ ] **DEL-10** (table)
  - Creating a namespace or branch under purged namespace's name: `412`; so a branch creator's retry once branch is purged.
  - Edge-grant issuance for grant naming a purged namespace: `410` only if every namespace refused is purged and grant verifies there; `ns`, `head` name first.
- [ ] **DEL-11** (Sealed namespaces) Where namespace documents and log ranges are sealed (§E.2.2), purge destroys the epoch keys their `K_n` derive from (§E.2.1); those reads, events, long-poll included, then `410`. `GET /ns/{ns}` still redirects, to revision that is `410` where sealed.
- [ ] **DEL-12** (Shared storage, Forcing, Irreversible) Shared storage loses only this namespace's references; `in_use` for schema references can be forced as §6.1 says; for dependents it can't. Purged namespace can't be restored.

### §8.6 Pruning and retention

- [ ] **DEL-6** (Pruning and retention, Horizon, Kept) Pruning changes no id. Revision below horizon without kept document: `410` (`pruned`), with link to archive if any. Pruning below horizon revision `H` drops patch sets before `H` and attachments of blobs only dropped documents referenced. Kept: every id, parent link, author, grant reference, creation time, `gesture`, `undoes`; ids of blobs whose attachments it ends; `H`'s document and protected documents; if `H` is tombstone, last live document.
- [ ] **DEL-13** (Request) `POST /r/{ns}/{name}/prune` with `{ "horizon": id, "keep"?: [ids], "snapshot"?: sealed }`: `200` `{ "horizon": id }`, effective horizon.
  - Needs `prune` verb, checked with a `prune` envelope whose `doc` is `{ horizon, keep? }` as sent.
  - No precondition; one sent `428`, at step 2.5 of §6.2, where resource that never existed is then `404`.
  - `horizon` MUST be head or ancestor (`422`); lowered to oldest protected revision if needed, never below current horizon.
  - Needs a grant chained to a `*` key: going below what `retention` keeps (everything, where no rule matches); pruning where no archive is configured.
  - Applying a retention rule saying `"archive": false`, within what it keeps, needs only `prune`.
- [ ] **DEL-14** (Request)
  - `keep`: extra revisions whose documents stay available, up to `keepPerResource`.
  - Outside a branch, each `keep` id MUST be a revision of resource whose document is still served (not `410` `pruned`), else `422`.
  - Prune sending `keep` replaces earlier set (`[]` clears); without `keep` leaves it. `keep` `422` in an E3 namespace.
  - `prune` entry `{ resource, kind: "prune", target }` (`target` effective horizon) appended only if horizon moved or `keep` changed; else nothing written.
- [ ] **DEL-15** (Protected revisions, Protected documents, Branches don't prune) Horizon never passes: any revision newer than retry window; resource's head as of the `at` of every unpurged branch, frozen or not.

  Below horizon these keep documents: schema revisions referenced (§6.1) from any namespace of deployment; revisions in `keep`. A branch's own entries are protected until it is purged. Prune in branch, once checks pass: moves no horizon, ignores `keep`, writes nothing (an archive included: only namespaces that aren't branches have archives), `200` with resource's current horizon as branch sees it, or its genesis id where none.
- [ ] **DEL-16** (Archive) Before pruning, server writes pruned history as full-history bundle (§G.4.1), `"authors": true` with grant lines, to destination configured by operator or in `retention`; MUST NOT write anywhere else. It holds that resource's pruned revisions alone, with the blobs they reference; no dependency closure (§G.4.2; an exception to §G.4.3's Modes close downward), no `external`; `docs` names only that resource, `requires` the parent of its first revision unless that is genesis. Outside a branch, only two prunes go without: under a `*` key where no destination is configured; applying a retention rule saying `"archive": false`. Encrypted namespaces: sealed bundles (§G.5.1.1), one per resource, only recipient a key server holds for that resource, destroyed by purge; each line padded (§E.2.2) where namespace sets `pad`.
- [ ] **DEL-19** (Archive)
  - At E3, prune carries `snapshot`, sealed like a patch set (§E.3.1), holding `H`'s document (last live one if `H` is tombstone).
  - At E3, prune without `snapshot`, or, outside a branch, with no archive configured: `422` (`invalid`), `*` key or not.
  - `snapshot` outside an E3 namespace: `422` (`invalid`), under any grant.
  - At E3, effective horizon moves horizon but isn't `H`: `422` (`invalid`), `horizon` effective horizon.
  - Server skips E3 namespaces when applying retention itself.
- [ ] **DEL-17** (Retention policy) Namespace document may declare `retention` rules, applied periodically by server or janitor with `prune`.
  - First rule whose `select` matches applies. `select`: name `prefix` or list of `names`; missing matches everything.
  - `keep`: whichever is longer, last `revisions` or everything newer than `age`.
  - Rule without `keep`, or `keep` with neither: `422` (`invalid`).
  - `archive`: rule's destination, default operator's. Rule with neither applies only if `"archive": false`; otherwise its resources keep everything, as where no rule matches. Any `"archive": false`: `422` in an E3 namespace.
  - Changing `/retention` requires a `*` key.
- [ ] **DEL-18** (The namespace log is never pruned) Namespace log is never pruned.
- [ ] **DEL-20** (Merges, branches and exports) Ancestry classification (§F.3) uses ids only, works across a horizon. Fast-forward or replay needing pruned patch sets after common ancestor: that item is conflict. Full-history export (§G.4.3) from before horizon needs archive.

## §9 Caching

- [ ] **CACHE-1** (table) In a public namespace, responses carry these `Cache-Control` values and tags. Unless other tags are named: `ns:{ns}`, plus `r:{ns}/{name}` for resources.

  | Class | `Cache-Control` | Tags |
  |---|---|---|
  | Head pointer (resource or namespace `302`, head `410`) | `public, max-age=0, s-maxage=1, stale-while-revalidate=5` | default |
  | Immutable (`/rev/{id}`, `/rev/{id}/log`, `/ns/{ns}/rev/{ns_id}`, its `/heads` pages, namespace log ranges, `/ns/{ns}/grants/{gid}`, `/blob/{bid}`, `/blob/{bid}/e/{e}`, and their ranges) | `public, max-age=86400, s-maxage=31536000, immutable`, except `/ns/{ns}/grants/{gid}` is `private` at E3 | default; `/heads` pages also `heads:{ns}` |
  | Short (unknown-id `404`) | `public, max-age=5` | default |
  | Long (`410` of a purged resource or namespace, on a URL that isn't `no-store`) | `public, max-age=86400, s-maxage=31536000` | default |
  | Pruned (`410` below a horizon) | `public, max-age=3600` | `r:{ns}/{name}` and `ns:{ns}` |
  | Live long-poll `200` | `public, max-age=0, s-maxage={interval}` | as the log |
  | Live long-poll `204` | `public, max-age=0, s-maxage=2` | as the log |
  | Writes, batches, dry runs, SSE | `no-store` | none |
- [ ] **CACHE-4** (Serving stale) Edge serving immutable responses while origin is unreachable still removes them when purged. Head pointers stale only within `stale-while-revalidate`. Live long-poll `200` and `204` MUST NOT be served stale: no `stale-*` directive; edge MUST NOT apply stale-if-error or grace defaults.
- [ ] **CACHE-2** (Tags, Branches, Making a namespace private) Tag `{kind}:{value}`: `kind` a lowercase word, `value` namespace and resource names joined by `/`. `Cache-Tag` comma-separated, `Surrogate-Key` space-separated. A purge names whole tags, never part of one. Branches cached under their own URLs and tags; propagated purges (§8.3) purge those too. Making a namespace private, or raising it to sealed, requires purge of tag `ns:{ns}`, issued by origin with configuration write.
- [ ] **CACHE-6** (Branches, Base tags; §12.8) A branch's response for a resource it reads through MAY also carry `r:{base}/{name}` for each base in its `base` chain, down to the one it reads from, and its `/heads` pages `heads:{base}` for each base. The origin, or a service, adds them only where every response reaches clients through caches that strip `Cache-Tag` and `Surrogate-Key`. Once no cache its purges reach holds a branch's response without them, those cached before it began adding them included, a deployment MAY satisfy a propagated purge (§8.3) by the base's tags alone, except `r:{branch}/{name}` of a branch with its own chain for the name. Filtered `/heads` pages (§7.9) carry `heads:{ns}` too.
- [ ] **CACHE-5** (Sealed namespaces) Cached by its `read` mode, under public or private rules.
- [ ] **CACHE-3** (Private namespaces) Downstream responses: `Cache-Control: private`, `max-age` no longer than their public class's. Edge lifetimes (`CDN-Cache-Control` or `Surrogate-Control` at public values) only for read edge verified itself, needing all of: both edge verification headers present; each one line, no comma; secret matches; prefix covers the URL; no `Authorization`, `Source-Authorization` or signed-URL parameters.

  Origin still authorises read itself, from cookie or grant edge forwards (§C.5.3). Headers decide only lifetimes, never when event stream ends (§7.3). Every other private response: `CDN-Cache-Control: no-store` (and `Surrogate-Control: no-store`), edge or not, including grant in `Authorization`, schema revisions opened by referrer (§6.1), reads edge only relayed, and where no verifying edge is deployed.

## §10 Namespace consumers

- [ ] **CONS-2** (Checkpoint, Catch up, Follow, Fetch content, Consumers elsewhere) Checkpoint = last `ns_id` fully processed (`""` = start). Catch up: `GET /ns/{ns}`, then `…/rev/{current}/log?since={checkpoint}` page by page. Follow: `/events?since={checkpoint}` or long-poll (§7.7). Content from immutable URLs; at E3, where `/rev/{id}` is `404` (`not_offered`), fold its log as §7.1 says (HTTP-68). Another network or organisation: checkpoint `(origin, ns, ns_id)`, fetches verified as §G.2.
- [ ] **CONS-1** (Handle every kind of entry, Advance the checkpoint) Per entry kind:
  - `head`: process document. `tombstone`: drop resource. `purge`: drop resource, purge derived data and cache tags. `batch`: process entries as one unit.
  - `purge-ns`: drop everything from namespace, purge derived data and cache tags. Where log ranges are sealed, a `410` `purged` stands for it.
  - `hidden` (filtered logs only, §7.9): drop the resource, which left the reader's view.

  Pruned revision (`410` `pruned`): fetch head; if pruned too, treat resource as absent until later entry. Advance checkpoint only after entries are durably processed; processing idempotent.
- [ ] **CONS-3** (Verifying grants) A consumer verifying grants presented to it MUST check keys and revocations as of namespace head (in branch, its bases' heads too), not checkpoint. Grants recorded with entries verified as §C.3.1.
- [ ] **CONS-4** (Branches: Discovery, Contents, Access) Branches: from `branch` entries in followed logs, recursively; if started from `/heads`, earlier ones from `GET /ns/{ns}/branches`. For such a branch, or one told to follow: start from its `/heads` listing at its first `ns_id` (read-through resources included), then its own log. Needs unrestricted `read` on branch (§2.1); skip one it may not read.
- [ ] **CONS-5** (Filtered logs) Filtered logs (§7.9) aren't chain-verifiable: consumer verifying chains needs unrestricted `read`. Partial reader follows filtered URLs, which cover no branch and carry no `branch` entries (`GET /ns/{ns}/branches`: `403` for it). A document entering its view arrives as a `head`, one leaving it as `hidden`; a change of the rules gives it another view, from whose `/heads` it starts again.


## §12 Registries

### §12.1 Errors

- [ ] **ERR-1** (§12.1 table and the lead-ins under it) Error answers carry their §12.1 row's `code`, status, body shape, named members.

### §12.2 Limits

- [ ] **ERR-2** (§12.2, table, closing paragraph) Namespace document setting a deployment-only limit: `422` (`invalid`). `limits`: sizes integer bytes, counts integers, durations ISO 8601, rates `{ "rate": <per second>, "burst": <bucket size> }`. `rulesPerNamespace`, `rulesPerGrant` count every rule form, nested in `all`, `any`, `not`, `if`, `then` included; `rulesPerGrant` counts those in grant chain's blocks.

## Addendum A — Indexing service

### §A.1 Following the namespace

- [ ] **SVC-5** (A.1) Follows each namespace as in §10 under a grant with unrestricted `read` (§2.1), never through a filtered log (§7.9), one checkpoint per namespace, stored in the same transaction as index writes. Per coalesced `head`, fetches `/r/{ns}/{name}/rev/{id}`:
  - No `$schema`: resource's rows removed.
  - Schema document (`$schema` a dialect URL, §6.1): indexed against that dialect's meta-schema; `schema=` with dialect URL lists schema documents. Revision paths of `$ref` keywords at schema positions, fragment dropped, are references.
  - Other: annotated fields and references indexed with schema revision pinned. That revision answering `4xx` but `408` and `429`, or unopenable for lack of keys: indexed as without `$schema`. Schema or keys fetch failing for moment (transport error, `5xx`, `408`, `429`): retried.

  `tombstone` removes resource's rows. `purge`, and a `config` entry on which §9 purges `ns:{ns}`, also purge `idx:{ns}` from service's own cache and drop kept results, serving or keeping no result of `{ns}`, scores and counts included, computed from what was read before it.

### §A.2 What gets indexed: `x-index`

- [ ] **SVC-2** (A.2, `text`, `facet`, `sort`, References) `x-index`: `"text"`, `"facet"`, `"sort"` or array. Only strings, numbers, booleans collected, through keywords marking a path (§A.4).
  - `text`: full-text, strings only.
  - `facet`: arrays expand to one value per element; value matches and counts as its string form (number or boolean as canonical JSON).
  - `sort`: ascending, or descending with `sort=-{path}`; document sorts by its least value at path: numbers before strings before booleans; numbers by value, strings by UTF-8 bytes, `false` before `true`. No value: last either way.
  - References need no `x-index`: each document walked with schema revision it pins; §6.5's references stored as `{ ns, name }` plus revision (pinned) or entry (`#id`), plus full instance pointer, array indices included. Untyped documents' references aren't found. `x-index` rows name the field without indices; text isn't scanned for paths.

### §A.4 Query API

- [ ] **SVC-6** (table, Bounded redirects, Unavailable namespaces, plain document URL)
  - `GET /{ns}?…` → `302`, cached as head pointer, to `/{ns}/at/{checkpoint ns_id}?…`, or for private namespace `/{ns}/view/{view}/at/…` (`private, no-store` when it adds `/view/{view}`).
  - `GET /{ns}/at/{ns_id}?…` → `200` `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", … }] }`, immutable (`no-store` where §E.2.6 says), tagged `idx:{ns}` plus `r:{ns}/{name}` per hit. `ns_id` no longer kept → `302` to current checkpoint, cached as head pointer. SHOULD answer `200` for a while (e.g. a minute) at an `at` it redirected to, computing or keeping the result, unless §A.1 dropped it, so a reader may be redirected again while purges keep coming. A kept result is keyed by its URL, `view` included, so it never outlives the rules it was filtered by.
  - Namespace not followed, or sealed/end-to-end with keys lacking (`/keys` answers `4xx` but `408` and `429`, or none it can unwrap): `404`, also where it learns this only during the read check. Purged: `410` (`purged`), once the read check passes against the last namespace document the service read.
  - No checkpoint yet for followed namespace: once reader's grant verifies, `503`, `no-store`, `code: "behind"`, `Retry-After`.
  - Hit `url` is `/r/{ns}/{name}/rev/{id}`, which the service never serves.
- [ ] **SVC-7** (`schema`, `ref`, `refs`, order and paging, Branches) `schema`: exact `$schema` reference, or schema's resource path `/r/{ns}/{name}` for all revisions. `ref`: documents of `{ns}` referencing a resource, combined with other filters: `/r/{ns2}/{name}` any form (live, pinned, to entry); `…/rev/{id}` only pinned to that revision; `…%23{entry}` only naming that entry, pinned or not; `…/rev/{id}%23{entry}` both.

  `ref` hits carry `refs: [{ "path", "ref" }]` (locations and strings matched, as written); other queries' hits don't. A self-referencing document is hit of its own query, `"self": true`.

  Order: `sort` if given; else with `q` descending `score` (from documents of `{ns}` reader may see only); else resource name; ties by resource name. Paging as `/_refs`: `after` a bare resource name, or with `q` or `sort` opaque `next`. Redirect from head pointer or to another `at` (here and on `/_refs`) keeps an `after` naming a resource, applied to new result; drops opaque one, starting again.

  Branch preview index: `ref` matches targets as written, naming base; hits are branch's versions of referrers.
- [ ] **SVC-8** (Across namespaces, `view`, `min`) `GET /_refs?to=<reference>` → redirect to `/_refs/view/{view}/at/{at}?to=…`, path always with `/view/{view}`; `at` the combined checkpoint `text(trunc160(sha256(canonical({ ns: ns_id, … }))))` over the followed namespaces the reader may see, purged ones left out.
  - `view` = `text(trunc160(sha256(canonical(markers))))`, `markers` in byte order of UTF-8, one `{ns}:{v}` per followed non-public namespace where the reader has a view `v` (SVC-11). None, or neither grant nor cookie: the empty array's `view`, `401` only as Coverage says.
  - URLs and cookies as for private namespaces (SVC-11, SVC-59), under prefix `/_refs/view/{view}`; the exchange refuses only as Coverage and those say. A cookie is `403`, until the reader exchanges again, once a namespace's coverage changes, or where the cookie of any of its markers' views would be.
  - `?min={ns}:{ns_id}`, repeatable, as SVC-1; namespace reader can't see, service doesn't follow, or Coverage leaves out: `400`, purged excepted.

  **[vectors I.8]**
- [ ] **SVC-9** (Answers, Coverage, tags) `/_refs` answer `{ "at", "namespaces": { ns: ns_id, … }, "hits": [ … ], "next"? }`, `namespaces` listing what `at` covers, one `ns_id` per namespace.
  - Hits carry `ns` beside a `ref` hit's fields, filtered per namespace as for private namespaces (SVC-11), in byte order of `ns`, then resource name.
  - At most `limit` hits per page, counted after filtering; every page but the last holds exactly `limit`; `limit` above maximum: `400`. Hits strictly after `after` (`{ns}/{name}`, compared as pair (`ns`, name) split at first `/`); `next` is next page's `after`, absent on last.
  - Hits from sealed/end-to-end namespaces sealed per entry (§E.2.6), never as whole response.
  - Includes branch previews; omits namespaces not yet reached, purged, and sealed/end-to-end without keys; a `min` naming one of those, purged excepted: `400`.
  - `401`/`403` only to reader who may see none of namespaces, or, where every namespace its grant names is purged and grant verifies in each, `410` as §C.5.2 gives it. Namespace document unreadable for one grant names: `502`; any other: omitted.
  - Tags: `idx:{ns}` per namespace in `at`, `r:{ns}/{name}` per hit, with base tags as §9 allows (CACHE-6).
- [ ] **SVC-10** (Fields in hits) Hits carry facet and `sort` values as `"<path>": [values]`, always a list, facet values in string form (§A.2) without duplicates; path marked both shows facet values.
  - `fields=/a,/b` also returns those indexed fields, `text` included. A path with comma can't be named in `fields`, `counts`, `sort`.
  - `counts=/a,/b` adds `counts` `{ "<path>": { "<value>": <hits> } }` over every hit, not only page.
  - `400`: `fields` path no schema indexed in `{ns}` for document reader may see marks with `x-index`; `facet[…]` or `counts` path none marks `facet`; `sort` path none marks `sort`.
  - Path marked when `x-index` is reachable from schema root along it, whatever data, via `$ref`, `$dynamicRef`, applicators (`properties`, `patternProperties`, `additionalProperties`, `dependentSchemas`, `items`, `prefixItems`, `contains`, branches of `allOf`, `anyOf`, `oneOf`, `if`, `then`, `else`), never `not`, `propertyNames`, `unevaluated*`; array items count at array's path.
  - Marked path with no values at hit: left out of it.
- [ ] **SVC-11** (Public namespaces, Private namespaces, Sealed and end-to-end namespaces) Public: a query ignores any grant, answered as one without it (§7 step 1). Private: served at `/{ns}/view/{view}/at/{ns_id}?…`.
  - `view` is the reader's §7.9 `view` in `{ns}` (HTTP-74), at every level and whether or not the origin serves §7.9. A reader whose grant doesn't allow `read` in `{ns}`, or whose block or key-scope rules refer to `/now`, has none: `401` or `403`.
  - A hit is shown only where its head revision as of `at` is visible to the reader's `view` as §7.9 judges it (HTTP-71), `doc` `null` in sealed and end-to-end namespaces, so `/doc` rules fail there (RUL-8). A document the reader "may see" anywhere in §A.4 is one shown so. SHOULD judge each revision once per `view`.
  - A grant in `Authorization` reads only at its own `view` (`403` elsewhere); a URL without `/view/{view}` is redirected by it to its `…/view/{view}/at/…` form, `private, no-store`. A request needing `/view/{view}` with neither a grant verifying in a followed namespace nor a cookie the service verifies: `401`.
  - Sealed and end-to-end: sealed as §E.2.6.
- [ ] **SVC-59** (Private namespaces: Cookies) The service mints cookies for prefix `/{ns}/view/{view}` with a key of its own, at its own exchange following §C.5.2 as §7.9 changes it for a `view` prefix (HTTP-75), applying `exchangeRate`. A cookie is `403` where §7.9's `view` cookie would be (HTTP-74); another reader's exchange revives none. It keeps, per `view`, the rules and values it digests and judges a request under a cookie from those, never from a grant the request doesn't carry; it needn't compute the origin's `view`.
  - An exchange whose cookie would be `403` at once, a key or role its `view` draws on having changed since the checkpoint it is judged at, answers `503` (`behind`) with `Retry-After`; so does one where every `exp` it may give is that of a `403` cookie for the same prefix (§C.5.2).

### §A.5 Consistency

- [ ] **SVC-1** (A.5, Read-your-writes, `min` always redirects) Every response states `at`, the `ns_id` it reflects. An index whose checkpoints keep moving while it computes a result MAY answer `503` (`behind`, `no-store`, `Retry-After`) after a bounded number of tries.
  - `?min={ns_id}` once (one namespace), or `?min={ns}:{ns_id}` repeatable on `/_refs`: waits (bounded) until checkpoint is at or past `min`; else `503`, `no-store`, `code: "behind"`, `Retry-After`.
  - URL with `min` → `302` dropping it: to current checkpoint, or, on `…/at/{at}/…` whose `at` already includes every `min`, to same URL without it. If it can't tell whether `at` includes them (it no longer keeps that `at`'s per-namespace checkpoints; or `min` names a namespace reader may see that current checkpoint covers but the URL's `at` doesn't): current checkpoint, one hop.
  - `min` naming any other namespace: `400`, body's `min` listing those refused; on query of one namespace, only after that namespace's own `401`, `403`, `404`, `410`. On `/_refs`, `min` naming a purged namespace → current checkpoint, no read check.
  - Never `200` at a URL with `min`.
- [ ] **SVC-12** (Read-your-writes, `min` always redirects) A client takes `min` from `X-Namespace-Revision` on its own write; tool keeps it until a query carrying it was answered `200` after its redirect (ten minutes at most), dropping those a `400` lists; a tool whose grant can't see a namespace shows its writes there from what it wrote.
- [ ] **SVC-13** (Canonical URLs) Redirects give query in one form: parameters sorted by name, then value (decoded UTF-8 bytes); every byte other than ALPHA, DIGIT, `-`, `.`, `_`, `~` percent-encoded uppercase hex. Indexes answer `200` only at that form, redirecting others to it. Repeatable parameters (`min`) are sets, sorted likewise. Undefined parameter, or non-repeatable given twice: `400`. An ordered list (`fields=/name,/title`) is one value.

### §A.6 Operations

- [ ] **SVC-14** (Access control) Index service MUST enforce namespace's read permissions by verifying reader's grant locally (§C.6).

## Addendum B — Organising documents

- **SVC-3**, **SVC-4**, **SVC-15**–**SVC-58** Retired in v0.87: Addendum B (catalogs, the tree service, `$access`, `/read-grants`, `requireAt`, §B.11.9) is removed. Filtered reads are core: HTTP-70–HTTP-75.

## Addendum C — Capabilities and access

### §C.1 Grants

- [ ] **AUTH-1** (Fields, Narrowing only restricts, Format, Verification) Grant = `Authorization: Bearer <grant>`: root block signed by namespace-document key, then zero or more narrowing blocks, each chained to previous signature. Biscuit v3 (§C.8). Verifying needs only published keys: namespace's, its bases', deployment operator keys.
  - Root block only: `sub`, `groups`, `attrs`, `signers`, `enc` (other form: `401`). Narrowing blocks only: `via`.
  - `can` ⊆ `read`, `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `prune`. `*` is for keys only; in block `401`. Root block without `can` MUST list `roles` (`401`); verbs then come only from roles.
  - `nbf` (optional) and `exp`: absolute RFC 3339; a block is valid from `nbf` until `exp`.
  - Narrowing block may only reduce `ns`, `can`, `roles`, set later `nbf` / earlier `exp`, add `rules`, add `via`; a member it leaves out restricts nothing. Non-narrowing values (other than `"*"`) restrict nothing.
  - Root block MUST carry `kid`, `sub`, `ns`, `exp` and only its listed members. Any violation: `401`. Effective principal: root `sub`, `groups`, `attrs`, with `via` listing delegatees in order.

### §C.1.1 Roles

- [ ] **AUTH-3** (Roles, Expanded at the gate, Combination, Issuers are bounded) Grants carry role names only, expanded at gate against configuration in force at request. Unknown names grant nothing; `roles: []` no verb. Roles are alternatives, all else conjunctive (§C.2 items 2, 4). Issuers bounded by key scope's `roles` (§C.4).

### §C.1.2 Attributes and time

- [ ] **AUTH-10** (table, Principal attributes) Rules read `/principal/{attrs,groups,roles}` (issuer-set; root `attrs` bounded by key scope's `attrs`), `/doc/…`, `/action`, `/resource`, `/writes` (server-set), `/now` (server clock).

### §C.2 Checking requests

- [ ] **AUTH-2** (intro, Verify the chain) Checked at §6.2 step 1 (items 1–3, first part of 4), step 2 (item 2's retry check, settling), step 6 (`*`-key guard, then item 4), every read (item 5).

  Unverified shape errors first, in order: `grantSize` (`413`); blocks unparseable or breaking §C.1/§C.8 (`401`); `rulesPerGrant` (`413`); invalid rule (§6.4.2, `401`). Then §7's `ns` check (`403`), before any `401` below. Then check: root signature (key in configuration in force), every block's signature, `nbf` ≤ now < `exp` per block, revocation (§C.4), key scope (AUTH-6), its parts in the order `can`, `sub`, `maxTtl`, `groups`, `roles`, `attrs`, `readScope`, the first that fails giving the answer.

  A grant that can allow `read`, from a `readScope: "resource"` key, not fixing `/resource` (§2.1) fails scope: `403` on every request not ignoring grant (writes included), `404` for read of resource in private namespace. No usable grant (missing, malformed, badly signed, revoked, expired, not yet valid): `401`. Valid grant not allowing request: `403`.
- [ ] **AUTH-11** (Check the verbs, Several verbs, Settling, Later steps, Unrestricted `read`, Operator grants) Verb allowed when `ns` and `can` intersected over all blocks (and key's `can`) allow it and, with roles, effective role lists it. A request checks its action's verb, except:
  - **Several verbs.** Resource `PATCH` under `If-Match`, and batch item whose first step is patch set under `ifMatch`: `append` and `restore`. Those without usable precondition, and blob upload: `create`, `append` and `restore`.
  - **Candidate verbs**: those passing this check and item 4's step-1 rules with `/action` = verb, only roles listing it counting. A write with one passes; `PATCH`/item without usable precondition then `428` at step 2.5.
  - **Settling.** Step 2.2 settles verb of a `PATCH` under `If-Match` or such batch item; non-candidate refused. Idempotent retry of one: `200` only if recorded entry's verb is candidate (restore if parent is tombstone, else append); other retries have their one verb.
  - **Later steps** of batch item: patch set after a `"delete"` step is restore, else append.
  - **Unrestricted `read`.** Branching also checks `read` on base, which grant must read unrestricted (§2.1), public or not. A key-scope or block rule referring to `/now` fails it, as for any read (item 5); key-scope and block rules referring only to `/action`, `/principal` must pass with `/action` = `read` (rest: step 6); role counting for `read` must pass all its rules against a `read` envelope.
  - **Operator grants** check `config` for a namespace's creation and for `GET /ns`, and `purge` or `purge-ns` for a forced purge.
- [ ] **AUTH-12** (Build the principal, Rules, Reads) Principal: `{ id: root sub, groups, roles: effective roles, attrs, via, grant: grant id }`. Step 1 evaluates key-scope, block and role rules referring only to `/action`, `/resource`, `/principal`, `/now` (`/action` = verb checked); step 6 all rules (verb as settled where there were candidates), then namespace rules; reads use a `read` envelope (§6.4.1), which has no `now`: wherever rules are evaluated for a read, one referring to `/now` (§2.1), a rule on the whole envelope included, fails as a whole, so a role with one doesn't count for `read`, and a read's time window is its grant's `nbf`, `exp`; a grant with one in its blocks or key scope is refused every read that doesn't ignore the grant (§7 step 1), `GET /ns/{ns}/principal` excepted (§7.4): `404` at a resource's URLs, `403` elsewhere. With roles, role rules must pass for at least one effective role listing verb. Failing grant, key or role rule: `403`.
- [ ] **AUTH-31** (Reads, per revision) A read is judged per revision: its `read` envelope's `doc` is the document of the revision it concerns (RUL-8), for every read, filtered (§7.9) or not. A grant whose rules test that `/doc/team` is `"a"` can't read a head whose revision says `"b"`, by URL either, answered as any read-rule failure (`404` at a resource's URLs, `403` elsewhere). Whether a revision may be read never changes while its document is stored. A read serving several revisions (a resource's log range or event stream) passes only where each does, and each entry's parent too, as patches show it (`test` values, removed paths), except as §7.9 filters it.
- [ ] **AUTH-13** (`*` keys) Need grant chained to a `can: ["*"]` key (namespace creation: creating operator grant), else `403` (`forbidden`):
  - config write (batch `config` change included) covering or overlapping a §7.4 member, or setting `read` to `public`;
  - branch `patches` covering or overlapping one of those members (`*` key of base);
  - prunes §8.6 names.

  Guard runs first at step 6, after namespace-document validation. Forced purge: own step-1 guard (§6.1).

### §C.3 Attribution and signatures

- [ ] **AUTH-4** (Grant per revision, Stored grant form; §C.3.1 Reading grants) Each revision stores its grant id, `trunc160(sha256(canonical(root block)))`; grants are stored non-bearer (§C.8).
  - `GET /ns/{ns}/grants/{gid}` answers `{ "id", "root", "stored" }`; `stored` = authority block (protobuf `SignedBlock`, unpadded base64url) of first token recorded with that id: signature verifies under `root.kid`'s key, its one `grant_block` string equals `canonical(root)` byte for byte, `id` = `text(trunc160(sha256(that string)))`.
  - Serves grants recorded by this namespace's log entries and, in a branch, its bases' up to their `at`, recursively. Other: `404`; purged namespace `410`.
  - Needs unrestricted `read`; immutable. Sealed namespaces: sealed per ENC-2; a grant recorded only by a branch's base under the branch's current epoch.
  - End-to-end: in clear, `Cache-Control: private` not immutable class, `no-store` in `CDN-Cache-Control` and `Surrogate-Control`.

  **[vectors I.4]**
- [ ] **AUTH-5** (Optional author signatures; §C.3.1 Signer keys live in grants, Tombstones) Signature over `sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ ns ‖ 0x0A ‖ name ‖ 0x0A ‖ bytes(parent) ‖ 0x0A ‖ canonical(patches))`.
  - `origin`: canonical origin published at `GET /`, RFC 6454 ASCII (`scheme://host[:port]`, `https` or `http`, lowercase, default port omitted). Tombstone: ASCII `tombstone` replaces `canonical(patches)`.
  - Sent as `Signature: <alg>:<kid>:<sig>`; stored beside revision (not in its id), served in logs.
  - Root block may list `signers: [{ "kid", "alg", "pub" }]`, `alg: "Ed25519"`; `kid`s unique within `signers`, no `:`; `pub` and `<sig>` unpadded base64url, 43 and 86 characters. An entry breaking this, or with another member or `alg`, makes grant invalid (`401`); so do `signers` in narrowing block.
  - Issuers MUST list key only after principal proved possession, and MUST NOT list one `pub` for two subjects.

  **[vectors I.4]**

### §C.3.1 Signer keys and verification

- [ ] **AUTH-14** (At the gate, The parent, Retries) A write whose signature `kid` is in its grant's `signers` MUST be verified at §6.2 step 2.3.
  - Bad signature, or `alg` not signer's: `422`, `code: "signature"`. Other `kid`: stored unverified, read as unattributed.
  - Signed parent = precondition's: `If-Match` id (empty for create); batch: item `ifMatch` (empty with `ifNoneMatch`) for first step, previous step's id after. No usable precondition: unchecked here, `428` at step 2.5.
  - `Signature` header or step member not `<alg>:<kid>:<sig>` with 86-character base64url `<sig>`: `400` (`bad_input`), shape error.
  - Batch steps carry their own `signature`. `Signature` header covers only single resource `PATCH`/`DELETE`; any other write: `400` (`bad_input`).
  - Idempotent retry answers entry as first recorded, whatever well-formed signature it has or lacks, even after `required`.
  - E3: input covers sealed patch set as sent.
- [ ] **AUTH-15** (Requiring signatures) Namespace document `"signatures": "required"` (default `"optional"`).
  - Every revision and tombstone then needs valid signature by signer of its grant, else `422 signature` at same gate point.
  - Batch items are judged under configuration their config change produces; if it fails, only replay can succeed, answered as first recorded.
  - Not covered: revisions written before it was turned on, and those branch reads through.
  - Merges, replays, imports (§F.3, §G.4.4): step's `signature` is writer's own; originals aren't re-sent.
  - Authentication disabled (§1): every resource write to such namespace fails.
- [ ] **AUTH-16** (chain, Verifiers) Verify against keys in force when revision was written, along one chain: revision `Signature` → entry with that `kid` in `signers` of root block of grant its reference names → key signing that root block (key of configuration write was checked against: namespace document in force at its log entry, after batch's config change, plus in branch its bases' keys at `created`; or operator key in force at `created`) → namespace log or operator key history. A branch's verifiers also follow its bases' namespace document histories. `revoked` isn't checked. A failing signature or incomplete chain is reported as such.

### §C.4 Keys, scopes and revocation

- [ ] **AUTH-6** (Keys, Key scope; §C.1.2 Principal attributes) Namespace document lists `keys`.
  - **Entries**: `kid` (unique within `keys`); `alg: "Ed25519"`; `pub` (unpadded base64url, 43 chars); `can` (none: no verb allowed); optional scope fields (`maxTtl`: ISO 8601 duration).
  - Root blocks must be signed by listed key. Changing keys/scopes: config write needing a `*` key.
  - **Scope** restricts every grant key signs:
    - `can`: allowed verbs (all for `*`); root block `can` with another verb fails scope; role verbs bounded by it;
    - `maxTtl`: max root-block lifetime remaining, `exp − max(now, nbf)`;
    - `sub`: regex (§6.6) whole root `sub` must match;
    - `groups`, `roles`: `{ "allow": [...] }` or `{ "deny": [...] }` on asserted values;
    - `attrs`: JSON Schema asserted `attrs` must validate, held to rule's `schema` limits (§6.4.2);
    - `rules`: added to every grant; `readScope: "resource"`: grants that can allow `read` must fix `/resource` (§2.1);
    - `rate`: lower per-principal write rate `{ "rate", "burst" }` as in `limits`; `ratePerPrincipal` takes smaller rate and burst; its `429` names `ratePerPrincipal`.
- **AUTH-30** Retired in v0.87: `requireAt` and `maxLag` are removed.
- [ ] **AUTH-17** (Revocation, In a branch; §C.8 Keys, Revocation ids) `revoked` lists revocation ids: root block's = its grant id in text (§C.3); narrowing block's = `text(trunc160(sha256(its Biscuit signature)))`.
  - A chain containing any revoked block is rejected. Per namespace; in branch also rejected if any block is revoked in any base.

  **[vectors I.14]**
- [ ] **AUTH-18** (Keys follow the base) A branch accepts its base's current keys as well as its own.
  - Key added to base later works in branch; removed or replaced in base stops working in every branch. Shared `kid` is base's, accepted only while base has it with same `pub`.
  - Base later adds a `kid` branch added itself: only base's entry accepted; base removes it again: branch's own applies again. A `kid` copied from base at creation never falls back.
  - Recursive through every base; branch can't refuse base key.
- [ ] **AUTH-19** (Bootstrapping, Operator grants) Creating namespace needs deployment operator key.
  - A grant for not-yet-existing namespace names it in `ns` or uses `"*"`, which only operator-signed grants may (else `401`). Branch creation: a `branch` grant on its base.
  - Operator grants authorise exactly (verb checked): namespace creation with genesis document (`config`); `GET /ns` (`config`); forced purge/namespace purge (`purge`/`purge-ns`). Any other request under one, at the origin or a service (§C.6): `401`; requests that ignore any grant (public reads, `GET /`, `DELETE /edge-grants`) ignore it too; `GET /ns/{ns}/principal` describes it.
  - Root `kid` naming both operator key and namespace key: verified against namespace key first; namespace grant if that verifies.
  - Operator grant: forced purge and `GET /ns/{ns}/principal` on nonexistent namespace `404`; `ns` check still `403` first; purged `410`.
- [ ] **AUTH-20** (Operator key history) Operator keys are a JWK Set (RFC 7517) at `GET /`'s `jwks_uri` (default `/.well-known/patchlog-keys`), `application/jwk-set+json`, publicly cached for minutes.
  - Each key: OKP Ed25519 JWK with `kid`, `use: "sig"`, `"patchlog": { "from", "until"? }` (RFC 3339 period in force); `from` MUST be no later than first entry written under grant key signed.
  - Authorises only within its period: grants it signed `401` before `from` and after `until`; verify only for revisions created within it.
  - Keys never removed, `kid`s never reused, no namespace keys.
  - Verifiers take URI from `GET /`; only a `200` with a JWK Set body having a `keys` array is read of history, else failed read, never empty history.

### §C.5 Reading

- [ ] **AUTH-21** (Read modes, Public, Grant, The stream is metadata, Four exceptions) Namespace document `"read": "public" | "grant"` (default `"grant"`).
  - Public: cached publicly. `grant`: served with grant in `Authorization`, or via edge grants issued for verified grant with `read` (not in cache key; downstream caching `private`).
  - `/ns/{ns}` and everything under it (events stream and long-poll included) need unrestricted `read` (§2.1); resource's own URLs (events included) need `read` on that resource.
  - Exceptions: filtered reads (§7.9); and, answered by origin with grant in `Authorization`, `no-store`: gestures listing (filtered per revision), `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`.

### §C.5.2 Issuing edge grants

- [ ] **AUTH-7** (Scope, Request, Answer, Browsers, What a cookie authorises) `POST /edge-grants` on origin takes grant in `Authorization`, or `{ "grants": [ … ] }` with `Content-Type: application/json`; issues per grant for every namespace all its `ns`-carrying blocks name.
  - **Scope.** Smallest edge prefix grant allows: `/r/{ns}/{name}` (one per name) when its rules fix `/resource` (§2.1) and none refer to `/doc`; else `/r/{ns}` and `/ns/{ns}`, or, to partial reader where §7.9 applies, `/ns/{ns}/view/{view}` in their place (HTTP-75).
  - **Answer.** `200`, `{ "prefixes": [ … ], "exp" }`, one `Set-Cookie` per prefix (named per §C.5.3): no `Domain`, `Path` = prefix, `Secure`, `HttpOnly`, `SameSite=None` when deployment names credentialed origins else `Lax`.
  - **Lifetime.** Earliest `exp` among grant's blocks or 15 minutes, whichever sooner, less any whole seconds a minter MAY take off so that cookies for one prefix that it must tell apart differ in `exp` (§A.4). A prefix given by several grants: one cookie, as long as longest; body `exp` = earliest, RFC 3339.
  - **Browsers.** Credentialed responses name calling origin from deployment's list, `Access-Control-Allow-Credentials: true`, `Vary: Origin`; never `*` or echoed `Origin`.
  - **Authorises** only `GET`/`HEAD` under its prefix. Origin-minted cookies never cover service's URLs; service's never cover core ones.
- [ ] **AUTH-22** (Refusals, table, All or nothing, Rate) `POST /edge-grants` refuses:
  - authentication disabled: `404` (`not_offered`), before reading body;
  - body not `application/json`: `415`; neither `Authorization` nor body: `401`;
  - body with no grants, over 50, or together with `Authorization`: `400` (`bad_input`); larger than 50 grants of `grantSize` can be: `400` (`bad_input`), before parsing; single grant over `grantSize`: `413` once decoded;
  - nonexistent namespace, or grant failing verification there: `401`/`403` as for any request;
  - `403`: grant without `read` there; block/key-scope rules referring to `/doc`, or to `/resource` where it isn't fixed (§2.1), except for a partial reader's view prefix (HTTP-75); roles with none qualifying (§2.1); block/key-scope rules failing now against a `read` envelope for its principal, `/resource` set to each name it fixes, if any;
  - purged namespace: `410`, `code: "purged"`, if grant verifies in it;
  - over 100 distinct prefixes: `400` (`bad_input`); empty `exchangeRate` bucket of principal: `429`, `code: "rate"`, `limit: "exchangeRate"` (both only once nothing else is refused).

  Precedence: body with `Authorization` (`400`) before non-JSON body (`415`), both before `401`. All grants and namespaces are covered, none skipped: `401` if any refusal is `401`, else `403` if any is `403`; `410` only when every refused namespace is purged and grant verifies in each; only this `410` carries `ns` and `head`, naming first refused in grant and root-block order. Once nothing is refused (prefix-cap `400` included), one token is drawn, however many grants, from each distinct principal's `exchangeRate` bucket (keyed as write buckets are), none from write buckets.

### §C.5.3 Edge-grant format and checks

- [ ] **AUTH-8** (Format, Keys, What an edge MUST check, Forwarding, Without the edge, Attribution) Default cookie name: `__Secure-pl-eg-` + first 8 bytes of `sha256(prefix)`, lowercase hex.
  - Value: `base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))`, unpadded; `c` = canonical JSON (§3.1) of exactly `{ "kid", "p": prefix, "exp": <epoch seconds> }`. Other members, or not canonical byte for byte: ignored.
  - A key vouches only for its own prefixes: origin's for core edge prefixes; service's for prefixes under its own root, never overlapping `/r/` or `/ns/`.
  - Every request, cache hits included, before serving or forwarding as verified, edge MUST check:
    1. method `GET`/`HEAD`, no `Authorization` header field (even empty);
    2. path has no empty, `.` or `..` segment and no percent-escape, `/` excepted;
    3. cookie name derived from its own `p` (other cookies ignored);
    4. `c` in format, `kid` held by edge and vouching for `p`, valid MAC;
    5. `exp` in future;
    6. `p` covers path segment by segment: path is `p` or starts with `p/`.
  - **Forwarding.** Passing request: forwarded on cache miss with its cookies (origin still authorises from them and takes the `exp` ending an event stream, §7.3) and verification headers, by default `X-Edge-Verified` (secret shared with origin) and `X-Edge-Prefix` (checked `p`), each exactly one header line, no comma, both stripped from incoming requests. One covering cookie suffices. Failing any check: forwarded without headers, origin answers as without edge; path-check failure is `400` from origin either way.
  - **Without the edge.** Origin verifies unverified cookie, answers `CDN-Cache-Control: no-store`; cookie counts only on request passing check 1.
  - Logging deployments attribute cookie reads to the prefix.

  **[vectors I.5]**
- [ ] **AUTH-23** (Service-minted grants) Service minting edge grants for document-derived output: key origin never holds; mints only after checking reader may read every source document; expires no later than earliest of those reads; withdraws own cookies.

### §C.5.4 Withdrawing edge grants

- [ ] **AUTH-24** (§C.5.4 and its bullets) `DELETE /edge-grants?prefix=…` (repeatable) answers `204`, `no-store`, with expired `Set-Cookie` (same name and attributes) once per prefix named, even if named twice.
  - No `prefix`, or one not edge prefix (§2.1): `400` (`bad_input`).
  - Needs no grant, ignores any sent, same answer while authentication is disabled. Only `DELETE` withdraws; its preflight is allowed only for credentialed origins of issuance.

### §C.6 Consumers and plug-in services

- [ ] **AUTH-25** (Least privilege) A service gets `read` for what it follows; one that writes back gets narrowing block with `writes within` its own paths, without `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `prune`.
- [ ] **AUTH-26** (Services verify as the origin does, Upstream failures, Filtering proxies, Services that re-publish content MUST enforce reader permissions)
  - Local grant verification applies keys, scopes (`readScope` included), revocations, `grantSize`, `rulesPerGrant` as §C.2 does.
  - A service's `502` (`upstream`) carries nothing of the answer that caused it.
  - Where origin doesn't filter itself (§7.9), a filtering proxy serving namespace's `/ns/{ns}/…` view per document pages and derives cursors itself, never passing upstream ones on.
  - A re-publishing service MUST filter search results and other derived output by reader's verified grant, per revision as §C.2 item 5 judges reads (AUTH-31); private results cached per `view` (§7.9, §A.4), never with embedded bearer URLs.

### §C.7 Private content and guessable hashes

- [ ] **AUTH-9** (A nonce in every patch set, Requiring it) A write that `add`s `/$nonce` of fresh form is left out of `writes` (§6.4.1); validation doesn't see key (§6.2). Namespace MAY set `"nonce": "required"` (default `"optional"`).
  - Then at §6.2 step 3 resource create, append or restore MUST yield document with top-level fresh-form `$nonce` differing from parent's (restore: last live document's); else `422`, `code: "nonce"`. A failed `test` or patch application is reported first, as `invalid`.
  - A server also enforcing sealed-namespace rule (§E.2.5) answers `422 nonce` at same point.
  - Exempt: deletes, config, branch and prune writes. Applies to every patch set, whatever its origin.
- [ ] **AUTH-27** (Requiring it)
  - A branch copies setting and can't turn off its base's. A base can't start requiring it while dependent doesn't. Setting/changing needs a `*` key (all §7.4). End-to-end namespace: `422` (Addendum E, Levels).
  - A snapshot import's upstream namespace takes its target's setting. Merge tools building resolution or squash set add fresh `$nonce` where required.
- [ ] **AUTH-28** (Blobs, Encryption) Sealed namespaces and where nonces are required: created blobs carry nonce (§7.8). `$nonce` refresh: ENC-5.

### §C.8 Encoding: Biscuit v3

- [ ] **AUTH-29** (One block, one fact, Keys, Sealed tokens, Stored form, Transport) Each §C.1 block = one Biscuit v3 block with exactly one fact `grant_block(<string>)`, block's canonical JSON; MUST be I-JSON and equal its own canonical form (`401` otherwise). Authority block carries the root block, each appended block one narrowing block, in order.
  - Anything else in block (other facts, rules, checks, scopes, public keys, non-empty context, a symbol it adds that its own fact doesn't use), third-party block, or signature not over Biscuit's version 1 payload: invalid (`401`).
  - Datalog not evaluated: server verifies signature chain and applies §C.2 to JSON blocks (validity from their `nbf`/`exp`).
  - All signatures (ephemeral narrowing-block keys included) Ed25519, verified strictly (RFC 8032, `S < L`); other algorithm `401`.
  - Root key named by `kid` inside root block, not `rootKeyId`, looked up in configuration in force; wrong `kid` fails verification.
  - Sealed tokens accepted. Stored form: authority block with its signature and next key only (AUTH-4).
  - Sent as `Authorization: Bearer <token>`, URL-safe base64, with or without `biscuit:` prefix; any other `Authorization` field is a malformed grant (`401`). `grantSize` (decoded bytes) and `rulesPerGrant`: `413` (`code: "limit"`), in §C.2 item 1's order, on every request not ignoring grant (§7).

  **[vectors I.14, I.21]**

## Addendum E — Encryption

- [ ] **ENC-8** (Levels, Invariant, Changing it, After a raise) Level = `encryption.level`: `at-rest`, `sealed`, `e2e`; a namespace is `e2e` from its creation or never. Lowering or removing it, or raising it to `e2e`: `422` (`invalid`). A namespace document holding member its level refuses (§6.1, §7.4, §8.6, §C.7): `422` (`invalid`), whichever member write changes. A namespace that should become end-to-end is imported into a new `e2e` one, under a new name, by a client holding the new one's keys (§G.5.1). Raise to `sealed` purges namespace's cache tag; then `Last-Modified`, `Repr-Digest`, `/heads` fields, caching, `…/raw` and gestures listing follow new level; content stored before it is served as §E.2.2 says for pre-sealing content.
- **ENC-9** Retired in v0.78: a namespace is end-to-end only from creation.
- [ ] **ENC-10** (Branches and dependents)
  - Creating branch below its base's level, or `e2e` where its base isn't, or not `e2e` where its base is: `422` as branch field (§7.4). Config writes aren't checked against base's level.
  - Write raising namespace above dependent's level: `409` (`in_use`, with `dependents`).

### §E.1 At rest

- [ ] **ENC-1** (What it is, What it doesn't change, Purge becomes cryptographic, Stored digests) E1: origin encrypts stored patches, snapshots and grants with KMS keys; nothing else changes. Key per resource: purge destroys it. Stored `/heads` `size`/`digest` (§7.4) at E1: omitted, computed at read time, or kept under resource's key.

### §E.2.1 Keys

- [ ] **ENC-11** (Epoch keys, Per-resource keys, Namespace key) `K_e`: 256-bit random, `kid = "{ns}#{e}"`; current epoch = `encryption.epoch`. Key material never in namespace document or log. `K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name)`, 32 bytes; it opens only that resource's revisions of epoch `e`, yields neither `K_e` nor `K_n`.
  - **Namespace key.** What is sealed for the namespace rather than a resource (§E.2.2) is sealed under `K_n = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A)`, 32 bytes. `K_e` itself seals nothing. `/keys` never returns `K_n`; a holder of `K_e` derives it.

  **[vectors I.7]**
- [ ] **ENC-26** (Message bound) IVs are 96 random bits; no key this spec seals under, a sealed bundle's `K_b` included (§G.5.1.1), seals 2³² values or more. Keys that only encrypt storage (§E.1) are the implementation's.
  - Origin counts its sealings per key, reserving what may still be sealed under an epoch after it ends (§E.2.2); its counts may exceed the sealings made, stored or not, never fall short of them; how it reserves is its choice.
  - A `*`-key holder rotates before any key of the current epoch reaches the bound; at E2 the origin MAY instead rotate by itself, frozen or not (§8.4), in a config entry it writes itself (§7.4).
  - Until then, a request needing a sealing past the bound: `503` (`behind`), `Retry-After`.
  - At E3 only clients seal under `K_r`, and the origin need not count. Each writer counts the sealings under a `K_r` that it knows of (the log's and its own) and seals none past the bound; the key holder that rotates (§E.3.2) rotates before any count it knows of reaches the bound.
- [ ] **ENC-12** (Rotation) Config write incrementing `encryption.epoch` starts new epoch, recorded in namespace chain; needs a `*` key (§7.4). Already `sealed`/`e2e`: write changing `epoch` other than adding one is `422` (`invalid`). Later revisions sealed under new epoch; old keep theirs.

### §E.2.2 Sealed representation

- [ ] **ENC-2** (intro, Algorithms, Protected header, What gets sealed, table) In sealed namespace each payload below is compact JWE (RFC 7516): `alg: "dir"`, `enc: "A256GCM"`, protected header `{ "alg", "enc", "kid": "{ns}#{e}", "pl" }`, canonical JSON (§3.1). Ids in `pl` in text form; empty is `""`.
  - Served alone: `Content-Type: application/jose`. Resource log range or resource long-poll answer: canonical JSON array (§3.1) of entries' JWEs, `application/json`. SSE event `data`: one JWE.

  Payload: key, epoch, `pl`:
  - `/rev/{id}` document: `K_r`, revision's epoch, `{ "ns", "name", "id", "kind": "doc" }`.
  - Resource log entry, in range or `revision`/`tombstone` event: `K_r`, revision's epoch, `{ "ns", "name", "id", "kind" }`, `kind` = `rev` or `tombstone`.
  - Resource `purge`/`prune` event: `K_r`, epoch current when sealed, `{ "ns", "name", "kind" }`, `kind` = event type.
  - Namespace document at `ns_id`: `K_n`, epoch in force at `ns_id`, `{ "ns", "id": ns_id, "kind": "doc" }`.
  - Namespace log range or long-poll answer: `K_n`, epoch current when sealed, `{ "ns", "range": [since, last] }`, bounds of page actually served (`[since, id]` if empty).
  - Namespace event (§7.3): `K_n`, epoch current when sealed, `{ "ns", "event": id }`, `id` its entry's.
  - Grant (§C.3.1): `K_n`, epoch in force at first namespace log entry recording it, `{ "ns", "grant": gid }`.

  Every plaintext is canonical JSON (§3.1): a resource log entry's the whole §7.1 entry; a namespace log range's or long-poll answer's the JSON array of its §7.4 entries (`[]` for an empty page); a namespace event's its one entry.

  Epoch in force at namespace entry = `encryption.epoch` of document in force there. A revision's epoch = current one when first sealed; likewise namespace document or grant from before sealing, and grant only base records.

  **[vectors I.13, I.19, I.22]**
- [ ] **ENC-13** (What stays in the clear, Stored once, served forever) Sealed namespace:
  - A revision's exact `created`, document's length and digest aren't sent outside sealed logs.
  - Sealed bytes of revision, document, resource log entry or grant: produced once, stored, served identically thereafter. Sealed revision `ETag: "{id}.{e}"`; sealed namespace document `ETag: "{ns_id}.{e}"`.
  - Exception, namespace log ranges: MAY keep only some, oldest evicted first, and seal evicted range again on request, fresh bytes, under the `K_n` and `pad` then current. Range `ETag`, if any, is weak.
  - Resource `purge` and `prune` events and namespace events need not be stored: each may be sealed again, fresh bytes, whenever sent; every sealing counts (§E.2.1).
- [ ] **ENC-14** (Protected header, Stored once, served forever; readers)
  - Readers MUST compare `pl`, and namespace `kid` names, with what they fetched; at E3 they accept in both a base's `ns` for a `sealed` op a branch reads through, up to resource's foreign parent (§E.3.1), and in nothing else (Levels); where they can't place that parent the op fails the check (§E.3.2, ENC-24); at E2 a branch seals all it serves under its own keys (§E.2.5), so no base's `ns` is accepted. Accept either copy of re-sealed namespace log range, MUST NOT rely on one.
- [ ] **ENC-15** (Compression, Padding (optional)) Sealed payloads never compressed, no `zip` header. With `"pad": true` in `encryption`, every JWE sealed for namespace (server at E2, clients at E3) pads its plaintext before encryption:
  - plaintext = UTF-8 JSON otherwise sealed, then ASCII spaces (`0x20`) to padded length; blob is zero-padded inside its sealed form instead;
  - `L` plaintext bytes: padded length 256 for `L` ≤ 256, else `padmé(L)`: `L` rounded up to multiple of `2^(E − S)`, `E = ⌊log₂ L⌋`, `S = ⌊log₂ E⌋ + 1` **[vectors I.6]**;
  - each JWE padded as whole (each JWE of log range included); turning `pad` on/off affects only later sealing, re-sealed log ranges included.
- [ ] **ENC-3** (Sealed blobs) Sealed namespace blobs: `application/vnd.patchlog.sealed-blob`: `"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(size ‖ bytes ‖ padding) ‖ tag`.
  - `len` = length of `header`, 4-byte big-endian; `header` canonical JSON; at E2 `{ "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "blob": bid } }`, keyed by resource's `K_r` of epoch `e`.
  - `iv` 12 random bytes, tag 16 bytes; additional data = everything before `iv`. `size` = length of `bytes`, 8-byte big-endian. `padding`: zero bytes, only with `pad`, up to bucket of `size ‖ bytes`.
  - Readers check padding is all zeros; clients open sealed blobs only in namespaces whose document says sealed or end-to-end, or after epoch redirect. **[vectors I.13]**
- [ ] **ENC-16** (Sealed blobs: Epochs, Served epochs, A revision's epoch, Stored once, In a branch; ranges) Sealed namespace:
  - `…/blob/{bid}`: `302`, cached as head pointer, to `…/blob/{bid}/e/{e}` for latest served epoch. Served epochs = those of this namespace's revisions whose documents are still stored and reference blob.
  - A revision's epoch is fixed by its first stored sealing: when written, or, if read through from a base or written before the namespace was sealed, when first served or a check first judges by its epoch (§2.1, §6.1). A request or such a check for blob none of whose referencing revisions has epoch yet first fixes newest of them under current epoch. A refused request fixes no epoch.
  - Other epochs: `404`, `no-store`. Epoch whose referencing revisions were all pruned: `410` as in §7.1 where server recorded it when pruning, else `404`.
  - Pruning in base doesn't delete branch's stored sealings of base's blobs, but branch stops serving them and answers as above.
  - Each epoch's sealing stored once (concurrent instances: first stored wins), served unchanged, `ETag: "{bid}.{e}"`, sealed type as `Content-Type`; range requests served over them.

### §E.2.3 Getting keys

- [ ] **ENC-4** (What a grant gets, Which epochs, From, To, Responses) `POST /ns/{ns}/keys` takes `{ "epochs"?, "resources"? }`:
  - E2, grant whose rules fix `/resource` (§2.1): `K_r` for names in `resources` (default every name it fixes); name it doesn't fix or may not read: `403`.
  - E2, other grant: `K_e` if it reads namespace unrestricted (§2.1), else `403` (public namespace too, §C.2); `resources` ignored.
  - Epochs = `epochs` (default all) within window; others omitted. From: current epoch if no block has `nbf`, or authentication disabled; else epoch in force (§E.2.2) at last namespace entry created at or before latest `nbf` among grant's blocks (a `batch` entry's config change included), or namespace's first epoch if there is no such entry or namespace wasn't yet sealed/end-to-end there. To: current epoch; with `encryption.historyEpochs`, no more than current and that many before.
  - A reader lacking the epoch that sealed a grant reports signatures naming it as unverifiable.
  - Answer `{ "epoch", "level", "pad", "keys": [{ "kid", "name"?, "from"?, "wrapped" }] }`, `Cache-Control: no-store`; `epoch` = current, `name` for a `K_r`, `from` for keyring entry. E2, grant without `enc`: each key as base64url `key` instead of `wrapped`; E3: `422` (`invalid`).
  - Namespace neither sealed nor end-to-end: `404`, `code: "not_offered"`. Draws token from `exchangeRate` (§6.6), as `/edge-grants` does.
- [ ] **ENC-17** (At E3) E3 `/keys` relays to a `read` grant whose rules pass for a read (§C.2 item 5) keyring entries whose `to` is its `enc` thumbprint, without read of `keyring`: namespace's entries for epochs ENC-4 selects and, in branch, also its bases' keyrings as of `at`, whether or not branch wrote its own `keyring`. For bases: epochs up to `at`, from epoch each base had at latest `nbf` (or at `at` if earlier), with no `nbf` from base's epoch in force now, at most that base's `historyEpochs` at `at` before its epoch there; `epochs` doesn't select.
- [ ] **ENC-18** (Wrapping) Keys wrapped to `enc`, an X25519 public key in root block:
  - `enc` = JWK of only `kty: "OKP"`, `crv: "X25519"`, `x` (32 bytes, unpadded base64url, 43 chars); another form, or in a narrowing block: `401` (§C.1). Grant without one: as Responses says (ENC-4).
  - HPKE single-shot Seal/Open (RFC 9180, section 6.1), base mode (auth mode for `keyring` entries), DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, empty `aad`.
  - Plaintext = key's 32 bytes; `info` = `"patchlog-key-v1" ‖ 0x0A ‖ kid ‖ 0x0A ‖ name`, `name` empty for `K_e`.
  - `wrapped` = HPKE's 32-byte encapsulated key then ciphertext. Thumbprint = RFC 7638 SHA-256 thumbprint of JWK. Both unpadded base64url.

  **[vectors I.12]**

### §E.2.5 Interaction with the rest of the spec

- [ ] **ENC-5** (Caching, Ids, Branches) Sealed namespace cached by its `read` mode (§9). Ids over plaintext canonical patches; MUST refresh `$nonce` in every patch set (§C.7). E2 branch: own epoch keys; read-through content sealed under keys derived from them when first served.

### §E.2.6 Derived views

- [ ] **ENC-19** (Getting keys, What gets sealed, Aggregates) A service serving views derived from sealed/end-to-end namespaces:
  - fetches epoch keys via §E.2.3 with its own key pair and a `read` grant. E3, service whose public key isn't recipient in namespace's `keyring`: skips namespace, says so in its status, MUST NOT index ciphertext as content; `keyring` entry whose `from` it doesn't trust (§E.3.2) counts as no key;
  - seals every value derived from such content; names, ids, URLs, heads and view's structure (`at`, `ns`, result order, pagination cursors) stay clear; cursor never encodes sealed value; each plaintext sealed is canonical JSON (§3.1), before any padding (§E.2.2);
  - serves values combining several resources only whole-response, refusing them (`400`) to reader that would get per-entry sealing.
- [ ] **ENC-20** (Whole-response sealing, Per-entry sealing, `pl.view`, View keys) `pl.view` = request target of `…/at/{at}/…` URL served, in origin form (path, then `?` and the query where there is one; no scheme or host), byte for byte as service's redirect gave it (§A.5).
  - **Whole response**: MAY be one JWE only when all hold: every sealed value is from one non-public namespace; every reader its URL admits has unrestricted `read` of that namespace (§2.1, §A.4); every such value derives from revisions served under one epoch. Format §E.2.2, that epoch's `K_n` (§E.2.1), `kid` naming that epoch, `Content-Type: application/jose`, `pl: { "ns", "view" }`; plaintext the response body.
  - **View keys**: where this section seals a view's JWE under a `K_n` or `K_r`, the key used is `HKDF-SHA256(ikm = that key, salt = "patchlog-view", info = pl.view)`, 32 bytes; views count toward no epoch key's message bound (§E.2.1).
  - **Per entry**: else JSON; each entry (a hit) with sealed values replaces them with `"sealed": "<JWE compact>"`, plaintext the object of the members it replaces. Key: `K_r` of entry's own resource, in a branch the branch's, read-through entries included (§E.2.5); `kid`: epoch source revision is served under (§E.2.2), at E3 one prune's `snapshot` of it would carry (§E.3.1), judged once, when service first seals a value derived from it, at E2 taken from the `kid` of that revision's JWE as the origin serves it (§E.2.2); until it can judge it, service seals nothing derived from that revision, serving the entry by name only and leaving such values out of other entries, in a response that is `no-store` and isn't stored, or, while it may yet judge it, answers `503` (`behind`, §A.5) instead; `pl`: `{ "ns", "name", "view" }`. Entry whose epoch service's grant gets no key for (§E.2.3) is served by name only, or left out where service never opened that revision. Of an entry carrying `sealed`, a reader takes from outside it only what this section leaves in the clear.

  **[vectors I.23]**
- [ ] **ENC-21** (Stored once, served forever, Caching, Local storage, `pl.view`)
  - A view at given `at`, other than a `no-store` one (Per-entry sealing), is sealed once, under epochs of revisions its values derive from, then served unchanged, until a config entry on which §9 purges a source's `ns:{ns}` drops it (§A.1); stored views keyed by URL and shape of reader's keys.
  - Padding follows source namespace; whole-response sealing pads only when every source is padded. Cached publicly only when all sources are public, else private result (§C.6).
  - Derived data from sealed/end-to-end namespace is kept in storage encrypted as at E1, keys held outside it. Purge of source, or destruction of its keys, MUST remove it: rows deleted, freed pages overwritten, stored sealed views deleted, cached keys forgotten.
  - Readers MUST compare `pl` with URL fetched (ENC-14), so nothing between service and reader may rewrite it.

### §E.3.1 Wire format

- [ ] **ENC-6** (Patch sets, Snapshots, Ids, Namespace documents stay plaintext) End-to-end write body = one-element patch set `[{ "op": "sealed", "value": "<JWE compact>", "blobs"? }]`, sealed under resource's `K_r` of epoch its `kid` names; JWE protected header carries `kid` and `pl: { ns, name, parent }`.
  - §6.2 step 3 checks, else `422` (`invalid`): op has no members but `op`, `value`, `blobs`; header is canonical JSON with no members but `alg`, `enc`, `kid`, `pl` (§E.2.2); `pl` names this namespace, resource and parent signature would bind (§C.3.1); `kid` names this namespace's epoch in force.
  - Prune's `snapshot` is one such op, holding requested `horizon`'s document, `pl: { ns, name, id }` naming this namespace and that revision, or the tombstone's parent where it is a tombstone, which the tombstone's `410` names as `last` (§7.1). Its `kid` names this namespace and an epoch set by newest revision in horizon's chain that isn't tombstone and whose patch set isn't `[]`:
    - epoch of that revision's `sealed` op, where op is this namespace's own (its `pl.ns` names it), not base's;
    - or, below earlier horizon, epoch of that horizon's `snapshot`, where its `kid` names this namespace;
    - else this namespace's epoch in force.
    Server checks `pl` and `kid` (`422`, `invalid`). Ids are over op's ciphertext; namespace documents stay plaintext.

  **[vectors I.13]**
- [ ] **ENC-22** (Blobs, Declared blobs; server) End-to-end:
  - Empty `blobs` (omitted or `[]`) and any order accepted. Duplicates, declared blob whose type isn't sealed type, or one with nonce: `422` (`code: "blob"`).
  - Restore with empty patch set `[]` keeps last live document's list. List is part of hashed patch set, kept with revision's skeleton after pruning; length checked against `blobsPerDocument`; declared blobs must be available (§7.8). Lists drive unreferenced blobs, pruning, purge and bundles. A prune's sealed `snapshot` needs no list.
- [ ] **ENC-23** (Patch sets, Retries, Blobs, Declared blobs; clients and readers) End-to-end:
  - Client MUST keep write's exact ciphertext until acknowledged.
  - Client encrypts each blob under fresh random 256-bit key in sealed-blob form of §E.2.2 with header `{ "enc": "A256GCM" }`, uploads as `application/vnd.patchlog.sealed-blob`, puts key in reference as `sealed: { "key", "type", "size" }` (plaintext `type`, `size`).
  - Writers list in `blobs` id of every blob resulting document references; omit when empty, else sort by ids' binary form (§3.2). A sealed empty set keeping document unchanged repeats its list.
  - Readers check `pl` (ENC-14), MUST compare declared list with decrypted document as sets, and flag revision whose list differs.

  **[vectors I.13]**

### §E.3.2 What the server can and cannot do

- [ ] **ENC-24** (Validation moves to clients) End-to-end:
  - Every client MUST validate decrypted document against its `$schema` before writing, leaving out members §6.2 step 5 leaves out.
  - Revision failing validation on read: flagged, still folded.
  - Revision whose patch set doesn't open, fails `pl` or `kid` check, or doesn't apply to its parent's document (failing `test` included): flagged; readers fold on from parent's document as if its patch set were `[]`.
- [ ] **ENC-25** (Keys) End-to-end: server only relays wrapped keys.
  - `keyring` document `{ "keys": [{ "kid": "{ns}#{e}", "to", "from", "wrapped" }] }`; `to`, `from` = thumbprints (§E.2.3) of recipient and wrapping admin's X25519 key. No other members but a `$nonce` (§C.7), new random bits on every write carrying one, the server checking only its form; each entry only `kid` (this namespace, epoch ≤ `encryption.epoch`), `to`, `from`, `wrapped` (80 bytes). Breaking this, or two entries for one `kid` and `to`: `422` (`invalid`).
  - Written in plaintext; checked and pruned as outside E3, without `snapshot` (§6.2, §8.6).
  - Entries wrapped as §E.2.3, HPKE auth mode under admin key. A client opens and seals only under key whose `from` it trusts to distribute keys, configured out of band with its public key.
  - Rotation and re-wrapping: by key holder, never server, taking readers from its own configuration, not stored `to` members.

  **[vectors I.12]**

### §E.4 Metadata that no level hides

- **ENC-7** Retired in v0.73: §E.4 requires nothing a tester can check.
## Addendum F — Branches, merge and rebase

### §F.3 Merge

- [ ] **MRG-1** (step 1 Collect, step 2 Classify, table, step 3 Dry run, step 4 Resolve, step 5 Submit, Conflicts inside arrays) A merge is one batch into base. Per resource the branch changed, base head `B` vs branch head `H`:
  - `B` = `H`, or `H` ancestor of `B`: no item.
  - `B` ancestor of `H` (foreign parent included; "absent in the base" for a branch-created resource): fast-forward, entries after `B` with `ifMatch: B` (or `ifNoneMatch: *`), same ids; at E3 re-sealed replay (§F.8.1).
  - Neither: replay onto `B`, new ids, always reviewed; conflicts if `writes` overlap (branch's counting each `copy`'s `from`) or needed history was pruned.
  - Purged in base or branch: no item, reported.

  A write whose last segment indexes an array counts as one to the whole outermost array holding it. Dry-run (`?dry-run=1`); each conflicting resource's steps are replaced by one resolution set against `B`; submit with `source: { ns: <branch>, at }`, `at` as classified in step 2. `412` (base moved): reclassify, resubmit.
- [ ] **MRG-6** (step 2) A `"delete"` step reproduces tombstone. Deleting a document the base has since changed, and changing one the base has since deleted, always need a person.
- [ ] **MRG-2** (step 6 Freeze the branch, and its sub-bullets) A merged branch is frozen by config write also recording `"merged": { "at": <base's ns_id> }`, or kept and merged again; second merge replays only changes since earlier counting merge batches from same branch, each per resource giving the pair (branch revision as of its `source.at`, base revision from its entries) from the most recent batch with an entry for it.
  - Resource deliberately kept at base's version is recorded as identical-content revision (`[]`, a fresh `$nonce` add where nonces are required or namespace is sealed, a sealed empty set at E3), only if base head is live: tombstone or absent head stays unmerged and is offered again.
  - Batches count only with: no `origin`; `source.ns` branch; `source.at` in branch's chain; recorded grant root `sub` and `kid` in base's current `merge.authors`. Removing an author withdraws its earlier batches. Changing `/merge` needs a `*` key (§7.4).
  - The merger's dry-run report lists, per resource, which batch and author its pair came from.
- [ ] **MRG-7** (Blobs, Nonces, Configuration is never merged implicitly, Authorisation, Attribution)
  - Merger with unrestricted `read` on branch copies no blobs within deployment; any other copies first, or uploads where ranks refuse copy (§2.1). At E3, a resource whose document references a blob that can't be declared (of another type or with a nonce, §E.3.1) gets no item: merger reports it and offers it again.
  - Tools diffing documents for a merge or review leave out a fresh `$nonce`. Base config change goes in batch's `config`.
  - Batch checked in base under merger's grant (base's verbs for every item, base's rules); merged revisions record merger as author, who signs its own steps where signatures are required.

### §F.5 Rebase: a successor branch

- [ ] **MRG-3** (steps 1–5, Previews) Rebase creates successor from base's current head, `patches` giving it old branch's `read`, or `"grant"` where that would rank it below old branch (§2.1); never replays into successor ranking below it. It replays in batches with `source: { ns: <old branch>, at }`, classified as §F.3 against new branch; resources the base didn't change since the old `at` fast-forward with same ids (not at E3).
  - On resuming, successor batches without `origin` whose `source.ns` is old branch count as earlier merges (§F.3), whoever wrote them, even without `merge.authors`.
  - Switch, once replay has recorded every resource old branch changed up to replay's latest `source.at` (other than those §F.6 excepts), or a person has given up the rest: one config write on old branch, `"frozen": true, "successor": <new branch>`. Then what old branch received after step 2 is replayed, reporting what it leaves unmerged. A give-up is recorded nowhere: janitor then doesn't purge old branch as superseded (§F.6), and a later replay may still take the rest (step 3). Previews follow the `successor` chain.

### §F.6 Lifecycle and cleanup

- [ ] **MRG-8** (Cleanup, A janitor service) `cleanup` is data in branch's namespace document, not core-enforced; without it janitor never purges. It purges branch only when: frozen, and merged, superseded or abandoned; its cleanup period passed (`cleanup` member for state purged as, none: not purged as that state; counted from last config write that froze it or set `merged`, `successor` or `abandoned`) and base's `cleanup` minimums passed, counted from the same config write; no dependents. Needs `purge-ns` on branches only, never bases.
- [ ] **MRG-4** (The janitor MUST verify claims, and the closing rules) Before purging, janitor MUST verify claims `merged`, `successor`, `abandoned`, `cleanup` (held to base's minimums):
  - **merged:** base's log has batch without `origin`, by principal in base's current `merge.authors`, `source.ns` branch, `source.at` in branch's chain; branch's log has no `head`, `tombstone` or `batch` entry after `source.at` (other kinds allowed).
  - **superseded:** successor is still one §7.4 allows (or was until purge after branch was last frozen and janitor still holds what this check needs that the purge stopped serving, read before it); its log has a batch without `origin`, `source.ns` branch, `source.at` in branch's chain, whose recorded grant has root `sub` and `kid` in base's current `merge.authors` or chains to current `*` key of branch; branch's log has no `head`, `tombstone` or `batch` entry after that `source.at`.
  - **abandoned:** `"abandoned": true` set by config write whose recorded grant chains to current `*` key of branch (inherited or own).
  - Batch in branch's log counts as `batch` entry only through its items.
  - Merged and superseded: each resource with own `head`, `tombstone` or `batch` entry up to `source.at` (not purged ones, nor `keyring` at E3) also has entry in counting batch with `source.at` at or after its last such entry, or batch-namespace head equal to or descending from its branch head as of `source.at`. At E3, `keyring` entries after `source.at` are allowed and batch counts only with other items. Branch with no such entry counts as merged.

### §F.7 Merge service

- [ ] **MRG-9** (Automation) A merge service automates only: rebasing branches where every resource fast-forwards (at E3, is re-sealed onto unchanged base); submitting at a set time a batch a person approved. All else, unapproved replays included, waits for a person.

### §F.8 Access, encryption and indexes

- **MRG-10** Retired in v0.87: catalogs, their merge grants and §B.11.9 are removed.
- [ ] **MRG-11** (Editors limited to some documents, Indexes) A service branching base for editors limited to some documents records creation with `via`, creates branch with `read: "grant"`, and issues them grants on it with the rules of their base grants; filtered reads don't cover branches (§7.9), so such grants list only through a preview index (§A.4). The main index follows only base; search over branch is a separate preview index.

### §F.8.1 Merging and rebasing at E3

- [ ] **MRG-12** (Keys, Classification, Re-sealing an entry, Blobs) At E3 merge or rebase is done by key-holding client and submitted as ordinary batch sealed for target.
  - Read-through content keeps base's ciphertext and `kid`; keys are asked of namespace read first, the `kid`'s only if that fails. Branch's own writes carry its `kid`s; its `keyring` is never merged.
  - No fast-forwards: `B` ancestor of `H`: branch entries after `B` are re-sealed onto `B` in order, new ids, no conflict check. Neither: replayed with §F.3's conflict check.
  - Re-sealing: merger decrypts and checks `pl` against where read, resource and entry's parent, then seals same plaintext patches under target's current epoch, fresh IV, target's `pad`, `pl: { ns: target, name, parent }` (`parent`: `B`, then previous entry's id), and computes each id. Tombstones aren't sealed; blobs keep ciphertext and ids, each re-sealed op its `blobs` list.
- [ ] **MRG-13** (Conflicts, Validation, Retries, Rebases) Conflicts come from the `writes` of decrypted patch sets, as §F.3, arrays included. Before submitting, merger folds every item and validates each document against its `$schema` as target's gate resolves it; failure is conflict of kind `invalid`. Sealed batch is kept byte for byte until acknowledged; reclassifying after `412`, or changing resolution, reseals affected items. Rebases re-seal likewise with the successor as target.
- [ ] **MRG-14** (Later merges and the janitor) At E3 second merge takes its common ancestors from earlier merge batches (§F.3); without one, every resource the branch changed conflicts, except one whose target and branch head documents are equal as decrypted plaintext (counted merged).

### §F.9 Releases across namespaces

- [ ] **MRG-15** (intro, Cleanup) A release document authorises nothing: every tool acting on it checks for itself, under its own authority, what it is about to do. Each listed branch's own `at` is authoritative; branches SHOULD start from heads current together. Janitor purges release's draft branch after its other branches.
- [ ] **MRG-16** (Documents keep naming the bases) Release documents name bases (`x-ref`s, `$schema`), never branch names. Draft schema revisions go in the release's branch of the schema namespace, listing the other branches in `drafts.for`; a namespace keeping schemas beside content drafts them in its own branch, merging schema resources in step 1 and the rest in step 2. Previews follow the listed branches (§F.8 Indexes).
- [ ] **MRG-5** (Merging, The plan, Before approval, Approval) A release merges as one batch per branch.
  - Before approval: each branch's `base` is namespace it is keyed by (or, for release built on another, that release's branch for key where it lists one) and it is not frozen or purged; on resuming, its own approval's freeze is accepted.
  - A person approves the digest `text(trunc160(sha256(canonical(plan))))`; `plan` is `{ "release": <release document's revision path>, "batches": [{ "ns", "source"?, "config"?, "items": [{ "resource", "ifMatch" | "ifNoneMatch", "steps" }] }] }`, no other members: `release` is `/r/{ns}/{name}/rev/{id}`, id in text form, as `on` writes it; batches in submission order, as §7.5 sends them, before sealing, only step 3's without `source`; each step `"delete"` or its plaintext patch set without fresh `$nonce` ops and without fresh top-level `$nonce` in the value of an `add` or `replace` at `""`; precondition on earlier batch's result is `{ "batch", "item" }` (or `{ "batch" }` for its config id), counting from 0, in place of id.
  - Approval fails if re-planning gives different digest. Approving freezes every listed branch; each `source.at` stays branch's `ns_id` before freeze; unfreezing branch invalidates plan. Each step is dry-run right before submission; difference from plan stops for new approval.

  **[vectors I.15]**
- [ ] **MRG-17** (Merging, steps 1–3) Batches go in three steps:
  1. Schema resources (dialect URL as `$schema`, tombstones and restores included), fast-forward only, in `$ref` order; one the base changed since `at` is a conflict. An end-to-end schema namespace isn't branched.
  2. Content, any order.
  3. Publishing, where readers' rules test a field marking documents published (e.g. `/doc/published`, §7.9): one batch per content namespace sets it on the documents the release created, which carried it unset.
- [ ] **MRG-18** (Merging, Before approval: reported conflicts) The merge service reports as conflicts:
  - a pinned `x-ref` to a revision of another listed branch that the merge replays (at E3, every one);
  - a document resolving a draft in a branch the release doesn't list;
  - a change to step 3's published field in steps 1 and 2.
- [ ] **MRG-19** (Approval: stored plan) The merge service stores the plan before submitting anything; a merge stopping part-way resumes from it, never reverts. Each branch records `merged` after the last step, `at` the target's `ns_id` after the last batch into it.
- **MRG-20** Retired in v0.87: the merge lock and catalog-base serialisation are removed (MRG-22).
- [ ] **MRG-21** (Rebasing, Cleanup) Rebasing a release creates a successor of each branch, listed in new revision of release document.
  - Schema successor is created first, with `drafts.for` naming other successors in its creation `patches`.
  - A resource referencing a replayed draft is squashed (§F.3), with `$schema` moved to the new revision.
  - Abandoning freezes the branches with `abandoned: true` (§F.6); schema revisions merged in step 1 stay.
- [ ] **MRG-22** (Releases built on another) A release built on another branches that release's branches and names it in `on`, still keyed by the namespaces paths name, resolving drafts from both (§6.1) where the earlier draft branch lists the earlier release's branches in `drafts.for`. Of two releases drafting one schema resource, the second to merge is rebased onto the first.

## Addendum G — Federation and portability

### §G.1–§G.2 Principles and external consumers

- [ ] **FED-1** (One canonical origin, Checkpoint, Verification, Access) One canonical origin per deployment, published at `GET /`. Consumer checkpoint: `(origin, ns, ns_id)`. It verifies revisions through their log (`/r/{ns}/{name}/rev/{id}/log`) by recomputing ids back to verified revision, and namespace chain from checkpoint; MUST verify when fetching through cache or mirror it doesn't control. Private namespaces need a `read` grant from source.
- [ ] **FED-26** (Purges follow imports; §G.4.4 step 7) A namespace imported from another deployment records that origin in its import batches' `source`. Where its operator trusts that origin (any writer can assert a `source`), its deployment SHOULD follow the origin's namespace log from the first such `source.at` and apply each `purge` there of a name it imported, and each `purge-ns` to every such name, as §8.3 does: its own chains for the name, its upstream namespace's, its branches, its cache tags. It writes these entries itself, without `grant` or `via` (HTTP-25); one §6.1 refuses as `in_use` waits for an operator. The importer doesn't apply them.

### §G.3 Remote branches

- **FED-2**, **FED-6**, **FED-7**, **FED-8**, **FED-9**, **FED-10**, **FED-11** Retired in v0.87: remote branches are removed; following an origin's purges is FED-26.

### §G.4 Bundles

- [ ] **FED-3** (Format, Full-history lines, Digest) Bundle: newline-delimited JSON (`application/vnd.patchlog.bundle+jsonl`), each line canonical JSON then one `0x0A`; any other line rejects it, as does a member §G.4.1 doesn't define, in a line or in an object whose members it lists (unlike namespace documents, §7.4 Versions). First line is the header, then one line per entry.
  - Full-history lines: resource log entries (§7.1) of kind `rev` or `tombstone`, with `ns` (exporting namespace) and `resource`, authorship members only as Authors (below) allows, in chain order per resource; every id recomputed, last line per resource MUST be that document's `docs[…].head`.
  - Every `docs` entry MUST have lines and every line naming resource a `docs` entry; any mismatch rejects bundle.
  - Chain starts at genesis or right after its `requires` id; chains exported from branch include base's entries back to genesis, or name in `requires` the foreign parent: the resource's head as the branch's `/heads` lists it at the branch's first `ns_id` (§10).
  - Digest: `text(trunc160(sha256(b)))`, `b` bytes as written.

  **[vectors I.9, I.20, I.24]**
- [ ] **FED-12** (Snapshot lines, Blob lines) A snapshot line carries document and its source id, one per `snapshot` document; `snapshot` MUST be that document's `docs[…].head`. Document tombstoned at source: `{ …, "snapshot": <tombstone id>, "deleted": true }`, no document.
  - Blob lines carry every blob exported document references (any exported revision of a `full` document, or snapshot), once per resource, with `nonce` if any, before first line mentioning it: one whose patches carry its id as a `$blob` member or as the value of an operation whose path ends in `/$blob`, whose snapshot document references it, or whose declared list names it. `data` is base64url without padding (readers accept either). Importer recomputes each blob id; mismatch rejects bundle. An incremental bundle MAY leave out blobs the history up to `requires` already references.
- [ ] **FED-13** (`requires`, Authors, `written`, `key`) `requires` applies only to `full` documents; `requires[r]` MUST be in target's chain for `r`; if target moved on along another line, `r` is conflict.
  - Authors, `via`, grant ids, author signatures, creation times, `gesture`, `undoes` only with `"authors": true`. History lines then carry `grant: gid` and bundle one grant line `{ "ns", "grant": gid, "root", "stored", "key"? }` per grant, before first line naming it, its `ns` the namespace whose entry first recorded the grant, in `written`'s form. An exporter that can't fetch a grant leaves `grant` off the lines that would name it. Rejected: line naming grant with no earlier grant line, second grant line for one grant, grant line whose `grant` isn't the id of its `root`, whose `stored` block's `grant_block` isn't `canonical(root)` (§C.3.1), or whose `key` has a `kid` other than `root.kid` or doesn't verify the `stored` block, or, without `"authors": true`, a grant line or history line with `author`, `via`, `grant`, `signature`, `created`, `gesture`, `undoes` or `written`.
  - Revision written in namespace other than exporting one carries `written` (its name); where undeterminable, `written` and `grant` are omitted.
  - `key` is `{ "kid", "alg", "pub" }`, the key entry the grant's root block verified against at source (a key of the namespace document in force at the first entry recording the grant, in a branch or its bases' then; else an operator key in force at the `created` of the first revision naming it), omitted if exporter finds none. Bundle tools SHOULD verify signatures against the header's `origin`; a tool holding source's namespace log or operator key history checks `key` at revision's position; otherwise it reports signature attested, not verified.

  **[vectors I.24]**
- [ ] **FED-14** (Never exported, Consistency) Purged content is never exported. Each namespace is exported as of its own `at`, taken when export starts.
- [ ] **FED-15** (Selection and dependencies) The closure always includes the `$schema` of every exported revision, the `$ref` inside those schemas, and blobs those revisions reference. Reference to schema revision existing only in branch can't be exported (`schema_unavailable`) unless that schema's namespace is `external`.
  - It also includes `x-ref` fields: pinned needs that exact revision, live head as of export's `at`. It doesn't follow `$successor`.
  - The importer checks dependencies left out as `external` exist in the target: by id for pinned references, in the resource's chain and neither purged nor pruned without a kept document (§8.6); by name for live ones.
- [ ] **FED-16** (History or snapshot, table) A `full` document carries every revision, or those after `requires`, source ids kept; a `snapshot` document head only. Schemas are always `full`. Everything a `full` document reaches through `$schema`, `$ref` or pinned `x-ref` MUST be `full`; pinned reference to non-head revision forces `full` for that document.
- [ ] **FED-4** (step 1 Check the bundle, step 2 Classify) An import first checks bundle (`requires`, `external` included) against target, writing nothing if this fails. Full-history documents by ancestry: missing in target: created with whole chain, ids kept; target has ancestor: fast-forward; target has it or is beyond it: nothing; different history: conflict; purged in target: nothing, reported.
- [ ] **FED-17** (step 3 Import snapshot documents through an upstream namespace) Snapshot documents go through `{ns}-upstream`, one per source namespace, written only by imports (batches whose `source` names a `bundle`) from one origin; step 1 refuses name breaking §3.6 and bundle from another origin than imports that wrote it.
  - Each import appends per snapshot document one revision `diff(previous snapshot, new snapshot)` (genesis first time); deleted document gets tombstone where upstream document is live, else nothing; empty diff writes nothing; diffs ignore `$nonce`. Target or upstream namespace sealed or requiring nonces: each generated patch set carries fresh `$nonce`.
  - First time: target fast-forwards from upstream, or conflicts if it already has document. Later: base is upstream revision in previous import batch's `source.ids`; upstream revisions after it are replayed onto target's head, conflicting where they overlap target's own changes (§F.3 array rule); deletion conflicts if target changed document.
  - Pinned references between snapshot documents are rewritten to `/r/{ns}-upstream/{name}/rev/{id}`, keeping any `#{id}` fragment. Dry run lists undeclared strings of revision-path form.
- [ ] **FED-18** (step 4 Dry run, step 5 Order, Rewriting waits for its targets, Partial failure) Conflicts resolved as §F.3. Batches changing existing dependencies are dry-run first (upstream appends don't count).
  - Batch goes once every batch holding revision it pins (schemas included) has committed; live references order nothing; batches writing same resource chain through `ifMatch`, in order. Document's references are rewritten only after its dependencies' batches committed, with returned ids.
  - Promotion that changes existing dependencies and isn't one batch: each later batch that moves heads target had is dry-run, failures that wouldn't occur once earlier batches are written are reported as deferred, and batch continuing chain earlier one cuts is skipped.
- [ ] **FED-19** (Size, Blobs first, Missing namespaces) An import tool paces batches, dry runs included, at fraction of lower of namespace's and its principal's rate, or under allowance at most its full rate, counting dry runs, per-resource buckets still applying. With several batches in flight, a request is paced as drawing when sent.
  - Blobs batch's step values mention are uploaded before it by importer, or copied with `Blob-From` within one deployment, unless batch's local `source` supplies them. Import that will submit uploads before dry run; one that only dry-runs uploads none. A snapshot document's blobs go to both its upstream resource and its target.
  - Under authentication operator creates missing namespaces (upstream included) before step 1.
- [ ] **FED-20** (Renaming) Import mapping namespaces (`src=dst`) rewrites every reference to mapped namespace: `$schema`, `$ref`, pinned and live `x-ref` values, `$successor` of form `/r/{src}/…` (and an `add` or `replace` of `/$successor` in history line), and pins to revisions (new ids), also in documents of unmapped namespaces; reference only later revision's schema declares is rewritten in that revision by added `replace`.
  - Full-history steps are rewritten and submitted one by one with new ids, never fast-forwarded; `source.ids` records source ids. Dry run lists undeclared strings naming a mapped namespace. Snapshot documents of renamed namespace go through `{dst}-upstream`. Mapping onto branch whose `base` chain reaches `src` keeps references and ids.
  - Refused at step 1: incremental document that would change, whose `requires` names source id; full-history document's pin whose new id isn't known (target `external`, left out, or snapshot document's revision).
  - Where nonces are fresh, a re-run recognises its earlier writes by import batches' `source.ids`.
- [ ] **FED-21** (Source, step 6 Today's rules judge old history, Authors) Import batch `source`: `{ "origin", "ns", "at", "bundle": <digest>, "ids": { name: upstream or source id } }`, without `origin` when bundle's `origin` is target's own. Importer is recorded as author and signs its own steps. Full-history import replays every step through target's current gate, as importer, at current `now`.

### §G.5 Encryption

- [ ] **FED-5** (`access`, Importing) Exporters MUST include `access` in header, and so does the server in a prune's archive (§8.6): each exporting namespace's protection as source (§2.1), `"public"`, `"private"`, `"sealed"` or `"e2e"`.
  - Step 1 refuses bundle putting namespace's lines into target, or its upstream namespace, ranking below that namespace (§2.1), unless operator explicitly overrides for that import; also target or upstream namespace whose protection it can't read.
  - An importer holding an `e2e` target's keys MAY import a non-`e2e` source into it by sealing each patch set client-side, encrypting each blob as §E.3.1 and rewriting references to the new blob ids, and puts a source resource named `keyring` in under another name, as target's is its key ring (§E.3.2); pins to the new ids, incremental documents and later imports are then handled as for a renamed import (§G.4.4).
- [ ] **FED-22** (Importing, No snapshots at E3) An `e2e` source goes only into an `e2e` target of same namespace name, override or not. Lines carry ciphertext and plaintext `keyring` verbatim; ids verify as usual; its documents are exported `full`.
  - Step 1 refuses: blob line lacking sealed type or having nonce; a `rev` line other than the `keyring`'s whose `patches` are neither one `sealed` op whose `pl.ns` and `kid` name line's `ns` nor restore's `[]`; snapshot documents for an `e2e` target.
  - Such history read through from a base, and an import under another name, are carried over as a merge, new ids, by a client holding both sets of keys. An exporter writes no line of such history but the `keyring`'s, exported whole under the branch's `ns`: it names the foreign parent in `requires` (§G.4.1), or refuses that document.
  - Target created for import starts at bundle's lowest epoch and moves up one epoch at a time as keyring lines arrive (importer needs `config` on it, with a `*` key); existing target likewise, refused at step 1 if its `keyring` would conflict with bundle's or its epoch is below bundle's lowest or above that of sealed line it lacks.
- [ ] **FED-23** (Sealed bundles: Envelope line, Lines, Checks, Digest, What stays visible) A sealed bundle (`application/vnd.patchlog.sealed-bundle+jsonl`) starts with `{ "sealedBundle": 1, "id", "recipients": [{ "kid", "suite", "wrapped" }] }`; envelope canonical JSON, each line then one `0x0A`; any other line, blank one included, rejects it.
  - `id`: 128 random bits, base64url without padding. The 256-bit content key `K_b` is wrapped per recipient as §E.2.3 with `info` `"patchlog-bundle-v1" ‖ 0x0A ‖ id` (`id` as its 22 ASCII characters); recipient `kid` is its thumbprint.
  - Each following line: JWE compact under `K_b`, protected header `{ "alg": "dir", "enc": "A256GCM", "pl": { "bundle": id, "line": n, "last"?: true } }` as canonical JSON (`last` on last line only), plaintext bundle line `n` (header = 0) as canonical JSON without newline. Lines are never compressed.
  - Reader MUST reject whole sealed bundle if: line fails to decrypt, or its protected header isn't canonical JSON or (`pl` included) has other members; `pl.bundle` differs from `id`; line numbers aren't 0, 1, 2… in order or reach 2³² − 1 (§E.2.1); no line says `last` or line follows it. It then checks decrypted bundle as §G.4.1. Padding is removed from line's plaintext before these checks and digest; `source.bundle` is decrypted bundle's digest.

  **[vectors I.12, I.17]**
- **FED-24** Retired in v0.87: remote branches (§G.5.2) are removed.
- **FED-25** Retired in v0.78: no source is raised to `e2e`.

## Addendum H — Files

### §H.1 What a file is

- [ ] **FILE-1** (Raw files, table, Which kind a new file is, Empty files) Every non-JSON file is a raw document, bytes kept exactly. `type`: from extension (any case) by table; else upload's `Content-Type` minus parameters unless absent or `application/octet-stream`, `binary/octet-stream`, `application/x-www-form-urlencoded` or `multipart/*`; else existing file's type, or `application/octet-stream` for a new file. A `text/` type needs a UTF-8 body (BOM allowed), else `application/octet-stream`. At E3 the reference's `sealed` holds the file's `type` and `size`, its own the sealed blob's.
  - New file named `*.json` (any case) with an I-JSON body (§3.1, leading BOM dropped) is a JSON file; any other new file is raw. Existing file keeps its kind: JSON accepts only I-JSON (`400` otherwise), raw any bytes.
  - Empty body makes or truncates a 0-byte raw file, except over a JSON file (`400`) and under new `.json` name; that, and `LOCK` of new name, is gateway-held 0-byte placeholder until body decides kind.
- [ ] **FILE-7** (JSON files) A JSON file's rendering is the canonical JSON text of the document minus a fresh top-level `$nonce` and a top-level `$successor` of §8.1's form, laid out as `JSON.stringify(value, null, 2)` (LF line ends, one final LF); tokens and member order exactly JCS's. Type `application/json`. **[vectors I.10, I.16]**
- [ ] **FILE-8** (Writer's bytes, Nonces, Identity) Every tool shows a document as the same rendering. A gateway serving a writer its own bytes back uses weak `ETag` `W/"{id}"`, accepted like the strong one in any `If-Match`.
  - Where nonces are required or namespace is sealed: in the flat view, a JSON file's root must be object carrying `$nonce` (other root: `422`, saying why); raw file's root carries `$nonce` beside reference, its blob a `Blob-Nonce`.
  - File's `ETag` is its document's head revision id. Raw save is stored with uploaded value; a JSON save when stored rendering parses to it. After save merged with others' edits, next `GET`, `HEAD` or `PROPFIND` is answered in full whatever validators it carries.

### §H.2 Trees

- [ ] **FILE-2** (A file tree, `content`, `folder`, Folders) A file tree is a namespace whose documents carry their place as data, a gateway configured with the namespaces it serves as trees and their file schema.
  - `content` is the file: what Addendum H says of a file's document applies to `content`, paths included (`/content/$blob`); `$nonce` and `$successor` stay at the document's top level, so a tree's JSON file may have any root.
  - `folder` is the holding folder's path, `/` or `/`-separated titles, `name` its title; the file schema marks `/folder`, `/name` `x-index: "facet"`, `/name` also `"sort"`.
  - Folders are documents without `content`, the folder `{folder}/{name}` (`/{name}` at the top). A document is in the tree only when its `folder` is `/` or has a folder document; tools leave out the rest however they list. Two folder documents for one path are one folder.
- [ ] **FILE-9** (Titles) Titles (the file schema's `pattern`, the tool the byte length): Unicode NFC, 1–255 UTF-8 bytes, not `.` or `..`, none of `/`, `\`, NUL, categories `Cc`, `Zl`, `Zp`, U+202A–U+202E, U+2066–U+2069 (other `Cf` allowed). Gateway converts received NFD to NFC and refuses trailing space or dot on create and rename for every client. Existing title breaking rules is shown escaped (offending characters, a trailing space or dot, and a whole `.` or `..` percent-encoded as UTF-8, stem shortened to stay within 255 bytes); escaped name never takes real title's name (it is numbered as a duplicate).
- [ ] **FILE-10** (Siblings) Files and folders in one folder share one name set, compared after NFC and, unless gateway is case-sensitive, Unicode simple case folding. Tools refuse to create a name a visible sibling has; a `MOVE` source isn't its own sibling (case-only rename allowed).
  - `PUT`, `COPY` or `MOVE` to a name matching a sibling only under another case: `409` naming the sibling, and sets a guard, unless the sibling is a file and either the request carries a tag or the user read or wrote that file under this spelling. `MKCOL` under another case: `405`; a folder mid-path matches whatever its case.
  - Duplicate left by race is shown as `name (2).ext`, `name (3).ext`, … in order of resource name; first keeps its name, a number colliding with a real title is skipped, stem shortened to stay within 255 bytes.
- **FILE-11** Retired in v0.87: tree-derived access is removed; folders as access is FILE-23.
- [ ] **FILE-12** (Flat view) Flat view: namespace is one directory; raw document is listed under its resource name, any other as `{name}.json`; raw `x.json` and document `x` both existing: raw keeps its name, document is shown by duplicate rule. §3.6's names, no folders; rename is copy plus delete.
  - New file whose resource is tombstoned, where §H.6 doesn't restore it: restores it with root `replace`; last revision has a `$successor`: `409` naming new path.
  - New file whose resource is a live document shown under another file name: `409` naming that file.

### §H.3 Listings

- [ ] **FILE-13** (In a tree, A folder too large to list whole, An index that is behind, Read-your-writes) In a tree a folder is listed by the index: `GET /{ns}?facet[/folder]={path}&schema=/r/schemas/file&sort=/name`, paged through; a path is resolved one folder at a time, or with `facet[/name]` too; hits filtered by the reader's read rules (SVC-11).
  - Folder too large to list whole: `403` saying why, never cut short.
  - A tool answers `503` for an index's `503 behind` (FILE-18), deleting nothing on listing meanwhile; sends its writes' `X-Namespace-Revision` as `?min` on later listings (§A.5).
- [ ] **FILE-14** (In the flat view, Sizes, Where times are absent, End-to-end trees) Flat view lists from `head` rows of `/heads` (tombstones and purges left out), `ETag` from `target`, time from `created`. JSON file size is its rendering's, not `/heads`' `size`; raw file's is blob reference's `size` (E3: `sealed.size`). Rows without `created` take `Last-Modified` from document read for size; in sealed and end-to-end namespaces gateway with keys takes times from logs. End-to-end trees no index holds keys for are listed only by a gateway with keys and unrestricted `read`, from the documents.

### §H.4 Saving a file

- [ ] **FILE-15** (Names before writes) The index lags, so before any write a tool reads the documents it resolved from a listing and checks each still has that `folder` and `name`, listing again with `?min` where one doesn't. A folder is empty only when a listing at or past the tool's last write in the namespace has nothing in it. A name the filtered listing lacks is never revealed or edited: `PUT` onto a name only a hidden sibling has creates a new file.
- [ ] **FILE-3** (The base, Records, Several records, The reload)
  - Base of `PUT`: revision named by `If-Match` (first value, `W/` dropped), else by `If` (first tag of first list applying to this resource, not negated with `Not`); older tag starts rebase, not failed precondition. `If-Match: *` asks only that file exist (head is base). No base: head.
  - Tag naming revision where path holds no file `412` (a tag naming a tombstone counts as naming the revision it deletes); revision of flat resource another user since deleted `409`; unknown revision `412`; pruned revision, recorded base below horizon, or pruned range between base and head `409`; failed read of anything save decides by, `theirs` and user's own entries included, fails save (FILE-18); head never taken as base instead.
  - Tagless saves, where gateway keeps records (per user and path, kept day then evicted; none for `304`, `HEAD`, `PROPFIND`; a save changing nothing is no write; when full, oldest records other than the first and the latest write go first): path now naming another document, or none `409` (a `GET` is reload); user's own `DELETE`/`MOVE` forgets path, except move to scratch name; evicted path `409`; never-recorded path takes head as base.
  - JSON save is checked against every recorded version as base: `409` naming paths if any two give different documents, except tagless save that sets back value someone else changed, which is merged keeping other value.
  - Reload after `409`: full read by refused token (`200`, not `304`), becoming path's only record; refusal re-arms nothing for user's other tokens. After `409` because someone else deleted file, the `404` is reload and next save restores it as §H.6 does. Exceptions, save `409`: file whose last revision has a `$successor`, naming new path (§11.3); one gateway can't read but for a failed read, saying it can't tell whether file moved. A failed read fails save as above.
- [ ] **FILE-16** (Others' writes, JSON files, Raw files) `theirs` = writes of log entries between base and head by other users; value changed and changed back is still conflict.
  - JSON file: saved as patch set from base's rendering to new file, keeping base's `$successor`, with `add /$nonce` of fresh value where §C.7 asks; write anywhere inside array counts for whole outermost array. Patch set over `opsPerSet` or `patchSetSize`: root `replace` carrying fresh `$nonce` and any `$successor` if base is head and namespace isn't end-to-end, else `413`.
  - Raw file: conflicts only if someone else changed bytes, or deleted or restored file, after any version user had. Body uploaded as blob (`413` above `blobSize`, before any upload); reference members (`/$blob`, `/type`, `/size`, `/nonce`, E3 `/sealed`) set one by one, fresh `/$nonce` where nonces apply, never root. A `412` retry reuses the pending blob; bytes compare by blob id.
- [ ] **FILE-17** (New files, Partial writes) New file in a tree: upload a raw file's blob, then create the document under a fresh opaque name with `If-None-Match: *`, its `folder` a folder the user can see (`409` otherwise).
  - `PUT` with `Content-Range`, or body cut short: `400`, nothing written. `POST` to file: `405` with `Allow`.
- [ ] **FILE-18** (Answers, table) Gateway answers:
  - save stored with uploaded value: `201`/`204` with new revision as `ETag` (even if rendering bytes differ); merged with others' edits: `201`/`204`, no `ETag`;
  - `409` naming paths: overlap with others' edits since base, delete or restore by another user between base and head, pruned base, disagreeing or evicted records, path now naming another file, file moved away or whose last revision gateway can't read but for failed read (FILE-3, FILE-19); `412`: `If-None-Match: *` on live file (but see move-aside), `If-Match` as FILE-3, `Overwrite: F` on existing target;
  - `403` saying why: new name breaking title rules or ending in space or dot, or not resource name in flat view;
  - core or index `422`, `401`, `403`: that answer with its message, or `502` naming service where user can't fix it;
  - frozen namespace `403` naming successor, never `423`; purged `410`; rate limited, or service behind longer than client waits: `503` with `Retry-After`;
  - a core or service request the gateway makes for the user's request failing (`408`, `429`, `5xx`, no connection, or no answer in time), a read of another namespace's documents or a write included, whether or not the answer needed it: `503` with `Retry-After` after a `429`, a `503` or no answer in time, else `502`; a failed read never counts as a refusal;
  - a gateway's `502` and `503` name only the upstream that failed, the core or a service, and carry nothing of its answer, as §C.6 says of a service's `502` (AUTH-26); the `503`'s `Retry-After` is the gateway's own;
  - limit exceeded (core `413`, or `422` with `code: "limit"`): `413` as `too large: {limit} {measured} > {max} (§6.6): {message}` (no sizes: limit alone; no limit named: core's text); gateway's own bound: same shape naming its setting, `measured` lower bound where reading stopped;
  - gateway memory for scratch files or locks full: `507`.

### §H.5 Deleting, renaming, moving and copying

- [ ] **FILE-4** (Delete a file, Delete a folder) Deleting a file deletes its document, with `If-Match` on the head the tool read: client `If-Match` not the head `412`; gateway's own delete finding the head moved since its read `409`. Folder is deleted only without visible children (FILE-15), else `409` naming those children; children the user can't see don't stop the delete and fall out of the tree.
- [ ] **FILE-19** (Rename or move a file, Rename or move a folder, Move onto an existing file, Moves that copy, Move to a scratch name, Across namespaces, Copy)
  - File: one append replacing `/name` or `/folder` with `If-Match`, after checking the document still has the name and folder the path named (`404` otherwise); new folder must exist. On any `MOVE`, client `If-Match` names source; not its head `412`.
  - Folder: one batch rewriting the folder document and the `folder` of every visible document under it, each item with `ifMatch` on the head read; into itself or a descendant `403`; too large for a batch refused as a limit (FILE-18); documents under it the user can't see fall out of the tree.
  - Move onto existing file (`Overwrite: T` or absent; `F` `412`) is a save of the source's content into target (source's type as upload's `Content-Type`; base as §H.4, never from `If-Match`), then delete of source; `COPY` onto existing file likewise save. `MOVE`/`COPY` onto existing folder, or folder onto file: `403` (`412` with `Overwrite: F`).
  - Moves that copy: check source can be deleted, copy, delete source with `If-Match` naming revision copied; source changed since `409`, stays; failing delete leaves copy.
  - After move to scratch name file stays live; next create-only `PUT` of original path by same user within 30 seconds is accepted once as edit, base as for any untagged save.
  - Document moved to another namespace: last revision before tombstone carries `$successor`, unless flat view's JSON file whose root isn't object.
  - A copy is a new document with source's current content. Raw blob copied with `Blob-From` where §7.8 allows, else bytes uploaded again: decrypted with the reference's key from an `e2e` source, encrypted under a fresh key, new id, into an `e2e` target.
  - Folder copy, or move to another namespace: new folder document as `MKCOL` makes one, titled with destination's last segment; visible children copied or moved one by one (`Depth: 0`: folder alone); moved folder deleted once empty; failure part-way leaves what was done, with no rollback, answered as that child's request would be.
  - Copy into the folder itself or a descendant of it: `403`, before anything is written.

### §H.6 Clients as they are

- [ ] **FILE-5** (Scratch files, Delete, then write)
  - Scratch names (§H.6's lists) are kept by gateway in bounded memory, never written to core; no other folder is scratch; existing document with such name is real file. Copy names (`x copy.txt`, `x (1).txt`) are real in tree; in flat view scratch only as `COPY` destinations, plain `PUT` of one `403`.
  - Write to path same user deleted within 30 seconds restores that file rebased on its last live document, as a whole-document `replace` when its patch set would exceed `opsPerSet` or `patchSetSize` and its base is the last live document. Restore refused (`403`, `410`): write creates new file or is refused as such write would be. File whose document has `$successor`, or whose last revision gateway can't read, is never restored so; failed read fails the write (§H.4). Write refused: user's delete (never one older than 30 seconds) is undone where possible.
  - Refused `PUT` or `COPY`, move onto file, or case variant sets guard: that user's `DELETE` of that path within 10 seconds is `409`, once per refusal; `DELETE` with `If-Match` passes and leaves guard. Refused plain move sets none; two refusals never share guard; a guard ends only by time; none after undo.
- [ ] **FILE-20** (Locks, Dead properties, Listings, Headers, Status codes)
  - Locks are kept by gateway, per user, bounded, never sent to core; `DELETE` drops user's locks on path and below; `MOVE` or `COPY` with source's lock token isn't `412` for want of destination lock.
  - Dead properties: refused, or kept per user and scope up to a bound (past it, least recently set path's dropped), moved with `MOVE`, dropped with `DELETE`; a property the gateway doesn't keep is never acknowledged.
  - `PROPFIND` `Depth: infinity` `403` (`propfind-finite-depth`); no `Depth` is `1`.
  - Gateway serves raw files itself, under revision's `ETag`, never as cross-origin redirect; every response carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox` (PDFs excepted as §7.8). `423` and `507` only for what they mean.

### §H.7 Access and encryption

- [ ] **FILE-6** (Grants, Users) Gateway either passes each user's grant through as bearer of every core request, or holds its own grant and narrows it per user with `via`; either way the core authorises every core read and write.
  - User = root `sub` plus `key` that verified root block (from `GET /ns/{ns}/principal`). User's own entries: `grant` has its `sub` and a `kid` that named its `key` when written. One token's reading of namespace documents serves another only once that one has read a range of namespace log; for token that can't read them (§C.5), a `kid` counts as naming the key it names now.
  - Authentication disabled: user = `X-Author`, entries those with that `author`. Operator grants are never users of gateway (`403`).
  - Narrowed gateway grant: user = one named in `via`, own entries only those gateway recorded writing for it. One bearer for everyone is one user; programs sharing grant count as one.
- [ ] **FILE-21** (What a user's tokens share, Re-checking) Guards, user's own deletes, move-aside marks and records are per user. Scratch files, placeholders, locks with owners and dead properties are kept per user and scope (root block without `kid`, `sub`, `nbf`, `exp`, `enc`, `signers`; narrowing blocks without `nbf`, `exp`; `ns`, `can`, `roles`, `groups` compared as sets), served only to token of that scope whose grant names namespace. Read caches are per token.
  - Per-user state is bounded; new scope when content scopes are full: `503` with `Retry-After`, never dropping one holding content.
  - Gateway creates state for grant only after core accepted it, bounds the users it keeps state for, re-checks grant at least every five minutes, relies on `writer` block 30 seconds at most (re-read after `409 frozen`, `422 nonce` or a limit refusal), and stops serving token core refuses, keeping user's state for other tokens, each re-checked at its next request.
- [ ] **FILE-22** (Limited grants, Sealed and end-to-end namespaces) A limited grant lists a tree through the index (FILE-13), and a flat view only through filtered `/heads` (§7.9); it learns what it may write from `GET /ns/{ns}/principal`. Gateway without keys doesn't offer sealed or end-to-end namespaces and never shows their files as writable empty files.
- [ ] **FILE-23** (Folders as access) Read rules on `/doc/folder` give a grant a subtree, its own folder document included: under H.7's `team-a` rule a reader sees `/team-a`'s folder document and every document whose `folder` is `/team-a` or below, and no other (§7.9 per revision). Write rules guard `folder` and `name` (§6.4.4). In sealed and end-to-end trees such grants read nothing, `/doc` rules failing (RUL-8).

## Addendum I — Test vectors

### §I.1 Canonical JSON (§3.1)

- [ ] **VEC-1** (table, member order, noncharacters) §3.1:
  - accepts `{"a":1,"b":2.0}`, `{"a":1e2}`, `{"a":9007199254740991}`, `{"a":1000000000000000000000}`, `{"a":1e21}`, `{"a":1e300}`, `{"a":0.1}`, `{"a":1e-400}`, `{"a":-1e-400}`, with I.1's canonical forms (the last two `{"a":0}`);
  - `400` for `{"a":9007199254740992}`, `{"a":-9007199254740992}`, `{"a":1,"a":2}`, lone surrogates `"\ud800"`, `"\udc00"`, `"\ud800A"`, `{"a":1e400}`, `{"a":-1e400}`, `{"a":1e20}`, `{"a":-1e16}`, `{"a":9007199254740992.0}`, `{"a":9.007199254740992e15}`;
  - sorts members by UTF-16 code units: `{"b":1,"a":2,"ä":3}` → `{"a":2,"b":1,"ä":3}`; keys above U+FFFF sort by surrogate pairs;
  - `400` for noncharacters U+FDD0 (raw, bytes `efb790`), U+FDEF, U+FFFE, U+FFFF, U+1FFFE, U+10FFFF, raw or escaped; accepts U+FDCF, U+FDF0, U+FFFD, raw or escaped: as `t` in `[{"op":"add","path":"","value":{"t":…}}]` the genesis ids are `1sxrx3wwzxwyahs7khilka36c6selzwrb`, `1jkaabmuivygpelkeuncgmiatzunwp5zw`, `137ielgcxtgdymhcykw5flzgaml4d6kbx`.

### §I.2 Ids (§3.2–§3.5)

- [ ] **VEC-2** (table, namespace chain) §3.2–§3.5:
  - reproduces I.2's text forms and bytes for genesis `g` of `patches₁`, its child `c` by `patches₂`, and tombstone of `c`;
  - reproduces `ns_id₁` for `entry₁` (empty previous id) and `ns_id₂` for `entry₂` after `ns_id₁`;
  - rejects the seven text ids I.2 marks rejected (empty string included); accepts `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm`, the bytes of `g` with last one `6c`.

### §I.3 Blob ids (§3.7)

- [ ] **VEC-3** (table) §3.7 gives the 15 bytes `hello patchlog\n` of type `text/plain` the id `1m5jj344d7tz7cicfmq53ayhmwuubpmyt` without nonce, `1hdwkfub2zymqzgc75snybxosfk67633s` with nonce `aaaaaaaaaaaaaaaaaaaaaaaaaa`.

### §I.4 Grant ids and author signatures (§C.3, §C.3.1)

- [ ] **VEC-4** (root block, signing input, signature) §C.3 and §C.3.1:
  - I.4's root block has grant id `15swdvi5nbnlkv76v7y6k77h52atov6ru`;
  - signing input for origin `https://cms.example`, `ns` `matches`, `name` `derby`, parent `g`, `patches₂` is `43bba3f8e86bdd96435153ddb0d704cab7e5e9459087f3fd78c157b6a7102c54`;
  - I.4's signature `Ed25519:key-1:…` verifies under public key `RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM`, listed under `kid` `key-1` in grant's `signers`; Ed25519 (RFC 8032) over the digest's 32 raw bytes.

  A tombstone's signing input uses ASCII bytes `tombstone` in place of `canonical(patches)`.

### §I.5 Edge-grant cookies (§C.5.3)

- [ ] **VEC-5** (cookie, rejected claims) §C.5.3's default format, I.5's key, clock before `exp`: claims `{"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}` give name `__Secure-pl-eg-4390e78526d94754` and value I.5 shows. Edge using that format ignores:
  - claims with fourth member;
  - claims not canonical byte for byte;
  - a MAC verifying only over re-encoding of claims;
  - name not matching its `p`;
  - an `exp` in past;
  - a `p` covering the path only as string prefix.

### §I.6 Padding buckets (§E.2.2)

- [ ] **VEC-6** (table) §E.2.2 pads `L` bytes to I.6's length: 1, 255, 256 → 256; 257 → 272; 300 → 304; 511 → 512; 513 → 544; 1000 → 1024; 4096 → 4096; 1000000 → 1015808; 1048576 → 1048576; 67108864 → 67108864.

### §I.7 Derived keys (§E.2.1)

- [ ] **VEC-7** (derivation) §E.2.1 derives, for `K_e` bytes `00 01 … 1f`, `ns` `demo`, `name` `derby`: `K_r` = `37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25`; `K_n` = `b2d9864bdf7f562d58e3638e08ec2e97e553c74995edbcef110ee9adfed62b4c`.

### §I.8 Views and combined checkpoints (§7.9, §A.4)

- [ ] **VEC-8** (view, combined checkpoint) §7.9 and §A.4:
  - subjects `["group:match-desk","user:anna"]`, an input only, give `view` `17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm` (`text(trunc160(sha256(canonical(subjects))))`);
  - checkpoints `{"cat":"1vmctae4vewju6nvxi374rkrkmyzpdrif","matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"}` give combined checkpoint `1vwnfnoyshruyx4lul4a25rtctooiph5v`.

### §I.9 Bundle digests (§G.4.1)

- [ ] **VEC-9** (digest) §G.4.1: I.9's two lines, each followed by one LF, have digest `1b3a64kkqf3o6f3rglkgi6ok5hgldbne6`.

### §I.10 File renderings (§H.1)

- [ ] **VEC-10** (rendering, escapes) A tool claiming Addendum H renders I.10's document as the 118 bytes shown, sha-256 `c7e8bfb3ff3fed1b111dda8cce06b4f2c1b7615565e828f4777ebf63055e887c`; fresh `$nonce` left out, `"10"` before `"2"`. I.10's escapes document renders as 70 bytes, sha-256 `25a705341cb21ebb8a4fe6b4a4059fcf16d8ef3eeaed137094ba0f9dfc2f3c65`: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, `\u0000`, `\u001f` kept, `\/` as `/`, the rest raw (U+007F and U+2028 included).

### §I.11 Regular expressions (§6.6)

- [ ] **VEC-11** (table) §6.6's regular expressions, patterns and strings taken as characters, not JSON:
  - `^\u00e9$` matches `é`, not `e` or the six characters `\u00e9`;
  - `^\ud83d\ude00$` matches `😀`;
  - `^[\u00e0-\u00ff]+$` matches `àéÿ`, not `a`;
  - `^\\u0041$`, with an escaped backslash, matches the six characters `\u0041`, not `A`;
  - `\ud800`, `\udc00`, `\ud83dA` and `\x{D800}` are refused.

### §I.12 Wrapped keys (§E.2.3, §E.3.2, §G.5.1.1)

- [ ] **VEC-12** (keys, wrapped keys, envelope) §E.2.3, §E.3.2, §G.5.1.1:
  - X25519 private keys `20 21 … 3f` (recipient), `40 41 … 5f` (admin), `60 61 … 7f` (ephemeral) give I.12's `x`; the first two give its thumbprints;
  - with that ephemeral key, I.7's `K_e` and `K_r`, `kid` `demo#3`, wrapped to recipient in base mode, and `K_e` in auth mode under admin's key, give I.12's `enc`, `info` and ciphertexts (`wrapped` = `enc` then ciphertext); the auth-mode one opens under no other sender;
  - `422` for a `keyring` entry without `kid` or `wrapped`, or with a `from` that isn't thumbprint (`"admin"`);
  - I.12's sealed-bundle envelope opens with recipient's key to `K_b` `dbe5882e2579683432c1bfc525454add0cd87274d67084caaf0e0d36c8496db7`;
  - Ed25519 seed `a0 a1 … bf` gives `pub` `T9CZzNR9eJPf6ewkQU7LDZtUICMqrTDZHEZb4zy-ZcQ` and `/principal` `key` `7c_8cf3VPZjtkqQSzpjXvbhEeMBVVWow5j-JOgj_uu8`.

### §I.13 Sealed payloads and blobs (§E.2.2, §E.3.1)

- [ ] **VEC-13** (sealed payloads, sealed blobs) §E.2.2 and §E.3.1, with I.7's keys, `kid` `demo#3`, IV `c0 c1 … cb`, canonical headers and plaintexts:
  - the document of `g` (I.2) seals under I.13's header to its JWE, and, padded to 256 bytes, with tag `p2Mr0OgF8n6NV7D4m7OZzw`;
  - unpadded, the grant (under `K_n`, tag `sAMGTdYa8kLrAP_ZfHvxCA`), E3 patch set and E3 prune snapshot of I.13's table seal with its keys, `pl` and tags;
  - I.13's E3 write, with that patch set's JWE as `value`, has genesis id `1ptb7hgvw5g5msprod2l5d2pp5b2mtppz`;
  - I.3's blob under `K_r` with I.13's header seals to the 168 bytes shown, 401 bytes padded;
  - at E3, under key `e0 e1 … ff` with header `{"enc":"A256GCM"}` it seals to the 76 bytes shown, blob id `1chzlyccn2qkoz6mobtbzvzm4s6h7pbi6`, and I.13's blob reference.

### §I.14 Biscuit grants (§C.4, §C.8)

- [ ] **VEC-14** (token, revocation ids) §C.4 and §C.8: I.14's token, under root key of seed `00 01 … 1f` (`pub` `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`), carries I.4's root block and narrowing block `{"can":["read"],"via":"svc:reader"}`, with Biscuit's version 1 signature payloads, and has revocation ids `15swdvi5nbnlkv76v7y6k77h52atov6ru` (the grant id) and `1chpmwycvsbh7sqmzckzhe7hk6obtra72`.

### §I.15 Plan digests (§F.9)

- [ ] **VEC-15** (release document, `plan₁`, `plan₂`) §F.9:
  - I.15's release document's genesis has the id I.15 gives, and its revision path is both plans' `release`; I.2's `ns_id`s serve as `source.at` inputs only;
  - `plan₁` (one batch, one item, a patch-set step) has I.15's first digest;
  - `plan₂` (two batches with `config`, a `"delete"` step, an empty step, `ifNoneMatch`, `{ "batch" }` and `{ "batch", "item" }` preconditions) has I.15's second digest once its fresh nonces (an `add /$nonce` op, a fresh top-level `$nonce` in a root `add` value, a restore's `replace /$nonce`) are left out and `semi`'s `$nonce`, not of the fresh form, kept;
  - keeping the fresh nonces gives the digest I.15 marks wrong.

### §I.16 More file renderings (§H.1)

- [ ] **VEC-16** (table) A tool claiming Addendum H renders each document of I.16's table to its byte length and sha-256:
  - a top-level `$successor` naming a resource or a `/r/` path left out; one that isn't a name (`Derby-2`, §8.1) kept;
  - a top-level `$nonce` not of the fresh form (uppercase, or 25 characters) kept, and a nested fresh one kept;
  - an array root: nothing left out;
  - numbers as JCS writes them: `1e+21`, `1e-7`, `-0.0000015`, `1.23e-18`, `1e+300`, `5e-324`.

### §I.17 Sealed bundles (§G.5.1.1)

- [ ] **VEC-17** (sealed bundle, digests, table) §G.5.1.1:
  - I.12's envelope, wrapping I.17's `K_b` to I.12's recipient (key `20 21 … 3f`), over the three lines of I.20's accepted bundle (`"authors": false`), with I.13's IV and I.17's three line headers, gives the sealed bundle shown, with I.17's length and sha-256; padded (§E.2.2), each line's plaintext spaced to its bucket (272, 256, 256 bytes), it gives I.17's tags, length and sha-256, and decrypts to the same bundle once the spaces are removed;
  - decrypted, it is I.20's accepted bundle, which §G.4.1 accepts; its `source.bundle` is that bundle's digest, not the digest of the sealed bytes;
  - each of I.17's twelve changes to the unpadded file rejects it whole, by the rule of §G.5.1.1 I.17 names: a line's protected header not canonical (`pl` members out of order, a space added); other `pl` members; `pl.bundle` differing from `id`; line numbers not 0, 1, 2… in order; no `last` (line 2 without it); a line after `last` (line 0 with it); `0d 0a` after the envelope or the last line, or the last `0a` removed; a blank line at the end; a line that fails to decrypt.

  I.17's values were recomputed from the text in v0.85 and await the reference's confirmation.

### §I.18 Hostnames (§6.2 step 5)

- [ ] **VEC-18** (table) §6.2 step 5's formats:
  - `hostname` accepts `"ab--cd"`, refuses (`422`) a lone U+00B7 and `"l·l"`;
  - `idn-hostname` refuses `"ab--cd"` (`--` in positions 3–4 without `xn--`) and a lone U+00B7 (CONTEXTO without `l` on both sides), accepts `"l·l"`;
  - both accept `"XN--BCHER-KVA"` and `"xn--bcher-kva"`.

### §I.19 Sealed log entries, namespace documents and ranges (§E.2.2)

- [ ] **VEC-19** (entries, table, ranges) §E.2.2, with I.13's keys, `kid` and IV, over I.19's illustrative plaintexts:
  - `nsentry₁` and `nsentry₂` rehash to I.2's `ns_id₁` and `ns_id₂`;
  - resource log entries `entry_g`, `entry_c` (with `via`) and `entry_t` (a tombstone) under `K_r`, `nsdoc` under `K_n`, and namespace log ranges of both entries and of an empty page (`[]`, `since` = `id`) under `K_n` seal, with I.19's `pl`, to its tags, unpadded and padded;
  - `entry_g` seals to the JWE shown;
  - the resource log range from `g` to `c`, the array of `entry_g`'s and `entry_c`'s JWEs, has I.19's length and sha-256.

### §I.20 Full-history lines with `via` (§G.4.1)

- [ ] **VEC-20** (bundle, rejected, accepted) §G.4.1:
  - I.20's full-history bundle (`"authors": true`; a grant line whose `stored` is I.14's authority block and `key` its root key; `c` written through a delegatee, with `via`) has I.20's length and digest;
  - rejected without its grant line, and with `"authors": false`;
  - with `"authors": false`, no grant line and history lines without `author`, `via`, `grant` and `created`: accepted, with I.20's length and digest; rejected if `c`'s line keeps its `via`.

### §I.21 Biscuit tokens refused (§C.8)

- [ ] **VEC-21** (tokens) §C.8: each of I.21's tokens, I.14's with one change, from the same keys and version 1 payloads unless stated, is `401`, at decoding or at verification:
  - an authority block with a second fact, a rule, a check, a scope (block version 4), a public key (block version 4), a context, an added symbol it doesn't use, or a symbol it adds that only the narrowing block uses;
  - a third-party narrowing block;
  - the authority or the narrowing block signed over the version 0 payload;
  - a root block string not canonical, or not I-JSON; a narrowing block string not canonical;
  - a narrowing block signed with P-256; an authority signature with `S + L` in place of `S`;
  - a root block naming a `kid` the namespace lists with another key than the one that signed it (`ops-2027`, its grant id the one I.21 gives).

### §I.22 Sealed events (§E.2.2)

- [ ] **VEC-22** (events, table, rejected) §E.2.2 and §7.3, with I.19's keys, `kid` and IV:
  - a resource `purge` and `prune` event, each plaintext its namespace entry without `id` and `prev` (I.22's `purge`, `prune`), under `K_r` with `pl` `{ "ns", "name", "kind" }`, and the namespace event for `ns_id₂`, plaintext `nsentry₂`, under `K_n` with `pl` `{ "ns", "event" }`, seal to I.22's tags, unpadded and padded;
  - the namespace event seals to the JWE shown;
  - a namespace event whose `pl` is a `range` of its one entry is rejected.

### §I.23 View keys and per-entry sealing (§E.2.6)

- [ ] **VEC-23** (`pl.view`, view key, per-entry JWE, rejected) §E.2.6 and §A.5, for an index on its own origin serving `demo` (epoch 3) at I.8's `view` (an input only) and `ns_id₂`, query `q` = `a b`, `sort` = `/title`:
  - the canonical query is `q=a%20b&sort=%2Ftitle`, giving I.23's `pl.view` `/demo/view/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle`;
  - the view key `HKDF-SHA256(K_r, "patchlog-view", pl.view)`, `info` the `pl.view`'s ASCII bytes, is `e3fdb292d5cae0f7a6829614b3a3c5a0a5e573246a039d90c89e6b30616219d5`;
  - the hit for `derby`, sealed per entry under it with `kid` `demo#3`, I.23's header and plaintext, gives the JWE shown, and padded the tag I.23 gives; the hit is served as I.23 shows;
  - a reader rejects a JWE whose `pl.view` has `+` for the space, lowercase hex (`%2ftitle`), the parameters in another order, or a scheme and host; no `pl.view` has a `min`.

### §I.24 Bundles refused (§G.4.1)

- [ ] **VEC-24** (table) §G.4.1: each of I.24's changes to I.20's bundle, with I.24's sha-256, rejects it whole:
  - grant line's `grant`, and both history lines', the id of I.21's `ops-2027` root block: a grant line whose `grant` isn't the id of its `root`;
  - grant line's `stored` the authority block of I.21's token whose root block string isn't canonical: `grant_block` isn't `canonical(root)`;
  - the header with `"x-note":"hi"`: a member §G.4.1 doesn't define.

### §I.25 Long-poll phases (§7.7)

- [ ] **VEC-25** (table) §7.7: at the default 20 s interval, a path's phase is the first 8 bytes of its SHA-256, big-endian, modulo 20,000 ms:
  - `/r/docs/a/log`: `c6b6521efdba5aa1`, 15,777 ms;
  - `/r/docs/b/log`: `d88ca141ae2485cf`, 1,327 ms;
  - `/ns/docs/log`: `7a75dc61743845ce`, 18,318 ms;
  - `/ns/matches/view/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/log` (I.8's `view`): `e0ffbec41992c73a`, 12,058 ms.

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
11. Bundle with `access: { "matches": "private" }` → import into a public target, or into its public `{ns}-upstream` → refused at step 1, unless an operator overrides it for that import (§G.5.1, §2.1)
12. Bundle whose `access` lacks a namespace → import → that namespace counts as `private` (§2.1, §G.5.1)
13. `sealed` source, sealed target with `read: "public"` → import → refused at step 1. Into a sealed target with `read: "grant"` → accepted (§2.1, §G.5.1)
14. `e2e` source → import into a non-`e2e` target, or into an `e2e` target with another name, override or not → refused (§G.5.1)
15. Public source, `e2e` target, importer holding the target's keys → import → allowed, each patch set sealed client-side, blobs re-encrypted, ids change (§G.5.1)
16. `PATCH /ns/{name}` with `If-None-Match: *` and a genesis setting `base` → `422`, since only a branch's creation sets it, so no namespace reads a base through without a `branch` entry and the base's checks (§7.4 Branch fields, §7.6)
17. Gateway copying a raw file within a tree → blob → `Blob-From` where the ranks allow it, otherwise the bytes are uploaded again (§H.5 Copy)
18. A sealed namespace with `read: "public"`. A writer in an unsealed private namespace knows a blob id and a resource name, holds no grant for the source, and so gets no keys → `Blob-From` copy → `404` (a sealed source needs a grant that §E.2.3 would give the resource's key)
19. Same sealed source with `read: "public"` → batch with a local `source` naming it, by a caller without keys → its blobs are not made available, `422 blob` (§7.8 Availability)
20. Sealed source with `read: "grant"`. A reader may read the resource, but no served epoch of the blob is one its grant gets keys for (`nbf` window, `historyEpochs`) → `Blob-From` into an unsealed private namespace → `404` (§7.8, §E.2.3)
21. Private branch `release-7` of a public base → rebase per §F.5 step 1 (successor created with `patches: []`), then replay → the successor gets the old branch's `read`, and a replay into a successor that ranks below the old branch is refused (§F.5, §2.1)
22. Grant fixed to `old` and `new` with `create`, `append` and `delete` only, and `old` has blobs → in-namespace move (`Blob-From`, then the batch) → the copy is `404`, so such a move also needs `read` on `old` (§7.8 Copying, §8.1 Moves)
23. A public, private or sealed source, full history → import into a sealed target, whose writers must refresh `$nonce` in every patch set → history without fresh nonces can't be replayed, so it goes in snapshot mode (§G.4.4 step 6, §E.2.5)
24. Sealed base `matches` with `read: "public"`, branch `release-7` created without a `read` patch (so sealed, `read: "public"`, ranking `sealed` as a source) → rebase per §F.5 step 1 → successor created with `read: "grant"`, and the replay works. With `read: "public"` (ranking `public` as a target) the replay is refused (§F.5, §2.1)
25. E3 branch, merger who reads it per resource → `Blob-From` copy of a branch blob into the `e2e` base before the merge batch → `201`: equal ranks, and only an import's lines stay under their own name (§2.1, §F.3 Blobs, §F.8.1)
26. Sealed branch with `read: "grant"` → rebase into a successor that the base's current document leaves unsealed, given `read: "grant"` → replay allowed: `private` = `sealed` (§2.1, §F.5)
27. Import under an operator override into a lower-ranked target in the same deployment → `Blob-From` of the source's blobs → `404`, since the override is the tool's, not the server's. The importer uploads them, or a caller with unrestricted `read` on the source names it as the batch's local `source` (§7.8, §G.4.4 Blobs first)
28. Gateway `COPY` of a raw file from an `e2e` namespace into one that isn't, or into an `e2e` namespace from one that isn't → `Blob-From` is `404` (ranks) or the upload `415` (check 4) → the gateway uploads the file's plaintext, decrypted with the reference's key, or, into `e2e`, encrypted under a fresh key with a new id (§H.5, §E.3.1)
29. Private source, public target, a caller who may read the source resource, whose blob Reading serves there → `Blob-From` copy → `404`, each condition of §7.8 Copying refusing on its own (§2.1, §7.8)
30. Base `N`: name `x` created after `n5`, purged at `n9`. Branch `L` created afterwards at `n5`, by a creator whose branch readers can't read `N` → `GET /r/L/x` → `404`, as for a branch at `n5` that existed before the purge, and `L`'s `/heads` doesn't list `x` (§8.3, invariant 7)
31. Public sealed `schemas` (`read: "public"`, E2); a writer in `docs` with no grant for `schemas`, or with one whose key window starts after revision `X`'s epoch → write in `docs` whose `$schema` is `/r/schemas/match/rev/X` → `422 schema_unavailable`, with no validation errors from `X` (§6.1 Read permission, §2.1)
32. Sealed source `matches`; snapshot import into a private unsealed target `matches` through a sealed `matches-upstream` (ranks `sealed` = `private`, so step 1 accepts it) → each generated upstream patch set carries a fresh `$nonce`, so upstream ids can't confirm guessed content (§G.4.4 step 3, §E.2.5)
33. A caller who may write the target but can't read the source, or a source that doesn't exist → `Blob-From` copy carrying `If-Match` → `428` in both cases, before the source check, so the answer shows nothing about the source (§7.8 Copying, check 4)
34. Private `matches`; `derby`'s documents reference a schema in private `schemas` and a pinned `x-ref` to `matches/cup` → prune `derby` → the archive holds only `derby`'s pruned revisions and the blobs they reference: no `schemas` or `cup` lines, no `external`, `docs` naming only `derby`. A later prune's archive starts at the earlier horizon, its parent in `requires`, even where the earlier prune went without an archive (§8.6 Archive, §G.4.1, §G.4.3)
35. Release `release-7` with branch `matches-r7` of private `matches`; a collaborator whose `matches` grant is fixed to `derby` → the branching service's grant for it on `matches-r7` → the rules of its base grant, so fixed to `derby`, never unrestricted `read`. `GET /r/matches-r7/cup` with it → `404`, as for any resource the grant doesn't cover, so `cup` is never read through the branch; the branch's preview index lists only `derby` (§F.8 Access, §A.4, §2.1, §7.6)
36. Bundle with `"authors": true` and a grant line whose `grant` isn't the id of its `root`, whose `stored` block's `grant_block` isn't `canonical(root)`, or whose `key` has a `kid` other than `root.kid` or doesn't verify the `stored` block, signatures otherwise valid → import → rejected whole at step 1, before anything is written, never imported with its signatures reported as attested (§G.4.1, §C.3.1 Reading grants)
37. Bundle whose header, a history line or a grant line carries a member §G.4.1 doesn't define (e.g. `"x-note"`) → import → rejected whole at step 1 (§G.4.1)
38. `e2e` namespace with an archive configured → prune → the archive's header carries `access` naming it `"e2e"`, so its lines are refused at step 1 for any target but an `e2e` one of the same name (§G.5.1, §8.6, §2.1)
39. Bundle with a pinned `external` reference to a tombstone id of `media/photo-12` → import into an E3 target whose `photo-12` chain holds that id, not purged → accepted. The same id purged in the target, or not in its chain → refused at step 1, nothing written (§G.4.2, §G.4.4 step 1)

### Filtered reads (§7.9)

**Invariant.** A partial reader learns of a revision, its document, its patches or its blobs only where its grant's read rules allow that revision's `read` envelope, beyond the accepted leaks §7.9 lists. Whether a revision is visible never changes while its document is stored, a view's kept answer survives pruning, and a revision first judged without a stored document is visible to no `/doc` rule. Filtered answers are cached and shared only per `view`, and a `view`'s cookie never outlives the rules, keys and roles it digests.

Unless a line says otherwise: private, unsealed `matches`, not a branch, on an origin that implements §7.9. li's grant verifies in `matches` and allows `read` there, with the block rule `{ "op": "test", "path": "/doc/team", "value": "a" }`, so li is a partial reader. `derby`'s revisions say `team: "a"` (visible to li), `secret`'s `team: "b"` (hidden from her).

1. li → `GET /ns/matches/rev/{ns_id}/heads` → `302`, `private, no-store`, to `/ns/matches/view/{view}/at/{at}/heads` at the current `at`, which lists `derby` and never `secret`. `secret`'s entries never appear in her log ranges, long-poll, events or index hits either (§7.9 URLs, `/heads`, Log entries, §A.4 Private namespaces)
2. li → `GET /ns/matches/rev/{ns_id}`, `/ns/matches/grants/{gid}` or `/ns/matches/branches` → `403`, and her filtered log never shows a `branch` entry. `GET /ns/matches/principal` → `200`, `roles` only her effective roles, each exactly `{ "name", "can", "rules" }` even where the role entry also has `includes` or `x-note`, never the namespace's whole `roles` (§7.9 Answers, Log entries, §7.4)
3. `matches` sealed (E2) or public, or li's grant on branch `matches-r7` → `/ns/{ns}/view/{view}/at/{at}/heads`, a filtered log range or long-poll → `403`, and `401` with neither a grant nor a cookie that verifies. `POST /edge-grants` with her grant in sealed `matches` or in `matches-r7` → `403`, since its rules refer to `/doc` and no `view` prefix is given there (§7.9 Where, §C.5.2)
4. A branching service creates `matches-r7` for li and issues her a grant on it with her base grant's rules (§F.8) → filtered `/heads` of `matches-r7` → `403`; `GET /r/matches-r7/secret`, read through → `404`, judged per revision as any read; the branch's preview index lists `derby` only (§F.8 Access, §7.9 Where, §C.2 item 5, §A.4)
5. li's grant in `Authorization` at another `view`'s URL → `403`. A filtered URL with neither a grant nor a verified cookie → `401` (§7.9 URLs)
6. li holding only the `/ns/matches/view/{view}` cookie → `GET /ns/matches/rev/{ns_id}/heads` → `401`. `GET /ns/matches/view/{view}/heads` → `302`, `private, no-store`, to the current `at`. `…/view/{view}/log?since=…` without `live` → `302` to the range at the current `at`, whose pages she reads until one without `X-Log-Next`, each carrying that `at` as `X-Namespace-Revision` (§7.9 URLs, Log ranges, §C.5.3)
7. li → `/ns/matches/view/all/heads`, or a `view` or `ns_id` that isn't an id in text form → `400` (`bad_input`), a request-shape error, before any `401` or `403` (§7.9 URLs, §6.2)
8. A reader with unrestricted `read` on `matches` → `GET /ns/matches/rev/{ns_id}/heads` and `…/log` → `200`, unfiltered, at those URLs; at a filtered URL with the grant in `Authorization` → `403`; with a `/ns/matches` cookie → served as that `view`'s cookie would be (§7.9 Partial reader)
9. li presents a `/ns/matches/view/{view}` cookie for a `view` the origin keeps nothing for (never exchanged, or swept) → `401` (§7.9 `view`, §12.1 `unauthenticated`)
10. Two partial readers whose rules differ only in a block rule limiting one to `^pub-`, or only in the value at a `/principal` path a role rule compares (`/principal/attrs/team`) → different `view`s, so they share no cached page. Two with the same rules and values, whose grants the same key verified → one `view` and its cache entries (§7.9 `view`, Cost)
11. li and bo have the same rules; li's grant is verified by key `access-02`, bo's by `access-01` → different `view`s (`key:`). `access-02`'s `pub` then changes → li's cookie, at any URL → `403`, and her exchange under the old grant → `401` (§7.9 `view`, §C.4)
12. A key-scope rule `{ "op": "compare", "path": "/principal/attrs/tier", "in": { "value": ["gold"] } }`; a grant under that key with `attrs.tier` `"silver"` and namespace-wide `read`, so unrestricted `read` by §2.1, though every read it makes fails → its `view` is the one §7.9 computes, with its rules' `scope:` string, since §C.5.2 wouldn't give it `/ns/matches`. The index drops nothing from it by reading the grant as unrestricted, so it never shares the `key:`-only `view`, whose URL admits only readers who read all: it is never served the gold readers' kept hits, and its own are filtered to none. `GET /ns/matches/log` with it → `403` (§7.9 `view`, §C.5.2, §C.2 item 5, §A.4 Private namespaces)
13. `matches` removes the role li's `view` stored as effective, drops `read` from that role's `can`, or changes the key her `key:` string names, after her exchange → her cookie → `403` at every URL, ranges at `at`s from before the change included, until she exchanges again; so is every other cookie of her `view`, bo's included, whoever exchanged (§7.9 `view`)
14. `matches` changes the `groups` scope of the key behind li's grant, then changes it back in a later config entry → li, on her cookie, at the later `at` → `403` until she exchanges again. Both changes in one batch → her cookie holds (§7.9 `view`)
15. li's `/ns/matches/view/{view}/events` is open, and `matches` removes the key her `view` digests → the stream ends at its next read check, judged at the current entry (§7.9 `view`, Events, §7.3)
16. li, or a partial reader whose only read role tests `/resource` by pattern and who fixes no `/resource` → `POST /edge-grants` → `200` with only `/ns/matches/view/{view}`, never `/r/matches` or `/ns/matches`. The same grant with a block rule on `/now` → `403`, since that rule fails for a read (§7.9 Partial reader, Edge grants, §C.5.2 Scope, §C.2 item 5)
17. `matches` purged; li → `GET /ns/matches/rev/{ns_id}/heads` with her grant → `410` at once, no `302`. Her grant in `Authorization` at another `view`'s `/ns/matches/view/{view}/heads` → `403`, not `410`, since the URL's read check, its `view` included, comes first (§7.9 Purged namespaces, URLs, §8.5)
18. `derby`, visible to li, is deleted → her filtered log shows its `tombstone`. bo, whose rule tests `/doc/team` = `"b"` and who never saw `derby` → the tombstone is dropped, as is every `derby` entry (§7.9 Log entries)
19. `derby`'s `v3` sets `team` to `"b"` → li's filtered log shows `{ "id", "prev", "kind": "hidden", "resource": "derby" }` at `v3`'s `ns_id`, and her `/heads` at later `at`s leave `derby` out; ranges at earlier `at`s still show `v2`, unchanged. `v4` (still `"b"`) → dropped, not a second `hidden`: `v3`'s stand-in isn't a shown revision. `v5` back to `"a"` → shown, and li fetches `v5`'s document instead of folding (§7.9 Log entries, Log ranges, §C.2 item 5)
20. li's `/ns/matches/view/{view}/events` is open, and `derby` moves to `team: "b"` → a `hidden` event, then none of `derby`'s later entries until a revision is visible again (§7.9 Events, Log entries)
21. Documents that leave a view inside a batch: `x`'s `v1` is visible and shown; one batch writes `v2` and `v3`, both hidden, and its entry names only `v3` → shown as a `hidden` item, so li never keeps `v1` as current. The same batch ending in a delete → its tombstone is shown as `hidden` too. `y` created hidden and never shown; a batch writes `v2` (visible) then `v3` (hidden) → dropped, never a `hidden` entry for a resource li never had (§7.9 Log entries, §3.5)
22. `derby` (`team: "a"`) is deleted, then restored with `team: "b"` → li's log shows the tombstone, judged by the document it deleted, and the restore as `hidden`; neither is judged again by a later revision (§7.9 Log entries, §6.4.1 `read`)
23. One batch writes visible `derby` and hidden `secret`, each with a gesture, and its local `source.ids` name both → li's filtered log → its `entries`, `gestures` and `source.ids` name only `derby`. Where `secret`'s previous entry was shown, so that it appears as a `hidden` item, `gestures` and `source.ids` still leave it out (§7.9 Log entries)
24. A batch with a `config` change that writes only `secret`, never shown to li → her filtered log → a `batch` holding only its config entry. Without the `config` change → dropped. `config` and `purge-ns` entries are always shown (§7.9 Log entries)
25. `secret` purged → li's filtered log shows the `purge`, as her only rule refers to `/doc` (the accepted leak of purged names). A reader whose only rule is `{ "all": [ { "op": "test", "path": "/resource", "schema": { "pattern": "^a-" } }, { "op": "test", "path": "/doc/state", "value": "pub" } ] }` → the purge of `b-x` isn't shown, and that of `a-y` is: `all`s are flattened before rules on `/doc` are set aside (§7.9 Log entries, Accepted leaks)
26. A retention prune (§8.6) of live `secret` → li's filtered log → the `prune` entry isn't shown, since its `target`'s document is hidden, so prunes never name hidden live resources. A prune of `derby` → shown (§7.9 Log entries, §8.6 Kept)
27. A `view` first judged after `derby` was pruned at `H` → filtered ranges over `head` entries below `H` whose documents aren't kept → `doc` is `null`, so li's `/doc` rule fails and they aren't shown, never judged against `{}` or with the rule skipped (§6.4.1 `read`, §8.6)
28. li → `GET /r/matches/secret` → `404`, as any read-rule failure. `derby` has moved to `team: "b"` at `v3` → `GET /r/matches/derby` → `404`, and `GET /r/matches/derby/rev/{v2}` → `200`: each revision judged by its own document (§C.2 item 5, §6.4.1 `read`)
29. `x`'s `v1` is hidden (`team: "b"`, with `/salary`); `v2`'s patches are `[{ test /salary 91000 }, { remove /salary }, { replace /team "a" }]` → li → `GET /r/matches/x/rev/{v2}/log?since={v1}` → `v2` shown without `patches`, and li fetches its document. On a server without §7.9 → `404`: a range passes only where each entry's parent does too, so `test` values and removed paths of a hidden parent never show (§7.9 Log entries, §C.2 item 5)
30. `x`'s `v2` (`team: "b"`) attaches a confidential PDF, blob `P`, and `v3` (`team: "a"`) drops the reference → li, knowing `P`'s id → `GET /r/matches/x/blob/{P}` → `404`, since the only stored document referencing `P` is hidden; a `Blob-From` copy of it into a resource li writes → `404`. The reverse: `x`'s head hidden, `v1` visible and referencing blob `Q` → `GET …/blob/{Q}` → `200` (§6.4.1 `read`, §7.8 Reading, Copying)
31. Gesture `G` wrote `derby`'s `v2` (visible), `derby`'s `v3` (hidden) and `secret` → li → `GET /ns/matches/gestures/G` → only `v2`'s row. Knowing the id `X` of `secret`'s entry → `?after=secret/X` → `404`, as for an entry that doesn't exist (§7.4, §7.9 Answers, §C.2 item 5)
32. li, who also has `create` and `delete` → `PUT /r/matches/secret` with `If-None-Match: *`, or a `DELETE` of it → `403` at step 2.2, before any precondition, since she may `read` but her rules don't allow reading `secret`'s head: no `412` names it. A writer whose block rule is `not /resource = "secret"` → `403` at step 1, before that (§6.2 steps 1 and 2.2, §6.4.1 What rule failures reveal)
33. li's filtered `/heads` with rows `a` and `c` visible and `b` and `d` hidden → `next`, where present, is the last row returned, never `b` or `d`, whichever row the scan ended on (§7.9 `/heads`)
34. li's filtered `/heads` with exactly `logPageSize` visible rows after `after`, followed only by hidden rows → `next` present, and the next page empty, without `next`. With no rows at all after them → the same first page (§7.9 `/heads`)
35. A batch writes one visible item and 999 hidden ones → li's filtered log range → pages cut as if the batch had one item (§7.9 Log ranges)
36. Twenty writes to hidden documents during one interval → li's long-poll → no `200`; `204`, at once after a bounded scan or at the interval's end, with `X-Namespace-Revision` naming the newest entry scanned. Her next poll with that `since` is accepted (§7.9 Long-poll, §7.7)
37. Read rules test `/doc/folder`, and `matches` guards it as §6.4.4's example does → a writer who isn't a `librarian`, may append to `x` in `/team-b` but has no `read` (so step 2.2 doesn't refuse it) and knows its head → `replace /folder "/team-a/x"` → `403`, so it can't move `x` into its own view or another's. Without the guard, with only a write rule that `/doc/folder` match `^/team-a` → the write passes and `x` is readable to the writer: why §6.4.4 says to guard (§6.4.4 Guarding, §6.4.1)
38. Read rules test `/doc/team`, and `matches` requires nonces → li sees a `hidden` entry's id after `derby`'s `replace /team "b"` → she can't confirm that guess by recomputing the id, as the patch set carries a fresh `$nonce`. Without nonces, she can (§6.4.4 Guarding, §C.7, §3.3)
39. Release `release-7`; readers' rules test `/doc/published`. An editor of `matches-r7` sets `/published: true` on a new document there → the merge service's plan → that change is a conflict at step 2, so nothing is published before step 3 and its approval (§F.9 Merging)
40. Index over `matches` → a reader with unrestricted `read`, and li → both served at `…/view/{view}/at/{ns_id}`, `at` an `ns_id` of `matches` alone; li's hits leave out `secret`, judged on its head as of `at` (§A.4 Private namespaces, §7.9 Checkpoint)
41. `derby` moves to `team: "b"` → li → an index query on `matches` → a redirect to a new `at`, whose hits, facets and `counts` leave out `derby` (§A.4 Private namespaces)
42. Index over `matches`; li → `q=transfer` → the scores of her hits don't change when `secret` gains the word. `fields=/salary`, `facet[/salary]=x`, `counts=/salary` or `sort=/salary`, where `/salary` is marked only by the schema of hidden documents → `400`, as for a path no schema marks (§A.4 Fields in hits)
43. li, or a reader limited to `^pub-`; hidden hits fall between visible ones → `/_refs` or a query with `limit=10` → every page but the last holds exactly 10 hits, counted after filtering, so no page shows a count of hidden hits (§A.4)
44. The index computes a hit page for li's `view` showing `derby`, and `derby`'s purge is applied before it answers or stores the page → that page is neither served nor kept: the request is recomputed or redirected, and no edge copy of it outlives the purge (§A.1, §A.4 Bounded redirects)
45. li holds an index cookie for `matches`, or a `/_refs` cookie whose markers include her `view` there. `matches` removes the key that verified her grant, changes any member of it (its `groups` scope, its `pub`), or adds `not /resource = "x"` to the role she reads through → a query under that cookie → `403` until she exchanges again, never hits judged by the old key or rules (§A.4 Private namespaces, `/_refs`, §7.9 `view`)
46. An index whose checkpoint of `matches` is behind a change to the key that verified li's grant, or to a role her `view` draws on → li's exchange → `503` (`behind`, `Retry-After`), no cookie (§A.4 Private namespaces, §12.1)
47. The index has read `matches`'s change to the key behind li's index cookie, and `matches` is then purged → li → a query under that cookie → `403`, not `410`. A cookie that still passes → `410` (`purged`), the read check judged against the last namespace document the index read (§A.4 Unavailable namespaces, Private namespaces)
48. Readers A and B of private `docs` with namespace-wide `read` through key `k1`, under different read roles, so one `view`, exchange at the index in the same second → their cookies differ in `exp`, so each can be told apart. A's role changes → A's cookie is `403`, and B's: a change to a role that lists `read` voids every cookie of the view, whoever exchanged. Where every `exp` A's new exchange could get is that of a `403` cookie → `503` (`behind`, `Retry-After`), no cookie (§A.4 Private namespaces, §C.5.2 Answer, §12.1)
49. File tree `docs`; li's read rule is §H.7's for `/team-a` → the index's listing of `/` shows folder `team-a`, its document `{ "folder": "/", "name": "team-a" }` included by the rule's second branch, and nothing of `/team-b`; listing `/team-a` shows its files. `PROPFIND /team-b/` → as for a folder that doesn't exist (§H.7 Folders as access, §H.3, §H.2)
50. li → a new file in `/team-b`, a folder she can't see → `409`, as for a missing folder (§H.4 New files)
51. li deletes `/team-a/old`, whose only other children are hidden from her → succeeds: hidden children don't stop it and aren't named, and fall out of the tree. With a visible child → `409`, naming only visible children (§H.5 Delete a folder)
52. li moves folder `/team-a/x`, under which some documents are hidden from her → one batch rewrites the folder document and the `folder` of the visible documents only; the hidden ones keep their `folder`, fall out of the tree, and are never moved into another view (§H.5 Rename or move a folder)
53. Gateway `COPY` of folder `F` to `F/sub/copy` → `403`, nothing written (§H.5 Copy)
54. Gateway that isn't case-sensitive; folder `Reports` exists → `PUT /reports` carrying a tag → `409`, naming `Reports`, since the sibling isn't a file. A `PUT /notes.txt` onto file `Notes.txt`, which the user read under `notes.txt` → written to `Notes.txt` (§H.2 Siblings)
55. A sealed or end-to-end file tree; a grant whose read rules test `/doc/folder` → reads nothing there, listings included, since `doc` is `null` and the rule fails (§H.7 Folders as access, §6.4.1 `read`)
56. Index over `matches`, whose gold readers have unrestricted `read` through key `k1` and a read role on `/principal/attrs/tier`; the silver grant of scenario 12, whose reads all fail → a query by a gold reader fills the index's kept results at the key-only `…/view/{view}/at/{ns_id}` → silver's grant or cookie there → `403`, and her own `view`, redirected to by her grant, serves none of those results. An index that gave her the key-only `view` because her grant is unrestricted by §2.1 would serve her the gold readers' hits (§A.4 Private namespaces, §7.9 `view`, §E.2.6)
57. Team-`a` writers have `append` across `matches`, and both their read and write rules test `/doc/folder` against `^/team-a`, guarded as §6.4.4 advises. One learnt `x`'s head, in `/team-b` → `PATCH /r/matches/x` with `If-Match` on it and `[{ "op": "test", "path": "/salary", "value": 91000 }]` → `403`, a right guess or a wrong, never `422`. Likewise a `copy` of `/salary` into a schema-constrained field (no `{ pointer, message }`), a `DELETE` and a create of `x`, and a batch dry run (§7.5), whose items report as failing authorisation. Its own `/team-a` documents → written as usual. A writer with `append` and no `read` isn't refused there: a `test` or a schema error still tells it of any document it may write (§6.2 step 2.2, §6.4.1 What rule failures reveal, §6.4.4 Guarding)
58. `x`'s `v1` is visible to li. One batch writes `v2` (`team: "b"`, with `/salary`) and then `v3` (`team: "a"`, the new head, whose patches `test` and `remove` `/salary`) → li → `/r/matches/x/events`, `…/log?since={v1}` and a long-poll of `x`'s log → `v2` as `hidden` (event type `hidden`, `{ "id", "parent", "kind": "hidden" }`) and `v3` as `revision` without `patches`, never `v3` with them; the page passes the head check all the same. `x`'s `prune` and `purge` events are shown as the namespace log shows them (§7.9 Log entries, §7.3, §12.7, §C.2 item 5)
59. `derby`'s `v1` (`team: "a"`) is followed by `v2` (`team: "b"`, the head); li's view has judged `v1` visible, and a CDN holds her page with `v1`. `matches` prunes `derby` at `H` = `v2`, and `v1`'s document isn't kept → her log, fetched afresh, shows `v2` as `hidden`, so she never keeps `v1`: her view's answer for `v1` stands, not judged again with `doc` `null`. A `prune` entry shown before a later prune moved the horizon stays shown (§7.9 Cost, Log entries, §8.6, §10)
60. `derby`'s `v1` is shown to li; `v2` is hidden → `hidden`; `v3` is hidden in a later entry and `v4` hidden in a batch item → neither is shown, never a second `hidden`, whatever the number of hidden revisions that follow, until a visible one. A later `purge` of `derby` is shown by her `/resource` rules, as `purge`, not as a stand-in (§7.9 Log entries, Accepted leaks)
61. Role `staff`, which lists `read` and has the rule `{ "op": "compare", "path": "/principal/attrs/tier", "in": { "value": ["gold", "silver"] } }`; li (`silver`) and bo (`gold`) hold `/ns/matches/view/{view}` cookies of the key-only `view`, which digests no rule → `staff` is narrowed to `gold` only → both cookies `403` at every URL, li's included though no rule her `view` digests changed, and bo's whoever's exchange made it; undone in a later entry → still `403`. A role that doesn't list `read` changed → both cookies hold (§7.9 `view`, §C.5.2, §A.4 Private namespaces)

### Encryption levels and epochs

**Invariant.** An epoch key reaches only grants whose window covers that epoch. Content sealed at one level is never later served under a weaker level or a newer key. Levels never go down, and a namespace is end-to-end from its creation or never: a namespace is raised only above dependents already raised, and a branch never reads below its base. A sealed payload binds its namespace, resource, revision or parent and epoch, and readers check that binding.

1. Config write lowering or removing `encryption.level`, or raising it to `e2e` from any level, with a new epoch or without → `422 invalid`. A namespace becomes end-to-end only at creation, or by an import into a new `e2e` one (Addendum E Levels, §G.5.1)
2. Raise to `sealed` while `schemaReads` is set → `422` unless the same write removes it. In an `e2e` namespace, its creation or a config write setting `drafts`, `"nonce": "required"` or a `retention` rule with `"archive": false` → `422` (Levels, §6.1, §7.4, §8.6, §C.7)
3. Raise of a base above a live or frozen dependent's level → `409 in_use` with `dependents`. Public base whose public branch was raised to `sealed` first → raising the base to `sealed` → allowed (§7.4, Levels)
4. Branch of an `e2e` base `N` whose `patches` set its level to `sealed`, or a branch of a `sealed` base whose `patches` set `e2e` → creation `422`, as a branch field. A branch of `N` keeping `e2e` → `201`: a branch is `e2e` exactly when its base is (Levels, §7.4)
5. `/keys` at E2: grant `nbf` after a rotation made by a batch's config change → window starts at that batch's epoch. `nbf` before the namespace was sealed → its first epoch. No `nbf` → the current epoch only (§E.2.3 Which epochs)
6. E3 branch → `/keys` → relays the base keyrings' entries for base epochs up to `at`, each starting at the epoch that base had in force at the latest `nbf` (or at `at` if earlier), never by `epochs` (§E.2.3 At E3)
7. Writer grant first recorded in epoch 3, reader window starting at 6 → reader verifies a signature → reported unverifiable, never an error about the content (§E.2.3, §C.3.1)
8. Grant recorded only by a branch's base → branch serves `/grants/{gid}` → sealed under the branch's current epoch (§E.2.2 table, §C.3.1)
9. Public sealed namespace, grant failing the `ns` check or unusable → `POST /ns/{ns}/keys` → `403` or `401`, never ignored like a public read (§7)
10. E3 `keyring` entry wrapped by the server or an untrusted admin, or two entries for one `kid` and `to` → client fetches keys → seals only under a key whose `from` it trusts. The duplicate write → `422` (§E.3.2 Keys)
11. Root block `enc` with a member besides `kty`, `crv` and `x` (e.g. a private `d`), or a narrowing block carrying `enc` → any request, `POST /keys` included → `401` (§C.1, §E.2.3 Wrapping)
12. E3 write whose `sealed` op's `kid` isn't the epoch in force, whose header carries `zip`, or whose `pl` names another namespace, resource or parent → `422 invalid`. The op is sealed under `K_r` (§E.3.1, §E.2.2 Compression)
13. E3 prune in a branch whose chain's newest `sealed` op is a base's → `snapshot` with the base's `kid` → `422`. It must carry the branch's own epoch (§E.3.1)
14. `e2e` bundle → import with a plaintext `rev` line, an unsealed or nonced blob line, or into an existing target whose epoch is below the bundle's lowest or above a line it lacks → refused at step 1, before anything is written (§G.5.1)
15. E3 writer limited to some resources (no unrestricted `read`, no fixed names) → `/keys` → `200` with the keyring entries wrapped to its `enc`, without reading `keyring` (§E.2.3 At E3)
16. E3 branch reader → read-through ciphertext of another revision of the same resource and epoch, served under `/r/{branch}/{name}/rev/{id}` → rejected: `pl` is compared in full, and only a base's `ns` is accepted (§E.2.2)
17. Existing `e2e` target `matches` with its own keyring entry for `matches#5`, and a bundle from another deployment carrying a different `matches#5` → import → refused at step 1 (§G.5.1)
18. `e2e` branch → full-history export → the exporter writes no read-through line but the `keyring`'s, exported whole under the branch's `ns`: for the rest it names the foreign parent in `requires`, or refuses that document. A bundle that carries other such lines anyway (bound to the base's `pl.ns`) → same-named target → refused at step 1 (§G.5.1, §G.4.1)
19. Key-holding importer seals a source that isn't `e2e` into an `e2e` target → later pins, incremental `requires` and re-imports → handled as for a renamed import (§G.5.1, §G.4.4 Renaming)
20. Public namespace whose `/ns/{ns}/rev/{ns_id}` documents and `/heads` pages are CDN-cached → raise to `sealed` → the `ns:{ns}` purge removes them (§9, Levels)
21. Sealed namespace with `historyEpochs: 0`, rotated from epoch 3 to 6, head of `derby` last written in epoch 3; reader whose grant gets keys for epoch 6 only → search hit for `derby` → its sealed values are under epoch 3, so the reader can't open them, as it can't open `derby`'s head (§E.2.6, §E.2.3)
22. E3 branch `Z` of E3 base `N`, whose own `keyring` has since been written to add `Z`'s epochs; a reader that `N`'s keyring wraps to, whose latest `nbf` is before `at` → `POST /ns/Z/keys` → `N`'s entries for `N`'s epochs up to `at`, as before `Z`'s first keyring write (§E.2.3 At E3, §F.8.1)
23. E3 branch `Z` of E3 base `N`, created at `at` while `N` was at epoch 4; `N` has since rotated to 5. A reader of `Z` whose grant has no `nbf` in any block → `POST /ns/Z/keys` → only `Z`'s entries for `Z`'s current epoch, and none of `N`'s, since `N` has moved past its epoch at `at`. A reader whose latest `nbf` is before `at` gets `N#4` too (§E.2.3 At E3)
24. E3 namespace; a `read` grant without `enc` → `POST /keys` → `422 invalid`, never a raw `key` (§E.2.3 Responses)
25. E3 `keyring` write with an entry whose `kid` names another namespace or an epoch above `encryption.epoch`, whose `to` or `from` isn't a thumbprint, whose `wrapped` isn't 80 bytes, or with a member beyond the four → `422 invalid`. A branch's first `keyring` write that keeps the base's read-through entries → `422` (§E.3.2 Keys)
26. E3 rotation to revoke a reader, where the server has added a `to` entry to `keyring` → the key holder re-wraps only for the readers in its own configuration, so that `to` gets no entry for the new epoch (§E.3.2 Keys)
27. Sealed namespace at epoch 6, per-entry sealing; `derby`'s head is from epoch 3 → its hit's sealed values are under epoch 3, never 6. A hit whose epoch the service's grant gets no key for is served by name only (§E.2.6 Per-entry sealing)
28. E3 branch `Z` of `N`; `N` had `historyEpochs: 1` and epoch 6 at `at`; a reader whose latest `nbf` is in `N#3` → `POST /ns/Z/keys` → `N`'s entries for epochs 5 and 6 only (§E.2.3 At E3)
29. Bundle import where the importer can't read the protection of the target or of its `{ns}-upstream` → refused at step 1, override or not (§G.5.1)
30. Sealed bundle with a blank line, a non-canonical envelope, `last` beside `pl` in a line header, or an extra `pl` member → rejected whole (§G.5.1.1)
31. Public sealed namespace, valid grant without `read` → `POST /keys` → `403`, not `404` or ignored (§E.2.3, §C.2, §7)
32. Authentication disabled, sealed namespace → `POST /keys` → the current epoch's key only (§E.2.3 Which epochs)
33. E3 reader folds a revision whose patch set doesn't open, or whose `pl` or `kid` doesn't match → flagged, and the fold continues as if it were `[]` (§E.3.2 Validation)
34. E3 write whose `sealed` op's protected header isn't canonical, or carries a member besides `alg`, `enc`, `kid` and `pl` (such as `zip`, `crit` or `cty`) → `422 invalid`, so each sealing has one serialisation, as §E.2.2 requires (§E.3.1, §E.2.2)
35. Sealed `matches`; the index opened `derby`'s revision in epoch 3; `derby` then gets a head in epoch 4, which the service's grant gets no key for → a query at a new `at` → `derby` left out, since the service never opened that revision, never shown with values from its epoch-3 revision (§E.2.6 Per-entry sealing)
36. Sealed `matches`, whole-response candidate: every reader its URL admits has unrestricted `read`, and every hit's values derive from revisions served under epoch 6 → the response may be sealed whole under epoch 6's `K_n`. One hit whose values derive from a revision in epoch 3 → per-entry sealing instead (§E.2.6 Whole-response sealing)
37. Sealed source with `read: "public"`, and a blob whose referencing revisions have no epoch yet → a `Blob-From` copy by a caller holding the current epoch's key, then a rotation, then `GET …/blob/{bid}` → the redirect is to the epoch the copy's check fixed, never the newer one (§E.2.2, §2.1)
38. Sealed namespace with `pad: true` and an archive configured → a prune → a per-resource sealed-bundle archive whose line plaintexts are padded to their buckets (§8.6, §E.2.2)
39. Sealed bundle whose line JWE's protected header is valid JSON but not canonical (whitespace, or members out of order) → import → rejected whole (§G.5.1.1 Checks)
40. E3 index service whose grant's `keyring` entries all come from a `from` it doesn't trust → a query of the namespace → `404`, as for keys it lacks, and no ciphertext is indexed (§E.2.6 Getting keys, §A.4)
41. Sealed namespace; blob `b` whose referencing revisions have no epoch yet. At epoch 5, `GET …/blob/{bid}` by a caller without `read` (`404`), or a `Blob-From` copy refused after its check judged epoch 5 (`404`, or a later check such as `422`) → rotation to 6 → a reader's `GET …/blob/{bid}` → the redirect is to epoch 6: a refused request fixes no epoch (§E.2.2 Epochs, §2.1)
42. E3 `matches`; the index first seals `derby`'s hit values while `matches` is at epoch 5, under the epoch a prune's `snapshot` of that revision would carry, and `matches` then rotates to 6 → a later query at a new `at` → the values still carry `kid` epoch 5, never 6 (§E.2.6 Per-entry sealing, §E.3.1)
43. Sealed namespace; a grant that fixes `/resource` to `derby` → `POST /ns/{ns}/keys` → `200` with only `derby`'s `K_r`s, never `K_e` or `K_n`. With them it opens `derby`'s revisions, but no namespace document, namespace log range, namespace event or grant (§E.2.1 Namespace key, §E.2.3)
44. Sealed namespace; a reader with unrestricted `read` → `/keys` → `K_e` only, never a `K_n` entry. It derives `K_n`, and opens `/ns/{ns}/rev/{ns_id}` and `/grants/{gid}` with it; none of them opens under `K_e` itself, which seals nothing (§E.2.1, §E.2.2)
45. Sealed namespace whose current epoch's `K_n` nears 2³² sealings (evicted ranges re-sealed, long-poll answers, events), not yet rotated → a request that would need a sealing past the bound → `503` (`behind`) with `Retry-After`, never that sealing. The origin's count reserves what may still be sealed under the epoch after it ends, such as its namespace documents and grants first sealed later (§E.2.1 Message bound, §12.1)
46. Search service; sealed namespace rotated past epoch 3, `derby`'s head from epoch 3 → many distinct queries hitting `derby` → each view's JWEs open only under that view's key, `HKDF-SHA256(ikm = epoch 3's K_r, salt = "patchlog-view", info = pl.view)`, never under `K_r` itself, so the views count toward no epoch key's message bound (§E.2.6 View keys, §E.2.1)
47. E3 `matches`, `derby` never pruned; a reader → `GET /r/matches/derby` → `302` to `…/rev/{head}`, which is `404` (`not_offered`) without `horizon`, so the reader folds the log from genesis. The server never serves a fold or plaintext. A caller failing the read check → that check's answer, never `not_offered` (§7.1 End-to-end namespaces, §7)
48. E3 `derby` pruned at `H` → `GET …/rev/{H}` → `200` with the stored snapshot's JWE, `application/jose`, `ETag: "{H}"`; with `If-None-Match: "{H}"` → `304`. `GET …/rev/{head}` → `404` (`not_offered`) with `horizon: H` (§7.1, §8.6)
49. E3 prune whose horizon `H` is a tombstone, with a `snapshot` whose `pl.id` is `H` → `422 invalid`. With `pl.id` its parent `P` → accepted; then `GET …/rev/{P}` → `200` with the snapshot, and a later live id → `404` (`not_offered`) with `horizon: H` and `last: P`; `GET …/rev/{H}` → `410` with `{ "tombstone": H, "last": P }`, from which a pruning client learns `P` (§E.3.1 Snapshots, §7.1)
50. E3 namespace → `GET /r/{ns}/keyring/rev/{id}` → `200` with the plaintext document, as outside E3 (§7.1, §E.3.2)
51. Private, unencrypted namespace → prune with a `snapshot`, under a `*` key or not → `422 invalid` (§8.6 Archive)
52. Bundle with `"authors": false` (or none), no grant line, and a history line carrying `author`, `via` or `grant` → import → rejected whole at step 1, before anything is written; the attribution is neither ignored nor kept (§G.4.1, §G.4.4 step 1)
53. Sealed namespace; a namespace event's JWE (`pl: { ns, event: id }`) served as a one-entry log range, or a range's JWE served as an event → the reader rejects it: `pl` is compared in full, and no range carries `event` (§E.2.2)
54. E3 namespace; a reader configured to expect `e2e`, or that has learnt `e2e` before, and a server whose namespace document or `/keys` now claims a lower level → `GET …/rev/{id}` of a resource other than `keyring`, answered with a plaintext `200` → refused, since a client keeps the highest level it has learnt (§7.1 End-to-end namespaces, Levels)
55. E3 `derby` pruned at tombstone `T` with parent `P`, then again at a later live `H2` → `GET …/rev/{P}` → `410` (`pruned`, `horizon: H2`), never the old snapshot; `GET …/rev/{T}` → still `410` with `tombstone` and `last: P`. After the first prune alone, whatever is restored from an archive → `/rev/{P}` still `200` (§7.1, §8.6)
56. Sealed branch `matches-r7` with a preview index; `derby` read through from the base → its hit → sealed under the branch's `K_r` and epoch, never the base's, so a base reader without `read` on the branch can't open it (§E.2.6 Per-entry sealing, §E.2.5)
57. Sealed `matches`; the index hasn't yet judged the epoch of `derby`'s head revision → a query → `derby` by name only, and values derived from that revision left out of other entries, never sealed under the current epoch, in a `no-store` response the service doesn't store; or, while it may yet judge it, `503` (`behind`). Once judged, a query at the same `at` carries `derby`'s sealed values (§E.2.6 Per-entry sealing, Stored once, §A.5)
58. Sealed namespace (E2); a grant fixing no `/resource`, whose only role listing `read` has a `/now` rule → `POST /ns/{ns}/keys` → `403`, never `K_e`: such a role gives no unrestricted `read` (§2.1 Unrestricted read, §E.2.3, §C.2 item 5)
59. A deployment keeps data from an earlier draft under which `N` was raised to `e2e` after content was stored in the clear or E2-sealed → that content → refused or discarded, never served from `N` or from a branch reading it through, since that would give it less protection than this draft gives `N`'s content (Reading this spec, Levels)
60. Sealed or end-to-end namespace, `derby` tombstoned at `T` → `GET /r/{ns}/derby/raw` or `…/rev/{T}/raw` by a reader → `404` (`not_offered`), never the `410` with `last` the document URL gives. `derby` purged, or the namespace purged → `410` (`purged` for the namespace), before `not_offered`. A caller failing the read check → that check's answer (§7.1, §8.3, §8.5)
61. A client that has learnt `sealed` for `N` → `N`'s current namespace document, wherever the client reads it, now claims `at-rest`, or a level that isn't one of the four → refused, and the client still holds `sealed` for `N`. `N`'s document read by id at an `ns_id` before its raise → teaches nothing and isn't refused. A reader of sealed branch `Z` of `N` needn't read `N`'s document at all: `Z` seals all it serves under its own keys (§7.1 End-to-end namespaces, §E.2.5, Levels)
62. Sealed (E2) branch `Z` of sealed `N` → a read-through revision served under `Z`'s URL as a JWE whose `pl.ns` and `kid` name `N` → rejected: a base's `ns` is accepted only at E3, and at E2 a branch seals all it serves under its own keys (§E.2.2, §E.2.5, Levels)
63. E3 branch `Z` of `N`; `derby` written in `Z` after its foreign parent `F` → an entry in `Z`'s log range after `F` whose `sealed` op's `pl.ns` names `N` → flagged and folded as `[]`: a base's `ns` is accepted only up to the foreign parent (§E.2.2, §E.3.1, §E.3.2)
64. Sealed `matches`; a per-entry hit that carries `sealed` and also a cleartext facet value → the reader shows the decrypted value, or the hit by name only, never the cleartext one (§E.2.6 What gets sealed, Per-entry sealing)
65. Authentication disabled, sealed namespace; the origin rotates by itself (§E.2.1) → its config entry carries neither `grant` nor `via`, not `"grant": null`, so it counts for no one, in `merge.authors` checks or the janitor's `*`-key checks (§7.4, §1 Conformance)
66. Client configured with a level for `N` that isn't one of the four → `GET /r/N/derby/rev/{id}` answered with a plaintext `200` → refused, as the configured level counts as `e2e`. A later document claiming `sealed` → refused (§7.1 End-to-end namespaces)
67. E3 branch `Z` of `N`. A reader can read neither `N`'s `/heads` nor any `/heads` of `Z` that places `derby`'s foreign parent. A `sealed` op in `Z`'s `derby` log whose `pl.ns` names `N` → the op fails the `pl` check: flagged and folded as `[]`, never opened unchecked (§E.2.2 `pl`, §E.3.2)
68. E3 branch `Z` of `N` → a delivery-sealed JWE served under `Z` whose `pl.ns` or `kid` names `N` (a `/rev` document, a log entry, an event, a namespace range or a sealed blob header) → rejected. A base's `ns` is accepted only in a `sealed` op read through (Levels, §E.2.2, §E.3.1)
69. Branch `Z` with an archive configured → `POST /r/Z/derby/prune` passing its checks → `200` with the current horizon. Nothing is written: no archive, no `prune` entry, no horizon moved (§8.6 Branches don't prune and Archive)
70. Frozen sealed namespace whose current `K_n` nears the bound (events, long-poll, evicted ranges) → the origin rotates by itself → the config entry is written with no `grant` or `via`, draws no token, and is not `409 frozen`. Resource writes stay `409 frozen` (§E.2.1, §8.4, §6.6 Exempt, §7.4)
71. A client that holds `sealed` for `N` from its configuration and has learnt no level for branch `Z` of `N` → `GET /r/Z/derby` read through, answered with a plaintext `200`, or a `Z` document claiming `at-rest` → refused: it holds for `Z` at least what it holds for any base in `Z`'s `base` chain (§7.1 End-to-end namespaces, Levels)

### Grant scope

**Invariant.** A request is allowed only through what every block, the key's scope and at least one effective role allow together. No role, value or block a narrowing step dropped counts. "Unrestricted", "qualifying" and "fixes `/resource`" are judged so that nothing reads more than its rules permit. Members that widen exposure or touch keys move only under a `*` key, or the operator grant that creates the namespace. Unless a line says otherwise, the origin doesn't implement filtered reads (§7.9).

1. Root `roles: ["reader", "scoped"]` (`scoped` has a `/resource` rule), narrowed to `["scoped"]` → branch the namespace, or `POST /edge-grants` → `403`: only effective roles count, so there is no unrestricted `read` and no qualifying role for `/r/{ns}`. Not narrowed, both effective → branching passes the unrestricted-`read` check, judged by `reader` alone (§2.1 Unrestricted read, §C.2 item 2)
2. Roles `B` (a `/now` office-hours rule, no `/resource` rule) and `A` (`not /resource = "secret"`), in hours or out → `GET /ns/{ns}/log` → `403`. `B`'s rule fails for any read, so `B` never counts for `read`, and `A`'s `/resource` rule keeps it from counting where unrestricted `read` is needed (§C.2 item 5, §2.1 Unrestricted read)
3. Roles `A` (office hours) and `B` (no rules), both listing `append`, at night → append → passes, since roles are alternatives at step 1 too (§C.2 items 2 and 4)
4. Grant whose read role has a `/doc` rule → `POST /ns/{base}/branches` → `403`, since a role that counts for `read` passes all its rules against a `read` envelope (§C.2 Unrestricted `read`)
5. Batch item `steps: ["delete", [p1], [p2]]` under a grant with `delete` and `restore`, no `append` → `p2` is an append → `403` (§C.2 Later steps)
6. Key with `readScope: "resource"` signs a roles-only grant (`roles: ["reader"]`, no `can`, no `/resource` rule) → `GET /r/matches/x` → `404`. `GET /ns/matches/log` → `403`. Any write → `403` (§2.1 Fixes `/resource`, §C.2 item 1)
7. `POST /edge-grants`: a grant fixing `{a, b}` with a block rule `not /resource = "b"` → `403` for the whole request, since the rules run per fixed name. A block rule `/action = "read"` → issued, against a `read` envelope (§C.5.2 refusals)
8. `POST /edge-grants`, roles `reader` (no rules) and `desk` (a `/now` rule) → `200`: `desk`'s rule fails for a read, so `desk` isn't a qualifying role, and `reader` is (§2.1 Qualifying role, §C.2 item 5, §C.5.2)
9. `/read-grants` grant fixed to `derby`, carrying a role whose rule tests `/resource` → `POST /edge-grants` → `200`, since a qualifying role may test a fixed `/resource` (§2.1 Qualifying role)
10. Root block with neither `can` nor `roles`, a block whose `can` lists `*`, or a narrowing block with `ns: ["*"]` → any request → `401`. A narrowing block listing `can: ["read", "delete"]` under a root `can: ["read"]` → a read → `200`, restricting nothing more (§C.1)
11. Config write adding a key with a duplicate `kid`, `alg: "ES256"`, or a `pub` that isn't 43 base64url characters → `422 invalid`. A stored key without `can` → its grants allow no verb (§C.4 Keys)
12. Key with `maxTtl: "PT15M"`, root `exp` a year ahead, and a narrowing block with `exp` 10 minutes ahead → any request → `403`, since `maxTtl` uses the root block. Edge cookies last until the earliest `exp` among the blocks (§C.4, §C.5.2)
13. Key scope `sub: "user:"`, root `sub: "svc:x-user:y"` → `403`: the whole `sub` must match (§C.4)
14. Grant with one block rule `{ "all": [ …500 rules ] }` → any request that doesn't ignore it (§7) → `413` (`rulesPerGrant`) before step 1, or before a read's `ns` check, since nested forms count (§12.2, §C.8)
15. Key whose `can` lacks `delete`, grant role `desk` listing `delete` → delete → `403`, since the key's `can` bounds role verbs (§C.2 item 2)
16. Config write overlapping `/keys` that also fails a namespace rule, under a non-`*` grant → `403 forbidden`: the guard runs first at step 6. A namespace's creation under the operator grant whose genesis covers `/keys` → passes the guard (§6.2 step 6, §C.2 `*` keys)
17. `prune` grant without a `*` key → prune below what `retention` keeps (everything, where no rule matches), or where no archive is configured → `403` at the step-6 guard (§8.6, §C.2)
18. Operator grant, or an expired namespace grant, sent to `DELETE /edge-grants` or `GET /` → ignored: `204`, `200` (§C.4 Operator grants, §C.5.4)
19. Key removed from a base, or a block revoked in a base → a request to its branch, or a consumer of the branch verifying a presented grant → `401` at once (§C.4 Keys follow the base, §10)
20. Purged resource, a caller without `read` on it → `GET /r/{ns}/{name}` → `404`, not `410`. A write → the step-1 answer first (§8.3 Responses)
21. Retry of a recorded write under the same root `sub`, but a grant from a rotated `kid` → `412`, not `200` (§7.2)
22. Key with `readScope: "resource"`, grant block rule `{ "not": { "all": [ /resource = "derby" ] } }` → `GET /ns/{ns}/log` → `403`, since a negated `all` doesn't fix `/resource` (§2.1)
23. Key `can: ["read"]`, root block `can: ["read", "append"]` → `GET` → `403`, since the root block fails the key's scope (§C.4)
24. Key scope `attrs` whose schema has `$ref: "/r/schemas/…/rev/…"` or an unknown keyword → config write → `422 invalid`, held to a rule `schema`'s limits (§C.4, §6.4.2)
25. A batch whose `config` change revokes a block, or removes a key → the next write under that grant → `401` (invariant 6)
26. Operator creates a namespace whose genesis `rules` require `/principal/groups` to contain `ops` → creation → rules skipped, as for a `*` key (§6.4.3)
27. Audit consumer verifying the grant references of history after a key rotation or revocation → judged at the time of writing, never by today's `revoked` (§C.3.1, §10)
28. Writer in `docs` whose document pins `/r/schemas/…`, with a grant that names `schemas` but isn't signed by a `schemas` key → write → `422 schema_unavailable`, judged as for reading other namespaces (§6.1 Read permission, §7.5)
29. Grant with `can: ["append"]`, no roles and no rules, in a private namespace → `GET /ns/{ns}/grants/{gid}`, `GET /ns/{ns}/branches`, or the namespace log → `403`: unrestricted `read` needs the `read` verb (§2.1, §C.5)
30. Private `schemas` with `schemaReads: { "for": ["docs"] }`, and private `docs` whose document `d` pins `/r/schemas/match/rev/X`. A grant naming `docs` and `schemas`, signed by a `docs` key, that may read `d` → `GET /r/schemas/match/rev/X` with it in `Authorization` → `200`, `private`, judged as a read of `d` (§6.1, §7 step 3)
31. A reader of `matches` whose grant fixes `/resource` to `derby`, who knows gesture `G` and an id `X` of hidden resource `secret` → `GET /ns/matches/gestures/G?after=secret/X` → `404`, as for an entry that doesn't exist (§7.4, §7 step 4)
32. Private branch `x`, which the writer can't read → write in `docs` whose `$schema` is `/r/x/a/rev/1…` → `422 schema_unavailable`, as for a name that doesn't exist (§6.1, §7)
33. Root block with `can: ["read", "append"]` and no `roles`, narrowing block `roles: ["reader"]` → any request → `403`. Effective roles are only those the root lists, here none, and a grant that carries roles needs one that lists the verb (§2.1 Effective roles, §C.2 item 2)
34. Branch writer with `config` but no `*` key → config write setting `abandoned: true` and `frozen: true` → janitor → not purged as abandoned, since the flag counts only if its write's grant chains to a current `*` key of the branch (§F.6 abandoned)
35. Author in a successor, not in the base's `merge.authors` and without a `*` key of the old branch → batch in the successor with `source: { ns: <old branch>, at }`, then a config write on the old branch setting `successor` and `frozen` → janitor → not purged as superseded. The rebase tool counts that batch as an earlier merge (§F.5 step 3), but the janitor doesn't (§F.6 superseded)
36. Merger whose base grant allows `append` but not `restore`, and a fast-forward item whose base head `B` is a tombstone the branch restored → merge batch → `403` at step 2.2, reported as an authorisation failure, since the settled verb `restore` isn't a candidate (§C.2 Settling, §6.2 step 2.2, §F.3 Authorisation)
37. Branch config writer without `*` key → config write setting `merged: { at }` and `frozen: true`, with no merge batch in the base, or with one by a `merge.authors` principal whose `source.at` isn't in the branch's chain → janitor → not purged as merged (§F.6 merged)
38. Private `schemas` with `schemaReads: { "for": ["docs*"] }`; a user with `branch` on public `sandbox` creates branch `docs-x` of it → write in `docs-x` pinning `/r/schemas/match/rev/X`, and an unauthenticated `GET /r/schemas/match/rev/X` → `422 schema_unavailable`, and `401` as for any private revision: a branch never matches `schemaReads.for` (§6.1, §7)
39. Private namespace behind a verifying edge; a reader with a signed-URL edge grant for `/r/{ns}/{name}` → `GET` → the edge strips the parameters and forwards. The origin authorises the read itself from the grant, passed on as its cookie, and answers `200` with edge lifetimes. A request with the verification headers but no credential gets no content (§7 Query parameters, §9 Private namespaces, §C.5.3)
40. Private `schemas` with `schemaReads: { "for": ["docs"] }`; `docs` public and sealed (E2), with `d` pinning `/r/schemas/match/rev/X`; a self-made, unsigned token with `ns: ["docs"]` → `GET /r/schemas/match/rev/X` → `401`, as for any private revision, since only a grant that verifies under `docs`'s keys and may read `d` opens it (§6.1, §7 step 3)
41. Role `reader` (`can: ["read"]`, rule `/principal/attrs/clearance ≥ 3`); grant `roles: ["reader"]`, `attrs.clearance: 1`, no `/resource` rule → `POST /edge-grants` → `403`: no qualifying role. With `clearance: 3` → `200`: fixing no name, the rule is evaluated once, without `/resource` (§2.1 Qualifying role, §C.5.2)
42. An issuer signs root block `R` twice (same claims; grant id `G`), and both tokens are used, the first one recorded first. The second leaks, and an admin adds to `revoked` the revocation id of `stored` from `GET /ns/{ns}/grants/G` → a request with the leaked token → `401`: revoking the grant id a log names refuses every token minted from it (§C.4 Revocation)
43. `e2e` namespace; role `translator` (`can: ["read", "append"]`, rule `{ "op": "test", "path": "/writes", "schema": { "items": { "pattern": "^/i18n" } } }`) → append of a `sealed` op → `403`: a rule whose outcome depends on `/writes` fails as a whole at E3, as a `writes` predicate does (§6.2 End-to-end namespaces, §E.3.2)
44. Private namespace with a live branch; a grant with `config` but no `*` key → config write setting `encryption.level` to `sealed`, or `"nonce": "required"` → `403` (`forbidden`) at the `*`-key guard, never `409 in_use` with `dependents` (§6.2 step 6, §C.2, §7.4)
45. A reader opens `GET /r/matches/derby/events` on private `matches` under a grant with `read`. Then its root block is added to `revoked`, its `exp` passes, or its only role loses `read`. Or the stream was opened without credentials while `matches` was public, and `matches` then turns `read: "grant"` → the next revision of `derby` → not sent, and the stream ends; a reconnect with `Last-Event-ID` gets the step-3 or step-4 answer (§7.3, §C.2 item 5, §C.4 Revocation)
46. Private `matches` behind a verifying edge. A browser opens `EventSource` on `/r/matches/derby/events` with an edge cookie for `/r/matches/derby` whose `exp` is `t` → the edge checks it and forwards the request with the cookie, `X-Edge-Verified` and `X-Edge-Prefix` → the origin authorises from the cookie, and the stream ends at `t` at the latest. An edge that forwards only its headers, without the cookie → no stream, since the origin has no credential (§7.3, §9 Private namespaces, §C.5.3 Forwarding)
47. A grant naming only `docs`, with a block rule whose `pattern` RE2 refuses, sent to private `secret` → `401`: every token check before the `ns` check is a stateless request-shape error, so nothing about `secret` is consulted (§C.2 item 1, §6.2)
48. A token whose narrowing block is signed over Biscuit's version 0 payload, which doesn't bind the previous signature → any request → `401` (§C.8)
49. Private `matches` behind a verifying edge. A `GET` with a valid edge cookie and an empty `Authorization` field → the edge forwards it without its verification headers, and the origin answers `401`, since the cookie counts only on a request that passes check 1 (§C.5.3)
50. An entry recorded with `grant: null` while authentication was disabled. Under `grants`, a retry of it by a grant whose root `sub` equals its `author` → `412`, not `200` (§7.2, §1 Conformance)
51. A reader on `GET /r/matches/derby/events`, past replay and waiting for live entries; the grant is revoked, then `derby` gets a revision before the next keep-alive → the revision is not sent, and the stream ends: live entries are log pages fetched, judged again first. Grant scope 45's live case (§7.3)
52. A caller with `purge` and without `read` → purge of a name that never existed, with `If-Match` → `404`, with no `head`, never `412`. Without a precondition → `428` (§6.2 step 2.5, §7.2)
53. A grant limited by a `/resource` or `/doc` rule → `GET /ns/{ns}/gestures/G` → only the revisions its grant may read, judged per revision (§7.4, §C.2 item 5)
54. Line 1's grant (`scoped` only, a `/resource` rule, no fixed name) in `matches` where §7.9 applies → `POST /edge-grants` → `200` with only `/ns/matches/view/{view}`, never `/r/matches` or `/ns/matches`; its filtered `/heads` lists only documents `scoped`'s rules allow. Branching `matches` → `403` (§C.5.2 Scope, §7.9 Edge grants, Visible, §7.6)
55. Fifty grants, each fixed to one name in `matches` (§C.5.1), where §7.9 applies → `POST /edge-grants` → `200` with their fifty `/r/matches/{name}` prefixes and no `/ns/matches/view/{view}` (§C.5.2 Scope)
56. A gateway user with two tokens under one root `sub` and key; `T1` has unrestricted `read`, `T2` is limited by a `/resource` rule, and `T1` has read the key history → `T2`'s saves → its own entries judged by the key each `kid` names now, never by `T1`'s reading, since `T2` can't read a range of the namespace log. A third token that can read the log reuses `T1`'s reading only after it has read such a range (§H.7 Users, §C.5)
57. Branch `X` marked `merged`; after its `source.at`, its log has only a batch whose sole change is `config` (an epoch rotation) → janitor → the `merged` check passes. The same batch with any item, other than the branch's `keyring` at E3 → it fails (§F.6)
58. A grant in private `matches` fixing `/resource` to `{a, b}`, with a block rule `not /resource = "b"` → `GET /_refs?to=…` at the index → served under its `view` in `matches`, which carries its rules' `scope:` string, with hits from `a` only, never `b`. The index's exchange issues the cookie, while `POST /edge-grants` at the origin refuses the same grant (Grant scope 7). Fixing only `{a}`, with `not /resource = "a"` → a query on `matches` → no hits (§A.4 Private namespaces, `/_refs`, §7.9 `view`)
59. Private `matches`; a verified grant fixed to `derby` → `GET /ns/matches/rev/{ns_id}/log` or a namespace event stream → `403`, never `404`. `GET /r/matches/other` → `404` (§7 step 4, §C.2)
60. Private `matches`; a verified grant with `read` whose block rule is `not /resource = "secret"` → `GET /r/matches/secret` → `404`, as for a name that doesn't exist, never `403`. `GET /ns/matches/events` → `403` (§7 step 4, §C.2 item 1)
61. Two readers of private `docs` have the same `/resource` pattern rules, from keys `k1` and `k2` → `GET /_refs` → different `view`s, as their `key:` strings differ. `k1` is removed → the `k1` reader's cookie → `403` until she exchanges again (§A.4, §7.9 `view`)
62. Private `{ns}`; a key whose scope rules hold only a deadline, `{ "op": "compare", "path": "/now", "lt": { "value": "2026-12-01T00:00:00Z" } }`, signs a grant with `read`, `append` and `branch`. Before the deadline → `POST /ns/{ns}/branches` → `403`, since the unrestricted-`read` check judges that rule as for a read, where it fails; `GET /ns/{ns}/log` → `403`, and `GET /r/{ns}/x` → `404`. The same grant's append before the deadline → passes, and after it → `403`, as before (§C.2 Unrestricted `read`, items 4 and 5, §7 step 4)
63. `POST /edge-grants` with two grants, one naming purged `old`, the other refused `403` in `matches` → `403`, its body without `ns` or `head`. With only purged namespaces refused, and the grant verifying in each → `410`, with `ns` and `head` naming the first refused one (§C.5.2 All or nothing)
64. A token whose authority block adds, besides `grant_block` and its own string, the narrowing block's string as a symbol, used only by the narrowing block's fact; signatures valid → any request → `401` (§C.8)
65. Private `{ns}`; a grant with `read` whose only block rule is `{ "op": "test", "path": "", "schema": { "required": ["action"] } }` → `GET /ns/{ns}/log` → `403`, `GET /r/{ns}/x` → `404`, and branching `{ns}` → `403`: a rule on the whole envelope refers to `/now`, so it fails every read and the unrestricted-`read` check (§2.1 Refers to, §C.2 Unrestricted `read`, item 5, §7 step 4)
66. Public `pub`, not sealed; a grant with a block rule on `/now` → `GET /r/pub/x` → served as to an unauthenticated request, the grant ignored. Public sealed `pubs`, the same grant → `POST /ns/pubs/keys` → `403`, since `/keys` never ignores the grant; `GET /ns/pubs/principal` → `200`, which evaluates no rule (§7 step 1, §C.2 item 5, §7.4, §E.2.3)
67. Private `{ns}`; a grant whose only role lists `read` and has a `/now` rule → `GET /ns/{ns}/gestures/G` → `403`, never `200` with nothing listed (§7.4, §C.2 items 2 and 5)
68. A grant signed by a `*` key of `matches` naming `ns: ["matches"]` → `GET /ns` → `403`; one naming `"*"` → `401`, as only operator keys sign `"*"`; an operator grant naming `"*"` with `config` → `200`, every namespace listed, branches and purged ones included (§7.4, §C.4).
69. Two readers of private `docs` with namespace-wide `read`, through keys `k1` and `k2` → `GET /_refs` → different `view`s, as their views in `docs` are their `key:` strings alone. `k1`'s `groups` scope changes → only the `k1` reader's cookie is `403`, until she exchanges again; another reader's exchange through `k1` doesn't revive it (§A.4 Private namespaces, §7.9 `view`)
70. Gateway user `DELETE` of a file while the core answers `408` to the gateway's `GET /ns/{ns}/principal`, or refuses the connection → `502`, never `403`; while it answers `429` or `503`, or nothing in time → `503` with `Retry-After`. The same for `MOVE` and `COPY`: a failed read never counts as a refusal (§H.4 Answers)
71. Operator grant naming `"*"` with `can: ["config"]` → `GET /ns`: narrowed by a block with only `via` and `exp`, or with `"rules": []` → `200`; narrowed by a block with `can: ["read"]`, or with one rule in `rules`, even one that passes → `403`; with a root block listing `roles`, with `can: ["config"]` or without → `403`, never `200` (§7.4, §C.2)
72. An operator grant naming `"*"` that its operator key's scope doesn't allow, where the deployment scopes its operator keys → `GET /ns` → `403`. The same grant expired → `401` (§7.4, §C.2 item 1)
73. A principal whose `ratePerResource` bucket for `x` holds one token appends to `x` with a stale `If-Match` → `412`, the token spent; an immediate resend → `429` (`ratePerResource`), not `412`. A step-2 `410`, `428`, `409` (`frozen`) or settled verb's `403`, and an idempotent retry's `200`, draw tokens alike (§6.2 step 1, §6.6 Cost)
74. A writer without `read` on `x` appends to `x`, whose `$schema` nests `anyOf`s, or under a narrowing block whose rule `schema` on `/doc` recurses through them, so that validation and rule `schema` tests together need more than `validationSteps` steps → `422` (`limit`, `limit: "validationSteps"`, `max`), without `measured`, never unbounded work. A namespace document setting `limits.validationSteps` → `422` (`invalid`) (§6.6 Validation work, §6.2 step 5, §12.2)
75. An operator grant → the index's exchange, `GET /_refs`, or a query on a private namespace → `401`, never a cookie or a `key:` string with an empty `pub`; a public namespace's query ignores it (§C.4 Operator grants, §C.6)
76. Gateway user `PROPFIND` of a folder while the index answers the gateway `503` (`behind`) naming `ns` → `503` with `Retry-After`, naming only the service, no `ns` and none of the index's text (§H.3, §H.4 Answers)
77. Gateway user `GET` of a file while the index answers `500` to the listing the gateway made resolving its folder → `502` naming only the index, never `200` from the rest and never `403` (§H.4 Answers, §C.6)
78. A grant whose step-1 block rule (on `/resource` only) is a schema of 30 nested levels, each applying the next twice → append → `422` (`limit`, `validationSteps`), after the rate limits, drawing tokens only from buckets keyed by its principal, never the namespace's. With the principal's bucket empty → `429`, never `422`. Where another step-1 check fails outright, such as a verb or a key-scope rule, that `401` or `403` answers and no token is drawn. In a batch the item counts as failing authorisation (§6.2 step 1, §6.6 Validation work, §7.5 Failure)
79. The same grant on a read of `/r/{ns}/x` in a private namespace → `404`. On `GET /ns/{ns}/log` → `403`. On `POST /edge-grants` → `403`. A run-out inside a `not` never passes the rule: the whole check fails (§6.6 Validation work, §C.2 item 5)
80. An index hit, or a row of a filtered `/heads` (§7.9), judged by a grant's rule whose `schema` test runs out of `validationSteps` for one revision → that item is left out, the rest listed, never the item shown and never the whole answer failed (§6.6 Validation work, §7.9, SERVICES §A.4)
81. A batch of 1,000 items, each a typed document needing 4,000,000 steps, at the default `validationSteps` → passes, since each step of each item has its own budget. One item needing 6,000,000 → `422` (`limit`) for that item (§6.6 Validation work, §7.5)
82. `POST /ns/{ns}/branches` with an unrestricted-`read` check whose role rule runs out → `403`, as for a role that can't read (§6.6 Validation work, §C.2 Unrestricted `read`)
83. An operator grant creating a namespace under a taken name → `412`, drawing no token. A namespace's own grant with `config`, sending `If-None-Match: *` to that name → `412`, drawing one token from that grant's principal bucket in that namespace (§6.6 Cost and Exempt, §7.4)
84. A schema referenced from 5,000 branches, of which the caller may read 2,000 → purge → `409 in_use`, with `referencing` holding the first `logPageSize` (1,000) by name and `"more": true`. A caller who may read none of them → `referencing: []` without `more`. A namespace purge held up by 5,000 dependents → `dependents` holds the first `logPageSize` by name, with `"more": true` (§6.1 Refusals, §8.5 item 4)
85. Branch `b` of private `docs`, behind a CDN that strips `Cache-Tag` and `Surrogate-Key`, the origin adding base tags. A reader of `b` fixed to `x` → `GET /r/b/x` → no `docs` name in any header it receives. Any response that reaches clients through a cache that doesn't strip them, an index hit served by a service included → no base tags, whoever would add them (§9 Base tags, SERVICES §A.4)
86. A deployment begins adding base tags to `b`'s responses while caches still hold some of them, immutable ones included, without them → a propagated purge of `docs/x` → purges `b`'s own `r:b/x` as before; the base's tags alone suffice only once no cache its purges reach holds a response of `b` without them, those cached before included (§9 Base tags)
87. A writer with only `append` in `matches` submits a batch whose `source` is `{ "origin": "https://evil.example", "ns": "x", "at": … }` → recorded as asserted (§7.5), but its deployment follows only origins its operator trusts, so a `purge` of `derby` in evil.example's log purges nothing here: a grant without `purge` never gets one (§G.1 Purges follow imports)
