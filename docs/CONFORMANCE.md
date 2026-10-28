# Patch Log — Conformance checklist

Status: against spec v0.74. Items restate spec requirements as checkable statements; parentheses name the passages restated (bold lead-ins of the section's bullets, or "table"). The spec's text governs: an item that says more or less than its passage, or seems to disagree, is an error here. Ids are never renumbered or reused; a dropped item keeps its id, marked "retired in v0.NN". **[vectors]** items are byte-exact, covered by Addendum I.

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

- [ ] **CONF-1** (Conformance: Addendum C) `"auth": "grants"` implements all of Addendum C. Otherwise (`"disabled"`): every request counts as a `*` key; config writes skip namespace rules, resource writes are still checked; entries record `"grant": null`, earlier grant references still served; `merge.authors` checks (§F.3, §F.6) match such an entry on its author's `sub` alone, and janitor's `*`-key checks for `abandoned`/`superseded` accept it. Under `grants`, entries with `grant: null` or no `grant` count for no one.
- [ ] **CONF-2** (Conformance: Addendum E) Without Addendum E, `encryption` in namespace documents: `422` (`invalid`); likewise a level the server lacks. A remote branch whose raise (§G.5.2) needs a missing level, and each branch whose base chain reaches it, answer `502` (`upstream`) for resources read through or written on since (remote: those its source had at `at`, not purged since, §8.3); writes to them other than purges likewise (step 2.1 of §6.2; check 2 of §7.8). A batch's local `source` takes no blobs from them.
- [ ] **CONF-3** (Conformance: Branches) A server refusing local branches answers `branch` `403` after verification (§C.2), never lists it in `/principal`'s `can`, finds no candidate in §6.1's draft lookup; remote registration (§G.3) is unaffected.
- [ ] **CONF-4** (Conformance: Addenda A, B, F, G and H) A core server has hooks for these addenda: `remote` branch entries, `export`, batch `source`, `GET /`, pruning's archive bundles (§G.4.1; §G.5.1.1 encrypted), their namespace-document members (§12.3), `/principal`'s `catalog`. Without remote branches, a remote `base` is `422`.
- [ ] **CONF-5** (Conformance: Byte-exact definitions) Ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9) and padding buckets (§E.2.2) agree across implementations; each implemented part reproduces Addendum I. **[vectors I]**

## §2 Terminology

### §2.1 Defined terms

- [ ] **TERM-1** (Dependents) A namespace's dependents: unpurged namespaces whose `base` it is.
- [ ] **TERM-2** (Edge prefix) `/r/{ns}/{name}`, `/r/{ns}` or `/ns/{ns}` (names per §3.6); covers its URL and all below, segment-wise as RFC 6265 path matching; likewise a service's prefix under its root.
- [ ] **TERM-3** (Effective roles) A grant carries roles when a block lists `roles`. Effective roles: those its root block lists that every narrowing block listing `roles` keeps and configuration in force defines.
- [ ] **TERM-4** (Encryption level) `encryption.level`: none < `at-rest` < `sealed` < `e2e`. Sealed means `sealed` (E2) only; `e2e` (E3) is end-to-end.
- [ ] **TERM-5** (Protection) Moving content never makes it readable to anyone who couldn't read it at its source, unless a caller who can read it there writes it itself or an operator overrides one import. Allowed moves work within a namespace, between equal ranks and upward; only a key holder seals into `e2e`; an import keeps an `e2e` source's lines under its own name. Ranks `public` < `private` = `sealed` < `e2e`: source is `e2e` at E3, `sealed` at E2 whatever `read`, else `public`/`private` by `read` (unknown: `private`); target is the same but sealed with `read` `public` is `public`. A blob copy, remote branch schema mirror, rebase replay into its successor and (barring operator override) an import never move content to a lower-ranked namespace. Nothing else is ranked (branches: §7.4; batch local `source`; a writer's own writes).
- [ ] **TERM-6** (Protection: sealed sources) From a sealed source (public or not), and from an `e2e` source for a blob from before a raise from `sealed`, a blob copy or batch local `source` takes only a blob that opens under an epoch it is served under there (fixed as for a request for the blob), with keys §E.2.3 gives there to the request's own grant or one in `Source-Authorization`. Other copies: `404`; a local `source` doesn't make them available.
- [ ] **TERM-7** (Fixes `/resource`) A grant fixes `/resource` when a rule of its blocks or key scope (top level or nested only in `all`s) tests `/resource` against one name (`value`, or `compare` `eq` with a literal) or a finite set (`schema` of only `enum`, or `compare` `in` with a literal array); fixed names satisfy every such rule. An empty set, or any such literal not a valid name (§3.6), even one the intersection drops, means not fixed. A key with `readScope: "resource"` requires each grant it signs that can allow `read` (§C.2 item 2) to fix it.
- [ ] **TERM-8** (Qualifying role) Qualifies for edge grants: an effective role listing `read` whose rules don't refer to `/now`, refer to `/resource` only if grant fixes it, and pass now against a `read` envelope for grant's principal with `/resource` set to each fixed name (once if none).
- [ ] **TERM-9** (Referrer) In `N` setting `schemaReads`, a referrer of a schema revision is an unpurged resource of a namespace `schemaReads.for` lists (`N` included) whose head, or last live document if tombstoned, reaches the revision through `$schema` and the `$ref` closure; only that namespace's own resources count, not what a branch reads through, and a schema document's own `$ref`s don't make it one.
- [ ] **TERM-10** (Unrestricted read) Unrestricted `read` of a namespace: grant may `read` there (§C.2 item 2), its key has no `readScope`, no rule in its blocks or key scope refers to `/resource`, and, if it carries roles, an effective role listing `read` has no such rule (where a request needs it, only such roles count). Branching and remote registration check it at gate step 1.

## §3 Identity

- [ ] **ID-1** (Input) All JSON accepted is I-JSON (RFC 7493): a request body (not a blob upload) containing what it forbids is `400` (grants: §C.8). Also `400`: numbers overflowing an IEEE 754 double, and numbers whose JCS canonical form is an integer literal outside ±(2⁵³−1), however written. Numbers whose canonical form has an exponent are accepted; underflow reads as the nearest double. **[vectors I.1]**
- [ ] **ID-2** (Canonical form, What is stored) `canonical(v)` is JCS (RFC 8785) in UTF-8; server stores, serves and hashes `canonical(patches)`, never received bytes. **[vectors I.1]**
- [ ] **ID-3** (Id format) 20 bytes binary; text form (URLs, headers, JSON) is 33 characters: prefix `1` (SHA-256 truncated to 160 bits) then lowercase RFC 4648 base32 (`a–z2–7`), unpadded. **[vectors I.2]**
- [ ] **ID-4** (Revision id, Foreign parents, Tombstone id, Namespace revision id, Blob id) Ids follow §3.3, §3.4, §3.5, §3.7 exactly; `trunc160` keeps the first 20 bytes. Genesis `bytes(parent)` is empty; a branch's first entry of a read-through resource has a foreign parent; a tombstone's parent is the head deleted; `bytes(prev_ns_id)` is empty for a namespace's first entry; config revision ids use the revision formula over namespace document's own chain. **[vectors I.2, I.3]**
- [ ] **ID-6** (Namespace revision id: `forced`, `purge` target, Branch entries, `source`, Batch entries) Namespace entries have exactly §3.5's shapes, ids in text form.
  - `forced: true` only on a purge that overrode an `in_use` refusal, then on every entry it writes (propagated included).
  - A `purge` entry's `target` is the resource's head or tombstone as namespace written in sees it (branch: including what it reads through).
  - `branch` entries go in base's chain; a local branch's `target` is its config genesis id.
  - `source` is hashed with its entry; `origin` only for another deployment, as its canonical origin (§C.3); `ids` at most one member per batch item, named by its resource; any other shape: `400` (`bad_input`).
  - A `batch` entry lists the config entry first, if any, then per resource, in request order, one `head` or `tombstone` entry with its final entry.
  - Config entries and resource pointers share one chain.
- [ ] **ID-5** (Names) Namespace names match `^[a-z0-9][a-z0-9_-]{0,63}$`, resource names `^[a-z0-9][a-z0-9._-]{0,127}$`. URLs use names verbatim; percent-escapes are `400`.
- [ ] **ID-7** (Blob id) `type`: upload `Content-Type` lowercased without parameters, `type/subtype`; missing or unparseable is `400`. `nonce`: empty or 26 base32 characters hashed as ASCII. `bytes`: as stored (E3: client ciphertext). Text blobs aren't UTF-8-checked. **[vectors I.3]**

## §4 Invariants

- [ ] **INV-1** (Append-only, Linear) Entries are never modified or removed except by purge and pruning. One first entry per resource (genesis; in a branch, foreign parent); at most one child per entry; a head moves only to a child of the previous head. Likewise namespace and namespace-document chains.
- [ ] **INV-2** (Valid) A non-tombstone revision whose folded document has `$schema` validates, without the members §6.2 step 5 leaves out, against the schema revision it names; re-validating later agrees unless that revision or one in its `$ref` closure was purged or pruned without a kept document. At E3 readers check this, not the gate.
- [ ] **INV-5** (Verifiable) Entries suffice to recompute every id and check every parent link; below a pruning horizon, ids check only against archive.
- [ ] **INV-3** (Ordered namespace log) Every mutating request that takes effect (`create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `export`, `purge-ns`, `prune`, batches) writes exactly one entry in the addressed namespace's chain, atomically with its change. An idempotent retry answered from the log, and blob uploads and copies, write none. Server-written entries are one per resource and namespace affected. A local branch's creation writes its `branch` entry in base's chain atomically with first `config` entry of its own chain; a remote branch's also writes the schema histories it mirrors. A batch writes one `batch` entry.
- [ ] **INV-4** (Configuration in force) A write is checked against configuration (rules, keys, revocations, limits; in a branch also its local bases' current keys and revocations) at chain head when the write is inserted: namespace document of the nearest `config` entry, or `batch` entry with a config change, before the write's own entry; a batch's items as §7.5 says. A namespace's creation, and a document write changing what one of its own bounds limits, are held to the bounds of the document produced.
- [ ] **INV-6** (Fixed base) `base` never changes. Reads through a branch see base as of `at`, except that purges in base propagate and base's pruning applies; for a base in another deployment, purge notices apply as the branch's deployment sees them.
- [ ] **INV-7** (Referenced blobs) Every blob a stored document references is available to its resource and kept as long as document is; at E3 server relies on writers' declarations.

## §5 Storage requirements

- [ ] **STO-1** (list, items 1–3) Persisted: per entry, id, parent, kind, exactly recoverable `canonical(patches)` (until purged or pruned), author, `via`, grant reference, creation time, any `gesture`, `undoes`, author signature; per namespace log entry, author, `via`, creation time and, if written on request, grant reference with its non-bearer form (none hashed); per blob and resource, type, nonce, and, while pending, uploader. A blob is removed on purge, after pruning, and when unreferenced.
- [ ] **STO-2** (list, items 4, 5, 8 and 9)
  - Invariants 2, 5, 6 are enforced atomically, under concurrent writers and multiple processes too; a batch applies atomically, holding them across all items.
  - The document at any revision id can be served unless purged or pruned without a kept document (end-to-end namespaces: only revisions from before a raise to `e2e`, and a prune's sealed snapshot).
  - `base` is persisted; "this resource's head as of namespace revision `n`" is answerable for any resource and any `n` in a base's chain.
- [ ] **STO-3** (list, items 6, 7 and 10) After purge: ids, parent links, namespace entries, nothing else of the resource's content. After pruning: what §8.6 keeps. After a namespace purge: namespace document chain, namespace log, every resource's ids and parent links.
- [ ] **STO-4** (closing paragraph) Storage choices change nothing observable: reads serve exact canonical bytes; ids and limits are computed over them.

## §6 Validation and rules

### §6.1 Schema references

- [ ] **SCH-1** (Opting in, Accepted forms) A document opts in with top-level `$schema` string (`422`, `schema_ref`): exactly `^/r/[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}/rev/1[a-z2-7]{32}$`, or dialect URL `https://json-schema.org/draft/2020-12/schema` (a schema, validated against the dialect's meta-schema). Anything else: `422` (`schema_ref`); no normalisation.
- [ ] **SCH-2** (`$id`, `$ref`) A schema document uses `$id` in no subschema and `$schema` in none but its root (`422`, `invalid`); validators are registered and looked up only by revision path. `$dynamicRef` is same-document fragment (`422`, `schema_ref`). `$ref` resolves only same-document fragment (`#…`) or schema revision path in accepted form, optionally with fragment; percent-decoded fragment empty or starting with `/` is JSON Pointer, otherwise a plain name an `$anchor` or `$dynamicAnchor` of target must define. A schema's own `$ref`s resolve when written (step 5 of §6.2); one naming nothing in its target makes schema invalid (`422`, `invalid`).
- [ ] **SCH-3** (Never into a branch, Drafts in branches) `$schema` and `$ref` never name branch namespace (`422`, `schema_ref`); path naming branch where writer can't read revision: `422` (`schema_unavailable`). In a write to a branch, a path `/r/N/R/rev/X` that `N` can't resolve for writer (lacks it, or writer can't read it there) is looked up in candidates: `N`'s local branches (branches of branches included) not end-to-end, counting only revisions each wrote itself. A candidate serves writes to itself and its own branches, and to namespaces its `drafts.for` lists and their branches (namespace written, or one in its `base` chain, is listed); its branches don't inherit `drafts.for`. Writer needs `read` on `R` in candidate (as §7.5), else revision counts as not found. Any candidate holding `X` serves, and the whole `$ref` closure resolves likewise. In a non-branch namespace, paths resolve only in `N`.
- [ ] **SCH-4** (Schemas follow their documents) With `schemaReads.for` set in `N` (names or prefixes ending `*`, matched as `drafts.for`, never against branch; `N` always counts), schema revision in `N` whose own `$schema` is dialect URL:
  - resolves without `read` for write to listed namespace, or local branch of one (branches of branches included), whose document pins it through `$schema` or its `$ref` closure;
  - may be read by revision path, even under grant that doesn't name `N`, doesn't verify or can't read it there, when grant may read referrer of it (§2.1) in listed namespace it names, verifying under that namespace's keys and allowing that read, even where its `read` is `public`. A referrer in listed namespace that is public and neither sealed nor end-to-end counts for every request, grant ignored. An edge knowing only prefixes forwards such read to origin; origin serves it `private`.

  Nothing else opens (resource head, log, other revisions; non-schema documents; branch drafts). `schemaReads`: `422` in sealed and end-to-end namespaces.
- [ ] **SCH-5** (Within a batch, Tombstoned schema resources, Purged or unknown references) Batch items may reference revisions created by earlier items; revisions of tombstoned schema resource still resolve, for new references too. A reference that is unknown, purged, pruned without a kept document, unreadable by writer, or names tombstone, non-schema document, or revision written while its namespace was end-to-end, is `422` (`schema_unavailable`), `path` the revision path that didn't resolve.
- [ ] **SCH-6** (Referenced schema revisions, Copies, Refusals) Referenced: schema revision named by `$schema`, or reached through that schema's `$ref` closure, from head (or last live document if tombstoned) of any unpurged resource in deployment, head as of `at` (or last live document then) of resource branch reads through, or any revision branch wrote. A reference is satisfied by a copy whose document is neither purged nor pruned, in `N` or, for a document in a branch, in a branch it may resolve drafts in (candidate rules, never one writer's grants); pruned in `N` counts as unresolvable there. Unless forced, `409` (`in_use`): purge of resource or namespace removing last satisfying copy in any namespace it reaches (branches it propagates to included), and config write leaving reference without copy; `referencing` lists referencing namespaces in which caller may read anything (as §7.5).
- [ ] **SCH-8** (Forcing) A refused purge is forced with `?force=1` under grant chained to deployment operator key or, for purge of branch or resource in one, to a `*` key of that branch (inherited or own); under any other grant `?force=1` is `403` at step 1 of §6.2, needed or not. A forced purge's entries carry `forced: true` (ID-6).
- [ ] **SCH-7** (Read permission) Resolving a `$schema` or `$ref` needs writer's `read` on copy resolved to, in schema's namespace or branch holding draft (as §7.5 where not the namespace written), unless that namespace opens it with `schemaReads`. From sealed namespace (public or not), and from end-to-end one for revision from before raise from `sealed`, it also needs keys as in TERM-6, for the epoch a read of the revision would fix, in namespace written too; without them revision is unreadable (`422`, `schema_unavailable`).

### §6.2 On write

- [ ] **GATE-1** (intro) Checks run in §6.2's order. Only errors in a request's own shape, which no state influences, may precede step 1, as the request's own answer, never a batch item's: malformed names or URLs, content types, header and body syntax, size of what is read (`400`, `413`, `415`, a grant's request-shape `401`s of §C.2 item 1), unless an endpoint fixes its own order (blob uploads). A batch body cut off by the verified principal's `batchSize` (§7.5, LIM-1) is `413` once the grant is verified, before its verbs are checked; a malformed body read then is `400`.
- [ ] **GATE-2** (Authenticate and authorise) Step 1 authenticates and authorises (`401`/`403`): verbs and grant, key-scope and role rules referring only to `/action`, `/resource`, `/principal`, `/now` (§C.2). Rate limits come last, only for requests that passed (`429`).
- [ ] **GATE-3** (Precondition) Step 2, in order:
  1. Idempotent-retry lookup, with its verb check (§C.2 item 2). Not applied to purged resource (`410`); nor in purged namespace, where every write is `410` (`purged`) here, before any later check; nor to resource answering `502` under CONF-2 (a remote branch's, or one whose base chain reaches it), whose writes other than purges are `502` here.
  2. For a `PATCH` with `If-Match`, or batch item whose first step is patch set under `ifMatch`, verb is settled from resource's state as writer sees it: tombstoned head → restore; live head or none → append; purged → `410`; in branch read-through resource settles by base's head as of `at` (a tombstone there: restore, with it as foreign parent). A settled verb that isn't a candidate: `403`, before `If-Match` comparison, counting as failing authorisation for §7.5's failure report and dry run.
  3. Author signatures (`422`, `signature`); signed parent is the one precondition names.
  4. Frozen namespace (`409`).
  5. In batch, `422` for a `"delete"` following a `"delete"`; then precondition: `412`, or `410` on tombstoned resource, then `428`. A purge or prune of resource that never existed: `404`, never `412`.
- [ ] **GATE-4** (Apply, Limits, Schema) Step 3 applies patches to parent's document (`null` for create); operation validation, failing `test`, or create whose `writes` (§6.4.1) are empty: `422`. A delete skips steps 3–5. In namespace requiring nonces, create, append or restore is checked for a fresh `$nonce` (`422`, `nonce`). Step 4 validates namespace document config write or branch creation yields (§7.4) and prune's `horizon`, `keep`, `snapshot` (E3: archive too; §8.6) (`422`, `invalid`, or `limit`), then §6.6's limits, then that every blob reference in resulting document is well-formed and names blob available to resource (`422`). Step 5: if resulting document has `$schema`, resolves it (§6.1) and validates the document against draft 2020-12 with format assertions for formats it defines, `idn-hostname`/`idn-email` per RFC 5890 without UTS 46 mapping; schema naming any other `format` is invalid. The instance omits top-level `$schema`, fresh `$nonce` and `$successor` of §8.1's form; other forms are validated as data. Failure: `422` with `{ pointer, message }` errors.
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
  - `resource` is absent for `config`, `purge-ns`, `export`, and new namespace's name for `branch`. `principal` is absent when authentication is disabled.
  - `doc` is document as it will be stored. Delete: resource's last live document as target namespace sees it (read through bases in branch; in batch, after item's earlier steps); a replayed delete is judged against target's document at that step. `config`: resulting namespace document. `branch`: new branch's namespace document, evaluated in base. Null for `purge`, `purge-ns`, and in end-to-end namespace for `create`, `append`, `restore`, `delete` (not `keyring`); `{ remote, at }` for `export`; `{ horizon, keep? }` as sent for `prune`.
  - A batch yields one envelope per patch set; there is no `batch` action.
  - `principal`: `groups`, `attrs` from root block, `roles` its effective roles (§2.1); defaults `{}` for `attrs`, `[]` for `groups`, `roles` (a grant without roles too), `via`. `now`: server clock at gate, RFC 3339 UTC, millisecond precision, read once per request.
  - `read` envelopes carry only `action`, `resource`, `principal`, `now`.
- [ ] **RUL-6** (Rule forms, Path policy, `compare`) Every rule form of §6.4.2 is implemented; path policy uses `writes` predicates, never patterns over `/patches/*/path`.
  - `test` with `value` is RFC 6902 equality. A missing path fails `value` and `schema` tests and satisfies `exists: false`.
  - A `schema` is draft 2020-12 fragment with format assertions, checked like schema document (§6.1 `$id` ban, §6.5, §6.6), with no `$schema` in any subschema and only same-document `$ref`/`$dynamicRef`; otherwise namespace document: `422` (`invalid`), grant invalid (`401`).
  - `within` is true when there are no writes; `covers` and `overlaps` are false.
  - `lt`, `le`, `gt`, `ge` compare numbers, or RFC 3339 `date-time` strings as instants at full fractional precision (leap second `:60`, lowercase `t`/`z`, space for `T`: unsupported type); `eq` is RFC 6902 equality; `in` is true when the left value equals element of the right-hand array, false if the right isn't array. A missing path, or different or unsupported types for `lt`, `le`, `gt`, `ge`, makes `compare` false.
  - When all `if` rules pass, all `then` rules must pass.
- [ ] **RUL-3** (Evaluation) Rules run at step 6 of §6.2, in order; all must pass. Failing namespace rule: `422`, `code: "rule"`, `rule` (index), `path` (failing rule form, descending only through first failing member of an `all`/`then`). Failing grant, key or role rule: `403` (`forbidden`). Rules apply only at write time (read time too for grant, key, role rules); changing them never invalidates history.
- [ ] **RUL-4** (Config writes are rule-checked too, Operator overrides, Except as above) Namespace rules see every action (`delete`, `purge`, `config`, `branch` (evaluated in base), `purge-ns` included), except: a `config` write under grant chained to a `can: ["*"]` key (as does every request when authentication is disabled, CONF-1); namespace's creation under operator grant that creates it; purge or namespace purge forced past `in_use` under deployment operator grant. A purge forced with branch `*` key (inherited or own), or any purge while authentication is disabled, is still judged.

### §6.5 Reserved keys and extension keywords

- [ ] **RUL-5** (Reserved keys, `$blob`, `x-*` keywords) Top-level keys starting with `$` other than `$schema` are stored as data, never interpreted, except a fresh `$nonce` is left out of `writes` and can be required (§C.7), and well-formed `$successor` is read into deleted resource's `410` (§8.1); validation leaves both out (GATE-4; any other form is data; in a schema document also before its dialect check and compilation). `$blob` is reserved at any depth: object with a string `$blob` member is blob reference and must be well-formed (`422`); schema and namespace documents aren't searched for references. Schema keywords starting `x-` are ignored by core validator; any other unknown keyword makes schema invalid (`dependencies`, `$recursiveAnchor`, `$recursiveRef` included); `definitions` holds subschemas.
- [ ] **RUL-7** (`x-ref`, Entries inside a document, Finding references) An `x-ref` value is `{ "pinned"?: boolean, "key"?: pointer }`; pinned is revision path (§6.1), live resource path `/r/{ns}/{name}`. With `key`, reference names one entry of target (`/r/{ns}/{name}#{id}`, pinned `/r/{ns}/{name}/rev/{rev}#{id}`), `key` pointing into target at an array of objects with a string `id` or an object keyed by id; `{id}` matches those ids, never array positions, percent-encoded as URI fragment; a missing entry is dangling. References are found by a static walk of each document (without members validation leaves out) with its schema over every subschema that could apply at each location; a string where any carries `x-ref` is reference even if that subschema didn't validate. Core doesn't check `x-ref`.

### §6.6 Limits

- [ ] **LIM-1** (Configurable limits, Exceeding a limit) Every namespace has §12.2's limits under `limits`. Config writes, batch's `config` change and branch's `patches` are held to patch-set and document limits (`patchSetSize`, `opsPerSet`, `documentSize`, `nestingDepth`, `valueSize`, `pathSize`) as resource writes are (a namespace's creation: deployment defaults; local branch's: its base's limits), with bodies cut off as resource `PATCH`'s are.
  - Exceeding limit: `413` where request is refused before or while read, or where §7.8 says so, else `422`; `code: "limit"`, `limit` its key, and for sizes and counts `measured` and `max`; durations and rates give `limit` alone.
  - Where reading stopped, `measured` is a lower bound in body bytes, and before step 1 `max` is the deployment's. `measured`: for `pathSize`, `valueSize` the first value too long, quotes included; for `branchesPerNamespace` the base's live branches with the new or unfrozen one; for `blobPending` pending bytes with this blob, each at least 4 KiB; for a blob without `Content-Length`, `blobSize` + 1. It is left out for `documentSize`, `nestingDepth`, `valueSize`, `pathSize`, `blobsPerDocument` under a grant that can't read the resource.
  - Bodies of endpoints without limit of their own (prune, `/keys`) above 1 MiB: `400` (`bad_input`). A resource `PATCH` body over 4× the larger deployment maximum of `patchSetSize` and `documentSize`: `413` before parsing, naming `documentSize` with the deployment maximum. A batch body cut off by `batchSize` (§7.5) names it, verified principal's as `max`.
- [ ] **LIM-2** (Whole documents, Values) A create's patch set, and append's or restore's whose first operation other than `test` is root `replace` or `add` (more may follow), may be as large as `documentSize` instead of `patchSetSize`; at E3 every create and restore may, appends stay within `patchSetSize`. Every other patch set (even one starting with root `copy`, `move` or `remove`) stays within `patchSetSize`; in a batch all still count toward `batchSize`. A namespace's creation (a branch's included), and config write changing `limits` or `encryption` other than `epoch`, is `422` (`code: "limit"`, `limit: "patchSetSize"`, `measured` the left side, `max` the `patchSetSize`) unless, in resulting configuration, `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize`, the left side adding `36 B × blobsPerDocument` at E3.
- [ ] **LIM-3** (Rate limits) Token buckets checked at end of step 1 of §6.2, keyed by root `sub` and root-block `kid`, never `via`; per-resource bucket is per resource and principal, namespace bucket bounds all writers together. A request is admitted while every bucket it draws on holds at least one token; cost is then deducted (even below zero) atomically across instances sharing store, never committing write without it. A request refused after admission keeps its deduction; dry runs draw as submit would.
  - Cost: batch, one per touched resource from each per-resource bucket and one per item from principal and namespace buckets, plus one from those for its `config` change unless exempt (one failing after step 1: only under a `*` key); blob upload, one from per-resource, principal and namespace buckets plus its size from `blobRate`; other non-exempt write, one from principal and namespace buckets of namespace whose chain records it (a branch's creation: base's), plus per-resource for resource writes and prunes.
  - Exempt: config writes under a `*` key, or whose non-empty `writes` all lie at `/frozen`, `/successor` or `/merged` with resulting `frozen: true`; purges; server-written entries.
  - Exceeding: `429`, `Retry-After` in whole seconds rounded up, `code: "rate"`, `limit` a bucket hit (§6.6 key, `allowance`, `allowance.blobRate`), `retryAfter` (decimal seconds until every bucket drawn on holds a token). A key scope may lower per-principal rates.
- [ ] **LIM-4** (Allowances) An allowance gives principal (matched by root `sub` and signing `kid`) its own bucket for writes and uploads, replacing principal and namespace buckets and key scope's lower `rate`; per-resource buckets still apply. Its batches may be as large as it says, and it may set `blobRate` and `blobPending`. It never exceeds deployment maximums (`bucket`: `ratePerNamespace`'s): above is `422` (`code: "limit"`, `limit` naming that maximum's limit); one stored before a maximum was lowered is held to it. With `until`, it applies only while `now` is before it. While authentication is disabled, buckets are keyed by author and allowance matches author's `sub` alone. The first matching entry whose `until` hasn't passed applies.
- [ ] **LIM-5** (Deployment defaults and maximums) A deployment sets default and maximum for every limit and minimum for retry window; namespace may set any limit up to maximum, except those marked deployment only. A write setting value above maximum, or retry window below minimum, is `422` (`limit`); a stored value is held to lowered maximum; write leaving value or allowance unchanged doesn't set it. A namespace's own bound holds its creation and every write changing what it bounds (one lowering count still over bound is refused); other writes, freezes included, still pass document earlier release stored over it.
- [ ] **LIM-6** (Regular expressions) Regular expressions in rules, grants, key scopes and schemas use RE2 syntax and semantics, reading `\uXXXX` as `\x{XXXX}` (not after escaped backslash `\\u`, nor inside `\Q…\E`); surrogate pair of such escapes is one code point, a lone surrogate or one written `\x{…}` is a pattern RE2 doesn't accept; `regex` format asserts the same syntax. A pattern RE2 doesn't accept makes schema or config `422` (`invalid`), grant invalid (`401`). **[vectors I.11]**

## §7 HTTP API

- [ ] **HTTP-1** (URLs, Query parameters) URLs `/r/{ns}/{name}`, `/ns/{ns}`. A path other than `/` with an empty segment (`//`, trailing `/`), a `.` or `..` segment, or any percent-escape: `400` (`bad_input`). An id not in text form (§3.2): `400` (`bad_input`), request-shape (§6.2), in a URL, a write's precondition other than `If-None-Match: *`, `Last-Event-ID`, or a request field such as `ifMatch` outside a namespace document.
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
  4. Without `read`, existing and nonexistent resource both `404`.

  Writes, `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`, and any request to a non-public or nonexistent namespace keep steps 2, 3's `403`, `401`.

### §7.1 Reads

- [ ] **HTTP-4** (table) `GET /r/{ns}/{name}`: `302`, `Location: /r/{ns}/{name}/rev/{head}`, `ETag: "{head}"`; never existed `404`; tombstoned `410` `{ "tombstone": id, "last": lastRevisionId, "successor"? }`, `ETag: "{tombstone}"` (§8.1); purged `410`. `HEAD` as `GET`, no body.

  `GET …/rev/{id}`: `200`, `ETag: "{id}"` (`"{id}.{e}"` sealed), `X-Revision: {id}`. Neither sealed nor end-to-end: also `Last-Modified` (revision `created`, HTTP date to the second) and, without content coding, `Repr-Digest` of the canonical JSON document; neither on sealed or end-to-end. `If-None-Match`: `304`; likewise `If-Modified-Since` when `If-None-Match` is absent and `Last-Modified` sent, else ignored. Tombstone `id` `410`; unknown `id` `404`; purged resource `410`; `id` below the horizon without a kept document (§8.6) `410` `{ "code": "pruned", "horizon": id, "archive"?: url }`.
- [ ] **HTTP-16** (table) Raw document (§7.8): `GET …/raw`, `GET …/rev/{id}/raw` `302` to `…/blob/{bid}`. Unknown, pruned, purged, tombstoned ids and heads answer as the document URL; non-raw `404` (`not_found`); sealed or end-to-end `404` `code: "not_offered"`, after the document's read check.
- [ ] **HTTP-17** (table) `GET …/blob/{bid}`: `200`, `206` for a range; pending or unknown `404`; pruned or purged `410` (§7.8); sealed namespaces and E3 blobs from before a raise from `sealed`: `302` to `…/blob/{bid}/e/{e}` (§E.2.2). `GET …/blob/{bid}/e/{e}` serves only those: `200` sealed under epoch `e`, `206` for a range; `404` for an epoch not served; `410` per §E.2.2. Elsewhere, and other E3 blobs: `404` `code: "not_offered"`, after the resource's read check. Epoch `404`: `no-store`.
- [ ] **HTTP-18** (table) `GET …/rev/{id}/log?since={a}`: `200`, entries after `a` (exclusive) up to `id` (inclusive); empty or omitted `since` from genesis; `since={id}` empty. `404` if `id` unknown or `a` neither `id` nor an ancestor. `410`, as below the horizon, if any revision after `a` up to `id` has its patch set pruned and not restored from an archive (`a` itself may lie below it).
- [ ] **HTTP-5** (Paging) A log range answers its first page only if longer than the log page size (§6.6; a batch entry counts as its items), over `logPageBytes` of patch sets, or spanning an `e2e` raise. A page ends before an entry that would pass a bound or cross the raise, but holds at least one. At E2, `logPageBytes` counts each entry's sealed bytes as served. Oldest first, `X-Log-Next: {id}` (last entry returned = next `since`); a page reaching the URL's `id` needs none. `404`, `410` are judged over the whole range.
- [ ] **HTTP-19** (Paging, Continuations) Every paged answer names how to continue: log ranges in `X-Log-Next` (next `since`), `/heads` in body's `next` (next `after`), gestures listing in `X-Log-Next` (next `after`). Long-poll answers (§7.7) use the same page limits and carry no `X-Log-Next`. An E3 prune's sealed snapshot (§8.6) is served as `/rev/{H}`, never as a log entry, unless `H` is from before a raise to `e2e`.
- [ ] **HTTP-20** (Log entry shape) Resource log entry `{ "id", "parent", "kind": "rev", "patches", "author", "via"?, "created", "grant"?, "signature"?, "gesture"?, "undoes"? }`, `patches` canonical; a tombstone entry has `kind: "tombstone"`, no `patches`. `grant` `{ "id", "sub", "kid" }`, absent where none recorded (auth-disabled writes included). `created` RFC 3339 UTC, millisecond precision (namespace entries too). `via` the grant's delegatees in order, absent when none.

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
- [ ] **HTTP-8** (Namespace revision, Caching) Every successful write recording a namespace entry answers `X-Namespace-Revision: {ns_id}` naming it: creates, appends, restores, deletes; purges and namespace purges (on `204`); config writes; batches; branch creation and remote registration; a prune that moved the horizon or changed `keep`. An idempotent retry carries the original's entry. Blob uploads and copies, a no-change prune, a dry run: none. Write responses `Cache-Control: no-store`.

### §7.3 Events (Server-Sent Events)

- [ ] **HTTP-9** (Events) `GET /r/{ns}/{name}/events?since={id}`, `GET /ns/{ns}/events?since={ns_id}` replay entries after `since`, one log page (§7.1) per fetch, then stream live.
  - `Last-Event-ID` wins over `since`. Neither, or empty `since`: from genesis; no entries yet: waits for the first.
  - Replay judged as its log range, before any event: `since` not in the log `404`; a revision to replay with pruned patch set `410`. A prune reaching a page not yet sent ends the stream.
  - `Cache-Control: no-store`. Requires `read`, unrestricted for a namespace stream (§2.1), re-judged before each log page fetched and each keep-alive; the stream ends if it fails, and when the grant or cookie it was admitted under expires.
- [ ] **HTTP-24** (Events) Resource stream event types: `revision`, `tombstone` (data the resource log entry (§7.1), `id:` its id); `purge`, `prune` (data the recording namespace entry (§7.4) without `id`, `prev`; no `id:`). Ends after its `purge` event. A namespace purge sends no `purge` event and ends the resource's streams. Replay carries only `revision`, `tombstone`. Namespace stream events: its log entries as §7.4 serves them, `id:` the entry's `id`; ends after its `purge-ns` event, or without it where log ranges are sealed; a `since` naming that entry `410`.

### §7.4 Namespace

- [ ] **HTTP-10** (table) `GET /ns/{ns}`: `302`, `Location: /ns/{ns}/rev/{ns_id}`, `ETag: "{ns_id}"`, `X-Config-Revision: {config_id}`; head pointer. `GET …/rev/{ns_id}`: `200`, document in force at that chain point, `ETag: "{ns_id}"` (`"{ns_id}.{e}"` sealed), `X-Config-Revision: {config_id}`; immutable. `ns_id` not in the chain `404` (short), also at its `/log` and `/heads`.
- [ ] **HTTP-25** (table) `GET …/rev/{ns_id}/log?since={a}`: `200`, immutable, paged (§7.1), array of `{ id, prev, kind, resource?, name?, remote?, at?, target?, entries?, source?, forced?, author, via?, grant?, gesture?, undoes?, gestures?, created }` per §3.5. `gesture`, `undoes` of a single write; `gestures` maps each batch resource to a list of `{ "gesture"?, "undoes"? }`, one per step; none hashed. `grant` `{ "id", "sub", "kid" }`: grant id (§C.3) in text form, root `sub`, `kid`.
  - `grant` recorded for: local branch creation (creator's, both entries); namespace genesis (operator's); janitor prune (janitor's); schema namespaces a remote branch mirrors at creation (creating operator's).
  - `grant`, `via` absent from server-written entries (propagated purges, purges applied from a remote base, its own prunes); `grant` also absent before v0.37 unless recoverable from revisions; `null` while authentication is disabled.
  - Empty or omitted `since`: from the chain's first entry; `404` if `a` is neither `ns_id` nor earlier in its chain.
- [ ] **HTTP-26** (table) `GET …/rev/{ns_id}/heads?after={name}`: `200`, immutable, `{ "heads": [ … ], "next"? }`, page of `{ resource, kind, target, created?, size?, digest? }`: one row per resource as of that revision, read-through ones included; `kind`, `target` of its latest `head`, `tombstone` or `purge` entry, or `purge` with that `target` if purged since (§8.3); ascending byte order of name, strictly after `after` (needn't name a resource). `next` names the following page, absent on the last. Neither sealed nor end-to-end, judged by the serving namespace: `created` the target entry's; for a live head of an unpurged resource, `size` canonical document byte length, `digest` its uncoded `Repr-Digest` value (`sha-256=:…:`). At E2, E3, and for a resource §1 answers `502` for: all three absent. Readers MUST NOT rely on them. `410` once purged (§8.5).
- [ ] **HTTP-27** (table) `GET /ns/{ns}/principal`: `200`, `no-store`, `X-Config-Revision`, `{ "principal", "kid", "key", "operator", "can", "roles", "writer": { "frozen", "successor"?, "nonce", "signatures", "level"?, "limits" }, "catalog"?: { "trust", "files"? } }`, for the grant in `Authorization`:
  - `principal` per §6.4.1; `kid` the key that verified the root block; `key` the RFC 7638 SHA-256 thumbprint, base64url unpadded, of that key as JWK `{"crv":"Ed25519","kty":"OKP","x":<pub>}` (namespace key) or the published JWK (operator key).
  - `operator` true for an operator grant: `can` its blocks' verbs, `roles` `[]`. Otherwise `can` the verbs its blocks and key allow (role-carried: only those an effective role lists), `roles` its effective roles. `can` never lists `branch` where local branches are refused.
  - `writer`: `frozen`, `successor`; `nonce` `required` where the document requires nonces or the namespace is sealed at E2, else `optional`; `signatures` `optional`/`required`; `level` `at-rest`/`sealed`/`e2e`, absent without `encryption`; `limits` every §6.6 limit in force (namespace value, else deployment default), without allowances or a key scope's `rate`.
  - Document has `catalog`: `trust` (`[]` when absent), `files` (§B.6, §H.2). Grant without unrestricted `read` of the catalog: `files` without `x-` members, and `trusted` (whether `files.ns` is trusted; `false` without `files`) in place of `trust`.

  **[vectors I.12]**
- [ ] **HTTP-28** (table) `GET /ns/{ns}/principal` applies only the `ns` check (§7) and verification (§C.2 item 1, key scope included); no verb check, no rule. Operator grant, nonexistent namespace `404`; grant failing `ns` check `403`; grant unusable or none `401`, even in a public namespace; authentication disabled `200` without `principal`, `kid`, `key`, with `operator: false`, `can` every verb the server allows, `roles` `[]`, nonexistent namespace `404`; purged namespace `410` once the grant verifies (§8.5). Draws no rate token.
- [ ] **HTTP-29** (table) `GET /ns/{ns}/gestures/{gesture}`: `400` (`bad_input`), request-shape, for `{gesture}` not of §7.2's form or `after` not `{resource}/{id}`. Sealed or end-to-end namespaces: `404` `code: "not_offered"`, after the `read` check. `200`, `no-store`, `[{ resource, id, kind, gesture?, undoes?, author, ns_id }]`, one per revision or tombstone written with or undoing that gesture, oldest first, omitting purged resources and resources the grant can't read. Paged by `logPageSize`: a full page carries `X-Log-Next: {resource}/{id}` (its last row), the next page is `?after=` that; `after` naming no such entry of an unpurged readable resource `404`; no `X-Log-Next` is the last page.
- [ ] **HTTP-30** (table) `GET /ns/{ns}/grants/{gid}`: `200` `{ id, root, stored }` for a grant recorded by an entry of this namespace, or, in a local branch, of its bases up to their `at`, in non-bearer form (§C.3.1); else `404`. Needs unrestricted `read` (§2.1). Sealed in sealed namespaces, `private` in end-to-end ones; cached immutable (`private` at E3).
- [ ] **HTTP-31** (table) `GET /ns/{ns}/branches`: `200` (head pointer), `[{ name, at, frozen, purged, successor?, drafts? }]` for direct branches, `{ remote, at, ns_id, expires }` for remote branches with unexpired registration (§G.3). Needs unrestricted `read` (§2.1); `410` once purged (§8.5).
- [ ] **HTTP-11** (Namespace writes, table, Content types) `PATCH /ns/{ns}`, `application/json-patch+json`; precondition `If-Match: "{config_id}"` or `If-None-Match: *` to create. Success `201`, `X-Config-Revision: {new config_id}`, `X-Namespace-Revision: {ns_id}`, `Location: /ns/{ns}/rev/{ns_id}`, body `{ "config": new config_id, "ns_id" }`. Idempotent retry (§7.2) `200`, same headers and body (config change written by a batch: `ns_id` the batch's entry). Failure `412` `{ config }` (no `config` for creation under a taken name); `422`; `428`; `401`; `403`. Other content types `415`.
- [ ] **HTTP-32** (Envelope) Config writes are checked with a `config` envelope (§6.4.1); key-scope and grant rules apply.
- [ ] **HTTP-33** (Keys, roles, revocations, limits and exposure) Need a `*` key (§C.2): writes covering/overlapping `/keys`, `/roles`, `/revoked`, `/limits`, `/allowances`, `/merge`, `/retention`, `/encryption`, `/signatures`, `/nonce`, `/schemaReads`, `/catalogs`, `/maxLag`; writes setting `read` to `public`. Making `read` stricter: none.
- [ ] **HTTP-34** (Validation, Members, `x-` members, Errors) The namespace document is validated against the built-in schema of the deployment's version: rules and patterns well-formed and within limits; §12.3 members (core, Addenda B, F) strict; any other top-level member must start with `x-` (case-sensitive) and is stored as data, as may members inside the addenda's objects (§12.3) except keys of `catalogs`; role entries open (core reads `can`, `rules`); other nested objects (key entries) strict. Else `422`, `code: "invalid"`, `errors: [{ "pointer", "message" }]`.
- [ ] **HTTP-35** (Documents stored under an earlier version, Versions) A member this version doesn't define (or such a key-entry field): a write may keep it unchanged or remove it, and is `422` only if it adds or changes one; `move` to an `x-` name renames it. Creating a branch of a namespace holding one: `422` until renamed. Deployments reading another's documents ignore undefined members; only a tool copying a document into a namespace refuses one (unless `x-`); none refuses on spec version alone.
- [ ] **HTTP-36** (Logging) A config change appends a `config` entry to the namespace chain. Namespace event type is the entry's `kind` (`head`, `tombstone`, `purge`, `config`, `batch`, `branch`, `purge-ns`, `prune`).
- [ ] **HTTP-37** (Branch fields) `422` (`invalid`, `errors` pointing at the member):
  - changing `base` after branch creation; a `PATCH`-created namespace setting a `base` that isn't remote (§G.3), or a remote `base` without `origin`;
  - a branch config write removing or changing a key entry with the `kid` and `pub` of a `*` key in a base (MUST NOT);
  - `successor` at a creation other than a branch's;
  - setting or changing `successor` to anything but another existing, unpurged namespace (MUST): for a branch, a branch of the same base or of a namespace further up its `base` chain (`at` may differ); else another non-branch;
  - a branch of a non-public namespace becoming `public` (MUST NOT);
  - a branch breaking Addendum E's level rules (Levels) or turning off its base's `nonce` requirement (MUST NOT).
- [ ] **HTTP-38** (Branch fields) `drafts: { "for": [ … ] }` optional: names or `*`-ending prefixes of other namespaces whose writes, and their branches', may resolve schema paths into this branch (§6.1). Bare `"*"` serves all; without `drafts`, only the branch and its own branches. Narrowing: §6.1's `in_use` rule. `drafts` `422` in a namespace that isn't a local branch or is end-to-end. `409` `code: "in_use"` with `dependents`: making a namespace with public dependents non-public; making a namespace require nonces while a dependent doesn't. A namespace can't raise its level above a dependent's (Addendum E, Levels).

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
  - `200` `{ "items": [{ "index", "status", "code"?, "ids"?, … }], "config"? }`: every item, `status` `201` if it would pass, `200` for each when a submit would be an idempotent retry; with the ids a submit would produce and any `signature` failure. `config`: `{ "status", "code"?, "config"?, … }`, the id a submit would produce.
  - `config` change fails step 1: answered as that config write. Else any item failing authorisation (§6.2 steps 1, 2.2): `401`/`403`, only those items.
  - Rate limit, purged or frozen namespace, `itemsPerBatch`, `batchSize`, refused `source`: answered as a submit.
- [ ] **HTTP-45** (Idempotent retry) `200` with an earlier batch, as §7.2, when one earlier `batch` entry by the same principal contains exactly the entries this batch would produce, config entry included, with the `config` change's `ifMatch` as its parent, and every item passes the retry's verb check (§C.2 item 2). Only `batch` entries match: a config-only batch retries an earlier `batch` entry holding just that config entry. A purged resource among the items: `410` before any other precondition, `batch` body listing those items (`code: "gone"`).
- [ ] **HTTP-46** (Reading other namespaces) Checks reading a namespace other than the request's (a batch's local `source`, a blob copy's source (§7.8), a schema revision elsewhere, a branch draft included (§6.1)) try the request's grant and every `Source-Authorization` grant (repeatable). The first grant that names that namespace, verifies under its keys (§C.2) and allows that read serves; a public namespace needs none. If none serves, the check fails as its own section says, revealing nothing about the namespace.
- [ ] **HTTP-47** (`source`) `source` is recorded in the batch entry. Local source, caller with unrestricted `read` on `source.ns` (as HTTP-46): `source.at` must be in `source.ns`'s chain (`422`, `code: "source"`), at step 4 of §6.2, after the batch limits and before any item's checks. Other callers: recorded unchecked, no blobs available. Source in another deployment carries `origin`, recorded unchecked; an `origin` equal to this deployment's own: `422` (`source`), any caller, same step.
- [ ] **HTTP-48** (Events) Each resource's event stream carries its new entries; the namespace stream one `batch` event.

### §7.6 Branches

- [ ] **HTTP-13** (Request, Result) `POST /ns/{base}/branches` `{ "name", "at"?, "patches"? }` (`patches` defaults `[]`). Local branch:
  - `at` defaults to the base's latest `ns_id` at entry insertion.
  - `If-None-Match: *` required; `If-Match` alone `428`, at step 2.5 of §6.2, never answered as a retry.
  - `201`, `Location: /ns/{name}`, `X-Namespace-Revision` of the `branch` entry appended to the base's log (§3.5).
  - Taken name (a purged namespace's included): `412`, no `head` or `config`.
  - Retry by the same principal with the same `at` and `patches` (omitted `at` counts as the recorded one): `200` as §7.2 until the branch is purged, then `412`.
  - `at` not in the base's chain `422`; purged base `410` `code: "purged"`.

  Remote branch registration (§G.3) uses this endpoint too, renewing with `If-Match`.
- [ ] **HTTP-49** (Configuration) The branch's document starts as a copy of the base's current one; `frozen`, `successor`, `merged`, `abandoned`, `cleanup`, `drafts`, `schemaReads` removed, `base: { "ns": base, "at": at }` added, then `patches` applied. Its configuration chain starts with one entry, genesis patch set `[{ "op": "add", "path": "", "value": <document after patches> }]`, the `target` of the base's `branch` entry. Rules, roles, read mode are then the branch's own; keys follow the base (§C.4).
- [ ] **HTTP-50** (Authorisation) Creating a local branch needs `branch` and unrestricted `read` (§2.1) on the base, per §C.2 item 2. The `*`-key guard (§C.2) applies to `patches`, with a `*` key of the base; every `*` key of the base stays in the branch, unremovable. The base's rules evaluate a `branch` envelope: `resource` the new name, `doc` the new document, `writes` from `patches`. Failures as other writes (§6.2, §C.2).
- [ ] **HTTP-51** (A branch is a copy, Nesting and number) Whoever can read the branch can read the base as of `at`, under the branch's configuration. A branch of a non-public namespace MUST NOT be public. A branch may be a base, within the branch-depth and branches-per-namespace limits (§6.6).
- [ ] **HTTP-52** (In another deployment) Remote branch `base: { "origin", "ns", "at", "chain" }`: a new namespace created with the operator key (§C.4 bootstrapping, §G.3). Not across deployments: keys following the base, revocation in bases, purge propagation, dependents blocking a namespace purge.
- [ ] **HTTP-53** (Reading through) A resource with no entries of its own in the branch answers as the base did at `at`, recursively through bases: `302`, `Location: /r/{branch}/{name}/rev/{id}`, `ETag: "{id}"`, `id` the head as of `at`; tombstoned then `410`; nonexistent then `404`. Base changes after `at` are never seen, except purges (§8.3) and the base's pruning (§8.6).
- [ ] **HTTP-54** (History) `/r/{branch}/{name}/rev/{id}` serves any id in the resource's ancestry as seen from the branch, base revisions up to the foreign parent included; `…/log?since=` crosses the foreign parent; `…/blob/{bid}` serves the branch's own blobs and the base's that the branch's view references.
- [ ] **HTTP-55** (First write) The first write to a read-through resource checks its precondition against the base's head as of `at` and takes it as foreign parent, whether appending, deleting or restoring. If the document built on (for a delete, the one deleted) is pruned (§8.6): `410` (`pruned`) once the precondition passes. A name nonexistent in the base at `at`: ordinary create.
- [ ] **HTTP-56** (Logs) The branch's namespace log holds only its own entries.

### §7.7 Live reads by long-poll

- [ ] **HTTP-57** (Answer) `GET /ns/{ns}/log?since={ns_id}&live=long-poll&cursor={c}`, `GET /r/{ns}/{name}/log?since={id}&live=long-poll&cursor={c}`:
  - Entries after `since` (empty or missing: from the beginning): `200` at once, up to one log page (§7.1), in §7.1, §7.4 shapes; `X-Namespace-Revision` (resource logs: `X-Revision`) names the last entry returned.
  - Else waits for an entry or the end of the current interval; timeout `204`, same header naming `since` (omitted when `since` is empty); both answers carry `X-Cursor`.
  - `since` not in the chain `404`; pruned range `410` (§7.1). A resource with no entries waits as for empty `since`.
  - Namespace log needs unrestricted `read` (§2.1); resource log `read` on the resource.
  - Without `live`: `302` (head pointer) to `…/rev/{head}/log?since=…`; a resource with no entries `404` (short).
- [ ] **HTTP-14** (Intervals and cursors, Clients)
  - Fixed intervals (default 20 seconds) from a fixed epoch; cursor is the decimal interval number.
  - Response cursor: `200` current interval number; `204` the greater of that and request cursor plus one.
  - Cursor more than an hour's worth of intervals ahead of or behind the server's: `400`.
  - No cursor, or behind by less: answered at once, entries after `since` if any, else `204` with current cursor in `X-Cursor`.
  - Ahead by an hour's worth or less: waits as a current one, to this server's interval boundary at the latest; `204` carries request cursor plus one.
  - Clients echo `X-Cursor` as `cursor` in the next request and take the returned revision as the next `since`.
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
  - in a batch with a local `source` whose `source.at` is checked (§7.5): attached to the same resource in `source.ns`, or a base it reads through, and referenced by a document in that resource's history as `source.ns` sees it at `source.at`, whatever the ranks. From a sealed `source.ns`, and for an `e2e` one's blobs from before a raise from `sealed`: only blobs the caller's keys open (§2.1).

  An unavailable blob, or a reference not matching its `type`, `size` or `nonce`: `422` (`code: "blob"`), at step 4 of §6.2.
- [ ] **HTTP-61** (Uploading, No precondition) `PUT …/blob/{bid}` checks in order:
  1. Authorisation at step 1 of §6.2, `create`, `append`, `restore` as candidates (§C.2 item 2), then rate limits (§6.6). No rule beyond step 1 sees an upload.
  2. Purged resource `410`; any upload to a purged namespace `410` (`purged`). Tombstoned resource accepts uploads.
  3. Frozen namespace `409`.
  4. Unparsable media type `400` (`bad_input`); likewise a `Blob-Nonce` not 26 base32 characters, empty included. E3: any type other than `application/vnd.patchlog.sealed-blob` `415`. Order: these `400`s, a precondition's `428`, this `415`.
  5. Body over `blobSize` `413`; likewise one taking the uploader's pending blobs in the namespace past `blobPending`.
  6. Id recomputed over the body (§3.7), `Blob-Nonce` as nonce or empty, must match, else `422` (`blob_mismatch`).

  URL and query errors, malformed `{bid}` included (`400`, `bad_input`), precede check 1. Other request-shape errors in upload headers `400` (`bad_input`) at check 4 (a copy's: see Copying); a precondition: `428`, at check 4. Idempotent: `201`, `ETag: "{bid}"` whether or not the bytes were stored; each uploader is charged for its own pending entry.
- [ ] **HTTP-62** (Copying) An upload with empty body and `Blob-From: /r/{ns2}/{name2}/blob/{bid}`, naming the same `bid`, copies a blob within the deployment.
  - Checks 1–3 first, for the target.
  - Then, before any body is read: a request with a body, an unparsable `Blob-From`, or a check-4 header error outside `Content-Type`, `Blob-Nonce` `400`; then a precondition `428`. A different `bid` `422` (`blob`).
  - Source then checked as a read of `/r/{ns2}/{name2}`, as HTTP-46; a grant whose blocks name both namespaces, signed by a key they share, serves for both. Any failure, `401` and `403` included: `404`.
  - Also `404`, each alone: the copy goes into another namespace ranking below its source (§2.1); Reading wouldn't serve the blob at the source; the blob is from a sealed source, or an `e2e` one from before a raise from `sealed`, and the caller's keys don't open it.
  - Then checked as an upload of the source's type, nonce and size (checks 4, 5), whatever `Content-Type`, `Blob-Nonce` it carries.
  - Costs a token like an upload, nothing from `blobRate`.
- [ ] **HTTP-63** (Files) A document is raw when its root is a blob reference with no members other than the top-level ones validation leaves out (`$schema`, a fresh `$nonce`, a `$successor`). Served at `…/raw` (§7.1) with the blob's type. The read check of `…/raw` and `…/blob/{bid}` is the document's own; a `schemaReads` referrer (§6.1) opens revision paths only. Its `size` in `/heads` (§7.4) is the reference's length.
- [ ] **HTTP-64** (Reading)
  - Every blob URL response, errors included: `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`. Exception: `200`/`206` for a stored `type` of exactly `application/pdf` may omit the sandbox, keeping `nosniff`. PDFs: `Content-Disposition: attachment` unless the deployment opts into inline display.
  - `200` carries `Content-Type` the stored type (§3.7), plus `; charset=utf-8` for `text/*`, `ETag: "{bid}"`, `Accept-Ranges: bytes`. Sealed namespaces, and E3 blobs from before a raise from `sealed`, answer as §E.2.2.
  - Whoever may read `/r/{ns}/{name}` may read its blobs, those attached to it and, in a branch, the base's that the branch's view references. A tombstoned resource keeps serving its blobs. Cached immutable, with the resource's tags (§9).
- [ ] **HTTP-65** (Encryption) In sealed namespaces and those requiring nonces, writers MUST give blobs they create a nonce (§C.7); the server doesn't check. Blobs carried over from another namespace keep their ids, nonce or not.

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
  - CDN purged by tag, `heads:{ns}` included, never by id.
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
  5. dependents (§2.1): `409`, `code: "in_use"`, `dependents`;
  6. last copy of schema revision (§6.1) referenced from another namespace (own documents not counting): `409`, `code: "in_use"`, `referencing`.
- [ ] **DEL-8** (Effect)
  - Every resource purged as in §8.3, no individual entries; one `purge-ns` entry appended, log's last. CDN purged by tag `ns:{ns}`.
  - Purges propagated from base (§8.3, §G.3) and retention prunes skip a purged namespace.
  - Kept: namespace document chain, namespace log with authors, every resource's ids and parent links.
- [ ] **DEL-9** (Answers afterwards, table) Every `410` of §8.5: `code: "purged"`, `head` the `ns_id` of the `purge-ns` entry.
  - `410` URLs: `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…`, `/ns/{ns}/keys`, `/ns/{ns}/principal`, `/ns/{ns}/branches`, `/heads` at any revision. As soon as full read check passes, before any other answer to well-formed request, `not_offered` included. Read check: grant's rules plus unrestricted `read` where the URL needs it (any `read` for gestures; §E.2.3's test for `/keys`; verification alone for `/principal`).
  - `/ns/{ns}` and `/ns/{ns}/rev/{ns_id}`, logs, events, long-poll served as before, except events and long-poll from the `purge-ns` entry are `410`, and except where sealed (DEL-11).
  - Any write to namespace `410`, after authorisation and rate limits, before any other check (§6.2 step 2.1): resource writes, batches, blob uploads and copies, purges, prunes, config writes, branching from it, remote registration.
- [ ] **DEL-10** (table)
  - Creating a namespace or branch under purged namespace's name: `412`; so a branch creator's retry once branch is purged.
  - Creating a remote branch whose base on A is purged, or whose chain holds purged base: `410` for any `at`, before `at` is checked; `ns`, `head`, `origin` name first purged namespace found, A's before its bases'.
  - Edge-grant issuance for grant naming a purged namespace: `410` only if every namespace refused is purged and grant verifies there; `ns`, `head` name first.
- [ ] **DEL-11** (Sealed namespaces) Where namespace documents and log ranges are sealed (§E.2.2), purge destroys epoch keys sealing them; those reads, events, long-poll included, then `410`. `GET /ns/{ns}` still redirects, to revision that is `410` where sealed.
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
- [ ] **DEL-15** (Protected revisions, Protected documents, Branches don't prune) Horizon never passes: any revision newer than retry window; resource's head as of the `at` of every unpurged local branch, frozen or not; its head as of the `at` of every remote branch whose registration hasn't expired.

  Below horizon these keep documents: schema revisions referenced (§6.1) from any namespace of deployment; revisions in `keep`. A branch's own entries are protected until it is purged. Prune in branch, once checks pass: moves no horizon, ignores `keep`, writes nothing, `200` with resource's current horizon as branch sees it, or its genesis id where none.
- [ ] **DEL-16** (Archive) Before pruning, server writes pruned history as full-history bundle (§G.4.1), `"authors": true` with grant lines, to destination configured by operator or in `retention`; MUST NOT write anywhere else. Only two prunes go without: under a `*` key where no destination is configured; applying a retention rule saying `"archive": false`. Encrypted namespaces: sealed bundles (§G.5.1.1), one per resource, only recipient a key server holds for that resource, destroyed by purge.
- [ ] **DEL-19** (Archive)
  - At E3, prune carries `snapshot`, sealed like a patch set (§E.3.1), holding `H`'s document (last live one if `H` is tombstone).
  - At E3, prune without `snapshot`, or, outside a branch, with no archive configured: `422` (`invalid`), `*` key or not.
  - `snapshot` outside E3: `422` (`invalid`).
  - At E3, effective horizon moves horizon but isn't `H`: `422` (`invalid`), `horizon` effective horizon.
  - Server skips E3 namespaces when applying retention itself.
- [ ] **DEL-17** (Retention policy) Namespace document may declare `retention` rules, applied periodically by server or janitor with `prune`.
  - First rule whose `select` matches applies. `select`: name `prefix` or list of `names`; missing matches everything.
  - `keep`: whichever is longer, last `revisions` or everything newer than `age`.
  - Rule without `keep`, or `keep` with neither: `422` (`invalid`).
  - `archive`: rule's destination, default operator's. Rule with neither applies only if `"archive": false` (`422` in an E3 namespace); otherwise its resources keep everything, as where no rule matches.
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
  | Writes, batches, dry runs, SSE, a `502` (§G.3) | `no-store` | none |
- [ ] **CACHE-4** (Serving stale) Edge serving immutable responses while origin is unreachable still removes them when purged. Head pointers stale only within `stale-while-revalidate`. Live long-poll `200` and `204` MUST NOT be served stale: no `stale-*` directive; edge MUST NOT apply stale-if-error or grace defaults.
- [ ] **CACHE-2** (Tags, Branches, Making a namespace private) Tag `{kind}:{value}`: `kind` a lowercase word, `value` namespace and resource names joined by `/`. `Cache-Tag` comma-separated, `Surrogate-Key` space-separated. A purge names whole tags, never part of one. Branches cached under their own URLs and tags; propagated purges (§8.3) purge those too. Making a namespace private, or raising it to sealed or end-to-end, requires purge of tag `ns:{ns}`, issued by origin with configuration write.
- [ ] **CACHE-5** (Sealed namespaces) Cached by its `read` mode, under public or private rules.
- [ ] **CACHE-3** (Private namespaces) Downstream responses: `Cache-Control: private`, `max-age` no longer than their public class's. Edge lifetimes (`CDN-Cache-Control` or `Surrogate-Control` at public values) only for read edge verified itself, needing all of: both edge verification headers present; each one line, no comma; secret matches; prefix covers the URL; no `Authorization`, `Source-Authorization` or signed-URL parameters.

  Origin still authorises read itself, from cookie or grant edge forwards (§C.5.3). Headers decide only lifetimes, never when event stream ends (§7.3). Every other private response: `CDN-Cache-Control: no-store` (and `Surrogate-Control: no-store`), edge or not, including grant in `Authorization`, schema revisions opened by referrer (§6.1), reads edge only relayed, and where no verifying edge is deployed.

## §10 Namespace consumers

- [ ] **CONS-2** (Checkpoint, Catch up, Follow, Fetch content, Consumers elsewhere) Checkpoint = last `ns_id` fully processed (`""` = start). Catch up: `GET /ns/{ns}`, then `…/rev/{current}/log?since={checkpoint}` page by page. Follow: `/events?since={checkpoint}` or long-poll (§7.7). Content from immutable URLs. Another network or organisation: checkpoint `(origin, ns, ns_id)`, fetches verified as §G.2.
- [ ] **CONS-1** (Handle every kind of entry, Advance the checkpoint) Per entry kind:
  - `head`: process document. `tombstone`: drop resource. `purge`: drop resource, purge derived data and cache tags. `batch`: process entries as one unit.
  - `purge-ns`: drop everything from namespace, purge derived data and cache tags. Where log ranges are sealed, a `410` `purged` stands for it.
  - `branch` with `remote`: never fetch from it.

  Pruned revision (`410` `pruned`): fetch head; if pruned too, treat resource as absent until later entry. Advance checkpoint only after entries are durably processed; processing idempotent.
- [ ] **CONS-3** (Verifying grants) A consumer verifying grants presented to it MUST check keys and revocations as of namespace head (in branch, its local bases' heads too), not checkpoint. Grants recorded with entries verified as §C.3.1.
- [ ] **CONS-4** (Branches: Discovery, Contents, Access) Branches: from `branch` entries with `name` in followed logs, recursively; if started from `/heads`, earlier ones from `GET /ns/{ns}/branches`. For such a branch, or one told to follow: start from its `/heads` listing at its first `ns_id` (read-through resources included), then its own log. Needs unrestricted `read` on branch (§2.1); skip one it may not read.


## §12 Registries

### §12.1 Errors

- [ ] **ERR-1** (§12.1 table) Error answers carry their §12.1 row's `code`, status, body shape, named members.

### §12.2 Limits

- [ ] **ERR-2** (§12.2, table, closing paragraph) Namespace document setting a deployment-only limit: `422` (`invalid`). `limits`: sizes integer bytes, counts integers, durations ISO 8601, rates `{ "rate": <per second>, "burst": <bucket size> }`. `rulesPerNamespace`, `rulesPerGrant` count every rule form, nested in `all`, `any`, `not`, `if`, `then` included; `rulesPerGrant` counts those in grant chain's blocks.

## Addendum A — Indexing service

### §A.1 Following the namespace

- [ ] **SVC-5** (A.1) Follows each namespace as in §10, one checkpoint per namespace, stored in the same transaction as index writes. Per coalesced `head`, fetches `/r/{ns}/{name}/rev/{id}`:
  - No `$schema`: resource's rows removed.
  - Schema document (`$schema` a dialect URL, §6.1): indexed against that dialect's meta-schema; `schema=` with dialect URL lists schema documents. Revision paths of `$ref` keywords at schema positions, fragment dropped, are references.
  - Other: annotated fields and references indexed with schema revision pinned. That revision answering `4xx` but `429`, or unopenable for lack of keys: indexed as without `$schema`. Schema or keys fetch failing for moment (transport error, `5xx`, `429`): retried.

  `tombstone` removes resource's rows. `purge`, and a `config` entry on which §9 purges `ns:{ns}`, also purge `idx:{ns}` from service's own cache and drop kept results.

### §A.2 What gets indexed: `x-index`

- [ ] **SVC-2** (A.2, `text`, `facet`, `sort`, References) `x-index`: `"text"`, `"facet"`, `"sort"` or array. Only strings, numbers, booleans collected, through keywords marking a path (§A.4).
  - `text`: full-text, strings only.
  - `facet`: arrays expand to one value per element; value matches and counts as its string form (number or boolean as canonical JSON).
  - `sort`: ascending, or descending with `sort=-{path}`; document sorts by its least value at path: numbers before strings before booleans; numbers by value, strings by UTF-8 bytes, `false` before `true`. No value: last either way.
  - References need no `x-index`: each document walked with schema revision it pins; §6.5's references stored as `{ ns, name }` plus revision (pinned) or entry (`#id`), plus full instance pointer, array indices included. Untyped documents' references aren't found. `x-index` rows name the field without indices; text isn't scanned for paths.

### §A.4 Query API

- [ ] **SVC-6** (table, Bounded redirects, unfollowed and purged namespaces, plain document URL)
  - `GET /{ns}?…` → `302`, cached as head pointer, to `/{ns}/at/{checkpoint ns_id}?…`, or for private namespace `/{ns}/g/{gs}/at/…` (`private, no-store` when it adds `/g/{gs}`).
  - `GET /{ns}/at/{ns_id}?…` → `200` `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", … }] }`, immutable, tagged `idx:{ns}` plus `r:{ns}/{name}` per hit. `ns_id` no longer kept → `302` to current checkpoint, cached as head pointer. Kept results are also keyed by what the reader reads whole; those computed before reads narrowed are dropped.
  - Namespace not followed, or sealed/end-to-end with keys lacking (`/keys` answers `4xx` but `429`, or none it can unwrap): `404`. Purged: `410` (`purged`).
  - No checkpoint yet for followed namespace: once reader's grant verifies, `503`, `no-store`, `code: "behind"`, `Retry-After`.
  - Hit `url` is `/r/{ns}/{name}/rev/{id}`, which the service never serves.
- [ ] **SVC-7** (`schema`, `ref`, `refs`, order and paging, Branches) `schema`: exact `$schema` reference, or schema's resource path `/r/{ns}/{name}` for all revisions. `ref`: documents of `{ns}` referencing a resource, combined with other filters: `/r/{ns2}/{name}` any form (live, pinned, to entry); `…/rev/{id}` only pinned to that revision; `…%23{entry}` only naming that entry, pinned or not; `…/rev/{id}%23{entry}` both.

  `ref` hits carry `refs: [{ "path", "ref" }]` (locations and strings matched, as written); other queries' hits don't. A self-referencing document is hit of its own query, `"self": true`.

  Order: `sort` if given; else with `q` descending `score` (from documents of `{ns}` reader may see only); else resource name; ties by resource name. Paging as `/_refs`: `after` a bare resource name, or with `q` or `sort` opaque `next`. Redirect to another `at` (here, `/_refs`, tree listings §B.5) keeps an `after` naming a resource, applied to new result; drops opaque one, starting again.

  Branch preview index: `ref` matches targets as written, naming base; hits are branch's versions of referrers.
- [ ] **SVC-8** (Across namespaces, `gs`, `min`) `GET /_refs?to=<reference>` → redirect to `/_refs/g/{gs}/at/{at}?to=…`; `at` combined checkpoint (§B.5) over only followed namespaces reader may see; path always has `/g/{gs}`.
  - `gs` computed, URLs served, as §B.11.5, over markers: `reads:{ns}` for each followed non-public namespace where reader's grant would be issued a namespace-wide edge grant (§C.5.2); `reads:{ns}:scope:{digest}` where grant allows `read` otherwise, `digest` covering rules limiting it there (its blocks', key scope's, each effective role listing `read`) and the `/principal` values they refer to. Rules referring to `/now`: namespace unreadable. No marker, or neither grant nor cookie: empty set's `gs`.
  - `?min={ns}:{ns_id}`, repeatable, as SVC-1; namespace reader can't see or service doesn't follow: `400`, purged excepted.
- [ ] **SVC-9** (Answers, Coverage, tags) `/_refs` answer `{ "at", "namespaces": { ns: ns_id, … }, "hits": [ … ], "next"? }`, `namespaces` listing what `at` covers.
  - Hits carry `ns` beside a `ref` hit's fields, filtered per item as catalog listings are (§B.11.5), in byte order of `ns`, then resource name.
  - At most `limit` hits per page; `limit` above maximum: `400`. Hits strictly after `after` (`{ns}/{name}`, compared as pair (`ns`, name) split at first `/`); `next` is next page's `after`, absent on last.
  - Hits from sealed/end-to-end namespaces sealed per entry (§E.2.6), never as whole response.
  - Includes branch previews; omits namespaces not yet reached, purged, and sealed/end-to-end without keys; a `min` naming one of those, purged excepted: `400`.
  - `401`/`403` only to reader who may see none of namespaces. Namespace document unreadable for one grant names: `502`; any other: omitted.
  - Tags: `idx:{ns}` per namespace in `at`, `r:{ns}/{name}` per hit.
- [ ] **SVC-10** (Fields in hits) Hits carry facet and `sort` values as `"<path>": [values]`, always a list, facet values in string form (§A.2) without duplicates; path marked both shows facet values.
  - `fields=/a,/b` also returns those indexed fields, `text` included. A path with comma can't be named in `fields`, `counts`, `sort`.
  - `counts=/a,/b` adds `counts` `{ "<path>": { "<value>": <hits> } }` over every hit, not only page.
  - `400`: `fields` path no schema indexed in `{ns}` for document reader may see marks with `x-index`; `facet[…]` or `counts` path none marks `facet`; `sort` path none marks `sort`.
  - Path marked when `x-index` is reachable from schema root along it, whatever data, via `$ref`, `$dynamicRef`, applicators (`properties`, `patternProperties`, `additionalProperties`, `dependentSchemas`, `items`, `prefixItems`, `contains`, branches of `allOf`, `anyOf`, `oneOf`, `if`, `then`, `else`), never `not`, `propertyNames`, `unevaluated*`; array items count at array's path.
  - Marked path with no values at hit: left out of it.
- [ ] **SVC-11** (Private namespaces, Sealed and end-to-end namespaces) Private: served at `/{ns}/g/{gs}/at/{ns_id}?…`, `gs` and URLs as `/_refs`, hits filtered as there over `{ns}` alone; reader with no marker for `{ns}`: `401`/`403`. Sealed and end-to-end: sealed as §E.2.6.

### §A.5 Consistency

- [ ] **SVC-1** (A.5, Read-your-writes, `min` always redirects) Every response states `at`, the `ns_id` it reflects.
  - `?min={ns_id}` once (one namespace), or `?min={ns}:{ns_id}` repeatable: waits (bounded) until checkpoint is at or past `min`; else `503`, `no-store`, `code: "behind"`, `Retry-After`.
  - URL with `min` → `302` dropping it: to current checkpoint, or, on `…/at/{at}/…` whose `at` already includes every `min`, to same URL without it. If it can't tell whether `at` includes them (it no longer keeps that `at`'s per-namespace checkpoints; or `min` names namespace the URL's `at` doesn't cover but current checkpoint does and reader may see): current checkpoint, one hop.
  - `min` naming any other namespace: `400`, body's `min` listing those refused. On `/_refs` and tree listings, `min` naming a purged namespace → current checkpoint, no read check.
  - Never `200` at a URL with `min`.
- [ ] **SVC-12** (Read-your-writes, `min` always redirects) A client takes `min` from `X-Namespace-Revision` on its own write; tool keeps it until listing carrying it was answered `200` after its redirect (ten minutes at most), dropping those a `400` lists.
- [ ] **SVC-13** (Canonical URLs) Redirects give query in one form: parameters sorted by name, then value (decoded UTF-8 bytes); every byte other than ALPHA, DIGIT, `-`, `.`, `_`, `~` percent-encoded uppercase hex. Index and tree services answer `200` only at that form, redirecting others to it. Repeatable parameters (`min`) are sets, sorted likewise. Undefined parameter, or non-repeatable given twice: `400`. An ordered list (`fields=/name,/title`) is one value.

### §A.6 Operations

- [ ] **SVC-14** (Access control) Index service MUST enforce namespace's read permissions by verifying reader's grant locally (§C.6).

## Addendum B — Organising documents

### §B.2 Catalog namespaces: folders and placements

- [ ] **SVC-15** (table, `parents`, `order`) Node name without dot: folder. `{ns}.{name}`: placement of item `/r/{ns}/{name}` (split at first dot; no `item` field); item placeable only where `{ns}.{name}` is at most 128 characters. `parents` entry: live link to folder of same catalog, own optional `order`; none or `[]`: root. Children sort by edge `order` (UTF-8 bytes), unordered after ordered, ties and no `order` by node name.

### §B.3 Links

- [ ] **SVC-16** (B.3, Referential integrity) Link: live (`/r/{ns}/{name}`) or pinned (`/r/{ns}/{name}/rev/{id}`) path on this service, names valid under §3.6. Integrity not enforced. Dangling: placement whose item is deleted; `parents` entry naming a missing folder or anything but live link to folder of this catalog. Tree service drops dangling ones from traversals and reports them.

### §B.4 Manifests (pinned snapshots)

- [ ] **SVC-17** (B.4, Creation, Shared items) A manifest's links are all pinned; tree service generates it for subtree as of catalog `ns_id`. In a DAG, item reached along several paths has one entry per path, with that path and order of its last edge.

### §B.5 Tree service

- [ ] **SVC-3** (B.5) Per coalesced `head` of node, replaces its outgoing edges from `parents`; `tombstone`, `purge` remove them. Also follows content namespaces catalog trusts; marks dangling a placement whose item is gone or in namespace catalog doesn't trust.
- [ ] **SVC-18** (Query API) Served on the tree service's own origin or under a root of its own.
  - Listings → `302`, cached as head pointer, to `/{catalog}/at/{at}/…` or `/{catalog}/g/{gs}/at/{at}/…` (§B.11.5).
  - `at` = combined checkpoint `text(trunc160(sha256(canonical({ ns: ns_id, … }))))` over catalog and followed content namespaces, purged left out.
  - Listing at an `at`: immutable class, tagged `r:{ns}/{name}` per item shown, `ns:{ns}` per namespace in checkpoint; service whose cache origin's purges don't reach purges these itself.
  - `200` at an `at` only if current or that exact result was stored; else `302` to current one.
  - `?min`: SVC-1.
  - Several catalogs: combined checkpoint per catalog; `?min` judged against catalog in the URL, even for content namespace other catalogs follow. **[vectors I.8]**
- [ ] **SVC-19** (table, Parameters) Nodes by node name, items as `/r/{ns}/{name}`. Node or item not in this catalog, or hidden from reader: `404`.
  - `children?of=`: direct children, folders and items, ordered and paginated as `/_refs`, opaque `next`, `total` (visible children). Each node carries `born`, `created` of its first revision (implicit placement: its item's; left out for sealed/end-to-end item or pruned entry), sealed per entry in sealed/end-to-end catalog.
  - `lookup?path=`: node named by path of titles joined with `/`, from folder `root` of file tree, or, where `root` is hidden or missing, visible roots of its subject set; filtered like `children`. Titles compare after NFC and Unicode simple case folding; numbered or escaped display names don't resolve. Shared title: earliest `born`, none last, then node name. Unresolved or invisible: `404`. Catalog without `files`, or sealed/end-to-end: `404`, `code: "not_offered"`.
  - `ancestors?of=`: every path to root. `subtree?of=&depth=`: nested. `roots`: parentless nodes. `orphans`: cyclic nodes, and nodes whose parents are all gone, dangling or cyclic. `problems`: cycles, dangling items, dangling parents. `where?item=`: item's placement and paths. `manifest?of=`: subtree manifest pinned at checkpoint.
- [ ] **SVC-20** (Fresh listings after a write) Relist after own write with `?min` (SVC-1), not `no-store`.
- [ ] **SVC-21** (Behind) Until caught up with catalog and every namespace it follows: listings `503` once reader's grant verifies, `no-store`, `code: "behind"`, `Retry-After`; names awaited namespace, as `ns`, only to reader with unrestricted `read` (§2.1) of catalog. Never serves a listing whose placements dangle for want of data.
  - Caught up = reaching head read when catch-up started (§10), not first checkpoint; restart on same store doesn't wait again.
  - No wait for namespace it can't follow as configured (purged, refused it, unknown, sealed/end-to-end without keys it can have; its placements dangle). Waits after fetch failing for the moment (as SVC-5).
- [ ] **SVC-22** (Items in listings) Items carry content URL and current head, in file tree `file`. Where the `catalog` object sets `"title"` to a JSON Pointer, listings copy string at it in each item's head as `title`, for items in namespaces neither sealed nor end-to-end; placement's own `title` wins.
- [ ] **SVC-23** (Cycles) Cyclic node: in strongly connected set of more than one node, or its own parent. It and all its edges (to parents off cycle too) are left out of traversals, listings, access. `/problems` lists each cycle as its set of nodes; `/orphans` lists them too. Walks bounded at depth 64; deeper paths flagged.
- [ ] **SVC-24** (Shared nodes in DAGs, `mode`) `subtree`, `ancestors`, `where` show node with several parents under each. MUST bound response by depth limit and per-response node limit, and report when cut. A `tree` catalog whose rules allow several parents is served as a DAG.
- [ ] **SVC-25** (Previews of a release) A tree service previewing a release follows branches its release document lists in place of their bases (`checkpoints` holding them); resolves placement to release's branch of its item's namespace, if listed. `403`, no edge grant, to viewer without unrestricted `read` (§2.1) on every listed non-public branch. Previews only, no grants issued. Follows release document's own log (new revision takes effect without restart).

### §B.7 Lifecycle

- [ ] **SVC-26** (Create and place, Deleting content, Deleting a placement, Deleting a folder, Restoring) Placement of not-yet-existing item dangles until it exists. Deleted item's placements dangle, drop out of listings and access immediately, reported for cleanup. Deleting a placement removes item from this catalog only. Deleting a folder doesn't cascade: children appear under `/orphans`. Restoring a folder or placement re-attaches everything that pointed at it.

### §B.9 Self-placing documents (optional shortcut)

- [ ] **SVC-27** (B.9, Not accepted by default) Where configured to accept `$parents` for trusted namespace, content document's `$parents` is implicit placement; explicit one for same item wins, live, deleted or purged. No access derives from self-placements unless content namespace's rules protect `/$parents` as strictly as catalog protects placements; then a Place of self-placed item also needs `move` on each folder of its `$parents`, and no widening (§B.11.4).

### §B.10 Access control

- [ ] **SVC-28** (Services that list content) MUST enforce read permissions for every node and item listed, titles and structure included.

### §B.11.1 `$access` and roles

- [ ] **SVC-29** (`$access`, role meaning, tree powers, Placements) `$access` on folders and placements maps subjects (`group:…`, `user:…`) to role names for items below. A role's verbs and rules come from the content namespace's `roles`; a namespace not defining it grants nothing through it. Catalog namespace's `roles` define tree powers: `move` (nodes out of or into folder), `place` (new items directly into folder).

### §B.11.2 Effective access

- [ ] **SVC-30** (Subjects, Walk up, Where a path stops)
  - Subject set: `sub` if it starts with `user:`, plus `group:{g}` per group.
  - A subject's roles at node: union, over every path from node up to root, of role names `$access` gives it along path, node's own included. An item's roles are those at its placement; caller's, union over its subjects.
  - A path stops after node with `inherit: false`; at tombstoned, purged, dangling or cyclic node it ends, that node contributing nothing.
  - Dangling placement grants nothing, except for item in trusted namespace: `create` for one that never existed; `restore` for tombstoned, unpurged one, going to those of roles it had when deleted that it would have now if live.
- [ ] **SVC-31** (Through the key) A role counts for verb in content namespace when namespace defines it with that verb and catalog's key there may grant it to caller:
  - key's `can` lists verb; its `roles` scope allows role; its `sub` scope, if any, matches caller's `sub`, which must start with `user:`; role was collected through caller's `sub`, or group its `groups` scope allows.
- [ ] **SVC-32** (Across catalogs, Allow-only) Each catalog the item's namespace trusts issues grants from its own computation; total access is their union. No denies.
- [ ] **SVC-33** (Tree powers) `move`, `place` apply only at folder where role granting them is assigned; where its `$access` sets `"inheritPowers": true`, roles collected on walk up from it grant them there too. Count only at live, non-cyclic folder, only through subjects catalog's key in catalog may assert. Folder without `$access` but with parents: subject's role has power when its same role has it at every parent; tombstoned, purged, dangling or cyclic parent gives none.

### §B.11.4 Issuing grants

- [ ] **SVC-4** (Resolve, Sign a root grant, Read-your-writes, `checkpoint`)
  - `POST /grants` for item signs root grant for exactly that resource, carrying roles kept at current checkpoint for wanted verb (§B.11.2), absolute `exp` within `maxTtl`; roles' rules aren't evaluated.
  - `POST /grants`, `POST /read-grants` accept `?min` (SVC-1): decide at checkpoint at or past every `min`, or `503`.
  - Answers carry `checkpoint` `{ ns: ns_id, … }`, the `ns_id`s at decision of every namespace it read (catalog, each named item's namespace, content namespaces read for roles or `includes`): beside each grant, never inside, and beside refusals decided at it (`403`, `404`, `409`, `410`). A refusal from state it doesn't pin has none and isn't cached, nor is refused `/read-grants` item. Grants' own `at` is catalog's `ns_id` alone.
  - `POST /grants` → `200` `{ "grant", "checkpoint", "parents"?, "head"? }`; `parents`, `head` (as decided) come with a Move or Unplace or delete.
  - `POST /read-grants` → `200` `{ "items": [{ "item", "grant"?, "public"?, "keys"?, "keysWithheld"?, "status"?, "code"? }], "checkpoint" }`, one entry per item in request order; `status`, `code` for item refused or undecided.
- [ ] **SVC-34** (Sign a root grant) Item requests other than Place: `403` first for item in namespace catalog doesn't trust. Those other than Create are then refused as Restore's are, in order: purged namespace `410`; `404`; purged item `403` without role making it visible (§B.11.5) at its placement, else `410`; `403` when no role is kept.
- [ ] **SVC-35** (organising requests) Grants for catalog namespace, no `roles`, verb as write needs unless a request gives another: `create` for Place and Create a folder, `append` for Move, `delete` for Unplace or delete a folder. Each fixes `/resource` to node name and `/doc/parents` to exactly requested target set, compared by `href` (`order` the writer's, §B.2).
  - Unless a request gives its own answers, in order: `400` malformed; `404` for a `node` (a new folder's excepted) that isn't an untombstoned node of this catalog, a `to` entry that isn't a live folder of it, or, to caller not in `catalog-admins`, either hidden from it (a new folder's name excepted); `403` for failed requirement, or an `item` in namespace catalog doesn't trust; then `409`.
  - End-to-end catalog: no organising grants (`404`, `not_offered`).
  - `catalog-admins` need no tree power (a Place still needs place list). Others also need non-empty `to` where request takes one, and can't move, unplace or delete a node without parents or with parent hidden from them.
- [ ] **SVC-36** (Place, Unplace or delete a folder, Create a folder)
  - Place (`{ "item", "want": ["place"], "to" }`): caller in content namespace's `catalogs.{catalog}.place` list, and role with `place` on every folder in `to`.
  - Earlier placement deleted: grant carries only `restore`, restoring with root replace that must not widen; if placement is live again when used, write is append, refused at step 2.
  - Placement live: `409`; purged: `410`; both after the `400`, `404`, `403` answers.
  - Unplace or delete (`want: ["delete"]` on node): role with `move` on every current parent; grant fixes `/doc/parents` to exactly those (SVC-35).
  - Folders restored only by `catalog-admins`, under grants of their own; request naming a tombstoned folder: `404`.
  - Create a folder (`{ "node", "want": ["create"], "to" }`): `node` a folder name (`400` otherwise) that no node has or had and no `parents` entry or accepted `$parents` names, hidden included (`409` otherwise); role with `move` on every folder in `to`.
- [ ] **SVC-37** (Move, No widening)
  - Move (`{ "node", "want": ["move"], "to" }`): role with `move` on every current parent node leaves and every folder in `to`; no widening. `to` entry that is node or below it: `403`.
  - May also change node's other members, `$access` excepted; a rename is a move to node's current parents.
  - Unless `catalog-admins`: patch set must begin with a `test` of `/parents` against node's parents as decided (answer's `parents`).
  - No widening, unless `catalog-admins`: for every subject, roles of every node after write are subset of those before. Move: roles at node computed as for live items, even for item deleted or not yet created. Re-placing or restoring: compared with frozen rows.
  - A role counts as present before if it, or role including it, was; `includes` is transitive, read from item's own content namespace, trusted as declared. Folder roles compare by name.
- [ ] **SVC-38** (Create) Create (`{ "item", "want": ["create"] }`): caller's roles at item's placement counting for `create`; grant fixed to that name with `can: ["create"]`. In order: purged namespace `410`; name exists or existed in content namespace `409`; `403` if item has no placement in this catalog or no role is kept.
- [ ] **SVC-39** (Restore) Restore (`{ "item", "want": ["restore"] }`): caller's roles at item from the `effective` rows kept when service saw tombstone, keeping those counting for `restore` both there and at item's placement now (as for live item); grant fixed to that name with `can: ["restore"]`.
  - Item live when used: write is append, refused at step 2. Item must still have placement here; frozen rows stay those of its deletion, even if re-placed.
  - In order: purged namespace `410` for every name; name never existed `404`; `403` without role making item visible (§B.11.5), counting both at placement now and, if deleted, in its frozen rows; purged item `410`, live item `409`; `403` if no role is kept, no placement, or restore would widen.

### §B.11.5 Reads and listings

- [ ] **SVC-40** (Listing URLs carry the subject set)
  - Combined checkpoint with only public namespaces: served unfiltered at `/{catalog}/at/{at}/…` while they stay public. Any other listing: `/{catalog}/g/{gs}/at/{at}/…`.
  - `gs` is `all`, or `text(trunc160(sha256(canonical(subjects))))`, `subjects` caller's `group:` entries, no duplicates, UTF-8 byte order, adding its `sub` only if catalog has direct entries for that user or catalog's key in content namespace it trusts has a `sub` scope.
  - Listing URL without `at` is under prefix too, with the `gs` exchange's `prefixes` gives; grant in `Authorization` redirects one without `/g/{gs}` to its `…/g/{gs}/at/{at}/…` URL, `private, no-store`.
  - A grant in `Authorization` reads only at its own `gs`, or `all` where it qualifies; `403` elsewhere. Needing `/g/{gs}` with neither a grant verifying in followed namespace nor cookie service verifies: `401`. Tree service without §B.11 serves only `all` (`403` otherwise).
  - Edge admits request only with edge grant bound to that exact `gs`: cookie minted with service's own key for prefix `/{catalog}/g/{gs}` at its own exchange endpoint, following §C.5's issuance rules (`application/json`, `415`, credentialed CORS). Service applies §9 to its own origin, keeps which subjects each `gs` stands for, and applies `exchangeRate` (§6.6) to its exchanges, buckets shared across instances.
  - `gs` cookie other than `all` authorises listings of that subject set only; `problems`, `orphans`, manifests `403` under it. Listings cached per (listing, subject set, `at`). **[vectors I.8]**
- [ ] **SVC-41** (Listings are filtered by their subject set)
  - Node visible to subject set when walk up from it collects a role counting for `read` (§B.11.2; roles, definitions, keys as of content namespaces' `ns_id`s in listing's combined checkpoint); caller's `sub` is set's `user:` subject, set without one fails a `sub` scope.
  - Role's rules and key's scope `rules` must pass as read evaluates them, `/principal` holding only groups key may assert and, as `roles`, that role. Item: role of its own content namespace, `/resource` item's name. Folder: role of some trusted content namespace whose rules don't refer to `/resource`, through key whose scope `rules` refer only to `/principal/groups` and `/principal/roles`. A rule referring to `/now`, or to anything in `/principal` but `groups` and `roles`: role doesn't count.
  - `children`, `subtree`, `roots`, `ancestors`, `where` show visible nodes only, only paths through visible folders, nothing about a hidden node, not even a count. A visible node with no visible parent is root for that subject set: `roots` lists it, paths end at it.
  - Request naming a hidden node is answered as one naming a node not in this catalog (`404`, body included): listings, catalog node in `/read-grants`, and, from caller not in `catalog-admins`, organising requests (a dangling placement judged as if its item were live). Exceptions, `409`: new folder's name; a Place of item whose placement is live.
  - Limits, cut markers, pagination count visible nodes only; `/read-grants` applies same test to catalog nodes and keys.
- [ ] **SVC-42** (unfiltered listings, `g/all`)
  - `problems`, `orphans`, `manifest` are unfiltered; need unrestricted `read` (§2.1) on catalog and content namespaces they cover (manifest: those of items it pins; others: every one in combined checkpoint; public counts), else `403`.
  - Edge grant bound to `all` only after checking every non-public namespace in its combined checkpoint: reader's grants would have to be issued a namespace-wide edge grant (`/r/{ns}` and `/ns/{ns}`, §C.5.2); it expires with earliest of those. Under such a cookie: `403` at an `at` including a namespace not in its combined checkpoint at issuance.
  - Default-format minting takes issue time as `exp` less 15 minutes unless recorded.
  - Without edge grants, `g/all` listings are `private`, `max-age` no longer than such a cookie's lifetime.
- [ ] **SVC-43** (Listings never embed signed URLs, Every item at once) Listings never embed signed URLs. `POST /read-grants { "items": [...] }` → `no-store`, short-lived grants carrying roles that make each item visible, fixed to exactly `/r/{ns}/{name}` and `/r/{ns}/{name}/…`.
  - Item in public, non-sealed namespace: `"public": true` instead of grant. Catalog node, or item in public sealed namespace: key alone. Sealed item in private namespace: grant and key.
  - Item refused as `POST /grants` refuses item request, only roles making it visible counting: hidden item is answered as one without placement (`403`). Catalog node: `400` in catalog neither sealed nor end-to-end, otherwise `404` if hidden.
  - Item `4xx`: refused; `5xx`: undecided. Service capping items per request: above cap `400`.
- [ ] **SVC-44** (Keys, Which keys, Checked like grants, Which epochs, `keysWithheld`)
  - Sealed items, and nodes of sealed/end-to-end catalogs: `/read-grants` also returns per-resource keys `K_r` (§E.2.1), wrapped to caller's public key (§E.2.3 format), only for items passing same role check as grants, public sealed namespaces included.
  - Item in sealed (E2) namespace: own `K_r`; in E3: none. Catalog sealed or E3: item's placement node also gets its `K_r`. A catalog node named in `items` and visible: its `K_r`, no grant.
  - Keys cover current epoch and `encryption.historyEpochs` before it, or every epoch held if no cap.
  - Grant without public key: grants returned, `"keysWithheld"` and reason in place of keys.

### §B.11.7 Catalog storage

- [ ] **SVC-45** (Maintenance, Role definitions, Deleted items, Consistency)
  - Change to node's `$access` or `parents`, tombstone, or item's deletion or restore recomputes `effective` for the subtree; content namespace's `/roles` change recomputes the listing visibility it affects.
  - Deleted item keeps its `effective` rows as when tombstone was seen (marked tombstoned, not recomputed); deleted placement's likewise until placed again.
  - Checkpoints stored in the same transaction as `effective`; their catalog `ns_id` is the `at` of every grant issued from it.

### §B.11.8 Staleness and revocation

- [ ] **SVC-46** (Overtaken decisions) A Move grant's `exp` is at most catalog's `maxLag` (§7.4) after its decision.

## Addendum C — Capabilities and access

### §C.1 Grants

- [ ] **AUTH-1** (Fields, Narrowing only restricts, Format, Verification) Grant = `Authorization: Bearer <grant>`: root block signed by namespace-document key, then zero or more narrowing blocks, each chained to previous signature. Biscuit v3 (§C.8). Verifying needs only published keys: namespace's, its local bases', deployment operator keys.
  - Root block only: `sub`, `groups`, `attrs`, `signers`, `enc` (other form: `401`). Narrowing blocks only: `via`.
  - `can` ⊆ `read`, `create`, `append`, `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export`, `prune`. `*` is for keys only; in block `401`. Root block without `can` MUST list `roles` (`401`); verbs then come only from roles.
  - `nbf` (optional) and `exp`: absolute RFC 3339; a block is valid from `nbf` until `exp`. `at`: an `ns_id` of namespace itself or `{ "ns", "id" }`; optional unless key has `requireAt`.
  - Narrowing block may only reduce `ns`, `can`, `roles`, set later `nbf` / earlier `exp`, add `rules`, add `via`; a member it leaves out restricts nothing. Non-narrowing values (other than `"*"`) restrict nothing.
  - Root block MUST carry `kid`, `sub`, `ns`, `exp` and only its listed members. Any violation: `401`. Effective principal: root `sub`, `groups`, `attrs`, with `via` listing delegatees in order.

### §C.1.1 Roles

- [ ] **AUTH-3** (Roles, Expanded at the gate, Combination, Issuers are bounded) Grants carry role names only, expanded at gate against configuration in force at request. Unknown names grant nothing; `roles: []` no verb. Roles are alternatives, all else conjunctive (§C.2 items 2, 4). Issuers bounded by key scope's `roles` (§C.4).

### §C.1.2 Attributes and time

- [ ] **AUTH-10** (table, Principal attributes) Rules read `/principal/{attrs,groups,roles}` (issuer-set; root `attrs` bounded by key scope's `attrs`), `/doc/…`, `/action`, `/resource`, `/writes` (server-set), `/now` (server clock).

### §C.2 Checking requests

- [ ] **AUTH-2** (intro, Verify the chain) Checked at §6.2 step 1 (items 1–3, first part of 4), step 2 (item 2's retry check, settling), step 6 (`*`-key guard, then item 4), every read (item 5).

  Unverified shape errors first, in order: `grantSize` (`413`); blocks unparseable or breaking §C.1/§C.8 (`401`); `rulesPerGrant` (`413`); invalid rule (§6.4.2, `401`). Then §7's `ns` check (`403`), before any `401` below. Then check: root signature (key in configuration in force), every block's signature, `nbf` ≤ now < `exp` per block, revocation (§C.4), key scope (AUTH-6).

  A grant that can allow `read`, from a `readScope: "resource"` key, not fixing `/resource` (§2.1) fails scope: `403` on every request not ignoring grant (writes included), `404` for read of resource in private namespace. No usable grant (missing, malformed, badly signed, revoked, expired, not yet valid): `401`. Valid grant not allowing request: `403`.
- [ ] **AUTH-11** (Check the verbs, Several verbs, Settling, Later steps, Unrestricted `read`, Operator grants) Verb allowed when `ns` and `can` intersected over all blocks (and key's `can`) allow it and, with roles, effective role lists it. A request checks its action's verb, except:
  - **Several verbs.** Resource `PATCH` under `If-Match`, and batch item whose first step is patch set under `ifMatch`: `append` and `restore`. Those without usable precondition, and blob upload: `create`, `append` and `restore`.
  - **Candidate verbs**: those passing this check and item 4's step-1 rules with `/action` = verb, only roles listing it counting. A write with one passes; `PATCH`/item without usable precondition then `428` at step 2.5.
  - **Settling.** Step 2.2 settles verb of a `PATCH` under `If-Match` or such batch item; non-candidate refused. Idempotent retry of one: `200` only if recorded entry's verb is candidate (restore if parent is tombstone, else append); other retries have their one verb.
  - **Later steps** of batch item: patch set after a `"delete"` step is restore, else append.
  - **Unrestricted `read`.** Branching and remote registration also check `read` on base, which grant must read unrestricted (§2.1), public or not. Key-scope and block rules referring only to `/action`, `/principal`, `/now` must pass with `/action` = `read` (rest: step 6); role counting for `read` must pass all its rules against a `read` envelope.
  - **Operator grants** check `config` for a namespace's creation and a remote branch's (mirrored schema histories included), and `purge` or `purge-ns` for a forced purge.
- [ ] **AUTH-12** (Build the principal, Rules, Reads) Principal: `{ id: root sub, groups, roles: effective roles, attrs, via, grant: grant id }`. Step 1 evaluates key-scope, block and role rules referring only to `/action`, `/resource`, `/principal`, `/now` (`/action` = verb checked); step 6 all rules (verb as settled where there were candidates), then namespace rules; reads use a `read` envelope (§6.4.1). With roles, role rules must pass for at least one effective role listing verb. Failing grant, key or role rule: `403`.
- [ ] **AUTH-13** (`*` keys) Need grant chained to a `can: ["*"]` key (namespace creation: creating operator grant), else `403` (`forbidden`):
  - config write (batch `config` change included) covering or overlapping a §7.4 member, or setting `read` to `public`;
  - branch `patches` covering or overlapping one of those members (`*` key of base);
  - prunes §8.6 names.

  Guard runs first at step 6, after namespace-document validation. Forced purge: own step-1 guard (§6.1).

### §C.3 Attribution and signatures

- [ ] **AUTH-4** (Grant per revision, Stored grant form; §C.3.1 Reading grants) Each revision stores its grant id, `trunc160(sha256(canonical(root block)))`; grants are stored non-bearer (§C.8).
  - `GET /ns/{ns}/grants/{gid}` answers `{ "id", "root", "stored" }`; `stored` = authority block (protobuf `SignedBlock`, unpadded base64url) of first token recorded with that id: signature verifies under `root.kid`'s key, its one `grant_block` string equals `canonical(root)` byte for byte, `id` = `text(trunc160(sha256(that string)))`.
  - Serves grants recorded by this namespace's log entries and, in local branch, its bases' up to their `at`, recursively. Other: `404`; purged namespace `410`.
  - Needs unrestricted `read`; immutable. Sealed namespaces: sealed per ENC-2; a grant recorded only by a branch's base under the branch's current epoch.
  - End-to-end: in clear (sealed if from before raise from `sealed`), `Cache-Control: private` not immutable class, `no-store` in `CDN-Cache-Control` and `Surrogate-Control`.

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
- [ ] **AUTH-16** (chain, Verifiers) Verify against keys in force when revision was written, along one chain: revision `Signature` → entry with that `kid` in `signers` of root block of grant its reference names → key signing that root block (key of configuration write was checked against: namespace document in force at its log entry, after batch's config change, plus in branch its local bases' keys at `created`; or operator key in force at `created`) → namespace log or operator key history. A branch's verifiers also follow its local bases' namespace document histories. `revoked` isn't checked. A failing signature or incomplete chain is reported as such.

### §C.4 Keys, scopes and revocation

- [ ] **AUTH-6** (Keys, Key scope; §C.1.2 Principal attributes) Namespace document lists `keys`.
  - **Entries**: `kid` (unique within `keys`); `alg: "Ed25519"`; `pub` (unpadded base64url, 43 chars); `can` (none: no verb allowed); optional scope fields (`maxTtl`, `maxLag`: ISO 8601 durations).
  - Root blocks must be signed by listed key. Changing keys/scopes: config write needing a `*` key.
  - **Scope** restricts every grant key signs:
    - `can`: allowed verbs (all for `*`); root block `can` with another verb fails scope; role verbs bounded by it;
    - `maxTtl`: max root-block lifetime remaining, `exp − max(now, nbf)`;
    - `sub`: regex (§6.6) whole root `sub` must match;
    - `groups`, `roles`: `{ "allow": [...] }` or `{ "deny": [...] }` on asserted values;
    - `attrs`: JSON Schema asserted `attrs` must validate, held to rule's `schema` limits (§6.4.2);
    - `rules`: added to every grant; `readScope: "resource"`: grants that can allow `read` must fix `/resource` (§2.1);
    - `rate`: lower per-principal write rate `{ "rate", "burst" }` as in `limits`; `ratePerPrincipal` takes smaller rate and burst; its `429` names `ratePerPrincipal`;
    - `maxLag`: stricter `maxLag` for `at`.
  - **`requireAt`**: `true`: `at` must be an `ns_id` in chain of namespace grant is checked in (base's key in branch too); namespace name: in that namespace's chain. Either way `at` must not have been superseded in that chain more than `maxLag` before issue. Issue time = later of root `nbf` and `exp − maxTtl`, of those existing; neither: scope fails. `maxLag` = smaller of key's and that of namespace document of namespace `at` belongs to (default 60 seconds).
- [ ] **AUTH-17** (Revocation, In a branch; §C.8 Keys, Revocation ids) `revoked` lists revocation ids: root block's = its grant id in text (§C.3); narrowing block's = `text(trunc160(sha256(its Biscuit signature)))`.
  - A chain containing any revoked block is rejected. Per namespace; in branch also rejected if any block is revoked in any local base.

  **[vectors I.14]**
- [ ] **AUTH-18** (Keys follow the base) A branch accepts its base's current keys as well as its own.
  - Key added to base later works in branch; removed or replaced in base stops working in every branch. Shared `kid` is base's, accepted only while base has it with same `pub`.
  - Base later adds a `kid` branch added itself: only base's entry accepted; base removes it again: branch's own applies again. A `kid` copied from base at creation never falls back.
  - Recursive through every local base; branch can't refuse base key.
- [ ] **AUTH-19** (Bootstrapping, Operator grants) Creating namespace needs deployment operator key.
  - A grant for not-yet-existing namespace names it in `ns` or uses `"*"`, which only operator-signed grants may (else `401`). Branch creation: a `branch` grant on its base.
  - Operator grants authorise exactly (verb checked): namespace creation with genesis document (`config`); remote-branch creation, mirrored schema histories and their `nonce` settings included (`config`); forced purge/namespace purge (`purge`/`purge-ns`). Any other request under one: `401`; requests needing no grant ignore it (public reads, `GET /`, `DELETE /edge-grants`); `GET /ns/{ns}/principal` describes it.
  - Root `kid` naming both operator key and namespace key: verified against namespace key first; namespace grant if that verifies.
  - Operator grant: forced purge and `GET /ns/{ns}/principal` on nonexistent namespace `404`; `ns` check still `403` first; purged `410`.
- [ ] **AUTH-20** (Operator key history) Operator keys are a JWK Set (RFC 7517) at `GET /`'s `jwks_uri` (default `/.well-known/patchlog-keys`), `application/jwk-set+json`, publicly cached for minutes.
  - Each key: OKP Ed25519 JWK with `kid`, `use: "sig"`, `"patchlog": { "from", "until"? }` (RFC 3339 period in force); `from` MUST be no later than first entry written under grant key signed.
  - Authorises only within its period: grants it signed `401` before `from` and after `until`; verify only for revisions created within it.
  - Keys never removed, `kid`s never reused, no namespace keys.
  - Verifiers take URI from `GET /`; only a `200` with a JWK Set body having a `keys` array is read of history, else failed read, never empty history.

### §C.5 Reading

- [ ] **AUTH-21** (Read modes, Public, Grant, The stream is metadata, Three exceptions) Namespace document `"read": "public" | "grant"` (default `"grant"`).
  - Public: cached publicly. `grant`: served with grant in `Authorization`, or via edge grants issued for verified grant with `read` (not in cache key; downstream caching `private`).
  - `/ns/{ns}` and everything under it (events stream and long-poll included) need unrestricted `read` (§2.1); resource's own URLs (events included) need `read` on that resource.
  - Origin answers with grant in `Authorization`, `no-store`: gestures listing (filtered per resource), `GET /ns/{ns}/principal`, `POST /ns/{ns}/keys`.

### §C.5.2 Issuing edge grants

- [ ] **AUTH-7** (Scope, Request, Answer, Browsers, What a cookie authorises) `POST /edge-grants` on origin takes grant in `Authorization`, or `{ "grants": [ … ] }` with `Content-Type: application/json`; issues per grant for every namespace all its `ns`-carrying blocks name.
  - **Scope.** Smallest edge prefix grant allows: `/r/{ns}/{name}` (one per name) when its rules fix `/resource` (§2.1); else `/r/{ns}` and `/ns/{ns}`.
  - **Answer.** `200`, `{ "prefixes": [ … ], "exp" }`, one `Set-Cookie` per prefix (named per §C.5.3): no `Domain`, `Path` = prefix, `Secure`, `HttpOnly`, `SameSite=None` when deployment names credentialed origins else `Lax`.
  - **Lifetime.** Earliest `exp` among grant's blocks or 15 minutes, whichever sooner. A prefix given by several grants: one cookie, as long as longest; body `exp` = earliest, RFC 3339.
  - **Browsers.** Credentialed responses name calling origin from deployment's list, `Access-Control-Allow-Credentials: true`, `Vary: Origin`; never `*` or echoed `Origin`.
  - **Authorises** only `GET`/`HEAD` under its prefix. Origin-minted cookies never cover service's URLs; service's never cover core ones.
- [ ] **AUTH-22** (Refusals, table, All or nothing, Rate) `POST /edge-grants` refuses:
  - authentication disabled: `404` (`not_offered`), before reading body;
  - body not `application/json`: `415`; neither `Authorization` nor body: `401`;
  - body with no grants, over 50, or together with `Authorization`: `400` (`bad_input`); larger than 50 grants of `grantSize` can be: `400` (`bad_input`), before parsing; single grant over `grantSize`: `413` once decoded;
  - nonexistent namespace, or grant failing verification there: `401`/`403` as for any request;
  - `403`: grant without `read` there; block/key-scope rules referring to `/resource` where it isn't fixed (§2.1), or to `/now`; roles with none qualifying (§2.1); block/key-scope rules failing now against a `read` envelope for its principal, `/resource` set to each name it fixes, if any;
  - purged namespace: `410`, `code: "purged"`, if grant verifies in it;
  - over 100 distinct prefixes: `400` (`bad_input`); empty `exchangeRate` bucket of principal: `429`, `code: "rate"`, `limit: "exchangeRate"` (both only once nothing else is refused).

  Precedence: body with `Authorization` (`400`) before non-JSON body (`415`), both before `401`. All grants and namespaces are covered, none skipped: `401` if any refusal is `401`, else `403` if any is `403`; `410` only when every refused namespace is purged and grant verifies in each, `ns` and `head` naming first refused in grant and root-block order. Once nothing is refused (prefix-cap `400` included), one token is drawn, however many grants, from each distinct principal's `exchangeRate` bucket (keyed as write buckets are), none from write buckets.

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

- [ ] **AUTH-25** (Least privilege) A service gets `read` for what it follows; one that writes back gets narrowing block with `writes within` its own paths, without `restore`, `delete`, `purge`, `config`, `branch`, `purge-ns`, `export`, `prune`.
- [ ] **AUTH-26** (Services verify as the origin does, Filtering proxies, Services that re-publish content MUST enforce reader permissions)
  - Local grant verification applies keys, scopes (`readScope` included), revocations, `grantSize`, `rulesPerGrant` as §C.2 does.
  - A filtering proxy serving namespace's `/ns/{ns}/…` view per document pages and derives cursors itself, never passing upstream ones on.
  - A re-publishing service MUST filter search, tree and catalog results by reader's verified grant; private results cached per `gs`, never with embedded bearer URLs.

### §C.7 Private content and guessable hashes

- [ ] **AUTH-9** (A nonce in every patch set, Requiring it) A write that `add`s `/$nonce` of fresh form is left out of `writes` (§6.4.1); validation doesn't see key (§6.2). Namespace MAY set `"nonce": "required"` (default `"optional"`).
  - Then at §6.2 step 3 resource create, append or restore MUST yield document with top-level fresh-form `$nonce` differing from parent's (restore: last live document's); else `422`, `code: "nonce"`. A failed `test` or patch application is reported first, as `invalid`.
  - A server also enforcing sealed-namespace rule (§E.2.5) answers `422 nonce` at same point.
  - Exempt: deletes, config, branch and prune writes. Applies to every patch set, whatever its origin.
- [ ] **AUTH-27** (Requiring it)
  - A branch copies setting and can't turn off its base's. A base can't start requiring it while dependent doesn't. Setting/changing needs a `*` key (all §7.4). End-to-end namespace: `422` (Addendum E, Levels).
  - Remote branch of base whose current namespace document requires nonces MUST be created requiring them (`422` otherwise).
  - Schema namespaces mirrored for remote branch start `optional`; take source's setting by config write once their history is in, under creating operator grant; stay `optional` if source's namespace document can't be read.
  - A snapshot import's upstream namespace takes its target's setting. Merge tools building resolution or squash set add fresh `$nonce` where required.
- [ ] **AUTH-28** (Blobs, Encryption) Sealed namespaces and where nonces are required: created blobs carry nonce (§7.8). `$nonce` refresh: ENC-5.

### §C.8 Encoding: Biscuit v3

- [ ] **AUTH-29** (One block, one fact, Keys, Sealed tokens, Stored form, Transport) Each §C.1 block = one Biscuit v3 block with exactly one fact `grant_block(<string>)`, block's canonical JSON; MUST be I-JSON and equal its own canonical form (`401` otherwise). Authority block carries the root block, each appended block one narrowing block, in order.
  - Anything else in block (other facts, rules, checks, scopes, public keys, non-empty context, unused symbol), third-party block, or signature not over Biscuit's version 1 payload: invalid (`401`).
  - Datalog not evaluated: server verifies signature chain and applies §C.2 to JSON blocks (validity from their `nbf`/`exp`).
  - All signatures (ephemeral narrowing-block keys included) Ed25519, verified strictly (RFC 8032, `S < L`); other algorithm `401`.
  - Root key named by `kid` inside root block, not `rootKeyId`, looked up in configuration in force; wrong `kid` fails verification.
  - Sealed tokens accepted. Stored form: authority block with its signature and next key only (AUTH-4).
  - Sent as `Authorization: Bearer <token>`, URL-safe base64, with or without `biscuit:` prefix. `grantSize` (decoded bytes) and `rulesPerGrant`: `413` (`code: "limit"`), in §C.2 item 1's order, on every request not ignoring grant (§7).

  **[vectors I.14]**

## Addendum E — Encryption

- [ ] **ENC-8** (Levels, Changing it, After a raise) Level = `encryption.level`: `at-rest`, `sealed`, `e2e`. Lowering or removing it: `422` (`invalid`); so is raising `sealed` to `e2e` without new epoch (§E.2.1). A namespace document holding member its level refuses (§6.1, §7.4, §8.6, §C.7): `422` (`invalid`), whichever member write changes. Raise to `sealed`/`e2e` purges namespace's cache tag; then `Last-Modified`, `Repr-Digest`, `/heads` fields, caching, `…/raw` and gestures listing follow new level; after raise to `sealed`, earlier content is served as §E.2.2 says for pre-sealing content.
- [ ] **ENC-9** (After a raise) After raise to `e2e`, served as at prior level (in clear, or after raise from `sealed`, sealed per §E.2.2 with last pre-raise epoch and `pad`): revisions, resource log entries, namespace documents and log ranges from before raise, grants first recorded before it, and blobs those revisions reference, even where later revisions do too. Sealed blobs keep epoch URLs under those revisions' epochs only.
  - `/keys` gives pre-raise epochs' keys as at E2 (§E.2.3), window judged against current epoch, omitting (not `403`) those grant wouldn't get there.
  - E3 prune with `H` from before raise doesn't change how `/rev/{H}` is served; from `sealed`, server first stores `H`'s sealing (§E.2.2) if none.
  - No log page spans raise: it lies before namespace entry (`config` or `batch`) that made namespace end-to-end, and in resource log before first entry written with or after it.
- [ ] **ENC-10** (Branches and dependents, Branches of a raised base)
  - Creating branch below its base's level, or at `e2e` over base that isn't: `422` as branch field (§7.4); likewise config write raising branch to `e2e` over base that isn't. Other config writes aren't checked against base's level.
  - Write raising namespace above dependent's level: `409` (`in_use`, with `dependents`).
  - Branch of base raised to `e2e` can't be created, or raised to `e2e`, with `at` before that raise (`422`, branch field).
  - Such branch serves pre-raise read-through content as base does. Its `/keys` gives base's keys as at E2, `K_r` derived with base's `ns`, for base epochs §E.2.3 selects (remote branch: fetched from its source with its own grant). Readers accept base's `ns` in that content's `pl` and `kid`.

### §E.1 At rest

- [ ] **ENC-1** (What it is, What it doesn't change, Purge becomes cryptographic, Stored digests) E1: origin encrypts stored patches, snapshots and grants with KMS keys; nothing else changes. Key per resource: purge destroys it. Stored `/heads` `size`/`digest` (§7.4) at E1: omitted, computed at read time, or kept under resource's key.

### §E.2.1 Keys

- [ ] **ENC-11** (Epoch keys, Per-resource keys) `K_e`: 256-bit random, `kid = "{ns}#{e}"`; current epoch = `encryption.epoch`. Key material never in namespace document or log. `K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name)`, 32 bytes. **[vectors I.7]**
- [ ] **ENC-12** (Rotation) Config write incrementing `encryption.epoch` starts new epoch, recorded in namespace chain; needs a `*` key (§7.4). Already `sealed`/`e2e`: write changing `epoch` other than adding one is `422` (`invalid`). Later revisions sealed under new epoch; old keep theirs.

### §E.2.2 Sealed representation

- [ ] **ENC-2** (intro, Algorithms, Protected header, What gets sealed, table) In sealed namespace each payload below is compact JWE (RFC 7516): `alg: "dir"`, `enc: "A256GCM"`, protected header `{ "alg", "enc", "kid": "{ns}#{e}", "pl" }`, canonical JSON (§3.1). Ids in `pl` in text form; empty is `""`.
  - Served alone: `Content-Type: application/jose`. Resource log range or resource long-poll answer: JSON array of entries' JWEs, `application/json`. SSE event `data`: one JWE.

  Payload: key, epoch, `pl`:
  - `/rev/{id}` document: `K_r`, revision's epoch, `{ "ns", "name", "id", "kind": "doc" }`.
  - Resource log entry, in range or `revision`/`tombstone` event: `K_r`, revision's epoch, `{ "ns", "name", "id", "kind" }`, `kind` = `rev` or `tombstone`.
  - Resource `purge`/`prune` event: `K_r`, epoch current when sealed, `{ "ns", "name", "kind" }`, `kind` = event type.
  - Namespace document at `ns_id`: `K_e`, epoch in force at `ns_id`, `{ "ns", "id": ns_id, "kind": "doc" }`.
  - Namespace log range, long-poll answer or event: `K_e`, epoch current when sealed, `{ "ns", "range": [since, last] }`, bounds of page actually served (`[since, id]` if empty). Event: range of its one entry, `[prev, id]`, plaintext entry.
  - Grant (§C.3.1): `K_e`, epoch in force at first namespace log entry recording it, `{ "ns", "grant": gid }`.

  Epoch in force at namespace entry = `encryption.epoch` of document in force there. A revision's epoch = current one when first sealed; likewise namespace document or grant from before sealing, and grant only base records.

  **[vectors I.13]**
- [ ] **ENC-13** (What stays in the clear, Stored once, served forever) Sealed namespace:
  - A revision's exact `created`, document's length and digest aren't sent outside sealed logs.
  - Sealed bytes of revision, document, resource log entry or grant: produced once, stored, served identically thereafter. Sealed revision `ETag: "{id}.{e}"`; sealed namespace document `ETag: "{ns_id}.{e}"`.
  - Exception, namespace log ranges: MAY keep only some, oldest evicted first, and seal evicted range again on request, fresh bytes, under epoch key and `pad` then current. Range `ETag`, if any, is weak.
- [ ] **ENC-14** (Protected header, Stored once, served forever; readers)
  - Readers MUST compare `pl`, and namespace `kid` names, with what they fetched (base's `ns` accepted for read-through content); accept either copy of re-sealed namespace log range, MUST NOT rely on one; accept sealed bytes with or without fields later version adds.
  - Grants for pre-v0.37 entries missing from sealed bytes don't count in janitor's checks (§F.6).
- [ ] **ENC-15** (Compression, Padding (optional)) Sealed payloads never compressed, no `zip` header. With `"pad": true` in `encryption`, every JWE sealed for namespace (server at E2, clients at E3) pads its plaintext before encryption:
  - plaintext = UTF-8 JSON otherwise sealed, then ASCII spaces (`0x20`) to padded length; blob is zero-padded inside its sealed form instead;
  - `L` plaintext bytes: padded length 256 for `L` ≤ 256, else `padmé(L)`: `L` rounded up to multiple of `2^(E − S)`, `E = ⌊log₂ L⌋`, `S = ⌊log₂ E⌋ + 1` **[vectors I.6]**;
  - each JWE padded as whole (each JWE of log range included); turning `pad` on/off affects only later sealing, re-sealed log ranges included.
- [ ] **ENC-3** (Sealed blobs) Sealed namespace blobs: `application/vnd.patchlog.sealed-blob`: `"PLB1" ‖ len ‖ header ‖ iv ‖ AES-256-GCM(size ‖ bytes ‖ padding) ‖ tag`.
  - `len` = length of `header`, 4-byte big-endian; `header` canonical JSON; at E2 `{ "enc": "A256GCM", "kid": "{ns}#{e}", "pl": { "ns", "name", "blob": bid } }`, keyed by resource's `K_r` of epoch `e`.
  - `iv` 12 random bytes, tag 16 bytes; additional data = everything before `iv`. `size` = length of `bytes`, 8-byte big-endian. `padding`: zero bytes, only with `pad`, up to bucket of `size ‖ bytes`.
  - Readers check padding is all zeros; clients open sealed blobs only in namespaces whose document says sealed or end-to-end, or after epoch redirect. **[vectors I.13]**
- [ ] **ENC-16** (Sealed blobs: Epochs, ranges) Sealed namespace, and E3 for blobs from before raise from `sealed`:
  - `…/blob/{bid}`: `302`, cached as head pointer, to `…/blob/{bid}/e/{e}` for latest served epoch. Served epochs = those of this namespace's revisions whose documents are still stored and reference blob.
  - A revision's epoch is fixed by its first stored sealing: when written, or, if read through from a base or written before the namespace was sealed, when first served. A request for blob none of whose referencing revisions has epoch yet first fixes newest of them under current epoch.
  - Other epochs: `404`, `no-store`. Epoch whose referencing revisions were all pruned: `410` as in §7.1 where server recorded it when pruning, else `404`.
  - Pruning in base doesn't delete branch's stored sealings of base's blobs, but branch stops serving them and answers as above.
  - Each epoch's sealing stored once (concurrent instances: first stored wins), served unchanged, `ETag: "{bid}.{e}"`, sealed type as `Content-Type`; range requests served over them.

### §E.2.3 Getting keys

- [ ] **ENC-4** (What a grant gets, Which epochs, Responses) `POST /ns/{ns}/keys` takes `{ "epochs"?, "resources"? }`:
  - E2, grant whose rules fix `/resource` (§2.1): `K_r` for names in `resources` (default every name it fixes); name it doesn't fix or may not read: `403`.
  - E2, other grant: `K_e` if it reads namespace unrestricted (§2.1), else `403` (public namespace too, §C.2); `resources` ignored.
  - Epochs = `epochs` (default all) within window, starting at epoch in force (§E.2.2) at last namespace entry created at or before latest `nbf` among grant's blocks (a `batch` entry's config change included), or namespace's first epoch if there is no such entry or namespace wasn't yet sealed/end-to-end there; with no `nbf` in any block, or authentication disabled, current epoch only. Ends at current epoch; with `encryption.historyEpochs`, no more than current and that many before. Others omitted.
  - A reader lacking the epoch that sealed a grant reports signatures naming it as unverifiable.
  - Answer `{ "epoch", "level", "pad", "keys": [{ "kid", "name"?, "from"?, "wrapped" }] }`, `Cache-Control: no-store`; `epoch` = current, `name` for a `K_r`, `from` for keyring entry. E2, grant without `enc`: each key as base64url `key` instead of `wrapped`; E3: `422` (`invalid`), pre-raise epochs included.
  - Namespace neither sealed nor end-to-end: `404`, `code: "not_offered"`. Draws token from `exchangeRate` (§6.6), as `/edge-grants` does.
- [ ] **ENC-17** (At E3) E3 `/keys` relays to a `read` grant keyring entries whose `to` is its `enc` thumbprint, without read of `keyring`: namespace's entries for epochs ENC-4 selects and, in branch, also its bases' keyrings as of `at`, whether or not branch wrote its own `keyring`. For bases: epochs up to `at`, from epoch each base had at latest `nbf` (or at `at` if earlier), with no `nbf` from base's epoch in force now, at most that base's `historyEpochs` at `at` before its epoch there; `epochs` doesn't select.
- [ ] **ENC-18** (Wrapping) Keys wrapped to `enc`, an X25519 public key in root block:
  - `enc` = JWK of only `kty: "OKP"`, `crv: "X25519"`, `x` (32 bytes, unpadded base64url, 43 chars); else `401`.
  - HPKE single-shot Seal/Open (RFC 9180, section 6.1), base mode (auth mode for `keyring` entries), DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, empty `aad`.
  - Plaintext = key's 32 bytes; `info` = `"patchlog-key-v1" ‖ 0x0A ‖ kid ‖ 0x0A ‖ name`, `name` empty for `K_e`.
  - `wrapped` = HPKE's 32-byte encapsulated key then ciphertext. Thumbprint = RFC 7638 SHA-256 thumbprint of JWK. Both unpadded base64url.

  **[vectors I.12]**

### §E.2.5 Interaction with the rest of the spec

- [ ] **ENC-5** (Caching, Ids, Branches) Sealed namespace cached by its `read` mode (§9). Ids over plaintext canonical patches; MUST refresh `$nonce` in every patch set (§C.7). E2 branch: own epoch keys; read-through content sealed under them when first served.

### §E.2.6 Derived views

- [ ] **ENC-19** (Getting keys, What gets sealed, Aggregates) A service serving views derived from sealed/end-to-end namespaces:
  - fetches epoch keys via §E.2.3 with its own key pair and a `read` grant. E3, service whose public key isn't recipient in namespace's `keyring`: skips namespace, says so in its status, MUST NOT index or list ciphertext as content;
  - seals every value derived from such content; names, ids, URLs, heads and view's structure (`at`, `ns`, result order, pagination cursors) stay clear; cursor never encodes sealed value;
  - serves values combining several resources only whole-response, refusing them (`400`) to reader that would get per-entry sealing.
- [ ] **ENC-20** (Whole-response sealing, Per-entry sealing, `view`, Values of another resource) `view` = request target (path and query) of `…/at/{at}/…` URL served, exactly as service's redirect gave it.
  - **Whole response**: MAY be one JWE only when all hold: every sealed value (another resource's excepted) is from one non-public namespace; every reader its URL admits may read that namespace whole (`g/all`, §B.11.5, or index `gs` with `reads:{ns}`, §A.4); every such value derives from revisions served under one epoch. Format §E.2.2, that epoch's `K_e`, `Content-Type: application/jose`, `pl: { "ns", "view" }`.
  - **Per entry**: else JSON; each entry with sealed values replaces them with `"sealed": "<JWE compact>"`. Key: `K_r` of entry's own resource; `kid`: epoch source revision is served under (§E.2.2), at E3 one prune's `snapshot` of it would carry (§E.3.1); `pl`: `{ "ns", "name", "view" }`. A value derived from revision of another epoch is sealed in place as value of another resource; entry whose epoch service's grant gets no key for (§E.2.3) is served by name only. Folders and placements from sealed/end-to-end catalog namespace are entries of it.
  - **Another resource**: value derived from another resource is sealed in place as `{ "sealed": "<JWE compact>" }`, plaintext object of that one member. Key: that resource's `K_r`; `kid`: epoch of revision it derives from; `pl`: `{ "ns", "name", "view" }` naming that resource and response's `view`; its namespace's padding applies. Nests inside whole-response JWE where rest is sealed whole. Its namespace's keys unfetchable: `503`.
- [ ] **ENC-21** (Stored once, served forever, Caching, Local storage, `view`)
  - A view at given `at` is sealed once, under epochs of revisions its values derive from, then served unchanged; stored views keyed by URL and shape of reader's keys.
  - Padding follows source namespace; whole-response sealing pads only when every source is padded. Cached publicly only when all sources are public, else private result (§C.6).
  - Derived data from sealed/end-to-end namespace is kept in storage encrypted as at E1, keys held outside it. Purge of source, or destruction of its keys, MUST remove it: rows deleted, freed pages overwritten, stored sealed views deleted, cached keys forgotten.
  - Readers MUST compare `pl` with URL fetched (ENC-14).

### §E.3.1 Wire format

- [ ] **ENC-6** (Patch sets, Ids, Namespace documents stay plaintext) End-to-end write body = one-element patch set `[{ "op": "sealed", "value": "<JWE compact>", "blobs"? }]`, sealed under resource's `K_r` of epoch its `kid` names; JWE protected header carries `kid` and `pl: { ns, name, parent }`.
  - §6.2 step 3 checks, else `422` (`invalid`): op has no members but `op`, `value`, `blobs`; `pl` names this namespace, resource and parent signature would bind (§C.3.1); `kid` names this namespace's epoch in force; header is canonical JSON with no members but `alg`, `enc`, `kid`, `pl` (§E.2.2).
  - Prune's `snapshot` is one such op, `pl: { ns, name, id }` naming this namespace and requested `horizon` whose document it is, sealed under `K_r` of namespace and epoch its `kid` names. `kid` is set by newest revision in that chain that isn't tombstone and whose patch set isn't `[]`:
    - this namespace's epoch of that revision's `sealed` op, where op is its own, not base's, or, below earlier horizon, of that horizon's `snapshot` where its `kid` names this namespace;
    - epoch that revision is served under, where it is from before raise from `sealed`;
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
  - `keyring` document `{ "keys": [{ "kid": "{ns}#{e}", "to", "from", "wrapped" }] }`; `to`, `from` = thumbprints (§E.2.3) of recipient and wrapping admin's X25519 key. No other members but a `$nonce`; each entry only `kid` (this namespace, epoch ≤ `encryption.epoch`), `to`, `from`, `wrapped` (80 bytes). Breaking this, or two entries for one `kid` and `to`: `422` (`invalid`).
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

  A write ending in array index or `-` counts as a write to the whole array. Dry-run (`?dry-run=1`); each conflicting resource's steps are replaced by one resolution set against `B`; submit with `source: { ns: <branch>, at }`, `at` as classified in step 2. `412` (base moved): reclassify, resubmit.
- [ ] **MRG-6** (step 2) A `"delete"` step reproduces tombstone. Deleting a document the base has since changed, and changing one the base has since deleted, always need a person.
- [ ] **MRG-2** (step 6 Freeze the branch, and its sub-bullets) A merged branch is frozen by config write also recording `"merged": { "at": <base's ns_id> }`, or kept and merged again; second merge replays only changes since earlier counting merge batches from same branch, each per resource giving the pair (branch revision as of its `source.at`, base revision from its entries) from the most recent batch with an entry for it.
  - Resource deliberately kept at base's version is recorded as identical-content revision (`[]`, a fresh `$nonce` add where nonces are required or namespace is sealed, a sealed empty set at E3), only if base head is live: tombstone or absent head stays unmerged and is offered again, as does an E3 head referencing a blob a `sealed` op can't declare (§E.3.1).
  - Batches count only with: no `origin`; `source.ns` branch; `source.at` in branch's chain; recorded grant root `sub` and `kid` in base's current `merge.authors`. Removing an author withdraws its earlier batches. Changing `/merge` needs a `*` key (§7.4).
  - The merger's dry-run report lists, per resource, which batch and author its pair came from.
- [ ] **MRG-7** (Blobs, Nonces, Configuration is never merged implicitly, Authorisation, Attribution)
  - Merger with unrestricted `read` on branch copies no blobs within deployment; any other copies first, or uploads where ranks refuse copy (§2.1); another deployment: uploads.
  - Tools diffing documents for a merge or review leave out a fresh `$nonce`. Base config change goes in batch's `config`.
  - Batch checked in base under merger's grant (base's verbs for every item, base's rules); merged revisions record merger as author, who signs its own steps where signatures are required.

### §F.5 Rebase: a successor branch

- [ ] **MRG-3** (steps 1–5, Previews) Rebase creates successor from base's current head, `patches` giving it old branch's `read`, or `"grant"` where that would rank it below old branch (§2.1); never replays into successor ranking below it. It replays in batches with `source: { ns: <old branch>, at }`, classified as §F.3 against new branch; resources the base didn't change since the old `at` fast-forward with same ids (not at E3).
  - On resuming, successor batches without `origin` whose `source.ns` is old branch count as earlier merges (§F.3), whoever wrote them, even without `merge.authors`.
  - Switch is one config write on old branch, `"frozen": true, "successor": <new branch>`; what it received after replay is replayed too. Previews follow the `successor` chain.

### §F.6 Lifecycle and cleanup

- [ ] **MRG-8** (Cleanup, A janitor service) `cleanup` is data in branch's namespace document, not core-enforced; without it janitor never purges. It purges branch only when: frozen, and merged, superseded or abandoned; its cleanup period passed (`cleanup` member for state purged as, none: not purged as that state; counted from last config write that froze it or set `merged`, `successor` or `abandoned`) and base's `cleanup` minimums passed; no dependents. Needs `purge-ns` on branches only, never bases.
- [ ] **MRG-4** (The janitor MUST verify claims, and the closing rules) Before purging, janitor MUST verify claims `merged`, `successor`, `abandoned`, `cleanup` (held to base's minimums):
  - **merged:** base's log has batch without `origin`, by principal in base's current `merge.authors`, `source.ns` branch, `source.at` in branch's chain; branch's log has no `head`, `tombstone` or `batch` entry after `source.at` (other kinds allowed). Remote branch merged back with `origin` never passes.
  - **superseded:** successor is still one §7.4 allows (or was until purge after branch was last frozen and janitor read what it needs before it); its log has a batch without `origin`, `source.ns` branch, `source.at` in branch's chain, whose recorded grant has root `sub` and `kid` in base's current `merge.authors` or chains to current `*` key of branch; branch's log has no `head`, `tombstone` or `batch` entry after that `source.at`.
  - **abandoned:** `"abandoned": true` set by config write whose recorded grant chains to current `*` key of branch (inherited or own); entry recording no grant doesn't count.
  - Merged and superseded: each resource with own `head`, `tombstone` or `batch` entry up to `source.at` (not purged ones, nor `keyring` at E3) also has entry in counting batch with `source.at` at or after its last such entry, or batch-namespace head equal to or descending from its branch head as of `source.at`. At E3, `keyring` entries after `source.at` are allowed and batch counts only with other items. Branch with no such entry counts as merged.

### §F.7 Merge service

- [ ] **MRG-9** (Automation) A merge service automates only: rebasing branches where every resource fast-forwards (at E3, is re-sealed onto unchanged base); submitting at a set time a batch a person approved. All else, unapproved replays included, waits for a person.

### §F.8 Access, encryption, catalogs and indexes

- [ ] **MRG-10** (Catalogs) A catalog service MUST issue content grants only from catalog it follows as base.
  - Merging catalog branch goes through catalog service: for end-to-end catalog it issues no merge grants and checks no catalog batch; without merge key it issues none (`404`, `not_offered`), as for organising requests (§B.11.4). Otherwise it checks every change as §B.11.4 does, approver as caller (from their own grant), no widening whoever approved, then issues one grant covering exactly that batch.
  - Grant allows exactly batch's `/resource` and `/action` pairs, expires within minutes, and is signed with dedicated key that can neither assert admin groups nor write `$access`; root `sub` merge service's, `attrs.approvedBy` approver. It is handed only to merge service, which submits exactly batch checked.
  - Batch changing `$access`, or moving or re-placing so as to widen (§B.11.4), and any end-to-end catalog batch, goes only with approver in `catalog-admins`: dry-run checked (except end-to-end) with that admin as caller, submitted under their grant through merge service, which adds narrowing block with its own `via`.
  - Catalog base lists in `merge.authors` merge service's `sub` with merge key's `kid`, and each such admin.
- [ ] **MRG-11** (Editors limited to some documents, Indexes) A service branching base for editors limited to some documents records creation with `via`, creates branch with `read: "grant"`, and issues grants fixed to resources their base grants cover. The main index follows only base; search over branch is a separate preview index.

### §F.8.1 Merging and rebasing at E3

- [ ] **MRG-12** (Keys, Classification, Re-sealing an entry, Blobs) At E3 merge or rebase is done by key-holding client and submitted as ordinary batch sealed for target.
  - Read-through content keeps base's ciphertext and `kid`; keys are asked of namespace read first, the `kid`'s only if that fails. Branch's own writes carry its `kid`s; its `keyring` is never merged.
  - No fast-forwards: `B` ancestor of `H`: branch entries after `B` are re-sealed onto `B` in order, new ids, no conflict check. Neither: replayed with §F.3's conflict check.
  - Re-sealing: merger decrypts and checks `pl` against where read, resource and entry's parent, then seals same plaintext patches under target's current epoch, fresh IV, target's `pad`, `pl: { ns: target, name, parent }` (`parent`: `B`, then previous entry's id), and computes each id. Tombstones aren't sealed; blobs keep ciphertext and ids, each re-sealed op its `blobs` list.
- [ ] **MRG-13** (Conflicts, Validation, Retries, Rebases) Conflicts come from the `writes` of decrypted patch sets, as §F.3, arrays included. Before submitting, merger folds every item and validates each document against its `$schema` as target's gate resolves it; failure is conflict of kind `invalid`. Sealed batch is kept byte for byte until acknowledged; reclassifying after `412`, or changing resolution, reseals affected items. Rebases re-seal likewise with the successor as target; remote branches merge likewise with the target's keys.
- [ ] **MRG-14** (Later merges and the janitor) At E3 second merge takes its common ancestors from earlier merge batches (§F.3); without one, every resource the branch changed conflicts, except one whose target and branch head documents are equal as decrypted plaintext (counted merged).

### §F.9 Releases across namespaces

- [ ] **MRG-15** (Where it lives, Starting, Cleanup) Every tool acting on release document checks for itself, under its own authority, what it is about to do. Branch's own `at` overrides document's. Janitor purges release's draft branch after its other branches; release document never authorises purge.
- [ ] **MRG-16** (Reading) Release previews follow listed branches, refuse viewers (`403`) as §B.5 says, never show base's versions.
- [ ] **MRG-5** (Merging) A release merges as one batch per branch.
  - Before approval: each listed branch's `base` is namespace it is keyed by (or, for release built on another, that release's branch for key) and it is not frozen or purged; on resuming, its own approval's freeze is accepted.
  - A person approves the digest `text(trunc160(sha256(canonical(plan))))`; `plan` is `{ "release": <release document's revision path>, "batches": [{ "ns", "source", "config"?, "items": [{ "resource", "ifMatch" | "ifNoneMatch", "steps" }] }] }`, no other members: batches in submission order, members as §7.5 sends them, before sealing; each step its plaintext patch set without fresh `$nonce` ops and without fresh top-level `$nonce` in root operation's value, or `"delete"`; precondition on earlier batch's result is `{ "batch", "item" }` (or `{ "batch" }` for its config id), indices from 0, in place of id.
  - Approval fails if re-planning gives different digest. Approving freezes every listed branch; each `source.at` stays branch's `ns_id` before freeze; unfreezing branch invalidates plan. Each step is reclassified by dry run right before submission; difference from plan stops for new approval.
- [ ] **MRG-17** (Merging, steps 1–4) Batches go in four steps:
  1. Schema resources, fast-forward only, in `$ref` order; one the base changed since `at` is a conflict.
  2. Catalog changes that narrow access: for every subject, roles at every node afterwards subset of those before (§B.11.4's test on step-2 batch as whole, whoever merges, `catalog-admins` included). A folder the release creates goes here too, with its own `$access`, when narrowing move needs it; the subset test then applies to items moved into it, not the folder.
  3. Content branches, any order.
  4. Catalog changes that widen access: new placements, remaining moves and `$access` edits.

  A branch with both merges schema resources in step 1 and content in step 3. End-to-end schema namespace isn't branched for release.
- [ ] **MRG-18** (Merging, reported conflicts) Before submitting anything the merge service reports for a person:
  - catalog node whose change narrows access for some subjects and widens it for others (two resolution sets: narrowing in step 2, widening in step 4);
  - content item that step 3 creates or restores and a placement in the catalog base already names, unless step 2 removes that placement, or release keeps it unchanged and its approver accepts;
  - pinned `x-ref` or manifest entry naming revision of another listed branch that merge replays rather than fast-forwards;
  - document resolving a draft in a branch the release doesn't list.
- [ ] **MRG-19** (Merging, stored plan) The merge service stores whole plan, both halves of every split node, before submitting step 2. A merge stopping part-way resumes from it, never reverts; until the step-4 batch the stored plan, not classification, decides what is left of a split node. Catalog batches are submitted by authors the catalog base lists in `merge.authors`. Every branch records `merged` only after step 4, `at` target's `ns_id` after last batch into it.
- [ ] **MRG-20** (Several releases, The merge lock) One release per catalog base is merged at a time, under lock `merge-lock.{catalog}` in release namespace; releases on one catalog base keep their documents in one namespace.
  - Lock document is `{ "holder": <merge service's sub>, "plan"?: <plan digest> }` while held, `{}` or only `$nonce` while free. Taking it is compare-and-append setting `holder` (and `plan` if already stored): first take create with `If-None-Match: *`, later ones append with `If-Match` on free head. Holder sets `plan` once stored and releases by appending `{}`.
  - Resuming service replaces `holder` with its own `sub` by compare-and-append only if lock's `plan` is the digest of its stored plan; any other held lock is released by a person.
- [ ] **MRG-21** (Rebasing, Abandoning) Rebasing a release creates a successor of each branch, listed in new revision of release document.
  - Schema successor is created with `drafts.for` naming other successors in its creation `patches`, and replayed first.
  - A resource whose entries reference a draft that had to be replayed is squashed into one resolution set against its new base.
  - Abandoned release's branches are frozen with `abandoned: true` by an administrator.

## Addendum G — Federation and portability

### §G.1–§G.2 Principles and external consumers

- [ ] **FED-1** (One canonical origin, Checkpoint, Verification, Access) One canonical origin per deployment, published at `GET /`. Consumer checkpoint: `(origin, ns, ns_id)`. It verifies revisions through their log (`/r/{ns}/{name}/rev/{id}/log`) by recomputing ids back to verified revision, and namespace chain from checkpoint; MUST verify when fetching through cache or mirror it doesn't control. Private namespaces need a `read` grant from source.

### §G.3 Remote branches

- [ ] **FED-2** (Creating one) Remote branch on B: new namespace, created with B's deployment operator key by `PATCH /ns/{name}`, `If-None-Match: *`, genesis setting remote `base: { origin, ns, at, chain }`. Its namespace document is B's own and MUST require nonces if A's does (`422` otherwise). No `branch` entry is written on B.
  - `422` unless `origin` isn't B's own, `at` is in A's chain (B verifying A's namespace log up to it), and `chain` names A's namespace, then its base, and so on, as of `at`. Exceptions: what A serves and B can't verify, parse or open with keys A gives it: `502` (`upstream`); what B can't open because §E.2.3 gives its grant no key for that epoch: `422`.
  - A's namespace or base in its chain purged: `410 purged` (§8.5). A's deployment silent or `5xx`: `502` (`upstream`).
- [ ] **FED-6** (Schemas, at creation) Unless source is end-to-end, B at creation reads A's `/ns/{ns}/rev/{at}/heads` once and mirrors history of each schema resource in the `$schema`/`$ref` closure, up to referenced revisions, into same-named namespace on B.
  - Referenced revision that doesn't resolve in its own namespace, or is in end-to-end namespace: `422` `schema_unavailable`.
  - Missing mirror namespace gets genesis `{ "read": "public" }` if source is `public` (§2.1), else `{ "read": "grant" }`; mirror ranking below its source: `422`, judged before its resources.
  - That namespace on B being a branch, or holding a resource at those paths whose chain neither contains A's nor is a prefix of it: `409 name_conflict`; refused history fails creation with that refusal.
- [ ] **FED-7** (Reading through) B answers untouched resources as A did at `at`, under its own URLs, resolving read-through `$successor` on B.
  - Only A's immutable URLs (`/ns/{ns}/rev/{ns_id}` with its `/log` and `/heads`, `/r/{ns}/{name}/rev/{id}` with its `/log`, `/r/{ns}/{name}/blob/{bid}` or the `…/e/{e}` URL it redirects to) and `POST /ns/{ns}/keys` (E2 source, or an E3 one's epochs from before its raise).
  - Verifies each listed head against A's namespace log up to `at`, each revision through its log, each blob against its id; where A's namespace is branch, each read-through head against log of base that wrote it (`422` at creation if B can't read those bases).
  - Clients reading an E3 remote branch accept read-through ciphertext whose `pl.ns` is in `chain`. Failed lazy fetch: `502` (`upstream`) for that resource.
- [ ] **FED-8** (Registration) B may register on A: `POST /ns/{ns}/branches`, `{ "remote": { "origin", "ns" }, "at" }`, `If-None-Match: *`; `412` only while unexpired registration of same `remote` exists.
  - Renewal: `If-Match` = `ns_id` of latest entry for that `remote`, expired or not (`412` otherwise), same `at` (`422` otherwise); `201` with `X-Namespace-Revision`.
  - Same principal's retry gets `200` with latest if its `If-Match` names entry before latest, or it sends `If-None-Match: *` where latest is its own, unexpired, same `at`.
  - Needs unrestricted `read` and `export` on A, evaluated as an `export` envelope with `doc` = `{ "remote": { "origin", "ns" }, "at" }`. `origin` MUST be `https` (or `http` for loopback: `localhost`, `127.0.0.0/8`, `[::1]`); `at` MUST be in A's chain (`422` for either).
- [ ] **FED-9** (Registration, Registrations expire) A appends a `branch` entry with `remote` per registration and renewal, listed in `/branches` as `{ remote, at, ns_id, expires }` only (`expires` RFC 3339). Remote entries don't count toward `branchesPerNamespace`. Consumers, janitors and merge services MUST NOT fetch from a `remote` entry automatically. Registration protects A's history from pruning only for `remoteRegistration` from its latest `remote` entry.
- [ ] **FED-10** (Purges) On a `purge` in A's namespace log B MUST apply §8.3 locally (its own chains for that name, its own branches, its cache tags); on `purge-ns`, for every name A had at `at`. Purges in A's schema namespaces don't reach mirrored schemas.
- [ ] **FED-11** (Merging back, Rebasing) Merging back is batch on A, classified by ancestry as §F.3, submitted by principal with grant on A, `source: { origin: <B's origin>, ns: <branch>, at }`, recorded as asserted; A's gate checks every item, fast-forwards reproduce B's ids.
  - Schema revisions created on B go to A first as full-history bundle, else referencing items fail `schema_unavailable`; blobs A lacks are uploaded to A first by submitting principal.
  - Rebasing is §F.5 on B, new branch based on A's current head.

### §G.4 Bundles

- [ ] **FED-3** (Format, Full-history lines, Digest) Bundle: newline-delimited JSON (`application/vnd.patchlog.bundle+jsonl`), each line canonical JSON then one `0x0A`; any other line rejects it. First line is the header, then one line per entry.
  - Full-history lines: resource log entries (§7.1) of kind `rev` or `tombstone`, with `ns` (exporting namespace) and `resource`, authorship members only as Authors (below) allows, in chain order per resource; every id recomputed, last line per resource MUST be that document's `docs[…].head`.
  - Every `docs` entry MUST have lines and every line naming resource a `docs` entry; any mismatch rejects bundle.
  - Chain starts at genesis or right after its `requires` id; chains exported from branch include base's entries back to genesis, or name foreign parent in `requires`.
  - Digest: `text(trunc160(sha256(b)))`, `b` bytes as written.

  **[vectors I.9]**
- [ ] **FED-12** (Snapshot lines, Blob lines) A snapshot line carries document and its source id, one per `snapshot` document; `snapshot` MUST be that document's `docs[…].head`. Document tombstoned at source: `{ …, "snapshot": <tombstone id>, "deleted": true }`, no document.
  - Blob lines carry every blob exported document references (any exported revision of a `full` document, or snapshot), once per resource, with `nonce` if any, before first line mentioning it: one whose patches carry its id as a `$blob` member or as the value of an operation whose path ends in `/$blob`, whose snapshot document references it, or whose declared list names it. `data` is base64url without padding (readers accept either). Importer recomputes each blob id; mismatch rejects bundle. An incremental bundle MAY leave out blobs the history up to `requires` already references.
- [ ] **FED-13** (`requires`, Authors, `written`, `key`) `requires` applies only to `full` documents; `requires[r]` MUST be in target's chain for `r`; if target moved on along another line, `r` is conflict.
  - Authors, `via`, grant ids, author signatures, creation times, `gesture`, `undoes` only with `"authors": true`. History lines then carry `grant: gid` and bundle one grant line `{ "ns", "grant": gid, "root", "stored", "key"? }` per grant, before first line naming it, its `ns` the namespace whose entry first recorded the grant, in `written`'s form. An exporter that can't fetch a grant leaves `grant` off the lines that would name it. Rejected: line naming grant with no earlier grant line, second grant line for one grant, grant line without `"authors": true`.
  - Revision written in namespace other than exporting one carries `written` (its name or `{ "origin", "ns" }`); where undeterminable, `written` and `grant` are omitted.
  - `key` is `{ "kid", "alg", "pub" }`, the key entry the grant's root block verified against at source (a key of the namespace document in force at the first entry recording the grant, in a branch or its local bases' then; else an operator key in force at the `created` of the first revision naming it), omitted if exporter finds none. Tool holding source's namespace log or operator key history checks `key` at revision's position; otherwise it reports signature attested, not verified.
- [ ] **FED-14** (Never exported, Consistency) Purged content is never exported. Each namespace is exported as of its own `at`, taken when export starts.
- [ ] **FED-15** (Selection and dependencies) The closure always includes the `$schema` of every exported revision, the `$ref` inside those schemas, and blobs those revisions reference. Reference to schema revision existing only in branch can't be exported (`schema_unavailable`) unless that schema's namespace is `external`.
  - It also includes `x-ref` fields: pinned needs that exact revision, live head as of export's `at`. It doesn't follow `$successor`.
  - The importer checks dependencies left out as `external` exist in the target: by id for pinned references, by name for live ones.
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
  - Full-history steps are rewritten and submitted one by one with new ids, never fast-forwarded; `source.ids` records source ids. Catalog placement names aren't renamed; dry run lists undeclared strings naming a mapped namespace. Snapshot documents of renamed namespace go through `{dst}-upstream`. Mapping onto branch whose `base` chain reaches `src` keeps references and ids.
  - Refused at step 1: incremental document that would change, whose `requires` names source id; full-history document's pin whose new id isn't known (target `external`, left out, or snapshot document's revision).
  - Where nonces are fresh, a re-run recognises its earlier writes by import batches' `source.ids`.
- [ ] **FED-21** (Source, step 6 Today's rules judge old history, Authors) Import batch `source`: `{ "origin", "ns", "at", "bundle": <digest>, "ids": { name: upstream or source id } }`, without `origin` when bundle's `origin` is target's own. Importer is recorded as author and signs its own steps. Full-history import replays every step through target's current gate, as importer, at current `now`.

### §G.5 Encryption

- [ ] **FED-5** (`access`, Importing) Exporters MUST include `access` in header: each exporting namespace's protection as source (§2.1), `"public"`, `"private"`, `"sealed"` or `"e2e"`.
  - Step 1 refuses bundle putting namespace's lines into target, or its upstream namespace, ranking below that namespace (§2.1), unless operator explicitly overrides for that import; also target or upstream namespace whose protection it can't read.
  - An importer holding an `e2e` target's keys MAY import a non-`e2e` source into it by sealing each patch set client-side, encrypting each blob as §E.3.1 and rewriting references to the new blob ids; pins to them, incremental documents and later imports are then handled as for a renamed import (§G.4.4).
- [ ] **FED-22** (Importing, No snapshots at E3) An `e2e` source goes only into an `e2e` target of same namespace name, override or not. Lines carry ciphertext and plaintext `keyring` verbatim; ids verify as usual; its documents are exported `full`.
  - Step 1 refuses: blob line lacking sealed type or having nonce; a `rev` line other than the `keyring`'s whose `patches` are neither one `sealed` op whose `pl.ns` and `kid` name line's `ns` nor restore's `[]`; snapshot documents for an `e2e` target.
  - Target created for import starts at bundle's lowest epoch and moves up one epoch at a time as keyring lines arrive (importer needs `config` on it, with a `*` key); existing target likewise, refused at step 1 if its `keyring` would conflict with bundle's or its epoch is below bundle's lowest or above that of sealed line it lacks.
- [ ] **FED-23** (Sealed bundles: Envelope line, Lines, Checks, Digest, What stays visible) A sealed bundle (`application/vnd.patchlog.sealed-bundle+jsonl`) starts with `{ "sealedBundle": 1, "id", "recipients": [{ "kid", "suite", "wrapped" }] }`; envelope canonical JSON, each line then one `0x0A`; any other line, blank one included, rejects it.
  - `id`: 128 random bits, base64url without padding. The 256-bit content key `K_b` is wrapped per recipient as §E.2.3 with `info` `"patchlog-bundle-v1" ‖ 0x0A ‖ id` (`id` as its 22 ASCII characters); recipient `kid` is its thumbprint.
  - Each following line: JWE compact under `K_b`, protected header `{ "alg": "dir", "enc": "A256GCM", "pl": { "bundle": id, "line": n, "last"?: true } }` as canonical JSON (`last` on last line only), plaintext bundle line `n` (header = 0) as canonical JSON without newline. Lines are never compressed.
  - Reader MUST reject whole sealed bundle if: line fails to decrypt or its protected header (`pl` included) has other members; `pl.bundle` differs from `id`; line numbers aren't 0, 1, 2… in order; no line says `last` or line follows it. It then checks decrypted bundle as §G.4.1. Padding is removed from line's plaintext before these checks and digest; `source.bundle` is decrypted bundle's digest.

  **[vectors I.12]**
- [ ] **FED-24** (Remote branches, E2 sources, E3 sources, Epoch start times) B MUST refuse (`422`) to create remote branch whose `read` or level §7.4 would refuse for local branch of its source, or whose source's namespace document it can't read.
  - B likewise refuses config write making remote branch `public`, raising it to `e2e`, or turning off a `nonce` requirement its source has; creation and such writes are judged by source's current namespace document, read for that write, and refused as creation is where it can't be read (§G.3).
  - B MUST raise its level when its source does so in log it follows, or to at least `sealed` once that log or source's namespace documents are served sealed, as far as Levels allow (`sealed` where they refuse `e2e`), raising its dependents first, leaves first.
  - E2 source: B fetches keys from A with its own key pair and grant, mirrors plaintext, seals what it serves under branch's own epoch keys.
  - E3 source: B mirrors ciphertext, `keyring` and A's sealings from before its raise verbatim, verifies ids over ciphertext, skips §G.3's schema step. Branch name MUST NOT be in `base.chain` (`422`). Read-through content keeps source's name in `pl.ns`; B relays source's keys from mirrored keyring through `POST /ns/{branch}/keys`.
  - B chooses epochs it relays to a grant (§E.2.3) by the epochs of source's namespace documents and the start times its namespace log gives them. For keys B hands out itself (source epochs before its `e2e` raise), B reads epoch start times only through `base.origin` itself, never mirror or other intermediary, whatever its `GET /` says.

## Addendum H — Files

### §H.1 What a file is

- [ ] **FILE-1** (Raw files, table, Which kind a new file is, Empty files) Every non-JSON file is a raw document, bytes kept exactly. `type`: from extension (any case) by table; else upload's `Content-Type` minus parameters unless absent or `application/octet-stream`, `binary/octet-stream`, `application/x-www-form-urlencoded` or `multipart/*`; else existing file's type, or `application/octet-stream` for a new file. A `text/` type needs a UTF-8 body (BOM allowed), else `application/octet-stream`. At E3 the reference's `sealed` holds the file's `type` and `size`, its own the sealed blob's.
  - New file named `*.json` (any case) with an I-JSON body (§3.1, leading BOM dropped) is a JSON file; any other new file is raw. Existing file keeps its kind: JSON accepts only I-JSON (`400` otherwise), raw any bytes.
  - Empty body makes or truncates a 0-byte raw file, except over a JSON file (`400`) and under new `.json` name; that, and `LOCK` of new name, is gateway-held 0-byte placeholder until body decides kind.
- [ ] **FILE-7** (JSON files) A JSON file's rendering is the canonical JSON text of the document minus a fresh top-level `$nonce` and a top-level `$successor` of §8.1's form, laid out as `JSON.stringify(value, null, 2)` (LF line ends, one final LF); tokens and member order exactly JCS's. Type `application/json`. **[vectors I.10]**
- [ ] **FILE-8** (Writer's bytes, Nonces, Identity) Every tool shows a document as the same rendering. A gateway serving a writer its own bytes back uses weak `ETag` `W/"{id}"`, accepted like the strong one in any `If-Match`.
  - Where nonces are required or namespace is sealed: a JSON file's root must be object carrying `$nonce` (other root: `422`, saying why); raw file's root carries `$nonce` beside reference, its blob a `Blob-Nonce`.
  - File's `ETag` is its item's head revision id. Raw save is stored with uploaded value; a JSON save when stored rendering parses to it. After save merged with others' edits, next `GET`, `HEAD` or `PROPFIND` is answered in full whatever validators it carries.

### §H.2 Trees

- [ ] **FILE-2** (A file tree is a catalog, Folders, Files, Untrusted namespaces, Shape) File tree is catalog `C` whose `catalog` object has `"files": { "ns", "root", "folder"?, "placement"? }`: `ns` content namespace for new files, `root` top-level folder's node name (created without parents), `folder` and `placement` schema revision paths new nodes carry as `$schema`.
  - Any item in `files.ns` is placed only in this tree; gateway doesn't also serve `files.ns` as writable flat folder.
  - Folders: folder nodes with opaque dot-free names, shown by `title`; files: placements named `{ns}.{item}`, shown by their `title`. Without non-empty string `title`, node is shown by its item's name (folder: node name). File trees don't set `catalog.title`; where one does, tools read titles from placement documents, never listings.
  - Placements of items in namespaces `C` doesn't trust are left out, whether listed via tree service or node documents.
  - `catalog.mode: "tree"`: one parent each, inside `root` subtree; new nodes get `order` after their last sibling.
- [ ] **FILE-9** (Titles) Titles: Unicode NFC, 1–255 UTF-8 bytes, not `.` or `..`, none of `/`, `\`, NUL, categories `Cc`, `Zl`, `Zp`, U+202A–U+202E, U+2066–U+2069 (other `Cf` allowed). Gateway converts received NFD to NFC and refuses trailing space or dot on create and rename for every client. Existing title breaking rules is shown escaped (offending characters, a trailing space or dot, and a whole `.` or `..` percent-encoded as UTF-8, stem shortened to stay within 255 bytes); escaped name never takes real title's name (it is numbered as a duplicate).
- [ ] **FILE-10** (Siblings) Files and folders in one folder share one name set, compared after NFC and, unless gateway is case-sensitive, Unicode simple case folding. Tools refuse to create a name a visible sibling has; a `MOVE` source isn't its own sibling (case-only rename allowed).
  - `PUT`, `COPY` or `MOVE` to a name matching a sibling only under another case: `409` naming the sibling, and sets a guard, unless the sibling is a file and the request carries a tag or the user read or wrote it under this spelling. `MKCOL` under another case: `405`; a folder mid-path matches whatever its case.
  - Duplicate left by race is shown as `name (2).ext`, `name (3).ext`, … ordered by `born` (none last), then node name; first keeps its name, a number colliding with a real title is skipped, stem shortened to stay within 255 bytes.
- [ ] **FILE-11** (Access) With tree-derived access, user's rights to read, place and move come from catalog's grants and `/read-grants`, not grant on content namespace.
- [ ] **FILE-12** (Flat view) Flat view: namespace is one directory; raw document is listed under its resource name, any other as `{name}.json`; raw `x.json` and document `x` both existing: raw keeps its name, document is shown by duplicate rule. §3.6's names, no folders; rename is copy plus delete.
  - New file whose resource is tombstoned, where §H.6 doesn't restore it: restores it with root `replace`; last revision has a `$successor`: `409` naming new path.
  - New file whose resource is a live document shown under another file name: `409` naming that file.

### §H.3 Listings

- [ ] **FILE-13** (In a tree, A folder too large to list whole, A tree service that is behind, Read-your-writes) In tree folder is listed from tree service's `children` listing, with `total`; top level from `roots` where `root` is hidden from user or missing; path of titles resolved with `lookup`. Case-sensitive gateway lists folder instead when answer's title differs in case.
  - Tree service following file tree adds `file: { "size", "type", "modified"? }` to placements of items in trusted namespaces, from the item's head (raw: reference's `size`, `type`; JSON: rendering length, `application/json`; `modified` head's `created` where known) (sealed as another resource's value for sealed namespaces; `{ "absent": "e2e" }` for end-to-end items, `{ "absent": "pending" }` for head not yet read, which tool reads from core).
  - Folder too large to list whole: `403` saying why, never cut short; path inside still resolves by `lookup`, or `403` in sealed or end-to-end catalog.
  - Tool passes on `503 behind`, deleting nothing on listing meanwhile; sends `X-Namespace-Revision` of each of its writes (catalog's and content namespace's) as `?min` on later listings, kept and dropped as §A.5 says.
- [ ] **FILE-14** (In the flat view, Where times are absent, Sealed and end-to-end catalogs) Flat view lists from `head` rows of `/heads` (tombstones and purges left out), `ETag` from `target`, time from `created`. JSON file size is its rendering's, not `/heads`' `size`; raw file's is blob reference's `size` (E3: `sealed.size`). Rows without `created` take `Last-Modified` from document read for size; in sealed and end-to-end namespaces gateway with keys takes times from logs. A gateway without a sealed or end-to-end catalog's keys doesn't offer the tree.

### §H.4 Saving a file

- [ ] **FILE-15** (Names before writes) Before any write tool checks names resolved from listing against node documents: each node still in its folder under that name, none under a name the listing lacked; on disagreement it resolves from node documents. Folder's emptiness comes only from node documents. Grant unable to read them keeps listing's view for names and deletes no folder (`403`). A name the filtered listing lacks is never revealed or edited: `PUT` onto a name only a hidden sibling has creates a new file.
- [ ] **FILE-3** (The base, Records, Several records, The reload)
  - Base of `PUT`: revision named by `If-Match` (first value, `W/` dropped), else by `If` (first tag of first list applying to this resource, not negated with `Not`); older tag starts rebase, not failed precondition. `If-Match: *` asks only that file exist (head is base). No base: head.
  - Tag naming revision where path holds no file `412`; revision of flat resource another user since deleted `409`; unknown revision `412`; pruned revision, recorded base below horizon, or pruned range between base and head `409`; failed read fails save (`503`, `502`), never taking head as base.
  - Tagless saves, where gateway keeps records (per user and path, kept day then evicted; none for `304`, `HEAD`, `PROPFIND`; a save changing nothing is no write; when full, oldest records other than the first and the latest write go first): path now naming another document, or none `409` (a `GET` is reload); user's own `DELETE`/`MOVE` forgets path, except move to scratch name; evicted path `409`; never-recorded path takes head as base.
  - JSON save is checked against every recorded version as base: `409` naming paths if any two give different documents, except tagless save that sets back value someone else changed, which is merged keeping other value.
  - Reload after `409`: full read by refused token (`200`, not `304`), becoming path's only record; refusal re-arms nothing for user's other tokens. After `409` because someone else deleted file, the `404` is reload and next save restores it as §H.6 does (last revision with `$successor`: `409` naming new path).
- [ ] **FILE-16** (Others' writes, JSON files, Raw files) `theirs` = writes of log entries between base and head by other users; value changed and changed back is still conflict.
  - JSON file: saved as patch set from base's rendering to new file, keeping base's `$successor`, with `add /$nonce` of fresh value where §C.7 asks; write anywhere inside array counts for whole outermost array. Patch set over `opsPerSet` or `patchSetSize`: root `replace` carrying fresh `$nonce` and any `$successor` if base is head and namespace isn't end-to-end, else `413`.
  - Raw file: conflicts only if someone else changed bytes, or deleted or restored file, after any version user had. Body uploaded as blob (`413` above `blobSize`, before any upload); reference members (`/$blob`, `/type`, `/size`, `/nonce`, E3 `/sealed`) set one by one, fresh `/$nonce` where nonces apply, never root. A `412` retry reuses the pending blob; bytes compare by blob id.
- [ ] **FILE-17** (New files, Partial writes) New file in tree only where `C` trusts `files.ns`.
  - Grants from catalog: place first, then upload raw file's blob and create item with `If-None-Match: *`, deleting placement if create fails. Otherwise: dry-run placement as one-item batch before any upload, then upload, create, place, removing item at once if placement fails. Nobody else deletes unplaced item younger than `blobGrace`.
  - `PUT` with `Content-Range`, or body cut short: `400`, nothing written. `POST` to file: `405` with `Allow`.
- [ ] **FILE-18** (Answers, table) Gateway answers:
  - save stored with uploaded value: `201`/`204` with new revision as `ETag` (even if rendering bytes differ); merged with others' edits: `201`/`204`, no `ETag`;
  - `409` naming paths: overlap with others' edits since base, delete or restore by another user between base and head, pruned base, disagreeing or evicted records, path now naming another file, file moved away (FILE-3, FILE-19); `412`: `If-None-Match: *` on live file (but see move-aside), `If-Match` as FILE-3, `Overwrite: F` on existing target;
  - `403` saying why: new name breaking title rules or ending in space or dot, not resource name in flat view, or new file where `C` doesn't trust `files.ns`;
  - core or tree service `422`, `401`, `403`: that answer with its message, or `502` naming service where user can't fix it;
  - frozen namespace `403` naming successor, never `423`; purged `410`; rate limited, or service behind longer than client waits: `503` with `Retry-After`; tree service unreachable `502`;
  - limit exceeded (core `413`, or `422` with `code: "limit"`): `413` as `too large: {limit} {measured} > {max} (§6.6): {message}` (no sizes: limit alone; no limit named: core's text); gateway's own bound: same shape naming its setting, `measured` lower bound where reading stopped;
  - gateway memory for scratch files or locks full: `507`.

### §H.5 Deleting, renaming, moving and copying

- [ ] **FILE-4** (Delete a file, Delete a folder) Deleting file deletes its placement, then, where tree owns item and grant allows `delete`, item; otherwise it stays. The delete carries `If-Match` on the head the tool read: client `If-Match` not the head `412`; gateway's own delete finding the head moved since its read `409`. Folder is deleted only without visible children (from node documents), else `409` naming those children, nothing hidden from caller. Dangling placements (gateway deletes those it can first), and placements user can't see, aren't contents: they don't stop delete and become orphans.
- [ ] **FILE-19** (Rename or move within a tree, Move onto an existing file, Moves that copy, Move to a scratch name, Across trees or namespaces, Copy)
  - Within tree: one append to node's `title` or `parents` with `If-Match`, under Move grant beginning with its required `test` of `/parents`, after checking node's document still has name and parent path named (`404` otherwise); new parent inside `root` subtree, not node or descendant (`403`). On any `MOVE`, client `If-Match` names source; not its head `412`.
  - Move onto existing file (`Overwrite: T` or absent; `F` `412`) is a save of the source's content into target (source's type as upload's `Content-Type`; base as §H.4, never from `If-Match`), then delete of source; `COPY` onto existing file likewise save. `MOVE`/`COPY` onto existing folder, or folder onto file: `403` (`412` with `Overwrite: F`).
  - Moves that copy: check source can be deleted, copy, delete source with `If-Match` naming revision copied; source changed since `409`, stays; failing delete leaves copy.
  - After move to scratch name file stays live; next create-only `PUT` of original path by same user within 30 seconds is accepted once as edit, base as for any untagged save.
  - Item moved to another namespace: last revision before tombstone carries `$successor`, unless JSON file whose root isn't object.
  - A copy is a new item with source's current content, plus a placement. Raw blob copied with `Blob-From` where §7.8 allows, else bytes uploaded again: decrypted with the reference's key from an `e2e` source, encrypted under a fresh key, new id, into an `e2e` target.
  - Folder copy, or move to another tree: new folder node as `MKCOL` makes one, titled with destination's last segment, without source's `$access`; visible children copied or moved one by one (`Depth: 0`: folder alone); moved folder deleted once empty; failure part-way leaves what was done, answered as that child's request would be.

### §H.6 Clients as they are

- [ ] **FILE-5** (Scratch files, Delete, then write)
  - Scratch names (§H.6's lists) are kept by gateway in bounded memory, never written to core; no other folder is scratch; existing node with such name is real file. Copy names (`x copy.txt`, `x (1).txt`) are real in tree; in flat view scratch only as `COPY` destinations, plain `PUT` of one `403`.
  - Write to path same user deleted within 30 seconds restores that file (placement, then item) rebased on its last live document, as a whole-document `replace` when its patch set would exceed `opsPerSet` or `patchSetSize` and its base is the last live document. Restore refused (`403`, `410`): write creates new file or is refused as such write would be. File whose item has `$successor` is never restored so. Write refused: user's delete (never one older than 30 seconds) is undone where possible.
  - Refused `PUT` or `COPY`, move onto file, or case variant sets guard: that user's `DELETE` of that path within 10 seconds is `409`, once per refusal; `DELETE` with `If-Match` passes and leaves guard. Refused plain move sets none; two refusals never share guard; a guard ends only by time; none after undo.
- [ ] **FILE-20** (Locks, Dead properties, Listings, Headers, Status codes)
  - Locks are kept by gateway, per user, bounded, never sent to core; `DELETE` drops user's locks on path and below; `MOVE` or `COPY` with source's lock token isn't `412` for want of destination lock.
  - Dead properties: refused, or kept per user and scope up to a bound (past it, least recently set path's dropped), moved with `MOVE`, dropped with `DELETE`; never acknowledged and kept nowhere.
  - `PROPFIND` `Depth: infinity` `403` (`propfind-finite-depth`); no `Depth` is `1`.
  - Gateway serves raw files itself, under revision's `ETag`, never as cross-origin redirect; every response carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox` (PDFs excepted as §7.8). `423` and `507` only for what they mean.

### §H.7 Access and encryption

- [ ] **FILE-6** (Grants, Users) Gateway either passes each user's grant through as bearer of every core request, or holds its own grant and narrows it per user with `via`; one that narrows serves only trees configured as lacking tree-derived access, hiding from each user what that user's narrowed grant can't read.
  - User = root `sub` plus `key` that verified root block (from `GET /ns/{ns}/principal`). User's own entries: `grant` has its `sub` and a `kid` that named its `key` when written; in tree with tree-derived access, also those in content namespaces whose `grant` has its `sub` and a `kid` that named catalog's key there.
  - Authentication disabled: user = `X-Author`, entries those with that `author`. Operator grants are never users of gateway (`403`).
  - Narrowed gateway grant: user = one named in `via`, own entries only those gateway recorded writing for it. One bearer for everyone is one user; programs sharing grant count as one.
- [ ] **FILE-21** (What a user's tokens share, Re-checking) Guards, user's own deletes, move-aside marks and records are per user. Scratch files, placeholders, locks with owners and dead properties are kept per user and scope (root block without `kid`, `sub`, `nbf`, `exp`, `at`, `enc`, `signers`; narrowing blocks without `nbf`, `exp`; `ns`, `can`, `roles`, `groups` compared as sets), served only to token of that scope whose grant names namespace. Read caches are per token.
  - Per-user state is bounded; new scope when content scopes are full: `503` with `Retry-After`, never dropping one holding content.
  - Gateway creates state for grant only after core accepted it, bounds the users it keeps state for, re-checks grant at least every five minutes, relies on `writer` block 30 seconds at most (re-read after `409 frozen`, `422 nonce` or a limit refusal), and stops serving token core refuses, keeping user's state for other tokens, each re-checked at its next request.
- [ ] **FILE-22** (Limited grants, Catalog writes, Sealed and end-to-end namespaces) A grant limited to some resources lists only in tree with tree-derived access, via tree service; gateway learns what it needs to write, and tree's settings, from `GET /ns/{ns}/principal`. Catalog writes carry fresh `$nonce` where catalog requires nonces or is sealed. Gateway without keys doesn't offer sealed or end-to-end namespaces and never shows their files as writable empty files.

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

### §I.7 Per-resource keys (§E.2.1)

- [ ] **VEC-7** (derivation) §E.2.1 derives `K_r` = `37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25` for `K_e` bytes `00 01 … 1f`, `ns` `demo`, `name` `derby`.

### §I.8 Subject sets and combined checkpoints (§B.5, §B.11.5)

- [ ] **VEC-8** (subject set, combined checkpoint) §B.5 and §B.11.5:
  - subjects `["group:match-desk","user:anna"]` give `gs` `17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm`;
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
  - unpadded, the grant, E3 patch set and E3 prune snapshot of I.13's table seal with its keys, `pl` and tags;
  - I.13's E3 write, with that patch set's JWE as `value`, has genesis id `1ptb7hgvw5g5msprod2l5d2pp5b2mtppz`;
  - I.3's blob under `K_r` with I.13's header seals to the 168 bytes shown, 401 bytes padded;
  - at E3, under key `e0 e1 … ff` with header `{"enc":"A256GCM"}` it seals to the 76 bytes shown, blob id `1chzlyccn2qkoz6mobtbzvzm4s6h7pbi6`, and I.13's blob reference.

### §I.14 Biscuit grants (§C.4, §C.8)

- [ ] **VEC-14** (token, revocation ids) §C.4 and §C.8: I.14's token, under root key of seed `00 01 … 1f` (`pub` `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`), carries I.4's root block and narrowing block `{"can":["read"],"via":"svc:reader"}`, with Biscuit's version 1 signature payloads, and has revocation ids `15swdvi5nbnlkv76v7y6k77h52atov6ru` (the grant id) and `1chpmwycvsbh7sqmzckzhe7hk6obtra72`.

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
42. Remote branch `B` on deployment D, whose server lacks `sealed`, of source `N` on A raised to `sealed` after `at` → `GET /ns/B/rev/{ns_id}/heads` → the rows of resources `B` answers `502` for carry `kind` and `target`, never `created`, `size` or `digest`, which could confirm guessed content (§7.4, §1 Conformance)
43. A caller who may write the target but can't read the source, or a source that doesn't exist → `Blob-From` copy carrying `If-Match` → `428` in both cases, before the source check, so the answer shows nothing about the source (§7.8 Copying, check 4)

### Tree-derived access (§B.11, used by Addenda A and H)

**Invariant.** No request widens any subject's roles at any node, as judged at its grant's decision, except one by `catalog-admins`. A hidden node is indistinguishable from a missing one to every request but a `catalog-admins` organising one, except where the text names `409` because names aren't secrets. Only a role that counts through the catalog's key (its `can`, `roles`, `groups`, `sub` and `rules`) grants, shows or powers anything. A listing URL serves a reader only the subject set its credentials prove.

Personas and folders are those of the §B.11 worked example:
- **Folders:** `season-2026` (`match-desk: desk`, `translators: translator`, `fan-club` and `user:li`: `reader`), and TR, the "Transfer rumours" folder (`inherit: false`, `editors-in-chief: desk`).
- **Content:** `matches.derby` is placed in `season-2026`.
- **Roles:** `desk` lists `create` and `restore`.

1. desk (bob) → Create a folder `previews`, `to: [season-2026]` → grant: the new name is exempt from the `404`, and bob has `move` at `season-2026`. The same with `to: [TR]` → `404`, since TR is hidden from him (§B.11.4 Create a folder)
2. Folder F without `$access`, parents P1 (`group:a: desk`) and P2 (`group:b: desk`), a caller only in `a` → Place into F → `403`, since powers are judged per subject (§B.11.2 Tree powers)
3. Caller not in `catalog-admins` → Create a folder or Place with `to: []`, or Move, rename, unplace or delete a node without parents that it can see → `403`. The same for a root hidden from it, such as the example's `root` → `404` (§B.11.4 answers, §B.11.5)
4. Caller in `catalog-admins` → the same requests, a Place aside (49) → granted, with no tree power needed. A hidden or orphaned node can be named (§B.11.4, §B.11.5)
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
49. A `catalog-admins` member not in `matches`'s `catalogs.cat-season.place` → Place `derby` into `season-2026`, or with `to: []` → `403`. A member in the list → granted, with no tree power needed (§B.11.4)
50. Content key whose `sub` scope `svc:bot` matches; a caller with root `sub: "svc:bot"` → `POST /grants` for an item → `403`, since no role counts through the key for a `sub` that doesn't start with `user:`; listings hide the item alike (§B.11.2 Through the key, §B.11.5)
51. Item in a namespace the catalog doesn't trust, purged or not → `POST /grants` with `append`, `create` or `restore`, or `/read-grants` → `403`, before any `404`, `409` or `410` (§B.11.4, §B.11.5)
52. `derby` purged; a caller whose only role at its placement counts for `read` but has a `/now` rule, so doesn't make it visible → `POST /grants { "item": "/r/matches/derby", "want": ["restore"] }` → `403`, not `410` (§B.11.4, §B.11.5)
53. Release preview with private `matches-r7`; a viewer whose grant there is fixed to `derby` (no unrestricted `read`), in the same subject set as an admitted viewer → preview listing → `403`, and no edge grant from the preview service's exchange, so no cached preview reaches it (§B.5 Previews, §B.11.5)
54. File tree whose `root` is missing; li → `lookup?path=Season 2026/…`, and a gateway's top level → both start from li's visible roots, as where `root` is hidden (§B.5 `lookup`, §H.3)
55. Visible node `X` whose only parent `P` is (a) live but hidden, (b) tombstoned or (c) dangling → `roots`, `where` and `ancestors` for that subject set → the same answer in all three cases: `X` is a root, so a hidden live parent can't be told from a missing one (§B.11.5, §B.11 Invariant)
56. A grant that verifies in none of the namespaces a tree service follows → a listing at any `/g/{gs}` → `401`, as with no credential, never `403` (§B.11.5)
57. End-to-end catalog `cat-season`; release step 2 unplaces `matches.derby`, and the plan's approver isn't in `catalog-admins` → no merge grant (`404`, `not_offered`) and no admin path, so the step waits. With an approver in `catalog-admins` → submitted unchecked under a `catalog-admins` member's grant, through the merge service (§F.8)
58. File gateway on its own grant, narrowed per user, that isn't configured for a tree → the tree isn't served, whether or not it has tree-derived access (§H.7 Grants)

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
43. Namespace raised `sealed` → `e2e`; a grant with `enc` and no `nbf` in any block → `POST /keys` → `200` with no key of an epoch before the raise (Levels, §E.2.3 Which epochs)
44. E3 namespace, raised from `sealed` or not; a `read` grant without `enc` → `POST /keys` → `422 invalid`, never a raw `key`, pre-raise epochs included (§E.2.3 Responses)
45. E3 `keyring` write with an entry whose `kid` names another namespace or an epoch above `encryption.epoch`, whose `to` or `from` isn't a thumbprint, whose `wrapped` isn't 80 bytes, or with a member beyond the four → `422 invalid`. A branch's first `keyring` write that keeps the base's read-through entries → `422` (§E.3.2 Keys)
46. E3 rotation to revoke a reader, where the server has added a `to` entry to `keyring` → the key holder re-wraps only for the readers in its own configuration, so that `to` gets no entry for the new epoch (§E.3.2 Keys)
47. Raise `sealed` → `e2e`; blob `b` referenced by a pre-raise revision and by a post-raise one → `b` is never served in the clear, and its epoch URLs serve only under the pre-raise revisions' epochs (Levels)
48. Sealed catalog, per-entry sealing; the entry's head is in epoch 6, and a value it carries derives from a revision in epoch 3 → that value is sealed in place under epoch 3, never under 6. An entry whose epoch the service's grant gets no key for is served by name only (§E.2.6)
49. E3 branch `Z` of `N`; `N` had `historyEpochs: 1` and epoch 6 at `at`; a reader whose latest `nbf` is in `N#3` → `POST /ns/Z/keys` → `N`'s entries for epochs 5 and 6 only (§E.2.3 At E3)
50. Remote branch `R1`, at-rest, whose follow of A's log misses `N`'s raise entry but receives sealed log ranges or namespace documents → B raises `R1` to `sealed` (§G.5.2)
51. Remote branch on a server offering `sealed` but not `e2e`; source raised from at-rest or `sealed` to `e2e` after `at` → B raises the branch to `sealed`, as far as Levels allow, and SHOULD rebase; reads are served sealed, never below `sealed` and never `502` (§1 Conformance, §12.1 `upstream`, §G.5.2, Levels)
52. Bundle import where the importer can't read the protection of the target or of its `{ns}-upstream` → refused at step 1, override or not (§G.5.1)
53. Sealed bundle with a blank line, a non-canonical envelope, `last` beside `pl` in a line header, or an extra `pl` member → rejected whole (§G.5.1.1)
54. Remote branch of a source that isn't E3, referencing a schema revision in an E3 namespace on A → creation `422 schema_unavailable` (§G.3 step 3, §12.1)
55. Public sealed namespace, valid grant without `read` → `POST /keys` → `403`, not `404` or ignored (§E.2.3, §C.2, §7)
56. Authentication disabled, sealed namespace → `POST /keys` → the current epoch's key only (§E.2.3 Which epochs)
57. E3 reader folds a revision whose patch set doesn't open, or whose `pl` or `kid` doesn't match → flagged, and the fold continues as if it were `[]` (§E.3.2 Validation)
58. E3 write whose `sealed` op's protected header isn't canonical, or carries a member besides `alg`, `enc`, `kid` and `pl` (such as `zip`, `crit` or `cty`) → `422 invalid`, so each sealing has one serialisation, as §E.2.2 requires (§E.3.1, §E.2.2)

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
51. A grant naming only `docs`, with a block rule whose `pattern` RE2 refuses, sent to private `secret` → `401`: every token check before the `ns` check is a stateless request-shape error, so nothing about `secret` is consulted (§C.2 item 1, §6.2)
52. A token whose narrowing block is signed over Biscuit's version 0 payload, which doesn't bind the previous signature → any request → `401` (§C.8)
53. Private `matches` behind a verifying edge. A `GET` with a valid edge cookie and an empty `Authorization` field → the edge forwards it without its verification headers, and the origin answers `401`, since the cookie counts only on a request that passes check 1 (§C.5.3)
54. An entry recorded with `grant: null` while authentication was disabled. Under `grants`, a retry of it by a grant whose root `sub` equals its `author` → `412`, not `200` (§7.2, §1 Conformance)
55. A reader on `GET /r/matches/derby/events`, past replay and waiting for live entries; the grant is revoked, then `derby` gets a revision before the next keep-alive → the revision is not sent, and the stream ends: live entries are log pages fetched, judged again first. Grant scope 48's live case (§7.3)
56. A caller with `purge` and without `read` → purge of a name that never existed, with `If-Match` → `404`, with no `head`, never `412`. Without a precondition → `428` (§6.2 step 2.5, §7.2)
