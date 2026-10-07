# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.45**. This file
collects what the reference does that the text doesn't yet describe.

## Open

### From Doors (an editor built on Patch Log), against v0.45 and 0.14.1

Doors keeps every layout, workflow, route and schema of an organisation in one
`read: "grant"` namespace, with a DAG catalog issuing per-item grants, the tree and index
services, branches per editor and per agent session, and gestures for undo. Its server
bugs are fixed in the reference (CHANGELOG); what follows needs the text. Each item gives
the reference's position.

**Needs a decision (Doors calls these blockers or major)**

D1. **A per-resource write grant can't validate a document pinning schemas in its own
   private namespace** (§6.1, §7.5, §B.11.3–§B.11.4). Catalog grants are
   `readScope: "resource"`, so a typed write whose `$schema`/`$ref` closure pins another
   resource of the same namespace needs a second grant (Doors mints a `Source-Authorization`
   grant over the pin closure). Doors proposes any of:
   (a) validation may resolve an immutable schema revision the document pins without the
   writer's read, since the writer learns only valid or invalid plus error pointers (the
   error must not echo schema content);
   (b) `POST /grants` also returns source grants for the target's pin closure;
   (c) a key-scope flag letting `readScope: "resource"` grants resolve pin closures.
   *Reference:* (a) is simplest to implement and closes the gap for every issuer; the
   residual leak is one bit per pinned revision the writer already names by id. We'd
   implement (a) if adopted.
D2. **Edge-grant issuance** (§C.5, §9). The text defines what an edge grant is, but no
   endpoint or wire format, so a browser can't read a `read: "grant"` namespace without a
   proxy (long-polls with `Authorization` preflight; `EventSource` can't send it). Doors
   proposes `POST /edge-grants` (grant in `Authorization`; answers `Set-Cookie` scoped to
   §C.5's prefix, lifetime ≤ min(grant `exp`, 15 min); credentialed CORS for a named
   origin), and the origin verifying the cookie itself when no CDN is in front.
   *Reference:* agree; it would implement it alongside `-edge-secret`.
D3. **`?min` on `POST /grants` and `POST /read-grants`** (§B.11.4, §B.11.5, §A.5). Grants
   are decided at the service's current checkpoint, so a create grant right after its
   placement, or a read decision right after an `$access` change, can be stale (7–8 of 10
   in Doors' probe). Proposal: both accept `?min={ns}:{ns_id}`, repeatable, with §A.5's
   semantics (wait, else `503` + `Retry-After`). *Reference:* agree; small to implement.
D4. **Branches for folder-limited editors** (§7.6, §F.8). Branching needs unrestricted read
   on the base, so an issuer must branch on the editor's behalf, and everything read
   through is then readable by whoever reads the branch. Proposal: bless issuer-created
   branches (recorded with `via`, the branch reading through per document like the base),
   or a scoped branch whose read-through is limited to what the creator could read at `at`.
D5. **Branches pick up keys added to the base** (§C.4 "Keys follow the base": removals
   reach branches, additions don't). Key rotation means a `*` config write into each of up
   to 100 live branches. Proposal: additions after the branch point are accepted in the
   branch unless the branch removed that kid, or a member opting branches in.
   *Reference:* additions are a smaller trust change than the spec's existing removal
   rule; we'd follow either.
D6. **Index hits that can render a list** (§A.4). Hits carry facet values but not sort
   values or text-indexed fields, so a list of names reads every document (8,092 reads,
   19 s on Doors' largest seed). Proposal: hits carry their sort values and text fields,
   or `fields=/name,/title` (indexed paths only).

**Clarifications**

D7. **What an operator grant may do after bootstrapping** (§C.2, §C.4, §6.1, §C.3.1). The
   reference accepts operator grants for creating namespaces (remote branches included) and
   forced purges; any other request under one is `401` (the key isn't in the namespace's
   configuration). Proposal: list exactly that in §C.4.
D8. **Filtering proxies leak names and timing** (§C.5, §C.6, §7.4, §7.7). A proxy filtering
   `/ns/{ns}/…` per document can't hide that the namespace moved on a hidden edit, and
   `/heads` cursors are names. Proposal: a paragraph in §C.6 on what such a proxy can hide
   (namespace revisions and timing always leak to stream readers; names need re-paging; it
   derives its own cursors).
D9. **The gestures listing needs unrestricted read** (§7.4, §11.2), so a folder-limited
   editor can't find its own gestures in a private namespace. Proposal: answer any reader,
   limited to entries its read envelope allows, or to entries whose grant has its `sub`.
D10. **Merged gestures land under the merger** (§F.3, §11.2), so the author's undo stack on
   the base loses them. Proposal: §11.2 counts a carried gesture for the source revision's
   author (reachable through `source`).
D11. **`x-index` as an array** (§A.2). The reference already accepts `["facet", "sort"]`;
   the text lists single values only. Proposal: "one of `text`, `facet`, `sort`, or an
   array of them".
D12. **Schema documents in the index** (§6.1, §A.1). A document whose `$schema` is a
   dialect URL has no revision to fetch; the reference skips it, so blueprints aren't found
   by `schema=`, `q` or `?ref=` ("which schemas `$ref` this one"). Proposal: say which, or
   index them against the dialect (listed under `schema=<dialect>`, their `$ref` revision
   paths counted as references). *Reference:* would implement the latter.
D13. **Self-references in `?ref=`** (§A.4). The reference lists a document that references
   itself as its own user (three self-calling workflows in Doors' sample). Delete guards
   want them out or flagged. Proposal: exclude, or mark `self: true`.
D14. **`roles: []` allows nothing** (§C.1.1, §C.2): consistent but easy to trip on.
   Proposal: one sentence saying to omit `roles` for a grant without role checks.
D15. **`$nonce`** (§C.7). Reference: merge plans and diffs leave fresh `$nonce` writes out,
   as the gate does (§6.4.1). Doors asks for a namespace member `"nonce": "required"` so
   servers can refuse patch sets without one where wanted, since the SHOULD is easy to
   forget.
D16. **Type-keeping rules and root-replace restores** (§6.4.1, §6.4.4, §8.2). A root
   `replace` overlaps `/$schema`, so a rule "only services change `$schema`" refuses it,
   while a `[]` restore passes. Proposal: an example in §6.4.4, or a root write whose
   `$schema` is unchanged doesn't count as writing it.
D17. **Addendum D is stale** (§D.6 lists namespaces, grants, batches, branches, blobs,
   long-poll cursors and the A/B/F/G services as not implemented). Editorial.

**Proposals (smaller)**

D18. **Titles in tree listings** (§B.5): a catalog-level pointer (e.g. `/name`) the tree
   service copies from each item's head into listings.
D19. **Cross-namespace reference queries** (§A.7): `GET /refs?to=…` over every followed
   namespace, as Doors originally proposed.
D20. **Ephemeral presence**: say in §11 that live presence (pointers at 20 Hz) is out of
   scope and sketch the side channel, or define an unlogged per-resource broadcast.
D21. **Bootstrapping consumers from the log** (§10, §A.6): a new consumer that needs only
   current state scans the log and fetches each resource's last revision (2.4 s at 50k
   items vs 25 s replaying every revision, in Doors' measurements). Recommend it in §10.
D22. **Inherited tree powers** (§B.11.4): an optional per-folder flag letting `place`/`move`
   inherit from parents, still bounded by no-widening.

## Settled in v0.45

All eight open notes, as the reference does them:
- end-to-end grants are `no-store` for shared caches, and edges don't serve them;
- a batch whose config change fails doesn't check its items' signatures;
- batch errors and dry runs report `signature` per item;
- index `refs` paths keep array indices;
- a pinned entry is a fourth `ref` form;
- `refs` appear only in `ref` hits;
- adding references to an existing index means one replay.

## Settled in v0.43

- **Which epoch seals a grant:** the epoch of the first entry recording it, or the branch's
  current epoch for a grant only its base recorded (as the reference did).
- **Repeated query parameters** are `400` (as the reference did).
- **`from` binds** like `until`. The reference now refuses grants signed by an operator key
  before its `from`.
- **A line whose `written` is unknown** carries neither `written` nor `grant` (as the
  reference did).
- The gestures listing's `?after=` (a conformance fix in the reference) needed no change in
  the text.

## Settled in v0.42

Twelve of the thirteen v0.41 notes were taken up, plus unknown query parameters:
- the gate position and the signed parent;
- malformed signatures;
- retries;
- the stale-config batch;
- grants in sealed and end-to-end namespaces, and `410` for purged namespaces;
- operator key periods and media type;
- how lines name grants, `written` and key lookup;
- archives with grants.

The text doesn't mention reporting a `422 signature` per item in a batch error; the reference
keeps doing so, like other per-item failures.

## Settled in v0.41

Proposal P1 (signer keys and verification) was adopted as §C.3.1, with these
refinements over the proposal:

- signer entries are a `signers` array in the root block, not Datalog facts;
- tombstones have a signing input (`tombstone` in place of the patch set);
- the `Signature` header is `400` on a batch request, and each step carries its own;
- a step's `signature` is always the writer's own: merges and imports never re-send
  originals;
- issuers must check proof of possession and never list one `pub` for two subjects;
- `stored` at `GET /ns/{ns}/grants/{gid}` is defined byte for byte;
- bundle grant lines carry the `key` the grant verified against, attested by the
  exporter;
- the JWK Set lists operator keys only, with `"patchlog": { "from", "until"? }`;
  namespace keys come from the namespace log.

## Settled in v0.40

Adopted as the reference already does it:

- **Forced purges under a deployment operator grant** skip namespace rules. A purge
  forced with a branch's own `*` key is still judged (§6.4.3).
- **Request-shape errors** (`400`, `413`, `415`) may come before authentication;
  nothing else may (§6.2).
- **Gestures on config writes** (§7.2, §7.4):
  - config writes carry gestures;
  - a batch's config change gets none;
  - undoing config is out of scope.
- **The gestures listing** (§7.4):
  - pages by `{resource}/{id}`;
  - leaves out purged resources;
  - answers `404 not_offered` in sealed namespaces.
- **The batch body bound** leaves room for the batch's own envelope (§7.5).
- **Sealed namespace log ranges** may be evicted and sealed again (§E.2.2, §9).
- **`keep`** is `422` at E3, and E3 retention is a key-holding client's job (§8.6).
- **Role entries:** the core reads `can` and `rules`; `includes` is the catalog's
  (§7.4).
- **Signatures** are stored and served, and the server doesn't verify them (it MAY
  where it knows the key, with `422 signature`). Bundle tools SHOULD verify when
  they can (§C.3, §G.4.1). The reference stores and carries them without verifying.

Decided against the reference, which now follows the text:

- **A batch's config change costs a token** from the principal and namespace
  buckets unless it is exempt (a `*` key, or only a freeze), as a config write does
  (§6.6). A config-only batch used to cost nothing.
- **A branch of a non-public base can't be public, sealed or not** (§7.4, §7.6,
  §C.5.1, §E.4). Ciphertext would be safe, but names, sizes and timing aren't. The
  reference again refuses such branches with `422`, and counts public sealed
  branches as dependents that keep a base from going private.

Still open in the spec itself (§13), not in the reference:

- what `/rev/{id}` serves at E3 for revisions other than a prune's snapshot;
- test vectors for the byte-exact definitions.
