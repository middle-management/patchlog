# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.49**. This file collects what
the reference does that the text doesn't yet describe.

## Open

From implementing v0.49. Each gives what the reference chose.

1. **Which `head` edge-grant issuance's `410` carries** (§8.5, §C.5). The all-or-nothing answer
   is `410 purged` only when every refused namespace is purged, but a grant may name several,
   each with its own `purge-ns` entry. The reference gives the `head` of the first one the
   grant's root block names. *Propose:* say which, or add `ns` to the body.
2. **Retrying the creation of a branch since purged** (§7.6, §8.5). §7.6 answers a retry by the
   same principal with the same `at` and `patches` `200`, and §8.5 keeps a purged name
   reserved. The reference answers `412`, to the creator too: the branch the retry would name
   no longer exists. *Propose:* say that the retry rule doesn't outlive a purge.
3. **A remote branch of a purged base** (§G.3, §8.5). Creating a remote branch on B whose base
   on A, or a base of it, is purged answers `410` with `code: "gone"`: it isn't a write to a
   purged namespace on B. *Question:* should it be `purged`, with A's `purge-ns` entry as
   `head`, as for a local branch of a purged base?
4. **What "after the read check" covers** (§8.5, §7.4, §E.2.3). The reference answers a purged
   namespace's `410` only once the grant's rules have been applied too: `404` for a grant whose
   rules refuse the read (at E3, the keyring's), `403` at `/keys` for one that reads neither
   unrestricted nor per resource. The gestures listing of a purged sealed or e2e namespace is
   `410`, not `404 not_offered`. *Propose:* say the full read check, and `purged` first.
5. **Upstream appends as "existing dependencies"** (§G.4.4). Batches that change existing
   dependencies are dry-run first. The reference dry-runs later batches that move heads the
   target had (fast-forwards, resolved conflicts, restores), but not a snapshot's next diffs
   upstream: live references see only pinned upstream revisions, not its heads, and the next
   import picks up a diff whose target batch didn't follow. *Propose:* say they aren't.
6. **Dry-running a promotion end to end** (§G.4.4 "Partial failure"). A dry run sees only what
   is committed, so a later batch that depends on earlier, unsubmitted ones can't be checked
   alone. The reference's `-dry-run` dry-runs each later batch that moves heads the target
   had, reports failures that only need earlier batches written as deferred, and skips one
   that goes on with a chain an earlier batch cut. *Question:* is that "end to end", or should
   a tool submit such a promotion as one batch where the limits allow?
7. **Writers limited to some resources** (§11.2, §C.5, §C.7, §E.2). They can't read the
   namespace document, so they don't know its encryption level either; the reference takes it
   as unknown and adds nonces. In sealed and e2e namespaces they can't undo at all: there is
   no gestures listing, and the namespace log needs unrestricted read. *Question:* intended?
   If not, a gestures listing sealed like log ranges would serve them.
8. **Sealed answers at an `at` URL with `?min=`** (§A.4, §E.2.6). §A.4 answers `200` on an
   `at` URL whose `at` already includes every `min`, but §E.2.6 binds a sealed answer's `view`
   to the URL "as the redirect gave it", which has no `min`. The reference redirects such a
   request to that URL. *Question:* is that what §A.4 means for sealed answers?
9. **The canonical query form** (§A.4, §E.2.6). With `next` a bare `after` for `/_refs` and for
   name-paged `?ref=` queries, a client building the next page rarely orders the query as the
   service's redirect would, so a sealed page costs one more redirect. The reference's
   canonical form sorts the query's keys. *Propose:* state the canonical form.
10. **Namespaces whose documents `/_refs` can't read** (§A.4). The text gives `502` when the
    grant names the namespace; the reference leaves any other such namespace out, as one the
    reader can't see. *Propose:* say so.
11. **Kept listings when reads change** (§A.4, §B.5). In a tree service, a content namespace
    turning private changes neither the anonymous URL space nor `gs`, so a kept listing could
    reach a reader who may no longer read it. The reference also keys kept listings by what
    the reader reads whole, and doesn't serve one kept from before. *Propose:* say that a kept
    result mustn't outlive the reads it was computed for.

12. **Batches in flight at once** (§G.4.4 "Submit batches in dependency order"). The reference
    submits several batches at once under an allowance: a namespace's batches once those of the
    namespaces it depends on have committed, and within a namespace a batch after those holding
    documents it pins. It orders items by pinned references (schemas included), not by live
    ones, which name no revision that must exist, and orders namespaces the same way: a pin of
    a full document needs its namespace, a snapshot document's pin of a bundled snapshot
    document its upstream namespace. Within a cycle of namespaces it puts what upstream
    namespaces need first (schemas, full documents), then them. It paces each request before
    it is sent, counting one in flight as drawing no earlier than now: the server draws when
    it handles a request, possibly after later ones. *Propose:* say that dependency order is
    per batch, that live references don't order, and how "Upstream first" holds in a cycle.
13. **A whole-document genesis as a snapshot** (D.4). An intermediate snapshot falls after 64 KiB
    of patch sets, which a large create's genesis is by itself, doubling its writes for a copy
    of what the genesis holds. The reference counts a genesis that adds the whole document as a
    snapshot: the count starts after it, and a read there cuts the document from its canonical
    patch set. *Propose:* say so in D.4.

## Settled in v0.49

All twenty v0.47–v0.48 notes. As the reference did them:
- **`POST /ns/{ns}/keys`** (2) is named as a second exception to unrestricted read (§C.5).
  Epoch keys need unrestricted read, so the reference now answers `403` (was `404`) to a
  `read` grant that has it neither whole nor per resource (§E.2.3).
- **Read checks for branching and registration** (3) are gate step 1's (§C.5); the reference
  now makes them in public namespaces too, where registration checked no read and branching
  skipped the rules on `/action`, `/principal` and `/now`.
- **Edge-grant prefixes** (5) are the cookie paths, each covering its own URL and what lies
  below it.
- **`DELETE /edge-grants`** (6): no `prefix` or a bad one is `400`, a repeated one is withdrawn
  once, the answer is the same with authentication disabled, and `prefix` is the core's one
  repeatable parameter (§7); issuance is `404 not_offered` then (§12).
- **`$nonce` in schema documents** (8): a fresh top-level one isn't a keyword (§6.5).
- **Imports into missing namespaces** (14): the operator creates them first, with keys that
  include the importer's and an allowance for it (§G.4.4).
- **Bounded redirects** (15): a service SHOULD answer `200` at an `at` it redirected to for a
  while (§A.4), tree services too (§B.5), which the reference's tree service now does: a
  minute, at most 64 MiB per catalog, in a store shared with the index (`internal/kept`).
- **What marks a path with `x-index`** (16) is defined keyword by keyword as the reference
  walked them, `$dynamicRef`, `dependentSchemas`, `prefixItems` and `contains` included
  (§A.4); a table test now pins it.

The reference changed to follow the text:
- **`purged` on writes** (1) is in §12, and every write to a purged namespace is `410 purged`
  after authorisation and rate limits (§8.5): config writes, namespace purges, branching,
  registration and batches with a config change answered `gone`, the last before their
  items' authorisation.
- **Referrer reads in a public listed namespace** (4): one that is public and neither sealed
  nor e2e opens the revisions it pins to every request, a grant then ignored; any other
  referrer needs a grant that verifies there (§6.1). The reference counted a grant naming a
  public listed namespace unverified, and refused a read without one (`401`).
- **All or nothing with a purged namespace** (7): `410 purged` only when every refusal is a
  purge and the grant verifies there (§C.5). The reference now decides it after verification
  and the read checks, with `purged` and `head` instead of `gone`.
- **Requiring nonces with branches in place** (9) is refused, `409 in_use` with `dependents`,
  leaves first (§7.4, §C.7); the reference allowed it.
- **Remote branches and mirrored schemas** (10): the base's current document when the branch
  is created decides (`422` otherwise), and mirrored schema namespaces start `optional` and
  take their source's setting with a config write once their history is in, `optional` if it
  can't be read (§C.7, §G.3). The reference went by the base's document at `at`, and created
  mirrored namespaces with the setting.
- **`invalid` or `nonce` first** (11): a missing nonce is `422 nonce` in a sealed namespace
  too, a failed `test` or patch `invalid` first (§C.7). The reference answered `invalid` in
  sealed namespaces that don't require nonces.
- **Undo needs the setting** (12): not exposed; a writer that can't read the namespace
  document adds a fresh `$nonce` in any private namespace instead (§C.7, §11.2). The reference
  went by the current document's `$nonce`; undo, `schema import`, the release tools and the
  playground now use `client.NeedsNonce`, and undo no longer stops at the unreadable
  encryption level.
- **Dry runs in imports** (13): each existing namespace's first batch and a new one's first
  item, but batches that change existing dependencies are dry-run first (§G.4.4). The
  reference now dry-runs later batches that move heads the target had, `-dry-run` too.
- **`/_refs` answers** (17): the body, byte order, `limit`, and `after` as `{ns}/{name}` with
  `next` the following page's `after`; on an `at` URL, a `min` already included answers `200`
  (§A.4). The reference paged by offset with a `next` URL, and always redirected an `at` URL
  with `min`. It still sends `at` as `X-Namespace-Revision`, which the text doesn't mention.
- **`gs` for `/_refs`** (18) is over markers only, `reads:{ns}` and
  `reads:{ns}:scope:{digest}`, a namespace whose limiting rules refer to `/now` counting as
  unreadable, always under `/g/{gs}` (§A.4). The reference also hashed the reader's groups
  and subject and digested its whole principal; it now also takes one unrestricted read role
  as reading a namespace whole, as §C.5 does.
- **What `/_refs` covers** (19): branch previews count; namespaces not reached yet, purged
  ones and those without keys are left out, a `min` naming one `400`; `502` only for a
  namespace the grant names (§A.4). The reference waited for unreached ones, and answered
  `502` for any.
- **`/heads` of a purged namespace** (20): every `410 purged` carries `head`, the `purge-ns`
  entry, which is the log's last (§8.5, §10). The reference added it, and `internal/follow`
  takes the purge's position from it.

v0.49 also has a `ref` query without `q` or `sort` page by name as `/_refs` does (§A.4); the
reference now does.

## Settled in v0.48

None of the reference's notes; v0.48 (from Doors) took up two questions the text itself had
left open: `"nonce": "required"` (D15, §C.7) and references across namespaces (D19,
`GET /_refs`, §A.4).

## Settled in v0.47

All sixteen v0.46 notes. Adopted as the reference did them:
- **`schemaReads` referrers** (1) are defined as proposed (§6.1).
- **Referrer reads behind a verifying edge** (2) reach the origin, which serves them
  `private`.
- **Edge-grant cookie paths** (3) cover the namespace URL itself.
- **Edge-grant failures** (4): all or nothing, `401` if any namespace's answer is, else `403`.
- **Edge-grant lifetime and cookies** (6): the sooner of `exp` and 15 minutes; `SameSite=None`
  with credentialed origins, else `Lax`.
- **Operator grants to a missing namespace** (7): `401`, a forced purge `404`; the `ns`
  check's `403` comes first, and a purged namespace is `410`.
- **Keys following the base** (8): a branch's own `kid` applies again once the base removes
  it; one copied at creation never does.
- **Catalog titles** (10): a placement's own `title` wins.
- **Merged gestures and undo** (11): undoing a carried gesture is the source author's to do.
- **Dry runs draw rate tokens** (12), `429` bodies carry a decimal `retryAfter`, and §G.4.4
  counts dry runs in a backfill's pacing.
- **Backfill pacing** (13): a fraction of the lower of the namespace's and the importer's
  rate, or an allowance's full rate; per-resource buckets still apply.
- **Allowances without authentication** (14) match `sub` alone, the first entry winning.
- **Listings for readers limited per resource** (15): `/ns/{ns}` and everything under it but
  the gestures listing need unrestricted read, now defined once (§C.5).
- **`/heads` of a purged namespace** (16) is `410 purged`; the log's `purge-ns` entry says so.

Decided against the reference, which now follows the text:
- **Edge grants and roles** (5): roles are alternatives, so one qualifying read role is
  enough, with the blocks and key scope on top (this fixes implementer report B8).
- **Index hit values** (9) are as the reference gave them, but `fields=` is checked against
  schema marks, not the data: a marked path no hit has values at is left out, not `400`.

## Settled in v0.46

Doors' feedback (D1–D22, forwarded with v0.45): `schemaReads` (D1, as option (a) narrowed to listed
namespaces), `POST /edge-grants` (D2), `?min` on the grant endpoints (D3), service-created
branches (D4, with scoped branches left open), keys following the base (D5), hit values and
`fields` (D6), operator grant scope (D7), filtering proxies (D8), the gestures listing
(D9), merged gestures (D10), `x-index` arrays (D11), schema documents in the index (D12),
self-references (D13), `roles: []` (D14), nonces in merges (D15, `"nonce": "required"` left
open), `[]` restores (D16), Addendum D (D17), titles (D18), presence (D20), starting from
heads (D21) and `inheritPowers` (D22). Cross-namespace reference queries (D19) stay open
in §A.7.

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
