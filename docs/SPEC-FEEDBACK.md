# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.50**. This file collects what
the reference does that the text doesn't yet describe.

## Open

From implementing v0.50. Each gives what the reference chose.

1. **Grants in the body of `POST /edge-grants`** (§C.5). The text doesn't say what
   `Content-Type` the body form needs. A `text/plain` form from another site goes without a
   CORS preflight, so it could post `{ "grants": [T] }` with an attacker's grant and replace a
   reader's cookie for the same prefix, since cookie names come from the prefix alone. The
   reference requires `application/json` (`415` otherwise), and answers `404 not_offered`
   before looking at the body while authentication is disabled. *Propose:* require a
   non-simple content type, as `DELETE /edge-grants` relies on preflights.
2. **The cookie's claims** (§C.5 "Format"). The reference refuses claims with members other
   than `kid`, `p` and `exp`, or that aren't canonical JSON byte for byte. It holds one key
   and one `kid` (`-edge-grant-kid`), so replacing either invalidates every cookie until
   clients exchange again. Without `sub`, it attributes a cookie read to `edge:` plus the
   prefix. *Question:* may a minter add members, and is rotation (several `kid`s at once)
   expected of an origin?
3. **Edge verification headers** (§9). Several `X-Edge-Prefix` values, or one an intermediary
   joined with commas, aren't addressed; the reference requires exactly one value and treats
   anything else as unverified (`no-store`). It doesn't require the cookie it verifies itself
   to match the prefix, since it authorises the read from the cookie anyway. *Propose:* say
   "exactly one prefix".
4. **What check 2 refuses** (§C.5, §3.6, §7). "`400` anyway (§7)", but neither §7 nor §3.6
   says an empty segment (a trailing `/`) or a dot segment is `400`; the reference answers
   `400` for both, `//` and `%` included. As written the rule also fails `/` itself, which the
   origin serves (harmlessly: no prefix covers it). *Propose:* state it in §3.6 or §7, and
   exempt `/`.
5. **Services and §9** (§9, §B.11.5). The reference applies §9 to an index's or tree
   service's own origin too: no refusal, lifetimes only for reads an edge verified. Services
   read callers from `Authorization`, so their private listings are always `no-store` at the
   edge; they could be cached only under cookies a service mints with its own `kid`, bound to
   a `gs`, which §B.11.5 doesn't describe. *Question:* is that the intended path for cached
   private listings?
6. **Issuance and rate limits** (§C.5, §6.6). "Its own principal's rate limits", but limits are
   per namespace and a grant may name several. The reference draws one token per grant under
   the first namespace it issues, from the bucket writes use, and only once nothing is
   refused. Its buckets admit while one token is left and may go into debt, as writes of
   several items do, so two grants of one principal pass under a burst of 1. *Question:*
   which namespace's limits, and does a request drawing `n` tokens need `n`?
7. **Counting names** (§C.5). The reference counts each grant's distinct fixed names once,
   not names times namespaces, so one grant of 60 names over two namespaces gives 120 cookies
   and passes. Every literal of every fixing rule must be a valid name, even one the
   intersection removes. *Propose:* say which count is meant.
8. **A purged sealed namespace's log** (§8.5, §E.2). "`/ns/{ns}` and its log stay readable",
   but a namespace purge destroys the epoch keys, so sealed delivery can't seal the log: the
   reference answers `500 encryption_unavailable` there. *Question:* is a purged sealed
   namespace's log served from its stored sealed copies, or as the structural log in the
   clear?
9. **A remote branch of a purged base** (§G.3). The reference names the first purged
   namespace found, A before its bases, and answers `410` for any `at`, one A doesn't know
   included, as for a local branch, by reading A's `/heads` first. A base further up can only
   be purged after A, so that case reports A. *Propose:* say both.
10. **Repeatable parameters** (§A.4, §A.5). Canonical URLs sort a repeated parameter's values,
    which changes the meaning of any parameter whose values are ordered or read first-wins.
    The reference's multi-key `sort` is now one comma-separated parameter (`400` if
    repeated), and a tree listing parameter other than `min` given twice is `400`.
    *Propose:* say repeatable parameters are order-insensitive and a single-valued one given
    twice is `400`.
11. **`min` on an `at` the service no longer keeps** (§A.5, §A.4). "To the same URL without
    it", which then redirects to the current checkpoint, two hops against the bounded-redirect
    SHOULD; the reference goes to the current checkpoint in one. It can judge whether an older
    combined `at` (tree, `/_refs`) includes a `min` only while it keeps that `at`'s
    per-namespace checkpoints, and never for a bare `{ns_id}`; on a single-namespace index
    URL, a `min` naming another namespace is never included. *Propose:* "or to the current
    checkpoint, if the service can't judge `at`".
12. **"May this reader read all of these?"** (§B.11.5). "If a grant comes back for every
    item", but public items get `"public": true` and no grant, and per-item `5xx` entries
    (`behind` when the catalog lags, `upstream`) are undecided. The reference counts public
    items as readable, a `4xx` entry as a refusal and a `5xx` one as "ask again", and caps a
    request at 100 items. *Propose:* "a grant, or public, for every item", and allow a limit.
13. **Which refusals carry `checkpoint`** (§B.11.4). The reference adds it to `403`, `404`,
    `409` and `410` decided at it, but not to refusals decided from state it doesn't pin (a
    `409` for a name the core has and the service hasn't seen, a catalog key missing at the
    head). Keying cached decisions by the combined checkpoint drops them on any write to any
    trusted namespace, though a decision depends on the catalog and the item's own namespace
    only. The change log says decisions "carry their `at`"; the text names `checkpoint`.
    *Propose:* say which refusals carry it.
14. **Renamed imports** (§G.4.4). Several points the text leaves open, as the reference does
    them:
    - a mapping onto a branch whose base chain reaches `src` keeps references and ids;
    - a renamed namespace's upstream is `{dst}-upstream`;
    - an incremental document that would change is refused, since `requires` is a source id;
    - a pin whose new id can't be known (external, left out, a snapshot's revision) is refused,
      and so is a schema whose `$id` names its own revision path;
    - documents of unmapped namespaces that reference a renamed one are rewritten too;
    - a reference declared only by a later revision's schema is rewritten there by an added
      `replace`;
    - with fresh nonces ids differ between runs, so a re-run recognises its earlier writes by
      the import batches' `source.ids`.
    *Propose:* say which of these are intended.
15. **Undo by writers limited to some resources** (§11.2). At E3 such a writer can't learn the
    current epoch or pad, which are in the namespace document, so the reference refuses. A
    gesture a merge carried counts for the merger, since only the namespace log shows the batch
    counted as a merge. Resource logs carry no markers, so a gesture that may reach below a
    pruning horizon is refused as impossible, and `UndoSince` is dropped, since `/heads` needs
    unrestricted read. Plain and at-rest can't be told apart from reads. *Question:* how does
    such a writer learn the epoch and pad, and are the others intended?

## Settled in v0.50

All fifteen v0.49 notes, and Doors' S15–S19 and F12–F14. As the reference did them:
- **Retrying the creation of a branch since purged** (2): the retry rule lasts until the
  branch is purged, `412` after (§7.6).
- **What "after the read check" covers** (4): the full read check, rules included, and
  `purged` before any other answer, `not_offered` included (§8.5).
- **Upstream appends** (5) aren't changes to existing dependencies (§G.4.4).
- **Namespaces whose documents `/_refs` can't read** (10) are left out (§A.4).
- **Kept listings** (11) mustn't outlive the reads they were computed for (§A.4).
- **Batches in flight** (12): dependency order is per batch, live references don't order,
  what upstream namespaces need comes first in a cycle, and a request counts as drawing when
  it is sent (§G.4.4).
- **Compressed patch sets** (14): how things are stored is the implementation's choice, as
  long as reads serve the exact canonical bytes and ids and limits are computed over them
  (§5).
- **A whole-document genesis as a snapshot** (13) and **TOAST compression on Postgres** (15)
  left with Addendum D, which is now the prototype's `PROTOTYPE.md`: both are the
  implementation's choice.
- **Schema revisions a public referrer pins** (Doors S18) are public; §6.1 says so.

Adopted with more than the reference did, which now follows the text:
- **Edge-grant issuance's `410`** (1) carries `ns` as well as `head`: the first refused
  namespace in the order the grants and their root blocks list them (§C.5, §12).
- **Dry-running a promotion** (6): where the limits allow, a promotion within one namespace
  goes as one batch; otherwise dry runs reach as far as the reference's deferred and
  skipped batches (§G.4.4).
- **Writers limited to some resources** (7): intended. There is no sealed gestures listing;
  such a writer scans the logs of the documents it knows the action touched, and learns the
  level from what it reads (§11.2). The client's undo takes those documents
  (`UndoResources`).
- **`min` on `at` URLs** (8) always redirects, dropping `min`, so a `200` is served only at a
  URL without it (§A.5).
- **The canonical query form** (9): parameters sorted by name, then value, every byte but
  unreserved ones percent-encoded in uppercase hex; services answer `200` only at that form
  (§A.5).
- **Edges** (Doors S15, S16, S17): only reads an edge verified get edge lifetimes, and the
  edge says which prefix it verified (`X-Edge-Prefix`). Reads with a grant in
  `Authorization` and referrer schema reads are `no-store` and need no edge, so the origin
  no longer refuses unverified private reads (`403 edge_required` is gone). A default cookie
  format with a `kid`, and what an edge MUST check (§9, §C.5).
- **Several grants per exchange** (Doors F12): `{ "grants": [ … ] }`, and rules fixing
  `/resource` to a finite set, one cookie per name, at most 100 names (§C.5).
- **Catalog decisions** (Doors S19, F13): they depend on the content namespace too, so
  read-your-writes passes `min` for both; answers carry the combined `checkpoint` they were
  decided at; `/read-grants` answers "may this reader read all of these?" (§B.11.4,
  §B.11.5). A service may mint edge grants for derived output under its own `kid` (§C.5).
- **Renamed imports** (Doors F14): an import may map a set of namespaces to new names,
  rewriting references and recomputing ids (§G.4.4). Configuration in bundles stays open
  (§G.7).

Decided against the reference, which now follows the text:
- **A remote branch of a purged base** (3) is `410 purged`, not `gone`, with `origin`, `ns`
  and `head` naming the purged namespace on the base's deployment (§G.3, §12).

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
