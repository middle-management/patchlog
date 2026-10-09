# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.48**. This file collects what
the reference does that the text doesn't yet describe.

## Open

From implementing v0.47 and v0.48. Each gives what the reference chose.

1. **`purged` in §12, and on writes** (§8.5, §12). §12 lists `gone` (410) but not `purged`,
   and the text doesn't say what writes in a purged namespace get. The reference answers
   `purged` to resource writes, purges, prunes and batches with items, and `gone` to
   namespace-level writes (`PATCH /ns/{ns}`, a namespace purge, branching, registration,
   config-only batches). *Propose:* add `purged` to §12, and name the code for writes.
2. **`POST /ns/{ns}/keys` and unrestricted read** (§C.5, §E.2.3). It is under `/ns/{ns}/`,
   which §C.5 now reserves for unrestricted readers except the gestures listing, yet §E.2.3
   serves restricted grants their `K_r` there, as the reference does. *Propose:* name it as a
   second exception.
3. **Unrestricted read for branching and registration** (§7.6, §G.3). The reference checks the
   read rules as gate step 1 does, leaving rules over `/doc` and the rest of the envelope to
   step 6; otherwise a grant limited by `/doc` rules, as §G.3 suggests, could never register.
   *Propose:* say that this check is step 1's.
4. **Referrer reads in a public listed namespace** (§6.1). The reference counts any grant
   naming a public listed namespace as able to read its referrers, unverified, since public
   reads ignore grants (§7), while a referrer read with no grant is `401`. *Propose:* say
   whether a referrer read needs a grant that verifies in the listed namespace.
5. **The form of edge-grant prefixes** (§C.5). The text writes prefixes as `/r/{ns}/…` and
   `Path` as the prefix without `/…`, so `prefixes`, which `DELETE /edge-grants` takes back,
   could be either. The reference uses the cookie paths (`/r/{ns}/{name}`, `/r/{ns}`,
   `/ns/{ns}`) and refuses other shapes with `400`. *Propose:* give the form.
6. **`DELETE /edge-grants` details** (§C.5, §7). The reference answers no `prefix` with
   `400 bad_input`, withdraws a repeated one once, and answers `204` with authentication
   disabled too, where issuance is `404 not_offered`; `prefix` is the first repeatable core
   parameter, against §7's "each at most once". *Propose:* state these, and the §7 exception.
7. **All or nothing with a purged namespace** (§C.5). The text ranks `401` over `403`; the
   reference ranks a purged namespace's `410 gone` last, so it is the answer only when every
   refusal is one. *Propose:* say where it falls.
8. **`$nonce` in schema documents** (§6.1, §6.5, §C.7). §6.5 makes any unknown keyword
   invalid, so a schema document couldn't carry the top-level `$nonce` that a namespace
   requiring nonces (or a sealed one) needs. The reference treats a fresh-form top-level
   `$nonce` as mechanics, not a keyword. *Propose:* say so in §6.1 or §6.5.
9. **Requiring nonces with branches in place** (§C.7, §7.6). Turning it on at a base whose
   branches lack it isn't refused, unlike raising encryption above them (`409`); they may keep
   it off, and drop it once the base does, since "can't turn it off" is judged against the
   base's current setting. *Question:* refuse it, or is "set it at creation" enough?
10. **Remote branches and mirrored schemas** (§C.7, §G.3). A remote branch created without the
    setting of a base that requires nonces is `422`, not given it; its shadow keeps the base's
    setting at creation. Mirrored schema namespaces take their source's current setting,
    `optional` if B can't read it. *Propose:* say which setting (current, or as of `at`), and
    what applies when it can't be read.
11. **`invalid` or `nonce` first** (§E.2.5, §C.7). A namespace both sealed and requiring
    nonces could refuse a missing nonce either way; the reference answers `422 nonce`.
    *Propose:* state the precedence.
12. **Undo needs the setting** (§11.2, §C.7). The setting is in the namespace document, which
    now needs unrestricted read; a reader limited to some resources goes by whether the
    current document has a `$nonce`, which misses tombstones of documents written before the
    setting. *Propose:* expose it to such readers, e.g. in the gestures listing.
13. **Dry runs in imports** (§G.4.4). "Dry run, then resolve conflicts" and "Blobs first" read
    as a dry run per batch. Since batches are atomic and a dry run draws what its submit does
    (§6.6), the reference dry-runs only each existing namespace's first batch, and a created
    one's first item. *Propose:* say so.
14. **Imports into missing namespaces under authentication** (§G.4.4, §C.4). One bearer can't
    both create namespaces (an operator grant) and write them (a namespace grant, `401` for a
    namespace that doesn't exist yet). *Propose:* note that the operator creates them first,
    listing the importer's key and allowance.
15. **Bounded index redirects** (§A.4). "Redirects to the current checkpoint" has readers
    chase it under steady writes. The reference computes and keeps (a minute) the result at
    the `at` a redirect names, so one redirect suffices at any write rate, `/_refs` too; §B.5
    words this for the tree ("if that exact result was stored"). *Propose:* a service SHOULD
    compute or keep that result.
16. **What "marks with `x-index`" means** (§A.4). The reference counts an `x-index` reachable
    from the schema along the path, whatever the data: through `$ref`, `allOf`/`anyOf`/`oneOf`
    and `if`/`then`/`else`, not `not`, `unevaluated*` or `propertyNames`; array items at their
    array's path. *Propose:* define it, so implementations agree on which paths are `400`.
17. **`/_refs` answers** (§A.4). Paging, order and body are unspecified. The reference orders
    hits by namespace, then resource, pages with `limit`/`after`/`next` as `?ref=` does, adds
    `namespaces: { ns: ns_id }` (what `at` covers), sends `at` as `X-Namespace-Revision`,
    seals per entry, and redirects an `at` URL with `?min=` to the current `at`. *Propose:*
    specify them.
18. **`gs` for `/_refs`** (§A.4, §B.11.5). §B.11.5's subjects don't say which namespaces a
    grant reads, or reads only in part; the reference adds `reads:{ns}` and
    `reads:{ns}:scope:{digest}` markers. A reader of no private namespace gets the empty set's
    `gs`, still under `/g/`. *Propose:* `gs` keys all the answer depends on. *Question:* a
    public form without `/g/`?
19. **What `/_refs` covers** (§A.4). Left out: namespaces not reached yet, purged ones, and
    sealed or e2e ones whose keys the service lacks (a `min` naming one is `400`); branch
    previews count, so a referrer can show in base and branch. Only a reader who sees no
    namespace gets `401`/`403`; an unreadable namespace document is `502`. *Question:* follow
    only roots?
20. **`/heads` of a purged namespace** (§8.5, §10). A consumer that gets `410 purged` there
    has to re-read `/ns/{ns}` and assume its head is the `purge-ns` entry. *Propose:* carry
    that entry's `ns_id` in the `410` body, and say that nothing follows `purge-ns` in a log.

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
