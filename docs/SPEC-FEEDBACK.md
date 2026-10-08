# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.46**. This file
collects what the reference does that the text doesn't yet describe.

## Open

From implementing v0.46. Each gives what the reference chose.

1. **"Counts as a referrer" for `schemaReads` reads** (§6.1). Read as: an unpurged resource
   of a listed namespace whose head (or last live document, if tombstoned) reaches the
   revision through `$schema` and the `$ref` closure. Narrowings: only the listed
   namespace's own resources (not what a branch reads through); a schema document's own
   `$ref`s don't count (as for refusals); only namespaces the grant names are considered.
   *Propose:* define it in those terms.
2. **`schemaReads` reads behind a verifying edge.** An edge that knows only prefixes can't
   decide a read of `N` under a grant for `L`, so such reads must reach the origin.
   *Propose:* say so (they're served `private`).
3. **Edge-grant cookie paths.** Cookies are scoped to `/r/{ns}` and `/ns/{ns}`, which by
   RFC 6265 path matching also covers `GET /ns/{ns}` itself; the text writes `/ns/{ns}/…`.
   *Question:* is the namespace head covered?
4. **Edge-grant failures.** If any namespace a grant names doesn't exist or fails
   verification, the whole request answers `401`/`403` rather than skipping it, which would
   reveal existence.
5. **Edge grants and roles.** A grant is refused if any read-allowing role has a rule an edge
   can't evaluate, though roles are alternatives. Conservative; *question:* is that the
   intent?
6. **Edge-grant lifetime and cookies.** Lifetime is min(grant `exp`, 15 min). `SameSite` is
   `None` when credentialed origins are configured, else `Lax`; the text names neither.
7. **Operator grants to a namespace that doesn't exist** are `401`, except a forced purge
   (`404`). *Propose:* state it next to the list of what operator grants authorise.
8. **Keys following the base:** a kid the branch added itself, which the base later adds and
   then removes, falls back to the branch's own entry. The text covers only kids copied at
   creation.
9. **Index hit values** are lists under the field's path (`"/tags": ["a"]`), and a path both
   facet and sort shows its facet values. `fields` names a path some document has rows at; a
   path a schema marks but no document has yet is `400`. *Propose:* give the format.
10. **Catalog titles:** a placement's own `title` wins over the item's head title.
11. **Merged gestures and undo** (§11.2): `Undo` with the source author's name plans
    against the merger's entries in the base. *Propose:* say that undoing a carried gesture
    is the source author's to do.
12. **Dry runs draw rate tokens** (§6.6, §7.5). Rate limits are checked in step 1, and a dry
    run runs steps 1–6, so it draws what the submit will. §G.4.4's dry-run-then-submit
    therefore costs each batch twice. Retry-After is whole seconds (at least 1), so under a
    fast allowance a 429 costs a second when the deficit refills in milliseconds. *Propose:*
    say whether dry runs draw, and count them in §G.4.4's pacing if they do.
13. **Backfill pacing** (§G.4.4) is "a fraction of the namespace rate", but the importer's
    own `ratePerPrincipal` (a tenth of the namespace's by default) answers 429 first. The
    reference paces at a fraction of the lower of the two, and under an allowance at the
    allowance's full rate, since its bucket holds up no other writer; §G.4.4 mentions
    allowances only for one atomic batch. *Propose:* say both.
14. **Allowances with authentication disabled** (§6.6, §1): an allowance names a root `sub`
    and `kid`, but there is no `kid` then. The reference matches `sub` (the author) alone,
    first entry wins. *Propose:* specify it, since clients predicting their allowance need it.
15. **`/heads` and the namespace log for readers limited per resource** (§7.4): the reference
    checks `read` on the namespace (resource `""`), so a grant whose rules hide some
    resources still lists their names and heads, where `GET /r/{ns}/{name}` is `404`.
    `/grants` and branching require unrestricted read (§7.4, §7.6). *Propose:* require
    unrestricted read for listings, or filter them.
16. **`/heads` of a purged namespace** (§8.5): every `/r/{ns}/…` is `410`, but the listing
    isn't covered; the reference lists formerly existing resources as `purge`, and nothing
    says the namespace is purged short of its log (or `frozen`, which the importer uses).
    *Propose:* `410`, or a `purged` marker.

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
