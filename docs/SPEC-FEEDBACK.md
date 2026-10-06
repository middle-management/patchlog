# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.41**. This file
collects what the reference does that the text doesn't yet describe.

## Open

From implementing v0.41 (§C.3.1). Each gives what the reference chose.

**Gate**

1. **The parent at step 1.** The signing input needs the parent, but step 1 runs before the
   head is read. The reference uses the `If-Match` id (none for a create): a write only
   passes its precondition when that id is the head it is written on, so this keeps §6.2's
   order exactly. A write with no precondition (`428`) or a malformed `If-Match` (`400` at
   step 2) can't be verified, so it falls through to those errors. A missing signature in a
   `required` namespace is still `422` at step 1. *Propose:* say the parent is the
   precondition's id.
2. **A malformed `Signature`** (header or step member, not `<alg>:<kid>:<sig>` with
   base64url) is `400 bad_input`, as request shape. A listed kid with an `alg` other than
   Ed25519 fails verification (`422`). *Propose:* name the status.
3. **Idempotent retries.** Signatures are checked before the retry lookup. A retry whose
   signature doesn't verify is `422`, not a replay; so is an unsigned retry, after
   `required` was turned on, of a write made before. *Question:* which should win?
4. **A batch whose config change has a stale precondition.** Listed kids are verified
   against the current configuration, but `required` isn't applied, since the change's
   effect is unknown. As with an authorisation failure there, the batch answers `412`.
5. **Failures inside a batch** are reported per item in the `batch` error, with
   `items[].code: "signature"`, like other step-1 failures.

**Grants and logs**

6. **Resource logs while authentication is disabled.** Namespace logs serve
   `"grant": null`; resource logs leave `grant` out, since the revision row records no
   mode. *Question:* should resource logs serve `null` too?
7. **"Recorded by entries"** for `GET /ns/{ns}/grants/{gid}` is read as namespace log
   entries; a write's revisions record the same grant as its entry. A purged namespace
   answers `410` after the `read` and `not_offered` checks; the text is silent on it.

**Operator key history**

8. **`from` for keys already configured.** Nothing says how a deployment establishes when
   an existing operator key came into force. The reference publishes it from the
   deployment's first namespace log entry (or start time if empty), unless the operator
   lists a period. Keys listed with an `until` in the past are published but authorise
   nothing. The JWKS is served `application/jwk-set+json`, `public, max-age=300`.
   *Propose:* name the media type and say the period of a key is the operator's to declare.

**Bundles (§G.4.1)**

9. **How a history line names its grant.** Grant lines carry `grant: gid`, but nothing says
   how a revision line points at one. The reference adds `grant: gid` to history lines
   (with authors). A line naming a grant with no earlier grant line, a duplicate grant
   line, or a grant line without `authors` is refused. *Propose:* specify the member.
10. **(important) Sealed and end-to-end bundles can't carry grants.** §C.3.1 says "their
    bundles carry the grants", but the endpoint isn't offered there and no other API gives
    the exporter them. The reference writes no grant lines for such namespaces, so their
    signatures verify as unverifiable, and says so in the export plan's notes. *Propose:*
    either offer `GET …/grants/{gid}` sealed (sealed like a log range), or serve grants
    through the `export` verb.
11. **Branch bundles.** A signature binds the namespace it was written in, but a branch
    bundle names the exporting branch as `ns` on every line, so a revision the branch reads
    through from its base fails the digest under the branch's name. *Propose:* lines (or
    grant lines) record the namespace a revision was written in, when it differs.
12. **Key lookup for `key`.** The exporter takes the first of: the namespace document's keys
    at the position of the first revision naming the grant; the operator JWK Set at that
    revision's `created`; any version of the namespace document. The text says "the key
    entry the grant's root block verified against at the source", which an API-only
    exporter has to reconstruct this way.
13. **Archives (§8.6)** keep signatures but no grant lines, so archived signatures report
    as unverifiable. *Question:* should archives carry grants like bundles?

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
