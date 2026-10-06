# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.40**. This file
collects what the reference does that the text doesn't yet describe.

## Open

### P1. Signer keys and signature verification (§C.3, §C.9, §G.4.1)

This proposes answers to two §C.9 questions:

- how signers' keys are published;
- whether signatures can be required.

The reference would build it behind a flag first. Nothing here changes ids, the
signing input (`patchlog-sig-v2`) or existing data.

**The trust chain.** A signature is checked by following one chain, every link of
which is either immutable or already in the hash-chained logs:

1. `Signature: <alg>:<kid>:<sig>` on a revision.
2. A `signer` fact with that `kid` in the root block of the grant the revision was
   written under. The revision's grant reference identifies that grant (§C.3).
3. The key that signed that root block. This is a namespace key from the namespace
   document in force at that log position (§C.4), or a deployment operator key.
4. For a namespace key, the namespace log. For an operator key, the deployment's
   published key history (P1.6).

Verifying an old revision therefore uses the keys in force *when it was written*,
not today's.

**P1.1 Keys live in grants.** A grant's root block may carry
`signer(kid, alg, pub)` facts.

- The issuer who vouches for a principal's authority also vouches for their
  signing key, so no new registry is needed.
- Rotating a key means issuing a new grant. Old revisions keep pointing at the
  grant they were written under.
- Only root-block facts count. Attenuation blocks can be added by any holder, and a
  holder must not be able to add a key of its own.
- A delegated grant therefore signs with the delegator's keys, or none.

*Alternative considered:* a `signers` member in the namespace document. It is
versioned and hash-chained, but makes every author's key change an admin config
write and puts per-person data in configuration. It may still be worth it for
signers outside the grant system, such as long-lived bots.

**P1.2 Reading grants.** Add `GET /ns/{ns}/grants/{id}`. It returns the stored
non-bearer form (§C.3), immutable and cacheable.

- Grants reveal a principal's groups and attributes, so it needs unrestricted
  `read` on the namespace. Sealed namespaces seal the answer like any other.
- Bundles exported with `"authors": true` carry the non-bearer grants their history
  references (§G.4.1), so they verify offline.

**P1.3 Verification at the gate.**

- When a write carries `Signature` and its grant's root block has a `signer` fact
  with that `kid`, the server verifies it. A bad signature is `422`,
  `code: "signature"` (v0.40).
- This runs after authentication: it depends on the grant, so it isn't a
  request-shape error (§6.2).
- A `kid` the grant doesn't name stays unverified, as today, unless signatures are
  required (P1.4).
- At E3 the signature covers the canonical sealed patch set, so the server verifies
  it without decrypting.

**P1.4 Requiring signatures.** Add a namespace-document member
`signatures: "optional" | "required"`, defaulting to `"optional"`. Under strict
members (§7.4) it has to be listed. With `"required"`:

- a resource write, or a batch step, without a valid signature from a `signer` of
  its grant is `422 signature`. Readers can then rely on "every revision here is
  signed by its author".
- Changing the member needs a `*` key.
- Batch steps need a signature each: step objects (§7.5, v0.39) gain an optional
  `signature`. The request header covers single writes.
- **Merges and replays** (§F.3) are written by the merger, so the original author's
  signature can't verify in the target. In a `"required"` namespace the merger
  signs its own steps, and the original signature stays as provenance, verifiable
  against the batch's `source`.

**P1.5 Bundle tools.** §G.4.1's SHOULD becomes concrete: verify each signature
through the chain above, using the bundled grants, and the source's namespace keys
or operator keys (P1.6). An importer carries signatures either way, and reports
the revisions it could not verify.

**P1.6 Cross-deployment keys: a well-known key history.** Within a deployment,
link 3 is answered by the namespace document. Across deployments it isn't always:

- a bundle carries no namespace documents;
- a remote reader may lack `read` on the base's document;
- operator keys are configured outside the system (§C.4 bootstrapping).

Propose a key history published as a JWK Set (RFC 7517), so any JOSE library can
parse it.

- **Discovery:** `GET /` gains `"jwks_uri"`, the URL of the set, as OIDC discovery
  does (§7, §G.1). Verifiers read it there rather than guess a path. It lives at
  the deployment's canonical origin, which the signing input already binds.
- **Default path:** `/.well-known/patchlog-keys`, a name that could be registered
  with IANA (RFC 8615). `/.well-known/jwks.json` isn't a registered name, only a
  convention. On a shared domain an identity provider or API gateway often serves
  its own token-signing keys there. Mixing those with grant-root keys would let a
  verifier accept a key for a purpose it was never meant for. A deployment that
  owns its domain outright may still point `jwks_uri` at `jwks.json`.
- **Keys:** OKP/Ed25519 JWKs. Each carries `kid` and `use: "sig"`, plus the
  Patch Log members described below. Generic JWKS consumers ignore those members,
  which is another reason not to share a generic path.

- **What it lists:** the deployment's operator keys, plus the keys of its public
  namespaces. It lists no keys of private namespaces, since that would reveal they
  exist (§E.4).
- **It's a history, not a current set:** keys are never removed and `kid`s are never
  reused. Each key carries the period it was in force (`nbf`, and `exp` or
  `retired`), its role (`"patchlog": "operator"` or `"namespace"`) and, for
  namespace keys, `ns`. A signature verifies against the key in
  force at the revision's position, so rotation never breaks old signatures.
- **Bundles of private namespaces** instead carry the key entries of the namespace
  document revisions their grants verify against. The bundle digest covers them, so
  they are trusted as far as the bundle's origin is.
- **What it isn't for:** author keys. Those stay in grants (P1.1), so a deployment
  can't swap an author's key without the issuer's signature.

**The open question this leaves:** trust in a deployment's published key set
rests on TLS and the origin. That's the same trust a remote branch already places
in its base (§G.3), but a verifier that wants more needs the operator keys
distributed out of band. The spec should say which it expects.

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

- how signers' keys are published (proposal P1 above);
- what `/rev/{id}` serves at E3 for revisions other than a prune's snapshot;
- test vectors for the byte-exact definitions.
