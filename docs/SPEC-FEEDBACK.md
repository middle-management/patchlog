# Reference-implementation notes for the spec writer — draft v0.39

This repository is the **reference implementation** of Patch Log. The canonical
text of SPEC.md is maintained outside; the copy in `docs/` is a **mirror** of it.
Conformance matters: where an implementation question arises, the reference's
answer is what other implementations are measured against, and the text should
follow it — not the other way around.

This file records the deltas the reference took (through v0.9.0 plus the
Unreleased conformance fixes) that the text doesn't yet describe, with wording the
mirror can adopt. Section A states determinations: the behavior is settled in the
reference and its tests, so the text is asked to describe it. Section B pins
one-sentence answers to underspecified corners, where the reference's behaving-one-
way choice is stated. Section C holds the decisions the spec writer owns, with the
reference's position given as the proposal; C3 and C4 are places where the
reference already departs from text that is currently unconditional, so the
writer decides whether the text relaxes or the reference changes. Section and line
references are against `docs/SPEC.md` at v0.39.

## A. The text should say what the reference does

The reference took a position (documented in its README or CHANGELOG, and pinned
by tests — see each item). The mirror should adopt the position; where the
wording matters more than the mechanism, the suggested text is given.

### A1. Namespace log-range sealings are a bounded cache, not "stored once, served forever" (§E.2.2)

"Stored once, served forever" (L2980) and "stored sealed bytes are served unchanged
forever" (L2992) have no carve-out for ranges, but a range's sealing is keyed by
`since`, and every `since` in the chain defines one canonical page: a reader walking
all of them forces O(entries) stored JWEs, each the size of a page (~a log page of
entries, so orders of magnitude more than the summed `ns_log` rows). The
implementation stores ranges in the same `sealed` table but keeps at most 4096 per
namespace, oldest evicted, re-sealed on demand with fresh bytes
(`internal/core/sealed.go:28-35`, 58–59, 413–421; README documents the cap).
Documents and revisions are never evicted — the invariant holds for everything the
sentence literally names ("sealed bytes for a revision").

Deterministic re-sealing was considered and rejected for the implementation: deriving
key and nonce from the range's content would make eviction invisible, but a later
version adding fields to what is sealed (the very backfill §E.2.2's L2980 sentence
contemplates, and which happened for `grant` in v0.37) would re-use a key and nonce
over different plaintexts.

**Text to adopt:** give ranges their own sentence, e.g.:

> Namespace log ranges are sealed under the epoch key and stored as served, but a
> deployment MAY bound what it keeps (oldest first, by count); a re-request of an
> evicted range is sealed again. Entries and documents never are.

If the writer instead wants byte-stable ranges, that is a new normative design —
key, nonce derivation, and what happens when the sealed fields change — which the
reference would then implement; nothing in v0.39 provides it.

### A2. Gestures on config writes (§7.2, §7.4)

v0.39 defines gestures on resource writes and batch steps (§7.2 L744ff). Three
edges are unspecified:

- **Config writes.** The old reference ignored `Gesture`/`Undoes` headers on
  `PATCH /ns/{ns}` silently; the current one treats a config write as the single
  write its log entry already looks like (§7.4 L788 allows `gesture`/`undoes` on
  it), validating (`400`), storing the members outside the id, echoing them on the
  response and answering a retry with what was recorded (pinned by a test). **Text
  to adopt:** state that "a write" in §7.2 covers namespace-document writes.
- **A batch's config change.** Batch-level gesture headers are per-*item*-step
  defaults; a batch config change gets none. State that.
- **Undo of a config change** is out of §11.2's scope. State that.

### A3. The gestures listing's edges (§7.4)

- **Cursor wire form:** `X-Log-Next` on the listing is `"{resource}/{id}"`, not the
  §7.1 text-form id (ids identify content, not resources — they repeat across the
  list). Implementations and clients cannot share §7.1's paging code for it.
  **Text to adopt:** name the cursor in the endpoint's definition.
- **Purged resources:** the listing leaves out rows of purged resources (§8.3 makes
  even their content unanswerable) — worth a parenthetical.
- **E2/E3 namespaces:** the endpoint is optional; the reference answers
  `404` with `code: "not_offered"` after authorisation. `not_offered` is not in
  §12's table. **Text to adopt:** add it there (or a different code, which the
  reference would then follow).

### A4. §7.4 says the core reads `includes` in role entries

L814 ("the core reads `can`, `rules` and `includes`") misattributes: `includes` is
the catalog's role-inclusion relation (§B.11.4), and the reference's role parser
reads only `can` and `rules` (`internal/grant/keys.go:343-375`). §C.1.1 correctly
gives `includes` no core semantics. **Text to adopt:** drop `includes` from that
sentence.

### A5. E3 cannot use `keep`, so §8.6 should not offer it (§8.6 L1241 vs §13 L1534)

L1241 says at E3 "protect schemas with `keep` or `retention`"; L1534 (§13) concedes
`keep` "assumes a document" the server cannot compute. The implementation refuses
`keep` for e2e resources with a plain `422` (`internal/core/nsops.go`), keeps every
revision's declared blob list instead, and requires the key-holder's `snapshot`
(built in v0.9.0: served at `/rev/{H}`, never a log entry, matching the v0.38 text).
**Text to adopt:** drop `keep` from L1241's E3 advice — at E3 the protections are
`retention` (applied by a key-holding janitor, L1251) and the sealed snapshot; the
reference refuses `keep` with `422`.

## B. Underspecified — the reference's answer, to pin in one sentence

### B1. Request-shape errors vs authentication on the document paths

§6.2 orders the *gate* (auth before precondition; §7.2 and §7.8 make the intent
explicit; §7.8 even puts blob uploads' `400`/`415`/`413` after auth). For
`PATCH /r/…`, `DELETE /r/…`, `PATCH /ns/…` and batch item structure, the reference
answers malformed names, content types, preconditions, gestures and bodies with
`400`/`413`/`415` before the grant is looked at — state-safe, since they reveal
only the request's own malformation. **Text to adopt:** "A request whose shape the
resource's state does not influence (its names, content type, header and body
syntax, §7.2) may be answered `400`/`413`/`415` before authentication; nothing
else may."

### B2. Config-only batches

The reference accepts a batch with `items: []` (or absent) and a `config` change:
one `batch` entry, and — because item costs are per item — no rate tokens, where
the same change as a single `PATCH /ns` write draws one (pinned by a test). The
reference is indifferent between keeping this (free) and charging the config
write's token; **the text should pick one**. If the writer prefers charging, the
reference changes a `len(items) == 0` guard.

### B3. The batch body limit's reading bound

L877: "the server stops reading a body larger than that principal's batchSize at
once (`413`)". The reference bounds the read at
`batchSize·5/4 + 512·maxItems + max(patchSetSize, documentSize) + 64 KiB`
(`internal/core/write.go:311-337`), because the item count that sizes the real 413
lives inside the body, which cannot be known before reading it; the true size check
is step 4. The intent (nothing about any item is revealed) holds; the letter
doesn't. **Text to adopt:** relax the sentence ("…plus room for the batch's own
envelope"); the strict bound is unreachable without a fixed-position header.

## C. Decisions the writer owns, with the reference's position

### C1. Author signatures: stored, not verified (§C.3, §G.4.1)

The reference's position: the `Signature` header is stored with revisions and
served in logs, and nothing verifies `patchlog-sig-v2` — not at the gate (§C.3
doesn't require it) and not on bundle import, where §G.4.1 L3739 says signatures
"are verified against the header's `origin`" (the format carries them; nothing
checks them).

**Proposal:**

- §C.3: keep storage-only in the text; verification stays an optional client
  behavior ("A server MAY verify and reject"), with an optional per-namespace flag
  (the §C.9 open question) as future work.
- §G.4.1: make the importer sentence a requirement on bundle *tools* (who verify
  when the source's keys are known), or a SHOULD — so the reference's "carried,
  not verified" is a documented, deliberate position rather than an unimplemented
  MUST.

If the writer instead wants verified signatures as the default, that is a feature
the reference then builds (per-namespace `verify` flag first).

### C2. E3 retention's janitor (§8.6)

The reference's position: the server skips e2e namespaces (retention is the
key-holding janitor's job, L1251), and E3 retention is a client-library
responsibility — the reference's Go client now has the pieces (sealing, folding,
keyring administration). **Proposal:** say so, with a short profile: a consumer
with `read` and `prune`, holding the epoch keys, which computes and submits the
prunes as a client (§6.2's `prune` envelope, the sealed `snapshot` of §8.6,
refusing `keep` per A5).

### C3. Should a forced purge by a deployment operator skip namespace rules? (§6.4.3)

**What the reference does today:** it skips namespace rules for a purge that is
accepted only because of `?force=1` and a grant chained to a deployment operator
key (`internal/core/nsops.go`, `purger` returns `operator`). It does the same for
`purge-ns`. In every other case rules still run:

- a purge forced with a branch's own `*` key;
- a purge with authentication disabled.

**What the text says:** §6.4.3 says rules "see every action, including … `purge`,
… and `purge-ns`". Its only exception is a config write by a `*`-key principal.
So the reference departs from the text here.

**Proposal:** relax §6.4.3 to match the reference:

> Namespace rules apply to `config`, `branch`, `export`, `prune`, `delete`,
> `purge` and `purge-ns`, except when the request skipped the `in_use` refusal
> (§6.1) under a deployment operator grant: that purge is the operator's
> cryptographic override, and namespace rules do not judge it. A purge forced with
> a branch's own `*` key is still judged.

**For:** forcing exists for exactly the cases where policy refuses. A rule like
"only the `ops` group may purge" has the same shape as an `in_use` refusal, and
the operator must be able to override it.

**Against:** this lets a deployment operator bypass a namespace's own rules, which
the namespace's administrators may not expect. Rules would then never bind the
operator on purges.

**If the writer keeps the text as is,** the reference runs namespace rules on
operator-forced purges too. That is a small change: drop the `operator` skip.

### C4. May a sealed branch of a sealed, non-public base be public? (§7.4, §7.6, §C.5.1)

**What the reference does today:**

- It allows a `read: "public"` branch of a sealed base whose `read` isn't
  `public`.
- Such public sealed branches don't count as dependents that block the base from
  going private or sealed (`internal/core/nsops.go`, `sealedPair`; covered by a
  test).

**What the text says:** §7.4 (`422`), §7.6 and §C.5.1 forbid this without
exception, so the reference departs from the text here.

**Proposal:** relax the text with one sentence in §7.4, mirrored in §7.6 and
§C.5.1:

> Unless the branch is sealed (Addendum E): it serves ciphertext only, so it may be
> public whatever its base's read mode is — name and timing metadata are the base's
> own, which its readers already see.

**For:** everything a sealed namespace serves is ciphertext (§E.2.2). The metadata
a public branch exposes is what the base already publishes to its own readers, and
branch names appear in the base's log either way (§7.6).

**Against:** a public branch exposes the existence, size and timing of its writes
to anyone, not only to readers of the base. It also adds a case readers of §7.4
must remember.

**If the writer keeps the text as is,** the reference refuses such branches with
`422` and counts them as dependents again.

## D. Confirmed resolved by v0.37–v0.39 (no action)

For the record — these review findings were all fixed in the spec and the
implementation during v0.37–v0.39 and re-verified in this round: namespace log
grant references and `merge.authors` matching (§5, §7.4, §F.3, §F.6), strict
namespace-document members with `x-` latitude and per-entry `revoked`/`keys`
(§7.4), paged log ranges with whole-range `404`/`410` and the `/heads` byte order
(§7.1), `GET /` and its auth mode (§1, §7), CORS for browsers (§7), the retry-on-
purged order (§6.2, §7.2), catalog visibility/restore rules (§B.11), E3 prune
snapshots (§7.1, §8.6), group commit (D.8), and the v0.39 gestures core (§7.2,
§7.4, §7.5, §11.2) including their travel through merges, bundles, archives,
pruning and remote mirroring.
