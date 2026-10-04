# Feedback for the spec writer — draft v0.39 ↔ implementation

This file collects change requests for SPEC.md found by the conformance review that
ran against the v0.9.0 implementation (see the Unreleased section of CHANGELOG.md for
what the implementation side already fixed). Items are grouped by who should move.
Section and line references are against `docs/SPEC.md` at v0.39.

## A. The spec should say what the implementation deliberately does

The implementation took a position, documented it in its README or CHANGELOG, and
the spec text was never updated. Each item below should either be adopted (preferred,
with suggested wording) or rejected — in which case we will change the code instead.

### A1. A forced purge by a deployment operator skips namespace rules (§6.4.3)

The code skips namespace rules for a purge accepted only because `?force=1` and a
grant chained to a deployment operator key verified (`internal/core/nsops.go`,
`purger` → `operator`), and for the same reason on `purge-ns` — but only then: a
branch `*` key forced purge still runs rules, and purges under authentication
disabled run rules. §6.4.3 (L505–513) says rules "see every action, including …
`purge`, … and `purge-ns`" and defines exactly one rule skip (config writes by a
`*`-key principal). README and CHANGELOG document the operator behavior.

**Request:** adopt it in §6.4.3, so the text names the second skip. Sketch:

> Namespace rules apply to `config`, `branch`, `export`, `prune`, `delete`,
> `purge` and `purge-ns`, except when the request skipped the `in_use` refusal
> (§6.1) under a deployment operator grant: that purge is the operator's
> cryptographic override, and namespace rules do not judge it. A purge forced with
> a branch's own `*` key is still judged.

Rationale: forcing exists for exactly the cases where policy refuses (a rule like
"only the `ops` group may purge" that the operator must be able to override is the
same shape as an `in_use` refusal).

### A2. A sealed branch of a sealed, non-public base may be public (§7.4, §7.6, §C.5.1)

The code allows a `read: "public"` branch of a sealed base whose `read` is not
`public`, and does not count such public sealed branches as dependents blocking a
base from going private/sealed (`internal/core/nsops.go:296-301`, comment "a
relaxation of §7.4"; pinned by a test). §7.4 L834 (`422`), §7.6 L941 and
§C.5.1 L2358 are unconditional. Everything served from a sealed namespace is
ciphertext (§E.2.2), and `?` metadata is identical to what the base already
publishes to its own readers.

**Request:** adopt, as one sentence in §7.4 (and mirrors in §7.6 and §C.5.1):

> Unless the branch is sealed (Addendum E): it serves ciphertext only, so it may be
> public whatever its base's read mode is — name and timing metadata are the base's
> own, which its readers already see.

If rejected, the confidentiality argument to hear is the metadata one (branch names
appear in the base's log either way, §7.6), and we will restore the unconditional
`422`.

### A3. Namespace log-range sealings are a bounded cache, not "stored once, served forever" (§E.2.2)

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

**Request:** give ranges their own sentence, e.g.:

> Namespace log ranges are sealed under the epoch key and stored as served, but a
> deployment MAY bound what it keeps (oldest first, by count); a re-request of an
> evicted range is sealed again. Entries and documents never are.

If instead the spec wants byte-stable ranges, it must specify the deterministic
variant explicitly (key, nonce, and what to do when the sealed fields change), and
the implementation will follow.

### A4. Gestures on config writes (§7.2, §7.4)

v0.39 defines gestures on resource writes and batch steps (§7.2 L744ff). Three
edges are unspecified:

- **Config writes.** The old implementation ignored `Gesture`/`Undoes` headers on
  `PATCH /ns/{ns}` silently. The new one treats a config write as the single write
  its log entry already looks like (§7.4 L788 allows `gesture`/`undoes` on it),
  validating (`400`), storing the members outside the id, echoing them on the
  response and answering a retry with what was recorded. **Request:** confirm this
  reading ("a write" in §7.2 covers namespace-document writes) with a sentence.
- **A batch's config change.** Batch-level gesture headers are per-*item*-step
  defaults; a batch config change gets none. Confirm or define.
- **Undo of a config change** is out of §11.2's scope; confirm that is intended.

### A5. The gestures listing's edges (§7.4)

- **Cursor wire form:** `X-Log-Next` on the listing is `"{resource}/{id}"`, not the
  §7.1 text-form id (ids identify content, not resources — they repeat across the
  list). Implementations and clients cannot share §7.1's paging code for it.
  **Request:** name the cursor in the endpoint's definition.
- **Purged resources:** the listing leaves out rows of purged resources (§8.3 makes
  even their content unanswerable) — worth a parenthetical.
- **E2/E3 namespaces:** the endpoint is optional; the implementation answers
  `404` with `code: "not_offered"` after authorisation. `not_offered` is not in
  §12's table. **Request:** add it (or pick another code).

### A6. §7.4 says the core reads `includes` in role entries

L814 ("the core reads `can`, `rules` and `includes`") misattributes: `includes` is
the catalog's role-inclusion relation (§B.11.4), and the core's role parser reads
only `can` and `rules` (`internal/grant/keys.go:343-375`). §C.1.1 correctly gives
`includes` no core semantics. **Request:** drop `includes` from that sentence.

### A8. E3 cannot use `keep`, so §8.6 should not offer it (§8.6 L1241 vs §13 L1534)

L1241 says at E3 "protect schemas with `keep` or `retention`"; L1534 (§13) concedes
`keep` "assumes a document" the server cannot compute. The implementation refuses
`keep` for e2e resources with a plain `422` (`internal/core/nsops.go`), keeps every
revision's declared blob list instead, and requires the key-holder's `snapshot`
(built in v0.9.0: served at `/rev/{H}`, never a log entry, matching the v0.38 text).
**Request:** drop `keep` from L1241's E3 advice — at E3 the protections are
`retention` (applied by a key-holding janitor, L1251) and the sealed snapshot; the
server refuses `keep` with `422`.

## B. Underspecified — one sentence either way

### B1. Request-shape errors vs authentication on the document paths

§6.2 orders the *gate* (auth before precondition; §7.2 and §7.8 make the intent
explicit; §7.8 even puts blob uploads' `400`/`415`/`413` after auth). For
`PATCH /r/…`, `DELETE /r/…`, `PATCH /ns/…` and batch item structure, malformed
names, content types, preconditions, gestures and bodies answer `400`/`413`/`415`
before the grant is looked at (state-safe: they reveal only the request's own
malformation). Say which is intended — we'd suggest one sentence: "A request whose
shape the resource's state does not influence (its names, content type, header and
body syntax, §7.2) may be answered `400`/`413`/`415` before authentication; nothing
else may."

### B2. Config-only batches

A batch with `items: []` (or absent) and a `config` change is accepted, writes one
`batch` entry, and — because item costs are per item — draws no rate tokens, where
the same change as a single `PATCH /ns` write draws one (pinned by a test in the
implementation since the behavior was noticed). Is a config-only batch a thing? If
yes: does it draw? (Suggest: it must have the items' cost, i.e. at least one token
from the principal and namespace buckets.)

### B3. The batch body limit's reading bound

L877: "the server stops reading a body larger than that principal's batchSize at
once (`413`)". The implementation bounds the read at
`batchSize·5/4 + 512·maxItems + max(patchSetSize, documentSize) + 64 KiB`
(`internal/core/write.go:311-337`), because the item count that sizes the real 413
lives inside the body, which cannot be known before reading it; the true size check
is step 4. The intent (nothing about any item is revealed) holds; the letter doesn't.
**Request:** either relax the sentence ("…plus room for the batch's own envelope")
or confirm the strict bound and move the size judgment before reading (impossible
without a fixed-position header).

## C. Decisions we need from the spec

### C1. Author signatures: stored, not verified (§C.3, §G.4.1)

The `Signature` header is stored with revisions and served in logs, but nothing
verifies `patchlog-sig-v2` anywhere — not at the gate (§C.3 doesn't require it),
and not on bundle import, where §G.4.1 L3739 says "Signatures are verified against
the header's `origin`" (bundle format carries them; nothing checks them;
`internal/bundle/format.go` says so).

**Request:** decide the trust story. Our suggestion:

- §C.3: verification at the gate stays optional client behavior ("A server MAY
  verify and reject"), with an optional per-namespace flag (the §C.9 open
  question) if deployments want it enforced.
- §G.4.1: keep the importer sentence but make it a requirement on bundle *tools*
  (who verify when the source's keys are known), or downgrade to SHOULD, so the
  implementation's "carried, not verified" is a documented, deliberate gap rather
  than an unimplemented MUST.

### C2. E3 retention's janitor (§8.6)

The spec's story for e2e retention is a key-holding janitor; the server correctly
skips e2e namespaces (retention is their janitor's job, L1251) but nothing defines
what such a janitor is, with which verbs and keys it runs, or how it agrees with
the server on `prune` while the server itself refuses `keep` (A8) and needs the
sealed `snapshot`. **Request:** a short profile — a consumer with `read` and
`prune`, holding the epoch keys, which computes and submits the prunes as a client
(§6.2's `prune` envelope) — or an explicit note that E3 retention is a
client-library responsibility (the implementation's Go client now has the pieces:
sealing, folding, keyring administration).

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
