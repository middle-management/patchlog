# Patch Log — Conformance checklist (draft)

Status: draft, against spec v0.55. This index restates the spec's requirements as
checkable items, so an implementation can be reviewed against the text without reading
every sentence as load-bearing (see the review note on §1's reading convention). Each item
has an id and a section reference; the section text is authoritative, and where this index
and the text disagree the text wins. Items marked **[vectors]** are byte-exact and covered
by `docs/TESTVECTORS.md`.

Suggested conformance profiles (not in the spec; proposed):

| Profile | Contains |
|---|---|
| **Core-minimal** | §1–§10, §12 except: branches (§7.6, refused with `403` per §1), blobs (§7.8), pruning (§8.6) |
| **Core-full** | all of §1–§10, §12 |
| **Auth** | Addendum C |
| **Encryption** | Addendum E, per level (E1, E2, E3) |
| **Federation** | Addendum G |
| Services (A, B), merge tooling (F), file tools (H) | separate checklists below |

## §3 Identity

- [ ] **ID-1** Input JSON is I-JSON; duplicates, lone surrogates, non-finite numbers, and
      integers with 2⁵³ ≤ |v| < 10²¹ (judged by JCS canonical form) are `400`. **[vectors §1]**
- [ ] **ID-2** Storage, serving and hashing use `canonical(v)` (JCS, UTF-8), never the
      received bytes. **[vectors §1]**
- [ ] **ID-3** Ids are 20 bytes, text form `"1" + base32lower`, non-canonical encodings
      rejected. **[vectors §2]**
- [ ] **ID-4** Revision, tombstone, namespace-revision and blob ids follow the §3.3–§3.7
      formulas exactly, including the empty genesis parent and the foreign-parent case.
      **[vectors §2, §3]**
- [ ] **ID-5** Name grammars per §3.6; URLs use names verbatim; percent-escapes in names
      are `400`.

## §4–§5 Invariants and storage

- [ ] **INV-1** Entries are append-only except purge and pruning; each resource's chain is
      linear; namespace chain and namespace-document chain are linear.
- [ ] **INV-2** Every stored non-tombstone revision whose document has `$schema` validates
      against it (see VAL-* below).
- [ ] **INV-3** Every mutating request that takes effect writes exactly one namespace
      entry, atomically with its change (incl. batch = one `batch` entry; blob uploads
      write none; retries write none).
- [ ] **INV-4** Writes are checked against the configuration in force at insertion
      (nearest `config` entry; a batch's own config change for its items).
- [ ] **STO-1** Per §5: ids, parents, kinds, canonical patches, authors, grant references,
      times, gestures persist; any revision's document is servable; purge and pruning
      retain what §5 lists; branch bases answer "head as of ns revision n"; batch
      atomicity under concurrent writers and multiple processes.

## §6.1 Schema references

- [ ] **SCH-1** `$schema` matches the §6.1 grammar exactly (revision path or bundled
      dialect URL); anything else is `422 schema_ref`. No normalisation.
- [ ] **SCH-2** `$ref` resolves only same-document fragments and revision paths with
      optional JSON Pointer fragments; nothing else is fetched.
- [ ] **SCH-3** `$schema`/`$ref` never name a branch (`422 schema_ref`); draft lookup in
      branches follows the candidate rules (local branches of `N`, not E3, own revisions
      only, `drafts.for`, writer's `read` in the candidate).
- [ ] **SCH-4** `schemaReads` opens revision-path reads as §6.1 describes, never heads,
      logs or non-schema documents; it is `422` in sealed/E2E namespaces and needs a `*`
      key.
- [ ] **SCH-5** Tombstoned schema resources' revisions still resolve; unknown, purged or
      unreadable references are `422 schema_unavailable`.
- [ ] **SCH-6** Purge and config writes that would drop the last copy of a referenced
      schema revision are refused `409 in_use` with the `referencing` list; `?force=1`
      with an operator grant (or a branch `*` key for branch purges) overrides and writes
      `forced: true` entries.
- [ ] **SCH-7** Resolving a schema requires `read` on the resolved copy unless
      `schemaReads` opens it.

## §6.2 The gate

- [ ] **GATE-1** Checks run in the §6.2 order; only request-shape errors may precede
      step 1.
- [ ] **GATE-2** Step 1 covers verbs and all rules referring only to
      `/action`, `/resource`, `/principal`, `/now`; a `PATCH` with `If-Match` yields the
      candidate verbs `append`/`restore`; rate limits run last in step 1.
- [ ] **GATE-3** Step 2: retry lookup (same principal only; `200` with the recorded entry;
      purged → `410`) → verb settlement (a settled verb outside the candidates is `403`
      before the `If-Match` comparison) → author signature (`422 signature`) → frozen
      (`409`) → precondition (`428`/`412`).
- [ ] **GATE-4** Steps 3–6: patch application and `test` ops (`422`); nonce check (`422
      nonce`); limits and blob availability (`422 blob`); `$schema` validation over the
      document minus `$schema`, a fresh `$nonce` and a well-formed `$successor`; namespace,
      grant, key and role rules.
- [ ] **GATE-5** Step 7 inserts atomically with the namespace entry. In a batch each step
      runs for every item before the next step starts.
- [ ] **GATE-6** At E3: one `sealed` op (or `[]` for a restore) accepted without
      application; declared-blob list checked; step 5 skipped; rules touching `writes` or
      `/doc` fail the write; deletes see `doc: null`.

## §6.4–§6.5 Rules

- [ ] **RUL-1** `writes` is computed per §6.4.1: `move` writes both ends, `test` writes
      nothing, root ops write `""`, `…/-` records the resulting index, a lone fresh
      `$nonce` add/replace writes nothing. Pointers compare segment-wise after RFC 6901
      unescaping.
- [ ] **RUL-2** All rule forms of §6.4.2 are implemented, including `compare` with
      `value` or `path` RHS, number/timestamp ordering, and the failure modes (missing
      path, type mismatch → false).
- [ ] **RUL-3** Failures: namespace rule → `422` with `rule` index and `path`; grant/key/
      role rule → `403 forbidden`.
- [ ] **RUL-4** Config writes are rule-checked except under a `*` key; operator-forced
      purges skip namespace rules; every other action, `delete`/`purge`/`config`/`branch`/
      `purge-ns` included, sees rules.
- [ ] **RUL-5** `$` keys reserved; `$blob` recognised at any depth; unknown schema
      keywords rejected except `x-*`; fresh `$nonce` in schema documents exempt.

## §6.6 Limits

- [ ] **LIM-1** All §6.6 limits enforced with the listed defaults; refusal is `413`/`422`
      with `code: "limit"`, `limit`, and for sizes and counts `measured` and `max`.
- [ ] **LIM-2** Whole-document bound (`documentSize`) applies to creates and to
      appends/restores whose first non-`test` op is a root `add`/`replace` (further ops
      allowed; root `copy`/`move`/`remove` don't count); at E3 every create/restore gets
      it; batch items still count toward `batchSize`.
- [ ] **LIM-3** Rate limits: token buckets keyed by root `sub` + signing `kid` (by author
      with auth disabled), checked after authorisation, overdraw allowed, `429 rate` with
      `Retry-After` (whole seconds, rounded up) and decimal `retryAfter`. Batch costs per
      §6.6; exemptions (freeze, purge, server entries) honoured. Bucket deduction is
      atomic with the write's admission across instances sharing a database.
- [ ] **LIM-4** Allowances: replace principal and namespace buckets (and a key scope's
      `rate`), cap batches and blob budgets, honour `until`, never exceed deployment
      maximums; first matching entry applies.
- [ ] **LIM-5** Deployment maximums bound every namespace limit; only `retryWindow` may be
      raised by a namespace, up to the maximum; `/limits` writes need a `*` key.
- [ ] **LIM-6** Regexes everywhere are linear-time; backtracking features rejected at
      acceptance.

## §7 HTTP API

- [ ] **HTTP-1** URL canonicality: empty/dot/escaped segments are `400 bad_input`, `/`
      itself excepted. Unknown or repeated query parameters are `400`; flag parameters
      take only `1`.
- [ ] **HTTP-2** `GET /` answers `{ "spec", "auth" }` (+ `jwks_uri`, `origin` when the
      addenda apply). Version comparison is component-wise dotted decimal.
- [ ] **HTTP-3** Existence hiding: public namespaces ignore unusable or foreign grants;
      the `ns` check precedes verification (`403` before `401`); without `read`, existing
      and missing resources both `404`.
- [ ] **HTTP-4** Read table of §7.1 implemented row by row, including `Last-Modified`/
      `Repr-Digest` only outside E2/E3, `If-None-Match`/`If-Modified-Since` (the latter
      ignored where no `Last-Modified` is sent), the pruned-`410` body with `horizon` and
      `archive`, and raw-document `/raw` semantics.
- [ ] **HTTP-5** Log paging: `X-Log-Next` unquoted, equals the page's last entry; pages
      bounded by entries and `logPageBytes`, at least one entry; `404`/`410` judged over
      the whole range; pages are prefixes of their range.
- [ ] **HTTP-6** Writes: precondition always required (`428`), table of §7.2 honoured
      (`412` bodies with `head`, restore semantics, delete answers). Gesture/Undoes
      headers validated (26 base32, else `400`), stored unhashed, replayed on retries.
- [ ] **HTTP-7** Idempotent retry: recomputed id over the request's parent, same
      principal, whole-log search within the retry window, answered `200` as first
      recorded (including recorded Gesture/Undoes).
- [ ] **HTTP-8** `X-Namespace-Revision` on every successful write; write responses
      `no-store`.
- [ ] **HTTP-9** SSE: replay then live, entry ids as event ids, pruned replay → `410`.
- [ ] **HTTP-10** §7.4 rows: namespace redirect and immutable revisions, namespace log
      with `grant`/`gesture(s)` fields and their absence rules, `/heads` (byte order,
      `after` as a plain bound, optional `created`/`size`/`digest` absent at E2/E3),
      `/principal`, `/gestures/{id}` (per-resource filtered, not offered at E2/E3),
      `/grants/{gid}`, `/branches` (unrestricted `read` for both).
- [ ] **HTTP-11** Config writes: `If-Match` takes the config id; guarded members per
      §7.4's list need a `*` key; strict validation with `x-` escape hatch; unknown-member
      tolerance for documents stored under earlier versions; branch config invariants
      (`base` immutable, base `*` keys kept, no public branch of a private base, no lower
      encryption, no turning off base nonces, `drafts` restrictions, dependent-based
      `409 in_use`).
- [ ] **HTTP-12** Batches: item grammar, per-step chaining, `delete` after `delete` is
      `422`, config change checked first, failure report by earliest failing step, dry
      run semantics, idempotent batch retry, `source` checked only for callers with
      unrestricted read (`422 source`), `origin` equal to self is `422`.
- [ ] **HTTP-13** Branches: creation (`branch` + unrestricted `read`, `412` on taken
      names, idempotent retry, `422` on bad `at`), config copy rules, read-through
      semantics (`302`/`410`/`404` as of `at`), foreign parents, history and blob serving
      across the branch point, branch entries in the base's log.
- [ ] **HTTP-14** Long-poll: interval/cursor protocol exactly as §7.7 (deterministic
      cursor, one-hour bound → `400`), cache headers as specified, answer shapes and
      headers (`X-Cursor`, `X-Revision`/`X-Namespace-Revision`).
- [ ] **HTTP-15** Blobs: reference grammar (`$blob`/`type`/`size`/`nonce`, nothing else
      except `sealed` at E3), pending/attached lifecycle and `blobPending`/`blobGrace`,
      availability rules (own, pending by uploader, branch read-through, batch `source`),
      upload check order exactly per §7.8, copy via `Blob-From` (checks 1–3, then `400`/
      `422 blob`, then source read → `404` on any failure, rank refusal, then 4–5),
      reading semantics (`206`, `404` pending/unknown, `410` pruned/purged), `nosniff` +
      `CSP: sandbox` on every blob response, raw-document rules.

## §8 Deletion and purge

- [ ] **DEL-1** Tombstone: atomic dual append; `$successor` grammar and `410` body;
      history and blobs stay readable; further writes `410` except restore (`403` without
      the verb).
- [ ] **DEL-2** Restore: applies to the last live document; `[]` restores exactly; root
      `replace` recreates; one name, one chain.
- [ ] **DEL-3** Purge: content, snapshots, blobs and archives removed; ids/parents/entries
      kept; `purge` entry; `410` on all resource URLs; tag purge by resource, never by id;
      propagation by name to every branch recursively, never upwards.
- [ ] **DEL-4** Freeze: `409 frozen` with `successor` for resource writes; config writes,
      purges, branching, pruning still work; `successor` must share the base; unfreeze
      branch cap rechecked.
- [ ] **DEL-5** Namespace purge: requires `purge-ns`, frozen, no dependents, no last
      schema copies; one terminal `purge-ns` entry; name reserved forever; §8.5's answer
      table (including the sealed case and the `head` field) implemented exactly.
- [ ] **DEL-6** Pruning: horizon semantics (kept/dropped lists), protected revisions
      (retry window, branch points), protected documents (referenced schemas, `keep`),
      no pruning in branches, archive-before-prune as a full-history bundle with
      `"authors": true`, retention policy grammar and `*` key guard, `prune` entry only
      when the horizon moved, the log itself never pruned.

## §9–§10 Caching and consumers

- [ ] **CACHE-1** The §9 classes and exact header values, including head-pointer
      `stale-while-revalidate=5` and the absence of any `stale-*` on long-poll answers.
- [ ] **CACHE-2** Tag grammar, whole-tag purge matching, `ns:{ns}` purge on
      public→private or encryption-level changes.
- [ ] **CACHE-3** Private namespaces: `private` downstream; `CDN-Cache-Control: no-store`
      unless a verifying edge's headers (single line, no comma, secret match, prefix
      covers by segments, no other credential) are present.
- [ ] **CONS-1** Checkpoint/catch-up/follow protocol of §10, per-entry-kind handling
      (purge also purges derived data and tags; batch applied as one unit), grant checks
      against head keys, idempotent processing.

## §12 Errors

- [ ] **ERR-1** Every `code` row of §12 with its status, and the body members each row
      names (`limit`, `measured`, `max`, `dependents`, `head`, `items`, …).

## Addendum C (Auth profile)

- [ ] **AUTH-1** Root/narrowing block model; narrowing only restricts (`sub`, `groups`,
      `attrs` immutable); effective principal from the root.
- [ ] **AUTH-2** Verification order of §C.2 (ns check → signatures → times → revocation →
      key scope), `401` vs `403` split, verb check with candidate verbs, step-1 vs step-6
      rule partitioning, read-envelope checks on reads.
- [ ] **AUTH-3** Roles: expanded at the gate from the configuration in force, unknown
      names grant nothing, alternatives semantics, `roles: []` grants nothing.
- [ ] **AUTH-4** Grant id, non-bearer stored form, `/grants/{gid}` serving and access
      rules (incl. sealed/E3 variants).
- [ ] **AUTH-5** Author signatures: input construction (incl. origin binding and the
      tombstone variant), gate verification only for grant-listed `kid`s, `signers`
      rules (root only, unique kids, no narrowing-block signers), `required` semantics
      and its retry exception. **[vectors §4]**
- [ ] **AUTH-6** Keys and scopes: every §C.4 scope field enforced (`maxTtl`, `sub`,
      `groups`, `roles`, `attrs`, `rules`, `readScope`, `rate`, `maxLag`,
      `requireAt`); revocation per namespace, base reach in branches; keys-follow-base
      including the shared-`kid` shadowing rules; operator grants limited to their four
      uses; operator key history at `jwks_uri` with `from`/`until` honoured.
- [ ] **AUTH-7** Edge grants: issuance rules and refusal table of §C.5.2 (all-or-nothing,
      `410` aggregation, prefix cap, single `exchangeRate` draw per principal), cookie
      attributes (`__Secure-pl-eg-…`, host-only — no `Domain`, `Secure`, `HttpOnly`,
      `SameSite` policy, `Path` = prefix, ≤ 15 min), withdrawal per §C.5.4. **[vectors §5]**
- [ ] **AUTH-8** Edge-side checks of §C.5.3 (the six checks, forwarding rules) where the
      deployment ships an edge; origin-side cookie verification without an edge.
- [ ] **AUTH-9** Nonces: form, `writes` exemption, `required` semantics at gate step 3,
      exemptions, branch/base interaction (`409 in_use`), E3 forbiddance, blob-nonce
      obligations.

## Addendum E (Encryption profile)

- [ ] **ENC-1** E1 transparent to the protocol; purge destroys per-resource keys where
      implemented.
- [ ] **ENC-2** E2 wire format: JWE compact, `dir`/`A256GCM`, `pl` claims per payload
      kind, sealed-once-served-forever (with the namespace-range exception and weak
      ETags), compression-before-sealing per single revision only, `pad` buckets and the
      no-compression rule for padded payloads. **[vectors §6]**
- [ ] **ENC-3** Sealed blobs: `PLB1` layout, size commitment, zero padding check, epoch
      redirect and per-epoch serving rules, range-over-sealed-bytes only.
- [ ] **ENC-4** `/keys`: per-resource vs epoch keys by grant shape, epoch window rules
      (`historyEpochs`, no epochs past `exp`), HPKE wrapping, `no-store`, `404
      not_offered` outside sealed namespaces.
- [ ] **ENC-5** E2 interactions: public caching class, `$nonce` MUST per patch set,
      sealed branches, derived views sealed per §E.2.6 (whole-response vs per-entry,
      aggregates refused for per-entry readers, `view` binding).
- [ ] **ENC-6** E3: wire format (one `sealed` op, `pl` binding, declared-blob list rules
      and its `422 blob` cases), ids over ciphertext, exact-ciphertext retries, client
      validation and flagging, keyring relay through `/keys`, sealed-blob format and the
      in-document key.
- [ ] **ENC-7** §E.4 metadata acknowledged: no level hides names, ids, sizes (bucketed),
      timing, authors or log shape.

## Addenda A, B (services)

- [ ] **SVC-1** Consumer protocol (§10) with per-namespace checkpoints, `min` semantics
      (`302` always drops `min`; `503` + `Retry-After`), canonical query URLs, bounded
      redirects.
- [ ] **SVC-2** Index: `x-index` kinds, reference walking per §6.5, `ref` query forms,
      `/_refs` subject-set computation, per-item filtering, sealed results per §E.2.6,
      access control on re-published content.
- [ ] **SVC-3** Tree: edge maintenance, combined checkpoint, listing endpoints and their
      caching/tags, cycle handling exactly as §B.5 (strict, depth 64), shared-node
      bounding, preview mode.
- [ ] **SVC-4** Catalog: `$access` semantics (inherit, inheritPowers), effective-access
      walk with its stopping rules, grant issuance (place/move/unplace/create/restore and
      their checks, no widening with `includes`), listing visibility rules, `gs` keying,
      `/read-grants` with keys for sealed items, frozen `effective` rows for deleted
      items, `checkpoint` in answers.

## Addendum F (merge tooling)

- [ ] **MRG-1** Classification by ancestry, fast-forward vs replay, conflict detection
      with the array-widening rule, dry-run usage, `source.at` as of classification.
- [ ] **MRG-2** Second-merge pair discovery via `merge.authors` (all four conditions),
      empty-step recording and its tombstone/absent exceptions.
- [ ] **MRG-3** Rebase as successor branch; resumption counting prior successor batches;
      switch-over protocol.
- [ ] **MRG-4** Janitor verification of `merged`/`superseded`/`abandoned` exactly per
      §F.6 (incl. E3 keyring exception and the empty-branch rule).
- [ ] **MRG-5** Release procedure (§F.9): plan digest, freeze-on-approve, four-step
      ordering, conflict reporting list, one-release-per-catalog-base locking, rebase and
      abandon handling.

## Addendum G (Federation profile)

- [ ] **FED-1** Origin publication at `GET /`; external-consumer verification through
      logs.
- [ ] **FED-2** Remote branches: creation rules (operator grant, nonce inheritance, `410`
      on purged base chain), schema mirroring with `name_conflict`, verification of
      read-through (incl. `chain` recording), registration (renewal, expiry, `export`
      envelope, https-except-loopback), purge-notice application.
- [ ] **FED-3** Bundles: format and line kinds, ordering (blob lines before first
      mention, grant lines before first use), digest over the file as written,
      `requires`/`external` checks, rejection on any mismatch. **[vectors §9]**
- [ ] **FED-4** Import: ancestry classification, upstream-namespace snapshot merging,
      pinned-reference rewriting, batch ordering and pacing rules, rename semantics
      (rewrite set, step-1 refusals, `source.ids` re-runs), today's-gate judging.
- [ ] **FED-5** Protection ranking on import and copies; sealed-bundle format and its
      rejection cases; E3 import rules (same name, epoch stepping).

## Addendum H (file tools)

- [ ] **FILE-1** Raw vs JSON determination (extension table, I-JSON test, kind
      stickiness), rendering bytes (JCS tokens, stringify-layout, index-like keys),
      nonce handling per level.
- [ ] **FILE-2** File trees: `catalog.files` shape, titles grammar, sibling rules
      (NFC, simple case folding, duplicate numbering), one-parent shape.
- [ ] **FILE-3** Save procedure: base selection (tag, records, head fallback), overlap
      conflicts, the §H.4 answer table, blob-first raw saves, placement-then-create in
      catalog mode.
- [ ] **FILE-4** Delete/rename/move/copy semantics (incl. move-over-file as save+delete,
      scratch-name move-aside acceptance), `$successor` across namespaces.
- [ ] **FILE-5** Real-client handling: scratch patterns and their bounds, delete-then-
      write windows, guards, locks and dead properties in-gateway, `Depth` rules.
- [ ] **FILE-6** Access: per-user keying, grant re-check cadence, sealed/E3 behaviour
      (no keys → namespace not offered), header policy on every response.
