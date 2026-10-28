# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.74**. This file collects what
the reference does that the text doesn't yet describe.

## Open

From implementing v0.74 (branch `spec-v074`). Numbering restarts. Each entry gives the section,
what v0.74 says, what the reference does (the reading it chose) and the question. "Was Open n"
marks a v0.73 note that v0.74 left open or answered only in part, rewritten for v0.74; those
v0.74 doesn't touch at all are shortened at the end (33–45).

The two with the widest reach come first.

1. **"Every schema compiles under this version" against invariant Valid** (§4 Valid, §6.1, §6.2
   step 5, §E.3.2). v0.74 drops v0.73's "a schema stored under an earlier version is compiled as
   that version did" (Changes: "every schema compiles under this version"), but Valid still says
   "re-validating any revision later gives the same answer", excepting only purged or pruned
   schema revisions. The reference now compiles every stored schema revision under v0.74's rules,
   whatever marker its row carries (`internal/schema/dialect.go` `current`,
   `internal/schema/check.go`). So a schema stored under v0.55 to v0.73 that names `semver` or
   `period`, has a root `$id` equal to its own path, a dialect `$schema` in a subschema, or a
   `\x{D800}` pattern no longer compiles, and `idn-hostname` and `idn-email` verdicts change
   (now asserted, without mapping). A write pinning such a revision is refused, and documents
   already stored against it no longer re-validate. At E3, where readers validate ("Invariant 3
   becomes a property checked by readers"), the reference's client now flags revisions it used
   to accept (`internal/client/e2e.go`). The static walks needed a carve-out: the x-ref walk
   (§6.5) reads a stored schema for its structure, as the version that stored it accepted it
   (`internal/schema/check.go` mode `walk`, `internal/annot`), while the x-index walk compiles
   `patternProperties` under today's rules (`internal/index/fields.go` `regexp`), so the two can
   disagree on a stored pattern only raw RE2 takes. The `revisions.rules` marker and the
   `X-Schema-Rules` header are still written and served, and now select nothing. *Question:*
   does Valid need an exception for revisions stored before v0.74, and what does a write pinning
   one answer (`422 invalid` or `schema_unavailable`)? Or should re-validation keep the storing
   version's compile, which E3 readers can't do, since they can't date a revision? Should the two
   walks agree, and may the marker header go?
2. **E3 readers without `nbf` lose fold starts from before a raise** (Levels "After a raise",
   §E.2.3, §E.3.1, §G.3; was Open 4). v0.74: pre-raise keys come "as at E2, its window judged
   against the current epoch, so none to a grant without `nbf`". The reference does so
   (`internal/core/e2e.go` `preRaiseWindow`; `internal/core/sealed.go` `grantEpochsOf`). The text
   still doesn't say where an E3 fold starts across a raise; the reference's fold redirect starts
   at the chain's last revision from before the raise, whose document `/rev` serves sealed as at
   E2 (`internal/core/preraise.go` `preRaiseFoldSince`; `internal/client/e2e.go` `foldStart`,
   `openPreRaise`), and "no log page spans" the raise. So after a raise from `sealed`, a reader
   or writer whose grant has no `nbf` can't open the fold start of any document whose chain began
   before the raise, and so can neither read it nor write against it, until an E3 prune puts a
   snapshot above the raise. Remote branches fare the same: creating one over such content with
   an endpoint grant without `nbf` is `422` (§G.3, "no key for that epoch"), and its readers are
   in the same position. Under v0.73's reading such a grant got the last pre-raise epoch.
   *Question:* intended? If so, Levels should say that readers of pre-raise content need an `nbf`
   reaching back (or that writers prune after a raise); if not, give the fold start's epoch to
   every reader of the resource, as v0.73's reading did. Either way, say where the fold starts.

Keys and levels.

3. **A branch of a raised base: whose window** (Levels "Branches of a raised base", §E.2.3 At
   E3, Levels Invariant). "For the base epochs §E.2.3 selects" can be read as the base-epoch rule
   or as the raised namespace's own window judged against its current epoch. The reference uses
   the base-epoch rule alone: the base's epoch in force at the latest `nbf`, or at `at`, none
   without `nbf` once the base has moved past its epoch at `at`, capped by the base's
   `historyEpochs` at `at` (`internal/core/e2e.go` `baseEpochs`, `internal/core/preraise.go`
   `preRaiseKeyWindow`). So a branch's readers can keep pre-raise keys the base's own readers lose
   when the base lowers `historyEpochs`. *Propose:* say "the branch's window, not the base's
   current one", so the Invariant's "an epoch key reaches only grants whose window covers that
   epoch" isn't read as the base's window.
4. **Authentication disabled gets the current epoch only** (§E.2.3, Levels, §E.2.6, §A.4). The
   reference gives only the current epoch, base epochs only while the base's epoch now is its
   epoch at `at`, and no pre-raise key (`internal/core/sealed.go` `grantEpochsOf`,
   `internal/core/e2e.go` `baseEpochs`, `preRaiseWindow`). Development playgrounds and
   grant-less services then can't open older epochs after a rotation. A service that never read
   a document sealed under an earlier epoch (a fresh index or tree service, `-rebuild`, the
   index's format-2 rebuild) can't serve it "by name only" as §E.2.6 says, since it knows neither
   its text nor its parents, so the reference leaves it out (`internal/derived/keys.go` `ErrSkip`,
   `internal/follow/follow.go` `LacksKey`; `TestV074FreshIndexAfterRotationAuthDisabled`,
   `TestV074FreshTreeAfterRotationAuthDisabled`); upgrading an auth-disabled deployment with
   rotated sealed namespaces drops those documents from its services. *Question:* intended for a
   mode that has no grant to carry an `nbf`? And should §E.2.6 and §A.4 Coverage say a service
   leaves out, rather than names, documents it never could open?
5. **E3 keyring `$nonce`** (§E.3.2 Keys: "no other members but a `$nonce` (§C.7)"). Must it be
   of the fresh form? The reference accepts any string (`internal/seal/keyring2.go`
   `ParseKeyringV2`).

Remote branches (§1, §G.5.2).

6. **A raise B could make but that fails** (§1, §G.5.2, Levels Invariant). v0.74 keeps `502`
   for a raise needing a level B's server lacks and says nothing of one whose config writes fail
   for another reason (§6.6 Values, a dependent's refusal). As the Invariant forbids serving
   read-through content below the base's level once the raise is seen, the reference holds the
   resources §1 lists: `503` `encryption_unavailable` with `Retry-After` (the follow interval),
   writes other than purges alike, retried at every sync and at start-up before anything is served
   (`internal/core/upstream.go` `levelHeldErr`; `internal/core/remote_branch.go` `retryLevel`,
   `catchUpLevels`). A branch v0.73 left below `sealed` is so raised at its first start, and its
   content is then served only sealed. Separately, a source raised from none or at-rest straight
   to `e2e` makes the branch `sealed`, above the level at which the source still serves that
   content (in the clear). *Question:* name the status and code (`503 behind`, a new code, or
   `502` after all), say whether `/heads` rows and writes are held alike, and confirm the second
   case.
7. **Start times "only through `base.origin` itself"** (§G.5.2 Epoch start times). How does B
   learn where `base.origin` answers when it reaches it at another address (an internal URL, a
   compose network)? The reference adds `-remote-origin-url ORIGIN=URL` (`cmd/patchlog/main.go`,
   `internal/core/remote_branch.go` `originStarts`); does a configured URL count as "itself"?
   While the origin can't be reached, the reference keeps the keys, uses them to check and serve
   the source's sealings, hands none out (`knownStarts`) and retries at each sync
   (`followPreStarts`). *Question:* confirm, and is a retry expected?
8. **"Verbatim"** (§G.5.2 E3 sources). The reference stores A's pre-raise JWEs and sealed blobs
   byte for byte, each checked by opening it under its epoch's key; one it can't check, for want
   of that key, it leaves out and seals itself under the same `kid`, `pl` and `K_r`
   (`internal/core/remote_blobs.go` `fetchPreSealings`). *Question:* must the bytes be A's, or is
   a sealing under the same `kid`, `pl` and `K_r` enough?
9. **`/heads` rows "for a resource §1 answers `502` for"** (§7.4). A page at an older revision
   may list a resource live then and purged now, which §1 no longer answers `502` for. The
   reference judges by the row plus "the source had it at `at`", leaving the fields out there too
   (`internal/core/reads.go`). *Propose:* say which.

Derived views and services (§E.2.6, Addenda A and B).

10. **Values of another epoch** (§E.2.6). (a) Whole-response sealing needs "every such value"
    from revisions of one epoch; a value of another epoch is "sealed in place as a value of
    another resource is", and those are excepted from the one-namespace condition. Is it
    excepted from the one-epoch condition, nesting inside the whole JWE? The reference counts it,
    so a `g/all` listing whose `born` values span epochs is sealed per entry
    (`internal/tree/http.go`, `internal/tree/files.go`). (b) At E3, `born`'s epoch is taken from
    the served `kid` of the node's first log entry (`derived.EpochOf`), which may differ from "the
    one a prune's snapshot of that revision would carry" for read-through content and revisions
    from before a raise; where it is unknown, `born` goes with the head. (c) For a key that can
    never be had, "while that namespace's keys can't be fetched, the service answers `503`" sits
    beside "served by name only": the reference leaves `born` out, and leaves out a placement's
    `file` values on a lasting key failure. *Question:* each.
11. **Aggregates across epochs** (§E.2.6 Aggregates; was Open 14). Unchanged by v0.74: after any
    rotation, `counts` over documents written before and after it are `400` for every reader
    until all are rewritten, and so are counts over hits served by name only
    (`internal/index/http.go` `errEpochCounts`, `errLackCounts`). *Question:* should aggregates
    be sealed under the newest epoch among their sources?
12. **"Lacks keys"** (§A.4, §E.2.6). Besides a `4xx` other than `429` and a key it can't unwrap,
    the reference counts a keyring key from a sender it doesn't trust (§E.3.2) as lacking, and,
    following the text literally, a `408` (`internal/follow/follow.go` `LacksKey`). A key wrapped
    to the grant's `enc` when the service has no recipient key configured stays transient
    (`503 behind`), as the client returns no error that tells it apart (`internal/derived/keys.go`
    `Retryable`). *Question:* name both cases, and is `408` lasting?
13. **Fixed names at services** (§C.5.2, §2.1; was Open 93). The origin runs block and key rules
    for every fixed name. The index's exchange admits a scope marker when any fixed name passes
    (`internal/index/edgegrants.go` `readsFixed`), and the tree service keeps its own fixed-name
    logic likewise; at another `gs`'s `/_refs` URL the index still answers `401` where an exchange
    answers `403` (`internal/index/http.go`). *Question:* does one failing name refuse at a
    service that accepts non-fixing `/resource` rules, and which status?
14. **The index head pointer and an opaque `after`** (§A.4: a redirect "to another `at`" drops an
    opaque `after`). The head pointer `/{ns}?…&after=` names no `at`, so the reference passes
    `after` on whole (`internal/index/http.go`). *Question:* intended?
15. **A foreign `min`'s place** (§A.5). The reference answers the `400` after the queried
    namespace's own checks (its read check, `410 purged`, `404` for one not followed), and lists
    well-formed foreign `min`s only for a reader who passes the read check, malformed ones always
    (`internal/index/http.go` `judgeMins`). *Propose:* confirm the order.

Schemas, requests and grants.

16. **Stored rule fragments and key-scope patterns** (§6.4.2, §6.6; was Open 54). Is a rule's
    `schema` fragment a "schema" that "compiles under this version"? The reference compiles
    stored fragments as stored (`schema.Legacy`: `semver` and `period` asserted, `\x{D800}`
    through raw RE2; `internal/rules/rules.go` `compileSchema`) and new ones under today's rules,
    and keeps stored key-scope `sub` patterns with `\x{D800}` matching
    (`internal/grant/keys.go`), refusing them only when written, as §6.6 says. *Question:* both
    as intended, and which §6.6 limits apply to a fragment?
17. **RFC 5890 hostnames** (§6.2 step 5). The reference accepts all-ASCII NR-LDH labels compared
    case-insensitively and an A-label in uppercase (`XN--BCHER-KVA`), refuses R-LDH labels that
    aren't `xn--` (`ab--cd`), as Go's registration profile does, and applies RFC 5892's CONTEXTO
    rules (RFC 5891 §4.2.3.3), which common IDNA libraries leave out (`internal/schema/dialect.go`;
    `TestV074V03IDNHostnameUnmapped`, `TestV074V03IDNContextO`). *Propose:* say each.
18. **A copy's `428` and its different-`bid` `422`** (§7.8 Copying). "…then a precondition `428`,
    before any body is read, and a different `bid` is `422`" doesn't order the last two; the
    reference answers `400`, `428`, `422`, then the source's `404` (`internal/core/blobs.go`).
    *Propose:* confirm.
19. **How far the `403` reaches** (§7, §C.2). The changelog says "a verified grant without
    `read` is `403`"; the reference answers `403` for every failed read check off resource URLs,
    a grant whose `read` is limited to some resources included (`internal/core/auth.go`
    `readerCheckURL`), as §7's "a valid grant that doesn't allow the request" and the checklist's
    Grant scope 2 imply. *Propose:* say so.
20. **`/resource` inside `any` or `not` beside a fixing rule** (§C.5.2, §2.1). The reference
    reads such a rule as not fixing, allowed, and evaluated per fixed name, and evaluates every
    name before the 100-prefix cap, so a `403` still outranks the cap's `400`
    (`internal/core/edgegrants.go`). *Propose:* confirm.
21. **Biscuit version 0 in stored forms, and other schemes** (§C.8, §C.3, §C.5.3). Bearer tokens
    with a version 0 payload are `401`; a stored form recorded before v0.74 with a version 0
    authority block still verifies as stored history (`internal/grant/biscuit.go`). biscuit-go
    v2.2.0, the official Go library, still signs version 0. "Even an empty one" settles empty
    `Authorization` lines; other schemes (`Basic …`) are only implied to be present, which the
    reference takes them as (`internal/edge/edge.go`). *Question:* must stored forms still
    verify, and is any `Authorization` field present whatever its scheme?

Tree and catalog (Addendum B).

22. **Roots in unfiltered listings** (§B.5, §B.11.5). §B.5 still makes roots "nodes without
    parents" and nodes whose parents are all gone, dangling or cyclic orphans. The reference
    applies "a visible node with no visible parent is a root" only to subject-set listings;
    `g/all` and public listings keep §B.5 (`internal/tree/http.go` `rootFor`). *Question:*
    should a dangling-parent node be in both `roots` and `orphans`, and in which listings?
23. **`g/all` and trusted namespaces it can't read** (§B.11.5). Answering Open 95, v0.74
    judges `g/all` against "every namespace in its combined checkpoint"; the reference judges it
    against every trusted namespace (`internal/tree/http.go` `grantViewer` with `forCookie`), so
    one trusted namespace whose document it can't read withholds `g/all` cookies from everyone.
    *Question:* acceptable, or must a qualifying reader be issued `g/all`?
24. **Item requests' subjects** (§B.11.4: "a role that makes it visible (§B.11.5)"). §B.11.5
    defines visibility per subject set, whose `user:` subject is present only where the catalog
    has a direct entry for that user or a key with a `sub` scope, while frozen rows (§B.11.7) can
    hold a direct `user:` entry the graph no longer names. The reference judges item requests
    (Restore, the read check on a purged item) with the grant's own subjects, `user:{sub}` always
    among them, and `/read-grants` and organising requests with the listing's subject set
    (`internal/catalog/grants.go`). *Propose:* say so.
25. **Catalog answers** (§B.11.4, §B.11.5, §B.9, §8.5). An untrusted namespace's public,
    unsealed item still comes back `"public": true` from `/read-grants`, the `403` only moving
    ahead of the purge `410` (`TestCheckpointNamesItsNamespaces`, `internal/catalog/v051_test.go`);
    the service keeps its purge record for a namespace the catalog no longer trusts
    (`internal/tree/tree.go` `forgetUntrusted`); and "the node's parents as decided" is left out
    for an implicit placement (§B.9), which has no `parents` member (`internal/catalog/grants.go`).
    *Question:* each.
26. **Who counts as `catalog-admins` for an end-to-end catalog** (§F.8). With no catalog service
    checking, the merge service can only test the given admin grant: it requires `catalog-admins`
    in its root `groups` (`internal/merge/release.go` `grantE2E`). *Question:* is root `groups`
    the test, or do roles and `attrs` count?

Merges, the janitor and gateways (Addenda F and H).

27. **Config-only batches and the no-own-entries rule** (§F.6). Is a batch's config entry an
    entry "of its own"? The reference counts a config-only batch, or one whose items are all for
    resources purged in the branch, as the branch's own work, and at E3 a config-plus-`keyring`
    batch (an epoch bump) as not, by analogy with "a batch counts only if it has other items"
    (`internal/janitor/janitor.go`). *Propose:* say whether config changes count.
28. **`superseded` after a purge** (§F.6; was Open 113). "Only where the janitor read `/grants`
    first": the reference keeps grants it read from a live successor in memory only, at most
    4096, least recently used dropped first (`internal/janitor/janitor.go` `maxSeen`), and reads
    the successor's log, still served after an unsealed purge, afterwards, so the `merge.authors`
    route still passes. *Question:* does "what this check needs" include the log, and must
    remembered grants survive a restart?
29. **Nested array writes** (§F.3; was Open 114). Unchanged: an element write "counts as a write
    to the whole array"; the reference widens an insertion into a nested array to the outermost
    array (`internal/merge/writes.go`), which §H.4 says only for gateways. *Propose:* "outermost"
    in §F.3 too, or say otherwise.
30. **Own entries by key history** (§H.7 Users; was Open 134). The reference orders entries
    against config writes by `created` time, treats a config write with the same time that
    changed the `kid` as not the user's own, and, for a user whose grant can't read the namespace
    log (resource-limited, or tree-derived content namespaces), falls back to the key the `kid`
    names now. It shares one grant's reading of the log with another grant only after that one
    has read a one-entry range of it (`internal/dav/kidhist.go`, `internal/dav/dav.go`).
    *Question:* should unreadable cases count as someone else's (making every save over one's own
    writes from another program a `409` there), and may a gateway share what one grant read?
31. **The sealed moved-away `409`** (§H.4, §H.6). A keyless gateway can't read `$successor` from
    a sealed last revision, and a sealed namespace's `410` carries none. The reference answers
    `409` naming the path where the head names a successor, otherwise `409` saying it can't tell
    whether the file moved (`internal/dav/write.go` `tombLast`). *Question:* which?
32. **Sealed-bundle line headers** (§G.5.1.1). Lines says each protected header is canonical
    JSON, but the reader's checks don't list non-canonical bytes; the reference rejects them, a
    `0x0D` anywhere in a line, and a last line without its `0x0A` (`internal/seal/bundle.go`).
    *Propose:* add the header check, and rejection vectors (a JWE line with whitespace inside it)
    to I.15.

Still open from v0.73, shortened (v0.74 doesn't touch them).

33. **Deeper bases of a remote branch** (§G.5.2; was Open 11). The inference from sealed content
    is settled; a base deeper in `base.chain`, whose log B doesn't follow, is read at every sync,
    and the last epoch seen is kept when that read fails, without failing closed
    (`internal/core/upstream.go`). *Question:* fail closed?
34. **The keyring format change and legacy forms** (§E.3.2, §G.5.1, §C.3.1; was Open 19 and 20).
    No transition from the pre-v0.63 keyring; the reference relays it as stored and blocks E3
    writes until `patchlog e2e migrate-keyring` (`cmd/patchlog/e2e.go`), and such a namespace
    can't be bundled (`internal/bundle/access.go`). v0.74 makes the legacy `/keys` readings the
    reference's own, but doesn't say whether a sealed answer may be sealed again on a format
    change. *Question:* may a keyring lack epochs, may imports accept the old format for non-head
    revisions, and may a stored sealing be redone?
35. **Replayed items with undeclarable blobs** (§F.3, §E.3.1; was Open 27). Only kept heads are
    exempt; replayed or re-sealed items whose document references a blob a `sealed` op can't
    declare fail (`internal/merge/blobs.go` `undeclarableBlob`). *Question:* exempt them too?
36. **Fork discovery without base reads** (§E.3.1; was Open 29). The snapshot `kid` rule needs to
    know whether an op is the branch's own; readers without the base's `/heads`, and remote
    bases, can only use the depth rule (`internal/client/e2e.go`). *Propose:* allow it.
37. **Encrypted archives** (§8.6, §G.5.1.1; was Open 30). The per-resource archive key
    (HKDF-SHA256 of the resource data key, info `patchlog-archive-key-v1`) has no export path, and
    E3 archives are sealed twice (`internal/core/archiveseal.go` `archiveIdentity`). *Question:*
    export path, archive padding, double encryption?
38. **The key-window check stores no sealing** (§2.1 Protection, §6.1; was Open 31). A check
    "fixed as a read would fix one" stores nothing for content not yet sealed, so the next read
    may fix a newer epoch (`internal/core/keywindow.go`). *Question:* must it store it?
39. **Resent stored content** (§3.1, §F.3, §G.4.4; was Open 32). Merges, imports and mirrors
    resend stored patch sets and signatures; v0.55 content with a noncharacter or a short
    signature is `400` on resend (`internal/server/request.go`). *Question:* exempt?
40. **Sealed resource events** (§7.3, §E.2.2; was Open 60). `purge` and `prune` events bind no
    entry in `pl` and carry no `id:`, so a recorded one can be replayed into the same stream; the
    reference stores none (`internal/core/eventseal.go`). *Propose:* bind `target`, say they aren't
    stored.
41. **`via` on older entries** (§7.1, §7.4; was Open 62). Not recoverable for namespace entries
    written before servers stored it. *Propose:* "absent on entries written before v0.73".
42. **Revocation ids from before v0.71** (§C.4; was Open 79). A `revoked` naming an old
    root-signature id would silently un-revoke; the reference still honours it for block 0
    (`internal/grant/verify.go`). *Propose:* allow it, or name a migration.
43. **Why a resource purge purges `idx:{ns}`** (§A.1; was Open 89). Give the reason (positional
    cursors, counts, scores), and note that a stream of purges defeats "one redirect suffices".
44. **The index's range filters** (§A.4; was Open 92). `gt`, `ge`, `lt` and `le` filters, with a
    `sort` mark required, byte order for strings and each document's least value, remain the
    reference's own (`internal/index/query.go`). *Propose:* specify or drop them.
45. **Stored sealed results on a raise or on turning private** (§E.2.6, §A.1; was Open 94). They
    are dropped, so a later read at an old `at` is redirected rather than served the stored bytes
    (`internal/index/index.go` `dropWholePublic`). *Propose:* a sentence beside "stored once,
    served forever".

## Settled in v0.74

v0.74 settled 113 of the 134 notes open at v0.73; the other 21 are rewritten above as entries 2,
11, 13, 16, 28–30 and 33–45 (34 covers two). The reference follows the text in each. Where v0.74
went against it, the reference changed, in the area named:
- **Epochs and key windows** (1, 2, 3, 8, 25, 26): `epoch` defaults to 1; pre-raise keys are
  judged against the current epoch, none without `nbf` (changed: `internal/core/e2e.go`
  `preRaiseWindow`, `keyEpochs`; 2–4 above follow from it); E3 `/keys` without `enc` is `422`,
  pre-raise epochs included; the base's `K_e` open a public base's pre-raise log; base epochs are
  capped by the base's `historyEpochs` at `at` (changed: `baseEpochs`), and `historyEpochs: 0` is
  the current epoch alone; authentication disabled gets the current epoch only (changed:
  `internal/core/sealed.go` `grantEpochsOf`).
- **Pre-raise content and E3 sealing** (5–7, 17, 18, 21–24, 28): an E3 prune of a pre-raise
  horizon first stores `H`'s sealing (changed: `internal/core/e2e.go`); a branch's snapshot names
  the branch in `pl` and the base in `kid` and `K_r`; a pre-raise blob is one any pre-raise
  revision references; keyring entries are checked at the gate as listed, senders configured out
  of band, readers taken from the key holder's configuration; values of another resource seal an
  object of one member, and "order" is the result order; revisions that don't open fold as `[]`;
  ranges seal under the epoch current when sealed; the snapshot `kid` below a horizon is that
  snapshot's; HPKE is RFC 9180's single-shot Seal and Open. New in v0.74 and followed: E3
  protected headers are canonical with only `alg`, `enc`, `kid` and `pl` (`checkSealedKid`).
- **Remote branches** (9, 10, 12, 13, 115, 116, 119): mirrored sealings keep their epochs, stored
  as A served them (changed: `internal/core/remote_blobs.go`); a remote branch raises as far as
  Levels allow, to `sealed` where `e2e` is refused, also on seeing sealed content, and answers
  `502` only where its server lacks the level (changed: `internal/core/remote_branch.go`,
  `upstream.go`); start times come only through `base.origin` (changed: `originStarts`,
  `-remote-origin-url`); `502` rows in `/heads` lack `created`, `size` and `digest` (changed:
  `internal/core/reads.go`); creation's `422`/`502` split, the registration retry and the mirror
  genesis stand as the reference had them. 6–9 above ask what remains.
- **Derived views** (15): values of another epoch are sealed in place, and an entry whose epoch
  the service gets no key for is served by name only (changed: per-entry name-only hits in
  `internal/index/http.go`; `born` sealed apart under its own epoch, tree migration
  `005_nodes_born_epoch`, `internal/tree/files.go`). 10 above asks what remains.
- **Requests and the gate** (33–50, 52): request-shape errors before step 1, as the request's own
  answer; a malformed gestures `after` is `400` and one naming a purged resource `404` (changed:
  `internal/core/gestures.go`); `cursor` is checked live or not; upload check 4 is `400`, `428`,
  `415`, and a copy's sent precondition `428` comes before the `bid` and source checks (changed:
  `internal/core/blobs.go`); blob headers, `source` members, step 2.5's order, the dry-run config
  report, a create that must write something, what a failing config change draws, date-times in
  `compare`, strong Kleene logic at E3, step-6 refusals in a dry run, creation limits, the Values
  inequality escaped by an `epoch`-only change, unchanged stored values, the allowance maximum's
  name, the deduction wording, and the purge/prune `404`, all as the reference had them.
- **Schemas** (16, 53, 55–57): every schema compiles under this version, markers selecting nothing
  (changed: `internal/schema`; 1 and 16 above ask what follows); RFC 5890 without mapping
  (changed: `internal/schema/dialect.go`; 17 above); `\x{D800}`, `\\u` and `\Q…\E` as the
  reference read them, now normative; fragments percent-decoded first, a plain name naming nothing
  `422 invalid`.
- **Reads and streams** (58, 59, 61, 63–65): a `since` at a `purge-ns` entry is `410` (changed:
  `internal/core/reads.go`, `internal/server/live.go`); streams re-judge per page and keep-alive;
  `/principal`'s `trusted`, `/heads` at an older revision, sealed `ETag`s and the missing change-log
  entries as the reference read them.
- **Namespaces, branches and prunes** (66–72): branch prunes, extra members in answers, no
  `successor` at a creation, late branches, branch creation order, what precedes the `*`-key guard,
  and a base's `*` keys, as the reference had them.
- **Grants** (51, 73–78, 80–83, 108): checks before the `ns` check are stateless, `grantSize`
  first; key-scope rules don't count toward `rulesPerGrant`; services apply both limits; a
  verified grant without `read` is `403`, at `/keys` too (changed: `internal/core/auth.go`,
  `sealed.go`; 19 above); an empty `Authorization` is present at the origin and services (changed:
  `internal/server/edgegrants.go`, `internal/svcedge`); block and key rules run per fixed name
  (changed: `internal/core/edgegrants.go`; 13 and 20 above); under `grants` an entry without a
  recorded grant matches no one (changed: `internal/core/write.go` `sameRoot`,
  `internal/core/remote_source.go` `samePrincipal`); only Biscuit's version 1 payload verifies
  (changed: `internal/grant/biscuit.go`; 21 above); the rest as the reference had them.
- **Index** (84–88, 90, 91): a single-namespace query's foreign `min` is a strict `400` (changed:
  `internal/index/http.go`; 15 above); a schema answering any `4xx` but `429` leaves a document
  untyped (changed: `internal/index/extract.go`); `dependentSchemas` collected whatever the data
  (changed: `internal/index/fields.go`); a redirect drops an opaque `after` (changed; 14 above);
  comma lists, scores, scope markers and repeated `min`s as the reference had them.
- **Tree and catalog** (95–107, 109): purged namespaces leave the combined checkpoint (changed:
  `internal/tree`); a visible node with no visible parent is a root for its subject set (changed:
  `internal/tree/http.go`; 22 above); a key's `sub` scope matches only `user:` subjects (changed:
  `internal/catalog/catalog.go`); item requests judge visibility with rules and answer an untrusted
  namespace's items `403` first (changed: `internal/catalog/grants.go`; 24 and 25 above);
  `parents` in every Move, Unplace and delete answer (changed); a catalog without a merge key is
  `404 not_offered`, and end-to-end catalog batches go only under a `catalog-admins` grant
  (changed: `internal/catalog/mergegrants.go`, `internal/merge/release.go`; 26 above); the rest as
  the reference had them.
- **Merges, releases and imports** (110–112, 117, 118, 120, 121): `merged` skips resources purged
  in the branch (changed: `internal/janitor`); held upstreams are nonced where either side requires
  nonces (changed: `internal/bundle/access.go`); sealed bundles are framed strictly (changed:
  `internal/seal/bundle.go`, and archives in `internal/core/archive.go`; 32 above); the plan
  digest, the lock, imports and `via` lines as the reference had them.
- **Gateways** (122–133): the sealed moved-away `409` (changed: `internal/dav/write.go`; 31
  above); a narrowing gateway serves only trees configured without tree-derived access, which the
  reference, having no narrowing mode, meets; the rest as the reference had them.
- **Vectors.** Addendum I.11 to I.14 match the reference's golden files value for value
  (`internal/vectors/testdata`); I.11's `\ud83dA` and `\x{D800}` rows are now refused rows there.

## Settled in v0.56 to v0.73

All 81 notes that were open at v0.55: v0.56 took up notes 1–79 and the companion drafts (73–81 in
part), v0.57 and v0.58 took up note 80's structure (Requirements blocks, §12's registries). The
reference now follows the text in each; where it
had done otherwise, as follows:
- **Undo** (1, 2): the prefix cap draws no token; a log read from genesis doesn't make an undo
  impossible, and partial undos are said (§C.5, §11.2).
- **Limits** (11, 12, 21, 28, 32–35, 37, 38): `documentSize` defaults to 1 MiB, with a deployment
  default and maximum per limit (`serve -document-size`, `-max-document-size`); log pages count
  batch items; whole-document writes may go on after the root op; bodies without a limit of their
  own are `400` above 1 MiB; `measured` is defined per limit and left out of document limits for a
  grant that can't read the resource, which the reference had given; `/principal` draws no token
  (§6.6, §7.4).
- **`/principal`** (25–28): `key`, `operator` and `catalog` members, `writer.nonce` for sealed
  namespaces, unauthenticated answers, and operator key histories without `keys` as failed reads
  (§7.4, §C.4).
- **HTTP** (14–17, 73, 76, 79, 81): `spec` is informational and discovery is per feature;
  `If-Modified-Since` only where `Last-Modified` is sent; `/raw`'s caching and read check; paging
  continuations; a past long-poll cursor is answered at once and one more than an hour behind is
  `400`, where the reference had waited for the boundary (§7, §7.1, §7.7).
- **Moves** (13, 18–20, 23): schemas may carry `$successor`; where successors survive bundles,
  renames and remote branches is stated; a `410`'s successor isn't trusted in sealed namespaces
  (§8.1, §11, §G).
- **Blobs** (22): headers on every response to a blob URL; a PDF may go without the sandbox, served
  as an attachment, which the reference does by default with an inline opt-in (§7.8, §H.6).
- **Access** (3, 36, 74, 78): `/keys` at E3 relays a limited grant's own keyring entries;
  `readScope` failures are `403` on every request and services verify as the origin does; cookies
  are host-only; bucket checks are atomic across instances, which the reference now does in Postgres
  too (§6.6, §C.2, §C.5, §C.6, §E.2.3).
- **Encryption** (15, 17, 24, 30): the E3 reason for omitting times and sizes; log pages count
  sealed bytes at E2; stored digests at rest (§E.1); values of another resource sealed per member in
  derived views (§E.2.6; Open 21 asks the plaintext's shape).
- **Services** (4–10, 66, 67): `checkpoint` names every namespace a decision read; `min` refusals
  name the refused `min`s and purged namespaces redirect; read-your-writes guidance; every name in a
  purged namespace is `410`; `gs` cookies and `g/all` issue times; `exchangeRate` at services,
  shared across instances in the reference; tree services answer `503 behind` until caught up (§A.5,
  §B.5, §B.11).
- **Files** (29, 31, 39–72): Addendum H as the reference's gateway had found it, with users keyed by
  key thumbprint and `sub`, content per scope, re-checks at least every five minutes, names checked
  against node documents before writes, records per path, raw saves, empty files, types kept on
  re-save, the extended scratch names, case variants, NFD, moves that copy, locks and dead
  properties, tree-service refusals, gateway `413`s, and listings with `total`, `lookup`, `behind`
  and `file.absent` (§H, §B.5).
- **Releases** (75): the merge lock has a defined shape and takeover rule (§F.9; Open 111 asks about
  taking it).
- **Rules** (77): `compare … in` with a non-array right side is false (§6.4.2).
- **Structure** (80): Requirements blocks restate the prose, which governs, and §12 holds the
  registries; CONFORMANCE.md holds the checklist.

## Settled in v0.55

None of notes 1–24. v0.55 took up the WebDAV gateway as Addendum H, and added to the core `GET
/ns/{ns}/principal`, `limit`, `measured` and `max` on limit refusals, and `catalog.files` (§7.4,
§6.6, §12). Of the sections the notes cite it touched §6.6 (limit refusals, the `429` body), §7.4
(the `/principal` row, `catalog.files`), §8.5 (the `410` row), §11.2 (how an undo learns the nonce
setting), §12 (the error body) and §C.5 (a third exception to unrestricted read), but not the
passages the notes are about. One note meets new text:
- **Blob headers** (22): §H.6 asks a gateway for `nosniff` and `sandbox` on raw bytes too, with no
  exemption for PDFs, so the cost reaches files served from a gateway. The note stays open (56 gives
  the gateway's side).

## Settled in v0.53 and v0.54

v0.53 restructured the text without changing behaviour. v0.54 took up notes 13–19 from the
WebDAV gateway, as follows:
- **Revision times and digests** (13, 15): `Last-Modified` and `Repr-Digest` on revision reads,
  outside E2 and E3. The reference had sent `Last-Modified` at E2 too, and no longer does.
- **`/heads` fields** (14): `created`, `size` and `digest`, optional and stored at write time,
  outside E2 and E3 (the reference had sent `created` there too); a raise to sealed purges
  `ns:{ns}` (§9).
- **Whole documents** (16): an append or restore whose first operation other than `test` is a root
  `replace` or `add` is bounded by `documentSize`.
- **Raw files** (17): a document whose root is only a blob reference is raw, served at `…/raw` as a
  redirect outside E2 and E3; blob responses carry `nosniff` and a sandbox policy.
- **Moves** (18): `$successor` in the last revision before the tombstone, not in the tombstone,
  which the head's `410` returns outside E2 and E3 and validation leaves out.
- **Rebased writes** (19): declined as a server feature; §11.3 gives the client procedure.
- New besides: `logPageBytes` bounds log pages in bytes (§6.6, §7.1).

## Settled in v0.51 and v0.52

All fifteen v0.50 notes. As the reference did them:
- **Grants in the body of `POST /edge-grants`** (1) need `Content-Type: application/json`
  (`415` otherwise), and issuance is `404 not_offered` before the body is read while
  authentication is disabled (§C.5).
- **The cookie's claims** (2) are exactly `kid`, `p` and `exp`, canonical byte for byte; a
  value with more is ignored. Cookie reads have no principal, so a deployment attributes them
  to the prefix (§C.5).
- **Edge verification headers** (3): each is one header line without a comma; the origin
  authorises from the cookie or grant, and the headers decide only lifetimes (§9, §C.5).
- **What check 2 refuses** (4): §7 now says a path with an empty, `.` or `..` segment, or a
  percent-escape, is `400`, `/` itself excepted.
- **A remote branch of a purged base** (9) reports the first purged namespace found, A's
  before its bases', for any `at`, before `at` is checked (§G.3).
- **Repeatable parameters** (10) are sets; a single-valued one given twice is `400`, and an
  ordered list is one value (§A.5).
- **`min` on an `at` the service can't judge** (11) goes to the current checkpoint in one
  hop; a `min` naming a namespace the service doesn't follow, or the reader can't see, is
  `400` (§A.5).
- **"May this reader read all of these?"** (12): every item back with a grant, as
  `"public": true`, or with its key; `4xx` refused, `5xx` undecided; a cap is allowed
  (§B.11.5).
- **Renamed imports** (14), as the reference does them, with one addition: a renamed
  namespace's `{dst}-upstream` must fit the name limit, `422` at step 1 otherwise (§G.4.4).

Adopted with more than the reference did, which now follows the text:
- **Key rotation** (2): origins and edges SHOULD accept several keys and mint with the newest;
  `-edge-grant-key` is now repeatable (§C.5).
- **Services and §9** (5): services apply §9 to their own origin. Private listings are cached
  at the edge under cookies the service mints with a key of its own for
  `/{catalog}/g/{gs}`, at an exchange endpoint of its own, so listing URLs now put the subject
  set first: `/{catalog}/g/{gs}/at/{at}/…`, `/{ns}/g/{gs}/at/{ns_id}`, `/_refs/g/{gs}/at/{at}`
  (§A.4, §B.11.5). The catalog service (`tree -access`) now mints and verifies them.
- **Undo by writers limited to some resources** (15): `/keys` names `epoch`, `level` and
  `pad`, and is `404 not_offered` where nothing is sealed, so such a writer can seal and undo at
  E3 (§E.2.3, §11.2). It credits carried gestures to the merger, and reports an undo as
  impossible when the gesture may reach below a pruning horizon; a log read from genesis has
  nothing before it, so the reference reads the rule as applying after a horizon only (Open 2).

Decided against the reference, which now follows the text:
- **Issuance and rate limits** (6, v0.52, from Doors): exchanges draw on a bucket of their own,
  `exchangeRate` (deployment only, 10/s, burst 100), one token per request from each distinct
  principal's bucket however many grants it carries, and never on a write bucket; `429` with
  `limit: "exchangeRate"` otherwise (§6.6, §C.5). The reference drew one token per grant from
  the principal's write bucket.
- **The 100 cap** (7) counts distinct prefixes, and an exchange over it is `400`, once the
  grants have verified (§C.5); the reference counted names and answered `403`.
- **A purged sealed namespace's log** (8) is `410 purged` with `head`, its events and
  long-polls too, rather than in the clear; `GET /ns/{ns}` still redirects (§8.5). The
  reference answered `500` there.
- **Catalog `checkpoint`** (13) is `{ ns: ns_id, … }`: the catalog's and each named item's
  namespace's `ns_id`s, which are all a decision depends on, not the combined checkpoint
  (§B.11.4).

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
  (`UndoResources`), except at E3, where it refuses (Open 15).
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
  §B.11.5). A service may mint edge grants for derived output under its own `kid` (§C.5),
  which the reference's services don't (Open 5).
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
