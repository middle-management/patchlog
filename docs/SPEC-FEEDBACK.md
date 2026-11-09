# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.77**. This file collects what
the reference does that the text doesn't yet describe. Open notes come in one list, from
implementing v0.77; cite them as "v0.77 Open n". v0.77 answered the v0.76 list ("v0.76 Open n"):
what it settled is under "Settled in v0.77", and what it left open is rewritten in the new
list, marked "was v0.76 Open n". The v0.75 and v0.74 lists were answered in v0.76 (Settled in
v0.76).

## Open from v0.77

From implementing v0.77 (branch `spec-v077`). Numbered afresh; cite these as "v0.77 Open n".
Each entry gives the section, what the reference does now (the conservative reading where it had
a choice) and the question. The planner's questions from before the work and the implementers'
and reviewers' notes are merged here, each case once. Notes v0.77 leaves untouched are carried
at the end (25–42), shortened where they were; the ones it settled in part are rewritten to what
remains (10, 12, 18, 24, 29, 32).

42 are open: 24 from this version's work and 18 carried.

1. **A purged catalog's coverage** (§B.11.9 Where; was v0.76 Open 6). A purged catalog keeps
   the namespaces that trust it covered, with nothing visible. The origin reads the catalog's
   last stored `catalog.trust`; the index now keeps the last `catalog.trust` it applied for each
   catalog (migration `009_catalog_trust`) and uses that, and counts a purged catalog whose
   documents it never applied as no catalog (uncovered). A catalog
   whose only trusting member is purged, and a branch whose root is purged, are still uncovered
   (the catalog-kind branch skips a purged `catalog.trust` member). *Question:* must a service
   keep the last `catalog.trust` of each catalog it follows, or may it treat a purged catalog it
   never read as no catalog? Does a purged
   member still count for a catalog's coverage? Can a `requireAt` chain whose namespace is
   purged still be read (a grant of such a key now fails `502`, so a purged catalog's coverage
   may never be reached)?
2. **Dark catalogs in the branch head-trust check** (§B.11.9 Branches). A catalog that makes
   nothing visible (end-to-end or purged) is skipped, so a branch whose root stops trusting such
   a catalog at its head stays covered and empty. *Question:* should it become uncovered
   (`403`)?
3. **"Trusted it as of the branch's `at`"** (§B.11.9 Branches). The root's side is read at
   `baseAt`, the catalog's `catalog.trust` at its current document. *Question:* which time is
   meant for the catalog's side?
4. **Ending a cookie** (§B.11.9 gs, §A.4, §C.5). A `gs` cookie ends on a changed scope
   digest, a lost `read` or another `pub`; branches compare a key's whole entry. *Question:*
   should any change to the key's entry (`sub`, `groups`, `attrs`, `maxTtl`, `requireAt`) end
   it? And, as §C.5 lets namespace-wide cookies outlive revocation, does "for every marker" also
   end `reads:{ns}` cookies when the verifying key is removed or its `pub` rotates?
5. **`requireAt` naming a namespace the verifier can't find** (§C.4, §12.1). The services
   answer `502 upstream` (a service can't tell an unknown namespace from one its grant can't
   see, as §7 answers both `404`), the origin `403 "unknown namespace"`
   (`internal/core/auth.go`). A `requireAt` rejection's `403` (at not in the chain, beyond
   `maxLag`) still names the target, which may be a catalog `/principal` hides, while §C.4 says
   "naming no namespace" only for `503`/`502`. A chain that can't be read is reported even where
   a later check in the grant's verification would have refused with `403`, reading "never
   `403`" as covering it. A cancelled verification is a transient `503`. *Question:* `502` or
   `403` for the unknown namespace; must the `403` messages name none; confirm the order.
6. **Older sealed log ranges for a `requireAt` check** (§C.4, §E.2.3). A checker's grant
   issued after an epoch rotation gets no key for the older epoch's stored log range even where
   `/keys` answers, so every `requireAt` `at` from before the rotation is a lasting `502` for it.
   *Question:* should a verifier's grant open older sealed ranges for this, or is the `502`
   expected?
7. **The `key:` subject of a grant without a `pub`** (§B.11.9 gs, §A.4). A grant signed by an
   operator key (a published JWK has no `pub`), or by a `kid` the namespace document doesn't
   list, has `""` for `pub` and gets scope cookies that are always `403`, as `g:` cookies were.
   *Question:* is `pub` the JWK's `x`, or are operator grants never partial readers of the index?
8. **Where the index gives no marker** (§A.4; was v0.76 Open 2). The reference reads a local
   base both as of the branch's `at` and at its head, and either naming a catalog counts, a base
   purged or gone included, at every level up the chain; the namespace itself is exempt only if
   every document it reads (head and checkpoint) says sealed or end-to-end. *Question:* base at
   its head or as of `at`; deeper bases or only the immediate one?
9. **The exchange's `410`** (§A.4 Coverage, §C.5.2; was v0.76 Open 16). "Every namespace its
   grant names" includes unfollowed ones, which don't qualify; the set is that of the first block
   naming namespaces without `"*"`, so a block naming `"*"` never qualifies, and a narrowing
   block's narrower list isn't taken as the set. Where only purged namespaces are named and the
   grant fails to verify in one, the answer is `403` (`401` if a refusal was). At `/_refs`,
   where every reader sees public namespaces, a grant naming only purged ones gets `410` only on
   an index following no public namespace, else the public answer. *Question:* confirm each.
10. **503 bodies naming no namespace** (§A.4 Private namespaces, §B.5 Behind; was v0.76 Open
    14). v0.77 settles that a namespace visibility reads but hasn't reached is `503 behind`; only
    §C.4's `502` says "naming no namespace". The reference also strips the member's name from
    the index's `503` (as `/principal` hides `catalog.trust`) and the tree's and index's chain
    and root `503`s name none, with a fixed `Retry-After` (5 s in the tree; the spec fixes none).
    *Question:* must every `503 behind` body name no namespace?
11. **`/_refs` and "earliest"** (§A.4 Answers; was v0.76 Open 4). A base read at different
    `at`s is listed at the earliest in its chain, and `min` on it judged against that `at`; where
    the base's log can't be read (other than `404`) the index falls back to byte order of the
    `ns_id`s and logs it, which only changes which one is listed. *Question:* confirm "earliest"
    means in the hash chain, and the fallback.
12. **A result and a purge** (§A.1, §B.5; was v0.76 Open 15). The index never serves or keeps a
    result computed from rows read before a purge in `m`: it computes again after the purge, and
    answers `503 behind` if that keeps losing (after two more tries at `/{ns}`, after the third
    at `/_refs`). The tree service's `listing()` still serves a refused result once. *Question:*
    does §A.1's "serving or keeping none computed from what was read before it" also bind tree
    listings (§B.5 purges "as §A.1 does")? Is `503 behind` acceptable when recomputation keeps
    losing?
13. **Authentication mode that can't be learned** (§B.11.9 Where, §1). Coverage holds only
    while authentication is on. The index reads the core's root again once `CheckerTTL` has passed
    and, for a namespace the documents would cover, answers `503 behind` (transient: transport,
    deadline, `5xx`, `408`, `429`) or `502`, never reusing the last known mode. *Question:* may a
    stale mode be used for a bounded time?
14. **A purged covered namespace's `/heads`** (§8.5, §B.11.9 URLs, gs; was v0.76 Open 12). A
    grant that reads it unrestricted gets `410` at filtered `/heads` with or without `at`. A
    partial reader's unfiltered `/heads` is still `302` to the filtered form, which then
    answers `410`: two steps, not §8.5's direct `410`. A catalog's own partial reader gets a new
    subject set once it is purged (it leaves its own deciding views), and its old `gs` is `403`,
    counting the own-`gs` check as part of "the full read check". *Question:* which comes first
    for an unfiltered URL, and does a purged namespace's filtered `/heads` ignore `gs`?
15. **Pre-raise sealings on a remote branch, at creation** (§G.3 Creating one, §G.5.2; was
    v0.76 Open 22). Where B holds the key, a sealing A refuses (`403`, `404`), has pruned
    (`410`) or fails to serve is recorded as pending and creation is `201`; where the grant gets
    no key of an epoch (A's `/keys` refuses or omits it) creation is `422`; a transient `/keys`
    failure at creation is `502`, not a pending row. A refused sealing is not `422`, a pruned one
    not `410` (as pruned chain history is). *Question:* should creation be `422` (or `410`) for
    them, does §G.3's lazy fetching exempt a sealing B has no key for from the `422`, and should
    a transient `/keys` failure leave the branch pending instead of `502`?
16. **Pre-raise sealings on a remote branch, afterwards** (§G.5.2, §7.1; was v0.76 Open 22).
    A pending sealing is asked for again at every sync; the URLs needing it answer `502`, or
    `410 pruned` with the horizon A's `410` body gave, and that `410` is final. A served sealing
    that doesn't open to the mirrored content is recorded as `unverified` and keeps answering
    `502`. Where A `410`s a resource log from genesis, B asks for each entry in its own range
    (`…/rev/{id}/log?since={parent}`) and records one as pruned only if A `410`s that range, which
    §7.1 and §G.5.2 don't say. *Question:* does "502 until then" cover the whole resource or only
    the URLs needing the sealing; is "pruned is final" right if A serves it again (a restore from
    archive); do some answers (`403`, `404`) become final, or retries back off; which horizon does
    B's `410` name; does A's `410` stop B serving the rest of that mirrored chain? *Propose:* a
    note in §G.5.2 on one-entry ranges.
17. **"Judged once, when the service first seals"** (§E.2.6, §E.3.1; was v0.76 Open 25 in
    part). The tree and the index write the judgement just before sealing, in their own
    transaction (an update guarded by the head), apart from the one that stores the sealed
    listing; a crash between leaves a judgement without a listing, and an answer that judges and
    then fails has still judged. While a database's head epochs are still being read in, the tree
    seals under the current epoch without judging and drops what it stored, so readers in that
    window got the value under the epoch in force, as in v0.76. Rows from before v0.77 keep `born`
    epochs judged at apply time, which can differ from their head's. *Question:* is that "first
    seals"; may or must a service in that window answer `503 behind`; must legacy rows be
    re-marked?
18. **Snapshot values that name a base or no epoch** (§E.3.1, §E.2.6; was v0.76 Open 25 in
    part). The reference leaves out a value whose snapshot `kid` names a base, or whose epoch is
    unknown (a revision read through from before its base's raise, or a `born` whose first
    revision predates a raise from none and was applied while the catalog was still at none, so
    the level as of the log position gives no epoch), rather than seal it under a `K_r` derived
    from the base's key or the epoch in force. The client gives no epoch for an own op whose kid
    names another namespace (`PruneE2E` fails). *Question:* left out, or sealed, and should a
    raise make such borns pending?
19. **Epochs of branch catalogs in the tree service** (§E.2.6, §10 Branches). A release preview
    seals under the logical catalog's kids but takes the epoch from the branch's `Info`, so after
    the branch rotates `KeyAt(cat, 2)` fails and node values are left out; epoch numbers of the
    branch are sealed with the catalog's keys of the same number (pre-existing; v0.76). A service
    following a branch catalog directly sees only its own log, not what it reads through from its
    base. *Question:* which namespace's epochs does a preview listing seal under; must a directly
    served branch catalog include read-through nodes?
20. **Tree details after a redirect or a refusal** (§A.4, §B.5, §B.9, §C.4). A redirect keeps
    the legacy order cursor (`after={order}&name=…`, which names an order, not a resource) and
    drops position cursors. `POST /edge-grants` with one grant refused (`403`) and another's
    chain unreadable answers `403` (all or nothing, refusals win), not `503`/`502`. *Question:*
    confirm each.
21. **Switch and what is given up** (§F.5 Switch, §F.6; was v0.76 Open 29). A resource purged
    only in the successor is neither recorded nor an exception, so Switch waits for a person to
    give it up (`LeaveOut`); `Options.Resources` with Switch builds the gate from an extra
    unrestricted plan; a give-up still holds in the catch-up, which replays a resource that
    changes again after step 2 and reports `ErrConflicts` after the switch; nothing records what
    was given up, so §F.6's superseded check can never pass for that branch. *Question:* is
    "purged in the successor" an exception; should the switch's config write record the given-up
    resources (`"leftOut"`) for the janitor; is a give-up for good; is a partial replay followed
    by a full one allowed?
22. **Which array writes widen** (§F.3, §11.2, §6.4.1; was v0.76 Open 30 in part). v0.77 says
    "indexes an array" and drops "(an index or `-`)". A last `-` under an array (an append)
    still widens, judged in the document before the op, as merges did; an object member named
    `-` doesn't. *Question:* confirm, and say so.
23. **A failed read in §H.4 and §H.6** (was v0.76 Open 36). A failed read of the last revision
    or the tombstone's entry (a timeout, `408`, `429`, `5xx`, a failing key fetch, an unreachable
    core) fails a save over someone else's delete `503` (`408`, `429`, timeouts, with
    `Retry-After`) or `502` (`5xx`, core unreachable, a transport error with no answer, as
    "can't be reached"); a failed `GET /ns/{ns}/principal` deciding whether the delete was the
    user's counts too. Other reads (the key history behind `wroteAs`, `knowUser` in
    `ownLogEntry`) still swallow failures, and §H.4's Answers has no row for a gateway-side
    timeout (treated as 503). *Question:* confirm the mapping; must every read that decides
    "theirs" or "own" fail the save; and which of `503`/`502` does `408` get?
24. **Check-fixed epochs for pre-raise content** (§E.2.2 Epochs; was v0.76 Open 24 in part).
    v0.77 settles that a refused request fixes no epoch. The reference stores no fixing for
    pre-raise content, as the fallback epoch never changes and shadows carry A's epochs, which
    is harmless. *Question:* must a check store one where that changes nothing observable?
25. **Item 2's roles and the digest** (§B.11.9 Visible, §A.4; was v0.76 Open 8, v0.75 Open 10). A read role
    testing `/principal/sub` never allows anything through filtered reads, as item 2 counts roles
    "only as §B.11.5 counts them", yet its rules enter the scope digest
    (`grantcheck.ReadFilter.AllowsItem`); CONFORMANCE scenario 75 depends on this. *Question:*
    intended? Do the reader's own role rules filter at all?
26. **Authentication disabled gets the current epoch only** (§E.2.3, §E.2.6, §A.4; was v0.76 Open 27, v0.74
    Open 4). A playground, and services without grants, can't open older epochs after a
    rotation, and a fresh index or tree service leaves those documents out. *Question:*
    intended?
27. **A re-sealed restore with `[]`** (§F.3 kept bullet, §8.2, §E.3.1; was v0.76 Open 32). An honest e2e client
    can't write a branch revision referencing a pre-raise blob; the paths that do are a restore with
    `[]`, which keeps the declared list, and a replay onto a base head from before the raise.
    Sending such a restore unsealed as `[]` would let the resource merge; the reference leaves it
    unmerged, as the text says. *Question:* should a merge prefer that?
28. **Config plus items only for purged resources** (§F.6; was v0.76 Open 33). Outside E3 such a batch is not an own
    entry, but it is a `batch` entry after `source.at` (`internal/janitor/janitor.go`
    `countingItem`). *Question:* is the asymmetry intended?
29. **"Nothing promised" against invariant Valid** (§4 Valid, §6.1; was v0.76 Open 34 and v0.74
    Open 1). v0.77 changed only the changelog; §4 Valid still promises the same answer on
    re-validation. The reference compiles every stored schema under today's rules, and a write
    pinning one that no longer compiles is `422 invalid`. *Propose:* put the exception in the
    text and say what such a write answers (`422 invalid` or `schema_unavailable`).
30. **A fixing grant and `/ns/{ns}/g/{gs}`** (§B.11.9 Edge grants; was v0.76 Open 37, v0.75 Open 12). A grant
    that fixes `/resource` gets its `/r/{ns}/{name}` prefixes and no `/g/` prefix
    (`internal/core/edgegrants.go`). *Question:* may it get one too?
31. **Malformed `{gs}` or `{at}`** (§B.11.9 URLs, §7; was v0.76 Open 38, v0.75 Open 18 in part). `400
    bad_input`, `all` as `gs` too. *Propose:* say so.
32. **Filtered `/heads` and `next`** (§B.11.9 /heads, §7.4; was v0.76 Open 39 in part). `next`
    comes on every full page, unlike unfiltered `/heads`, and the client accepts a short page
    with `next` (a bad `prefix` is a request-shape `400`, settled in v0.77). *Question:* is the
    divergence intended?
33. **Ranges across a moving `at`, and client libraries** (§B.11.9 Log ranges, §10; was v0.76 Open 40, v0.75
    Open 22). The client starts again on a `302` partway through, takes `gs` and `at` from the
    `Location` path with its own query, and its `LongPoll` and `NSEvents` don't follow into a
    filtered log (`internal/client/filtered.go`). *Propose:* "a client library MUST NOT hand a
    filtered log to a caller that expects the unfiltered one"; may a client resume from `since`?
34. **A bounded scan before `204`** (§B.11.9 Long-poll; was v0.76 Open 41, v0.75 Open 23 in part). The reference
    scans the whole log while nothing is visible (`internal/core/filtered_live.go`). *Question:*
    may a server answer `204` after a bounded scan, naming the newest entry scanned?
35. **Live reads when the reader's `gs` changes** (§B.11.9 Events, Long-poll; was v0.76 Open 42, v0.75 Open 24).
    The stream ends, and a long-poll is `403`, rather than keep the URL's `gs`. *Propose:*
    confirm.
36. **`/resource` inside `any` or `not` beside a fixing rule** (§C.5.2, §2.1; was v0.76 Open 47, v0.74 Open 20).
    Read as not fixing, evaluated per fixed name, every name before the 100-prefix cap.
    *Propose:* confirm.
37. **Other `Authorization` schemes** (§C.3, §C.5.3; was v0.76 Open 48, v0.74 Open 21 in part). Any field counts
    as present, `Basic …` included (`internal/edge/edge.go`). *Question:* intended?
38. **Catalog answers** (§B.11.4, §B.9; was v0.76 Open 49, v0.74 Open 25 in part). The service keeps its purge
    record for a namespace the catalog no longer trusts (`internal/tree/tree.go`
    `forgetUntrusted`), and leaves "the node's parents as decided" out for an implicit placement,
    which has no `parents`. *Question:* each.
39. **Encrypted archives** (§8.6, §G.5.1.1; was v0.76 Open 50, v0.74 Open 37 in part). The per-resource archive
    key has no export path, and E3 archives are sealed twice (`internal/core/archiveseal.go`).
    *Question:* both.
40. **Sealed resource events** (§7.3, §E.2.2; was v0.76 Open 51, v0.74 Open 40). `purge` and `prune` events bind
    no entry in `pl` and carry no `id:`; the reference stores none (`internal/core/eventseal.go`).
    *Propose:* bind `target`, and say they aren't stored.
41. **Why a resource purge purges `idx:{ns}`** (§A.1; was v0.76 Open 52, v0.74 Open 43 in part). *Propose:* give
    the reason (positional cursors, counts, scores), and note that a stream of purges defeats
    "one redirect suffices".
42. **The index's range filters** (§A.4; was v0.76 Open 53, v0.74 Open 44). `gt`, `ge`, `lt` and `le` with a
    `sort` mark remain the reference's own (`internal/index/query.go`). *Propose:* specify or
    drop them.
43. **`scope:{digest}` in a `gs`** (§B.11.9 gs, §A.4). "of §A.4's marker" is read as the
    marker digest, which covers the key's `key:` string, though `key:` is also its own subject;
    the origin and index both use it, so `gs` values changed this release. *Question:* or did
    the authors mean the rules-only digest?
44. **How many recomputes before `503 behind`** (§A.1, §B.5). A tree listing or index result
    that keeps losing to purges, or to a raise between reading the encryption and computing, is
    computed again up to three times, then `503 behind` with `Retry-After: 1`, `no-store`.
    *Propose:* say a service may answer `behind` after a bounded number of tries.

## Settled in v0.77

v0.77 answers the 53 notes open from v0.76: it settles 31 whole, 6 in part (14, 15, 24, 25, 34,
39) and leaves 16 (8, 27, 32, 33, 37, 38, 40, 41, 42, 47–53; it doesn't mention 52 and 53). What
remains is rewritten above, marked "was v0.76 Open n". "n above" below means v0.76 Open n. The
reference follows the text in each. Where v0.77 went against it, the reference changed, in the
area named:
- **Subject sets, scope cookies and coverage** (1, 2, 5, 6, 7): the key joins `gs` as
  `key:{…}` and §A.4's scope digest covers it, so the index's scope markers and cookies bind
  the key too, and such a cookie ends with its key, its `read` or its `pub`; the index gives
  no marker where the namespace is a catalog or its or a local base's `catalogs` names one
  (not sealed or end-to-end); nothing is covered while authentication is disabled; a purged
  catalog keeps a namespace covered and makes nothing visible (changed at the origin's
  filtered `/heads` and the index; 1 above). Settled and already followed: the
  whole key entry as canonical JSON is "unchanged" (3), a branch's root that doesn't trust the
  catalog at `baseAt` is uncovered (5), tombstoned nodes decide subjects for filtered reads and
  the index only (9), the gestures `/now` `403` is a partial reader's only (10), a recorded
  `at` is answered again but for purges since (11), `403` or `401` in §7's order (13),
  `catalogs` must name the catalog (20), and a namespace that left the checkpoint is `403` at
  `g/all` (21).
- **The index's exchange, purges and follows** (4, 12, 14, 15, 16): a `/_refs` base read at
  different `at`s is listed at the earliest in its chain; `/heads` of a purged covered
  namespace answers as `/heads` (`410` once the full read check passes); the exchange is `410`
  only where every namespace the grant names is purged and the grant verifies in each,
  otherwise `401`/`403`, for `/_refs` too; a result computed from what was read before a purge
  is neither kept nor served, the query computed again (changed at the origin and the index). Settled as followed: purged namespaces follow §8.5 (12); a namespace
  visibility reads is `503 behind` until reached, `/_refs` included (14, whose `503` body now
  names no member); the view-read-before-a-purge rule is stricter than the reference's earlier
  one (15); the redirect from the head pointer drops an opaque `after` (44; changed in the
  index and the tree's children cursors).
- **`requireAt` and outages** (17, 18, 19, 28): "rules passing now" is the fixing check (17);
  a chain a verifier can't read is `503 behind` while transient and else `502 upstream`, naming no
  namespace, never `403` (changed: `grantcheck`, the grant, the index's, tree's and catalog's
  mapping; 18, 19 above); a `408` from `/keys` or the origin is transient everywhere (changed:
  the shared client, follow, derived keys, the index, the tree; 28 above).
- **Encryption and remote branches** (22, 23, 24, 25, 26): B stores and serves a pre-raise
  sealing of an E3 source only once opened and verified, at creation want of a key is `422`,
  after creation a sealing not served is `502` until a later fetch opens it, or `410` where A
  pruned it (changed; core migration `014_remote_pending_sealings`; 22 above);
  `born` and other values from a revision read through take the snapshot rule, judged once, when
  first sealed, in the tree service, the index and the client's `pl.ns` rule (changed; 25 above,
  the rest of it still open); B reads deeper bases as before (23), a refused request fixes no
  epoch (24, the second half of it open), and the nonce binds writes and imports, not stored
  keyrings (26).
- **Merges, undo and gateways** (29, 30, 31, 36): Switch waits until every changed resource is
  recorded, apart from §F.6's exceptions, or a person gives up the rest, and the catch-up reports
  what is left (changed: `Plan.Unrecorded`, `-leave-out`; 29
  above); only a write whose last segment indexes an array widens, which merge already did
  (30), and undo's writes and guard widen to the outermost array (changed:
  `pointer.WidenArray`; 31 above); a failed read fails a save over
  someone else's delete with `503`/`502`, never `409` (changed in the gateway; 36 above).
- **Schemas and answers** (34, 35, 39, 43, 45, 46): only the changelog says data written under
  earlier drafts gets nothing promised (34, still open); plain `hostname` and CONTEXTO (35), a
  bad filtered `prefix` as a request-shape `400` (39, whose `next` half is open),
  `/principal` roles as `{name, can, rules}` (43), limits on rule fragments only §6.6's regex rule
  (45) and the reach of the `403` (46) are settled as the reference had them.

## Settled in v0.76

v0.76 answers the 32 notes open from v0.75 and the 45 from v0.74; "n above" below means v0.76 Open n, which v0.77 settled or carried (Settled in v0.77). Of v0.75's, it settles 19
whole, 6 in part (3, 7, 17, 18, 23, 31) and leaves 7 (10, 12, 20, 22, 24, 28, 32); of v0.74's,
27 whole, 12 in part (4, 8, 12, 13, 16, 17, 21, 25, 29, 31, 37, 43) and leaves 6 (1, 14, 19, 20,
40, 44). What remains is rewritten above. The reference follows the text in each. Where v0.76
went against it, the reference changed, in the area named:
- **Coverage and branches** (v0.75 1, 4, 14, 17 in part, 29, 30): coverage follows the namespace
  documents alone, whatever the origin implements, and services needn't compute the same `gs` or
  scope digest; local branches and theirs only; covered forms for partial readers only. A
  branch's bases are read as of its `at`, by the root's trust, keys and roles, and a branch
  stays covered only while the root, at its head, still trusts the catalog through each counted
  key, unchanged (changed: `internal/core/filtered_scope.go` `fsHeadTrusts`,
  `internal/index/filtered.go` `branchTrustHolds`; 2–5 above). An `at` holds every
  `catalog.trust` member, one `ns_id` per namespace, a namespace read at its head listed at it
  (changed: `internal/core/filtered_state.go`, and the index's read positions kept apart from its
  listed ids; 4 above).
- **Subject sets and cookies** (v0.75 2, 5, 6, 7 in part, 8, 9, 11, 13, 16, 26): every role and
  every key of a trusted content namespace decides, a key's `groups` scope names none, and groups drop out only
  for the listed positive tests (changed: `internal/catvis/profile.go`,
  `internal/rules/grouptests.go`); only an unrestricted reader's grant is `403` at filtered URLs;
  rows are kept per namespace and `gs`, a miss is `401`; a cookie whose key or role is gone, or
  whose base key §C.4 no longer accepts, is `403`, so rows bind the key's `pub` (changed: core
  migration 012, index 006 and 007; 1 and 7 above); a catalog keeping every group refuses
  `"partial"`; each `requireAt` key is judged alone, and only trusting namespaces' roles count
  for folders; a marker of the old coverage form is `403`; a grant may be judged at the current
  checkpoint; any `at` the origin can compute exactly again may be answered, others get a `302`,
  `private, no-store` (11 above); the gestures listing is `403` for `/now` rules (10 above).
- **Answers, logs and tags** (v0.75 3, 15, 18 in part, 19, 21, 23 in part, 25, 27): a deleted
  resource is judged at the answer's `at` as if live, and a purged catalog node is hidden (9
  above); redirects drop the URL's `ns_id`, and `GET /ns/{ns}` keeps the head pointer; emptied
  `gestures` and `source.ids` are left out; Cost counts per `gs` and checkpoint; filtered
  answers carry their unfiltered forms' tags, `heads:{x}` included; `/branches` stays as §10
  says. An uncovered namespace answers filtered URLs `403`, or `401` as §B.11.5 says (changed:
  `internal/core/filtered_reads.go` `filteredOpen`, `grantVerifiesIn`; 12 and 13 above).
- **The index** (v0.75 25, 31 in part; v0.74 13 in part, 15, 43 in part, 45): markers per
  namespace, the exchange refusing only as Coverage says (changed: `internal/index/edgegrants.go`
  `exchangeGrant`, `http.go` `grantAccess`; 16 and 17 above), and `403` at another `gs`'s
  `/_refs` URL for a grant that verifies in a followed namespace (changed: `refsall.go`
  `verifiesFollowed`; 13 above); `502` while a namespace visibility reads can't be read or its
  keys are lacking, `503 behind` while they can't be fetched yet (changed, scenario 100); the
  index follows the namespaces visibility reads and purges `idx:{m}` with them, rather than read
  their heads within `CheckerTTL` (changed: `internal/index/members.go`, index migration 008;
  14 and 15 above); a foreign `min`'s `400` comes after the namespace's own `401`, `403`, `404`
  and `410`; a purge drops a kept result even at an `at` redirected to; stored sealed results
  last until a config entry purges `ns:{ns}`.
- **Keys, levels and remote branches** (v0.74 2, 3, 5–7, 8 in part, 9, 12 in part, 33, 38): an
  E3 fold across a raise, branches of a raised base by the base-epoch rule, start times only
  through `base.origin`, and `/heads` rows purged since, as the reference had them; a keyring
  `$nonce` has the fresh form (changed: `internal/core/e2e.go` `checkKeyring`,
  `internal/bundle/access.go`; 26 above); a failed raise is `502 upstream` (changed:
  `internal/core/upstream.go` `upstreamRefusal`); E3 source bytes are A's, never B's sealing
  (changed: `internal/core/remote_blobs.go`, `preraise.go`; 22 above); B relays no deeper base's
  keys while it can't read its namespace document (changed: `internal/core/remote_branch.go`,
  core migration 013; 23 above); a wrapped key no recipient key opens is lacking, an untrusted
  `from` no key (changed: `internal/client`, `internal/derived`, `internal/tree` `lastingKeyErr`;
  28 above); a check that fixes an epoch stores it (changed: `internal/core/keywindow.go`; 24
  above).
- **Derived views and the tree** (v0.74 4 in part, 10, 11, 22, 23): whole-response sealing
  excepts only values of another resource, a value whose key is lacking for good is left out, and
  so is an entry whose revision the service never opened (27 above); aggregates across epochs
  stay `400`; `born`'s epoch is its `snapshot`'s, never the first entry's served `kid`, and a
  `born` of unknown epoch is left out (changed: `internal/tree` `snapshotBornEpoch`, a one-shot
  refill under `meta` `bornsnap`; 25 above); `roots` of a subject-set listing as the reference had
  them; `g/all` is judged against the combined checkpoint only (changed:
  `internal/tree/edgegrants.go`, `meta` `inckpt:{ns}`; 21 above).
- **Catalog** (v0.74 24, 25 in part, 26): the catalog service's key in a content namespace is one
  whose `requireAt` names the catalog (changed: `internal/catalog` `contentKey`, with
  `namesCatalog`; 20 above); `/read-grants` answers an untrusted namespace's public item `403`
  before `"public": true` (changed: `internal/catalog/grants.go`); Restore judges the caller's
  own subjects, and an end-to-end catalog's `catalog-admins` is read from root `groups`.
- **Schemas, requests and formats** (v0.74 16 in part, 17 in part, 18, 21 in part, 32, 34, 36,
  37 in part, 39, 41, 42): hostname formats follow RFC 5891's registration rules without UTS 46
  mapping, R-LDH only as an A-label (35 above); copies check `400`, `428`, `422`, then the
  source; sealed bundles reject non-canonical line headers, and archive lines are padded where
  `pad` is set (I.15's rejection vectors are still to come); a snapshot `kid`'s op is the
  branch's own by its `pl.ns`; data written under earlier drafts gets nothing promised, so stored
  rule fragments, stored Biscuit version 0 forms, the legacy keyring, resent stored content,
  `via` on older entries and revocation ids from before v0.71 keep the reference's handling (34,
  45 and 48 above).
- **Merges, the janitor and gateways** (v0.74 27, 28, 29 in part, 30, 31 in part, 35): a batch
  counts against `merged` and `superseded` only through its items (changed: `internal/janitor/janitor.go`
  `countingItem`; 33 above); "what this check needs" is what the purge stopped serving;
  conflicts are judged at the outermost array (changed: `internal/merge/writes.go`; 30 and 31
  above); a replayed or re-sealed item whose document references a blob a `sealed` op can't
  declare stays unmerged, as a kept head does (changed: `internal/merge/e2e.go`, and
  `merge.Rebase` stops before a switch, 29 above); §H.7 own entries by key history, and §H.4's
  `409` where the gateway can't read the last revision (36 above).

## Settled in v0.74

v0.74 settled 113 of the 134 notes open at v0.73; the other 21 were rewritten as v0.74 Open 2,
11, 13, 16, 28–30 and 33–45 (34 covers two), and "n above" below means v0.74 Open n, which v0.76
settled or carried (Settled in v0.76). The reference follows the text in each. Where v0.74
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
