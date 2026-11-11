# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.82**, with `docs/SERVICES.md` and
`docs/TOOLS.md`, split from it in v0.80. This file collects what the reference does that the text
doesn't yet describe. Open notes come in one list, from implementing v0.82; cite them as "v0.82
Open n". v0.82 answered the v0.81 list ("v0.81 Open n"): what it settled is under "Settled in
v0.82", and what it left open is rewritten in the new list, marked "was v0.81 Open n". The v0.77
list was answered in v0.78 to v0.81 (Settled in v0.81), and earlier lists before it.

## Open from v0.82

From implementing v0.82 (branch `spec-v082`). Numbered afresh; cite these as "v0.82 Open n".
Each entry gives the section, what the reference does now (the conservative reading where it
had a choice) and the question. The planner's questions from before the work and the
implementers' and reviewers' notes are merged here, each case once. Notes from v0.81 that v0.82
leaves open are carried in place, by subject, marked "was v0.81 Open n" and cut to what
remains. The order is: sealed forms and end-to-end reads (1–31), access and coverage (32–65),
tree answers (66–71), documents, bundles and tools (72–83), vectors (84–85). Sections are
SPEC.md's unless TOOLS.md is named; Addenda A and B and §E.2.6 are in SERVICES.md.

85 are open: 55 from this version's work and 30 carried.

The spec's own question to the reference, "what is a shadow?", is answered under "Settled in
v0.82" (v0.81 Open 24).

1. **C.1's closing sentence** (VECTORS-PROPOSED C.1, §E.2.2). It says v0.81's
   `{"kind":…,"name":…,"ns":…}` form is no longer accepted, and the preface speaks of "three
   event rows … whose `pl` v0.82 changed". §E.2.2's row for a resource stream's `purge` and
   `prune` events is unchanged, and C.1's own two resource rows carry that `pl` with v0.81's
   tags. The reference keeps `{ ns, name, kind }` for resource events and refuses only the
   range form of a namespace event. *Question:* a slip?
2. **The tombstone `410`** (§7.1). The body gains `last` under an unchanged immutable `ETag
   "{id}"`, so caches hold the old body. The release notes ask for a purge at upgrade; the
   client falls back to the log on a `410` without `last`, and a remote branch's creation then
   answers `410 pruned`. `/rev/{T}`'s `{ tombstone, last }` has the members of `GET
   /r/{ns}/{name}` on a tombstoned head (both also carry `code: "gone"`). *Question:* is a
   purge the intended answer; may a reader take a `410` without `last` as an older server's;
   is the URL the only difference between the two bodies?
3. **A tombstone's `/raw` in sealed and end-to-end namespaces** (§7.1). The `/raw` row says such
   namespaces answer `404 not_offered` after the read check, and the tombstone row says `410`.
   The reference answers `not_offered` for `/rev/{T}/raw` there. *Question:* which comes first?
4. **Tombstones and remote branches** (§G.3, §G.5.2, scenario 75). B never learns ids below its
   source's horizon, so a tombstone id there is `404`, as any id is. Scenario 75 says B learns
   a tombstone horizon's parent from A's `410`; the reference also still takes it from the
   `last` of a later revision's `not_offered`, checked against the tombstone's id the same way.
   *Question:* is `404` right below the horizon; is the second source allowed?
5. **Which later prune ends a snapshot** (§7.1). After a restore, a prune can move the horizon
   to a revision below the stored snapshot's. The reference ends the older snapshot then too
   (`/rev/{H1}` is `404 not_offered`). Where earlier data left several snapshots for a resource
   with no horizon it deletes all of them at start, and it has no tag to purge for that.
   *Question:* confirm both.
6. **Branches and pruning** (§8.6, §G.5.1). A prune in a branch moves nothing in the reference:
   it checks the snapshot and leaves the base's rows alone. The server therefore never writes a
   branch's archive, and "the `access` of a branch's archive" has no case. *Question:* should
   §8.6 say whether a branch may prune its own segment, and that archives exist only for
   namespaces that aren't branches?
7. **Counts seeded before v0.81** (§E.2.1). "Never fall short" can't be shown for sealings an
   earlier draft made and didn't store (events, race losers). The reference doesn't count them
   and tells operators to rotate sealed namespaces whose epoch began before the v0.27.0
   upgrade. *Question:* covered by "no compatibility with earlier drafts' data", or must such
   epochs be rotated?
8. **Self-rotation in a frozen namespace** (§E.2.1, §7.4; was v0.81 Open 9). §E.2.1 lets the
   origin rotate "in a config entry it writes itself (§7.4)", but §7.4's exemption from
   `frozen` names only purge propagation among server-written entries. The origin rotates
   frozen namespaces. *Question:* may it?
9. **Self-rotation with authentication disabled** (§7.2, §E.2.1). §7.2 says `grant` and `via`
   are absent from the server's own rotations, and also that `grant` is `null` on entries
   written while authentication is disabled. The reference writes neither member. *Question:*
   absent, or `null`?
10. **First contact with a lower level** (§7.1 End-to-end namespaces, Levels). A client with no
    configured level that first meets a server claiming a lower level can't detect it. The Go
    client offers `WithExpectedLevel` (`-expect-level`), the playground an "expect" control,
    and both document it. *Question:* should the text say configuration is the only protection
    there?
11. **What teaches a level** (§7.1 "keeps the highest it has learnt"). In the reference only the
    current namespace document and `/keys` teach; a historical document read by id doesn't,
    since it legitimately names a lower level. A `404 not_offered` from `/keys` teaches nothing:
    the held level stands and a write fails for lack of an epoch. A level that isn't one of the
    four names, or isn't a string, is refused while any level is held and teaches nothing
    otherwise; a configured unknown level is held as e2e. *Question:* confirm each; should the
    text say what a reader does with an unknown level?
12. **A lowered claim** (§7.1, Addendum E Levels, §E.3.1). `ErrLevelLowered` is lasting, not
    transient, so a cache serving a stale head document after a legitimate raise makes a
    long-running service fail that namespace until the cache expires. Reading through a base
    whose document now names a lower level than the reader holds is refused too, for any
    namespace on the chain. *Question:* lasting or transient; must a reader refuse to read
    through such a base?
13. **Read-through at E2 and the fork** (§E.2.2, §E.3.1). The Go client's E2 path accepts
    content sealed with a base's `ns` at any depth of the chain with no check of the fork
    position, unlike its E3 path. *Question:* should §E.2.2 readers bound base-sealed content
    by the fork as well?
14. **The E3 count when the log can't be read** (§E.2.1). A writer whose grant can't read the
    log, or that writes below a pruning horizon, counts its own sealings only, reports the
    count as partial and keeps a margin of 2³¹. *Question:* how should such a writer weigh the
    bound?
15. **A replayed keyring `$nonce`** (§E.3.2). The server accepts the same well-formed `$nonce`
    twice on the keyring. *Question:* does "checks only its form" mean replays are the writer's
    concern?
16. **Sealed bundles and the line bound** (§E.2.1, §G.5.1.1). The 2³² − 1 rule is listed under
    reader checks only; the reference's writer stops there too. Its writer names the plain
    bundle's line in the refusal and its reader the sealed file's line, one higher because of
    the envelope line. *Question:* does the rule bind writers; which line should a rejection
    name?
17. **A head read without a `kid` at E2** (§E.2.6 Per-entry sealing). A revision indexed before
    a raise to sealed has no `kid`. The tree service serves its node by name only and reads the
    head again. The index judges it as the epoch in force when it first seals, read again under
    the lock a rotation takes, so never as an epoch already rotated away; the `kid` may then
    differ from the epoch the origin fixes for that revision. *Question:* may a service judge
    it as the epoch in force, or must it read the head again? If a re-read is required the
    index changes.
18. **A head that can no longer be read** (§E.2.6). The text lets a service judge an e2e head
    read without an own `kid` under the epoch in force. It doesn't say what to do with a head
    the service once read and can't read any more (a key lost for good, a head gone). The tree
    service never judges it: the node stays by name only, across restarts. *Question:* confirm.
19. **Values with no revision to judge** (§E.2.6). An implicit placement, and a node without a
    head, have no catalog revision whose epoch could be judged, yet their values (an item's
    title, a self-placed item's `born`) are sealed under the catalog node's `K_r`. The
    reference seals them under the catalog's current epoch. *Question:* which epoch?
20. **Name-only answers: kept, recomputed or refused** (§E.2.6 "until it can judge it … serves
    the entry by name only"). The tree service drops a listing that left values out once the
    judging read ends, rather than keep it at its `at`. The index computes a result again where
    it met an unjudged revision, and answers `503 behind` if that keeps happening, rather than
    serve entries by name only. *Question:* may a listing with values left out be stored and
    served unchanged at its `at`; are recomputing and `503 behind` allowed in place of name
    only?
21. **Previews, and branch catalogs served directly** (§B.5 Previews, §E.2.6; was v0.81 Open
    57). v0.82 says a preview seals under the branch's keys. The reference judges a base's op
    read through as the branch's epoch in force at first sealing, puts the branch's name in
    `pl.ns` and `kid` while `view` keeps the URL's catalog name, and records which namespace a
    store's epochs are of, judging all of them again when that changes. A preview service
    without the branch's keys can't follow the branch at all, so it answers `404` as for any
    catalog whose keys it lacks; there is nothing to list by name. *Question:* confirm each. At
    E3 "the branch's `K_r`" needs the preview service to be a recipient in the branch's
    keyring: intended? Still open from v0.81: must a branch catalog served directly include the
    nodes it reads through from its base?
22. **Naming the resource of a nested value** (§E.2.6 Values of another resource, §B.5
    Previews). "Where the entry names it": the reference compares `born` with the entry's own
    name and other members only where the entry carries `item` in the clear. In a preview a
    placement's `file` is drawn from the release's branch of the item's namespace, so `pl.ns`
    names the branch while `item` names the base. The tree service's entries carry a member of
    its own, `branch`, beside `item` and `url`, and the playground requires the value to be the
    branch's resource wherever `branch` is present. *Question:* does a placement entry always
    carry `item` in the clear; should the spec define `branch`, or have `item` name the branch
    in previews?
23. **A path-rewriting proxy** (§E.2.6 View keys). `view` is the request target as the
    service's redirect gave it, byte for byte. The reference documents as an operator rule that
    nothing between service and reader rewrites the path. *Question:* should the text say so?
24. **A sealed filtered event stream** (§E.2.2, §B.11.9). The changelog says "a filtered stream
    needs no previous id". At the origin covered namespaces are never sealed, and the reference
    has no sealed filtered stream. *Question:* is there one it should implement or test?
25. **A source's raise to e2e seen in a followed log** (§G.5.2, CONFORMANCE scenario 74; was
    v0.81 Open 19). Scenario 74 asks for `502 upstream`, never a weaker level, "whatever level
    R reaches", and the reference now holds everything the source had at `at` at `502` for
    good; it served that content sealed before. No spec sentence stands behind the scenario.
    *Propose:* say it in §G.5.2.
26. **Cross-version federation** (§G.5.2; was v0.81 Open 15). No sentence yet. A reader of one
    draft and a sealed source of another fail closed: a v0.82 follower on SSE and a v0.81
    origin, or the reverse, mismatch on every sealed namespace event. *Question:* is `502` the
    intended answer for a remote branch, and should §G.5.2 say so?
27. **Legacy E3 snapshots** (§7.1, §E.3.1; was v0.81 Open 17). Snapshots bound to a tombstone
    rather than its parent, or with the pre-v0.63 `kind` or `zip`, are never served (`410
    pruned`). No text of its own; "may refuse or discard" allows it. *Question:* confirm.
28. **Re-sealed rows keep their `ETag`** (§E.2.1, §E.2.2; was v0.81 Open 8). Unchanged: rows
    sealed again under `K_n`, or without compression, keep `ETag "{id}.{e}"`, so a private
    cache revalidates to `304` on bytes its reader no longer opens. *Question:* is a purge at
    upgrade the intended answer, or should the `ETag` or cache class change?
29. **Stored genesis entries without `parent`** (§7.1, §E.2.2; was v0.81 Open 28). Served as
    stored; readers take an absent `parent` as `""` on a genesis only. *Question:* do such
    sealings stay valid as served?
30. **Sealed resource events** (§7.3, §E.2.2; was v0.81 Open 73). v0.82 settles that they need
    not be stored and that every sealing counts. `purge` and `prune` events still bind no entry
    in `pl`. *Propose:* bind `target`.
31. **Encrypted archives** (§8.6, §G.5.1.1; was v0.81 Open 72). The per-resource archive key
    has no export path, and E3 archives are sealed twice (`internal/core/archiveseal.go`).
    *Question:* both.
32. **"Changes in any member" at the origin** (§B.11.9 `gs`). The changelog's list for the
    reference names only index cookies, but the sentence is in the origin's section, so the
    origin ends its `gs` cookies on any change to the key's entry or to a read role's whole
    definition, a role's `can` beyond `read` included. Key entries accept no `x-` members here
    (`422`), so "any member" of a key is the §C.4 fields; role entries are open, so an `x-`
    member added to a role ends cookies too. *Question:* the origin too; a role's whole
    definition; `x-` members of a role?
33. **Whose exchange cures a cookie** (§B.11.9 `gs`, §C.5.3). The text says a cookie is `403`
    "until the reader exchanges again", but the origin keeps one record per namespace and `gs`
    and the default cookie names no reader: two readers with the same key, groups and scope
    digest share a `gs`. In the reference another reader's exchange never revives a cookie the
    change ended. It tells cookies apart by expiry: once an exchange replaces a record under a
    changed key entry or role definition, a cookie that expires no later than the last one
    issued before is `403`. The cost: a reader who did exchange again is still `403` when her
    new cookie expires no later than that (the same second, or a grant that ends by then), for
    at most 15 minutes; her grant still reads. A cookie for `/ns/{ns}` read at a `gs` URL is
    held to the same test. A deployment minting shorter cookies would over-refuse for the
    difference. *Question:* may another reader's exchange revive a cookie; does the text allow
    the short refusal, or should the default cookie format carry an issue marker?
34. **Index cookies per key set** (§A.4 `gs`, §B.11.9 `gs`, §C.5.2). A marker, above all
    `reads:{ns}`, is shared by readers through different keys. The index records a cookie's
    keys once, per marker and `exp`: an exchange with other keys or entries gets an `exp`
    shifted down by whole seconds, so it vouches only for the cookie it mints, and a change to
    one key ends only the cookies minted through it. Where no second is left before the grant
    expires the exchange answers `503 behind` with `Retry-After`, a status §C.5.2 doesn't list;
    the rate token is drawn first. Two exchanges with the same keys, entries and `exp` produce
    one cookie. A document changed and then changed back gives a key its old entry digest, so a
    cookie from before holds again without an exchange (the grant verifies again too).
    *Question:* is that the intended reading, or must one key's change end every cookie of the
    shared marker? May a service shift `exp`, or should the cookie carry an exchange id?
35. **A cookie at an earlier `at`, behind the head, and in a branch** (§B.11.9 `gs`). After a
    new exchange the origin's record holds the new document's digest, so the new cookie is
    `403` at an `at` from before the key change, and paging in flight at the old `at` is
    stranded. At the index, where a `g:` marker is judged at a checkpoint behind the head and
    the head's entry for the key already differs, the exchange mints a cookie that is `403` at
    once. For a branch the reference takes the effective key's source entry, the base's current
    entry where the base has that `kid`. *Question:* `403` at the earlier `at`, or a `302` to
    the current one; a refusal or a wait at the exchange; which document's entry counts for a
    branch, and is a `kid` the branch copied and the base later removed "gone"?
36. **A cookie on a purged sealed namespace at the index** (§8.5, §A.4 `gs`). The document is
    `410`, so the index can't judge a cookie's key again. It passes cookies recorded with their
    key's entry and refuses the rest (`403`), so a cookie whose key changed between its
    exchange and the purge still gets the `410` and its head. *Question:* does such a cookie
    pass the read check?
37. **The caller's grant: which namespaces, and identity grants** (§B.11.4 The caller's grant,
    §B.11.6, scenario 116). "Allows `read` in no namespace it verifies in": the catalog service
    verifies the caller's grant in the catalog namespace alone, so a grant that reads only in a
    content namespace gets the `403`. It also refuses an identity-only base grant (`can: []`),
    which is what §B.11.6 describes ("group claims come in the base grant"); the reference's
    fixtures now issue `read` in the catalog namespace with a rule fixing `/resource` to a name
    no node has. And it counts a grant whose read roles all have a rule on `/now` as allowing
    `read` nowhere, though §C.2 item 2 alone is the verb check. *Question:* the catalog
    namespace alone, or any namespace the service follows; is refusing identity-only grants
    intended, and should the text say how such a grant reads without reading the catalog whole;
    item 2 alone or with item 5?
38. **The caller's-grant `403` and `?min`** (§B.11.4). The reference puts only request-shape
    `400`s (malformed syntax) before the `403`; a `?min` refusal that depends on what the
    reader can see, or a `?min` naming a namespace the service doesn't follow, comes after.
    *Question:* confirm.
39. **A mixed want** (§B.11.2, §B.11.4). For `want: ["read","append"]` where only `append`
    survives, the reference issues a grant with `can: ["append"]`. *Question:* the narrower
    grant, or `403`?
40. **`POST /merge-grants`** (§B.11.4). Not named in "The caller's grant"; the reference leaves
    it unchanged, with no `/now` check. *Question:* deliberate?
41. **A grant that reads nothing at listings** (§B.11.4, §B.11.5; was v0.81 Open 42). §B.11.4
    now treats a grant without `read` and one whose read roles all have a `/now` rule alike at
    `POST /grants` and `/read-grants`. At listings the first gets its subject set's listings
    and the second `403`. *Question:* intended?
42. **Purged catalogs and purged namespaces** (§B.11.9 Where, §C.4; was v0.81 Open 44). The
    changelog says "a purged namespace trusts no catalog"; §B.11.9 says only that its roles
    count for no catalog's folders, and scenario 124 calls a purged namespace covered, with a
    `gs`. The reference follows the text. "One a service never read counts as no catalog": the
    origin still serves a purged, unsealed namespace's document at its purge head to a grant
    holder, so an index started after the purge does read the trust, and the namespace is
    covered and dark. A `requireAt` naming a purged namespace makes the grant unverifiable at a
    service (`502`), not refused. *Question:* the text or the changelog; does "never read" mean
    never read while it was live; should a purged `requireAt` namespace be `403`?
43. **A purged namespace's filtered `/heads`** (§8.5, §B.11.9 Purged namespaces; was v0.81 Open
    54). "Once the URL's read check passes, its `gs` included": at a purged covered namespace
    an unrestricted reader's grant now gets `403` at `/ns/{ns}/g/{gs}/heads`, as at a live
    one's (v0.27.0 answered `410`). An uncovered purged namespace, which has no `gs`, still
    answers `410` there to any grant that passes the unfiltered read check. *Question:* confirm
    the `403`; does the clause apply to uncovered purged namespaces?
44. **A remote-branch catalog's trust list** (§B.11.9 Where). Such a catalog is dark, but
    coverage needs its `catalog.trust`. The reference reads the branch's own document as stored
    here, not its source's. *Question:* which?
45. **Public reads where not everything is public** (§B.11.5, §A.4; was v0.81 Open 23). v0.82
    settles that a grant is ignored at an all-public listing and a public query. Left: a public
    catalog whose listing isn't all public, for a grant whose `/now` rule applies in the catalog
    namespace, and the tree's `POST /edge-grants` on an all-public catalog, which isn't "a
    request for the listing": the reference answers `403` in both. A public listing with a
    `?min` naming a namespace of another catalog behind the same service still uses the grant
    to decide whether the reader sees that namespace. At `/_refs` of an index that also follows
    private namespaces an oversized grant is still `413` while an anonymous request gets the
    public hits. *Question:* each.
46. **"Never from an earlier read"** (§B.11.9 Where). The index reuses a successful `GET /` for
    the checker's TTL and never falls back to an earlier answer once a read fails. While `GET
    /` can't be read, `POST /edge-grants` goes on as with authentication on: it mints only for
    grants that verify, and a namespace whose coverage the root decides answers `503` or `502`
    for the whole exchange. *Question:* is the short reuse allowed; should the exchange refuse
    before looking at grants?
47. **The exchange within one grant at the index** (§C.5.2). A namespace refused `403` is left
    out while another's unreadable chain gives `502` or `503` for the whole grant; "`403`
    before `502`/`503`" is applied only across grants. *Question:* intended?
48. **A bounded scan before `204`** (§B.11.9 Long-poll). The MAY isn't taken. *Question:* how
    does a client tell "nothing more for now" from "scan cut short, poll again at once": only
    by `X-Cursor` being the current interval?
49. **A stopped namespace, subject sets and `at`** (§B.5 Behind). When a stopped namespace's
    roles stop counting, a subject set's listings shrink without its `gs` changing; the
    reference gives no new `gs` or profile at that `at`. After a resume with nothing written
    anywhere, `at` is the same as before the stop (same checkpoints), though it moved at the
    stop and at the resume. *Question:* is a new `gs` expected; is returning to the earlier
    `at` intended, given listings cached at immutable `at` URLs from before the stop?
50. **A stopped namespace at the catalog** (§B.5 Behind, §B.11.4). An item of a namespace the
    service stopped following gets a per-item `502 upstream` at `POST /read-grants` and `POST
    /grants`, since the service can't read the namespace document; never `"public": true`, a
    grant or keys. §B.5 alone ("its placements dangle and its roles count for no folder") would
    give the no-role `403`; the text names no status. `/read-grants` still reports the stopped
    namespace's last checkpoint in `checkpoint`. *Question:* which
    status; should a decision's `checkpoint` leave out a namespace the service no longer
    follows?
51. **"A listing computed before a purge"** (§B.5, §A.1). The tree service guards listings by
    the tags of what the purge removes. *Question:* only those, or every listing of the
    catalog, as §A.1 purges all of `idx:{ns}`?
52. **`requireAt` refusals** (§C.4; was v0.81 Open 46). v0.82 settles `403` at the origin,
    `502` or `503` at a service, and that no key-scope `403` names the namespace. The text
    names three refusals; the reference gives one text, `at rejected by requireAt`, also for an
    `at` that names another namespace and for a malformed one, so that a key holder can't test
    a guessed name. A cancelled verification is still a transient `503`. *Question:* should the
    text say every `requireAt` refusal is indistinguishable; confirm the cancelled case.
53. **`/keys` for a `/now` role beside a `/resource` role** (§2.1, §E.2.3). With roles of which
    one has a rule on `/now` and one fixes `/resource`, in a sealed (E2) namespace, `POST
    /keys` is `403`, not per-resource keys: only block and key-scope rules fix `/resource`.
    *Question:* confirm.
54. **The index's `gs` for a partial reader** (§A.4, §B.11.9, scenario 119). For the same
    partial reader and grant the origin redirects to `/ns/matches/g/{gs}` and the index to
    `/matches/g/{gs'}`, `gs'` the set id of the single marker `reads:{ns}:g:{gs}`. *Question:*
    is that derivation normative, and may a client assume the two are equal?
55. **The origin's error text in a `502`** (§B.11.4). No section says whether a service's `502
    upstream` may carry the origin's error text. The catalog service no longer relays it: it
    says what it couldn't read and logs the origin's answer. The tree service and the gateway
    weren't checked. *Question:* should the text forbid it?
56. **Legacy `"partial"` subject sets** (§B.11.5, §B.11.9 `gs`; was v0.81 Open 25). Refused
    `403`; no text of its own, and the earlier-drafts clause allows it. *Question:* `403`, or
    forget them (`401`)?
57. **Older sealed log ranges for a `requireAt` check** (§C.4, §E.2.3; was v0.81 Open 47).
    Unchanged: a checker's grant issued after a rotation gets no key for the older epoch's
    stored range, so every `requireAt` `at` from before the rotation is a lasting `502` for it.
    *Question:* expected?
58. **The `key:` subject of a grant without a `pub`** (§B.11.9 `gs`, §A.4; was v0.81 Open 48).
    Unchanged: a grant signed by an operator key, or by a `kid` the document doesn't list, has
    `""` for `pub` and gets scope cookies that are always `403`. *Question:* is `pub` the JWK's
    `x`, or are operator grants never partial readers of the index?
59. **The exchange's `410`** (§A.4 Coverage, §C.5.2; was v0.81 Open 50). Unchanged: "every
    namespace its grant names" includes unfollowed ones, which don't qualify; a block naming
    `"*"` never qualifies; a grant naming only purged namespaces that fails to verify in one is
    `403`; at `/_refs` it gets `410` only on an index following no public namespace.
    *Question:* confirm each.
60. **Item 2's roles and the digest** (§B.11.9 Visible, §A.4; was v0.81 Open 61). §A.4 now says
    the digest covers "the values at the `/principal` paths they test or compare". A read role
    testing `/principal/sub` never allows anything through filtered reads, yet its rules still
    enter the digest. *Question:* why; intended?
61. **A fixing grant and `/ns/{ns}/g/{gs}`** (§B.11.9 Edge grants; was v0.81 Open 63). Unchanged:
    a grant that fixes `/resource` gets its `/r/{ns}/{name}` prefixes and no `/g/` prefix.
    *Question:* may it get one too?
62. **Filtered `/heads` and `next`** (§B.11.9 /heads, §7.4; was v0.81 Open 65). Unchanged:
    `next` comes on every full page, unlike unfiltered `/heads`. *Question:* intended?
63. **Live reads when the reader's `gs` changes** (§B.11.9 Events, Long-poll; was v0.81 Open
    68). v0.82 says long-poll judges this at the current checkpoint. The reference also ends an
    event stream then. *Propose:* say so.
64. **`/resource` inside `any` or `not` beside a fixing rule** (§C.5.2, §2.1; was v0.81 Open
    69). Unchanged: read as not fixing, evaluated per fixed name, every name before the
    100-prefix cap. *Propose:* confirm.
65. **The index's range filters** (§A.4; was v0.81 Open 75). `gt`, `ge`, `lt` and `le` with a
    `sort` mark remain the reference's own. *Propose:* specify or drop them.
66. **`ancestors` and `where`: path elements and `nodes`** (§B.5, §E.2.6). §B.5's table names
    only `paths`, "an array of node names". Breadcrumbs need titles, which in a sealed catalog
    are sealed values of each node. The reference answers bare strings and a separate top-level
    `nodes` map keyed by node name, each entry `{ href, title }` or `{ href, sealed }` with no
    `name`; a reader derives `K_r` from the key and compares `pl.name` with it. `where`'s
    `paths` have the same shape, ending at the placement. A root's own path is `[name]`. The
    service also answers `node`, `of` and, for an unfiltered listing whose paths end below a
    root, `incomplete`, which the gateway ignores. The gateway takes a path that doesn't end at
    the node as a cut (`403`). *Question:* strings; may a service add members; if `nodes`
    stays, say an entry is named by its key; is a path not ending at the node malformed?
67. **`subtree` and `tooDeep`** (§B.5 Shared nodes in DAGs). `tooDeep: true` is set only for
    the depth-64 bound; a cut at the requested `depth` is reported per entry (`more`).
    *Question:* confirm.
68. **`/problems`' `tooDeep`** (§B.5). Not one of `subtree`, `ancestors`, `where`; the
    reference lists the nodes there, unchanged. *Question:* keep?
69. **Depth 64 and inherited access** (§B.5, §B.11.2, §B.11.5). §B.11.2 doesn't say the walk up
    is bounded; §B.5 says "Walks are bounded at depth 64". A folder whose effective-access walk
    stops at that bound collects no role from an ancestor 65 or more levels up. The reference
    treats it as hidden for such a reader: `ancestors` of its visible child lists neither that
    path nor `tooDeep`, since reporting a cut there would show a hidden node (§B.11.5).
    `tooDeep` appears where each folder of the chain carries its own `$access`. *Question:*
    does inherited access stop at depth 64, and is such a folder "hidden" (nothing appears) or
    "cut" (reported)?
70. **Tree details after a redirect** (§A.4, §B.5; was v0.81 Open 58). v0.82 settles `403`
    before `502`/`503` at the exchange. Left: a redirect keeps the legacy order cursor
    (`after={order}&name=…`) and drops position cursors. *Question:* confirm.
71. **The catalog's kept purge record** (§B.11.4, §B.9; was v0.81 Open 71). v0.82 settles the
    `404` for an implicit placement named as `node`. Left: the service keeps its purge record
    for a namespace the catalog no longer trusts (`internal/tree/tree.go` `forgetUntrusted`).
    *Question:* intended?
72. **Undefined members kept unchanged** (§7.4 Versions; CONFORMANCE HTTP-35, LIM-5; was v0.81
    Open 35). Unchanged: the core lets a config write keep an undefined, non-`x-` member
    unchanged, and a document stored over the rules bound take other writes. §G.4.1's "unlike
    namespace documents (§7.4, Versions)" hints that documents tolerate such members.
    *Question:* must such a write be `422`, or may a deployment keep the exemption?
73. **"Nothing promised" against invariant Valid** (§4 Valid, §6.1; was v0.81 Open 62).
    Unchanged: §4 Valid still promises the same answer on re-validation, while the reference
    compiles every stored schema under today's rules and a write pinning one that no longer
    compiles is `422 invalid`. *Propose:* put the exception in the text.
74. **Grant lines: `stored` as an array, undecodable or respelled** (§G.4.1). The pre-v0.73
    array form of `stored` is still read, its first element checked. A `stored` block that
    doesn't decode is rejected, and one whose grant block is the same root in a non-canonical
    spelling is rejected by the parser before the comparison. *Question:* is the array a
    rejected form now; is an undecodable block rejected under "isn't `canonical(root)`"?
75. **`key.kid` against `root.kid`** (§G.4.1). A reader doesn't reject a line whose `key.kid`
    differs from `root.kid`, or whose signature fails under `key`: `key` stays attested, not
    proven. *Question:* must a reader reject?
76. **Exporting an e2e branch** (§G.5.1). "Names the foreign parent in `requires`, or refuses
    that document" doesn't say how an exporter finds the foreign parent: tombstones and a
    restore's `[]` name no namespace, so the sealed-op test alone can't place them. The
    reference takes the base's head at `base.at`, which must be in the verified chain, and for
    a remote base refuses unless the document's genesis is the branch's own. It writes
    `requires` by default, and exports the branch's keyring whole, the base's keyring lines
    under the branch's name. *Question:* `requires` by default, or only on request and
    otherwise a refusal; is the keyring exempt?
77. **Checking a pinned `external`** (§G.4.4, §G.5.1, TOOLS §G.4.2). "Must exist in the target"
    can't be checked by reading the revision in an e2e target, which serves no document by
    revision, nor for a tombstone, which answers `410` by revision at every level. The
    reference accepts a pinned revision that is in the target's chain, for a tombstone at any
    target level; a purged resource is refused. *Question:* confirm, or should an exporter not
    pin a read-through tombstone at all?
78. **A `sealed` op in a namespace not labelled `e2e`** (§G.5.1 Importing, §8.6). An archive or
    bundle without `access` reads as private. The reference refuses such a bundle at step 1,
    override or not, so an e2e prune archive from before v0.82, which has no `access`, can be
    restored and never imported. *Question:* should that be a stated step-1 refusal?
79. **The answer for a failed read** (TOOLS §H.4; was v0.81 Open 60). v0.82 settles `503` with
    `Retry-After` after a `429` or `503`, else `502`, for every read the save decides by. A
    gateway-side timeout with no upstream answer isn't listed: the reference keeps `503` with
    `Retry-After`. A failed write (the core's `503` on the append itself) has no row either:
    `502`, as before. The spec changelog mentions neither the new split nor "theirs and the
    user's own entries included", though three reference tests had to be inverted. *Question:*
    does "else `502`" include a gateway-side timeout?
80. **What a save decides by** (TOOLS §H.4 "anything the save decides by"). The reference
    applies the split to every read of a `PUT`: its open, each commit's reads, the head of a
    new file's placement node, reads made after the write (cleanup, re-reads), and `GET
    /ns/{ns}/principal` and the namespace document of every namespace the request asked about,
    sibling items' namespaces read while resolving the folder included, so a save can fail
    because an unrelated namespace is briefly unavailable. The tree-owner check of a flat
    namespace still falls back to settings learned with another grant. `MOVE`, `COPY`, the
    dry-run batch and reads of the tree service keep the general answers (a core `503` gives
    `502`, a `408` gives `503`), and for a request that isn't a save a core `408` on
    `/principal` is kept like a refusal, so a `DELETE` answers `403` meanwhile. *Question:*
    which reads count; are `MOVE` and `COPY` saves; should a `408` be transient for every
    request?
81. **Folder deletes by readers who list through the tree service** (TOOLS §H.5, §H.7; was
    v0.81 Open 7). Unchanged: such a reader can't read the node documents a folder's emptiness
    is taken from, so it can't delete a folder or move one to another tree (`403`).
    *Question:* say so, or let a tree service's `children` listing stand for emptiness?
82. **Deep folder chains and copies** (TOOLS §H.5 Copy, scenario 130, §B.5). "Judged by the
    ancestry the user sees" lets a filtered reader start a copy of F into a folder that is
    below F only through a folder the reader can't see (69). With a chain of 65 or more
    inheriting folders the copy ends part-way (`403` at a nested level, 64 resources written),
    which §H.5's part-way rule allows and scenario 130's "nothing written" reads against. A
    copy of any chain of 63 or more nested folders, to any destination, fails part-way for a
    grant that can't read node documents (`403` or `409` after 64 writes). A node more than 64
    levels below a root isn't reachable by path through the gateway, so a copy into it is
    `409`, and scenario 130's `tooDeep` case arises only for a shared node with a short and a
    long path. *Question:* which wins; must a gateway judge depth before its first write?
83. **A save tagged with a tombstone** (TOOLS §H.4, §7.1). The tombstone `410`'s `{ tombstone,
    last }` has no consumer in the gateway, which judges a deleted file by its head. A `PUT`
    tagged with the tombstone's own id is `409`, as for a tag naming the last live revision.
    *Question:* confirm.
84. **Addendum I §I.15–§I.21.** §I.17 still seals I.9's lines, which §G.4.1 rejects once
    decrypted, so no vector exercises a sealed bundle that imports, and padded sealed-bundle
    lines remain missing (§I.22). §I.17 refers to I.12's recipient and envelope without
    restating them, and its rejection table names rules in a short form that doesn't match
    §G.5.1.1's wording. §I.16 gives the renderings only by length and SHA-256, where the
    candidate printed the bytes, so a failing implementation can't see what differs.
    *Propose:* seal a complete bundle; cite the clause per row; print at least the last
    rendering.
85. **Candidates C.2 and C.3** (VECTORS-PROPOSED, §E.2.6, TOOLS §G.4.1; C.1 is note 1). All
    three reproduce byte for byte. C.2 seals a whole response "to a reader who reads it whole,
    at §I.8's `gs`", but §I.8's `gs` is the set of `group:match-desk` and `user:anna`, and
    §E.2.6 seals whole only where every reader the URL admits reads the namespace whole; a
    conforming index would seal that URL per entry. C.2 gives no padded JWE in full, and doesn't
    say that a padded plaintext is canonical JSON followed by spaces to the §E.2.2 bucket. C.3
    row 1's id (`1d7hzis4…`) appears nowhere in SPEC.md. *Propose:* call C.2's premise
    illustrative or use the `gs` of `reads:demo`; add the padding sentence; have §I.21 state the
    id.

## Settled in v0.82

v0.82 answers the 77 notes open from v0.81. By the reference's reading of the changed text it
settles 47 whole, 16 in part (9, 17, 19, 23, 25, 42, 44, 46, 54, 57, 58, 60, 61, 68, 71, 73) and
leaves 14 (7, 8, 15, 28, 35, 47, 48, 50, 62, 63, 65, 69, 72, 75). What remains is rewritten
above, marked "was v0.81 Open n". "n" below means v0.81 Open n. The spec's changelog counts
differently: it says all 77 are answered, 23 of them because they already matched the text or
are the implementation's business; that count wasn't checked. "Left" above means no changed
line was found in the SPEC, SERVICES, TOOLS and CONFORMANCE diffs, not that the whole text was
searched. Where the text went against the reference, the reference changed, in the area named:
- **The question back: what is a "shadow"** (24). A shadow is internal to the reference, not a
  thing of the spec. For a remote branch `B` of a source on another deployment, the origin
  keeps a hidden local namespace named `~B` that mirrors the base's chain as B verified it. The
  remote branch is then, inside the engine, a local branch of its shadow, so read-through,
  foreign parents, history and logs work as for a local branch. A source that is itself a
  branch gets one shadow per level, `~B~1`, `~B~2`, …, each a local branch of the next. A
  shadow is hidden: no URL serves it, keys and revocations are the branch's own, and it follows
  the branch's encryption level. A name starting with `~` isn't a namespace name, so no
  `catalogs` or `catalog.trust` entry can name one. v0.81 Open 24's "or a shadow" described a
  lookup that could meet such a row; "a branch, local or remote" covers every case a document
  can express, and the text needs nothing more.
- **Sealed forms** (3, 13, 14, 38, 43, 55, 56; part of 57 and 73): a namespace event has its
  own `pl`, `{ ns, event: id }`, with no `prev` bound, and events need not be stored (3, 73).
  The view string is the request target in origin form, byte for byte (13, as the reference
  had it; candidate C.2). §3.6 says no name is empty, which keeps `K_r` apart from `K_n` (14).
  A nested value's `ns` and `name` are in the clear in its protected header, and a reader
  compares them where the entry names the resource (38). A keyring's `$nonce` is new on every
  write (43, as the reference had it). A service seals nothing from a revision until it has
  judged its epoch, and serves the entry by name only (55, 56). Changed: the core, the client
  and the vectors for the event's `pl`; the playground compares nested values; the tree
  service lists unjudged nodes by name only, reads kid-less heads again and has stored `born`
  epochs read in again (migration `006_v082_rejudge`); the index seals nothing unjudged;
  derived views are canonical JSON and stored ones are dropped (`003_v082_drop_sealed_views`);
  previews seal under the branch's keys (57; what remains is v0.82 Open 21).
- **End-to-end reads** (1, 2, 16, 18, 20, 39): a tombstone's `/rev/{T}` is `410` with `{
  tombstone, last }`, so a pruner and a mirroring remote branch learn its parent there (20, 1).
  §G.5.2 says B mirrors A's stored snapshot (1). A stored snapshot is served until a purge or a
  later prune that moves the horizon, whatever is restored (16), and a branch reads a base's
  stored snapshot whatever it has written since (18, as the reference had it). "Reading this
  spec" lets a deployment refuse or discard earlier drafts' data and forbids serving it under
  less protection (2: the start gate and the purge conform; how content is carried over isn't
  said). A client learns the level from its configuration, the namespace document or `/keys`
  and keeps the highest it has learnt (39). Changed: the core's tombstone `410` and snapshot
  lifetime; `PruneE2E`; a remote branch's creation at a tombstone head; the client's and the
  playground's level tables, with `WithExpectedLevel` and `-expect-level`.
- **Message bound** (10, 11, 12; part of 9): counts may run over, never under, and reserving is
  the origin's choice (10). At E3 the origin need not count; each writer counts what it knows
  (11). The bound covers every key sealed under with random IVs, a bundle's `K_b` included,
  storage-only keys being the implementation's (12). At E2 the origin MAY rotate by itself, in
  an entry with no `grant` or `via` (9; frozen namespaces are v0.82 Open 8). Changed: sealed
  bundles refuse line 2³² − 1; the playground counts its E3 sealings.
- **Rules on `/now` and the catalog** (21, 22, 40, 41; part of 23 and 42): a rule on the whole
  envelope, or on a pointer above `/now`, refers to it (21). The refusal is the read check's
  ordinary answer in its usual place, `/keys` included (22). Where reads are public the grant
  is ignored, at services too (23; the mixed cases are v0.82 Open 45). The catalog refuses a
  grant with such a block or key-scope rule every request, after `400` and `401` (40), a read
  `want` leaves out roles that don't count for `read` (41), and a grant that allows no `read`
  is refused read grants and read wants (42; listings are v0.82 Open 41). 21 and 22 as the
  reference had them. Changed: the catalog service's order of answers, its read wants and the
  caller's-grant `403`, which now also meets identity grants with `can: []` (v0.82 Open 37).
- **Coverage, cookies and services** (24, 26, 27, 45, 49, 51, 52, 53, 64, 66, 67, 70, 74, 76,
  77; part of 44, 46, 54, 58, 61, 68, 71): a trusted catalog that is a branch, local or
  remote, makes nothing visible (24). A stopped namespace leaves the combined checkpoint, `at`
  moves, its placements dangle and its roles count for no folder (26). The index's `404` for
  keys it lacks may be decided during the read check (27). A cookie ends when its key or a
  role it came from is gone or changed in any member, `reads:{ns}` included (45). §A.4 names
  where the index gives no marker (49). A `503 behind` may name `ns` only to an unrestricted
  reader (51). §B.5 binds tree listings to §A.1's purge rule, and `503 behind` after a bounded
  number of tries is allowed (52, 77). The authentication mode comes from `GET /`, never from
  an earlier read (53). A malformed `{gs}` or `{at}` is `400 bad_input` (64), a client may
  resume a range from `since` at a later `at` (66), a bounded scan before `204` is a MAY (67,
  not taken), another `Authorization` scheme is a malformed grant (70), §A.1 gives the reason a
  resource purge purges `idx:{ns}` (74), and `scope:{digest}` is the marker digest (76). A
  purged catalog's `catalog.trust` is the last one stored or read (44), an origin answers `403`
  naming nothing for a `requireAt` whose namespace doesn't exist and a service `502` or `503`
  (46), and a purged covered namespace's unfiltered `/heads` is `410` directly (54). Changed:
  remote-branch catalogs are dark at the origin and the index; origin and index cookies end on
  any change to the key's entry (core migrations `017_filtered_gs_entry` and
  `018_filtered_gs_entry_after`, index `011_edge_gs_keys_entry`); the `requireAt` `403` names
  nothing; the purged `/heads` answers; the tree service never serves a per-reader listing
  computed before a purge; stopped namespaces' roles count for no folder at the catalog. The
  rest as the reference had it.
- **Tree answers and the gateway** (5, 6; part of 60): a gateway may copy out of an `$access`
  folder, or refuse as its own policy (5; the reference keeps copying), and refuses a copy
  into itself; `ancestors` answers `paths`, `tooDeep` and `truncated` (6). A failed read of
  anything a save decides by fails it, `503` with `Retry-After` after a `429` or `503`, else
  `502` (60). Changed: the tree service's `ancestors`, `where` and `subtree` answers and their
  readers in the gateway and the playground; the gateway's saves.
- **Bundles and tools** (4, 29, 32, 33, 34, 36, 37, 59): release collaborators get unrestricted
  branch `read` only if they read the base unrestricted (4). Prune archives carry `access`
  (29). A reader rejects a grant line whose id or stored block disagrees with its `root` (32)
  and a member §G.4.1 doesn't define (33, as the reference had it). Read-only paths for earlier
  drafts' data that accept nothing this draft refuses conform (34; the array form of `stored`
  is v0.82 Open 74). §F.3 says an undeclarable blob gets no item and is offered again (36), an
  exporter writes no read-through lines for an `e2e` branch (37), and a give-up is recorded
  nowhere (59). Changed: the bundle reader and writer, the exporter, the importer's lookup of a
  pinned `external`, and `access` in archives.
- **Vectors** (30, 31): the candidates P.1–P.7 are §I.15–§I.21, plan₂ with `config` included
  (30), and the preface calls such inputs illustrative (31). New candidates C.1–C.3 are in
  VECTORS-PROPOSED.md; the reference confirms all three (v0.82 Open 1, 85).

## Settled in v0.81

v0.78 to v0.81 answer the 44 notes open from v0.77: they settle 10 whole (2, 3, 11, 15, 16, 22,
24, 26, 27, 28), 8 in part (1, 4, 8, 9, 18, 21, 23, 38) and leave 26. What remains is rewritten
above, marked "was v0.77 Open n". "n" below means v0.77 Open n. They also close questions the
spec itself listed as open: §13's (what `/rev/{id}` serves at E3), §E.5's two (the keyring, and
`/keys` with `/now`) and §B.12's (leaving an embargo). Where the text went against the reference,
the reference changed, in the area named:
- **Branches are not covered** (2, 3, 11; part of 1 and 8): v0.78's filtered reads cover a
  namespace that trusts a catalog, and that catalog, and no branch. So a branch whose root stops
  trusting a dark catalog (2), which time "as of the branch's `at`" means for the catalog's side
  (3), "earliest" for a base `/_refs` reads at different `at`s (11, the clause gone with branch
  coverage), a purged branch root (1) and a branch's own marker (8) no longer arise. Changed at
  the origin, the index and the tree service: a branch's filtered URLs answer `403` (`401`
  without credentials), a partial reader of a branch gets `403` with no redirect and `403` at
  `/branches`, `POST /edge-grants` gives no branch prefix, and a trusted catalog that is a local
  branch makes nothing visible and is in no checkpoint.
- **Raises to e2e are cut** (15, 16, 24): v0.78 makes a namespace end-to-end from its creation or
  never, so pre-raise sealings on a remote branch at creation (15) and afterwards (16), and
  check-fixed epochs for pre-raise content (24), no longer arise. Changed: a config write raising
  to `e2e` is `422`; the pre-raise read paths and remote pending sealings are deleted (core
  migration `016_v081_encryption` drops `remote_pending_sealings` and `e2e_raises`); a database
  holding a raised namespace is refused at start unless `-purge-raised-e2e` purges it (v0.81
  Open 2); and a remote branch of a raised source is `502 upstream` at creation.
- **Encryption** (26, 27; part of 18): §E.3.1 now says a snapshot's `kid` names this namespace,
  its epoch that of the newest own op, else of an earlier own snapshot, else the epoch in force.
  With the pre-raise cases gone no value names a base's epoch, and `PruneE2E` failing on an own
  op whose `kid` names another namespace matches the server's `422` (18, followed; what remains
  is v0.81 Open 56). Authentication disabled
  gets the current epoch only, as intended (§E.2.3 From, scenario 56; 26). The §F.3 kept bullet
  drops the undeclarable-blob clause: merge's pre-raise special case is deleted, and its check is
  kept as a defensive one (27; what remains is v0.81 Open 36).
- **Access** (part of 4, 9 and 38): a `gs` cookie ends when its rules differ, or when the key its
  `key:` string names, or a key or role they came from, is gone or no longer allows `read`, so a
  `pub` rotation ends it, and the branches' whole-entry comparison is gone (4); only the all-purged
  `410` carries `ns` and `head` (Grant scope 68; 9); SVC-34 gives `404` only for a name that never
  existed (38). All three as the reference had them. Changed with v0.78 besides: a `gs` holds all
  the caller's groups (plus its `sub` under the existing rule) and never `"partial"`, at the
  origin, the index and the tree service, and a stored `"partial"` set is `403` (v0.81 Open 25);
  a rule on `/now` never passes for a read, so its per-endpoint cases are gone (v0.81 Open 21–23).
- **Merges** (22, 28; part of 21 and 23): §F.6 excepts only resources purged in the branch and the
  keyring at E3, so a resource purged only in the successor is no exception (21, as the reference
  had it); a last `-` under an array widens, as merge and undo do (22); a batch of config plus
  items only for purged resources is settled as the reference counts it (`ownBatch`,
  `isDocEntry`; 28); a failed read fails a save over someone else's delete `503` or `502`, never
  `409` (23, as the gateway does).
- **The spec's own questions:** §13's is closed by "End-to-end reads": the server never folds,
  and `/rev/{id}` serves a prune's stored snapshot or answers `404 not_offered` with `horizon`
  and `last` (changed: the core, remote branches, the client and the playground; `X-E2E` is
  gone). §E.5's keyring question is closed by v0.78 (an e2e namespace's keyring is its key ring
  from creation; the importer already refused plaintext into an e2e target), and its `/keys` and
  `/now` question by v0.78's `/now` rule (changed: the read check, `/keys` included). §B.12's is
  closed by v0.81: a copy isn't refused where it widens access (changed: the WebDAV gateway copies
  `$access` folders; v0.81 Open 5).

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
