# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.87**, with `docs/SERVICES.md` and
`docs/TOOLS.md`, split from it in v0.80. This file collects what the reference does that the text
doesn't yet describe. Open notes come in one list, from implementing v0.87; cite them as "v0.87
Open n". v0.87 answered the v0.86 list ("v0.86 Open n", 68 notes): what it settled is under
"Settled in v0.87", and what it left open is rewritten in the new list, marked "was v0.86 Open
n". v0.86 answered the v0.85 list (Settled in v0.86) and the four questions of the branch-limit
report (docs/capacity/branches/report.md), v0.85 the v0.82 list (Settled in v0.85), v0.82 the
v0.81 list (Settled in v0.82), the v0.77 list was answered in v0.78 to v0.81 (Settled in v0.81),
and earlier lists before it.

## Open from v0.87

From implementing v0.87 (branch `spec-v087`). Numbered afresh; cite these as "v0.87 Open n". Each
entry gives the section, what the reference does now (the conservative reading where it had a
choice) and the question. Notes from v0.86 that v0.87 leaves open are carried in place, by
subject, marked "was v0.86 Open n" and cut to what remains, with their references moved to
v0.87's sections; those whose feature v0.87 removed (catalogs and the tree service, `requireAt`,
remote branches, the `export` verb, `gs`, combined checkpoints) are settled as moot. The order
is: levels, the foreign parent and archives (1–9), access, filtered reads, cookies and services
(10–23), documents, bundles, federation, releases and the gateway (24–35), vectors (36), index
(37), rates and validation (38–49), listings, refusals and the branch limits (50–55) and
long-poll intervals (56–59). Where the reference does less than the text says, that is under
Reference gaps, after the list. Sections are SPEC.md's unless TOOLS.md is named; Addendum A and
§E.2.6 are in SERVICES.md. Scenario numbers repeat across CONFORMANCE's groups, and v0.87
renumbered them (Tree-derived access is gone): "Encryption scenario n" is one under "Encryption
levels and epochs", "Grant scope scenario n" one under "Grant scope", "Filtered reads scenario n"
one under "Filtered reads (§7.9)".

59 are open: 9 from this version's work and 50 carried.

1. **How a client learns a branch's chain** (§7.1 End-to-end namespaces, HTTP-68, Encryption
   scenario 71; was v0.86 Open 1). "It holds for a branch at least the level it holds for any
   base in the branch's `base` chain" presumes the client knows that `Z` is a branch of `N`. The
   only source is `Z`'s own namespace document. A client of the reference that holds `sealed` or
   `e2e` for some namespace, learnt from `/keys` included, reads a namespace's current document,
   and those of the bases it names, once before it trusts a first plaintext `200` from that
   namespace; one that holds only `at-rest`, or nothing, asks nothing. A document its grant may
   not read (`403`, `404`) teaches nothing, the plaintext is then accepted, and the refusal is
   remembered for that grant alone. A read that fails for now fails the plaintext read too.
   *Question:* is that fetch what scenario 71 intends; and what does a client do where `Z`'s
   document is unreadable to it, or sealed and it has no key to see `base`?
2. **What the branch floor defends against** (§7.1, Encryption scenario 71; was v0.86 Open 2).
   The floor rests on what the server itself serves as `Z`'s namespace document. A server can
   keep the check from happening without a `403` or `404`: by a document with no `base` or a
   wrong one, by an error on `/ns/Z`, or by refusing an intermediate base's document. So the
   floor protects a first contact with an honest or misconfigured server or cache, not with a
   hostile one, against which only a level configured for the branch itself holds
   (`--expect-level Z=…`). *Question:* should the text say so, or give clients an authenticated
   way to learn a branch's chain?
3. **A `sealed` holder and a plaintext `200`** (§7.1, Encryption scenario 71; was v0.86 Open 3).
   §7.1 says only that "a reader that expects end-to-end refuses any other resource's `200` that
   isn't `application/jose`"; scenario 71 has a holder of `sealed` refuse one in a branch. The
   reference now refuses at `sealed` too, in the namespace itself as in a branch, a resource
   named `keyring` included (the keyring exception stays end-to-end's). *Question:* which text
   governs?
4. **A namespace document read by id** (§7.1, HTTP-68, Encryption scenarios 61, 71; was v0.86
   Open 4). Scenario 61 has `N`'s document, read by id at an `ns_id` before its raise, teach
   nothing and not be refused, and §7.1 names "the current namespace document (not one read by
   id)". The reference so accepts a plaintext namespace document read by id where `sealed` is
   held, at any `ns_id`, and takes its `base` link; scenario 71's "a `Z` document claiming
   `at-rest`" it reads as the current one. *Question:* is a by-id document from after the raise
   meant to be refused, and how would a client tell before from after?
5. **A refused document's `base`** (§7.1 "learns nothing from either"; was v0.86 Open 6). The
   reference keeps the `base` link of a document it refuses for its level, since a link can only
   raise what is held. *Question:* allowed?
6. **The foreign parent in a chain of branches** (§E.2.2, ENC-14, Encryption scenario 67; was
   v0.86 Open 7). "The resource's foreign parent" is singular. With `Z` a branch of `N` and `N`
   of `M`, the reference places a fork for each level and fails closed for each: where `N`'s fork
   from `M` can't be placed, `M`'s `ns` is refused while `N`'s is still accepted up to `Z`'s
   fork. *Question:* intended, or is only the serving branch's parent meant?
7. **A reader who can't read the base's namespace document** (Encryption scenario 67, §E.3.1; was
   v0.86 Open 9). The reference walks the bases' namespace documents for the chain at E3, so a
   reader whose grant covers the branch alone fails with the base's `403` before any fork is
   checked. Scenario 67's "flagged and folded as `[]`" is reached only by a reader who reads the
   base's document and not its `/heads`. *Question:* should the branch's own document suffice for
   its direct base?
8. **A tool configured with a level it doesn't know** (§7.1, Encryption scenario 66; was v0.86
   Open 10). The Go client and the playground hold it as `e2e`. `patchlog --expect-level
   ns=level` refuses the value when it starts, which fails closed too. *Question:* may a tool
   refuse it, or must it count as `e2e`?
9. **Encrypted archives** (§8.6, §G.5.1.1; was v0.86 Open 11, v0.85 Open 14). The per-resource
   archive key still has no export path. E3 archives are sealed twice
   (`internal/core/archiveseal.go`), which the unchanged bullet covers, since it excepts no
   level. *Question:* how does an archive's key leave the deployment; confirm the double sealing.
10. **Which writes step 2.2 judges, and by what head** (§6.2 step 2.2, §C.2 item 5, §7.6,
    Filtered reads scenarios 32, 57). Step 2.2 now refuses, `403` before the precondition, a
    write to a resource with a head by a grant that may `read` but whose read rules don't allow
    reading that head. The reference judges it for a grant whose reads can pass. One whose block
    or key-scope rules refer to `/now`, which fails every read (§C.2 item 5), skips it, as a
    grant without `read` does (scenario 57's last sentence, §6.4.1 What rule failures reveal). A
    purge, a prune and a blob upload aren't judged at 2.2 either. In a branch "the head" is the
    one the write sees through its base: for a resource it reads through, the base's head as of
    `at` (§7.6), a tombstone included. *Question:* are those the readings meant of "may `read`"
    and "a write to a resource with a head"; should §6.2 say who is skipped, and which head a
    branch's writer is judged on?
11. **A block rule on `/doc` and branching** (§2.1 Unrestricted read, §C.2 item 2, §7.6, §F.8,
    Grant scope scenario 4). A rule on `/doc` in a grant's blocks or key scope (or in every role
    that lists `read`) removes unrestricted `read` (§2.1), and branching needs it (§C.2 item 2,
    §7.6), so a grant limited by content can't create branches. §7.6 and §F.8 already have it so
    for editors limited to some documents; v0.87 adds `/doc` to what removes it. The reference
    follows it, so a reader limited by `/doc/folder` (TOOLS §H.7 Folders as access) can't take a
    working copy of the tree it reads. A service that may branch makes the branch and issues
    grants on it (§F.8), and filtered reads don't cover branches (§7.9 Where), so such a grant
    lists only through a preview index. *Question:* intended; or may a grant limited by `/doc`
    branch what its rules let it read, and with which rules in the branch?
12. **A grant whose fixed names are empty** (§2.1 Fixes `/resource`, §7.9 Partial reader, §C.4).
    Two tests of `/resource` against disjoint names (`value` `a`, and `value` `b`) leave a set of
    no names, and §2.1 says such a grant doesn't fix `/resource`. The reference then treats its
    rules as referring to `/resource` without fixing it: the grant lacks unrestricted `read`, so
    it is a partial reader (§7.9) with a `view` of its own, from which nothing is visible, and a
    key with `readScope: "resource"` refuses it (§C.4). *Question:* is a partial reader with
    nothing to see the intended result, or should a grant that can read nothing be refused?
13. **`doc` null in purged and sealed answers** (§6.4.1 `read`, §7.9 Purged namespaces, §8.3,
    §8.5, Filtered reads scenario 17). `doc` is `null` for a purge entry, for a revision whose
    document is purged or pruned and not kept, and in a sealed or end-to-end namespace, and a
    rule that refers to `/doc` then fails as a whole. So a reader limited by `/doc` who asks for
    a purged resource's URL gets `404`, as for any read-rule failure, where §8.3 gives `410`
    "once the caller passes the read check for that URL"; likewise in a sealed namespace, where
    `doc` is always `null`. The reference follows that. At a purged namespace's view URLs it
    answers `410` directly, without the `302` to the current `at` (§7.9 Purged namespaces,
    scenario 17), for such a reader as for any other. *Question:* should a purged resource be
    `410` to a reader whose `/doc` rules fail only because `doc` is `null`; and at a purged
    namespace's URLs, where `doc` is `null` too, is "the URL's read check, its `view` included"
    to pass on the grant's verification and its `view` alone?
14. **An unrestricted reader at view URLs** (§7.9 Partial reader, §2.1 Edge prefix, Filtered
    reads scenario 8). Unrestricted readers keep the unfiltered URLs, and a `/ns/{ns}` cookie at
    a filtered URL "counts as that view's cookie". The reference gives such a cookie the whole
    namespace there: it reads every revision, whatever the `view` in the URL, and its pages at
    view URLs are `private, no-store` and never shared with that view's readers, whose cached
    copies are filtered. *Question:* is that what "counts as that view's cookie" means, or should
    its reads at a view URL be filtered by that view's rules?
15. **A pruned revision no view has judged** (§7.9 Cost, §8.6, Filtered reads scenarios 27, 59).
    "a revision first judged without a stored document is visible to no `/doc` rule" (the
    Filtered reads invariant), and an answer a view has given is kept even once pruning drops the
    document (§7.9 Cost). For a pruned revision with no kept answer the reference judges it with
    `doc` `null`, so it is hidden, and doesn't store that answer; one the view judged before the
    prune answers as before, `410` (`pruned`, §7.1). So a reader whose rules test `/doc` gets
    `404`, as for any read-rule failure (§C.2 item 5), for the first and `410` for the second.
    *Question:* must the "not visible" be kept too, as "keeps the answer" reads, though a restore
    from an archive (§8.6) brings the document back and would then be judged by it; and is the
    difference in status meant?
16. **The `503` for an exchange with no `exp` left** (§A.4 Private namespaces, §12.1 `behind`,
    Filtered reads scenario 48; was v0.86 Open 14). §A.4 gives it where every `exp` the minter
    may give "is that of a cookie for the same prefix that is `403`", and scenario 48 now says
    the same; §12.1 says only that no `exp` is left. The reference skips a second held by any
    cookie it must tell this one apart from, ended or not, and answers `503` (`behind`) when none
    is left, at the origin's `view` prefixes as at the index. The exchange has drawn its
    `exchangeRate` token by then. *Propose:* "that of another cookie for the same prefix that it
    must tell it apart from". *Question:* does this `503` keep its token?
17. **Seconds taken off at the origin** (§C.5.2, §7.9 `view`; was v0.86 Open 15). The origin
    keeps a record for each expiry second of a `view` cookie, and takes whole seconds off only
    for those. Several grants of one exchange that give one `view` give one cookie, with the
    latest `exp` among them (§C.5.2). A reader whose grant has under a second left gets `503`
    (`behind`), not a cookie that expires at once. Where an exchange carries several different
    `view`s, a `503` for a later one leaves the earlier ones' seconds recorded with no cookie
    minted. *Question:* is either a problem?
18. **A document that moves during the exchange** (§A.4 Private namespaces, Filtered reads
    scenario 46; was v0.86 Open 16, v0.85 Open 21). §A.4 answers `503` (`behind`) for an exchange
    whose cookie would be `403` at once, as a key or role its `view` draws on has changed since
    the checkpoint it is judged at (scenario 46). Left: the reference answers `503` also when the
    namespace document moved between its read and the grant's verification without changing
    either. *Question:* is any move meant?
19. **How far back a cookie is judged** (§7.9 `view`, Filtered reads scenarios 13, 14; was v0.86
    Open 18). To keep a changed cookie ended the origin judges every namespace document after the
    one its exchange recorded, up to the URL's checkpoint, at most 64 of them. At a checkpoint
    more than 64 documents past the record's the cookie is `403`; a cookie lives 15 minutes at
    most. *Question:* does the text allow such a bound?
20. **Changes an index can't judge** (§A.4 Private namespaces, §A.1, Filtered reads scenario 14;
    was v0.86 Open 19). The index judges, for a cookie, the config documents after its exchange.
    It records the exchange's place in a namespace's log only where the origin confirms that the
    index's checkpoint precedes the head the grant was verified at, and otherwise judges the
    cookie by every document it applies, so a cookie minted while it is behind may then be ended
    once by the backlog. A place it recorded and never comes to apply would leave the cookie
    judged by the head's document alone; no path to that is known. A base it doesn't follow is
    never judged for a branch's cookies. Where it can't read a namespace's document during a
    batch, and where it starts a namespace from a snapshot, it ends all of that namespace's
    cookies, which the text doesn't say; a namespace it first meets already purged so answers its
    cookies `403`, where scenario 47 gives `410` only to one that still passes. *Question:*
    should the text say how a service tells the entries before an exchange from those after; is
    ending them right, and what of the base?
21. **An operator grant at a gateway** (§C.4 Operator grants, TOOLS §H.7; was v0.86 Open 20).
    §C.4 says a request under an operator grant "at the origin or a service (§C.6)" is `401`.
    TOOLS §H.7 says operator grants "are never users of a gateway (`403`)". The reference's
    gateway answers `403`; its index and stream proxy `401`. *Question:* which is a gateway's?
22. **An operator grant where a public answer exists** (§C.4, Grant scope scenario 75; was v0.86
    Open 21). The scenario has `GET /_refs` under an operator grant `401`, and a public
    namespace's query ignoring it. Where the index follows a public namespace the reference
    ignores the grant at `/_refs` too, as §C.4 says of requests that ignore any grant, and gives
    the public answer; it is `401` only where nothing public is followed. *Question:* should the
    scenario say so?
23. **Public reads where not everything is public** (§A.4; was v0.86 Open 25, v0.85 Open 29).
    Left: at `/_refs` of an index that also follows private namespaces an oversized grant is
    still `413` while an anonymous request gets the public hits. *Question:* is the `413` right
    where the answer would otherwise be the public hits?
24. **An undefined member an earlier draft stored** (§7.4 Versions; was v0.86 Open 32, v0.85 Open
    36). "As a config write does" still names no exemption. The reference lets a config write
    keep such a member unchanged, so a namespace written before an upgrade can be frozen or
    rotated. *Question:* may a write keep it, under §1's earlier-drafts clause as §4 Valid now
    cites it, or must it be `422` until removed?
25. **Grant lines: `stored` as an array** (§G.4.1, §C.3.1; was v0.86 Open 33, v0.85 Open 38). The
    pre-v0.73 array form of `stored` is still read, its first element checked, though §C.3.1
    defines `stored` as one base64url string and §G.4.1 rejects what it doesn't define.
    *Question:* is the array a rejected form now?
26. **A `sealed` op in a namespace not labelled `e2e`** (§G.5.1 Importing, §8.6, §2.1; was v0.86
    Open 34, v0.85 Open 40). An archive or bundle without `access` reads as private (§2.1). The
    reference refuses such a bundle at step 1, override or not, so an e2e prune archive from
    before v0.82, which has no `access`, can be restored and never imported. *Question:* should
    that be a stated step-1 refusal?
27. **A pinned tombstone below a horizon** (TOOLS §G.4.2, FED-15; was v0.86 Open 35). "Neither
    purged nor pruned without a kept document": the core serves a tombstone revision `410
    tombstone` at any level, below a horizon too, and the reference takes such a pin as in the
    target. *Question:* does it count as pruned without a kept document?
28. **A pinned revision the importer can't open** (TOOLS §G.4.2; was v0.86 Open 36). A revision
    the target serves and the importer has no key for, such as an end-to-end target's horizon
    snapshot, counts as in the target: the reference asks for it without opening it. *Question:*
    confirm.
29. **Who may cause a followed purge** (§G.1 Purges follow imports, TOOLS §G.4.4 step 7, FED-26,
    Grant scope scenario 87; security). Any writer who may `append` can write a batch whose
    `source` asserts a trusted origin, with an `at` it picks (§7.5: nothing verifies it). A later
    `purge` of that name at the origin, or a `purge-ns`, then purges the local resource, though
    the writer has no `purge` right (scenario 87 is the case with an untrusted origin, where
    nothing follows). Origin trust is the only guard. *Question:* should following apply only to
    batches the importer wrote with a grant allowed to import, or require `source.bundle` to
    verify against the origin's key? Where the text is silent the reference takes the trust from
    `serve --follow-purges-from ORIGIN`, keeps its follow state per (`ns`, origin, `source.ns`),
    records the author of the entries it writes as `system:purge-follow`, can't follow a sealed
    origin (it has no keys), and polls the origin's log rather than long-polling it. *Question:*
    which of these should §G.1 state?
30. **Setting `published`, and a merge stopped between steps 2 and 3** (TOOLS §F.9 Merging,
    §6.4.4, Filtered reads scenario 39). Step 3 sets the field readers' rules test (e.g.
    `/doc/published`), and the field is guarded against everyone else (§6.4.4). The reference
    lets the merge service set it by §6.4.4 rules that exempt a group (e.g. `publishers`) carried
    in the merge grant's root block, not a role, since a role would grant verbs. A merge stopped
    for a new approval between steps 2 and 3 (the reference's `ErrPlanChanged`) can't be planned
    again: the documents it created now classify as merged, so a new plan has no step 3. The
    remedy is to set the field by hand. A document a release restores counts as created.
    *Question:* should §F.9 name the guard (a group in the root block, not a role), say how to
    recover a merge stopped there, and say that a restore counts as created?
31. **An upstream request the gateway waited out** (TOOLS §H.4 Answers, FILE-18; was v0.86 Open
    37). The reference counts an upstream request by its last outcome. A failure is cleared only
    by the same request made again and answered, for a request with a body the same body, or by a
    whole write attempt the gateway waits out and makes again after a `429`. A document that
    reaches its cache through another user's request doesn't clear it. *Question:* intended?
32. **Requests not made for the user's request** (TOOLS §H.4; was v0.86 Open 39). A token's
    re-verification and the gateway's refreshes of its shared caches aren't counted. *Question:*
    confirm.
33. **A read that fails before a write, or after one** (TOOLS §H.4, §H.5; was v0.86 Open 40). A
    read that failed before the request's first write stops that write, so nothing is written and
    then answered as a failure. A read that fails after a write was made doesn't stop the writes
    that follow, the rest of a sequence or a restore: the request answers `502` or `503` with the
    work done, and a `DELETE`'s or `MOVE`'s locks still follow the file. *Question:* is a failure
    the right answer after a commit, and should the later writes of the sequence be sent?
34. **What "nothing of its answer" covers** (TOOLS §H.4, §C.6; was v0.86 Open 41). The reference
    drops the upstream's status number with its code and text, and sends a `Retry-After` of its
    own: 1 s for busy or behind, 5 s for no answer in time. In local mode its `502` still says
    the core refused the gateway's own grant, with no number. A `4xx` passed through keeps the
    upstream's text. *Question:* each.
35. **Trees through the index** (TOOLS §H.2, §H.3, §H.4, §H.5, §H.6). A gateway lists a tree
    folder through the index (§H.3). (1) An empty tree makes the index answer `400` for the
    facet, the path not being indexed, and the gateway treats that as an empty folder. (2) Where
    a tool lists again "with `?min`" (§H.4 Names before writes), the reference sends the
    namespace head, since nothing exposes the revision at which a name changed. (3) A document
    found, during a folder move, to differ from the listing the move was planned from fails the
    move with `409`, where §H.4 lists again. *Question:* each of the three.
36. **VECTORS-PROPOSED.md and §I.26** (was v0.86 Open 43). The file that came with v0.87 has C.4
    recomputed for `view` paths and its header's section number corrected, but its source line
    still says "computed independently from the v0.85 draft", and it still cites "Open 85" and
    "Open 84". §I.26 still calls C.4 and C.5 "not yet confirmed by the reference implementation".
    The reference reproduces both (C.4 with the `view` paths the file now has, in `go test
    ./internal/vectors/`; C.5 unchanged: Settled in v0.85, 85; docs/TESTVECTORS.md), and §I.23
    and §I.25 as v0.87 prints them. *Propose:* regenerate the file from v0.87 and take C.4 and
    C.5 into Addendum I.
37. **The index's range filters** (§A.4; was v0.86 Open 45, v0.85 Open 48). `gt`, `ge`, `lt` and
    `le` with a `sort` mark remain the reference's own, against Canonical URLs' "a parameter the
    service doesn't define … is `400`" if that means the spec's parameters. *Propose:* specify or
    drop them.
38. **"Buckets keyed by its principal"** (§6.6 Validation work, §6.2 step 1, Grant scope scenario
    78; was v0.86 Open 46). For a write that ran out at step 1 the reference checks and draws the
    principal's bucket, its allowance's if it has one, and each per-resource bucket, whose key
    includes the principal. It neither checks nor draws the namespace's. *Question:* is the
    namespace bucket checked though not drawn, and do per-resource buckets count?
39. **An upload that runs out, and `blobRate`** (§7.8 check 1, §6.6; was v0.86 Open 47). The
    reference draws one token from each of those buckets and none of the declared bytes from
    `blobRate`, which is keyed by the principal too. *Question:* should `blobRate` be drawn?
40. **A batch with items that ran out** (§7.5, §6.6 Validation work; was v0.86 Open 48). "Counts
    as failing authorisation" doesn't say what the batch costs. In the reference a batch whose
    only failures are run-outs draws what the batch would, a token per item, one per resource and
    its `config` change's unless exempt, less the namespace bucket. One that mixes run-outs with
    items that fail outright draws nothing, takes the outright item's status and lists both
    kinds, the run-outs as `422` (`limit`). *Question:* each.
41. **A batch whose `config` change fails after its step 1 while an item fails step 1** (§7.5,
    §6.6 Cost; was v0.86 Open 49, v0.85 Open 55). The change's error answers the batch, as v0.86
    says. Left: whether the change's token is drawn. The reference draws nothing, since the batch
    didn't pass step 1 as a whole, though §7.5 runs the change's steps first. *Question:* does it
    draw?
42. **Candidate verbs and a run-out** (§C.2 item 2, §6.6 Validation work; was v0.86 Open 50).
    Candidates share the budget. Where one runs out the item ran out, though another would pass,
    and it is an outright `403` only if every candidate fails outright. In an item of several
    steps an outright failure in any step beats a run-out in another. An upload stops at the
    first candidate that passes without running out. *Question:* intended?
43. **Exempt writes that run out** (§6.6 Exempt, Validation work; was v0.86 Open 51). Purges,
    config writes under a `*` key or that only freeze, and an operator's creation, when they run
    out at step 1, answer `422` and draw nothing. *Question:* does "after the rate limits,
    drawing only…" make an exempt write pay when it runs out?
44. **A creation's `412` under a `*` key** (§6.6 Cost, Exempt, Grant scope scenario 83; was v0.86
    Open 52). "Under any but an operator grant" against the exemption of config writes under a
    `*` key. The reference charges it. *Question:* which?
45. **"That grant's principal bucket in `{ns}`"** (§6.6 Cost, §12.2; was v0.86 Open 53). The
    reference keys a principal's bucket by the root block's `sub` and `kid`, with no namespace,
    so a key listed in two namespaces has one bucket. §12.2's row doesn't say "per namespace".
    *Question:* which is meant?
46. **What "a read" is for its budget** (§6.6 Validation work, LIM-7, Grant scope scenario 79;
    was v0.86 Open 54). The reference gives one budget to an exchange per grant, over all its
    namespaces and fixed names, so a run-out for one namespace fails the rest of that grant's
    exchange and it gets no cookie, a `view` cookie included; one to a key request, however many
    names it carries; otherwise one to each read check, so a request that makes several gets
    several, and a long-poll a fresh one each time it is admitted. *Question:* is a read the
    request or the check?
47. **Several roles and one item** (§6.6 Validation work, §C.2 item 5, Grant scope scenario 80;
    was v0.86 Open 55). For one grant with several roles, at the origin (a filtered read's
    revision, §7.9, included) and in every read check of a service (whether it reads, reads
    unrestricted, or reads namespace-wide), a role that runs out fails the whole check, whatever
    role follows, though roles are alternatives (§C.2 item 4) and a later one might pass.
    *Question:* intended?
48. **Key-scope `attrs` schemas** (§C.4, §6.6 Validation work; was v0.86 Open 56). No clause
    names them. The reference gives each check of a grant's attributes against a key's `attrs`
    schema a budget of its own, and attributes whose check runs out don't match. *Question:* do
    they count, and against whose budget?
49. **Which `validationSteps` a service applies** (§A.4, §12.2; was v0.86 Open 57). The limit is
    the deployment's, no namespace document carries it, and SERVICES doesn't say how a service
    learns it. The reference's index takes it as an option that defaults to §12.2's value. One
    set lower than the origin's hides items the origin would show, and higher the reverse.
    *Question:* should the origin publish it where a service reads it?
50. **A config write's `dependents`** (§7.4, §8.5 item 4, §12.1; was v0.86 Open 58). The
    reference caps `referencing` everywhere and a namespace purge's `dependents`. It leaves a
    config write's `dependents` whole (sealing, raising the level, requiring nonces, leaving
    `public`), at any depth, leaves first, as the text does. *Question:* are those capped too,
    and how does "leaves first" combine with "by name"?
51. **What `more` promises** (§6.1 Refusals, Grant scope scenario 84; was v0.86 Open 60). The
    reference sets `more` only once it has found a further namespace the caller may read. For a
    caller who reads few of them the search so runs to the end, and one who reads none gets `[]`
    without `more` after a whole search. *Question:* may a server say `more` without having found
    one?
52. **A namespace purge's `dependents` and who may read them** (§8.5 item 4, §6.1 Refusals,
    TERM-1; was v0.86 Open 61). `dependents` names every unpurged direct branch, readable or not,
    to a caller who needs only `purge-ns`, where `referencing` names only namespaces the caller
    may read. The reference follows the text. *Question:* should `dependents` be filtered alike,
    and would `more` then mean others the caller may read?
53. **The per-level product of `branchesPerNamespace`** (§6.6, §12.2;
    docs/capacity/branches/report.md, question 2; was v0.86 Open 62). Not answered. The limit
    bounds each namespace's direct live branches, so at the defaults a base may have 100
    branches, each 100 of its own, to depth 8, and a purge in the root reaches all of them: 100
    branches with 100 each cost a purge 25.0 s on Postgres in the report, the same as 10,000
    direct ones (0.6 s now, where they all read the document through). *Question:* is the product
    intended? A limit meant to bound a purge's work would bound the namespaces a purge reaches.
54. **What a purge owes a frozen branch** (§8.3, SPEC-CHANGELOG v0.86 Branches; the report's
    question 1; was v0.86 Open 63). "Frozen branches are free" is in v0.86's summary alone, and
    nothing bounds how many a base collects. The reference now pays nothing for a branch, frozen
    or live, that neither holds the purged name nor may read it through: it searches from the
    name and never reads such a branch. One that sees the name still gets what §8.3 gives a live
    one, a `purge` entry in its own log and its own cache tags: with 100 live and 10,000 frozen
    branches that read the document through, 0.7 s on Postgres and 20,212 tags. Nobody can write
    to a frozen branch, and what it serves for the name is `410` from the base's purge on either
    way. *Question:* does a frozen branch need its own `purge` entry at the time of the purge, or
    may the server write it when the branch is next unfrozen (or never, for one that is purged
    while frozen), with readers of the branch's log told of the purge by the base's? A refused
    purge's search for references now stops at a page, but the reference still plans the purge
    over every branch that sees the name before it answers `409`.
55. **Base cache tags** (§9 Branches, §8.3, CACHE-6, Grant scope scenarios 85, 86; was v0.86 Open
    64). The reference adds none and purges each branch's own tags as before, which the text
    keeps as the default. Left unsaid for a deployment that adds them: `heads:{branch}` of a
    branch with its own chain for the name, where the exception names only `r:{branch}/{name}`;
    and that a restore or an E3 prune in the base, which purges `r:{base}/{name}`, then clears
    the branches' copies too. *Question:* both.
56. **"The long-poll phase as the default"** (SPEC-CHANGELOG v0.86 reference changes; §7.7,
    CONF-5; was v0.86 Open 65). §7.7 and CONF-5 make phases byte-exact with no alternative, so
    the reference removed its switch. *Question:* does "default" mean anything, or should it read
    "the rule"?
57. **The path that is hashed** (§7.7 Intervals and cursors; was v0.86 Open 66). The reference
    hashes the path built from the names (`/r/{ns}/{name}/log`, `/ns/{ns}/log`,
    `/ns/{ns}/view/{view}/log`), never the request's URL as received, so an edge's prefix or
    another spelling can't change it. Names and `view` need no escaping, so it equals the URL's
    path. *Propose:* "built from the names".
58. **Intervals that aren't whole milliseconds** (§7.7; was v0.86 Open 67). "Modulo the interval
    in milliseconds" is undefined for an interval under 1 ms or with a fraction of one. The
    reference truncates to whole milliseconds and gives an interval under 1 ms phase 0.
    *Question:* must an interval be whole milliseconds?
59. **A cursor carried over the filtered redirect** (§7.7, §7.9 URLs; was v0.86 Open 68). A
    partial reader's long-poll of `/ns/{ns}/log` is redirected to `/ns/{ns}/view/{view}/log` with
    its `cursor`, which then belongs to a log with another phase and may be one off. The
    reference judges it by the ordinary rules on the target's clock: behind is answered at once,
    current or ahead waits to the filtered log's boundary, and `X-Cursor` is always past the one
    sent. *Propose:* a sentence saying a carried cursor is judged on the target log's clock.

## Reference gaps

Where the reference does less than v0.87 says, or computes something the text defines otherwise.
They are not questions, so the count above leaves them out; each is the implementation's to
close.

1. **Cookie death at the index** (§7.9 `view`, SERVICES §A.4, SVC-59, Filtered reads scenarios
   45, 61). The origin ends a view's cookies when the key's entry or any role that lists `read`
   changes, digesting all the read roles (scenario 61). The index still covers only the key and
   the roles of the grant's own, so a change to another role that lists `read` leaves an index
   cookie standing.
2. **The `/_refs` view** (SERVICES §A.4). The text's `view` is the hash of the markers
   `{ns}:{v}`, one for each followed non-public namespace where the reader has a view `v`. The
   reference's index still computes it as the digest of its internal markers, so its `view`
   strings differ from the text's.
3. **Trees** (TOOLS §H.2, §H.5, §H.6, §H.7; the rest of Addendum H is v0.87 Open 35). The
   reference doesn't do what the text says in four places: the delete-then-write restore (§H.6)
   in trees creates a new document, where it restores in the flat view; a folder moved to another
   namespace (§H.5) is `403`; the case-variant exceptions of §H.2 Siblings are not implemented;
   and sealed and end-to-end trees aren't offered (§H.7).

## Settled in v0.87

v0.87 answers the 68 notes open from v0.86. It takes four features out (catalogs and the tree
service, `requireAt`, remote branches, the `export` verb) and moves filtered reads into the core
(§7.9). Its change log gives no list of answers, so they were found by reading the v0.87 text and
CONFORMANCE against each note. "n" below means v0.86 Open n. By the reference's reading 18 are
settled and 50 stay open, rewritten above and marked "was v0.86 Open n"; 2, 18, 19, 25, 55 and 57
are cut to what remains, and 14 and 43 restated for what v0.87 changed. The features gone from
the text are gone from the reference too. Carried, as v0.86 → v0.87: 1–4 → 1–4, 6–7 → 5–6, 9–11 →
7–9, 14–16 → 16–18, 18–21 → 19–22, 25 → 23, 32–36 → 24–28, 37 → 31, 39–41 → 32–34, 43 → 36, 45–58
→ 37–50, 60–68 → 51–59.

- **5** (a remote branch and its base's level): moot: remote branches are removed (§G.3 and
  §G.5.2 are gone, HTTP-52 is retired). Addendum E's Levels now say only that a branch never
  serves what it reads through at a weaker level than its base serves it.
- **8** (a filtered `/heads` and the fork): moot: §7.9 Where gives no filtered reads in a branch
  or a sealed or end-to-end namespace (HTTP-70, Filtered reads scenario 3), so no filtered
  listing exists there to place a fork; a limited reader's `/heads` there is `403` (§C.5).
- **12, 13** (a purge learnt at a head, and older sealed ranges, for `requireAt`): moot:
  `requireAt`, `maxLag` and a grant's `at` are removed (§C.1, §C.4; AUTH-30 is retired).
- **17** (a cookie at an earlier `at`, and in a branch): §7.9 `view`: "every cookie of a view is
  `403`, at every URL, once an entry after its exchange changes those rules" (Filtered reads
  scenarios 13, 14), so a cookie a change ended is `403` at an `at` before it too, and one from
  an exchange after the change isn't ended and, each revision being judged by rules that never
  change, reads at every `at`. Which document's entry counts for a branch is §C.4's (Keys follow
  the base): the base's current entry for a `kid` the branch shares, and a `kid` copied at
  creation never falls back. The origin has no view for a branch (§7.9 Where); the index's, which
  §A.4 gives "at every level", is v0.87 Open 20's "what of the base".
  The reference judges cookies so (`TestV087EndedCookieAtOldAt`).
- **22, 23** (a purged sealed catalog; a grant that verifies only in a content namespace at a
  listing): moot: catalogs, `catalog.trust` and the catalog's listings are removed (SERVICES
  Addendum B).
- **24** ("unseen" in scenario 148): moot: scenario 148 went with `requireAt`. §A.4 now builds
  `/_refs`'s `view` from markers for "each followed non-public namespace where the reader has a
  view", and a namespace whose document doesn't list the grant's key gives the reader none, as
  the reference has it.
- **26, 28, 29, 30, 31** (a stopped namespace and `at`; `/problems`; links in a branch catalog; a
  content grant from one; writing through its file tree): moot: the tree service, the catalog
  service and branch catalogs are removed (SERVICES §B.5 is gone).
- **27** (item 2's roles and the digest): moot: there is no item 2. §7.9 `view` digests the rules
  that limit `read` and the values at the `/principal` paths they test (HTTP-74), so a read role
  that tests `/principal/sub` gives each subject a view of its own.
- **38** (a fallback that could answer in full): moot: there is no tree service and no
  node-document fallback. TOOLS §H.3: an index that is behind answers `503` (`behind`), and the
  tool answers `503` and deletes nothing on the strength of a listing meanwhile.
- **42** (folder deletes by readers who list through the tree service): TOOLS §H.5: a folder is
  deleted if it has no visible children; hidden ones don't stop it and fall out of the tree
  (Filtered reads scenario 51), so no node document is read.
- **44** (a branch of a release branch): moot: SERVICES §B.5 Previews and catalog entries are
  removed, and with them the local `base` chain clause and Encryption scenarios 92 and 93.
  Preview indexes remain (§A.4 Branches, §F.8, Encryption scenario 56): §E.2.6 seals an entry
  under the branch's own `K_r`, read-through entries included.
- **59** (`after` on `/branches`): §12.4 now says `after` is "a name" for `/heads`, `/branches`
  and `GET /ns`, as §7.4's "plain bound"; "or a `/branches` key" went with remote registrations.

## Settled in v0.86

v0.86 answers the 61 notes open from v0.85 and the four questions of the branch-limit report
(docs/capacity/branches/report.md). Its change log says 22 already matched the text or are the
implementation's business and the rest got a clause each; it gives no list, so the answers
were found in the text. By the reference's reading 45 notes are settled and 16 stay open and
are rewritten above, marked "was v0.85 Open n", three of them in part (21, 23, 55); the
report's second question is v0.86 Open 62. "n" below means v0.85 Open n. "No clause" means no
changed line was found in the SPEC, SERVICES, TOOLS and CONFORMANCE diffs, not that the whole
text was searched. A test named is the one that shows the answer, `TestV086…` where this
version's work added it. Where the text went against the reference, the reference changed, in
the area named:
- **Levels and sealed forms** (1, 2, 3, 5, 6, 7): the `/raw` row now ends "but a purge's `410`"
  (1; `TestV085RawOfTombstoneNotOffered`). A reader of a sealed branch needn't read its bases'
  namespace documents (2). A configured level the client doesn't know counts as `e2e` (3;
  `TestV086UnknownConfiguredLevelCountsAsE2E`). A base's `ns` is accepted only in an E3
  `sealed` op read through, and in no delivery form (5;
  `TestV086BaseNSRejectedInEveryDeliveryForm`). A branch's prune writes nothing, an archive
  included, and only namespaces that aren't branches have archives (6;
  `TestV086BranchPruneWithArchiveWritesNothing`). The origin rotates a frozen namespace,
  drawing no token (7; `TestV086FrozenRotationDrawsNoToken`). All as the reference had them.
  Changed, for the clause that came with 2's answer: a client holds a branch at least at the
  level it holds for any base in its local chain, and a holder of `sealed` refuses a plaintext
  `200` (`TestV086BranchHeldAtBasesLevel`, `TestV086SealedHolderRefusesPlaintext`; the
  playground alike). A client that holds `sealed` or `e2e` for some namespace reads a
  namespace's document once before it trusts a first plaintext `200` from it
  (`TestV086FirstPlaintextReadsTheNamespaceDocument`, `TestV086FirstPlaintextReadLimits`).
  New: v0.86 Open 1–6, 10.
- **The foreign parent** (4, 39): a reader that can't place it accepts no base's `ns` (4), and
  §G.4.1 defines it as the resource's head as the branch's own `/heads` lists it at the
  branch's first `ns_id` (39). Changed, both. The Go client and the playground place the fork
  from the base's `/heads` or else the branch's own, and where neither does, flag the base's
  entries, fold them as `[]` and refuse a base's snapshot, where they opened them unchecked
  (`TestV086UnplaceableForeignParentFailsClosed`, `TestV086ForkUnplacedWithNode`). A base
  named without `at` places none (`TestV086BaseWithoutAtFailsClosed`), and a fork that
  couldn't be placed is asked for again at the next read (`TestV086UnplacedForkIsNotKept`).
  The exporter reads the branch's own `/heads` and nothing in the base, so a branch of a
  remote base exports like a local one (`TestV086ForeignParentFromBranchHeads`,
  `TestV086ForeignParentRemoteBase`); it refuses a branch whose log doesn't start with its
  config genesis (`TestV086ForeignParentNeedsConfigGenesis`). New: v0.86 Open 7–9.
- **Derived views and previews** (8, 9, 10, 11, 47): at E2 a service takes a pending head's
  epoch from the `kid` of the revision as the origin serves it, the sentence proposed (8;
  `TestV085E2EpochFromOriginSealing`). A value from a namespace that is neither sealed nor
  end-to-end goes inside the entry's own `sealed`, or stays in the clear in an entry without
  one (9; `TestV086ValuesOfAnUnsealedItemInASealedCatalog`). No clause: a name-only listing
  stays `no-store` and unstored (10), and a preview at E3 must be a recipient in the branch's
  keyring (11); both stand as the reference reads the unchanged text. A reader accepts a seal
  under another namespace only where the namespace documents it reads put the catalog's or
  item's namespace in that one's local `base` chain, and shows the entry by name only
  otherwise (47). 8 to 11 as the reference had them. Changed for 47: the playground follows
  the chain for an entry's own seal too, where it looked one level up
  (`TestV086PlaygroundPreviewChainWithNode`). New: v0.86 Open 44.
- **No clause in federation and stored data** (12, 13): a cross-draft remote branch's `502` is
  §12.1's, and re-sealed rows with their old `ETag` are data of an earlier draft; both are the
  implementation's. Left open: 14 (v0.86 Open 11).
- **`requireAt`** (15, 16, 18): a grant that a purged catalog's `requireAt` key signs is `403`,
  and scenario 133 now says which key signs li's grant (15;
  `TestV085RequireAtPurgedNamespaceOrigin`). The `403` is for a purged namespace "other than
  the one the grant is checked in" (16). Only the `requireAt` `403`s that depend on a chain,
  or on whether a namespace exists or is purged, are answered alike (18;
  `TestV086RequireAtRefusalsNameNoNamespace`). 15, 18 and 16's `requireAt: true` as the
  reference had them. Changed: a key that names its own namespace gets the purged namespace's
  `410`, not `403`, at the origin and at a service (`TestV086RequireAtOwnNamespacePurged`).
  Left open: 17, 19 (v0.86 Open 12, 13).
- **Cookies and the index's exchange** (20, 22, 25): a minter may take whole seconds off a
  cookie's `exp` to tell it from another, and answers `503` (`behind`) with none left (20;
  `TestV086CookiesToldApartByExp`). A cookie is `403` from the entry that changes a key, rule
  or role it drew on, even where a later entry undoes the change; both changes in one entry
  end nothing (22, scenario 145). The exchange answers `502` or `503` as a whole where a
  `requireAt` chain can't be read (25; `TestV086ExchangeChainUnreadMixed`). 20 and 25 as the
  reference's index had them. Changed for 22, at the origin too: the note's "the origin never
  revives one" was wrong where nobody exchanged between the change and its undoing. The
  origin now keeps a record for each expiry second of a `gs` and judges a cookie by its own,
  over every namespace document since its exchange (`TestV086FilteredCookieStaysEnded`,
  `TestV086AccessGSChangeUndone`); several grants that give one subject set give one cookie
  (`TestV086AccessGSTwoGrantsOneCookie`). Its exchange takes seconds off as 20 says, so the
  exchange
  after a change gives a cookie that reads, or `503` with no second left
  (`TestV086AccessGSExchangeAgainSameGrant`, `TestV086AccessGSNoSecondLeft`), and a cookie
  from before a change still reads at an `at` before it. The index judges every config
  document after a cookie's exchange, a base's for its branches' cookies too
  (`TestV086CookieEndedStaysEnded`, `TestV086BranchCookieEndedByBaseChange`,
  `TestV086CookieMintedBehindOutlivesBacklog`). Left open: 21 and 23 in part (v0.86 Open 16,
  17); new: v0.86 Open 14, 15, 18, 19.
- **Operator grants and the caller's grant** (24, 27, 28): an operator grant is `401` at a
  service as at the origin, so none reads under a cookie and the empty `pub` has no case (24,
  Grant scope scenario 85). A catalog service takes the caller's `sub` and groups from the
  base grant as the catalog namespace's keys verify it (27, §B.11.6 Whose claims;
  `TestV086ClaimsFromTheCatalogsKeysAlone`), and where "reads nowhere" turns on a chain it
  can't read it answers `502` or `503` (28; `TestV086CallersGrantChainUnread`). The catalog
  service had 27 and 28, and the index, the tree service and the catalog service answered an
  operator grant `401` already (`TestV086OperatorGrantAtTheIndex`, `…AtTheTreeService`,
  `…AtTheCatalogService`). Changed: the stream proxy answers `401` to an
  operator grant presented as a caller's, where it created the stream
  (`TestV086OperatorGrantIsNoCaller`). Left open: 26 (v0.86 Open 22); new: v0.86 Open 20, 21,
  23, 24.
- **No clause in access and tree answers** (32, 33): unchanged §B.11.9 gives the
  `/ns/{ns}/g/{gs}` prefix only to a grant that doesn't fix `/resource` (32), and puts `next`
  on every full page of a filtered `/heads` (33), both as the reference does. Carried: 29, 30,
  31, 34 (v0.86 Open 25–28), and the index's range filters, 48 (v0.86 Open 45).
- **Branch catalogs** (35): in a catalog branch a link into a namespace of its local `base`
  chain counts as a link to the branch's node of that name, and no content grant is issued
  from the branch (scenario 150). Changed: the tree service and the gateway resolve such
  links, where the base's nodes were roots and orphans
  (`TestV086BranchCatalogLinksThroughBase`, `TestV086BranchCatalogTree`), and a catalog
  service on a branch refuses content and read grants
  (`TestV086BranchCatalogIssuesNoContentGrant`). New: v0.86 Open 29–31.
- **Documents and bundles** (37, 41, 45): §4 Valid excepts a revision or schema written under
  an earlier draft, as proposed (37; `TestV073StoredPatternInV073Closure`). A pinned revision
  is in the target if it is in the chain and "neither purged nor pruned without a kept
  document" (41). A copy into the folder itself or a descendant is `403` before anything is
  written, and a nested copy's `403` part-way leaves what was done (45;
  `TestV082XFolderCopyOverRealAncestors`). 37 and 45 as the reference had them, and 41 but for
  one case. Changed: a pin to a revision that an end-to-end target serves and the importer
  can't open, its horizon snapshot, failed the import on the key and is now in the target
  (`TestV086PrunedPinNotInE2ETarget`; plain targets in `TestV086PrunedPinNotInTarget`). Left
  open: 36, 38, 40, 44 (v0.86 Open 32–34, 42); new: v0.86 Open 35, 36.
- **The gateway** (42, 43): every core or service request a gateway makes for the user's
  request counts toward its failure, "whether or not the answer needed it" (42, Grant scope
  scenario 87), and its `502` and `503` name only the upstream that failed, with a
  `Retry-After` of the gateway's own (43, Grant scope scenario 86). Changed, both: a `GET` or
  `PROPFIND` that answered from the rest now fails (`TestV086SiblingReadFailsRequest`), no
  first write is sent after a failed read (`TestV086NoWriteAfterFailedRead`), and
  the bodies carry no upstream code, text or status number
  (`TestV086CoreFailureNamesOnlyTheCore`, `TestV086TreeServiceFailureNamesOnlyTheService`).
  New: v0.86 Open 37–41.
- **Vectors** (46): §I.17's last row makes the `Q` an `A`, which keeps the tag canonical, as
  proposed. Changed: the vector data, and the row is checked as a decryption failure
  (`TestI17SealedBundle`). §I.25's four phases reproduce (`TestI25LongPollPhases`). New: v0.86
  Open 43.
- **Rates and validation** (49, 50, 51, 52, 53, 54): the budget is per document a write
  produces, each step of a batch item counting alone (49; `TestV085ValidationStepsWithRules`),
  and running out of it is `422` even inside a rule whose own failure is `403` (50), both as
  the reference had them. At step 1 the `422` answers only if no check there fails outright,
  after the rate limits, drawing only the caller's own buckets (51), for an upload too (53).
  Every read check, exchange, key request and item a service filters has a budget, running
  out is the check's usual refusal, and no deployment is unbounded (52). A creation's `412`
  costs a token under any but an operator grant (54). Changed: step-1 run-outs, which
  answered at once and cost nothing (`TestV086StepOneRunOut`, `TestV086StepOneOutrightFirst`,
  `TestV086StepOneRunOutOtherWrites`); budgets for reads at the origin and at services
  (`TestV086ReadCheckBudget`, `TestV086IndexItemBudget`), an exchange whose budget is spent
  issuing no cookie (`TestV086FilteredExchangeSpent`); `--max-validation-steps 0` is
  refused (`TestV086ValidationStepsNeverUnbounded`); and the `412` under a namespace's own
  grant (`TestV086CreationTakenDraws`; the operator's as it was). Left open: 55's draw (v0.86
  Open 49), its error answering the batch as the reference had it; new: v0.86 Open 46–48,
  50–57.
- **Streams** (56, 57, 58): an orphan, whose proxy died before calling upstream, ends
  `"timeout"` (56; `TestIdleTimeout`). The timeout is the deployment's, one for all its
  proxies (57; the option's help and the README now say so). A read grant never outlives the
  proxy grant (58; `TestV086ReadGrantCappedByProxyGrant`). All as the reference had them.
- **`GET /ns`** (59, 60): both proposals taken. §7.4 says an operator key's scope failure is
  `403` (59; `TestV085NamespacesKeyScope`), and the rows are "the namespaces the API can
  address" (60; `TestV084NamespacesRows`).
- **Long-poll intervals** (61): the phase is §7.7's, as proposed, with vectors in §I.25. The
  reference had it as its default. Changed: `serve --long-poll-fixed-epoch`, which kept the
  single epoch, is removed (`TestV086LongPollPaths`). New: v0.86 Open 65–68.
- **The branch-limit report** (its questions 1, 3 and 4): frozen branches stay free, by the
  summary alone (1; v0.86 Open 63). `GET /ns/{ns}/branches` is paged, and an `in_use`
  refusal's `referencing` and a namespace purge's `dependents` list a page with `"more": true`
  (3). Changed: both (`TestV086BranchesPaged`, `TestV086ReferencingCapped`,
  `TestV086DependentsCapped`). Base cache tags are a MAY the reference doesn't use (4; v0.86
  Open 64). Question 2 has no answer (v0.86 Open 62). New: v0.86 Open 58–61.

## Settled in v0.85

v0.85 answers the 103 notes open from v0.82, those added for v0.83 (93–100) and v0.84
(101–103) included. Its change log says 45 already matched the text or are the
implementation's business and the rest got a clause each; it gives no list, so the answers
were found in the text. By the reference's reading, 24 notes or parts of notes stayed open and
were rewritten in the v0.85 list, marked "was v0.82 Open n", and five more were asked again as
the new text left them (72, 77, 86, 102, 103); that list is answered above (Settled in v0.86),
and its text is in git history. "n" below means v0.82 Open n. "No clause" means
no changed line was found in the SPEC, SERVICES, TOOLS and CONFORMANCE diffs, not that the
whole text was searched. Where the text went against the reference, the reference changed, in
the area named:
- **Sealed forms and levels** (1, 2, 3, 9, 10, 11, 12, 13, 15, 23, 30): the three candidates
  are §I.22–§I.24, and §I.22 concedes C.1's closing sentence: only a namespace event's `range`
  form is rejected, and a resource event's `pl` stays `{ ns, name, kind }` (1, 30). A
  tombstone's `/raw` in a sealed or end-to-end namespace is `404 not_offered` whatever the
  document URL answers (3; what the summary says against it is v0.85 Open 1). Server-written
  rotations carry no `grant`, not `"grant": null` (9). A client learns each namespace's level,
  a base's included, from its configuration, the current document or `/keys`, refuses a claim
  below what it holds, and before it has learnt one only its configuration protects it (10,
  11, 12). `view` may be rewritten by nothing between service and reader (23). A base's `ns` is
  accepted only at E3 and only up to the resource's foreign parent (13). No clause, and the
  implementation's business: the `410`'s cached form (2), a replayed keyring `$nonce` (15), and
  whether a lowered claim is lasting (12). All as the reference had it but 13. Changed: the Go
  client refuses a base's `ns` in the E2 forms and bounds read-through at the fork, over
  remote chains too, and the playground's chain check does the same (v0.85 Open 2–5 are what
  that left).
- **End-to-end reads and remote branches** (4, 5, 7, 14, 16, 25, 27, 29): B may learn a
  tombstone's parent from the `last` of a `404 not_offered` whose `horizon` is `T` (4). After a
  source's raise to `e2e`, which only an earlier draft allows, B answers as §1 says for good
  (25, the proposal taken). No clause: which later prune ends a snapshot (5, unchanged text the
  reference matches), counts seeded before v0.81 (7), the E3 count when the log can't be read
  (14), sealed bundles and the line bound (16), legacy E3 snapshots (27) and stored genesis
  entries without `parent` (29) are the implementation's. Nothing changed. Left open: 6, 8, 26,
  28 and 31 (v0.85 Open 6, 7, 12, 13, 14).
- **Derived views** (17, 18, 19, 20, 21, 22, 24): a value an entry with no revision of its own
  carries, such as an implicit placement's, is sealed as a value of another resource (19). A
  name-only answer is `no-store` and isn't stored, or, while the service may yet judge the
  epoch, `503 behind` (20, 18). A placement's content URL names the release branch's resource
  in a preview, a reader compares nested values with it (22), and a catalog branch, previewed
  or served directly, lists what it reads through (21). An E2 service learns a pending head's
  epoch from the origin's sealing, by the change list alone (17). A sealed filtered event
  stream has no clause and no case at the origin (24). Changed: the tree service's name-only
  listings, its implicit placements (title and `born` no longer under the catalog's keys) and
  its branch catalogs; the index reads a pending head's `kid` from the origin; the playground
  compares with the content URL. Left: v0.85 Open 8–11 and 35.
- **Cookies and the index's exchange** (32, 33, 34, 35, 36, 63): a cookie ends on any member of
  its key or roles, at the origin too (32, no clause), no exchange revives one, and one the
  origin can't tell from an ended one is `403` (33, the reference's short over-refusal). Index
  markers name their key, `reads:{ns}:{k}` (34). An exchange whose cookie would be `403` at
  once is `503 behind` (35). A purged namespace's `410` is for a request that passes the read
  check against the last document the service read (36). Event streams end when the `gs` check
  fails (63). 32, 33 and 63 as the reference had them. Changed: the index's markers are
  `reads:{ns}:key:{id}`, so every namespace-wide reader's `gs` moved; its exchange's `503`; and
  it ends cookies as it applies each namespace document, which judges a purged sealed
  namespace's. Left: v0.85 Open 20–24.
- **The caller's grant and the catalog service** (37, 38, 39, 40, 41, 50, 55): "reads nowhere"
  is judged in every namespace the service follows that the grant verifies in, counting only
  roles item 5 lets count, and an identity-only grant is refused (37). Only a malformed
  request's `400` precedes the `403` (38), and a mixed `want` gets the wanted verbs its roles
  count for (39), both as the reference had them. A merge grant is refused to an approver with
  a `/now` rule (40), and listings and the exchange refuse a grant `/read-grants` refuses (41).
  A stopped namespace's items are `502`, after any `403` the catalog's own trust decides, or
  `410` once it is purged, and no `checkpoint` names it (50). A service's `502` carries nothing of the
  answer that caused it (55, as the catalog, tree and index had it). Changed: the catalog
  service judges the caller's grant over its content namespaces, refuses `/now` approvers and
  leaves stopped namespaces out of `checkpoint`; the tree service refuses listings and edge
  grants to a grant that reads nowhere. Left: v0.85 Open 27, 28, 43.
- **Coverage and purged namespaces** (42, 43, 44, 46, 52, 88): a `requireAt` naming a purged
  namespace fails the scope, `403`, at the origin and at a service that has learnt of the
  purge, and every `requireAt` `403` is answered alike (42, 52). Only purged covered namespaces
  answer filtered URLs as their unfiltered forms (43). A catalog's trust is that of its own
  document here, a remote branch's too (44, as the reference had it). A purged catalog's trust
  is read at its purge head, and one a service can't read there is no catalog (42, 88). A
  successful `GET /` is reused for at most a minute (46). Changed: the origin and the grant
  checker refuse a purged `requireAt` namespace, where the origin had gone on verifying and a
  service answered `502`; the origin's uncovered purged namespaces answer `403` or `401` at
  filtered URLs; the index counts a purged sealed catalog as none and caps the reuse. Left:
  v0.85 Open 15–18, 26.
- **No clause in access and coverage** (45, 47, 48, 49, 51, 53, 54, 56, 57, 58, 59, 60, 61, 62,
  64, 65): of 45, the `/now` grant at a `/g/{gs}` listing and at the tree's exchange is settled
  by the listing clause, the reference's `403`. `/keys` for a `/now` role beside a `/resource`
  role (53), the exchange's `410` (59) and `/resource` inside `any` or `not` (64) stand as the
  reference reads the unchanged text. The bounded scan (48), the listing guard by tags (51),
  the index's own `gs` for a partial reader (54) and legacy `"partial"` sets (56) are the
  implementation's. Carried: the rest of 45, and 47, 49, 57, 58, 60, 61, 62, 65 (v0.85 Open 29,
  25, 30, 19, 24, 31, 32, 33, 48).
- **Tree answers** (66, 67, 68, 69, 70, 71): `ancestors` and `where` answer `nodes` beside
  `paths`, keyed by node name, and a service may add members of its own (66). `tooDeep` is for
  the depth-64 cut alone (67), only `subtree`, `ancestors` and `where` report it (68), and a
  walk up collects nothing more than 64 levels above a node (69, with scenario 132). Cursors
  after a redirect (70) and the kept purge record (71) are the implementation's. Changed:
  `/problems` no longer lists deep nodes (v0.85 Open 34). The rest as the reference had it.
- **Documents, bundles and tools** (72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83): a reader
  rejects a grant line whose `key.kid` isn't `root.kid` or whose `key` doesn't verify `stored`
  (75), and an undecodable or respelled `stored` block is rejected (74). An exporter writes an
  e2e branch's keyring whole under the branch's name and names the foreign parent in
  `requires` (76). The gateway has one rule for a request that failed for now: `503` after a
  `429`, a `503` or no answer in time, `502` when there is no connection, and a failed read is
  never a refusal (79, 80). A pinned `external` (77) and a save tagged with a tombstone (83)
  stand as the reference had them; undefined members kept unchanged are called the
  implementation's (72, asked again as v0.85 Open 36). Changed: the bundle reader's grant-line
  check; the gateway's answers for every request. Left: 73, 78, 81, 82, the array form of 74
  and the finding of 76's foreign parent (v0.85 Open 37–40, 44, 45).
- **Vectors and the playground** (84, 85, 86, 87): §I.17 seals lines §G.4.1 accepts, I.20's
  bundle, and the reference reproduces every new value (84). C.1–C.3 are §I.22–§I.24, and the
  new candidates C.4 and C.5 reproduce, the index serving C.4's `gs` and the bundle reader
  rejecting C.5's bundles (85). A reader accepts a value sealed under another namespace than
  its item's only through local `base` links (86), and of an entry that carries `sealed` it
  takes from outside only what §E.2.6 leaves in the clear (87). Changed: the vector data and
  tests; the playground's readers. Left: v0.85 Open 46, 47.
- **Rates and validation** (89, 90, 91, 92): a deployment may raise the maxima of
  `ratePerResource` and `ratePerPrincipal`, and an allowance's writes stay held per resource
  (89). A write refused at its precondition, and an idempotent retry, draw tokens like any
  other (90): the reference has drawn at the end of step 1, before every check of step 2,
  since before the note was written, so only tests for scenario 81 were added. TOOLS §11.1
  says a list several parties add to wants a resource per entry, and a write applied on the
  current head, guarded by its own `test`s, is now one of §13's open questions (91; the
  measurements are in docs/CAPACITY.md). A write's validation and its rules' `schema` tests
  take at most `validationSteps` steps together, else `422` (92). Changed: one meter per step
  shared with rule `schema` tests, failures listed within the budget, `measured` hidden from
  non-readers, the limit in `/principal` and deployment-only. Left: v0.85 Open 49–55.
- **Streams** (93, 94, 95, 96, 97, 98, 99, 100): continuations are `{id}.{n}`, covered by the
  read grant (93, 94); the proxy identifies callers through `GET /ns/{ns}/principal` with a
  grant narrowed to no verbs (95); `exp` counts from a stream's creation (97); a proxy stops
  carrying a stream it finds closed (98); upstream error responses are kept with their status
  (99); and the pattern is for namespaces that are neither sealed nor end-to-end (100). Abort
  where nonces are required stands (96). Segmenting is advice (93; `--segment-size` added).
  Changed: a stream is purged with its continuations, by the first's creation. Left: 97's
  repeated create and 98's differing timeouts (v0.85 Open 56, 57).
- **`GET /ns`** (101, 102, 103): only blocks that carry `can` must list `config`, `"rules": []`
  is none, and a grant carrying roles is `403` (101). An operator key's scope failure is `403`
  by scenario 80 (102). Every namespace is listed, with `created`, which §E.4 now says an
  operator learns (103). Changed: which operator grants list. Left: v0.85 Open 59, 60.

## Settled in v0.82

v0.82 answers the 77 notes open from v0.81. By the reference's reading of the changed text it
settles 47 whole, 16 in part (9, 17, 19, 23, 25, 42, 44, 46, 54, 57, 58, 60, 61, 68, 71, 73) and
leaves 14 (7, 8, 15, 28, 35, 47, 48, 50, 62, 63, 65, 69, 72, 75). What remained was rewritten
in the v0.82 list, marked "was v0.81 Open n"; that list is answered above (Settled in v0.85),
and its text is in git history. "n" below means v0.81 Open n. The spec's changelog counts
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
  playground's level tables, with `WithExpectedLevel` and `--expect-level`.
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
  holding a raised namespace is refused at start unless `--purge-raised-e2e` purges it (v0.81
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
  what is left (changed: `Plan.Unrecorded`, `--leave-out`; 29
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
  `--remote-origin-url`); `502` rows in `/heads` lack `created`, `size` and `digest` (changed:
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
  default and maximum per limit (`serve --document-size`, `--max-document-size`); log pages count
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
  namespace's `{dst}--upstream` must fit the name limit, `422` at step 1 otherwise (§G.4.4).

Adopted with more than the reference did, which now follows the text:
- **Key rotation** (2): origins and edges SHOULD accept several keys and mint with the newest;
  `--edge-grant-key` is now repeatable (§C.5).
- **Services and §9** (5): services apply §9 to their own origin. Private listings are cached
  at the edge under cookies the service mints with a key of its own for
  `/{catalog}/g/{gs}`, at an exchange endpoint of its own, so listing URLs now put the subject
  set first: `/{catalog}/g/{gs}/at/{at}/…`, `/{ns}/g/{gs}/at/{ns_id}`, `/_refs/g/{gs}/at/{at}`
  (§A.4, §B.11.5). The catalog service (`tree --access`) now mints and verifies them.
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
  reference now dry-runs later batches that move heads the target had, `--dry-run` too.
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
