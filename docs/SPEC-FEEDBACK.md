# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.73**. This file collects what
the reference does that the text doesn't yet describe.

## Open

From implementing v0.73, the whole upgrade from v0.55 (branch `spec-v073`). Each gives what the
text leaves open or says twice, what the reference chose, and where it does so.

The most consequential for other implementations, in the encryption and key areas, come first.

1. **The `encryption.epoch` default** (§12.3, §E.2.1). The table gives `epoch` "an integer ≥ 0
   (default 0)", but v0.55 gave no default and implementations sealed from epoch 1, so existing
   namespaces' epoch keys are `#1`, and those kids are bound into stored and cached ciphertext.
   Reading an absent epoch as 0 would renumber them, and a later rotation to 1 would reuse a key a
   revoked reader may hold. The reference reads an absent epoch as 1 and refuses an explicit 0 at
   `sealed` and `e2e` (`internal/core/config.go`, "Epochs count from 1"), so a raise from none or
   at-rest starts at 1 at least; its derived services, Go client and playground read 0 as absent.
   *Propose:* "default 1", or require `epoch` at `sealed` and `e2e`.
2. **Which pre-raise keys `/keys` gives after a raise from `sealed`** (Levels, §E.2.3, §2.1).
   "`/keys` gives the keys of epochs before the raise as at E2", with "the last epoch and `pad`
   setting before the raise in place of the current ones", but "as at E2" can be read over all the
   namespace's epochs, where a grant without `nbf` gets only the (post-raise) current epoch and so
   no pre-raise key at all. The reference applies the §E.2.3 window to the epochs before the raise,
   with the last of them and the namespace document just before the raise standing for the current
   ones: a grant without `nbf` gets the last pre-raise epoch, earlier ones need an `nbf`, and that
   document's `historyEpochs` caps them. Its own key checks for moving pre-raise content (schema
   resolution, blob copies, a batch's local `source`) use the same window, so the two can't disagree
   (`internal/core/e2e.go` `preRaiseWindow`, `withPreRaise`, `internal/core/preraise.go`
   `preRaiseKeysOpen`). A branch's base keys from before the base's raise aren't narrowed by
   `epochs`, like its base keyring entries (`baseEpochs`). *Question:* is that the intended window?
3. **Pre-raise keys for grants without `enc`** (§E.2.3, Levels). At E3, `/keys` for a grant whose
   root block has no `enc` is unspecified; the reference answers `422` (`invalid`), pre-raise keys
   included (`internal/core/e2e.go` `keysE2E`), although "as at E2" could mean the raw `key` form E2
   gives such a grant. *Question:* `422`, or the E2 form for pre-raise epochs?
4. **Where an E3 fold starts across a raise** (Levels, §E.3.1, §7.1). Not stated. The reference's
   fold redirect for a revision written end to end starts at the later of the latest prune snapshot
   and the chain's last revision from before the raise (its last live one where that is a
   tombstone), and `/rev` serves that start document at the level before the raise, so a fold range
   never holds plaintext or E2-sealed entries (`internal/core/preraise.go` `preRaiseFoldSince`; the
   client's `internal/client/e2e.go` `foldStart`). *Propose:* say so.
5. **The prune of a horizon from before a raise** (§7.1, §8.6, Levels). §7.1 serves `/rev/{H}` "as
   before" where `H` is from before a raise to `e2e`, but after an E3 prune the server keeps no
   plain document there. The reference serves the stored E3 snapshot when it can compute none
   (`internal/core/preraise.go`). *Propose:* say that the snapshot is served then.
6. **A branch's snapshot of a base's pre-raise content** (§E.3.1, Levels). "The epoch that revision
   is served under" makes the kid name the base (`{base}#{e}`), but the text doesn't say which
   `pl.ns`, or which namespace's `K_r`, such a snapshot uses. The reference takes `pl.ns` the branch
   and `K_r` derived with the base's namespace, as the kid gives it; its client fetches that key
   from `/keys` as at E2 (no sender, since the server held that content before the raise)
   (`internal/core/e2e.go` `checkSnapshot`, `internal/client/e2e.go` `snapshotKid`). A client whose
   fold starts at a base's E3 snapshot sealed under a pre-raise epoch still seals under the current
   epoch where the base kept no plain document. *Propose:* state both namespaces.
7. **What counts as a blob from before a raise from `sealed`** (Levels, §7.8). Undefined. The
   reference takes a blob referenced by any pre-raise revision of the resource's chain, served or
   not; such a blob is never served in the clear, and with no served pre-raise revision referencing
   it is `404` `no-store`, even where a revision written end to end declares it too
   (`internal/core/preraise.go`). *Propose:* define it.
8. **"They also open a public base's namespace log and documents from before the raise"** (Levels,
   branches of a raised base). "They" can be the branch's `/keys` answer or its readers. The
   reference reads it as `/keys` giving `K_e` of the base's pre-raise epochs (`internal/core/e2e.go`
   `baseEpochs`). *Propose:* name the subject.
9. **Remote branches of a raised source** (§G.5.2, Levels). How a remote branch serves its source's
   pre-raise content isn't said. The reference serves shadows that recorded a raise as pre-raise
   content, sealed under the source's epochs with `kid`, `pl` and `K_r` naming the source
   (`internal/core/e2e.go` `kidName`). It doesn't record each mirrored entry's own epoch, so it
   falls back to the source's last pre-raise epoch for them (`preRaiseEpoch`). *Question:* should a
   mirror keep each entry's epoch, and should the text say how such content is served?
10. **"Raise its level as far as Levels allow"** (§G.5.2, ENC-45). A remote branch's `at` is always
    before a raise it later sees, so a raise to `e2e` is always refused there, and a literal reading
    raises to `sealed` in every case. The reference raises to the level the source had just before
    the raise: a missed `sealed` raise is followed, and a raise from none or at-rest straight to
    `e2e` leaves the branch as it is, marked for rebase (`internal/core/remote_branch.go`,
    `Engine.RemoteLevels`). With a key store every level counts as offered, so a source's raise to
    `e2e` leads to a rebase, never a `502` (F-E9: does a server that offers `e2e` only at creation
    "lack" the raise?). *Propose:* say which level, and what "lacks a level" means.
11. **Remote branches that can't see a raise** (§G.5.2, §1). A follower that can't open its source's
    log (the source is now sealed and gives it no keys) can't "see the raise in the log it follows";
    the reference infers at least `sealed` from the source serving its documents as JWEs. Where its
    own raise fails for another reason, it records the level as lacking (its resources answer `502`)
    and marks a rebase. For a base deeper in `base.chain`, whose log it doesn't follow, it reads the
    current document at every sync and keeps the last epoch it saw when that read fails, without
    failing closed (`internal/core/remote_branch.go`, `internal/core/upstream.go`). *Question:* are
    the inference and the fallback required, allowed or out of scope, and should a deeper base that
    can't be read fail closed?
12. **"Epoch start times … never from a mirror"** (§G.5.2). B can't tell A's origin from a mirror
    that publishes A's origin in `GET /`; the reference trusts the configured endpoint whose root
    reports the origin (`internal/core/remote_branch.go`). *Question:* what check is meant?
13. **A remote branch's `/heads` after its base was raised past this server** (§1, §G.3). Only
    resource URLs answer `502`; `/ns/{ns}/rev/{id}/heads` keeps working at the branch's own level,
    so `size`, `digest` and `created` of heads the base now hides can still show
    (`internal/core/remote_branch.go`). *Question:* should those listings answer `502` too, or drop
    the fields once the base is sealed?
14. **Derived views across epochs** (§E.2.6, §E.2.3). Whole-response sealing needs every value from
    one epoch and aggregates are served only sealed whole, so after any rotation `counts` over
    documents written before and after it are `400` for every reader until all are rewritten, which
    may never happen. A service whose grant has no `nbf` gets keys from the current epoch only and,
    after a restart, can't seal views over older revisions under the epoch they're served under
    (`503`); the reference's services take pre-raise epoch keys without a sender, only for an epoch
    older than the current one their keyring names no key of, and otherwise need an `nbf` that
    reaches back (`internal/derived/keys.go` `preRaiseKey`; `internal/index/query.go`). *Question:*
    should aggregates take the newest epoch among their sources, and should §E.2.6 say services need
    an `nbf`, or let them have the epochs their sources are served under?
15. **One derived entry, several revisions** (§E.2.6). An entry has one `kid`, but may carry values
    of different revisions (a tree node's title from its head, `born` from its first revision); the
    reference uses the head's epoch. At E3, "the epoch the revision is served under" isn't defined
    for content a branch reads through from a base, or for a document with no op of its own since a
    snapshot; the reference takes the sealed op's epoch where its kid names the namespace itself,
    else the snapshot's kid, else the current epoch (`internal/tree/files.go`,
    `internal/derived/keys.go`). Where an older epoch's key can never be had, the entry is shown by
    name only and stored so, rather than `503`. *Propose:* say which epoch, and allow or forbid the
    name-only entry.
16. **Rules markers of sealed schema revisions** (§6.1, Levels, §G.3). A schema revision read in the
    clear carries `X-Schema-Rules: v0.73 | legacy` from the reference
    (`internal/server/resource_reads.go`, `internal/schema/dialect.go` `RulesHeader`); a remote
    branch's mirror reads it with a `HEAD` per revision and stores it
    (`internal/core/remote_branch.go` `fetchRules`); no header means legacy. Sealed and end-to-end
    namespaces send none, so an E3 client compiles a sealed schema revision (one from before a raise
    from `sealed` included) as legacy while the core compiles it under its row's marker, and `idn-*`
    versus `semver`/`period` can differ. A header beside a JWE would show that the document is a
    schema and roughly when it was written. *Question:* should the marker be part of the protocol (a
    `/rev` header, a log-entry member, or inside the sealed payload or `pl`), and what does a mirror
    of a sealed source store?
17. **Which keyring checks remain** (§E.3.2, §E.2.3, F-E4). The reference's gate refuses a keyring
    whose `kid` isn't `{ns}#{e}` naming this namespace, whose epoch is after `encryption.epoch`,
    whose `to` or `from` isn't a 43-character thumbprint, or whose `wrapped` isn't 80 bytes; a
    `$nonce` may be any string (`internal/seal/keyring2.go` `ParseKeyringV2`). So a raise to `e2e`
    shares a batch with the keyring line, or comes before it. *Propose:* list the checks.
18. **Keyring senders and recipients are thumbprints** (§E.3.2, §F.8.1). An auth-mode entry opens
    only with the sender's public key, but the keyring names senders and recipients by thumbprint.
    Readers need the admin's key out of band, and the reference adds configuration for it
    (`internal/client/e2e.go` `WithSenders`, and `-keyring-sender` in `cmd/patchlog`), trusting its
    own keys and configured ones by default. Tools can't wrap for a reader known only by thumbprint
    (rotations, successor keyrings), so the reference wraps for readers it knows and, on a rebase
    with `Switch`, refuses rather than drop one (`internal/merge/rebase.go`). Auth mode
    authenticates an entry only to its recipient, so the recipient set isn't authenticated as a set:
    tools take readers from the caller, never from stored `to` members. *Propose:* a public-key
    member, or say all of this, including that a rebase must not reduce the readers.
19. **The keyring format change** (§E.3.2, §G.5.1). There is no transition from the pre-v0.63
    keyring (old shape, base mode, 160-bit recipient ids, old HPKE `info`). The server can't rewrite
    it; the reference relays an old keyring as stored, refuses writing that format, and blocks E3
    writes and derived views over it until a key holder runs `patchlog e2e migrate-keyring`
    (`cmd/patchlog/e2e.go`, `internal/client/e2e.go`). A holder that can't open every epoch can
    migrate only by leaving epochs out (`-skip-unopenable`). Bundles carry keyring lines verbatim
    and the gate checks each as the v0.63 document, so a namespace whose keyring was ever stored in
    the old format can't be bundled or restored, even after migration (`internal/bundle/access.go`).
    *Question:* may a keyring lack epochs the namespace had, may readers fall back to earlier
    keyring revisions, and may imports accept the old format for revisions that aren't the head?
20. **Legacy forms and "stored once, served forever"** (§C.3.1, §E.2.2, §G.4.1, F-C8). This round
    changed the stored grant shape, the `pl` kinds (`config`, `snapshot`), dropped zip, moved E3 to
    `K_r` and reshaped `/keys` entries. The reference's readers accept each legacy form
    (`internal/seal/keys.go` `ParseWrappedKey` reads `resource` and `suite`; `internal/seal/jwe.go`
    reads `DEF`), the E3 gate refuses old forms on new writes, grant answers sealed before keep the
    old array (new ones are sealed once under a new key), and bundle grant lines carry only the
    authority block. *Question:* MUST or MAY readers accept the legacy forms, and may a sealed
    answer be re-sealed on a format change?
21. **Values of another resource and order** (§E.2.6, F-E5, F-E6). Is the JWE plaintext the value
    itself, or `{ member: value }`? The reference seals `{ "file": value }`
    (`internal/tree/files.go`). Is "order" the result order or the `order` keys of `parents`
    entries? The reference reads it as the result order: `children` cursors are positions and never
    encode an order key (`internal/tree/http.go` `childPage`). If keys were meant, `order` members
    would need sealing.
22. **Folds of revisions that don't open** (§E.3.1, F-E7). The fold covers patch sets that don't
    apply, not decryption, `pl` or `kid` failures. The reference flags those too and folds them as
    `[]` (`internal/client/e2e.go` `fold`). A merge can't replay a fold's `[]`, so such a revision
    stays a conflict for a person. *Propose:* say so.
23. **Ranges sealed under "the current epoch"** (§E.2.2, F-E8). The reference seals a namespace
    range, long-poll answer or event under the epoch current when sealed, keeps a stored range's
    bytes and seals an evicted one again under the epoch current then (`internal/core/sealed.go`
    `rangeJob`), so a reader without `nbf` can't read an older stored range. *Propose:* "current
    when sealed", and say what such a reader gets.
24. **The snapshot kid below an earlier horizon** (§E.3.1, F-E2). Where only a snapshot is left of
    the newest content revision, the reference lets that snapshot's kid count where it names the
    namespace (`internal/client/e2e.go` `snapshotEpoch`). *Propose:* say so.
25. **`historyEpochs: 0`** (§12.3, §E.2.3). "An integer ≥ 0, no cap without it"; the reference takes
    0 as the current epoch only (`internal/core/sealed.go` `grantEpochsOf`). For a branch's base
    epochs it applies no `historyEpochs`. *Propose:* confirm both.
26. **`/keys` details** (§E.2.3). An explicit `"resources": []` asks for no names (only an absent
    member gets the default); a token is drawn only for requests answered with keys (`403`, `404`,
    `410` and `not_offered` draw none, as refused `/edge-grants` don't); with authentication
    disabled every epoch is given; and v0.55's "never epochs that started after `exp`" is gone, so
    the reference gives them (`internal/core/sealed.go`, `internal/core/e2e.go`). *Question:* each
    as intended?
27. **Replayed items with undeclarable blobs** (§F.3, F-E12). Only kept heads at E3 with blobs a
    `sealed` op can't declare are exempt; the reference keeps such a head unmerged and offers it
    again (`internal/merge/plan.go`, `internal/merge/blobs.go` `undeclarableBlob`). Replayed or
    re-sealed items whose document still references such blobs fail sealing. *Question:* exempt them
    too?
28. **HPKE auth mode** (§E.3.2, §E.2.3). Go's standard library offers base mode only, so the
    reference hand-writes RFC 9180 `mode_auth` (`internal/seal/hpke.go`), checked against RFC 9180
    A.1.3 and the CFRG vectors for X25519 with AES-256-GCM, which RFC 9180's appendix lacks. §E.2.3
    never says single-shot. *Propose:* cite RFC 9180 §6.1's single-shot Seal and Open, or consider a
    signed base-mode wrap.
29. **Fork discovery without base reads** (§E.3.1, ENC-27). Finding where a branch's chain forks
    needs the base's `/heads`; readers without that read, and remote bases, can only use the depth
    rule, which the reference falls back to (`internal/client/e2e.go`). *Propose:* allow the
    fallback.
30. **Encrypted archives** (§8.6, §G.5.1.1). How the per-resource key is made and kept is open; the
    reference derives an X25519 key from the resource data key (HKDF-SHA256, no salt, info
    `patchlog-archive-key-v1`) with no export command (`internal/core/archiveseal.go`
    `archiveIdentity`). It pads archive lines when the namespace pads, and at E3 seals archives as
    sealed bundles too, so their patch sets are encrypted twice. *Question:* is an export path
    expected, are archive lines padded, and is double encryption at E3 intended?
31. **The key-window check stores no sealing** (§2.1, §E.2.2). For content not yet sealed, the check
    uses the epoch a read would fix now but stores no sealing, so the next read may fix a newer one
    after a rotation (`internal/core/keywindow.go`). *Question:* acceptable, or must the check store
    it?

From implementing v0.73: requests and the gate (§1, §3, §6, §7).

32. **Resent stored content** (§3.1, §3.4, §F.3, §G.4.4, F-R0). Noncharacters are refused and
    `Signature` is strict for every request body, and merges, rebases, imports and mirrors resend
    stored patch sets and signatures; content or signatures stored under v0.55 (a noncharacter, an
    unlisted `kid`, a short signature) are `400` on resend. The reference checks every request alike
    (`internal/server/request.go` `jsonv.ParseInput`, `sig.ParseInput`). *Question:* is resent
    stored content exempt, and should tools drop such signatures?
33. **Where request-shape errors go** (§7, §6.2, F-R0b). For reads, is the `400` for a malformed id
    required, or only allowed, before the `401`, `403` or `404` that hides a namespace? Where does
    an error found late go (inside batch items, in a quoted `If-Match` list)? The reference answers
    it as the request's own `400`, before authentication and before any step-2 check, never per
    item, and treats an empty `If-Match`, `If-None-Match` or `Signature` value as present and
    malformed (`internal/server/request.go`). It also answers a malformed `at`, `horizon` or `keep`
    `400`, though §7.6 and §8.6 phrase their refusals as `422`. *Propose:* say so.
34. **Gestures `?after=`** (§7, §7.4, F-R1). Malformed: `400` (§7) or `404` (§7.4)? The reference
    answers `404` for a malformed `after`, one naming no entry, or one of a resource the reader
    can't see (`internal/core/gestures.go`). Can an `after` naming an entry of a purged resource
    resolve?
35. **`cursor` without `live`** (§7.7, F-R2). The reference checks its grammar (`400` unless
    decimal, leading zeros accepted) and otherwise ignores it on the `302` path
    (`internal/server/live.go` `liveQuery`). *Question:* `400`, and are leading zeros allowed?
36. **An upload's header errors** (§7.8). §7.8 puts an upload's header shape errors at check 4, so
    the reference answers a `Signature`, `X-Author` or precondition shape error on a blob `PUT`
    there (`internal/core/blobs.go` `ShapeErr`). For a copy, "come where Copying says" names only
    the body and `Blob-From` errors; the reference puts the others with them, after checks 1–3.
    Check 4's answers are unordered; the reference answers `400` (type or nonce), then `428`, then
    `415` at E3. *Propose:* list them under Copying and order check 4.
37. **Blob headers on uploads, ranges and PDFs** (§7.8, §H.6, F-R3). The reference counts `PUT
    …/blob/{bid}` as a blob URL for `nosniff` and the sandbox, and sends `Content-Disposition:
    attachment` with a PDF's `200`, `206` and `HEAD`; a deployment that opts in to inline PDFs drops
    the sandbox and the attachment header, and every other answer (`304`, `412`, `416`, errors)
    keeps the sandbox (`internal/server/blobs.go`). The gateway does the same. *Propose:* confirm
    `206`, and that §H.6's exception follows §7.8.
38. **`source` members** (§3.5, §C.3, F-S5). The reference requires every `source.ids` member to
    name a resource of the batch's items with a text-form id, answers a non-canonical
    `source.origin` `400` rather than normalising it, and accepts only `http` and `https` with an
    ASCII host (`internal/server/request.go`, `internal/sig/sig.go` `CanonicalOrigin`). §C.3 names
    no schemes. *Propose:* say so.
39. **Order within an item at step 2.5** (§6.2, F-G1). The reference checks a repeated `"delete"`
    first, then a stale `ifMatch`, the `ifNoneMatch`-with-delete `428` and the missing-precondition
    `428`; all depend only on the request (`internal/core/write.go`). *Propose:* state an order.
40. **The dry-run `config` report** (§7.5, F-G2). On success a batch's `config` is an id, in a dry
    run a report, so clients switch on the JSON type. The reference answers `{ "status": 201,
    "config": id }`, `{ "status": 200, "config": id }` for a retry, or `{ "status", "code", … }` for
    a failure after the change's step 1 (`internal/core/write.go` `ConfigReport`). *Propose:* state
    the shape.
41. **A create applies to null** (§6.2, §6.3, F-G3). Is a `null` document valid, at E3 too, and what
    does a create of `[]` do? The reference decides by §6.3's writes: `[]` and `[test "" null]`
    write nothing and are `422` (`invalid`); `add "" null`, `replace "" null`, and a root `move` or
    `copy` onto `""` store `null` (`internal/core/write.go`). *Question:* by writes, by the result,
    or let `[]` create `null`?
42. **What a batch draws when its config change fails after step 1** (§6.6, §7.5, F-G4). The
    reference draws, for a submit and a dry run alike, once the items pass step 1: a token per item,
    and one for the change unless a `*` key made it; the freeze exemption isn't applied, since a
    failed change's kind isn't known (`internal/core/write.go`). Drawing nothing would let dry runs
    with a failing change judge items for free. *Propose:* say which.
43. **Date-times in `compare`** (§6.4.2, F-G5). RFC 3339 §5.6 allows lowercase `t` and `z`; the
    reference treats them, a leap second and a space for `T` as an unsupported type, and reads
    `-00:00` as `Z` (`internal/rules/rules.go` `parseDateTime`). *Propose:* say so.
44. **"Outcome depends on" at E3** (§6.2, F-G6). The reference uses strong Kleene logic
    (`internal/rules/rules.go` `EvalTri`), so `any: [test /doc/x exists, not test /doc/x exists]`
    comes out unknown; it treats `writes` as unknown for every sealed step, a `[]` restore included,
    and as known (`[]`) for a delete (`internal/core/e2erules.go`). *Propose:* state the precision,
    and whether a `[]` restore's writes are known.
45. **Step-6 grant-rule refusals in a dry run** (§7.5, F-G7). "If any item fails authorisation, only
    those items are reported" should say steps 1 and 2.2, as the dry-run text does. The reference
    reports a step-6 grant-rule `403` per item in the dry run's `200`
    (`internal/core/authrules.go`).
46. **Limits in force at a creation** (§6.6, F-L2). Neither which limits apply to a namespace's
    creation or a branch's, nor which are "the patch-set and document limits", is said. The
    reference uses the deployment defaults for a creation and the base's for a branch, and applies
    `patchSetSize`, `opsPerSet`, `documentSize`, `nestingDepth`, `valueSize` and `pathSize`, not
    `blobsPerDocument` (`internal/core/nsbranch.go`, `internal/core/nsconfig.go`). *Propose:* say
    so.
47. **The Values inequality** (§6.6). It applies to every namespace, not only E3, so a namespace can
    never set `patchSetSize` ≤ 1 KiB, and a deployment whose defaults break it creates no
    namespaces; nothing says whether a deployment checks its own defaults. "A config write that
    changes `limits` or `encryption`", read literally, refuses the rotation §E.2.1 requires in a
    namespace whose stored limits fail it; the reference exempts a write whose only change to
    `encryption` is `epoch` (`internal/core/config.go`). *Propose:* "changes `limits` or
    `encryption` other than its `epoch`", and confirm the universal reading.
48. **Stored values a deployment has since bounded** (§6.6, §12.2). Whether a config write that
    keeps a value unchanged "sets" it isn't said; the reference holds unchanged limits, and
    unchanged allowance members per `sub` and `kid`, as stored. Namespace documents stored before
    v0.63 that set `grantSize` or `rulesPerGrant`, now deployment only, load, and their values are
    ignored until a write changes them (`internal/core/config.go`). *Propose:* say both.
49. **An allowance bucket above the maximum** (§6.6, F-L3). Which `limit` does it name? The
    reference names `ratePerNamespace`. The text's own example bucket (burst 20000) exceeds the
    default `ratePerNamespace` maximum (burst 1000); the reference has `-max-rate-per-namespace` to
    raise it, and clamps larger stored buckets (`cmd/patchlog/main.go`). *Propose:* name the limit,
    and fix the example or the default.
50. **Atomic deduction** (§6.6). "The check and the deduction are one atomic step … and with the
    write where there is one" pushes implementations to hold bucket rows locked until the write
    commits. A deduction must survive a refusal after admission anyway, so one committed first can't
    be told apart; the reference commits the draw first (`internal/core/ratebuckets.go`). It charges
    one token per item, even for two items on one resource. *Propose:* "a write it admits never
    commits without its deduction", and say how items on one resource count.
51. **A verified grant without `read`** (§7, §C.2). The answer on `/ns/{ns}` URLs of a private
    namespace, and at `POST /ns/{ns}/keys` of a public one, isn't stated; the reference answers
    `404` in both (`internal/core/auth.go`, `internal/core/sealed.go`). *Propose:* say so.
52. **Unknown resources on purge and prune** (§6.2, §8.3, §8.6). The `404` isn't placed; the
    reference answers it after the `428`, which depends only on the request
    (`internal/core/nspurge.go`, `internal/core/nsprune.go`).

From implementing v0.73: schemas (§6.1, §6.4).

53. **"A schema stored under an earlier version is compiled as that version did"** (§6.1, F-S1).
    "Version" is undefined (the spec's, or a release's). The reference stores a marker per revision
    (`v0.73` or `legacy`, `revisions.rules`), compiles each revision of a closure under its own
    (`internal/schema/marked.go`), and judges imports from another deployment by today's rules
    (§G.4.4), so a v0.55 bundle whose schema uses a format outside the 2020-12 set is refused;
    rebases and non-fast-forward replays give schema documents new ids, so they are new content too.
    Remote mirrors keep the source's marker (16). *Question:* should bundles carry a marker, or
    imported schema documents count as stored, and is the replay rule intended?
54. **Stored rule fragments and namespace documents** (§6.4.2, F-S3). Nothing says rule fragments
    and namespace documents stored earlier compile as stored. The reference compiles stored ones
    leniently and keeps unchanged rules as stored, but treats an imported or replayed namespace
    genesis as a creation, held to today's fragment rules (`internal/core/config.go`). A rule's
    schema now asserts the 2020-12 formats, so a stored `idn-email` rule refuses what v0.55 let
    through, while stored fragments keep v0.55's extra `semver` and `period`
    (`internal/rules/rules.go`). Which §6.6 limits apply to a fragment beyond its document's
    `documentSize` and `pathSize` isn't said either. *Propose:* a stored-fragment clause.
55. **IDNA profile** (§6.1 formats, F-S2). "UTS 46/RFC 5890" picks no profile. The reference uses
    the lookup profile (`internal/schema/dialect.go` `idna.MapForLookup`), which accepts uppercase
    ASCII and other mapped input that the registration profile refuses. *Question:* which, and what
    does an implementation without IDNA do?
56. **RE2 translation edges** (§6.1, F-S4). The text doesn't cover an escaped backslash before `u`
    (`\\u0041`, left as is), ECMAScript's `\u{…}` (left for RE2 to refuse), RE2's `\Q…\E` (its text
    left untranslated), or a lone surrogate written `\x{D800}`, which RE2 accepts and the reference
    refuses (`internal/pattern/pattern.go` `Translate`). Key `sub`s and rule patterns stored under
    v0.55 with `\x{D800}` still compile and are refused only when a write sets them. *Propose:* say
    each, and whether the stored leniency is acceptable.
57. **Fragments and plain names** (§6.1). "A fragment that is empty or starts with `/` is
    percent-decoded" doesn't say whether "starts with" applies before or after decoding; the
    reference decodes first (RFC 6901 §6), so `#%2F$defs%2Fk` is a pointer and `#%6Eum` the name
    `num`. A plain name outside the `$anchor` grammar (`#$defs/zip`, `#1a`) names nothing and is
    `422` `invalid`, not `schema_ref`; the dialect meta-schema runs first, so some refusals carry an
    `errors` list rather than a `message` (`internal/schema/check.go`). *Propose:* say which code
    and shape.

From implementing v0.73: reads, streams and logs (§7.1–§7.7).

58. **The end of a purged namespace's stream** (§7.3, §10, F-R4). A sealed namespace's stream can't
    end "after its purge-ns event", since its events answer `410` once the keys are destroyed. An
    unsealed one "ends … at once when `since` names that entry", which a client can't tell from a
    restart, so a follower reconnects with backoff for ever; a long-poll follower there
    gets `204`s. The reference's follower asks `/heads` (`410` at any revision) with an `after` past
    every name (`internal/follow/follow.go`). *Propose:* answer such a `since` `410 purged`, or end
    the stream with a comment naming the purge.
59. **Read checks in streams** (§7.3, F-R5, F-R12). "Before each event": the reference judges once
    per page, which is one fetch, and before each keep-alive comment. It ends a stream at the
    earliest `exp` among a narrowed grant's blocks, at a cookie's own `exp`, and doesn't end a
    public namespace's stream at a carried grant's `exp`, since a reconnect would be admitted anyway
    (`internal/server/live.go`). *Propose:* say per page is enough, and the rest.
60. **Sealed resource events** (§7.3, §E.2.2, F-R6). Purge and prune events carry no id in `pl` and
    no `id:` line, so a recorded one could be replayed into the same stream; and whether they are
    stored once isn't said. The reference seals them as served, under the epoch current then, with
    `pl {ns, name, kind}`, and stores none (`internal/core/eventseal.go`). *Propose:* bind the
    entry's `target` in `pl`, and say they aren't stored.
61. **`/principal`'s `catalog`** (§7.4, F-R7). "A catalog namespace" is read as one whose document
    has `catalog`, and `trusted` is `false` where `catalog.files` is absent
    (`internal/core/principal.go`). An operator grant gets the restricted catalog view only outside
    public namespaces, since a public namespace's catalog needs no grant. *Propose:* say so.
62. **`via` on older entries** (§7.1, §7.4, F-R8). It can't be recovered for namespace entries
    written before servers stored it, since grants are stored once per root id without narrowing
    blocks. *Propose:* "absent on entries written before v0.73", as for `grant` before v0.37.
63. **`/heads` at an older revision** (§7.4, §8.3). "Its latest head, tombstone or purge entry" as
    of that revision lists a resource live then and purged later as `head`. The reference lists it
    as `purge` with its head as of that revision, §8.3's rule for late branches, and leaves out
    resources with no entry then (`internal/core/reads.go`). A branch's own purge of a name it read
    through is taken to hold at every earlier `ns_id` where it read an entry for it. *Propose:* one
    rule for both.
64. **`ETag` of an E2-sealed revision served at E3** (§E.2.2, §7.1). A revision sealed by the server
    before a raise to `e2e` gets `"{id}.{e}"`, as §7.1 gives a sealed revision;
    fold redirects and client-sealed snapshots keep `"{id}"` (`internal/server/resource_reads.go`).
    *Propose:* confirm.
65. **Changes missing from the change log.** v0.60's "sealed namespaces use the public long-poll
    rules" was superseded by v0.63 without a note (F-R9); `/maxLag` joined the `*`-key list without
    one (F-R10); and §H.2's change to excluding only bidi controls among `Cf` has none (F-H10).

From implementing v0.73: namespaces, branches and prunes (§7.4, §7.6, §8).

66. **Branch prunes** (§8.6, F-B6). "Its genesis id where it has none": the reference answers the
    ancestry's genesis, and as the horizon the newest ancestry segment's that has one, which can lie
    above the branch's `at`. It still applies `keepPerResource` and E3's `keep` refusal in a branch,
    without checking ids against the history; compares `keep` as a set; requires a `*` key only for
    prunes that move the horizon, but the no-archive `403` for every prune without one, no-ops
    included; and binds a branch snapshot's `pl` to the requested horizon
    (`internal/core/nsprune.go`). The plaintext `keyring` resource's prune and snapshot aren't
    covered. *Propose:* say each.
67. **Extra members in answers** (§7.4, §B.11.4, §B.11.5, F-B8). The reference keeps `archive` in
    the prune answer, `ns`, `can` and `exp` in `POST /grants`, and `message` (and `head` on `410`)
    in `/read-grants` items. *Question:* allowed?
68. **`successor` at a namespace's creation** (§7.4, F-B9). The reference refuses any `successor` in
    a namespace's creation, and judges a branch creation that sets one against the new branch's base
    chain (`internal/core/nsconfig.go` `checkSuccessor`). *Propose:* say so.
69. **Late branches** (§8.3, F-B10). Say explicitly that only names with an entry as of `at` are
    listed as purged; the reference does so.
70. **Branch creation order** (§7.6, F-B11). The reference answers a taken name (`412`, step 2.5)
    before an `at` outside the base's chain (`422` `invalid` at `/base/at`, step 4), and a creation
    retry sent with no precondition `428`, never a retry (`internal/core/nsbranch.go`). *Propose:*
    confirm, and name the pointer.
71. **What precedes the `*`-key guard** (§7.4, F-B12). The reference counts as namespace-document
    validation: members and shapes, `rulesPerNamespace` and the Values bound, retention archive
    destinations, an immutable `/base`, drafts, the level rules and epoch steps, a base's `*` keys
    kept, a public branch of a non-public base, the base's nonce requirement and `successor`;
    unfreezing against `branchesPerNamespace` is a limit after the patch-set and document limits
    (`internal/core/nsconfig.go`). *Propose:* list them.
72. **A base's `*` keys after it changes them** (§7.4). Which branch entries "a `*` key in one of
    its bases" protects once a base changes its keys isn't said. The reference protects only entries
    the branch's document holds with the base's `pub`; a `*` key the base adds later is in no branch
    document, and an entry the branch holds without `*` that the base later makes a `*` key may stay
    so but can't be removed (`internal/core/nsconfig.go`). A creation retry compares `at` and
    patches by the genesis they produce, so across v0.73's dropping of `cleanup` from a branch's
    starting document a retry without patches can't be told from one whose patches set it.
    *Propose:* say so.

From implementing v0.73: grants (Addendum C).

73. **Refusal order of a grant before the `ns` check** (§C.8, §6.2, F-C1). The reference checks
    `grantSize` (`413`), then decoding and §C.1/§C.8 (`401`), then `rulesPerGrant` (`413`), then
    rule compilation (`401`), then the `ns` check (`403`) (`internal/grant/grant.go`
    `DecodeLimited`). A token that can't be parsed can't have its rules counted. *Propose:* state
    it.
74. **Key-scope rules and `rulesPerGrant`** (§12.2, F-C2). "Per grant chain" doesn't say whether a
    key's scope rules count; the reference counts only the token's blocks
    (`internal/grant/grant.go`).
75. **Limits at services** (§C.6, §C.8, F-C3). The index and tree service now answer an oversize
    grant or one over `rulesPerGrant` `413` `limit`, as the origin does
    (`internal/grantcheck/grantcheck.go` `LimitError`). *Propose:* say services apply both.
76. **`POST /edge-grants` refusal order** (§C.5.2, F-C4). The reference answers a body with
    `Authorization` `400`, then a body that isn't `application/json` `415`, then no grant at all
    `401` (`internal/server/edgegrants.go` `edgeGrantBearers`). *Propose:* state it.
77. **`"*"` in `ns`** (§C.4, F-C5). The reference answers a non-operator grant naming `"*"` `401` on
    every request (`internal/grant/verify.go`), and an operator grant at `/edge-grants` `401`.
    *Propose:* confirm.
78. **Narrowing roles over a root without roles** (§C.1, F-C6). The reference leaves no effective
    roles, so no verb. *Propose:* confirm.
79. **Revocation ids from before v0.71** (§C.4, F-C7). A namespace whose `revoked` lists an old
    root-signature id would silently un-revoke; the reference still honours that id for block 0
    (`internal/grant/verify.go`, `internal/grant/grant.go` `rootSigID`). *Propose:* allow it, or
    name a migration.
80. **`requireAt` in a branch, and without `maxTtl`** (§C.4, F-C9). The reference judges a base
    key's `requireAt` in the branch's own chain (`internal/core/auth.go` `checkAt`). With issuance
    fixed by `nbf`, a grant from a `requireAt` key without `maxTtl` and with no `nbf` now fails
    (`403`); the text says such keys SHOULD set `maxTtl`. *Propose:* state both.
81. **"There is no Authorization"** (§C.5.3). An empty `Authorization` header line is treated as
    present by `edge.Check` and as absent by the origin's pre-checks (`internal/edge/edge.go`).
    *Propose:* "carries no Authorization header field".
82. **Qualifying roles and fixed names** (§2.1). Role rules are checked for every fixed name, block
    and key rules once with the first name; that is sound only while they refer to `/resource`
    solely as fixing rules, which the reference enforces (`internal/grant/resource.go`). *Propose:*
    say so.
83. **The same principal without a recorded grant** (§7.2). How an entry with no recorded grant
    matches once authentication is on isn't said; the reference matches on `author`, registrations
    included (`internal/core/remote_branch.go`). *Propose:* say so.

From implementing v0.73: index (Addendum A).

84. **`min` naming another namespace on a single-namespace query** (§A.5, F-I1). The reference keeps
    v0.51's wait-and-redirect (`internal/index/http.go`, `strictMins` false). For a `min` naming a
    purged namespace there it still makes the read check, a temporarily skipped namespace's `min` is
    `503 behind`, and malformed `min`s are listed in the `400`'s `min` before the read check, with
    the refused well-formed ones added for a reader it admits. *Question:* strictly `400`, and the
    rest?
85. **Comma lists** (§A.4, F-I2). `counts`, `fields` and `sort` are each one comma-separated value
    in the reference, so a JSON Pointer token containing a comma can't be named. *Propose:* say so,
    or an escape.
86. **"Lacks keys" and "can't yet fetch keys"** (§A.4, F-I3). The reference's lack of keys is
    `client.ErrNoKeys`, an `e2e` namespace without a recipient key, any `4xx` from `/keys` and a key
    it can't unwrap; network errors, `5xx` and `429` are "not yet"; the `404` precedes the grant
    check (`internal/derived/keys.go`). A `401` from `/keys` lacks keys, while a `401` for a schema
    revision stays transient. *Propose:* one rule for "the service's own grant failed".
87. **Scores** (§A.4, F-I4). Say "from documents of `{ns}` the reader may see" for every namespace,
    public ones included. The reference counts FTS5 token instances (prefixes included) and phrase
    instances; implementations that tokenize differently score differently
    (`internal/index/query.go`).
88. **`x-index` collection** (§A.4, F-I5). The reference indexes nothing under an object marked
    `text`, gives invalid documents rows, doesn't full-text index numbers and booleans, and follows
    `dependentSchemas` only for members present, where §A.4 says marks are judged "whatever the data"
    (`internal/index/extract.go`, `internal/index/fields.go`). *Propose:* confirm.
89. **Why a resource purge purges `idx:{ns}`** (§A.1, F-I7). Give the reason (positional cursors,
    counts, corpus-dependent scores), and note that under a stream of purges, such as a retention
    sweep, "one redirect suffices" no longer holds.
90. **Index cookies** (§A.4, §B.11.5, F-I8). A `reads:{ns}:scope:{digest}` marker can only be
    authorised from a cookie if the service keeps what the digest covers; the reference stores the
    rules and the `/principal` values they read per marker until the last cookie expires
    (`internal/index/edgegrants.go`). Head pointers under the prefix (`/{ns}/g/{gs}?…`,
    `/_refs/g/{gs}?…`) follow only from §B.11.5 and aren't in §A.4's table. A namespace named `r` or
    `ns` can't get a cookie, its prefix lying under the core's; the reference leaves it out of
    exchanges. *Propose:* say each.
91. **Repeated `min`s** (§A.5, F-I9). The reference treats identical repeats as one, and two
    different bare `min`s as a refused-`min` `400` listing both.
92. **Reference extensions in §A.4.** The `gt`/`ge`/`lt`/`le` range filters aren't in the text; the
    reference requires a `sort` mark for their paths, compares strings by bytes and uses each
    document's least value. `schema=` with a trailing slash, a namespace-only path or a `/rev` path
    matches nothing. A facet path holding `"1"` and `1` shares one row, and a hit shows one of them
    (`internal/index/query.go`). *Propose:* specify or drop the filters, and say the rest.
93. **A grant naming no private namespace a service follows** (§B.11.5, §C.5.2). At another `gs`'s
    `/_refs` URL the reference answers `401` (nothing verified), while an exchange answers `403`
    (`internal/index/http.go`, `internal/index/edgegrants.go`). §C.5.2's "rules … don't pass now …
    with `/resource` set to each name it fixes" doesn't say whether one failing name refuses the
    grant; at a service that accepts non-fixing `/resource` rules the index refuses only when no
    fixed name passes. *Propose:* say each.
94. **Stored sealed results and purges** (§E.2.6, §A.1). Dropping stored sealed results on a raise
    or on turning private means a later read at an old `at` is redirected, not served the stored
    bytes (`internal/index/index.go` `dropWholePublic`). *Propose:* a sentence beside "stored once,
    served forever".

From implementing v0.73: tree and catalog services (Addendum B).

95. **`g/all` and purged namespaces** (§B.11.5, F-T1). A purged namespace can't be exchanged
    (`410`); should it be exempt from, or dropped from, the combined checkpoint? The reference also
    judges `g/all` against every trusted namespace, not only those in the checkpoint, since it
    records when each became trusted, so a trusted namespace whose document it can't read withholds
    `g/all` cookies from everyone (`internal/tree/edgegrants.go`).
96. **One checkpoint per `/read-grants` answer** (§B.11.5, F-T3). Refusals from state it doesn't pin
    can't be marked uncached; the reference adds no mark. A catalog node answered `400` adds no
    trusted namespace to the checkpoint (`internal/catalog/grants.go`). *Propose:* a per-item
    marker.
97. **Merge dry runs as the admin** (§F.8, §B.11.4, F-T4). The reference takes the admin's grant
    from `Admin-Authorization`, with the approver as the default, and requires the approver in
    `catalog-admins` for a widening merge, as scenario 44 says (`internal/catalog/mergegrants.go`).
    *Propose:* name the header and say the approver must be an admin.
98. **The place list and catalog-admins** (§B.11.4, F-T5). Does it apply to them (scenario 4)? The
    reference applies it to admins too (`internal/catalog/grants.go` `planPlace`).
99. **Plain tree services** (§B.11.5, §B.5, F-T6). Serving only `g/all`, they refuse limited grants
    `403`, which costs a gateway its filtered listings, and a preview, which has no §B.11, now
    refuses a viewer who can't read every branch (`internal/tree/http.go`). *Question:* intended?
100. **Uniform refusals** (§B.11.4, §B.11.5, F-T7). Require refusal messages that don't tell hidden,
     unplaced and never-existed names apart; a widening `403` still shows that some node below would
     widen, which the reference's generic message can't hide (`internal/catalog/mergegrants.go`).
101. **Cyclic nodes** (§B.11.5, F-T8) are hidden only by inference (scenario 8); the reference
     counts only walkable parents (live folders off any cycle), so a node whose parents all dangle
     stays an orphan (`internal/tree/graph.go`). *Propose:* state it.
102. **Tree powers and subjects** (§B.11.2). "When that subject's role has it at every one of them":
     the reference requires the same `(subject, role)` pair at every `parents` entry. `group:{g}`
     makes a group named `group:x` the subject `group:group:x`, while plain services keep prefixed
     groups. `POST /grants` matches a key's `sub` scope against the raw root `sub`, while listings
     and organising requests use the caller's listing subject set, which fails every `sub` scope
     without a `user:` subject. A key rule on `/action` or `/resource` hides every folder
     (`internal/catalog/catalog.go`, `internal/grantcheck/grantcheck.go`). *Propose:* say each.
103. **Deleted placements' rows** (§B.11.7). The reference drops them on purge (§8.3), keeps them
     whatever becomes of the item, and compares a re-place with no rows (placements deleted before
     an upgrade, or created and deleted between two applies) so only admins can re-place, with no
     checkpoint; an item deleted after its placement has empty frozen rows, so only admins restore
     it (`internal/catalog/catalog.go`). *Propose:* say so.
104. **Organising requests** (§B.11.4, §B.11.8). A missing `to` is `400` (only `to: []` asks for a
     root); a folder restore is `{node, want: ["restore"]}` or `{item, want: ["restore"]}`, `404`
     for a node that isn't untombstoned, `409` for a live one; a Move grant's `exp` runs from the
     service's decision, so an overtaken decision can be used for about 2 × `maxLag`; a refusal that
     stops before reading a content namespace names only the catalog in `checkpoint`; once every
     trusted namespace is purged only admins can reorganise (`internal/catalog/grants.go`).
     *Propose:* say each.
105. **Item answers** (§B.11.4, §B.11.5). The reference answers every item of an untrusted namespace
     `403` (the service can't tell a purge there) and `410 purged` first only for trusted ones;
     reads the Restore read check as one role counting both now and in the frozen rows; judges
     "counts for read" in `POST /grants` without evaluating rules, while `/read-grants` does, so
     they can differ; gives a public `e2e` item `public: true`; reads "accepted `$parents`" as
     implicit placements the graph keeps; and places the `403` for the catalog's key missing at the
     head after the decision's own answers (`internal/catalog/grants.go`). *Propose:* say each.
106. **Catalog merges** (§F.8, §B.11.4). An end-to-end catalog's step-2 batch that needs no
     `catalog-admins` (narrowing moves, unplacing) can't get a merge grant, so the reference's merge
     service refuses it and such a release can't proceed. A catalog service without a merge key
     answers `403`, not `404 not_offered`. A folder restore, and creating a folder a `parents` entry
     names (`409`, even for admins), aren't in §F.8's list (`internal/catalog/mergegrants.go`). §F.8
     doesn't say how a merge grant expresses its pairs; one alternative per item hits the default
     `rulesPerGrant` at 11 items, so the reference groups by action. *Question:* each.
107. **Listings** (§B.5, §A.4). `children`'s `next` is the following page's query in the reference
     (both forms accepted), not the bare `after` of `/_refs`. `born` is left out where the first
     revision's entry is pruned, and for implicit placements of sealed items; for other implicit
     placements it is the content document's first revision. `lookup` resolves only a node's own
     title, starts from the reader's roots where `root` is missing, is `404` for an empty segment
     and `400` without `path`, and answers `{at, path, node}`. `absent` has no reason for keys a
     service can never have (it says `pending`) and is in the clear. A cursor that reaches an `at`
     no longer kept restarts the folder, so children may repeat. v0.55's bare `after` is accepted
     for one release (`internal/tree/http.go`, `internal/tree/files.go`). *Propose:* say each.
108. **Service edge grants** (§B.11.5, §C.5.2). The `413` for a grant over the limits isn't placed
     in the all-or-nothing rule; the reference answers it first. "Its own `gs`" is read as its
     subject set's, so a grant qualifying for `all` reads its subject-set URLs too, filtered;
     subject-set listings of a public catalog still need a grant that verifies for it; and the
     `exchangeRate` bucket is keyed by the first content namespace that verifies a grant the catalog
     doesn't (`internal/svcedge/svcedge.go`). *Propose:* say each.
109. **Parents in organising answers** (§B.11.4, §H.5). No request returns a node's current parents
     without asking for a grant, so a gateway asks for a Move grant to read them; Unplace answers
     give only `head`, and Move answers leave `parents` out for admins
     (`internal/dav/catgrants.go`). *Propose:* `parents` in those answers too.

From implementing v0.73: merges, releases, imports and remote branches (Addenda F and G).

110. **The plan digest** (§F.9, F-F1). The reference leaves `gesture`, `undoes` and signatures out;
     a fresh `$nonce` op is an `add` or `replace` at exactly `/$nonce` with a value of the fresh
     form, and a root op's fresh top-level `$nonce` is dropped from its value; a second half's
     precondition is `{"batch": i, "item": j}`, indexed over the batches actually submitted, items
     in each batch by resource name (`internal/merge/plan.go`). The digest is agreed for a plan, so
     the item order decides the indices. A plan approved under the old digest resumes from its
     stored step digests. If one half of a split node changes nothing, its step has no item to name.
     *Propose:* show the form, fix the order, say each resolution set changes the node, and give a
     migration sentence.
111. **The merge lock** (§F.9, F-F2). The reference treats `{}` aside from `$nonce`, and an earlier
     `{"release": null}`, as free. Taking it sets `holder`, then `plan` in a second append, so a
     crash between them leaves a lock no service can release; the reference stores the plan first
     and lets the take set both when it can (`internal/merge/release.go`). *Propose:* say the take
     may set `plan`.
112. **The closing rule** (§F.6, F-F3). "An entry in a batch that counts there" doesn't say which
     batch; the reference requires a counting batch whose `source.at` is at or after the resource's
     last own entry, or a target head that equals or descends from the branch's revision as of
     `source.at`, and skips resources purged in the branch, which can never be merged
     (`internal/janitor/janitor.go`). *Propose:* that wording.
113. **Superseded and abandoned branches** (§F.6, F-F4). "Inherited" should say local bases only.
     For superseded, the reference requires the recorded `kid` to be a current `*` key of the old
     branch that the successor knows as the same key, treats a revoked root grant as not chaining,
     uses the old branch's base's `merge.authors`, compares a purge's `created` with the config
     write that began the current frozen run, restarts a period on a changed value but not on a
     removal, and, where several claims verify, purges as the first of merged, superseded, abandoned
     whose period has passed. A successor's grants are `410` after its purge, so the reference falls
     back to the old branch and keeps it for a manual purge otherwise
     (`internal/janitor/janitor.go`). *Propose:* say each.
114. **Merging details** (§F.3, §F.5, §6.4.1). The reference copies blobs before its dry run (the
     copies are pending and expire). An insertion into a nested array widens to the outer array, so
     it conflicts with edits to every other row; a `move` of an element onto itself writes the
     array. A sealed successor's `read` can't be seen without keys, so a rebase without them refuses
     rather than apply the rank rule (`internal/merge/writes.go`, `internal/merge/ranks.go`).
     *Question:* each intended?
115. **Remote branch creation** (§G.3, §G.5.2, F-F5). Verification failures stay `502 upstream`, not
     `422`; other `4xx`, `408` and `429` included, are `422`; a key B can't unwrap, or a body that
     doesn't parse or decrypt, is `502`. The raise "before at" is found from A's current document,
     since documents aren't covered by ids. A mirror ranking below its source is refused even if
     nothing would be written, a frozen one only where history would be written; mirror refusals go
     purged, rank, then per resource, frozen, `e2e`; `410` from a mirror carries `ns`. An operator
     grant's `ns` covers the branch only, and its rules judge only the branch's genesis, not the
     mirrors' (`internal/core/remote_branch.go`). *Propose:* say each, and that creation is judged
     against the source's current document.
116. **The registration retry** (§G.3, F-F6) is bounded by expiry only, with no `retryWindow`.
     *Propose:* confirm.
117. **End-to-end imports** (§G.4.4, §G.5.1, F-F7). The reference batches per epoch, in epoch order,
     with the bump between batches, so an atomic import is atomic per epoch; a source keyring that
     skips an epoch is crossed with a standalone config write. "Below the bundle's lowest" refuses
     an incremental bundle whose keyring starts at a rotation for a target one epoch behind; "above
     that of a line it lacks" is read as sealed lines only (`internal/bundle/import.go`). *Propose:*
     say so, and "the epoch before the bundle's lowest keyring line".
118. **Upstream imports** (§G.4.4). "The imports that wrote it" is read as batch entries whose
     `source` has `bundle`. The reference also nonces an existing upstream that doesn't require
     nonces when its target does, keeps the snapshot's `$nonce` in a non-sealed upstream's genesis,
     and needs read keys for a sealed target to rank it, refusing at step 1 otherwise. The `[]`
     restore exception for an incremental first line is judged from the target
     (`internal/bundle/import.go`). *Propose:* "or its target requires nonces", and the rest.
119. **The mirror genesis** (§G.3, F-F8) is exactly `{ "read": "grant" }` followed by the nonce
     config write; such a mirror has no keys, so until keys are added only an operator grant reaches
     it and readers of a private remote branch can't fetch its `$schema` targets. A schema namespace
     that is `e2e` at A ranks above any mirror, `422 invalid`, where `schema_unavailable` would tell
     more. *Propose:* say so.
120. **The sealed bundle framing** (§G.5.1.1, F-F9). The reference reads the decrypted lines
     strictly, but skips a blank line between JWE lines and accepts an envelope line that isn't
     canonical (`internal/seal/bundle.go`); it still reads `last` beside `pl`, as written before
     v0.73, and doesn't check that a line is padded to its bucket. Bundle ids, `K_b`, ephemeral keys
     and IVs are random, so sealed-bundle vectors are decrypt vectors. *Question:* must the envelope
     be canonical, may a JWE line be followed by anything but one LF, must readers refuse a
     top-level `last`, and should Addendum I take those values as inputs?
121. **`via` in history lines** (§G.4.1). The reference writes §7.1's form, only with `authors`, and
     its importer doesn't carry `via` into steps (`internal/bundle/format.go`). *Propose:* say so.

From implementing v0.73: gateways (Addendum H).

122. **What a folder `MOVE`'s `If-Match` names** (§H.5, F-H1). The reference takes the folder node's
     head, a tag clients can learn only from the catalog (`internal/dav/dav.go`).
123. **Weak tags** (§H.1, F-H2). The `PUT` answer is strong and the writer's next `GET` is
     `W/"{id}"`, so davfs2 refetches once; the reference compares `If-Match` on `GET` and `HEAD`
     with `W/` dropped, not strongly as RFC 9110 says (`internal/dav/dav.go`). *Question:* which?
124. **Records that expire** (§H.4, F-H3). "A path whose records expired counts as evicted": the
     reference expires per document (all records older than a day), bounds the marks, and treats a
     new file over the user's own delete as never recorded (`internal/dav/records.go`). *Propose:*
     say so.
125. **Saves and precondition corners** (§H.4, §H.5, F-H4). Editors that autosave an unchanged
     buffer after someone else's change now get `409`; intended? "No save recreates" a moved-away
     file is applied to saves only, so a `MOVE` back to the old name is allowed. The delete's
     `If-Match` is applied in the flat view too. An atomic save that sends `If-Match` is `412`, the
     scratch file having no revision. A malformed tag on a missing file is `412`, a stale
     well-formed one on `DELETE` `404`. The no-op compares bytes under the head's nonce, the
     conflict check counts any reference write by another (`internal/dav/write.go`). *Propose:* say
     each.
126. **A gateway with its own grant** (§H.3, §H.7, F-H5). Does "doesn't serve tree-derived trees"
     cover a single-bearer gateway? The reference has no narrowing mode: its local mode is one
     bearer for one user, its other mode passes each user's grant through. *Propose:* "holds its own
     grant and narrows it per user".
127. **COPY or MOVE onto an existing file** (§H.5, F-H7). Does the source's type or the target's
     win? In the reference the destination name's extension types the file, else the source's type
     does; the target's existing type isn't kept (`internal/dav/fs.go`, `internal/dav/files.go`
     `declaredType`).
128. **An operator grant at an absent namespace** (§H.7, F-H8): `404` before the `403`? The
     reference answers `404`, as the core does to an operator grant there (`internal/dav/dav.go`
     `verify`).
129. **The top level from `roots`** (§H.2, F-H9). The duplicate rule applies there; a new top-level
     write is `404`, and a top-level node's rename, move or delete `403`
     (`internal/dav/catalog.go`). *Propose:* a row in §H.4's table.
130. **A moved-away file where successors aren't trusted** (§H.4, F-H11). What does the `409` name
     in a sealed namespace? The reference makes no moved-away refusal there
     (`internal/dav/write.go`).
131. **Telling tree-derived access** (§H.2, §H.7, §B.12, F-H12). Nothing tells a gateway a tree has
     it. The reference probes `POST /grants` on the tree service (`404` or `405` means plain), and
     takes `$access` on a folder or an ancestor as the sign for refusing folder `COPY` and
     cross-tree folder `MOVE` (`403`), found part way rather than over the whole subtree first
     (`internal/dav/treesvc.go`, `internal/dav/catalog.go`). Delete-then-write restores under it
     would need a Place and a Restore grant, so the reference makes a new file. *Propose:* a marker
     such as `catalog.access: "tree"`, and say whether such copies may be refused.
132. **Folder copies and flat namespaces** (§H.2, §H.5). A copied folder is a fresh node as `MKCOL`
     makes it (no `x-` members, description or `$schema` of the source). A gateway without a grant
     of its own can't learn `files.ns` of a non-public catalog, so the reference keeps every served
     flat namespace read-only until some user's grant reads the catalog; untrusted placements count
     as dangling, so a folder `DELETE` deletes them first (`internal/dav/catalog.go`). *Propose:*
     say which tree owns a flat namespace (in it or in `/principal`), and the rest.
133. **Guards and case variants** (§H.2, §H.6). A refused `PUT` or `COPY` onto a folder sets a
     guard, a refused `MOVE` onto one doesn't; a case variant of a folder's name is refused whatever
     the request carries; `sed`'s six letters or digits are ASCII (`internal/dav/scratch.go`).
     *Propose:* say each.
134. **Which key a `kid` named** (§H.7). "A kid that named its key when written" needs namespace-
     document history; the reference judges kids as they name keys now, which is wrong after a `kid`
     is reused (`internal/dav/dav.go`). *Propose:* the entry's grant carries the key's thumbprint,
     or accept the current mapping.

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
