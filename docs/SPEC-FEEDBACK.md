# Reference-implementation notes for the spec writer

`docs/SPEC.md` mirrors the canonical specification, now at **v0.55**. This file collects what
the reference does that the text doesn't yet describe.

## Open

From implementing v0.51 and v0.52. Each gives what the reference chose.

1. **The prefix cap and the rate draw** (§C.5). "Once nothing is refused, the request draws
   one token", but the text doesn't say whether the `400` for more than 100 distinct prefixes
   counts as a refusal. The reference treats it as one and draws nothing. *Propose:* say so, or
   rank the cap after the draw.
2. **Undoing a genesis** (§11.2). "Impossible when the gesture's oldest entry lies at or before
   the oldest log entry it can read" makes a document's genesis impossible to undo even when
   nothing is pruned, since a log read from genesis has the genesis as its oldest entry. The
   reference exempts a log read from genesis. A gesture lying wholly below one named document's
   horizon but visible in another is undone in the other only, since resource logs carry no
   markers. *Propose:* "…at or before the oldest entry it can read after a pruning horizon",
   and say whether such a partial undo is acceptable.
3. **`/keys` for limited writers at E3** (§E.2.3, §E.3.2). That `/keys` relays a limited
   grant's own keyring entries, wrapped to its `enc`, without a read of the `keyring` resource,
   is only implied by "a writer limited to some resources needs [them] to seal". The reference
   does so. *Propose:* say it outright.
4. **What a catalog decision depends on** (§B.11.4). "The catalog's and the item's own
   namespace's entries, which are all it depends on", but a folder move's no-widening check
   reads `includes` from every trusted content namespace, and a folder's visibility needs a role
   in some trusted content namespace. Following the text, those decisions carry only the
   catalog's entry, so a cached one isn't invalidated by a `/roles` or `includes` change
   elsewhere. *Question:* should `checkpoint` name every namespace a decision read?
5. **`min` on a namespace whose items the reader can't see** (§A.5). Only a namespace the URL's
   `at` doesn't cover is `400`. In tree listings every followed namespace is covered, so for a
   content namespace whose items the reader can't see, `302` versus `503` reveals whether an
   `ns_id` is in its chain. The reference judges it normally. *Question:* intended?
6. **Subject-set cookies** (§B.11.5, §C.5). A cookie for `/{catalog}/g/{gs}` can't carry the
   subjects (the default format allows only `kid`, `p` and `exp`), so a service needs state
   mapping `gs` to subjects. The reference keeps it; `problems`, `orphans` and manifests, which
   need namespace-wide `read`, stay `403` under such a cookie. *Propose:* say so, or let a
   service's format carry more.
7. **`g/all` and trust changes** (§B.11.5). "`403` at an `at` that includes a namespace it
   didn't check at issuance" needs the issue time, which the cookie doesn't carry. The reference
   records issues in memory, and otherwise takes `exp` less 15 minutes, so with a shared key only
   full-length cookies read a newly trusted namespace for 15 minutes; such listings are
   `no-store` at the edge meanwhile. A namespace turning private under a live `g/all` cookie is
   left to the revocation latency. *Question:* should a service's cookie carry an issue time?
8. **`exchangeRate` at a service** (§6.6, §C.5). The bucket is the origin's; the reference's
   catalog service keeps one too, per process, so a principal draws on each instance's.
   *Question:* should services have it, and must it be shared across instances?
9. **A purged sealed namespace and `min`** (§8.5, §A.5). A service can't judge a `min` against
   a purged sealed namespace's log, which is `410`; the reference redirects to the current
   checkpoint. Its read check for such a namespace goes through the gestures listing, the one
   URL that still answers a limited reader. *Propose:* say how a service checks read on a
   purged sealed namespace.
10. **Restores and creates in a purged namespace** (§B.11.4, §8.5). §B.11.4 lists "a name
    that never existed is `404`, and a purged item `410`" without saying which wins in a purged
    namespace. Neither the core, which answers `410 purged` for every name there (§8.5), nor a
    service started after the purge can tell a name that never existed from a purged one, so the
    reference answers `410` for any name of a purged namespace. A create grant there is still
    `409` "exists or existed", as §B.11.4 states, though the core would refuse the write with
    `410`. *Propose:* say that any name of a purged namespace is `410`, for restores and creates.
11. **The `documentSize` default** (§6.6). Every write re-serialises, checks and validates the
    whole document, so a small append costs the document's size: measured at 1M documents and
    5M revisions, an append's p50 is 7 ms at 16 KiB, 15 ms at 1 MiB and 25 ms at 3.5 MiB
    (docs/CAPACITY.md), and every revision of a large document weighs on caches sized in
    documents. The reference defaults `documentSize` to 1 MiB and keeps 4 MiB as the deployment
    maximum a namespace may set (`serve -document-size`, `-max-document-size`). *Propose:* a
    1 MiB default, and say that a namespace may raise a limit up to the deployment maximum where
    the deployment's maximum exceeds the default (§6.6 now reads as defaults namespaces lower).
12. **Log pages of batch entries** (§6.6, §7.1). The log page size counts entries, and a batch
    entry carries its items, so a page of 1,000 batch entries of 1,000 items holds a million. The
    reference also bounds a namespace page by resource entries, a batch counting as its items: a
    page ends before an entry that would take it past the page size, and always holds one entry,
    so a batch larger than a page is a page of its own. *Propose:* say the page size bounds
    resource entries too, or that a page may be shorter for that reason.

From implementing v0.53 and v0.54.

13. **Moving a schema** (§6.5, §8.1). Only a fresh `$nonce` is exempt from a schema document's
    keyword check, so a schema with `$successor` is refused as an unknown keyword, and a schema
    resource can't be moved as §8.1 describes. The reference leaves it so. *Propose:* exempt a
    well-formed `$successor` there too, or say schemas aren't moved.
14. **`If-Modified-Since` where no `Last-Modified` is sent** (§7.1). The reference ignores it at
    E2 and E3 (RFC 9110 §13.1.3): a `304` there would let a reader probe for the created time the
    spec hides. *Propose:* say it applies only where `Last-Modified` is sent.
15. **The reason given for E3** (§7.4, §E.4). "`created` is hidden in the sealed log" isn't so at
    E3, whose resource and namespace logs serve `created` in the clear (§E.3.1, §F.8.1); the rule
    holds there for the other reason (exact lengths defeat padding). *Propose:* give that reason
    for E3.
16. **`/raw`'s caching and read check** (§7.1). "As the document URL it stands for" leaves the
    error answers open: the reference caches the `302`, the not-raw `404 not_found` and `404
    not_offered` with the URL's class (head pointer or immutable) and the tag `r:{ns}/{name}`, and
    uses the ordinary read check for both raw URLs (a `schemaReads` referrer opens revision paths
    only). *Propose:* say both.
17. **`logPageBytes` at E2** (§7.1, §E.2.2). Counting plaintext patch sets leaks exact sizes through
    where pages end (`X-Log-Next`, the long-poll `X-Revision`) in padded namespaces. The reference
    counts each entry's JWE as served (the stored one, or one sealed for the page), and stops its
    scan early on stored plaintext, a lower bound unless a JWE is compressed, which a padded one
    never is. *Propose:* say "as served" means the sealed bytes at E2.
18. **Moves across bundles, renames and deployments** (§G.3, §G.4). A deleted resource's snapshot
    line has no document (§G.4.3) and an upstream import appends only a tombstone, so `$successor`
    travels in history bundles only (the v0.54 change log says it travels with them); a renamed
    import (§G.4.4) doesn't rewrite a cross-namespace `/r/{ns2}/{name2}` and the closure (§G.4.2)
    doesn't follow it; through a remote branch (§G.3) it resolves on the branch's deployment, not
    the base's. *Propose:* say which of these a successor survives.
19. **Moves by catalog-limited editors** (§B.11.4, §8.1). Their grants fix one name, so the
    one-batch move (create the new resource, append to and delete the old) takes two requests or a
    grant fixed to both names.
20. **`gone` in §12** doesn't repeat §8.1's "outside sealed and end-to-end namespaces" for
    `successor`; the reference follows §8.1.
21. **Which writes count as whole documents** (§6.6). Worth saying that a root `replace` or `add`
    followed by further operations still counts (the reference allows it), and a root `copy`,
    `move` or `remove` doesn't.
22. **Blob headers** (§7.8). Chromium's PDF viewer shows a PDF served with
    `Content-Security-Policy: sandbox` as a blank page (Atlassian documents it for Jira 8.16+ and
    exempts `application/pdf`), so raw PDFs don't display inline. The reference also sends both
    headers on the request-shape `400`s answered before routing, whose body echoes a parameter's
    name. *Propose:* state the PDF cost or allow an exemption (e.g. as an attachment), and say
    "every response to a blob URL".
23. **Trusting a `410`'s successor** (§8.1, §11). A conforming server names none in sealed or
    end-to-end namespaces, so one there comes from the server (at E3 outside the trust boundary)
    or a cache. The reference's E3 client reads `$successor` from the verified document at `last`
    and ignores a `410`'s. *Propose:* say so in §11, and that sealed-namespace clients that don't
    trust caches do the same before following one automatically.
24. **Stored digests at rest** (§E.1, §7.4). A server that stores `/heads` `size` and `digest`
    keeps a plaintext sha-256 of each head's document beside its encrypted content, as ids hash
    patch sets (§C.7): a dump or backup, even one from before a purge, confirms a guess of a
    document without a `$nonce`. The reference documents it; it also purges cached `/heads` pages
    on a resource purge (a `heads:{ns}` tag), beyond §8.3. *Propose:* say this in §E.1, or
    suggest computing digests at read time at rest.

From implementing v0.55, in the core and the tree service.

25. **`/principal` and operator grants** (§7.4, §C.4). §7.4 shows `/principal` to "any grant that
    verifies", operator grants included, but §C.4 makes "Any other request under one" `401`. The
    reference answers `200`, with `can` the operator grant's block verbs and `roles` `[]`. A
    gateway keys users by root `sub` and `kid` (§H.7), and `kid`s are free-form, so an operator
    grant whose `kid` equals a namespace key's passed for that key's user, scratch files included,
    though every core request under it is `401`; the answer doesn't say which kind of key verified
    it. The reference's gateway reads the operator key history (`jwks_uri`, §C.4, no grant needed;
    kept five minutes, the last read used if a read fails, and none read meaning closed) and refuses
    a grant whose root `kid` is in it and whose chain verifies under that key. *Propose:* list
    `/principal` among §C.4's exceptions, and say what `can` and `roles` mean there; and either add
    `"operator": true` to the answer, or say in §H.7 that a gateway tells the keys apart by the
    history.
26. **`/principal` without authentication** (§1, §7.4). Not specified. The reference answers `200`
    without `principal` and `kid`, with `can` every verb, `roles` `[]` and `writer` as usual, and
    `404` for an absent namespace. *Propose:* say so.
27. **`writer.nonce` in sealed namespaces** (§7.4, §E.2.5). The reference says `"required"` at E2,
    where §E.2.5 requires a fresh `$nonce` in every patch set, `"optional"` at E3, and elsewhere the
    document's setting. *Propose:* say "required where nonces are required or the namespace is
    sealed".
28. **What `writer.limits` holds** (§6.6, §7.4). The reference lists every key of §6.6, the
    deployment-only ones at the deployment's values, and applies neither allowances nor the
    key-scope `rate`. It holds a namespace to its own `rulesPerGrant` and `grantSize`, and to its
    own `rulesPerNamespace` on a creation or a config write that changes `/rules` or
    `/limits/rulesPerNamespace`, even a write that lowers a count still over the bound; other
    writes, freezes included, still pass a document an earlier release stored over it. *Propose:*
    say whether allowances apply, and whether a namespace's own bound holds every config write or
    only those that change the rules or the bound.
29. **`catalog.files`'s shape** (§7.4, §H.2). The reference takes `root` as a folder name (a
    resource name without a dot), doesn't require `ns` to be in `trust` (the gateway checks it,
    §H.4), allows `x-` members inside `files`, and checks `folder` and `placement` as schema
    revision paths only. *Propose:* say "`root` is a node name", and confirm the `x-` members under
    §7.4's rule.
30. **The sealed form of `file`** (§H.3, §E.2.6). §E.2.6's per-entry `"sealed"` holds values of the
    entry's own resource, such as a sealed catalog's title under the placement's `K_r`; a value
    derived from another namespace's resource needs a member of its own. The reference uses `"file":
    { "sealed": JWE }`, the plaintext `{ "file": { … } }` under the item's `K_r`, with `kid` the
    item namespace's current epoch and `pl { ns, name, view }` naming the item, padded as that
    namespace pads. §E.2.6 allows whole-response sealing only when every sealed value comes from one
    namespace, so for a sealed catalog read whole the reference still seals the response under the
    catalog's `K_e` and nests `file` sealed per entry, and marks the form provisional. While a
    sealed content namespace's epoch key can't be fetched it answers `503`, not a listing without
    `file`, which "stored once, served forever" would keep; stored listings are keyed by URL and
    reader shape, as kept ones are. *Propose:* define a per-member sealed form for values of another
    source and allow or forbid the nesting, and say that a stored view is per URL and reader shape.
31. **`modified` where `created` is unknown, which placements get `file`, and why one lacks it**
    (§H.3). The reference leaves `modified` out and still gives `size` and `type`, and adds `file`
    to the placements of every trusted namespace, implicit ones included, not only `files.ns`'s. A
    placement without `file` is either an end-to-end item or a head the service hasn't read yet, and
    a tool has to read the namespace document to tell them apart: the reference's gateway leaves out
    a placement in a sealed or end-to-end namespace that has none, and reads the item from the core
    for any other entry without `file` or `modified`. *Propose:* say "`modified`, the head's
    `created`, where known", whether `file` is limited to placements of `files.ns`, and give a
    reason where `file` is absent, e.g. `"file": { "absent": "e2e" }`.
32. **Limit refusals for bounds that aren't §6.6 keys** (§6.6, §12, §C.5.2). Prune and `/keys`
    bodies over 1 MiB are `400 bad_input`. A resource `PATCH` body over 4× the larger of
    `patchSetSize` and `documentSize` names `documentSize`, with the deployment maximum. A `POST
    /edge-grants` body over room for 50 grants of `grantSize` is `400 bad_input` with no sizes,
    following §12's row ("an edge-grant exchange over its limits") and §C.5.2's `400` for more than
    50 grants; one grant over `grantSize` is `413` once decoded. Where reading stopped, `measured`
    counts body bytes, not canonical ones. *Propose:* list the oversized body in §C.5.2's table with
    the 50-grant row.
33. **The E3 inequality** (§6.6 Values). A config write that fails `3 × (valueSize + pathSize) + 1
    KiB ≤ patchSetSize` is `422`, but the text names no `limit` for it. The reference names
    `patchSetSize`, with `measured` the left side as §6.6 defines it for E3 and `max` the
    `patchSetSize`. *Propose:* say so.
34. **`429` bucket names** (§6.6). `limit` is `"allowance"` or `"allowance.blobRate"` for an
    allowance's buckets, which aren't §6.6 keys. *Propose:* name them.
35. **`measured` for the other limits** (§6.6). `pathSize` and `valueSize`: the first value found
    too long, quotes included. `branchesPerNamespace`: the live branches including the new one.
    `blobPending`: pending bytes plus this blob, counting at least 4 KiB each. A blob without
    `Content-Length`: `blobSize` + 1. Durations and rates: `limit` alone. *Propose:* say "first
    found" for the first, and the others as chosen.
36. **`readScope` at verification** (§C.2, §C.4, §C.6). The reference applies a key's `readScope:
    "resource"` in grant verification, which the core and the services that verify grants locally
    (§C.6: tree, catalog, index) share. A read grant from such a key that doesn't fix `/resource` is
    a key-scope `403` on every request, writes included, and `404` on a read of a private namespace
    at the origin; services treat it as reading nothing. Before, services counted it as reading per
    resource, and every name passed. *Propose:* confirm in §C.2 that the `403` holds on every
    request, and say in §C.6 that services apply key scopes, `readScope` included, as the origin
    does.
37. **`/principal` and rate limits** (§6.6, §7.4). The reference draws no token for it. *Propose:*
    say so.
38. **`measured` shows a document's size to a writer without `read`** (§6.6, §E.2.2). For
    `documentSize`, `nestingDepth`, `valueSize` and `pathSize`, `measured` describes the resulting
    document. A writer with `append` but not `read` can send k root copies (`{ "op": "copy", "from":
    "", "path": "/a" }`) and recover the document's exact canonical size, 2^k·S plus a constant,
    from one `413`. That holds at E2 too, where `/heads` omits `size` because an exact length
    defeats padding. Probing with `test` operations, or bisecting the old refusal, already gave it,
    so this is faster, not new. *Propose:* say whether `measured` for a limit on the resulting
    document is left out, or rounded to the padding bucket at E2, for a grant that doesn't allow
    `read` of the resource. The reference follows the current text and gives it.

From implementing v0.55, in the WebDAV gateway (Addendum H), tried with rclone, davfs2, vim and sed.

39. **JSON saves with several candidate bases** (§H.4). Without a tag, the base is the record with
    the fewest differing paths, and the save conflicts if "the closest records disagree". Taking the
    closest silently dropped a value the user had set back to an older one (an undo of their own
    save, together with a new edit). The reference makes a save `409`, naming the paths, when any
    two of the user's versions, taken as the base, would apply it differently, even if each is safe.
    The cost: a user whose client sends no `If-Match` and who adds a field, saves, then removes it
    while editing something else gets one `409` and reloads. *Propose:* say the check runs over all
    the user's versions, not the closest.
40. **A revert of someone else's change after a reload** (§H.4). A user reloads after someone else
    changed `/a`, then sets `/a` back and saves with no tag. The reference merges the save and keeps
    the other value, so the revert isn't applied and the next read shows it. The data is the same as
    for a stale editor buffer saved after a preview pane read the newer revision, which the other
    base would overwrite, so the gateway can't tell the two apart and takes the safe one. *Propose:*
    say that, without a tag, a save that sets back a value someone else changed is merged, and that
    only the client's `ETag` settles it.
41. **Raw saves against every version the user had** (§H.4). Without a tag, "the record with the
    fewest paths differing" has no paths to count in a raw file, and picking one by size gave false
    `409`s on a user's own consecutive saves whenever a size equalled an older version's. The
    reference checks a raw save against every version the user had (the `If-Match` revision, else
    every version served to them or written by them), and conflicts only if someone else changed the
    bytes, or deleted or restored the file, after any of them; the user's own writes are remembered
    as theirs. A user who reloaded early gets one `409` before the next save passes, which keeps the
    stale-buffer protection of 40. *Propose:* say this for raw files.
42. **Records per path** (§H.4). The text keeps records per user and file, but clients save to
    paths, and a path can come to name another file between a read and a save (a rename, an expired
    tree listing). A save without a tag then found no records and took the head as its base. The
    reference keeps the document last read whole or written under each path with the records: a save
    without a tag at a path that now names another document, or none, is `409`, and a `GET` of the
    path is the reload; the user's own `DELETE` or `MOVE` forgets the path. A save whose `If-Match`
    names a revision where no file is (a new name in a tree, a flat name that never existed) is
    `412`, not a create; a flat name someone deleted since stays `409`, as the table has it.
    *Propose:* say records are per path, and that a base on a path with no file is `412`.
43. **What counts as others' writes** (§11.3, §H.4). The reference takes the paths that differ
    between the documents at base and head together with the writes of the log entries between them,
    so a value changed and changed back is a conflict, and leaves out the user's own entries. It is
    stricter than §11.3's `theirs`, never looser. Its `409` for a pruned base covers a base it
    recorded, and a pruned range between base and head, not only one named by `If-Match`. *Propose:*
    say whether the user's own entries count, and that a pruned base includes recorded bases and
    ranges.
44. **Reloading a deleted file** (§H.4). After a `409` because someone else deleted the file, the
    reload the text asks for is a `GET` that finds it gone (`404`), and the text doesn't say what
    that reload is worth. In the reference the `409` lasts until that `GET`, after which a save
    makes the file anew, with a root `replace` that drops any `$successor`. *Propose:* say that the
    `404` is the reload, and whether the next save may recreate the file.
45. **Scratch names missing from the list** (§H.6). Real clients use more names than the list has:
    JetBrains' `*___jb_old___`, which pairs with the listed `*___jb_tmp___` (its safe save moves the
    original aside under it, a move that is `403` without it); LibreOffice's `.~lock.NAME#`, which
    in a tree otherwise creates and deletes a real file at each open; vim's `.swx`, `.swo` and the
    like (`403` in the flat view; vim warns but saves); `sed -i`'s `sedXXXXXX`, which in the flat
    view is neither a resource name nor listed, so `sed -i` fails there; macOS's `Icon\r`, a custom
    folder icon whose CR (`Cc`) makes it an invalid title; and the system folders `.Trashes`,
    `.Trash`, `.Trash-{uid}`, `.Spotlight-V100`, `.fseventsd` and `.DocumentRevisions-V100`, besides
    `.TemporaryItems`. The names a file manager gives a copy made beside a file contain a space, so
    no resource has one; in the flat view the reference takes them as scratch only as `COPY`
    destinations, and a plain `PUT` of one is `403`. It first took every dot folder as scratch, and
    what was put in one never reached the core; now only listed folders are scratch, and any other
    is a real folder in a tree. *Propose:* add the names, and say that a folder is scratch only if
    listed.
46. **The move-aside window and restores** (§H.5, §H.6). §H.5 accepts vim's create-only `PUT`
    "within a few seconds", with the head as its base. davfs2 uploads 10 s after the file is closed,
    so the reference uses 30 s, as for delete-then-write, and takes the base as for any untagged
    save (the user's records, else the head): with the head as base, edits others made after vim
    opened the file are overwritten. A restore whose patch set is over `opsPerSet` or `patchSetSize`
    is written as a whole-document `replace` when its base is the last live document. *Propose:* say
    30 s and the base in §H.5, and the `replace` for restores in §H.6.
47. **Guards and deliberate deletes** (§H.6). A refused `PUT` makes that user's `DELETE` of the path
    `409`, once, for 10 s, and a guard "ends only by time". The reference lets a `DELETE` that
    carries `If-Match` pass, since a client that sends one means it, but leaves the guard, so
    rclone's cleanup `DELETE` in the same 10 s is refused once even after the user's own. *Propose:*
    say whether an `If-Match` `DELETE` passes, and whether it ends the guard.
48. **Case folding** (§H.2). The reference first folded with full Unicode case folding (`ß` as `ss`,
    `ﬁ` as `fi`), merging names that Windows (NTFS, simple uppercase mapping) and Linux keep apart;
    it now uses simple folding. It folds by default (`-case-sensitive` turns it off). "Tools refuse
    to create a name a sibling has", but a `PUT` onto a sibling's name under another case edited the
    sibling, so Linux rclone and davfs2, which copy `a.txt` and `A.txt` as two files, wrote one over
    the other. Now a `PUT`, `COPY` or `MOVE` to a name that matches a sibling only under another
    case is `409` naming the sibling, and sets a guard, unless the request carries a tag or the user
    read or wrote that file under this spelling. `MKCOL` under another case is `405` (the folders
    merge, nothing is lost), and a folder in the middle of a path matches whatever the case.
    *Propose:* say "simple" folding, and that a case variant is refused with those exceptions.
49. **Names a gateway receives** (§H.2). Titles are NFC, but clients such as macOS's send NFD: the
    reference converts it to NFC rather than refusing. It refuses a trailing space or dot on create
    and rename for every client, since it can't tell a Windows one, and shows an existing one
    escaped. An escaped title (`a/b.txt` shown as `a%2Fb.txt`) never takes a real title's name, and
    a numbered duplicate stays within 255 bytes. *Propose:* say NFD is converted, that the trailing
    rule holds for every client, and how escapes and duplicate numbers meet real titles and the
    length limit.
50. **Folders with children the user can't see** (§H.5, §B.11.5). The text deletes a folder only if
    it has no visible children, which lets a folder be deleted while placements of items the user
    can't read stay in it. The reference neither names nor deletes them, so they become orphans
    (§B.7). *Question:* intended, or should such a folder be `409` without naming them?
51. **A partial move between namespaces** (§H.5). If the source's delete fails after the copy, the
    client gets the error and the copy stays; there is no rollback. The reference deletes the source
    only with `If-Match` naming the revision it copied (in a tree it checks the item's head before
    the placement goes), so a source that changed since is `409` and stays. *Propose:* say that the
    delete names the copied revision, that a failed delete leaves the copy, and that a changed
    source is `409`.
52. **Locks and dead properties** (§H.6, §H.8). `PROPPATCH` is "refused, or kept in the gateway";
    the reference first answered `200` and kept nothing, which is neither. It keeps values per user
    in memory (1 MiB per user, dropping the least recently set path's rather than refusing), moves
    them with a `MOVE` and drops them with a `DELETE`. Locks follow the same events: a `DELETE`
    drops the user's locks on the path and below (RFC 4918 §9.6.1), and a `MOVE` or `COPY` sent with
    the source's lock token isn't `412` for want of a lock on the destination. *Propose:* say that
    accepted properties are kept per user and follow the file, and that locks follow `DELETE` and
    `MOVE`.
53. **First-seen times** (§H.3, §H.7). §H.3 has a gateway without keys show "the time it first saw
    the revision, kept across restarts" in sealed and end-to-end namespaces, but §H.7 has it not
    offer them, so a keyless gateway never meets the case. The reference keeps the times it records
    in memory only. *Propose:* drop the clause, or say which gateway shows these namespaces without
    keys.
54. **Empty files and new names** (§H.1, §H.6). Tools create empty files (`touch`, `.gitkeep`,
    `__init__.py`) and `LOCK` a name before writing it. The reference makes or truncates a 0-byte
    raw file for an empty body (over a JSON file it is `400`), and keeps an in-memory placeholder
    only for a `LOCK` of a new name or a new `.json` name; it first answered `201` for an empty body
    and kept nothing, so no one else saw the file. *Propose:* say an empty body is a 0-byte raw
    file, and what a new empty `.json` name is (raw by §H.1, since an empty body isn't I-JSON, yet a
    placeholder until it is filled).
55. **A file's type on re-save** (§H.1). The reference works a raw file's type out again from the
    name and the upload at every save, as the text reads, so a file whose extension isn't in the
    table, saved by a client that sends no `Content-Type`, becomes `application/octet-stream` though
    it was stored with another type. *Propose:* say that an existing file keeps its type unless the
    extension is in the table or the upload names one.
56. **Headers on a gateway's other answers** (§H.6, and 22). §H.6 asks for `nosniff` and `sandbox`
    on raw bytes. The reference sends them on every answer, JSON and scratch files and error bodies
    too, which repeat names the client sent, and answers `POST` to a file with `405` and `Allow`: a
    `POST` had served the bytes without them. *Propose:* say "every response", as 22 does for blob
    URLs.
57. **Who owns `files.ns`** (§H.2, §H.5). A gateway deletes the item "where the tree owns
    `files.ns`", but it can't see other catalogs to know whether any trusts the namespace. The
    reference takes the tree to own it when the item is in `files.ns`. *Propose:* say how ownership
    is known, or that "owns" means the item is in `files.ns`.
58. **New files: the dry run before the upload** (§H.4). §H.4 lists the upload of a raw file's blob
    first. The reference dry-runs the placement before the upload, so a refused placement uploads
    nothing. *Propose:* say that order.

From the second round on v0.55, in the WebDAV gateway and the tree service it lists through.

59. **Which namespace names a user** (§H.7, §C.1, §7.4). "Keyed by the root `sub` and `kid` (from
    `GET /ns/{ns}/principal`)" is neither unique nor stable. A `kid` names a key in one namespace's
    document, so `(sub, kid)` is unique only within a namespace, and a gateway serving several, one
    of them controlled by another party, would merge different people into one user. The reference
    keys users by the namespace that verified the grant as well. A grant that names several then
    has several candidates, and the answer changes over time: a namespace created, or given the
    key, later and sorting first made the same token, or the person's re-minted one, someone else,
    which dropped their scratch files and records, and a save without a tag then reverted another
    user's edit. The reference asks the namespace that accepted the token before, then the one that
    first accepted a grant of its root `kid`, then the rest sorted; a token still verified as
    someone else has its old user's documents marked lost for the new one, so its next save without
    a tag is `409`. A token narrowed to drop the namespace that verified the person's other tokens
    is another user. Asking several namespaces, a `401` is also all a gateway learns of an absent
    one (only an operator grant gets the `404`, §7.4), which it can't tell from a revoked grant.
    *Propose:* say that a user is the namespace, `sub` and `kid`, with the namespace that first
    verified the `kid` where a grant names several, and that a token narrowed away from it is
    another user; or return something stable for the key (a thumbprint) or the user in `/principal`.
60. **What a user's tokens share** (§H.6, §H.7). §H.6 serves scratch files "only to that user", and
    §H.7 keys all gateway state by user, but a user's tokens aren't equally able: one narrowed by
    `ns`, `can`, rules or `via` may read less than the one that wrote a swap file, or than the one
    whose move aside (§H.5) copied a document into the scratch store. "Keyed by the root `sub` and
    `kid`" covers re-minted tokens, not narrowed ones. The reference found a token that had dropped
    a namespace reading the user's scratch files in it, and one narrowed by resource rules or `via`
    reading backups of documents the core refused it. It keeps what holds content (scratch files,
    locks with their owner, dead properties) per user and scope, the scope being a digest of the
    grant's narrowing blocks without `nbf` and `exp`, so tokens an issuer mints for a person share
    one, and serves it only to a token whose grant names the namespace. What holds none (guards, a
    user's own deletes, move-aside flags, records, the writes a listing waits for) stays per user,
    and what was read (documents, catalog graphs, tree listings, writer blocks) per token.
    *Propose:* say that scratch content is never served to a token narrower than the one that wrote
    it, nor outside the namespaces its grant names, and that caches of what was read are per token.
61. **Re-checking grants and the writer block** (§H.7, §7.4, §C.5). §H.7 has a gateway re-check a
    grant "at least as often as edge grants expire (§C.5)", but a deployment may set that lifetime
    below the 15-minute cap and a gateway can't learn it. `/principal` is `no-store`, and nothing
    says how long a writer may rely on its writer block, or what becomes of a user's state when
    one of their tokens is refused while others are still accepted. The reference re-checks a
    grant every five minutes by default (a longer setting than the cap is refused), relies on a
    writer block for 30 seconds or that interval if shorter, and refreshes it on `409 frozen`,
    `422 nonce` or a limit refusal. A refused token leaves the user's state, and the others are
    re-checked at their next request. *Propose:* state a maximum, such as five minutes, or expose
    the lifetime in `/principal` or the deployment document; and say the rest.
62. **Limited grants and the tree's settings** (§H.7, §7.4, §B.5). §H.7 says a grant limited to some
    resources "learns what it needs to write from `GET /ns/{ns}/principal`", but the writer object
    doesn't carry `catalog.files` (`ns`, `root`, `folder`, `placement`) or `catalog.trust`, which
    live in the namespace document, which needs unrestricted read, and the tree service's listings
    don't either. Such a grant can list a tree, but can't find `files.root`, say where a new file
    is created (§H.4) or which namespaces the catalog trusts. The reference's gateway uses the
    settings as last read with any grant, its own at start included: the one thing read with one
    grant and used for another, settings and not content, with the core and the tree service still
    checking every grant. A limited grant meets `404` for the tree until another has opened it,
    and can't write in it. *Propose:* add `catalog.files` and `trust` to `/principal`'s writer
    object, or give the tree service an endpoint for them.
63. **`catalog.title` and untitled placements** (§B.5, §H.2). A listing entry's `title` is the
    placement's own or, where the catalog sets `catalog.title`, the item's, but §H.2 shows a
    placement without a `title` by its item's name, and entries don't say which they carry. The
    reference lists a catalog that sets `catalog.title` from its node documents, not through the
    tree service. *Propose:* a separate member (e.g. `itemTitle`), or say that `catalog.title` is
    ignored, or refused, in a file tree.
64. **Numbering duplicates from a listing** (§H.2, §B.5). "In order of the nodes' creation in the
    catalog's log" can't be done from a `children` listing, whose entries carry no creation time or
    sequence, so a tool reads each duplicate node's head and first log page from the core (two
    requests each) every time the folder is listed. *Propose:* the tree service gives each node's
    genesis `created` or a sequence, or numbers duplicates itself (see §H.9's question on flagging
    collisions).
65. **Untrusted placements** (§H.2, §H.3, §B.6). The tree service marks placements of namespaces the
    catalog doesn't trust dangling and leaves them out, but §H.2 and §H.3 don't say whether a
    gateway that builds folders from node documents must too, and the two sources can disagree.
    The reference leaves them out of both when a tree service is configured, so the fallback lists
    a folder as the service does, and lists them without one. *Propose:* say that a gateway leaves
    out placements of namespaces the catalog doesn't trust.
66. **A tree service that is behind** (§B.5, §H.3). Nothing says what a listing answers while the
    service has the catalog but not a content namespace it trusts (a fresh database, a rebuild, a
    namespace trusted lately). The reference answered `200` with every placement dangling, so
    folders listed empty, which a sync tool mirrors as every file deleted and a gateway took for
    folders it could delete. Listings are now `503 behind` with `Retry-After`, naming the
    namespace, until the service holds a checkpoint of the catalog and of each trusted namespace. A
    trusted namespace it can't follow isn't waited for, or every listing would stay `503`: one
    purged, one skipped for its keys (Addendum E), one the core refuses it (`401`, `403`) or
    doesn't have (`404`); its placements dangle (§B.7). A catalog that trusts a large new namespace
    is `503` until the service catches up. The gateway passes the `503` on and deletes no folder
    meanwhile. *Propose:* say that a tree service answers `503` with `Retry-After` until it holds a
    checkpoint of every namespace it follows, and what it does about trusted ones it can't follow.
67. **Read-your-writes in a file tool** (§B.5, §A.5). §B.5 has a client add `?min={ns}:{ns_id}` from
    its write's `X-Namespace-Revision`, but not how a file tool keys mins to its writes or how long
    it keeps sending them. The reference notes every entry a write produced, the catalog's and a
    content namespace's alike, and sends them as `?min` for the catalog and the namespaces it
    trusts until a listing that carried them returns `200`. It first dropped them after 30
    seconds, and a service lagging longer brought back a renamed file's old name and dropped its
    new file, so a sync client deleted the one and uploaded the other again. A `min` the service
    refuses (`400`) is dropped after one listing from the node documents. There is no way to ask
    whether a listing already includes a `min` without waiting for it, so the gateway waits a few
    seconds and then lists from the node documents; and since a `min` naming a namespace the reader
    can't see is `400` (§A.5; compare 5), a write-only grant can't wait for its own writes.
    *Propose:* say that a tool keeps each `min` until a listing that carried it returns, and how a
    grant without `read` waits.
68. **Writes against a lagging listing** (§H.3, §H.5). §H.3 lists a tree through the tree service,
    which lags the core and doesn't wait for other users' writes through the same gateway, and
    says nothing of writes taking names from it. Resolving a path to what its folder listed, a
    short lag was enough for a `DELETE` or `MOVE` of a name another user had just changed to
    delete or re-parent that file, for a folder `DELETE` to take its emptiness from the listing
    and orphan a file just put in it, and for a `PUT` to make a second file of a sibling's name.
    The reference checks what the listing named against the node documents before every write:
    each node still in its folder by that name, and no node by a name the listing lacked. Where
    they disagree it reads the graph again, and then resolves the path from the node documents, as
    without a tree service: the stale `DELETE` is `404`, the `PUT` an edit of the renamed file, a
    `MKCOL` of an existing folder `405`. A `PUT` onto a name only a sibling hidden from the token
    has makes the new file, so its existence isn't revealed. Against changes the graph doesn't
    show either (another program's), a delete carries `If-Match` on the head it read (`409`), a
    move checks the node's document still has the name and parent the path named (`404`), and a
    folder's emptiness comes from the node documents, never the listing. A grant that can't read
    them keeps the listing. *Propose:* say that writes resolve, or check, names against the node
    documents, and take a folder's emptiness only from them.
69. **Large folders and titled paths** (§B.5, §H.3). §B.5 pages `children` with no total and no
    advice on how far to page or what to answer for an over-large folder; truncating is dangerous
    for sync clients, since `rclone sync` deletes what it doesn't see. The reference lists up to
    10 pages of 1,000 and answers `403` for a folder beyond that, never a cut-short one; a path in
    or below it finds its name in the node documents, reading only the items whose names match (it
    had refused every path there, `GET` and `PUT` included). And "a folder is then listed in one
    request" holds for a listing, but a path of titles still takes one `children` listing per
    folder on it. *Propose:* say what a tool answers for a folder it won't list whole, give
    `children` a total, and add a lookup by title path to the tree service, filtered like
    `children`, which would make a `GET` one request.
70. **Refusals from the tree service** (§H.4, §B.5). §H.4's table has nothing for the tree
    service's `401`, `403` or `503`, and where a gateway uses its own grant (local mode) it can't
    tell the user's grant being refused from its own. The reference answers `502` for a service it
    can't reach, `503` with the service's `Retry-After` for its `503` and `429`, and `410` for a
    purge, and passes `401` and `403` through, the token being checked again at its next request
    as after a core `401`. In local mode a tree-service `401` is `502` naming the service, since
    it would be taken for the core refusing the gateway's grant. *Propose:* add the rows: a
    refusal from the tree service is answered as the core's would be, except that one the user
    can't fix names the service.
71. **The gateway's own `413`s** (§H.4, §6.6). §H.4 answers a limit exceeded "with the limit and the
    sizes the core gave", which says nothing of a bound the gateway has itself: its upload buffer,
    a file-size flag, or a namespace limit it checks before sending (`blobSize` before an upload;
    `opsPerSet` or `patchSetSize` for a save merged with others' edits). The reference reads
    `limit`, `measured` and `max` from the core's `413`, or `422` with `code: "limit"`, and answers
    in one shape, such as `too large: documentSize 1048577 > 1048576 (§6.6): document too large`;
    a limit without sizes (a duration, a rate) is named alone, and a `413` naming no limit keeps
    the core's text. Its own bounds take the shape: `too large: blobSize 9 > 8 (§6.6, §7.8)`
    before any upload, and a flag's bound (`-max-file-size`, `-max-raw-size`) is named by the
    flag, the bytes read when it was passed being a lower bound, as in 32. *Propose:* say that a
    gateway names its own bounds in the same shape, with a key of its own.

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
