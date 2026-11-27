# Patch Log — Tools

Status: draft v0.91 · 2026-11-27. A companion to the [Patch Log specification](SPEC.md), versioned with it. Changes are listed there and in [CHANGELOG.md](CHANGELOG.md).

**Scope.** Clients and tools that use the protocol's public API. A server needs nothing from this document.

- **§11 (non-normative):** client behaviour: loading, saving, undo, and designing documents.
- **Addendum F (suggested):** working with branches: merge, rebase, cleanup and releases across namespaces.
- **§G.2 and §G.4.2–§G.4.4 (suggested):** external consumers, and exporting and importing bundles.
- **Addendum H (suggested, non-normative):** files: how file tools, such as WebDAV gateways and mounts, store files, folders and names to share a namespace.
- **Addendum J (suggested, non-normative):** streams: a proxy that keeps an upstream's streamed response for clients to resume, and shared agent sessions built on it.

**Reading.** "Reading this spec" in [SPEC.md](SPEC.md) applies here, and so do its terms (§2, §2.1). The three documents share one numbering: §1–§10, §12, §13, §C, §E (but §E.2.6), §G.1, §G.4.1, §G.5–§G.7 and §I are in SPEC.md; §A and §E.2.6 are in [SERVICES.md](SERVICES.md).

---

## 11. Client behaviour (non-normative)

- **load:** `GET /r/{ns}/{name}`, following the redirect; the head is `X-Revision`. At E3 it is the redirect's `ETag`, and the `404` (`not_offered`) at the target names the snapshot to fold the log from, or none for genesis (§7.1). At E2 a partial reader takes the revision's key from a filtered answer that names it, such as the resource's log (§7.9, §E.2.2).
- **sync(to):** `GET …/rev/{to}/log?since={head}`, following pages until `to` arrives (§7.1); apply the entries in order.
- **submit(patches):** `PATCH` with `If-Match: "{head}"`, then apply the returned revision. On `412`, `sync(body.head)` and resend the same patches, re-sealed at E3 (§E.3.1) and re-signed if signed (§C.3.1): this is the rebase. Surface `422` and `403` errors; retry a bounded number of times.
- **Conflict safety:** prefix a set that must not land on changed data with `test` ops of the values seen. A retry on changed data then fails with `422`. At E3, where the server applies nothing (§6.2), it fails instead when the client applies it to the new head before re-sealing.
- **watch:** SSE from `since={head}`, or long-poll (§7.7). De-duplicate by entry id: the client's own writes echo back.
- **Filtered logs:** a client library hands a filtered log (§7.9) only to a caller that asked for one.
- **Deleted resources:** a `410` on the head means deleted.
  - A `successor` (§8.1) means the resource moved: offer it as a link. Follow it automatically only into a namespace the client already trusts.
  - In sealed and end-to-end namespaces read `$successor` from the document at `last` instead.
  - At E3 read the verified document, ignoring any `successor` on a `410`. A sealed-namespace client that doesn't trust caches does the same before following one automatically.
- **Frozen namespaces:** on `409 frozen` with a `successor`, load the resource there and replay the pending patch sets as on `412`.
- **Combining changes under a rate limit:** while a save is in flight, collect edits into one pending patch set, the diff from the last saved revision, and send it when the response arrives. If that response is lost, first resend the in-flight set **unchanged** (§7.2). On `429`, wait for `Retry-After`. A combined set carries one `Gesture`, so its actions undo together (§11.2).
- **Presence is out of scope** for the log (`ratePerResource`, §6.6). Use a side channel that admits a client with the same read decision as the resource (§C.5), stamps each message with the verified principal, and keeps nothing.

### 11.1 Designing documents

- **Object member order isn't kept** (§3.1): use an array of objects with an `id` member, which `x-ref` with `key` can address (§6.5), or an explicit `order` field.

- **`$schema` names a revision** (§6.1); a migration (§6.3) moves documents to a later one.

- **Keep namespace names when moving data:** `$schema` and pinned references contain them (§G.1), and renaming rewrites documents and changes every id.

- **Large values are blobs** (§7.8): a string longer than `valueSize` can't be stored.

- **Large documents are created whole and then edited in parts** (§6.6, Whole documents): add large parts in several appends, or in one batch when they must land together (§7.5).

- **Split documents along the lines of access, editing and size:** a document is the unit of read access (§C.5), concurrency and rate limits (§6.6), merge conflicts (§F.3) and revision cost.

  Split one that grows without bound, has parts with different readers, or is edited by unrelated people at once; link the parts with `x-ref` (§6.5).

  Where several parties add to one list, make each entry a resource: creates of different resources never collide, and the namespace log orders them. This gives up constraints across entries, such as a schema's `maxItems`. Writers of one shared document queue behind its head, each lost race costing a request and its rate tokens (§6.6), and a `test` guards whatever a write depends on (§11).

### 11.2 Undo and redo

Gestures (§7.2) let undo work from the log.

- **Recording.** Each action gets a gesture id, sent as `Gesture` with every write it produces.

- **Finding a gesture.** `GET /ns/{ns}/gestures/{gesture}` lists its revisions where offered (§7.4). Otherwise scan the logs the client follows for that author's entries with that `gesture`.

  - In a sealed or end-to-end namespace (no listing), a writer limited to some resources scans the logs of the documents it knows the action touched, reading them with what `/keys` gives it (§E.2.3).
  - Lacking the namespace log, that writer:
    - credits every carried gesture to the merger (see Redo)
    - reports an undo as impossible when a log it read doesn't begin at genesis and the gesture's oldest entry is that log's oldest, where a pruning horizon may lie unseen. If that holds for only some resources, the undo is partial, and the client asks the user first.

- **The inverse.** For each resource, turn the gesture's own entries, newest first, into steps of one batch item (§7.5):

  - a revision: the patch set that turns its document back into its parent's, limited to the paths it wrote (§6.4.1), with writes widened as in §F.3; a `move` whose two ends are unchanged since is inverted as a `move` back. Where §C.7 asks for nonces, every patch-set step adds a fresh `$nonce`, even one before a `"delete"`, never restoring an old one.
  - a tombstone: a restore with `[]` (§8.2), or just a fresh `$nonce` where one is required.
  - a restore: the inverse of its patches, then `"delete"`.
  - a genesis: `"delete"`, after the later inverses. A resource the gesture created ends up deleted, not absent.

  Edits others made to other paths, even between the gesture's saves, are kept; one made to a path between two of the gesture's own writes to it stays lost.

- **The guard.** Before writing, compare the `writes` (§6.4.1), widened for arrays, of each resource's entries after the gesture's last one with the paths the gesture wrote: any overlap, or a later delete or restore, is a conflict for a person. The batch names the checked heads in `ifMatch`, so a write landing in between fails it with `412`, and the client checks again; at E3 it checks against decrypted entries.

- **Writing it.** Apply the steps to the current heads in one batch (§7.5), with a fresh `Gesture` and `Undoes: <gesture>`, splitting a large inverse into chained steps within `opsPerSet` and `patchSetSize` (§6.6). An action across namespaces is undone per namespace, possibly only in part.

- **When undo is impossible:** a revision the inverse needs is below a pruning horizon (`410`), a blob the earlier document references is unavailable (`422 blob`, §7.8), or a `$schema` migration means the old values no longer validate (`422 invalid`). Report these as such, not as conflicts.

- **Redo** is undoing the undo: its `Undoes` names the undo's gesture.

  - An author's undo stack is the gestures that author made, minus those the same author undid and didn't redo.
  - A gesture a merge carried into the base (§F.3) counts for its author in `source.ns` only when the batch counts as a merge under §F.3. Otherwise it counts for whoever wrote the batch.
  - The source author undoes a carried gesture under their own grant, planned against the merger's entries in the base.
  - `Undoes` naming a gesture that no longer exists, such as after a squashed merge, is ignored.

- **Scope.** Who may undo what is decided by the ordinary rules for the undo's writes. Undoing a config write is out of scope (§7.2).

### 11.3 Whole-document clients

File-style clients (WebDAV gateways, mounts, sync tools, editors) hold a whole new document and the revision it started from, its **base**, possibly older than the head, and write it as follows:

1.  **Head is the base.** Send the base-to-new patch set with `If-Match: "{base}"`.
2.  **Head has moved.** Compute, widening writes as §F.3 does:
    - `ours`, the writes (§6.4.1) of the base-to-new patch set plus the `from` of each `copy`
    - `theirs`, the writes of the log entries from base to head (§7.1)

    Any overlap, or a tombstone or restore between base and head, is a conflict: refuse the save and show both versions, never merging values. A base whose log range is `410` (§7.1) can't be compared; the client reloads and asks.
3.  **No overlap.** Send the same base-to-new patches with `If-Match: "{head}"`, re-sealed at E3 (§E.3.1) and re-signed if signed (§C.3.1), never a head-to-new diff, which would revert every edit since the base. On `412`, go back to step 2. The stored document is the head's with these changes (at E3, the readers' fold), not `new`, so read `/rev/{id}` of the new revision.
4.  **Overwriting on purpose,** only when the user means to, is a root `replace` with `If-Match: "{head}"` whatever the head (up to `documentSize`, §6.6, except at E3).
5.  **Deleted.** A `410` on the head means the document was deleted. If it moved, as found under Deleted resources (§11), the client offers the user the new path rather than writing to it unasked.

Where nonces are required or the namespace is sealed (§C.7), every patch set adds a fresh `$nonce`. The server checks only the precondition.

---

# Addendum F — Branches, merge and rebase (suggested)

This addendum uses the core's branches (§7.6), batches (§7.5), and namespace freeze and purge (§8.4–8.5) for drafts, releases, previews and reviews. **Merge and rebase are procedures built from core requests, not server operations,** carried out by clients or a merge service (§F.7).

## F.1 Model

    matches      ──●──────●──────●────────────────◆  batch, source: release-7
                     \ at                         ↑
    release-7         └── derby′ ── cup′ ── +final ┘
                      (everything else is matches as of `at`)

- **A branch is a fixed snapshot of its base plus its own changes** (§7.6), and **an ordinary namespace:** every namespace tool works on it.

- **Uses:**

  | Use                              | How                                                                                                                                                                                                                         |
  |----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
  | Drafts and review                | Authors write in a branch, an editor merges                                                                                                                                                                                 |
  | Releases                         | Publish many documents as one batch per namespace, possibly at a set time (§F.9)                                                                                                                                            |
  | Schema migrations                | Write the new schema revision first, or draft it in a branch of the schema namespace (§6.1, §F.9); migrate the documents in a branch and merge them in one batch whose `config` updates the rule allowing the new `$schema` |
  | Private drafts of public content | A branch with `read: "grant"`                                                                                                                                                                                               |

## F.2 Creating and working in a branch

``` jsonc
POST /ns/matches/branches
If-None-Match: *
Authorization: Bearer <grant with read and branch on matches>
{ "name": "release-7",
  "patches": [
    { "op": "replace", "path": "/read", "value": "grant" },
    { "op": "add", "path": "/cleanup", "value": { "merged": "P7D", "superseded": "P30D" } } ] }
```

- **Configuration and base policy** are §7.6's.

- **Grants name namespaces explicitly:** one for `matches` doesn't work in `release-7`. Issuers add the branch, or every branch a release lists (§F.9), to the grants they issue, typically only for the people working on it.

- **Consumers** that need the whole branch, such as a preview index, follow it (§10, Branches).

- **The base keeps moving;** the branch sees it only after a rebase (§F.5), except as §7.6 says.

## F.3 Merge

A merge is **one batch into the base**, built from the branch's changes:

1.  **Collect** the resources the branch changed, from its namespace log.

2.  **Classify** each resource by **ancestry** of ids (§3.3), comparing the base's current head `B` with the branch's head `H`:

    | Relation                                                                                                             | Batch item                                                                                                                                                                                                                                                                                                                 |
    |----------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
    | `B` = `H`                                                                                                            | none: already merged                                                                                                                                                                                                                                                                                                       |
    | `B` is an ancestor of `H` (including the foreign parent, and "absent in the base" for a resource the branch created) | **fast-forward:** the branch's entries after `B`, with `ifMatch: B` (or `ifNoneMatch: *`). The resulting ids are **identical** to the branch's. (At E3 this is a re-sealed replay instead, §F.8.1.)                                                                                                                        |
    | `H` is an ancestor of `B`                                                                                            | none: the base already has it and more                                                                                                                                                                                                                                                                                     |
    | neither                                                                                                              | **replay** the branch's entries after their latest common ancestor onto `B`, with new ids. **Always review it:** it conflicts if the two sides' `writes` overlap, the branch's counting the `from` of each `copy` too (§11.3), or if history it needs was pruned (§8.6).                                                   |
    | resource purged in the base or the branch                                                                            | none: report it                                                                                                                                                                                                                                                                                                            |

    A `"delete"` step reproduces a tombstone (§7.5). Two cases always need a person, however they classify: deleting a document the base has since changed, and changing one the base has since deleted.

3.  **Dry run** the batch (`?dry-run=1`) for a per-item report.

4.  **Resolve** each conflicting resource by replacing its steps with one resolution set against `B`.

5.  **Submit** the batch with `source: { ns: "release-7", at: <the branch's ns_id> }`, `at` being the branch revision step 2 classified from, not a later one. If the base moves meanwhile, the affected items fail with `412`: re-classify those and resubmit.

6.  **Freeze the branch** with a config write that also records `"merged": { "at": <the base's ns_id> }` (§F.6), or keep working and merge again later.

    After a replayed merge, whose ids exist only in the base, treat each earlier merge batch from the same branch as a common ancestor. A second merge then replays only what the branch changed since. Per resource, that ancestor is the pair of its branch revision as of the batch's `source.at` and its base revision from the batch's entries. The pair comes from the most recent such batch that has an entry for the resource.

    - A resource deliberately kept at the base's version is still recorded, with a revision of identical content: `[]`, or a fresh `$nonce` add where nonces are required or the namespace is sealed (§C.7), or a sealed empty set at E3. Only a live base head can be recorded so: a resource over a tombstone or absence stays unmerged and is offered again.
    - As `source` is asserted (§7.5), only batches count that meet all of these:
      - no `origin`
      - `source.ns` is the branch
      - `source.at` is in the branch's chain, which the merger checks itself
      - the recorded grant (§C.3) has a root `sub` and `kid` listed in the base's current `merge.authors`

      Removing an author withdraws its earlier batches, so a retired `kid` stays listed while branches it merged may merge again or await cleanup. Changing `/merge` needs a `*` key (§7.4). Other merges, such as an editor's by hand, aren't tracked, so such a branch should be rebased (§F.5) before it is merged again. The merger's dry-run report lists, per resource, which batch and author its pair came from.

- **Blobs.** A merger with unrestricted `read` on the branch copies nothing within the deployment, as the batch's `source` makes the branch's blobs available (§7.8). Any other merger copies them first, or uploads them where the ranks refuse a copy (§2.1). At E3, a resource whose document references a blob that can't be declared, of another type or with a nonce (§E.3.1), gets no item: the merger reports it and offers it again.
- **Nonces.** Tools that diff documents for a merge or a review leave out a fresh `$nonce`, as `writes` do (§6.4.1).
- **Conflicts inside arrays.** For merge and rebase, a write whose last segment indexes an array counts as one to the whole outermost array holding it.
- **Configuration is never merged implicitly.** A config change meant for the base goes in the batch's `config`.
- **Squash** replaces a resource's steps with one set of the same effect, losing per-set history and `test` ops. Replaying is the default.
- **Authorisation.** The batch is checked in the base under the merger's grant: the merger needs the base's verbs for every item, and the base's rules apply.
- **Attribution.** Merged revisions, fast-forwarded or replayed, record the merger as author; the original authors stay in the branch's log, and their signatures verifiable in the branch revisions `source` points at, until the branch is purged (§8.5, §F.6). The merger MAY carry each source revision's `gesture` and `undoes` in its steps (§7.5); squashing loses them. Where signatures are required, the merger signs its own steps (§C.3.1).

## F.4 Stacked branches

- **A branch of a branch** (`B2` based on `release-7`) reads through both, up to the branch depth limit (§6.6).
- **It is never broken by its base moving on** (§7.6), and a base with dependents can't be purged (§8.5).
- **Retargeting after a merge is almost free.** After `release-7` fast-forwards into `matches`, rebasing `B2` onto `matches` (§F.5) fast-forwards every resource that nothing else changed, reproducing `B2`'s ids, except at E3 (§F.8.1).

## F.5 Rebase: a successor branch

To bring `release-7` up to date with `matches`:

1.  **Create** `release-7-b` from `matches` at its current head, with `patches` that give it the old branch's `read`, or `"grant"` where that would rank it below the old branch (§2.1). A rebase never replays into a successor that ranks below the old branch.
2.  **Replay** `release-7`'s changes into it with batches carrying `source: { ns: "release-7", at }`, classified as in §F.3 but against the new branch. Resources that `matches` didn't change since the old `at` fast-forward and keep the **same ids**, except at E3 (§F.8.1).
3.  **Resuming.** When replaying resumes, batches in the successor without `origin` whose `source.ns` is the old branch count as earlier merges (§F.3), whoever wrote them, even without `merge.authors`; the janitor counts fewer (§F.6).
4.  **Resolve** conflicts, over as many batches and people as it takes; the old branch keeps working meanwhile.
5.  **Switch** with one config write on the old branch: `"frozen": true, "successor": "release-7-b"`. Switch once the replay has recorded every resource the old branch changed up to the replay's latest `source.at`, other than those §F.6 excepts, or a person has given up the rest. Then replay whatever the old branch received after step 2, reporting what it leaves unmerged. A give-up is recorded nowhere: the janitor then doesn't purge the old branch as superseded (§F.6), and a later replay may still take the rest (step 3).

- **Editors** of the old branch get `409 frozen` with the successor (§8.4), reload from it and replay their pending sets, as on `412` (§11).
- **The old generation stays readable:** reviewing a rebase is a diff between two namespaces, and every earlier link still works.
- **Previews** follow the `successor` chain.

## F.6 Lifecycle and cleanup

| State  | Namespace                                                          | Reversible    |
|--------|--------------------------------------------------------------------|---------------|
| Live   | a working branch                                                   | —             |
| Frozen | merged (`merged`) or superseded (`successor`), readable for review | yes: unfreeze |
| Purged | all gone but the reserved name and `purge-ns` id (§8.5)            | no            |

- **Cleanup** is data in the branch's namespace document (`cleanup`, §12.3), which the core doesn't enforce. Without it, the janitor never purges the branch.

- **A janitor service** follows the bases and their branches (§10), and purges a branch when all of these hold:

  - it is frozen, and merged, superseded or abandoned
  - its cleanup period has passed, counted from the last config write that froze it or set `merged`, `successor` or `abandoned`. The cleanup period is the member of its `cleanup` for the state it is purged as. Without that member, it isn't purged as that state.
  - any minimums the base sets in its own `cleanup` have passed too, counted from the same config write
  - it has no dependents

  The janitor needs `purge-ns` on branches only, never on bases.

- **The janitor MUST verify claims,** which any config writer of the branch can set: `merged`, `successor`, `abandoned` and `cleanup`, which it holds to the base's minimums (above). Before purging, it checks:

  - **merged:** the base's log has a batch that counts as a merge (§F.3), and the branch's log has no `head`, `tombstone` or `batch` entry after its `source.at`; entries of other kinds are allowed.
  - **superseded:** all of these hold:
    - The successor is still one §7.4 allows. Or it was, until a purge after the branch was last frozen, and the janitor still holds what this check needs that the purge stopped serving, read before it (§8.5).
    - The successor's log has a batch without `origin` whose `source.ns` is the branch and whose `source.at` is in the branch's chain. That batch's recorded grant has a root `sub` and `kid` in the base's current `merge.authors`, or chains to a current `*` key of the branch.
    - The branch's log has no `head`, `tombstone` or `batch` entry after that `source.at`.
  - **abandoned:** the branch's document has `"abandoned": true`, set by a config write whose recorded grant (§C.3) chains to a current `*` key of the branch, inherited from a base or its own.
  - A batch in the branch's log counts as a `batch` entry only through its items.
  - At E3, entries for the branch's `keyring` resource, which is never merged (§F.8.1), are allowed after `source.at` too, in either check; a batch counts only if it has other items.

  In either check, every resource with a `head`, `tombstone` or `batch` entry of the branch's own up to `source.at` must also meet one of these, other than its `keyring` at E3 and resources purged in the branch:

  - it has an entry in a batch that counts there whose `source.at` is at or after the resource's last such entry
  - it has a head in the batch's namespace that equals or descends from its head in the branch as of `source.at`

  A branch with no `head`, `tombstone` or `batch` entry of its own, other than for its `keyring` at E3 and resources purged in the branch, counts as merged.

## F.7 Merge service (plug-in, optional)

- **Discovery:** of new branches from `branch` entries in the bases it follows (§10).

- **Status:** per branch and resource, ahead, behind, clean or conflicting, from `writes` overlap.

- **Diffs:** branch against base, and generation against generation after a rebase.

- **Preparation:** batches and dry runs, with resolution sets for conflicts, for a person to approve.

- **Automation (optional):**

  - rebase branches whenever every resource fast-forwards, or at E3 is re-sealed onto an unchanged base (§F.8.1)
  - submit at a set time a batch a person approved, e.g. an embargoed release

  Anything else, including any replay a person hasn't approved (§F.3), waits for a person, who sees the replayed result next to the reviewed branch document.

- **Least privilege:**

  - `read` on bases and branches
  - `branch` on bases, and writes in branches, for rebases
  - `config` on branches, to freeze them and record `merged` or `successor`
  - write access to a base only if it merges on its own

## F.8 Access, encryption and indexes

- **Editors limited to some documents** can't branch the base themselves (§7.6). A service that may branch it creates the branch for them, recorded with `via` (§C.1), with `read: "grant"`, and issues them grants on it with the rules of their base grants. Filtered reads don't cover branches (§7.9), so such grants list only through a preview index (below, §A.4), and in a sealed branch those whose rules refer to `/doc` get no keys (§E.2.3).
- **Keys and revocation** in a base reach its branches (§C.4); roles and rules don't (§7.6, §F.3).
- **Encryption (Addendum E),** whose Levels also bind a branch's level to its base's:
  - **E2** as §E.2.5 says, where fast-forward merges keep ids, which are over plaintext.
  - **E3** as §F.8.1 says.
- **Indexes (Addendum A).** Search over a branch is a separate preview index (§10, Branches); the main index follows only the base.

### F.8.1 Merging and rebasing at E3

At E3 a merge (§F.3) or a rebase (§F.5) is carried out by a client that holds keys and submitted as an ordinary batch sealed for the target.

- **Keys.** The merger needs the branch's own epochs, plus the base's epochs up to the branch's `at` for read-through content, to read, and the target's current epoch key to write.

  A `kid` `{ns}#{e}` names the namespace whose `keyring` holds its key. Read-through content in a branch keeps the base's ciphertext and `kid`, and the branch's own writes carry the branch's `kid`s. A client asks the namespace it is reading for keys first, and only if that fails the `kid`'s namespace: `POST /ns/{branch}/keys` relays its bases' keyring entries as of `at` (§E.2.3).

  A branch's `keyring` is never merged.

- **Classification** is by ancestry over ids, as in §F.3; ciphertext ids suffice, as read-through content keeps the base's (§7.6). Two rows of the table change:

  - **`B` is an ancestor of `H`**: a **re-sealed replay** of the branch's entries after `B` onto `B`, in order, with new ids and no conflict check.
  - **Neither**: a replay with the conflict check, as in §F.3.

  There are never fast-forwards at E3, even under the same keys, as each sealed patch set binds its namespace and parent (§E.3.1).

- **Re-sealing an entry.**

  1.  The merger decrypts the patch set and checks its `pl` against where it was read: the branch (or the base, for read-through content), the resource, and the entry's parent.
  2.  It then seals the same plaintext patches under the target's current epoch, with a fresh IV and `pl: { ns: target, name, parent }`. `parent` is `B` for the first entry, and then the id the previous entry of the same item produces.
  3.  The merger computes each new id itself (§3.3, over the sealed patch set).

  The target's `pad` applies (§E.2.2). A tombstone needs no sealing: its id follows from its new parent (§3.4).

- **Blobs** keep their ciphertext and ids (§E.3.1), and are made available as for any merge (§F.3). Each re-sealed op keeps its `blobs` list.

- **Conflicts** are found by the merger, from the `writes` of the decrypted patch sets compared as in §F.3, arrays included.

- **Validation.** Before submitting, the merger folds every item and validates each resulting document against its `$schema` (§E.3.2), resolved as the target's gate would resolve it (§6.1). A document that fails is a conflict for a person, of kind `invalid`.

- **Retries.** The merger keeps the sealed batch byte for byte until it is acknowledged, so a retry reproduces the same ids (§E.3.1). Re-classifying after a `412`, or changing a resolution, seals the affected items again.

- **Later merges and the janitor.** Every E3 merge is a replay, so a second merge finds its common ancestors in earlier merge batches (§F.3); these, like the janitor's checks (§F.6), need no keys. Without such a batch, a merger MAY count a resource as merged when the target's and the branch's head documents are equal as decrypted plaintext. Every other resource the branch changed conflicts; rebase instead (§F.5).

- **Rebases** (§F.5) re-seal in the same way, with the successor as the target. Only read-through content keeps its ids.

## F.9 Releases across namespaces

A release may span several namespaces, such as content and schemas. Each is branched as usual, from heads that SHOULD have been current together, and the branches are listed, each with its own `at`, which is authoritative, in a **release document**: an ordinary resource that tools read and the core doesn't. It authorises nothing: every tool acting on it checks under its own authority what it is about to do.

``` jsonc
// /r/releases/release-7
{ "name": "release-7",
  "branches": { "matches": { "ns": "matches-r7", "at": "1k…" },
                "schemas": { "ns": "schemas-r7", "at": "1d…" } },
  "on": "/r/releases/release-6/rev/1x…",          // optional: the release this one builds on
  "owners": ["user:anna"] }
```

- **Documents keep naming the bases** (`x-ref`s `/r/matches/…`, `$schema` `/r/schemas/…`). Draft schema revisions are written in the release's branch of the schema namespace, which lists the other branches in `drafts.for` (§6.1, §7.4); a namespace that keeps its schemas beside its content drafts them in its own branch, merging its schema resources in step 1 and the rest in step 2. Previews follow the listed branches (§F.8, Indexes).

- **Merging** is one batch per branch, so a release across namespaces isn't atomic (§7.5). The merge service submits, in order:

  1.  **Schemas, by fast-forward only,** in `$ref` order: the resources whose documents have a dialect URL as `$schema` (§6.1), tombstones and restores included. One the base changed since `at` is a conflict: rebase (below), and migrate the documents with `replace /$schema` (§6.3). An end-to-end schema namespace isn't branched: new revisions are written to it first.
  2.  **Content,** in any order.
  3.  **Publishing,** where readers' rules test a field that marks documents published (e.g. `/doc/published`, §7.9, guarded as §6.4.4 says, with an exemption for a group the merge service's grant carries, since a role would add verbs): one batch per content namespace sets it on the documents the release created or restored, which carried it unset. A change to that field in steps 1 and 2 is a conflict. Edits to documents already published show at step 2. Planning again after a stop takes step 3's documents, those still live and unset, from the stored plan, since steps 1 and 2 have merged them, and reports those no longer live.

- **The plan.** A person approves the plan's **digest**, `text(trunc160(sha256(canonical(plan))))`, where `plan` is `{ "release": <the release document's revision path>, "batches": [{ "ns", "source"?, "config"?, "items": [{ "resource", "ifMatch" | "ifNoneMatch", "steps" }] }] }`, with no other members.
  - `release` is `/r/{ns}/{name}/rev/{id}`, the id in text form, as `on` writes it.
  - The batches are in submission order, as §7.5 sends them but before any sealing; only step 3's have no `source`.
  - Each step is `"delete"` or its plaintext patch set, without fresh `$nonce` ops (§6.4.1) or a fresh top-level `$nonce` in the value of an `add` or `replace` at `""`.
  - A precondition on an earlier batch's result is `{ "batch", "item" }`, or `{ "batch" }` for its config id, counting from 0.
  - Implementations agree on the digest of a given plan, not on how a plan is ordered.

- **Before approval** the merge service checks that each branch's `base` is the namespace it is keyed by, or, for a release built on another, that release's branch for the key where it lists one, and that it isn't frozen or purged. It reports as conflicts a pinned `x-ref` (§6.5) to a revision of another listed branch that the merge replays (at E3, every one, §F.8.1), and a document resolving a draft in a branch the release doesn't list.

- **Approval** fails if planning again gives another digest. It freezes every listed branch (§8.4), each `source.at` staying the branch's `ns_id` before that freeze; the merge service accepts that freeze on resuming, and unfreezing a branch invalidates the plan. Each step is dry-run right before it is submitted, and stops for a new approval if it differs. The plan is stored before anything is submitted; a merge that stops resumes from it and never reverts. Each branch records `merged` after the last step, with `at` the target's `ns_id` after the last batch into it.

- **Releases built on another** branch its branches and name it in `on`, still keyed by the namespaces paths name, and resolve drafts from both (§6.1) where the earlier draft branch lists the earlier release's branches in `drafts.for`. Of two releases drafting one schema resource, the second to merge is rebased onto the first.

- **Rebasing** creates a successor of each branch (§F.5), the schema one first, with `drafts.for` naming the others in its creation `patches`, and lists them in a new revision of the release document. A resource referencing a replayed draft is squashed (§F.3), with `$schema` moved to the new revision.

- **Cleanup** is the janitor's (§F.6), the draft branch last (§6.1, §8.5). **Abandoning** freezes the branches with `abandoned: true` (§F.6); schema revisions merged in step 1 stay, unused.

## F.10 Open questions

- Should grants have a form covering a namespace **and its branches**, or all the branches of a release?
- Should there be a stable alias that follows `successor` chains, for previews and bookmarks?
- Should the server offer three-way diffs, or leave them to the merge service?

---

# Addendum G — Federation and portability: consumers, export and import (suggested)

The rest of Addendum G is in [SPEC.md](SPEC.md): its principles (§G.1), the bundle format (§G.4.1), encryption (§G.5), multi-region (§G.6) and open questions (§G.7). Working across deployments is exporting and importing: exporting is a consumer (§G.2), and importing a client of the batch API (§7.5).

## G.2 External consumers

A consumer in another network or organisation works as in §10, plus:

- **Checkpoint.** It stores `(origin, ns, ns_id)`.
- **Verification.** Revisions are verified through their log (`/r/{ns}/{name}/rev/{id}/log`), by recomputing ids back to a revision already verified, and the namespace chain entry by entry from the checkpoint (below a pruning horizon, §8.6). A consumer SHOULD verify, and MUST when it fetches through a cache or mirror it doesn't control. Such a consumer confirms a `410` (`purged`), which carries nothing to verify, at the origin before dropping anything (§10).
- **Access.** Public namespaces need nothing; private ones need a `read` grant from the source deployment, and the consumer then holds a copy (§G.1).

### G.4.2 Selection and dependencies

A selection is a list of resources, or anything a resolver turns into one, e.g. an index query (Addendum A). The **dependency closure** is built in three levels:

1.  **Core references, always:** the `$schema` of **every exported revision**, not only the head's, `$ref` inside those schemas, and the blobs those revisions reference (§7.8). A document referencing a schema revision that exists only in a branch (§6.1) can't be exported until that branch is merged (`schema_unavailable`), unless that schema's namespace is declared `external`, when the importer checks the target instead.
2.  **Declared references:** fields marked `x-ref` in the documents' schemas (§6.5). A **pinned** reference needs that exact revision, a **live** one the head as of the export's `at`.
3.  **Application resolvers:** tool plug-ins for relationships no schema expresses, e.g. "a match brings its team pages".

Untyped documents have no level 2, but an opt-in rule may treat any string in them matching `^/r/` as a reference. Dependencies left out with `external` are checked by the importer to exist in the target: by id for pinned references, in the resource's chain and neither purged nor, unless it is a tombstone, pruned without a kept document (§8.6), and by name for live ones.

### G.4.3 History or snapshot

Each document is exported in one of two modes:

|                        | `full`                                    | `snapshot`                                           |
|------------------------|-------------------------------------------|------------------------------------------------------|
| Contents               | every revision, or those after `requires` | the head document only                               |
| Ids in the target      | identical to the source                   | new, derived from the sequence of snapshots imported |
| Verifiable lineage     | ✅                                        | ❌ provenance only                                   |
| Later imports          | fast-forward or merge (§F.3)              | merge through the upstream namespace (§G.4.4)        |
| Old drafts and authors | included (authors optional)               | never included                                       |

- **Schemas are always `full`.**
- **Modes close downward.** Everything a `full` document reaches through `$schema`, `$ref` or a pinned `x-ref` MUST also be `full`, and a pinned reference to a revision other than a document's head forces `full` for that document. A prune's archive is the one exception (§8.6).
- **No shallow mode:** a source id without its ancestors couldn't be recomputed (invariant 4).

### G.4.4 Importing

1.  **Check the bundle** (§G.4.1), including `requires` and `external` against the target. Nothing is written if this fails.
2.  **Classify full-history documents** by ancestry, as in §F.3:
    - missing in the target: created with the whole chain, keeping its ids
    - the target has an ancestor: fast-forward
    - the target already has it, or has moved beyond it: nothing
    - a different history: conflict
    - purged in the target: nothing, reported (§F.3)
3.  **Import snapshot documents through an upstream namespace.** The target keeps one namespace per source namespace for them, `{ns}-upstream`, written only by imports (batches whose `source` names a `bundle`) from one origin. A name that breaks §3.6, or a bundle from another origin than the imports that wrote it, is refused at step 1. So a second origin's namespace is imported renamed (below).
    - **Upstream first.** Each import appends to each snapshot document there one revision: `diff(previous snapshot, new snapshot)`, or a genesis the first time. For a deleted document it appends a tombstone where the upstream document is live, and otherwise writes nothing. An empty diff writes nothing, and diffs ignore `$nonce`. Upstream ids depend only on the sequence of snapshots imported, except where the target or the upstream namespace is sealed or requires nonces: there each generated patch set carries a fresh `$nonce` (§C.7).
    - **Then the target, as a merge from upstream.** The first time, the target fast-forwards and so shares the upstream ids, or conflicts (step 4) if it already has the document. Later, the base is the upstream revision recorded in the previous import batch's `source.ids`. The upstream revisions after it are replayed onto the target's head, conflicting where they overlap its own changes (the array rule of §F.3). A deletion conflicts if the target changed the document.
    - **Pinned references in snapshot documents** that point at other snapshot documents are rewritten to the matching upstream revision path, `/r/{ns}-upstream/{name}/rev/{id}`, keeping any `#{id}` fragment (§6.5). The dry run lists undeclared strings that have the form of a revision path.
4.  **Dry run, then resolve conflicts,** as in §F.3: skip the document, take the bundle's version, or replay. A dry run draws what its submit does (§6.6), so a tool may dry-run only these, relying on later batches' own failure reports (§7.5):
    - each existing namespace's first batch
    - a new namespace's first item, as a batch of its own

    The exception: batches that change existing dependencies are dry-run first (below). Appends to an upstream namespace don't change them.
5.  **Submit batches in dependency order.**
    - **Order.** A batch goes once every batch holding a revision it pins, schemas included, has committed; live references order nothing. Other batches may be in flight at once, except those that write the same resource, which chain through `ifMatch` and go in order. A pin of a full document needs its namespace's batches first, and a snapshot document's pin of another bundled snapshot its upstream namespace's. In a cycle of namespaces, what the upstream namespaces need (schemas, full documents) goes first, then the upstream namespaces' batches, then the batches that pin them.
    - **Size.** Batches split to fit §6.6 make the import non-atomic, so one that must land at once, such as a release, runs as one batch under an allowance (§6.6), typically as a merge from a branch it was first imported into (§F.3). The tool paces its batches, dry runs included, at a fraction of the lower of the namespace's and its own principal's rate, or, under an allowance, at up to its full rate, per-resource buckets still applying (§6.6). With several batches in flight, a request is paced as drawing when it is sent: the server may draw later, after later requests, never earlier.
    - **Blobs first.** The importer uploads the blobs a batch's steps' values mention (§G.4.1) before the batch, or copies them with `Blob-From` within one deployment (§7.8), unless the batch's local `source` already makes them available. Uploads aren't writes for step 1: an import that will submit uploads a batch's blobs before its dry run, if any (step 4). One that only dry-runs uploads none, and gets them reported as missing (§7.5). A snapshot document's blobs go to both its upstream resource and its target. Pending blobs expire after `blobGrace` (§7.8), and a large import needs an allowance raising the importer's `blobPending` (§6.6).
    - **Missing namespaces.** Under authentication, the operator creates the missing namespaces, upstream ones included, before step 1 (§C.4, §7), with keys that include the importer's and, for pacing at full rate, an allowance for it (§6.6).
    - **Renaming.** An import MAY map source namespaces to new names together (`src=dst`), to clone them; snapshot documents then go through `{dst}-upstream`. It rewrites every reference to a mapped namespace: `$schema`, `$ref`, pinned and live `x-ref` values, and pins to revisions, which take the new ids. A full-history document's rewritten steps are new content, submitted one by one with new ids, never fast-forwarded, without their signatures; `source.ids` records the source ids. The dry run lists undeclared strings naming a mapped namespace (`/r/{src}/…`). A renamed namespace's configuration isn't in the bundle (§G.7). Further:
      - a `$successor` naming a mapped namespace (`/r/{src}/…`), and the value of an `add` or `replace` at `/$successor` in a history line, is rewritten as any reference is, and a bare one needs nothing;
      - documents of unmapped namespaces in the bundle that reference a renamed one are rewritten too, and a reference that only a later revision's schema declares is rewritten in that revision, by an added `replace`;
      - mapping onto a branch whose `base` chain reaches `src` isn't a rename: references and ids are kept;
      - refused at step 1:
        - an incremental document that would change, whose `requires` names a source id
        - a full-history document's pin whose new id isn't known, because its target is `external`, left out, or a snapshot document's revision
      - where nonces are fresh, ids differ between runs, so a re-run recognises its earlier writes by the import batches' `source.ids`.
    - **Rewriting waits for its targets.** A document's references are rewritten only after the batches of its dependencies have committed, using the ids they returned.
    - **Source.** Each batch's `source` is `{ "origin", "ns", "at", "bundle": <digest>, "ids": { name: upstream or source id } }`, without `origin` when the bundle's `origin` is the target's own (§7.5), and the importer is recorded as author.
    - **Partial failure.** A failure part-way can leave updated heads in effect, which live references see. So a promotion that changes existing dependencies should be dry-run end to end first. Where the limits allow, it should be submitted within one namespace as one batch, whose dry run is end to end. Otherwise, as a dry run sees only what is committed, a tool:
      - dry-runs each later batch that moves heads the target had
      - reports as deferred any failure that wouldn't occur once the earlier batches are written
      - skips a batch that continues a chain an earlier one cuts
6.  **Today's rules judge old history.** A full-history import replays every step through the target's **current** gate (§6.2), as the importer, at the current `now`. Rules on `/principal`, `/now`, `writes` or, for replayed deletes, `/doc` may reject history valid at the source, as may a target that requires nonces, or a sealed one, whose writers add a fresh `$nonce` to every patch set (§C.7, §E.2.5). Such imports need an importer whose roles satisfy those rules, or snapshot mode.
7.  **Purges follow.** The target's deployment, not the importer, applies the origin's later purges of what it imported (§G.1).

---

# Addendum H — Files (suggested, non-normative)

Tools that show namespaces as files (WebDAV gateways, mounts, sync tools, editors) follow these conventions so they can share a namespace. A gateway is an ordinary client of the core API (§11) and needs nothing more from a core server.

## H.1 What a file is

- **Raw files.** Every file other than a JSON file is a **raw** document (§7.8), its bytes kept exactly. Its `type`, part of the blob id (§3.7), comes from the first of these that applies:

  1.  the file name's extension, in any letter case, by this table
  2.  the upload's `Content-Type`, parameters dropped (§3.7), if given and not `application/octet-stream`, `binary/octet-stream`, `application/x-www-form-urlencoded` or `multipart/*`
  3.  otherwise an existing file keeps its type, and a new one gets `application/octet-stream`

  At E3 the file's `type` and `size` are the reference's `sealed` ones (§E.3.1). A `text/` type needs a UTF-8 body (§3.7), a leading BOM allowed; any other body gets `application/octet-stream`.

  | Extensions                 | Type               | Extensions    | Type                                                                      |
  |----------------------------|--------------------|---------------|---------------------------------------------------------------------------|
  | `md`, `markdown`           | `text/markdown`    | `png`         | `image/png`                                                               |
  | `txt`, `text`              | `text/plain`       | `jpg`, `jpeg` | `image/jpeg`                                                              |
  | `html`, `htm`              | `text/html`        | `gif`         | `image/gif`                                                               |
  | `css`                      | `text/css`         | `webp`        | `image/webp`                                                              |
  | `js`, `mjs`                | `text/javascript`  | `svg`         | `image/svg+xml`                                                           |
  | `csv`                      | `text/csv`         | `pdf`         | `application/pdf`                                                         |
  | `xml`                      | `application/xml`  | `zip`         | `application/zip`                                                         |
  | `yaml`, `yml`              | `application/yaml` | `docx`        | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
  | `json` (not I-JSON, below) | `application/json` | `xlsx`        | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`       |

- **JSON files.** A document that isn't raw is a **JSON file**: the file is the document's value, read as its **rendering**. The rendering is the canonical JSON text (§3.1) of the document without a top-level `$nonce` of the fresh form (§6.4.1) and without a top-level `$successor` of the form of §8.1. It is laid out as ECMAScript `JSON.stringify(value, null, 2)` lays it out:
  - every member and element on its own line, indented two spaces per level
  - `": "` after member names, `,` at line ends
  - empty objects and arrays as `{}` and `[]`
  - LF line ends, and one final LF

  Tokens, member order included, are exactly JCS's: implementations lay out the canonical text, and never re-serialise a parsed object (§I.10). Its type is `application/json`.

- **Which kind a new file is.** A new file is a JSON file if its name ends in `.json` (in any case) and its body, a leading UTF-8 BOM dropped, is I-JSON (in this addendum, what §3.1 accepts); any other new file is raw. An existing file keeps its kind: a JSON file accepts only I-JSON, a leading BOM dropped (`400` otherwise), and a raw file any bytes.

- **Empty files.** An empty body makes or truncates a 0-byte raw file, except in two cases:
  - Over a JSON file, it is `400`.
  - Under a new `.json` name, it is a placeholder the gateway holds (§H.7), listed as a 0-byte file, until a non-empty body decides its kind. A `LOCK` of a new name is such a placeholder too.

- **Writer's bytes.** Every tool shows a document as the same rendering. A gateway MAY serve a writer its own bytes back for a revision that holds exactly what it sent, under the weak `ETag` `W/"{id}"`; everyone else gets the rendering. A gateway takes the weak tag like the strong one in any `If-Match`, as a save's base (§H.4) and as a delete's or move's precondition (§H.5).

- **Nonces.** Where nonces are required (§C.7) or the namespace is sealed (E2; at E3 ids need none):
  - In the flat view, a JSON file's root must be an object, which carries `$nonce`. Any other root is `422`, saying why.
  - A raw file's root carries `$nonce` beside the reference, its blob a `Blob-Nonce` (§7.8).

- **Identity.** A file's `ETag` is its document's head revision id. A raw save is always stored with the uploaded value, and a JSON save when the stored document's rendering parses to it. After a save the gateway merged with others' edits (§H.4), the next `GET`, `HEAD` or `PROPFIND` of the file is answered in full, whatever validators it carries.

## H.2 Trees

A **file tree** is a namespace whose documents carry their place as data. A gateway is configured with the namespaces it serves as trees, and the file schema they use.

``` jsonc
// /r/docs/f-7kq2…   (an opaque name)
{ "$schema": "/r/schemas/file/rev/…",
  "folder": "/reports/2026", "name": "q3.pdf",
  "content": { "$blob": "…", "type": "application/pdf", "size": 48211 } }
```

- **`content`** is the file. Everything this addendum says of a file's document applies to `content`, paths included (`/content/$blob`); `$nonce` and `$successor` stay at the document's top level, so a JSON file's root may be any value.
- **`folder`** is the path of the folder holding it, `/` or `/`-separated titles, and **`name`** its title. The file schema marks `/folder` and `/name` `x-index: "facet"`, and `/name` `"sort"` too (§A.2).
- **Folders** are documents without `content`: the folder `{folder}/{name}`, or `/{name}` at the top. A document is in the tree only when its `folder` is `/` or has a folder document; tools leave out the rest however they list. Two folder documents for one path, left by a race, are one folder.
- **Titles** are Unicode in NFC, 1 to 255 bytes of UTF-8. They are never `.` or `..`, and are without `/`, `\`, characters of the categories `Cc`, `Zl` and `Zp`, or the bidirectional controls U+202A–U+202E and U+2066–U+2069 (other `Cf` characters are allowed).
  - The file schema enforces this with a `pattern`, and the tool the byte length.
  - A gateway converts names it receives to NFC, refuses a trailing space or dot on create and rename for every client, and shows an existing one escaped.
  - Another tool's title that breaks these rules is shown with each offending character, a trailing space or dot, and a whole `.` or `..` percent-encoded as UTF-8. The stem is shortened so the name stays within 255 bytes.
  - An escaped name never takes a real title's name, and is numbered as a duplicate instead (Siblings).
- **Siblings.** Files and folders in one folder share one set of names. Names are compared after NFC and, unless the gateway is set to be case-sensitive, after Unicode simple (not full) case folding.
  - Tools refuse to create a name a visible sibling has. The source of a `MOVE` isn't its sibling, so a rename that only changes case is allowed.
  - A `PUT`, `COPY` or `MOVE` to a name that matches a sibling only under another case is `409`, naming the sibling, unless the sibling is a file and either the request carries a tag or the user read or wrote that file under this spelling.
  - `MKCOL` under another case is `405`.
  - A folder in the middle of a path matches whatever its case.
  - A duplicate left by a race is shown as `name (2).ext`, `name (3).ext`, …, in order of resource name, the first keeping its name.
  - A number that would collide with a real title is skipped, and the stem shortened so the name stays within 255 bytes.
- **Flat view.** A namespace may also be shown as one directory whose file names are resource names: a raw document as its name, any other document as `{name}.json`.
  - If a raw resource `x.json` and a document `x` both exist, the raw file keeps its name and the document is shown by the duplicate rule above.
  - There are no folders, and a rename is a copy and a delete (§H.5, §8.1).
  - A new file whose resource is tombstoned, where §H.6 doesn't restore it, restores it with a root `replace` (§8.2). If the last revision has a `$successor`, it is `409` instead, naming the new path.
  - A new file whose resource is a live document shown under another file name is `409`, naming that file.

## H.3 Listings

- **In a tree,** a folder is listed by the index (Addendum A): `GET /{ns}?facet[/folder]={path}&schema=/r/schemas/file&sort=/name`, paged through. A path is resolved one folder at a time, or with `facet[/name]` too. Hits are filtered by the reader's read rules (§A.4, §7.9). The index's `400` for the facet path, as where the reader may see no file document (§A.4), lists an empty folder, never one empty for a write (§H.4 Names before writes): a folder delete or move still answered that `400` after listing again at the namespace head is `503`.
- **A folder too large to list whole** (beyond what a tool pages through) is refused (`403`, saying why), never listed cut short.
- **An index that is behind** answers `503 behind` (§A.5); a tool answers `503` (§H.4 Answers), and deletes nothing on the strength of a listing meanwhile.
- **Read-your-writes.** A tool sends the `X-Namespace-Revision` of its writes as `?min` on later listings (§A.5).
- **In the flat view,** a directory is listed from the `head` rows of `/heads` (§7.4), tombstones and purges left out: `ETag` from `target`, the time from `created`.
- **Sizes.** A JSON file's size is its rendering's, not `/heads`' `size`, and a raw file's the blob reference's `size` (at E3 its `sealed.size`), both read from the head document once per revision, cacheable for good.
- **Where times are absent,** rows without `created` take `Last-Modified` from the document read for the size (§7.1). In sealed and end-to-end namespaces a gateway with keys takes them from the logs.
- **End-to-end trees** no index holds keys for (§E.2.6) are listed only by a gateway with keys and unrestricted `read`, from the documents.

## H.4 Saving a file

A save follows §11.3, with these specifics:

- **Names before writes.** The index lags (§A.5), so before any write a tool reads the documents it resolved from a listing and checks that each still has that `folder` and `name`, and lists again where one doesn't, with `?min` at the namespace head. A folder is empty only when a listing at or past the tool's last write in the namespace has nothing in it. A name the filtered listing lacks is never revealed or edited: a `PUT` onto a name only a sibling hidden from the user has creates a new file.

- **The base.** The entity tag a client sends names the **base**: the revision the client opened. The tag is the one in `If-Match` (its first value, `W/` dropped) or, failing that, in an `If` header (the first tag of the first list that applies to this resource and isn't negated with `Not`; tag-only lists are not lock tokens).

  - For `PUT` only, and unlike RFC 9110 on purpose, an older tag is not a failed precondition but the starting point of a rebase.
  - `If-Match: *` asks only that the file exist, and the head is the base.
  - A tag naming a revision where the path holds no file is `412`, not a create. A tag naming a tombstone counts as one naming the revision it deletes.
  - A tag naming a revision of a flat resource another user has since deleted is `409`.

  - An unknown revision is `412`. A pruned one is `409`, asking for a reload, as are a recorded base below a horizon and a pruned range between base and head. A failed read of anything the save decides by, `theirs` and the user's own entries included, fails the save (Answers, below). The head is never taken as the base instead.
  - **Records.** Without a tag, a gateway MAY keep, per user (§H.7) and path, the revisions it served that user in full and those it wrote for them, with the document each path named when last read whole or written.
    - A `304`, `HEAD` or `PROPFIND` records nothing, and a save that changed nothing isn't a write.
    - Records outlive sessions, for a day, and a path whose records expired counts as evicted.
    - A save at a path that now names another document, or none, is `409`, and a `GET` of the path is the reload.
    - The user's own `DELETE` or `MOVE` forgets the path, except a move to a scratch name (§H.5).
    - When the budget is full the oldest records other than the first and the latest write go first. A path whose records were evicted is `409`.
  - **Several records.** For a JSON file the save is checked against each of the user's recorded versions taken as the base: if any two would give different documents, it is `409`, naming the paths. The one exception: a save without a tag that sets back a value someone else changed is merged, keeping the other value.
  - **The reload** a `409` asks for is a full read of the file by the refused token (`200`, not `304`, to a conditional `GET`), which becomes the path's only record; a refusal re-arms nothing for the user's other tokens.
    - After a `409` because someone else deleted the file, the `GET` that finds it gone (`404`) is the reload. The next save restores the file as §H.6 restores one after a delete.
    - The exceptions are these, where the save is `409`:
      - a file whose last revision has a `$successor`, naming the new path (§11.3);
      - one that the gateway can't read but for a failed read, saying it can't tell whether the file moved.
    - A failed read fails the save as above.
  - With no base at all, the head is the base, and the save overwrites others' edits on the paths it changes. Clients SHOULD send their `ETag` back.

- **Others' writes.** `theirs` (§11.3) is only the writes of other users' (§H.7) log entries between base and head, unlike §11.3; a value changed and changed back is still a conflict.

- **JSON files** are saved as a patch set from the base's rendering (§H.1) to the parsed new file, so the base's `$successor` is kept, with `add /$nonce` carrying a fresh value where §C.7 asks for one. The overlap rule is §11.3's, except that a write anywhere inside an array counts for the whole outermost array. A patch set over `opsPerSet` or `patchSetSize` (§6.6) becomes a root `replace` carrying the fresh `$nonce` and any `$successor` if the base is the head and the namespace isn't end-to-end, and is `413` otherwise.

- **Raw files** have no paths to merge. A raw save is checked against every version the user had (the `If-Match` revision, else every version served to them or written by them). It conflicts only if someone else changed the bytes, or deleted or restored the file, after any of them. Then:

  1.  The body is spooled and hashed, and uploaded as a blob (§7.8; `413` above `blobSize`, before any upload).
  2.  The blob reference's members are set one by one with `add`, `replace` or `remove` (`/$blob`, `/type`, `/size`, `/nonce`, and at E3 `/sealed`), with a fresh `/$nonce` where nonces apply, never the root.

  A `412` retry reuses the pending blob. Bytes are compared by blob id, so under nonces identical bytes count as a change.

- **New files** in a tree: upload a raw file's blob, then create the document under a fresh opaque name with `If-None-Match: *`, its `folder` a folder the user can see (`409` otherwise).

- **Partial writes** (`PUT` with `Content-Range`) are `400`, and so is a body cut short; nothing is written. `POST` to a file is `405`, with `Allow`.

- **Answers** a gateway gives, to any request:

  | Case                                                                                                                                                                                                                                                                       | Gateway answers                                                                                                                                                            |
  |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
  | Saved, stored with the uploaded value (§H.1)                                                                                                                                                                                                                               | `201` or `204`, with the new revision as `ETag`, even where the rendering's bytes differ from the upload's: a deliberate deviation from RFC 9110 (section 9.3.4)           |
  | Saved, merged by the gateway with others' edits                                                                                                                                                                                                                            | `201` or `204`, no `ETag`, and the next read in full (§H.1)                                                                                                                |
  | Overlap with others' edits since the base, a delete or restore by another user (§H.7) between base and head (§11.3), a pruned base, records that disagree or were evicted, a path that now names another file, or a file moved away or whose last revision the gateway can't read but for a failed read                                        | `409`, naming the paths, and telling the user to reload                                                                                                                    |
  | The client's own precondition failed: `If-None-Match: *` on a live file (but see the move-aside, §H.5), `If-Match` naming an unknown revision, or where the path holds no file (a flat resource another user deleted excepted, §H.4), `Overwrite: F` on an existing target | `412`                                                                                                                                                                      |
  | A new name that breaks the title rules or ends in a space or dot (§H.2), or that isn't a resource name in the flat view (§H.2, §H.6)                                                                                        | `403`, saying why                                                                                                                                                          |
  | Validation, rules, blob or nonce refused (`422`), or the grant refused (`401`, `403`), by the core or by the index                                                                                                                                                  | that answer, with its message; where the user can't fix it, as when the gateway's own grant is refused, `502` naming the service                                           |
  | Frozen namespace                                                                                                                                                                                                                                                           | `403`, naming the successor; never `423` (§H.6)                                                                                                                            |
  | Purged                                                                                                                                                                                                                                                                     | `410`                                                                                                                                                                      |
  | Rate limited, or a service behind, for longer than a client waits (§6.6, §A.5)                                                                                                                                                                                             | `503` with `Retry-After`                                                                                                                                                   |
  | A core or service request the gateway makes for the user's request fails (`408`, `429`, `5xx`, no connection, or no answer in time) at its last attempt, a read of another namespace's documents, a write or a due re-check of the user's grant (§H.7) included, whether or not the answer needed it; a failed read never counts as a refusal | `503` with `Retry-After` after a `429`, a `503` or no answer in time, else `502` |
  | A limit exceeded (the core's `413` or `422` with `code: "limit"`)                                                                                                                                                                                                          | `413`, in one shape: `too large: {limit} {measured} > {max} (§6.6): {message}`, a limit without sizes named alone, and a `413` that names no limit keeping the core's text |
  | A bound of the gateway's own (an upload buffer, a file-size setting, `blobSize` checked before an upload)                                                                                                                                                                  | `413` in the same shape, naming its setting, `measured` a lower bound where reading stopped                                                                                |
  | The gateway's own memory for scratch files or locks full (§H.6)                                                                                                                                                                                                            | `507`; bounds are generous                                                                                                                                                 |

  A gateway's `502` and `503` name only the upstream that failed, the core or a service, and carry nothing of its answer, as §C.6 says of a service's `502`; the `503`'s `Retry-After` is the gateway's own. Requests made in the background, such as refreshes of a shared cache, never count. A read that fails before the request's first write stops the request, so nothing is written. One that fails after a write still fails the request, with the work done, and the writes that follow and don't decide by that read are still sent.

## H.5 Deleting, renaming, moving and copying

- **Delete a file:** delete its document, with `If-Match` on the head the tool read: a client's `If-Match` that isn't the head is `412`, and the gateway's own delete finding the head moved since its read is `409`.
- **Delete a folder:** only one without visible children (§H.4); `409` otherwise, naming those children. Children the user can't see don't stop the delete, and fall out of the tree (§H.2).
- **Rename or move a file:** one append replacing `/name` or `/folder`, with `If-Match`, after checking that the document still has the name and folder the path named (`404` otherwise). The new folder must exist. On any `MOVE`, a client's `If-Match` names the source, and one that isn't its head is `412`.
- **Rename or move a folder:** one batch (§7.5) rewriting the folder document and the `folder` of every visible document under it, each item with `ifMatch` on the head the tool read. One into itself or a descendant is `403`, and one too large for a batch is refused as a limit (§6.6, §H.4 Answers). Documents under it the user can't see fall out of the tree.
- **Move onto an existing file** (`Overwrite: T` or absent; `F` is `412`): a save of the source's content into the target (§H.4), then a delete of the source as above.
  - The source's type stands for the upload's `Content-Type` (§H.1).
  - The target's base is taken as §H.4 says, but never from `If-Match`, which names the source.

  A `MOVE` or `COPY` onto an existing folder, or of a folder onto a file, is `403` (`412` with `Overwrite: F`).
- **Moves that copy** (onto an existing file, across namespaces) check first that the source can be deleted; then copy, then delete the source with `If-Match` naming the revision copied. A source that changed since is `409` and stays; a delete that fails anyway leaves the copy, with no rollback.
- **Move to a scratch name** (§H.6): the file is copied into scratch and stays live. The next create-only `PUT` of the original path by the same user within 30 seconds is accepted once as an edit, its base taken as for any untagged save (§H.4), rather than `412`.
- **Across namespaces:** the document's last revision before the tombstone carries `$successor` (§8.1); a flat view's JSON file whose root isn't an object can't, and moves without one.
- **Copy:** a new document with the source's current content. A `COPY` onto an existing file (`Overwrite: T`) is instead a save into it, as for a move onto it.
  - A folder is copied, or moved to another namespace, as a new folder document as `MKCOL` makes one, titled with the destination's last segment. Its visible children are then copied or moved into it one by one (`Depth: 0` copies the folder alone), and a moved folder is deleted once empty.
  - A copy into the folder itself or a descendant of it is `403`, before anything is written.
  - A failure part-way leaves what was done, with no rollback, and is answered as that child's request would be.
  - A raw file's blob is copied with `Blob-From` where §7.8 allows it. Otherwise its bytes are uploaded again: decrypted with the reference's key from an `e2e` source, and encrypted under a fresh key, with a new id, into an `e2e` target (§E.3.1).

## H.6 Clients as they are

- **Scratch files.** Editor and system files are kept by the gateway in bounded memory (§H.7), never written to the core:

  - files: `.DS_Store`, `._*`, `Thumbs.db`, `Icon` followed by CR (U+000D), `~$*`, `.~lock.*#`, `*.swp`, `*.swo`, `*.swx`, `4913`, `*~`, `#*#`, `*___jb_tmp___`, `*___jb_old___`, `.goutputstream-*`, `sed` followed by six ASCII letters or digits;
  - folders: `(A Document Being Saved By …)`, `.Trashes`, `.Trash`, `.Trash-*`, `.Spotlight-V100`, `.fseventsd`, `.DocumentRevisions-V100`, `.TemporaryItems`. Any other folder, a dot folder included, is real.
  - An existing document with such a name is real. The names a file manager gives a copy beside a file (`x copy.txt`, `x (1).txt`) are real names in a tree, and, in the flat view, scratch only as `COPY` destinations; a plain `PUT` of one there is `403`.

- **Delete, then write.** Some clients delete a file before writing it again, or about a second after any refused upload (rclone). So:

  - A write to a path the same user deleted within the last 30 seconds restores that file rebased on its last live document (§8.2).
    - A restore whose patch set would exceed `opsPerSet` or `patchSetSize` is written as a whole-document `replace` when its base is the last live document.
    - If the restore is refused (`403`, `410`), the write creates a new file or is refused as such a write would be.
    - A file that was moved away (its document has `$successor`), or whose last revision the gateway can't read, is never restored this way. A failed read fails the write (§H.4).
  - If such a write is refused, the user's delete, never one older than 30 seconds, is undone where it can be.
  - A refused `PUT` or `COPY`, a refused move onto a file, or a refused case variant (§H.2) sets a guard: that user's `DELETE` of that path within the next 10 seconds is `409`, once per refusal. A `DELETE` that carries `If-Match` passes, and leaves the guard in place. A refused plain move sets none, two refusals never share one guard, a guard ends only by time, and none is set after an undo. Guards are sized for many uploads at once.

- **Locks** (`LOCK`, `UNLOCK`) are kept by the gateway, per user, bounded, and never sent to the core. A `DELETE` drops the user's locks on the path and below (RFC 4918, section 9.6), and a `MOVE` or `COPY` sent with the source's lock token isn't `412` for want of a lock on the destination.

- **Dead properties** (`PROPPATCH`) are refused, or kept by the gateway per user and scope (§H.7). A property the gateway doesn't keep is never acknowledged.
  - Kept properties are bounded: past the bound, the least recently set path's are dropped.
  - Kept properties are moved with a `MOVE` and dropped with a `DELETE`.

- **Listings.** A listing of `Depth: infinity` is `403` (`propfind-finite-depth`); `PROPFIND` without `Depth` is `1`, not RFC 4918's infinity (section 9.1).

- **Headers.** A gateway serves raw files itself, from `…/raw` or the blob, under the revision's `ETag`, never as a cross-origin redirect. Every response it gives, JSON files, scratch files and error bodies included, carries `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox` (PDFs excepted from the sandbox, §7.8).

- **Status codes.** Clients read `423` as "retry later" and `507` as a full disk; they are used only for what they mean.

## H.7 Access and encryption

- **Grants.** A gateway either passes each user's grant through as the bearer of every core request, or narrows its own grant per user with `via` (§C.1); either way the core authorises every core read and write.
- **Users.** A user is the root `sub` with the `key` that verified the root block, from `GET /ns/{ns}/principal` (§7.4). After a key rotation the person is a new user.
  - A user's own entries are those whose `grant` has its `sub` and a `kid` that named, when written, its `key`.
  - One token's reading of the namespace documents serves another only once that one has read a range of the namespace log. For a token that can't read them (§C.5), a `kid` counts as naming the key it names now.
  - With authentication disabled, a user is an `X-Author` (§7.2), and its entries those with that `author`.
  - Operator grants (`operator: true`) are never users of a gateway (`403`).
  - With a narrowed gateway grant, the user is the one named in `via`. The core's rate buckets, pending blobs and recorded authorship are then the gateway principal's, shared by its users (§6.6, §7.8). A user's own entries are then only those the gateway recorded writing for it.
  - One bearer used for everyone, or one grant several programs share, is one user.
- **What a user's tokens share.**
  - State that holds no content (guards, the user's own deletes, move-aside marks, records) is per user.
  - State that holds content (scratch files, placeholders, locks with their owners, dead properties) is kept per user and **scope**, the token's rights. It is served only to a token of that scope whose grant names the namespace.
  - The rights are its root block without `kid`, `sub`, `nbf`, `exp`, `enc` and `signers`, and its narrowing blocks without `nbf` and `exp`, with `ns`, `can`, `roles` and `groups` compared as sets.
  - Caches of what was read (documents, graphs, listings, writer blocks) are per token.
  - Each kind of per-user state is bounded per user. A new scope when content scopes are full is `503` with `Retry-After`, never a drop of one holding content.
- **Re-checking.** A gateway creates state for a grant only after the core has accepted it, bounds the users it keeps state for, and re-checks a grant at least every five minutes. It relies on a `writer` block (§7.4) for 30 seconds at most, and reads it again after `409 frozen`, `422 nonce` or a limit refusal. When the core refuses a token, the gateway stops serving it; the user's state stays for their other tokens, each re-checked at its next request.
- **Limited grants** list a tree through the index (§H.3), and a flat view only through filtered `/heads` (§7.9). They learn what they may write from `GET /ns/{ns}/principal` (§7.4).
- **Folders as access.** Read rules on `/doc/folder` give a grant a subtree (§7.9), its own folder document included: `{ "any": [{ "op": "test", "path": "/doc/folder", "schema": { "pattern": "^/team-a(/|$)" } }, { "all": [{ "op": "test", "path": "/doc/folder", "value": "/" }, { "op": "test", "path": "/doc/name", "value": "team-a" }] }] }`. Write rules guard `folder` and `name` (§6.4.4), else anyone who may edit a file, even one it can't read, may move it into its own view or another's. In end-to-end trees `/doc` rules fail (§6.4.1), so such grants read nothing there; in sealed ones they read with a view key (§E.2.3).
- **Sealed and end-to-end namespaces** need keys (Addendum E). A gateway without them doesn't offer those namespaces, and never shows their files as writable empty files.

## H.8 WebDAV

One mapping, as an example:

| WebDAV                      | In a tree                                                                | In the flat view                                               |
|-----------------------------|--------------------------------------------------------------------------|----------------------------------------------------------------|
| `PROPFIND` (`Depth` 0 or 1) | the index's listing of the folder (§H.3)                                 | `/heads` (§H.3)                                                |
| `GET`, `HEAD`               | its bytes for a raw file (§H.6), the rendering for a JSON file           | the same                                                       |
| `PUT`                       | §H.4                                                                     | §H.4                                                           |
| `DELETE`                    | §H.5                                                                     | delete the resource                                            |
| `MKCOL`                     | a folder document                                                        | `403`                                                          |
| `MOVE`                      | §H.5                                                                     | `403`, or a create and a delete with `$successor` in one batch |
| `COPY`                      | §H.5                                                                     | a new resource                                                 |
| `LOCK`, `UNLOCK`            | in the gateway (§H.6)                                                    | the same                                                       |
| `PROPPATCH`                 | refused, or kept in the gateway (§H.6)                                   | the same                                                       |
| `POST`                      | `405`                                                                    | `405`                                                          |

## H.9 Open questions

- Line-level merges for text files, which are raw and conflict as a whole.
- A tentative delete, or an atomic "replace content", for clients that delete before they write, so other readers don't see the deleted window.

---

# Addendum J — Streams (suggested, non-normative)

A **stream proxy** forwards a request to an upstream HTTP API and keeps the streamed response, so a client that loses its connection resumes where it stopped. The Durable Streams proxy protocol is one such design. This addendum builds one from core requests; the server checks nothing new.

## J.1 The stream document

The proxy keeps each upstream response as one resource, in a namespace of its own such as `streams`, with `read: "grant"`. It writes with a grant that allows `create`, `append`, `read` and `purge` there:

``` jsonc
// /r/streams/{id}
{ "upstream": { "method": "POST", "status": 200, "contentType": "text/event-stream" },
  "chunks": [ "data: {\"delta\":\"Hel\"}\n\n", "data: {\"delta\":\"lo\"}\n\n" ],
  "closed": { "reason": "complete" } }   // or "aborted", "error", "timeout", "size"; with "error"? and "next"?
```

- **Names.** The proxy learns its caller from `GET /ns/{ns}/principal` (§7.4) with the caller's grant, in a namespace of its choosing that callers' grants name; a grant narrowed to `"can": []` suffices. It draws `{id}` at random, or derives it from that answer's `key` and `principal.id` (a `sub` is unique only under its key) and a request key the caller sends, so a repeated request finds its stream. It is a name of §3.6, short enough that its continuations' are too. Names aren't secret: reads need the grant (J.3).
- **Chunks** are UTF-8 text, split at line ends, as `text/event-stream` and NDJSON allow. A body that isn't text is out of scope; it would go in blobs (§7.8).
- **Nothing secret.** The document holds no request headers, `Authorization` above all, and no upstream URL. `closed.error` is one of a few fixed sentences, as a library's error text may name the URL or host.
- **Size.** A chunk stays far below `valueSize`. Each append costs the stream's size so far, so where latency matters a stream continues well below `documentSize` (§6.6), at 256 KiB say. A `$schema` on the stream document revalidates the whole array on every append.
  - A stream about to pass that size closes with `"size"`, naming its continuation `{id}.{n}` in `next`, `n` counting from 1.
  - The proxy bounds the continuations. One that fills the last closes with `"size"` and an `error`, without `next`.

## J.2 Writing

1.  **Create** the resource with `If-None-Match: *` (§7.2), holding `upstream.method` and `"chunks": []`, before calling upstream. A `200` (the same create, retried) or a `412` means the stream exists: return it, and don't call upstream again. An orphan, whose proxy died before calling upstream, ends `"timeout"` (Restarts). A `410` means it was removed.
2.  **Call upstream.** Record `status` and `contentType` in the first append. An answer of any status, a `3xx` included and not followed, is kept with its body and closed `"complete"`. A call that gets no answer, is cut short or gets a body that isn't text closes with `"error"`; the proxy still answers its own caller as its protocol says.
3.  **Append** each flush as one patch set adding to `/chunks/-`, with a fresh `$nonce` (§C.7) and `If-Match` on the proxy's last revision, so no append lands twice (§7.2).
4.  **Close** with a last append that sets `closed`.

- **Restarts.** Upstream can't be resumed. A proxy that restarts closes its open streams with `"error"`, and a stream with no append for the deployment's set time, one for all its proxies, is closed by any proxy with `"timeout"`, the one carrying it included. A proxy that finds its stream closed by another cancels upstream and appends nothing more.
- **Pace.** Rate limits count by the proxy's principal (§6.6). Flush each stream at most every 200 ms, leaving room for aborts. `ratePerPrincipal` bounds how many streams the proxy carries at once; an allowance raises it. Callers' aborts, refused ones included, draw on the same buckets, so a caller can slow every stream; a proxy that can't accept this takes aborts itself and hands out `can: ["read"]`.
- **The namespace log** records every append (§3.5), so keep `streams` apart from namespaces that consumers follow.

## J.3 Reading and resuming

- **The read grant.** The proxy hands its caller the resource's URL and its own grant, narrowed (§C.1). The narrowing block names the caller in `via`, fixes the resource and its continuations, and allows appends only to `/abort`:

  ``` jsonc
  { "via": "{caller}", "can": ["read", "append"], "exp": "…",
    "rules": [ { "op": "compare", "path": "/resource", "in": { "value": ["{id}", "{id}.1", "{id}.2"] } },
               { "if":   [{ "op": "test", "path": "/action", "value": "append" }],
                 "then": [{ "op": "writes", "within": ["/abort"] }] } ] }
  ```

- **Following.** A reader loads the document (§11), then long-polls `GET /r/streams/{id}/log?since={rev}&live=long-poll&cursor={c}` (§7.7) and joins the chunks each entry adds. The last revision it saw is where it resumes; an empty `since` starts from the beginning. Readers who exchange the grant for an edge-grant cookie (§C.5.2) share one CDN answer.
- **The end** is the revision that sets `closed`. A `"size"` close with `next` continues in that resource, from its beginning.

## J.4 Abort, expiry and encryption

- **Abort.** The caller appends `{ "op": "add", "path": "/abort", "value": true }`, with a fresh `$nonce` where the namespace requires one (§C.7, as `GET /ns/{ns}/principal` says) and `If-Match` on the head it last saw, and on `412` retries on the head the body gives. The proxy's next append then gets `412`, or the proxy sees the entry while following the log between chunks. It reads the new entries, never resending blindly, cancels upstream and closes with `"aborted"`. An abort after `closed`, or of any value but `true`, is ignored.
- **Expiry.** The core deletes nothing by age, and retention prunes only history (§8.6). A stream's read grants have the `exp` counted from its creation (its first log entry's `created`), also when a repeated request hands one out again, or the proxy grant's own if earlier, which a narrowed grant never outlives (§C.2 item 1). After it the proxy answers that request `410` and, once the stream is closed, purges it and its continuations (§8.3).
- **Encryption.** This design is for a `streams` namespace that is neither sealed nor end-to-end: keys are wrapped to the root block's `enc` (§E.2.3), so a narrowed grant opens nothing for the reader, and at E3 the abort rule can't be judged (§6.2).

## J.5 Shared sessions

A **shared session** is a namespace in which several people and agents work on the same documents at once. It needs nothing beyond the core.

- **One namespace per session,** with `read: "grant"`.
  - The documents people work on, such as a plan or a draft, are ordinary resources.
  - Each message is a resource of its own, `m-…`, so people posting at once never conflict. The namespace log orders them the same way for everyone.
  - Streams live in a companion namespace, `{session}-streams`, so the session's log stays readable (J.2). A recorded call (J.7) adds only its own document to the session. A sealed or end-to-end session has no companion, so it doesn't stream replies or record calls (J.4 Encryption).
  - A session's name is at most 56 bytes, so that its companion's is a name (§3.6).

  ``` jsonc
  // /r/session-42/m-1794833504178064434
  { "author": "user:bo", "text": "@shared add a packing list to the plan", "to"?: "agent:shared" }
  ```

- **Who acts.** People edit as themselves. An agent acts through the person's grant narrowed with `via` naming it (§C.1), or, shared by all, through a grant of its own. Each log entry records `author` and `via` (§7.1, §7.4). The server verifies `user:anna`; `via agent:claude-code` is what her narrowing named.
- **Roles, not grant rules,** limit what participants write, since a grant whose rules refer to `/resource` loses unrestricted `read` and with it the session's whole log (§2.1, §7.9). Every grant names `reader`, since `member` never counts for reading the log: its rules refer to `/resource`. Members add `member`:

  ``` jsonc
  "roles": {
    "reader": { "can": ["read"] },
    "member": { "can": ["read", "create", "append", "restore", "delete"], "rules": [
      { "if":   [{ "op": "test", "path": "/resource", "schema": { "type": "string", "pattern": "^m-" } }],
        "then": [{ "op": "test", "path": "/action", "value": "create" },
                 { "op": "compare", "path": "/doc/author", "eq": { "path": "/principal/id" } }] },
      { "if":   [{ "op": "test", "path": "/principal/via", "schema": { "minItems": 1 } }],
        "then": [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append"] } }] } ] },
    "forker": { "can": ["read", "branch"] } }
  ```

  - The first rule lets a member only create a message, in their own name, and never change, delete or restore it.
  - The second limits a grant with `via` to creating and appending: deleting and restoring stay with the people. `forker` has no such rule, so add it there if agents mustn't branch. A shared agent's own grant isn't limited.
  - A rule on `/principal/via` can narrow agents in any other way.
- **A shared agent** is a service on the public API. It follows the session's log by long-poll (§7.7) and answers the messages addressed to it, in log order, so messages sent at once queue rather than conflict. It runs an agent with the tools of J.6 under its own grant, and posts the reply as its message. A reply can stream (J.2): the message then names its stream as `/r/{session}-streams/{id}`, which a schema may mark `x-ref` (§6.5), and a stream's read grant (J.3) goes to a caller whose own grant reads that message.
- **Joining and resuming.** A participant who joins late loads the documents (§11), then follows the session's log.
- **Forking.** Trying another direction is a branch of the session namespace (§7.6). The branch reads the earlier documents and messages through its base and leaves the session unchanged. Keeping its outcome is a merge (Addendum F).
- **Left to the application:** presence and typing (§11), and any turn order stricter than the log's.

## J.6 Agents through MCP

An agent takes part through tools, served over the Model Context Protocol so that any agent that speaks it can use them. Each agent's tools run under the grant it acts with (J.5).

| Tool | Request | Answer |
|---|---|---|
| `session_info` | `GET /ns/{ns}/principal` | Who the agent is, and the session's conventions |
| `list_documents` | `GET /ns/{ns}`, then that revision's `/heads` (§7.4) | Names and revisions, without `m-…` and `c-…` unless asked |
| `read_document` | `GET /r/{ns}/{name}`, following the `302` | The document and its revision, without `$nonce` |
| `create_document` | `PATCH` with `If-None-Match: *` (§7.2) | The revision, on `201` or `200` (a retry); on `412`, the current document; on `410`, the deleted one |
| `edit_document` | `PATCH` with `If-Match` on the revision read, and a fresh `$nonce` (§C.7), kept when resending | The new revision; on `412`, the current document and who changed it; on `422`, the refusal, with nothing applied |
| `document_history` | The resource's log (§7.1) | Each change's `author`, `via`, time and patch |
| `recent_changes` | `GET /ns/{ns}/log?since=`, optionally long-polled (§7.7) | Changes with who made them, and the next `since` |
| `post_message`, `read_messages` | Creating `m-…`; the log | As J.5 |

- **Edits are patches against what the agent read.** On a conflict, the agent reads the current document and redoes its change against it. It never resends a refused patch unchanged, and never replaces a whole document to get past a conflict.
- **`test` operations** (RFC 6902) state what an edit assumes, so the server refuses it when the assumption no longer holds.

## J.7 Recording model calls

The proxy of J.1–J.4 can stand between each participant's agent and its model API, so that what agents say is kept beside what they do.

- **One base URL per participant,** `…/p/{id}`. `{id}` is random and secret: it stands for that participant's grant, which never goes in a URL.
- **Each call** is a document `c-…` in the session, written under that grant: `author`, `agent` (the `via`), `api`, `model`, the number of turns, the call's last turn only, and the tool names. Its stream goes in `{session}-streams`, under a grant that can also purge it (J.1, J.4). Once the stream closes, the document gets the assembled `response` (text, tool calls, stop reason, usage) and `closed`.
- **The agent never waits on the recording.** It gets the upstream's bytes unchanged, and the recording runs beside it: a failure loses the record, not the call. Keys pass through to the upstream and are never stored.
- **Within limits.** Agents resend the whole conversation on every call, so only the newest turn is kept, strings are clipped below `valueSize` as canonical JSON, the closing append stays below `patchSetSize`, and each document below `documentSize` (§6.6).
- **Only where the agent takes a base URL.** An agent signed in to its vendor's own backend can't be recorded this way; its tools (J.6) work regardless.
