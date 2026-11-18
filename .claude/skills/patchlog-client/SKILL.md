---
name: patchlog-client
description: How to write to a Patch Log (patchlog) server well, as an app, a script or an agent. Covers sizing patch sets, combining rapid edits, splitting large changes, retries and conflicts, when to write straight to a namespace, when to use a batch and when to use a branch, and how to merge, squash, rebase and clean up branches. Use it when code or commands write documents through the patchlog HTTP API, the `patchlog` CLI or `internal/client`, and when planning bulk edits, migrations, reviews or releases on a patchlog namespace.
---

# Working with patchlog as a client

Patchlog stores each resource as an **append-only log of JSON Patch sets**. Each set becomes a
content-addressed revision. The log is the history, the unit of undo, the merge input and the
audit trail, so **how you cut your writes matters as much as what they write.** This guide is
the practical part of TOOLS.md §11 (client behaviour) and Addendum F (branches), plus the
`patchlog` CLI. The spec sections are named in brackets so you can check details.

## Mental model (read first)

- **Resource** `/r/{ns}/{name}`: one JSON document plus its log of revisions. The head is
  `X-Revision` / `ETag`.
- **Every write is conditional** (§7.2): `If-None-Match: *` to create, `If-Match: "{head}"` to
  append. A write with no precondition gets `428`. A stale one gets `412` with `{ head }`.
- **Namespace** `/ns/{ns}`: config, rules, grants and limits for its resources, and a
  namespace log. It is the unit you branch, freeze and purge.
- **Batch** `POST /ns/{ns}/batch` (§7.5): several resources in **one** namespace, all or
  nothing. Nothing is atomic across namespaces.
- **Branch** (§7.6): a new namespace that reads through to its base as it was at `at`. Merge
  and rebase are **client procedures** built from batches, not server operations (Addendum F).
- **Gesture** (§7.2, §11.2): a 26-character base32 id you choose for each *user action*. You
  send it as `Gesture:` on every write the action makes, so undo and redo treat those writes as
  one action.

## Golden rules

1. **One patch set is one coherent change. One gesture is one user action.** Don't send a
   set per keystroke, and don't send a day of edits as one set.
2. **Write the smallest paths that express the change.** Replace `/score`, not the whole
   document. Merge conflicts, undo and rules all work on the paths you write (`writes`,
   §6.4.1).
3. **Guard what you depend on with `test` ops** when a change only makes sense on the values
   you read (§11, Conflict safety).
4. **On `412`, sync and resend the same patches. Never send a fresh diff against the new head.**
   A head-to-new diff silently reverts other people's edits (§11.3).
5. **If a response is lost, resend the request unchanged.** The server answers an identical
   retry with the original result (idempotent retry, §7.2).
6. **Use a branch for anything that needs review, must not be seen half-done, or is a risky
   bulk edit.** Write directly only for small, independent, immediately-visible changes.
7. **Merge by replay (the default). Squash only on purpose.** Freeze the branch after merging.

## 1. Cutting patch sets

### Size by intent

| Situation | Do |
|---|---|
| A user edits one field | One set, a minimal `replace`/`add`/`remove`, with the action's `Gesture` |
| Rapid edits: typing, dragging, autosave | Combine them (below). Never one write per event |
| One action touches several fields of one doc | One set |
| One action touches several docs in one namespace | One **batch** with one `gesture`, one item per doc |
| One action spans namespaces | One write or batch per namespace with the **same** `Gesture`. It is not atomic, so plan for partial failure (or use a release, §F.9) |
| Deliberate overwrite of a whole document | A root `replace` with `If-Match: "{head}"`, only when the user means it (§11.3 step 4) |

### Combining rapid edits (client-side squash)

`ratePerResource` defaults to **10 writes/s, burst 20** per principal (§12.2), and every
revision costs storage and log reads. So (§11):

- Keep **at most one save in flight per resource**.
- While it is in flight, collect new edits into **one pending set**: the diff from the last
  *saved* revision to the current local state.
- When the response arrives, send the pending set with `If-Match` set to the new revision.
- If the in-flight response was lost, first resend the in-flight set **unchanged**, then the
  pending one.
- On `429`, wait for `Retry-After`.
- A combined set carries one `Gesture`, so it undoes as one action. Don't combine edits that
  belong to different user actions if the user should be able to undo them separately.

### Large changes: split, batch or blob

Default limits (§12.2; a namespace may set lower ones, so check `GET /ns/{ns}/principal` or
`patchlog whoami NS --json`):

| Limit | Default | If you hit it |
|---|---|---|
| `patchSetSize` | 256 KiB | Split into several appends, or several steps of one batch item |
| `opsPerSet` | 1,000 | Same |
| `documentSize` | 1 MiB | Split the document into several resources linked with `x-ref` (§6.5, §11.1) |
| `valueSize` (largest string) | 64 KiB | Store it as a blob (§7.8), e.g. `patchlog blob put NS/NAME FILE --at /path` |
| `itemsPerBatch` / `batchSize` | 1,000 / 16 MiB | Several batches, or a branch merged in one go |

- **Large documents are created whole, then edited in parts.** A create (and a restore) may be
  as large as `documentSize`; appends are capped at `patchSetSize` (§6.6, Whole documents).
- **Parts that must land together** go in one batch, as **chained steps** of one item:
  `"steps": [[…part 1…], […part 2…]]`. Each step becomes its own revision, and the batch commits
  all of them or none.
- A refusal names the limit: `422 {"code":"limit","limit":"opsPerSet","measured":…,"max":…}`.
  Split by that limit. Don't retry the same request.

### Designing documents so patches stay small (§11.1)

- **Split documents along lines of access, editing and size.** A document is the unit of read
  access, concurrency, rate limits and merge conflicts. Split one that grows without bound, has
  parts with different readers, or is edited by unrelated people at the same time.
- **Lists that many parties add to:** make **each entry its own resource**. Creates of
  different resources never collide. Appending to one shared array makes every writer queue
  behind one head.
- **Arrays and conflicts.** For merge and rebase, a write to an array element (or an append
  with `-`) counts as a write to **the whole outermost array** (§F.3). So two branches that
  touch different items of one array conflict. If items are edited independently, make them
  separate resources, or keep them in an object keyed by id. Object member order isn't kept,
  so keep an explicit `order` field.
- **`$nonce`.** Where the namespace requires nonces or is sealed (§C.7), **every** patch set
  must add a fresh `$nonce` (`422 nonce` otherwise). Never restore an old one.

## 2. Writing and handling errors

```text
load     GET /r/{ns}/{name}            → 302 to …/rev/{head}; head = X-Revision
submit   PATCH /r/{ns}/{name}           Content-Type: application/json-patch+json
         If-Match: "{head}"   Gesture: {g}   Authorization: Bearer … (or X-Author in --dev)
sync     GET …/rev/{to}/log?since={head}   (follow pages until `to` arrives)
watch    SSE or long-poll since={head}; de-duplicate by entry id (your own writes echo back)
```

| Response | Meaning | Do |
|---|---|---|
| `201` | Written | Apply the returned revision. It is your new base |
| `200` on a write | Idempotent retry matched | Same as `201` |
| `412` + `{head}` | Someone wrote first | `sync(head)`, re-apply locally, resend **the same patches** with the new `If-Match`. Use a bounded number of retries. Whole-document clients first check that their writes don't overlap the ones since their base (§11.3) |
| `422 invalid` | A `test` guard failed, a patch didn't apply, or schema validation failed | Surface it to the user (or caller). It is a real conflict or a bug. Don't force it |
| `422 limit` | Too big | Split (section 1) |
| `428` | Precondition missing | Always send `If-Match` or `If-None-Match` |
| `429` | Rate limited | Wait for `Retry-After`. Combine pending edits meanwhile |
| `409 frozen` + `successor` | Namespace frozen, e.g. a branch was rebased | Load from the successor and replay your pending sets there |
| `410` | Deleted (tombstone), purged, or pruned | Don't write blindly. If there is a `successor`, offer it (§8.1, §11) |
| `403` / `401` | Grant doesn't allow it | Report it. Don't retry |

CLI note: `patchlog patch NS/NAME '[…]'` re-reads the head and **tries again** on `412`. That's
fine for blind edits like counters or appends. When the patch depends on what you read, pin the
revision with `--if REV` and add `test` ops. `put` and `ns create` send `If-None-Match: *`.
`--gesture ID` groups CLI writes into one action. Use `batch NS FILE --dry-run` before risky
batches.

## 3. Direct write, batch or branch?

| Use | When |
|---|---|
| **Direct write** to the namespace | Small, self-contained changes that are fine to be visible at once and need no review: live edits, autosave, counters, appends, one-document fixes |
| **Batch** (no branch) | Several resources of **one** namespace must change together **now**, e.g. a move, a rename across docs, or create-and-link. Dry-run it first (`?dry-run=1`) |
| **Branch** | Changes that need **review or approval**; multi-step work that must not be seen half-done; **bulk or generated edits** (scripts, migrations, AI agents); schema migrations (§F.1); releases published at a set time (§F.9); private drafts of public content (`read: "grant"`); catalog reorganisations |
| **Release** (branches across namespaces, §F.9) | Coordinated change across several namespaces (`patchlog merge release`) |

**If you're an automated agent making more than a handful of edits, or any edit a person
should check, work in a branch** and hand over a merge plan instead of writing to the base.

### Branch hygiene

```sh
patchlog branch create matches fix-scores \
  --patch '[{"op":"replace","path":"/read","value":"grant"},
            {"op":"add","path":"/cleanup","value":{"merged":"P7D","superseded":"P30D","abandoned":"P30D"}}]'
patchlog patch fix-scores/derby '[…]'       # reads fall through to the base as of `at`
```

- **One branch per topic, short-lived.** The base keeps moving, and the branch sees it only
  after a rebase. The longer a branch lives, the more it conflicts.
- **Set `cleanup` when you create it.** `cleanup` isn't copied from the base, and without it
  the janitor never purges the branch (§F.6).
- **Branch names are visible to the base's readers** (in its log and branch list). Use neutral
  names for sensitive work.
- **A branch of a non-public namespace can't be public.** Use `read: "grant"` for drafts.
- **Grants name namespaces explicitly.** A grant for `matches` doesn't work in `fix-scores`.
  Issuers must add the branch.
- **Limits:** 100 live branches per namespace, depth 8 (branches of branches).
- **Config changes don't merge implicitly.** Changes meant for the base's config go in the
  merge batch's `config` (`merge apply --config FILE`).

## 4. Merging

```sh
patchlog merge status --branch fix-scores           # per resource: ahead, behind, clean, conflicting
patchlog merge plan   --branch fix-scores           # the batch, plus a server dry run
patchlog merge apply  --branch fix-scores --freeze  # one batch into the base, then freeze with merged.at
```

What the planner does per resource (§F.3):

- **Fast-forward** when the base hasn't changed it since the branch's revision. The steps
  are copied, and the **ids are identical** to the branch's. This is the best case.
- **Replay** when both sides changed it. The branch's sets are re-applied on the base's head
  and get new ids. **Always review a replay.** It conflicts if the two sides' `writes` overlap
  (whole outermost arrays, see above) or if history it needs was pruned.
- **Always needs a person:** deleting a doc the base has since changed, or changing a doc the
  base has since deleted.

### Resolving conflicts

`--resolve NAME=FILE.json` replaces a conflicting resource's steps with one resolution against
the **base's current head**. FILE is one of:

- a patch set
- a list of steps
- `"delete"`
- `"keep"`, to keep the base's version. It is still recorded, so the next merge doesn't offer it
  again.

If the base moves during `apply`, affected items fail with `412`. Re-run `plan`/`apply`, which
re-classifies against the new head.

### Replay or squash?

**Replay (the default) keeps:**

- each revision and its `test` guards
- fast-forward ids (so stacked branches retarget almost for free, §F.4)
- each step's `gesture`/`undoes`, so undo in the base still groups actions

**`--squash`** replaces each resource's steps with **one set that has the same net effect.**

- **Squash when:**
  - the branch history is noise nobody needs in the base, such as autosave churn, an agent's
    trial and error, or many tiny fix-ups
  - you want the base's log to show one reviewed change per document
- **Don't squash when:**
  - users need per-action undo in the base. Squashing drops gestures, and `Undoes` that names a
    dropped gesture is ignored.
  - other branches are stacked on this one. They lose fast-forwards.
  - the `test` guards matter
- **A squash set must still fit `patchSetSize`/`opsPerSet`.** A branch that rewrote a large part
  of a document may produce a set that's too large. If the dry run reports `limit`, merge without
  `--squash`, or split the work into smaller branches.
- Squash only ever covers **one resource's steps in one merge**. To shrink a long base log, use
  pruning (`patchlog prune`, §8.6), which destroys history.

### Merging again, rebasing and cleanup

- **Merging the same branch again** after a replayed merge only picks up new work **if the
  base lists the merger in `merge.authors`** (`{"merge":{"authors":[{"sub","kid"}]}}`, §F.3).
  Without it, rebase first. `status`/`plan` print a hint when this applies.
- **Rebase** when the base has moved a lot, before a second merge without `merge.authors`, or to
  refresh a long-lived branch:
  `patchlog rebase --branch fix-scores --new fix-scores-b --switch`.
  This creates a successor branch from the base's head, replays into it (unchanged resources
  keep their ids), then freezes the old branch with `successor`. Editors of the old branch get
  `409 frozen` and move over (§F.5).
- **After merging, freeze** (`--freeze` records `merged.at`). The janitor
  (`patchlog janitor --ns BASE`) purges merged, superseded or abandoned branches once their
  `cleanup` period has passed, after it verifies the claim (§F.6).
- To give up a branch, a branch admin sets `"abandoned": true` with `frozen`.

## 5. Pre-flight checklist

- [ ] Every write carries `If-Match`/`If-None-Match`, and a `Gesture` per user action.
- [ ] Patch paths are minimal. No root `replace` unless overwriting on purpose.
- [ ] Writes that depend on what was read are guarded with `test`.
- [ ] Rapid edits are combined, with at most one save in flight per resource.
- [ ] Oversize content is split, sent as chained batch steps, or stored as a blob.
- [ ] `412` resends the same patches after a sync. A lost response is resent unchanged.
- [ ] Fresh `$nonce` in every set where the namespace requires it.
- [ ] Bulk, generated, reviewable or release work goes in a branch with `cleanup` set.
- [ ] Merges are `status` → `plan` (review replays) → `apply --freeze`. `--squash` is a
      deliberate choice.

Encrypted namespaces (Addendum E) follow the same rules. At E3 the client re-seals on every
retry, and merges and rebases need a key-holding client (`--identity`). See §E.3 and §F.8.1
before writing tools for them.
