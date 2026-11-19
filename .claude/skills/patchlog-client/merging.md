# Branches, merge, squash and rebase

Part of the [patchlog-client skill](SKILL.md). Merge and rebase are client procedures built from
batches (TOOLS Addendum F), so the server has no merge endpoint.

## Branching

```sh
patchlog branch create matches fix-scores \
  --patch '[{"op":"replace","path":"/read","value":"grant"},
            {"op":"add","path":"/cleanup","value":{"merged":"P7D","superseded":"P30D","abandoned":"P30D"}}]'
patchlog patch fix-scores/derby '[…]'   # unchanged resources read through to the base as of `at`
```

Over HTTP: `POST /ns/{base}/branches` with `If-None-Match: *` and the body `{"name","at"?,"patches"?}`.

- **Keep branches short-lived, one per topic.** A branch sees base changes only after a rebase,
  so the longer it lives, the more it conflicts.
- **Set `cleanup` when you create the branch.** It isn't copied from the base, and without it the
  janitor never purges the branch.
- **Branch names are visible to the base's readers.** Don't give sensitive work a revealing name.
- **Use `read: "grant"` for drafts.** A branch of a non-public namespace can't be public.
- **Grants name namespaces explicitly.** Holders need one issued for the branch itself.
- **Limits:** 100 live branches per namespace, nested at most 8 deep.
- **Config never merges implicitly.** Put base config changes in the batch's `config`
  (`merge apply --config FILE`).

## Merging

```sh
patchlog merge status --branch fix-scores           # per resource: ahead, behind, clean, conflicting
patchlog merge plan   --branch fix-scores [--json]  # the batch, plus a server dry run
patchlog merge apply  --branch fix-scores --freeze  # one batch into the base, then freeze with merged.at
```

The planner handles each resource one of three ways (§F.3):

- **Fast-forward:** the base hasn't changed the resource since the branch took it. The
  branch's steps are copied and the ids stay identical.
- **Replay:** both sides changed the resource. The branch's steps are re-applied on the base's
  head and get new ids. **Always review a replay.** It conflicts when the two sides wrote
  overlapping paths (any write into an array counts as the whole outermost array), or when the
  history it needs was pruned.
- **Always a person:** deleting a doc the base has since changed, or changing one the base has
  since deleted.

**Resolving conflicts.** `--resolve NAME=FILE.json` replaces a resource's steps. The file holds
one of these, written against the base's current head:

- a patch set
- a list of steps
- `"delete"`
- `"keep"`, which is still recorded, so the next merge doesn't offer that resource again

A `412` during `apply` means the base moved: run `plan` and `apply` again.

**Merging again.** After a replayed merge, a second merge of the same branch picks up only the
new work if the base lists the merger in `merge.authors` (`{"merge":{"authors":[{"sub","kid"}]}}`).
Without that, rebase first. `status` and `plan` print a hint when this applies.

## Replay or squash?

**Replay is the default.** It keeps:
- each revision and its `test` guards
- each step's `gesture` and `undoes`, so undo in the base still groups actions
- fast-forward ids, so stacked branches retarget almost for free

**`--squash`** gives each resource one set with the same net effect.

- **Squash when** the branch's history is noise: autosave churn, an agent's trial and error, a
  string of fix-ups. You want one reviewed change per document in the base.
- **Don't squash when** any of these apply:
  - users need per-action undo in the base
  - other branches are stacked on this one
  - the `test` guards matter
- **The squashed set must still fit `patchSetSize` and `opsPerSet`.** If the dry run reports
  `limit`, merge without squashing or split the branch.
- **Squash shortens one merge only.** To shrink a long base log, prune it (`patchlog prune`),
  which destroys the older history.

## Rebase and cleanup

- **When to rebase:** the base has moved a lot, or you need a second merge and the merger isn't
  in `merge.authors`, or a long-lived branch needs refreshing.
  ```sh
  patchlog rebase --branch fix-scores --new fix-scores-b --switch
  ```
  This creates a successor branch from the base's head and replays the old branch into it.
  Unchanged resources keep their ids. It then freezes the old branch with `successor`, so
  editors who still write there get `409 frozen` and move over.
- **Freeze after merging.** `--freeze` freezes the branch and records `merged.at`.
- **Cleanup.** `patchlog janitor --ns BASE` purges merged, superseded and abandoned branches once
  their `cleanup` period has passed, after checking each claim.
- **Giving up a branch:** an admin sets `"abandoned": true` and freezes it.
- **E3 (end-to-end) branches:** merging and rebasing need a client that holds the keys
  (`--identity`, §F.8.1).

## Merge over HTTP

`patchlog merge plan` and `merge apply` run the steps below. In them, BASE is the base namespace
and BR the branch.

**Prefer the tool.** Correct replays have to handle:
- array widening
- delete-versus-change
- earlier merges counting as common ancestors
- pruned history
- nonces

That is about 2,000 lines in `internal/merge`. Instead, have the CLI make the plan: it writes
nothing.

```sh
patchlog merge plan --branch BR --json > plan.json
```

`plan.json` holds the classification (`plan`), whether the plan is conflict-free (`clean`) and
the dry-run report (`dryRun`). Its `batch` is the exact body for `POST /ns/BASE/batch`. An HTTP
client can review `batch` and submit it itself. Hand-write a merge only when every resource
fast-forwards.

1. **Pin the branch.** `GET /ns/BR` gives the branch's `ns_id`: call it `AT`. The branch
   document's `base` names BASE.
2. **Collect** the resources BR changed from `GET /ns/BR/rev/{AT}/log?since=` (paged). Take the
   `resource` of every `head` and `tombstone` entry, and every resource in a `batch` entry.
3. **Classify** each resource:
   - `H` is BR's head as of `AT`.
   - `B` is BASE's head. `GET /r/BASE/{name}` answers `302` (live), `410` (tombstone) or `404`
     (absent).
   - H's chain, from `GET /r/BR/{name}/rev/{H}/log?since=`, reaches back into the base's
     revisions.
   - **`B == H`:** no item.
   - **`B` is in H's chain**, or the resource is absent in BASE and H's chain starts in BR:
     **fast-forward**. The item has `ifMatch: B` (or `ifNoneMatch: "*"`), and its steps are the
     entries after `B`:
     - a `rev` entry becomes `{"patches", "gesture", "undoes"}`
     - a `tombstone` entry becomes `{"delete": true}`
   - **`H` is in B's chain** (from `GET /r/BASE/{name}/rev/{B}/log?since=`): no item.
   - **Otherwise, replay:** find the latest common ancestor `A`.
     - Conflict, for a person: the paths written after `A` overlap on the two sides, with array
       writes widened, or one side deleted what the other changed.
     - Clean: the item is BR's entries after `A`, with `ifMatch: B`.
4. **Dry-run** `POST /ns/BASE/batch?dry-run=1` with the items and
   `"source": {"ns":"BR","at":"AT"}`. If your grant doesn't read BR, add `Source-Authorization`
   with one that does, so the branch's blobs are available.
5. **Submit.** Items whose base moved fail with `412`: classify them again and resubmit, with the
   same `AT`.
6. **Freeze** with `PATCH /ns/BR` and `If-Match: "{config_id}"`:
   `[{"op":"add","path":"/frozen","value":true},{"op":"add","path":"/merged","value":{"at":"<merge's X-Namespace-Revision>"}}]`.

**Squash over HTTP.** Each item gets one step: the diff from B's document to H's.
- Leave `$nonce` out of the diff, and add a fresh one where the namespace requires it.
- A resource absent in BASE gets `[{"op":"add","path":"","value":<H's document>}]`.
- A resource H deleted gets `"delete"`.

**Rebase over HTTP** has three steps:
1. `POST /ns/BASE/branches` creates the successor, with the old branch's `read`.
2. Replay into it with batches carrying `source: {ns: old, at}`.
3. Write `{"frozen": true, "successor": "<new>"}` to the old branch's config.
