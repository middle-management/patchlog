---
name: patchlog-client
description: Writing to a patchlog server well (HTTP API or `patchlog` CLI). Use it to size patch sets, handle retries and conflicts, and choose between a direct write, a batch and a branch, and to merge, squash or rebase branches.
---

# Working with patchlog as a client

Each resource is an append-only log of JSON Patch sets, and each set becomes a revision. The log
is the history, the undo unit, the merge input and the audit trail, so cut writes with care.
Section numbers (§) refer to `docs/SPEC.md` and `docs/TOOLS.md`.

- **HTTP without the CLI:** [http.md](http.md) maps each command to its request.
- **Branching, merging, squashing or rebasing:** read [merging.md](merging.md).

## Model

- **Resource** `/r/{ns}/{name}`: the head is the `ETag` of the `302`. **Every write is
  conditional:** `If-None-Match: *` creates, `If-Match: "{head}"` appends. Without a
  precondition you get `428`; a stale `If-Match` gets `412 {head}`.
- **Namespace** `/ns/{ns}`: config, rules, grants and limits. It is the unit you branch, freeze
  and purge.
- **Batch** `POST /ns/{ns}/batch`: several resources of **one** namespace, all or nothing.
  Nothing is atomic across namespaces.
- **Gesture:** 26 characters of `[a-z2-7]`, chosen per *user action* and sent as `Gesture:` on
  each of its writes, so undo treats them as one action.

## Rules

1. **One patch set per coherent change, one gesture per user action.** Not one set per
   keystroke, and not a day of edits in one set.
2. **Use minimal paths.** Replace `/score`, not the document. Conflicts, undo and rules all use
   the paths you write. A root `replace` is only for a deliberate overwrite.
3. **Guard with `test` ops** when the change depends on the values you read.
4. **On `412`:** sync from your head to the new one, then resend **the same patches** with the
   new `If-Match`. Never send a head-to-new diff, which reverts others' edits. Bound the retries.
5. **On a lost response:** resend the identical request. The server answers an identical retry
   with the original result.
6. **Combine rapid edits.** Keep at most one save in flight per resource. Collect later edits
   into one pending set: the diff from the last *saved* revision. Send it when the response
   arrives. Rate limit default: 10 writes/s per resource.
7. **Nonces:** where the namespace requires nonces or is sealed, every set adds a fresh
   `$nonce`.

## Large changes

Limits default to the values below. A namespace may set lower ones: `GET /ns/{ns}/principal`
(or `patchlog whoami NS --json`) shows the limits in force.

| Limit | Default | If exceeded |
|---|---|---|
| `patchSetSize` / `opsPerSet` | 256 KiB / 1,000 | Split into several appends, or chained steps of one batch item |
| `documentSize` | 1 MiB | Split into resources linked with `x-ref` |
| `valueSize` (largest string) | 64 KiB | Store as a blob (`PUT …/blob/{bid}`, then reference it) |
| `itemsPerBatch` / `batchSize` | 1,000 / 16 MiB | Several batches, or a branch |

- Create a large document whole (up to `documentSize`), then edit it in parts.
- Parts that must land together go in **one batch item as chained steps**:
  `"steps": [[…], […]]`.
- A `422 limit` names the limit it hit (`limit`, `measured`, `max`). Split; don't retry.

**Document design.**
- Split documents by who reads them, who edits them and how big they grow.
- Where many parties add entries to a list, make each entry its own resource.
- For merges, a write to any array element counts as a write to the whole outermost array.
  Independently edited items belong in separate resources, or in an object keyed by id with an
  `order` field.

## Responses

| Response | Do |
|---|---|
| `201`, or `200` (an idempotent retry) | The returned id is your new head |
| `412 {head}` | Rule 4 |
| `422 invalid` | A `test` failed, a patch didn't apply, or the schema rejected it. Surface it; don't force it |
| `422 limit` | Split |
| `429` | Wait `Retry-After`; keep combining edits |
| `409 frozen` + `successor` | Reload from the successor and replay your pending sets there |
| `410` | Deleted, purged or pruned. Don't write blindly; offer a `successor` if one is given |
| `401` / `403` | Report it; don't retry |

**CLI.**
- `patchlog patch` retries on `412` against the new head. Use `--if REV` plus `test` ops when the
  patch depends on what you read.
- `--gesture ID` groups writes into one action.
- `batch NS FILE --dry-run` checks a batch before you send it.

## Direct write, batch or branch?

| Choose | When |
|---|---|
| **Direct write** | Small, independent changes that can be visible at once: live edits, autosave, counters, appends |
| **Batch** | Several resources of one namespace must change together now (a move, a rename, create-and-link). Dry-run first (`?dry-run=1`) |
| **Branch** | Review needed, work that must not show half-done, bulk or generated edits (scripts, migrations, agents), timed releases, private drafts. See [merging.md](merging.md) |
| **Release** | One coordinated change across several namespaces (`patchlog merge release`, §F.9) |

An agent making more than a handful of edits, or any edit a person should check, works in a
branch and hands over a merge plan.

Encrypted namespaces follow the same rules. At E3, re-seal on every retry. Read §E.3 first.
