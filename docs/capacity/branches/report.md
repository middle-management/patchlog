# What `branchesPerNamespace` and `branchDepth` cost in the reference implementation

Measured 2026-11-19 on the Go reference implementation at spec 0.85. This report is for the
spec writer: it takes §6.6's reasons for the two limits one by one and says what each cost
when measured, and it ends with four questions for the spec.

Spec 0.86 answered the questions, and the implementation has changed since: the last
section, [Afterwards](#afterwards-spec-086-and-the-same-measurements-again), has both. The
sections before it stand as they were sent.

## Summary

- **`branchesPerNamespace` bounds one thing that matters: purges.** A purge in a base costs
  about 1.5 ms per branch it reaches on Postgres, so about 0.15 s at the default of 100.
  Every other reason §6.6 gives costs nothing measurable, or costs the listing one entry.
- **The limit does not bound purges as written.** It counts live branches only, and a purge
  reaches frozen branches like live ones. A base with 100 live and 10,000 frozen branches
  paid for 10,100.
- **`branchDepth` costs every request, as §6.6 says.** Each level adds about 0.07 ms to a
  read and 0.7 ms to a write on Postgres. At the default of 8, a write costs about three
  times what it does in a plain namespace, and write throughput falls to about a third.
- **Two implementation faults were found and fixed along the way.** They are not the spec's
  concern except as background: before the fixes, a purge with 100 branches took 4.9 s.

## Setup

- One 4-vCPU / 15 GB host, which also ran the load generator.
- **Postgres:** the core at 2 vCPU / 4 GB and Postgres 16 at 2 vCPU / 4 GB, each in a
  container.
- **SQLite:** the core in a container with no limit.
- Every run started from an empty database. Every request carried a signed grant (§C).
- Both limits were raised for the measurement (depth to 64, branches to 1,000,000).
- Figures are medians. Purges are the median of 5; reads and writes of 500.
- Not measured: remote branches and remote base chains.

Unless a section says otherwise, each base held 20 plain documents and 20 typed ones, and
one schema the typed ones reference.

## `branchesPerNamespace`

### Postgres, median ms

| Live branches | 1 | 10 | 100 (default) | 1,000 | 10,000 |
|---|---|---|---|---|---|
| Purge in the base: branches don't see the document | 14 | 22 | 95 | 952 | 9,555 |
| Purge in the base: branches read it through | 12 | 30 | 158 | 1,685 | 26,753 |
| Purge in the base: each branch has its own revision | 14 | 34 | 201 | 2,268 | 29,134 |
| Purge in an unrelated namespace | 4.7 | 5.3 | 5.7 | 4.9 | 7.7 |
| Refused purge of the schema (409 `in_use`) | 139 | 196 | 690 | 5,747 | 53,562 |
| Cache purge tags sent per purge | 14 | 32 | 212 | 2,012 | 24,028 |
| `GET /branches` | 0.8 | 1.4 | 8.1 | 64 | 665 |
| Create one more branch | 2.9 | 3.3 | 4.7 | 8.6 | 13 |
| Add a key to the base | 2.3 | 2.1 | 2.6 | 3.1 | 2.4 |
| Add a revocation to the base | 2.3 | 1.9 | 2.3 | 2.7 | 2.0 |
| Create a document in a branch | 3.2 | 3.2 | 3.8 | 5.0 | 4.3 |
| The same, typed by a schema of the base | 4.1 | 4.4 | 4.6 | 6.0 | 5.3 |
| The same, typed by a draft in the branch | 5.0 | 4.8 | 5.7 | 6.7 | 5.8 |

### SQLite, median ms

| Live branches | 1 | 10 | 100 | 1,000 | 10,000 |
|---|---|---|---|---|---|
| Purge in the base: branches read it through | 1.7 | 2.7 | 15 | 143 | 1,671 |
| Slowest write to another namespace meanwhile | 10 | 11 | 15 | 140 | 1,838 |
| `GET /branches` | 0.4 | 0.6 | 1.4 | 13 | 153 |

### §6.6's reasons, one by one

| §6.6 says | Measured |
|---|---|
| **Purges.** A purge has to reach the same name in every branch, recursively, and must finish. | True, and it is the cost that matters. About 1 ms per branch that doesn't see the document and 1.5 to 2.3 ms per branch that does, on Postgres; about 0.15 ms on SQLite. |
| **Keys and revocations.** A revocation in the base takes effect in all of its branches. | No cost at the base: a key or a revocation is written in 2 ms at any branch count. The cost is on the branch's side, per level (see depth below). |
| **Draft schemas.** Looking up drafts considers every local branch of the namespace: a scan over the branches. | Not a scan here. The implementation finds a draft by its revision id, so only branches holding a copy are looked at. A write typed by a draft costs about 1 ms more than one typed by the base's schema, at any branch count. |
| **Cache purges and `/branches` grow by one entry per branch.** | True. Two cache tags per branch that sees the purged document, and 0.07 ms per branch in the listing. `/branches` has no paging, so it is 0.67 s at 10,000. |
| **Abuse.** Each new branch makes the base's purges more expensive. | True for purges only. Nothing else in the base slows down. |

### Other observations

- **Frozen branches cost a purge the same as live ones.** 100 live plus 10,000 frozen:
  25.4 s per purge on Postgres, against 26.8 s for 10,000 live. 100 live plus 1,000 frozen:
  1.9 s, against 1.7 s for 1,000 live.
- **Depth and width multiply.** 100 branches with 100 branches under each (10,100 reached)
  cost 25.0 s per purge on Postgres: the same as 10,000 direct branches. Each level's count
  is within the limit, so two levels at the default allow 10,100 and eight allow 100^8.
- **The number of documents in the base hardly matters.** 5,000 documents instead of 20, at
  100 branches: 186 ms against 158 ms.
- **Whether other namespaces wait depends on the store.** On Postgres the slowest write to
  another namespace during any purge was 53 ms. On SQLite, which has one writer, other
  namespaces' writes wait for the whole purge: 1.8 s at 10,000 branches.
- **A refused purge is the expensive one.** Purging a schema that documents reference means
  finding every namespace that references it, to list them in the 409. Here every branch
  reads 20 typed documents through from the base, so every branch is a referencing namespace:
  0.69 s at 100 branches, 5.7 s at 1,000, 54 s at 10,000.
- **Postgres is not quite linear at the top.** A purge the branches see costs 1.7 ms per
  branch at 1,000 and 2.7 ms at 10,000. The cause was not found.

## `branchDepth`

A chain of branches of branches, measured in the deepest one. The root held 520 documents.

### Postgres, median ms

| Depth | 0 | 1 | 2 | 4 | 8 (default) | 16 | 32 |
|---|---|---|---|---|---|---|---|
| Read a document written in the branch | 0.7 | 0.6 | 0.7 | 0.8 | 1.0 | 1.6 | 2.7 |
| Read one that falls through to the root | 0.5 | 0.6 | 0.7 | 0.8 | 1.1 | 1.7 | 2.6 |
| Read one that exists nowhere | 0.5 | 0.6 | 0.8 | 0.7 | 1.0 | 1.5 | 2.6 |
| Create a document | 2.9 | 3.8 | 5.2 | 5.6 | 9.3 | 14.3 | 25.6 |
| Create a typed document | 3.9 | 4.9 | 5.5 | 6.6 | 10.1 | 15.0 | 27.4 |
| Create one typed by a draft | n/a | 5.7 | 7.5 | 9.1 | 13.9 | 28.7 | 42.0 |
| Append to a document read through | n/a | 4.9 | 5.3 | 7.0 | 10.0 | 16.0 | 27.9 |
| Create a branch at this depth | n/a | 5.1 | 4.3 | 5.0 | 8.6 | 12.8 | 18.7 |
| Purge in the root | 5.7 | 15 | 16 | 24 | 40 | 56 | 134 |
| Reads per second, 16 callers | 7,282 | 5,679 | 5,113 | 4,742 | 3,677 | 1,977 | 1,324 |
| Creates per second, 16 callers | 1,197 | 990 | 772 | 633 | 420 | 258 | 159 |

### SQLite, median ms

| Depth | 0 | 1 | 2 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|---|
| Read that falls through to the root | 0.3 | 0.3 | 0.3 | 0.4 | 0.4 | 0.4 | 0.6 |
| Create a document | 0.7 | 0.7 | 0.8 | 0.8 | 1.0 | 1.3 | 2.1 |
| Purge in the root | 0.8 | 1.7 | 2.7 | 2.3 | 3.8 | 6.9 | 13.6 |
| Creates per second, 16 callers | 2,238 | 2,108 | 1,665 | 1,403 | 1,228 | 845 | 559 |

### §6.6's reasons, one by one

| §6.6 says | Measured |
|---|---|
| **Reads.** A read that falls through asks each level for the head as of `at`; a miss walks the whole chain. | Depth costs every read about 0.07 ms a level on Postgres. But a hit in the branch itself costs the same as a miss: most of the cost is not the walk for the document, it is checking the grant against every base's keys and revocations. |
| **Writes.** Every write is checked against the keys and revocations of every local base. | True, and it is the larger cost: about 0.7 ms a level on Postgres. At depth 8 a create takes 9.3 ms against 2.9 ms, and 16 callers write 420 documents a second against 1,197. |
| **Recursion.** Purge propagation and the remote checks are recursive. | A purge down a chain costs about 4 ms a level on Postgres. Remote checks were not measured. |

The costs are linear in depth, with no step at 8. Depth 16 costs a write five times a
plain namespace's, depth 32 nine times.

## Questions for the spec

1. **Should frozen branches count for purges?** §6.6 counts only live branches, on the
   grounds that each live branch adds work to the base. For the one cost that matters, a
   frozen branch adds the same work as a live one, and nothing bounds how many a base
   collects: merged branches are frozen, and they stay until purged. Either the limit could
   count branches that are not purged, or a second bound could apply to them, or §8.3 could
   say what a purge owes a frozen branch.
2. **Is the per-level product intended?** With the defaults, a base may have 100 branches,
   each with 100 of its own, to depth 8. A purge in the root reaches all of them. If the
   limit is meant to bound a purge's work, it would need to bound the namespaces a purge
   reaches, not the direct branches of each.
3. **Should `/branches` have pages?** Every other listing does. It is 0.67 s at 10,000
   branches on Postgres, and the limit is the only thing keeping it short.

4. **Could a propagated purge be satisfied by the base's cache tag?** Today a purge sends
   two tags for every branch that sees the document, `r:{branch}/{name}` and
   `heads:{branch}`: 212 tags at 100 branches, about 24,000 at 10,000. §9 requires this:
   branches are cached "under their own URLs and tags, which purges propagated to them
   (§8.3) purge too", and §8.3 purges by tag, `heads:{ns}` included, in each branch reached.

   One tag could clear them all if a branch's response for a document it reads through also
   carried the base's tag. That is safe against over-purging: a branch sees its base as of
   `at`, so ordinary writes in the base never change a read-through response, and ordinary
   writes purge no tags. Only purges, restores and E3 prunes in the base would clear the
   branches' copies, which is what should happen.

   The smallest change that would allow it:

   - **§9 "Branches" and §12.8:** a branch's response for a resource it reads through also
     carries `r:{base}/{name}` for each base in its chain, and its `/heads` pages carry
     `heads:{base}`. A purge propagated to such a branch MAY then be satisfied by the base's
     tags.
   - **Still per branch:** branches with their own chain for the name, and remote branches,
     keep their own tags.
   - **SERVICES:** a service whose cache the origin's purges reach either carries the same
     base tags or always purges its branch tags itself. Today it may rely on the origin
     purging `r:{branch}/{name}`.
   - **Switching over:** responses cached before the change lack the base tag, and immutable
     ones live for a year. A deployment keeps sending the per-branch tags until those expire,
     or clears each branch's `ns:` tag once.

   This reduces only the tag count. The `purge` entry in each branch's log (§8.3) stays, so
   a purge still writes once per branch it reaches.

Two smaller points, for the wording of §6.6:

- "Looking up drafts considers every local branch" describes the rule, not a cost an
  implementation has to pay: indexed by revision id, the lookup does not grow with branches.
- "A revocation in the base takes effect in all of its branches" costs the base nothing.
  It belongs with `branchDepth`'s reasons: it is why a write in a branch costs more per
  level.

## Background: what was fixed in the implementation first

The first measurements showed purges taking 0.4 s with one branch and 42 s with 1,000,
including purges in unrelated namespaces. Two faults in the reference caused it, and both
are fixed; the tables above are from the fixed code.

- **Every purge read every document of the deployment.** To refuse a purge that would leave
  a schema reference without a copy (§6.1), the server listed the `$schema` of every
  document every namespace sees, read-through ones included. It now asks first which schema
  revisions anything references, and looks further only when the purge touches one.
- **Finding a namespace's branches read the whole table of namespaces**, once per namespace
  a purge reached. There is now an index.

| Purge in a base, branches read the document through (Postgres) | 100 branches | 1,000 branches |
|---|---|---|
| Before | 4.9 s | 42 s |
| After | 0.16 s | 1.7 s |

The raw results are next to this file; `README.md` there names the runs.

## Afterwards: spec 0.86, and the same measurements again

### What spec 0.86 answered

| Question | Answer in 0.86 | The reference |
|---|---|---|
| 1. Should frozen branches count? | No: `branchesPerNamespace` stays as it was, and frozen branches are free. | Unchanged. A purge now costs a frozen branch that doesn't see the document nothing (below), which is most of what the question was about. |
| 2. Is the per-level product intended? | Not answered. | Carried as an open note (docs/SPEC-FEEDBACK.md). |
| 3. Should `/branches` have pages? | Yes: `?after=`, `{ "branches": [ … ], "next"? }`. An `in_use` refusal's `referencing` and a namespace purge's `dependents` list a page too, with `"more": true`. | Done. |
| 4. Could a propagated purge be satisfied by the base's cache tag? | Allowed, as an option: a branch's read-through responses MAY carry its local bases' tags, and once no cache holds a branch response without them a propagated purge MAY be satisfied by the base's tags (§9). | Not used: the reference still purges each branch's own tags, which conforms. |

### What changed in the implementation

- **A branch's chain of bases is read once per transaction**, in one statement, where each
  level was read, locked and checked on its own. Depth no longer adds statements to a read or
  a write.
- **A purge finds the branches it has work in by name**: those that hold a row for the
  document or may read it through. A branch that neither holds nor sees it is not read,
  locked or written. The branches a purge does reach get their `purge` entries in one
  statement on Postgres.
- **The cause of "Postgres is not quite linear at the top" was found.** A lookup the purge
  made per branch was planned as a scan of a table the purge itself was filling. That lookup
  is gone.

### Purges, Postgres, median ms

| Live branches | 1 | 10 | 100 | 1,000 | 10,000 | 100 × 100 | 100 + 10,000 frozen |
|---|---|---|---|---|---|---|---|
| Branches don't see the document: then | 14 | 22 | 95 | 952 | 9,555 | 9,918 | 9,048 |
| now | 7.3 | 7.8 | 9.0 | 13 | 52 | 56 | 54 |
| Branches read it through: then | 12 | 30 | 158 | 1,685 | 26,753 | 24,980 | 25,407 |
| now | 7.5 | 7.7 | 16 | 104 | 873 | 894 | 939 |
| Each branch has its own revision: then | 14 | 34 | 201 | 2,268 | 29,134 | 25,250 | 25,217 |
| now | 9.7 | 7.8 | 20 | 102 | 1,058 | 1,041 | 1,028 |
| Refused purge of the schema: then | 139 | 196 | 690 | 5,747 | 53,562 | 81,183 | 56,745 |
| now | 176 | 200 | 535 | 4,065 | 39,995 | 49,357 | 40,354 |
| `GET /branches`, every page: now | 0.8 | 1.9 | 9.1 | 72 | 662 | 7.4 | 646 |
| `GET /branches`, one page: now | 0.7 | 1.4 | 8.0 | 70 | 61 | 7.9 | 66 |
| Create one more branch: now | 3.5 | 3.3 | 3.8 | 4.7 | 5.0 | 3.7 | 5.1 |

- A purge now costs about 0.1 ms per branch that sees the document, at 1,000 and at 10,000,
  and about 0.005 ms per branch that doesn't (the search still looks each one up by key).
- The cache tags per purge are what they were: two per branch that sees the document.
- The slowest write to another namespace during a purge was 37 ms.
- **The refused purge of a referenced schema is not fixed.** The cap on `referencing` lets
  the search stop at a page only where the caller may read more than a page of referencing
  namespaces, and the purge is still planned over every branch before it is refused. Here it
  is 40 s at 10,000 branches.
- On SQLite at 10,000 branches: 39 ms where the branches don't see the document, 0.77 s
  where they read it through, 1.0 s where each has its own revision, and other namespaces'
  writes still wait for the purge (0.75 s at most).

### Depth, Postgres, median ms

| Depth | 0 | 1 | 2 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|---|
| Read one that falls through to the root: then | 0.5 | 0.6 | 0.7 | 0.8 | 1.1 | 1.7 | 2.6 |
| now | 0.5 | 0.7 | 0.6 | 0.6 | 0.7 | 0.9 | 0.8 |
| Create a document: then | 2.9 | 3.8 | 5.2 | 5.6 | 9.3 | 14.3 | 25.6 |
| now | 2.7 | 3.2 | 3.3 | 3.3 | 3.3 | 4.1 | 3.3 |
| Create one typed by a draft: then | n/a | 5.7 | 7.5 | 9.1 | 13.9 | 28.7 | 42.0 |
| now | n/a | 4.7 | 4.4 | 4.4 | 4.4 | 4.7 | 5.0 |
| Append to a document read through: then | n/a | 4.9 | 5.3 | 7.0 | 10.0 | 16.0 | 27.9 |
| now | n/a | 4.3 | 4.2 | 4.5 | 4.2 | 4.2 | 4.6 |
| Purge in the root: then | 5.7 | 15 | 16 | 24 | 40 | 56 | 134 |
| now | 5.9 | 6.7 | 7.8 | 9.8 | 9.1 | 12 | 14 |
| Reads per second, 16 callers: then | 7,282 | 5,679 | 5,113 | 4,742 | 3,677 | 1,977 | 1,324 |
| now | 8,556 | 5,999 | 5,781 | 5,499 | 4,873 | 4,706 | 3,578 |
| Creates per second, 16 callers: then | 1,197 | 990 | 772 | 633 | 420 | 258 | 159 |
| now | 1,331 | 1,092 | 922 | 996 | 937 | 827 | 993 |

- One caller's read or write now costs about the same at any depth. The summary's "each
  level adds about 0.07 ms to a read and 0.7 ms to a write" no longer holds here.
- Depth still costs under load: 16 callers read 3,578 documents a second at depth 32 against
  8,556 in a plain namespace, and a branch still costs more than a plain namespace (depth 0
  to 1). The first use of a base in a transaction locks the whole local chain.
- Creating a branch at depth 32 takes 8 ms against 4 ms at depth 1.

### What this says about §6.6's reasons

For this implementation, `branchDepth` no longer bounds a per-request cost that grows by
level, and `branchesPerNamespace` bounds a purge at about 0.1 ms per branch that sees the
purged document instead of 1.5 to 2.3 ms. Neither changes what the spec should say: another
implementation may pay per level, and the limits are the only bound the text gives. The
`-v086` result files are next to this one.

