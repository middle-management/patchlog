# Item 5 review: the deep cursor against the code (origin/main a3888a1)

Bottom line: as written, the design breaks several of its claims and introduces silent wrong
answers. A narrower form is sound: move only payloads (`revisions.patches`, old `snapshots.doc`)
and keep all row metadata hot.

## Claims that hold
- A new id can't equal a deep one in the same resource: linearity is `UNIQUE (res, parent_seq)` +
  `one_first`; a new row's parent is the head; ids are server-computed (blob ids re-hashed and
  checked). Hot-only unique indexes are sound if head, tombstone, first row and branch `at` heads stay hot.
- Successful writes need no deep lookup — but only after a code change: `replay` runs before every
  precondition check and probes the expected id (write.go:850-856, resolve.go:131-145). The deep
  lookup can be limited to the 412/410 path.
- `read_judged` (keyed by judge, name, id), the xid tailer, `{batch,item}` preconditions (client-side),
  merges/rebases/restore (If-Match = head or tombstone), branch first writes (base head as of `at`).

## Claims that break
A. Silent wrong answers (a missing hot row read as a fact):
1. `resolve` as-of: `ErrNoRows` from head_history falls through to base/NotFound (resolve.go:536);
   `t.rev(seq)` on a deep row panics (resolve.go:462); prefetchHeads alike (resolve.go:354-378).
2. `ancestry()` reads each resource's `first = 1` row (resolve.go:604-610) — not in the pin list;
   branch chains silently stop (findInAncestry, foreign-parent ranges, blobs.go:160, schemaload.go:743).
3. Purge propagation's `MIN(h.ns_seq)` over hot head_history (nspurge.go:319, 542, 799) and
   `base_at >= lo` (nspurge.go:556): branches get skipped unless "latest ≤ at" rows stay pinned.
4. Blob visibility joins blob_refs to revisions (filtered_visible.go:309, 352; sealedblobs.go:57-87):
   empty join → head decides; wrong blobs shown/hidden, wrong epoch sets.
5. All 19 docAt/docBytesAt callers read an error as pruned/purged: an outage becomes 422
   schema_unavailable, a null-doc filter judgment, a skipped schema copy (in_use undercounted → a purge
   could destroy a last copy, drafts.go:369…835), 422 on keep, dropped successor, wrong epoch.
6. Non-id lookups an id Bloom filter can't serve: gestures (gestures.go), grants (grants.go:127, 146;
   archive.go:323 — grantJob seals under the first recording entry's epoch), schema_ref scans
   (drafts.go, schemareads.go), cross-namespace copies by id, first ns_log entry / start time,
   revEpochFixed (sealed.go:328-345) — losing it re-seals under the current epoch.
7. `logBetween` panics on a gap ("the chain forks", resolve.go:994-1000).

B. Spec: §7.2 says the retry lookup covers the whole log; retryWindow is used only by prune
(nsprune.go:330); replay reads deep rows (write.go:1414-1499); releases resume on it. §7.1 paging
forbids ending pages at segment boundaries without a spec change.

C. Segments aren't immutable: prune rewrites (`patches = NULL`, nsprune.go:466, e2e.go:682; kept
snapshots; rev_epochs; archive reads), archive restore writes back (archive.go:610-677), raising to
at-rest re-encrypts every row in the config write (crypt.go:405-470), purge destroys per-resource DEKs
(nspurge.go:942) which whole-segment encryption can't, schema migrations touch every row.

D. Writes that need S3: `$schema`/`$ref` naming any old schema revision (schemaload.go:733-779);
writing a schema looks up copies of its id deployment-wide (schemaload.go:199-222); a batch's local
`source.at` (source.go:45; releases fix it at approval); branch creation at an old `at`
(nsbranch.go:341-346, plus re-hydrating heads); raising to at-rest.

E. Cost: 2.5 B/write ≈ 20 bits/key ≈ 6.7e-5 FP per filter → ~0.7 GETs per lookup at 10k segments;
purge would do S3 rewrites under write locks; FKs onto revisions/ns_log (head_history, snapshots,
e2e_snapshots, blobs.ref_seq) block deletion; sealed first reads write sealed/seal_counts rows;
whole-history clients (export, verify, merge, index/follow catch-up, purge-follow, janitor) see 503s.

## Extra rows that must stay hot
First row of each resource and every foreign-parent row; per unpurged branch and base resource the
head_history "latest ≤ at" row, its ns_log row, the branch's `at` entry and the fold chain; the first
ns_log entry of each namespace; every revision of any schema resource plus `$ref` closures; a branch's
own revisions until purged; rows referenced by FKs; hot indexes for (res, schema_ref), (ns, grant)
first seq, gesture → (res, id), blob_refs with seq/epoch; tables rev_epochs, sealed, seal_counts,
read_judged, heads, keep.

## Spec questions
1. Which tables move; may the namespace log move (§8.6 "never pruned")?
2. §5 "nothing observable changes" vs a 503 `unavailable`: which requests may answer it?
3. §7.2: may the whole-log retry lookup be bounded or 503 beyond the retry window?
4. §7.1: may pages end early (CDN-cached and sealed ranges keyed `since:id`)?
5. §8.3: may purge answer after destroying keys with a lazy rewrite, as archives allow?
6. May branch creation at an old `at` and `/heads?at=` answer 503?
7. How is this different from §8.6 prune + archive, which already moves history to object storage?

## Recommendation
Move only payloads; keep per-resource data keys inside segments (purge = crypto-shred + lazy
compaction); reorder replay so the deep lookup happens only on the 412 path; add a typed
errUnavailable and audit the 19 docAt sites; prefer extending prune and archive.
