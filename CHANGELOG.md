# Changelog

## Unreleased

- **CORS** for `serve`, `index` and `tree`, for demos and apps on other origins:
  - `-cors-origin` (repeatable or comma-separated, or `*`) or `PATCHLOG_CORS_ORIGINS`.
  - Preflights are answered by the server; the headers the API reads (`Authorization`, `If-Match`, `Blob-From`, …) are allowed and the ones it sets (`ETag`, `Location`, `X-Namespace-Revision`, …) exposed.
  - With a list of origins, responses say `Vary: Origin`, so the CDN keeps one copy per origin; `*` keeps one for all.
  - `-cors-credentials` for pages that send cookies (grants travel in `Authorization` and don't need it); `-cors-max-age`.
  - The compose files pass `PATCHLOG_CORS_ORIGINS` through.

## v0.3.1

Faster writes on both databases. On Postgres, writes to different resources of one namespace now run in parallel.

### Postgres: writes in one namespace run in parallel

- Resource writes and batches hold their namespace's lock shared. Config writes, purges, prunes, branch operations and blob uploads still take it exclusively.
- Only the namespace-log append is serialized: two statements and the commit, under the namespace row's lock.
- Two writers racing on one resource still give one success and a 412 with the new head. A write that keeps losing retries with the namespace locked exclusively, so every write finishes.
- Every write is now checked inside its own transaction (`LockedCheckBytes` 0).
- Batches insert their rows in multi-row statements.
- Missing resources are cached within a transaction.
- The counts that decide intermediate snapshots live on the resource row.
- New columns, migrated on startup: `namespaces.head_id`, `resources.snap_revs`, `resources.snap_bytes`.

### CPU, both databases

- Blob-reference walks skip documents without `$blob`.
- Canonical key sorting compares ASCII names bytewise.
- Each document's and patch set's canonical form is computed once.

### Measured (4 vCPUs shared with the database, fsync on)

Writes/s, p99 in brackets, for 20–70 KiB creates into one namespace:

| | 1 writer | 8 | 32 | 64 | 1,000-create batch |
|---|---|---|---|---|---|
| Postgres, v0.3.0 | 35 (51 ms) | 51 (228 ms) | 52 (1,376 ms) | 54 (3,225 ms) | 2,623 ms |
| Postgres, now | 161 (11 ms) | 438–500 (40–60 ms) | 350 (282 ms) | 343 (799 ms) | 330 ms |
| SQLite, v0.3.0 | 43 (45 ms) | 81 (154 ms) | 98 (419 ms) | 108 (887 ms) | 1,079 ms |
| SQLite, now | 381 (18 ms) | 669 (32 ms) | 664 (83 ms) | 721 (118 ms) | 252 ms |

## v0.3.0

Implements spec **v0.32** (`docs/SPEC.md`). Blobs are now complete across every namespace level and tool, blob bytes live on disk, and writes on Postgres are faster.

### Blobs everywhere

- **Sealed namespaces (E2):** `GET …/blob/{bid}` redirects (`302`) to `…/blob/{bid}/e/{e}`, which serves the blob in the binary sealed form (`application/vnd.patchlog.sealed-blob`, zero-padded). Each epoch's sealing is stored once; the first instance to store it wins. A blob is served under exactly the epochs of the revisions that reference it. A request for a blob whose revisions have no epoch yet fixes one under the current epoch.
- **End-to-end namespaces (E3):** clients encrypt each blob under its own key, which travels in the sealed reference. Each `sealed` op declares in plaintext the blobs its document references. The server checks those lists (`blobsPerDocument`, availability, sealed type, no duplicates) and uses them for attaching, pruning, purge and bundles. Readers flag revisions whose list differs from the document.
- **Merges** keep E3 blob ids and carry the declared lists over.
- **Bundles** export blob lines and import them: blobs are uploaded, or copied with `Blob-From` within one deployment, before the batches that need them. Sealed bundles seal blob lines like any other line.
- **Archives:** restore brings back the blobs that pruning ended.
- **Remote branches** mirror their base's blobs up front, from plaintext, sealed and E3 bases, and check each one against its id.
- **Playground:** blob references show as chips with previews (images, text), open and download. An "Attach file" control uploads files into public, sealed (with `Blob-Nonce`) and E3 namespaces (encrypted in the browser).
- **Go client:** `GetBlobRef`, `EncryptBlob`/`DecryptBlob`, `E2E.UploadBlob`/`GetBlob`.

### Blob storage on disk

- Blob bytes are stored as files: `serve -blob-dir DIR` or `PATCHLOG_BLOB_DIR`. A SQLite file database defaults to `<db>.blobs/`.
- Each file is written and fsynced before its row commits, and deleted only after the commit that frees it. Every stored copy has its own name, so a cleanup can't delete a concurrent re-upload. A sweep on the leader removes orphan files.
- Range requests read only their range. Bytes encrypted at rest are still per-resource and decrypted whole.
- **Postgres:** several instances must share the directory. Without `-blob-dir`, Postgres keeps bytes in the database and logs a line at startup.
- Rows that the earlier table stored keep working; no migration is needed. Back up the database and the blob directory together.

### Postgres

- **Faster writes:** a small write sends 16 statements instead of about 32. That's 2.9 ms instead of 4.4 ms on a local `postgres:16` with fsync on, and 0.9 ms instead of 1.34 ms when writing in parallel.
  - Small writes are checked inside their namespace's lock, skipping the separate check transaction.
  - Author and namespace ids are cached.
  - Rows are reused within a transaction.
  - A few queries were merged.
- **A second CDN purge:** a durable queue (`cdn_repurge`) sends every CDN tag purge again once no stale instance or replica can still serve the old content.
- **Leader checks:** background jobs confirm they still hold leadership before each step.
- A retried transaction no longer draws rate-limit tokens twice.

### Spec v0.32 behaviour changes

- **Blob upload order (`PUT`):** a purged namespace answers `410` after authorisation and rate limits. A copy with a body or an unreadable `Blob-From` is `400` before anything is read.
- **Pending uploads:** a write that references a blob ends every pending upload of it in that resource, including blobs already attached.
- **Batch `source`:** a bad `source.at` is `422` with the new code `source`. It is checked only for callers who may read the source; for anyone else, the source makes no blobs available.
- **Dry runs** report missing blobs and carry on with the later steps.
- **E3 prune** no longer takes a `blobs` list: the server already keeps every revision's declared list. Clients sort declared lists by binary id.
- **Bundles:** a blob line comes before the first line that mentions the blob (`test` values included). A local import doesn't copy blobs that the batch's `source` already covers. E3 blob lines must have the sealed type and no nonce.
- **Clients** decrypt a sealed blob only when it was served through `…/e/{e}`.
- The merge tool reports batches whose `source.at` isn't in the branch's chain.

### Fixes

- `TestLongPollWakes` no longer fails when a long-poll's cursor boundary falls inside the test's pause.

### Known gaps

- Importing a private or sealed source into an E3 target (re-encrypting blobs) isn't implemented.
- No resumable uploads.
- Restoring an archive of a namespace encrypted at rest deadlocks on an in-memory SQLite database. File databases and Postgres are unaffected.
