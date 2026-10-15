# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The Go reference implementation of the **Patch Log** specification: each resource is an
append-only log of content-addressed JSON Patch sets, served as immutable, CDN-cacheable
revisions. `docs/SPEC.md` mirrors the canonical spec (version in `core.SpecVersion`,
`internal/core/engine.go`). Where this implementation goes beyond what the spec text says, the
gap is recorded for the spec writer in `docs/SPEC-FEEDBACK.md`. Code comments, commits and docs
cite spec sections (`§6.2`, `§C.5`, `Addendum E.3`, `D.3`). "D.x" means Addendum D of spec ≤ v0.49
(storage layout, write path, Postgres), which this implementation still follows.

`README.md` is long (~2800 lines) and is the authoritative user documentation: the
implemented and not-implemented tables, each feature's behaviour, and the "Design notes"
section. Read the section you need with `grep -n '^##' README.md`.

## Commands

```sh
make build            # go build -tags grpcnotrace -o patchlog ./cmd/patchlog
make test             # go test ./...
make check            # vet + test + fail on unformatted files (what CI checks, minus race/pg)
make fmt              # gofmt -w internal cmd
make dev              # core server natively on :8080 in dev mode (dev.db, dev.key)
make up / up-pg / up-host / down   # whole Docker stack (core, seed, index, tree, janitor, Varnish CDN)
make fixture          # regenerate internal/playground/static/selftest.json (node on PATH for the JS->Go part)

go test ./internal/core -run TestName          # one test
go test -race ./internal/core ./internal/server ./internal/merge ./internal/index ./internal/tree   # CI race job
PATCHLOG_TEST_PG=postgres://user:pw@host:5432/postgres?sslmode=disable go test ./internal/...      # on Postgres (make test-pg)
PATCHLOG_TEST_LOG_PAGE_SIZE=2 go test ./...    # page every log range after two entries, to exercise multi-page paths
```

CI (`.github/workflows/ci.yml`) runs gofmt, vet and tests; the race detector on the packages
above; the whole `./internal/...` suite on Postgres 16, with and without `-race`; and a Docker build.
A change must pass on both SQLite and Postgres.

`-dev` turns authentication off (`X-Author` names the author, every request counts as holding a `*`
key). Otherwise the server needs `-operator-key` (from `patchlog keygen`) and Biscuit grants.

## Architecture

One binary, `cmd/patchlog`, with subcommands: `serve` (the core), `index` (search, Addendum A),
`tree` (tree/catalog service, Addendum B), `merge`/`rebase`/`janitor` (Addendum F), `export`/`import`
(bundles, §G.4), `archive`, `schema import`, `keygen`, `grant mint|narrow|seal`, `health`.

- **`internal/core`** is storage and semantics: the write gate (§6.2), batches, branches, purge,
  prune, encryption, sealed and e2e namespaces. **`internal/server`** is the HTTP API on top of it.
  The other services (`index`, `tree`, `catalog`, `merge`, `janitor`, `bundle`) are API
  consumers. They talk to the core through `internal/client` and follow logs with
  `internal/follow`, and do not import `core` directly.
- **Two storage dialects, one set of queries** (`internal/core/dialect.go`). SQLite
  (`modernc.org/sqlite`, pure Go) is the default; Postgres is chosen when `-db`/`PATCHLOG_DB` is a
  URL. Queries use `?` placeholders in the subset both accept, and the tx wrapper in `stmts.go`
  rewrites them for Postgres. Schemas are in `db.go` (`schemaSQL`) and `pgschema.go` (`schemaPG`),
  so a schema change goes in both, with a migration. Bools, JSON/binary columns (`blobArg`),
  arrays (`inArray`) and conflict detection differ per dialect.
- **Write path (D.3, `write.go` `writeOptimistic`).** Resource writes and batches run gate steps
  1–6 in a read transaction without the write lock. They then take the lock (an in-process mutex
  plus `BEGIN IMMEDIATE` on SQLite, per-namespace advisory locks on Postgres in `pglock.go`),
  re-check everything the decision read (`recheck.go`), and insert. Rarer writes (config,
  branches, purges, prunes) run the whole gate inside the write transaction. On Postgres several
  instances can share one database: commits are grouped under contention (`groupcommit.go`), and
  `tailer.go` tells each instance about other instances' commits for live readers and caches.
- Foundational packages: `jsonv` (I-JSON, JCS canonical form), `ids` (content-addressed base32
  ids), `patch` (JSON Patch + `writes`), `rules` (§6.4.2 rule language), `schema` (`$schema`
  validation), `grant` (Biscuit grants, Addendum C), `seal` (JWE/HPKE, Addendum E), `keystore`
  (master key, E.1).
- `internal/playground` is the web UI at `/playground/`. It is embedded static JS/CSS
  (`go:embed static`) with no build step. `selftest.json` holds crypto vectors shared between Go and
  `seal.js`.
- The README's `## Layout` section has a one-line description of every package.

## Tests

- Tests of API consumers use `internal/client/clienttest`, which runs an in-process core and server
  over httptest and has helpers for keys and grants. `clienttest.Paged` and the per-package
  `TestPagedFlows` run flows with small log pages.
- `internal/pgtest` hands each test that opens a store its own Postgres database (pooled, emptied
  between tests) when `PATCHLOG_TEST_PG` is set, and an in-memory SQLite database otherwise. Use
  `pgtest.FreshDB` for a test that changes the schema.
- `internal/testenv` holds test-suite settings such as `PATCHLOG_TEST_LOG_PAGE_SIZE`.

## Conventions

- Commit subjects start with the area or package (`core: …`, `tree: …`, `Docs: …`,
  `CHANGELOG: …`, `Spec v0.52: …`). User-visible changes get a `CHANGELOG.md` entry under the
  upcoming version, grouped into "Changes to check before upgrading", features and "Fixes".
  Behaviour changes also update the matching README section. Deviations from or questions
  about the spec go in `docs/SPEC-FEEDBACK.md`.
- Errors are HTTP status codes plus spec error codes (e.g. `422 nonce`, `409 in_use`,
  `410 purged`). Keep the gate's order of checks (§6.2) when adding checks; tests verify it
  (`internal/server/gateorder_test.go`).
