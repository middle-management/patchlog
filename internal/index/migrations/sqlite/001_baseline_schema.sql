-- Migration: baseline schema
-- Created: 2026-10-27T08:00:27Z
-- Checksum: 91bad3454eb1d140cf9fa67966508e87c6e4c56a8a59c3e42a185c6cd976b9c0
-- Chain: 6ac0068c954f97144a4bb21785432b00940f3b4622efd01c440d96cd6dd70f94
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The index's tables (index.go describes them), but for text, which is
-- FTS5 or a plain table depending on the SQLite build (initSchema). The
-- sealed-view cache and the repurge queue have migrations of their own
-- (packages derived and repurge).
--
-- query.go names facet_q, sort_q, refs_t and the primary keys' indexes
-- (sqlite_autoindex_facet_1, _sort_1, _refs_1) in INDEXED BY, which fails
-- the query if one is missing: a table keeps its primary key as its only
-- constraint.
-- IF NOT EXISTS throughout: a database created before migrations were
-- tracked (v0.22.0) already has all of it, and is adopted as is.

-- follow.SQLCheckpoints, under its default table name.
CREATE TABLE IF NOT EXISTS checkpoints (origin TEXT NOT NULL, ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (origin, ns));
CREATE TABLE IF NOT EXISTS checkpoints_bootstrap (origin TEXT NOT NULL, ns TEXT NOT NULL, at_id TEXT NOT NULL, after_name TEXT NOT NULL, PRIMARY KEY (origin, ns));
CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ns_state (ns TEXT PRIMARY KEY, purged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS docs (docid INTEGER PRIMARY KEY, ns TEXT NOT NULL, resource TEXT NOT NULL, head TEXT NOT NULL, schema TEXT, UNIQUE (ns, resource));
CREATE TABLE IF NOT EXISTS facet (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value TEXT NOT NULL, raw TEXT NOT NULL, PRIMARY KEY (ns, resource, path, value));
CREATE TABLE IF NOT EXISTS "sort" (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, value, raw TEXT, PRIMARY KEY (ns, resource, path));
CREATE TABLE IF NOT EXISTS refs (ns TEXT NOT NULL, resource TEXT NOT NULL, schema TEXT, path TEXT NOT NULL, ref TEXT NOT NULL, target_ns TEXT NOT NULL, target TEXT NOT NULL, rev TEXT, entry TEXT, PRIMARY KEY (ns, resource, path));
CREATE INDEX IF NOT EXISTS docs_q ON docs (ns, schema);
-- refs_t leads with ns: a ?ref= filter reads only the namespace's
-- references to the target.
CREATE INDEX IF NOT EXISTS refs_t ON refs (ns, target_ns, target, rev, entry);
CREATE INDEX IF NOT EXISTS facet_q ON facet (ns, path, value);
CREATE INDEX IF NOT EXISTS sort_q ON "sort" (ns, path, value);
