-- Migration: baseline schema
-- Created: 2026-10-27T08:00:27Z
-- Checksum: 32ebe0d70fda46b8ae3bf8ba640d88e7fb3f6b3e3a53679de984b4059da9e20b
-- Chain: 0db411726dddd877adbcf2bc9f4ee89d3db34c9e7a19b86bfd432d6ef542aa2a
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The tree service's tables (store.go describes them). The sealed-view
-- cache, the repurge queue and the catalog's tables have migrations of their
-- own (packages derived, repurge and catalog).
-- IF NOT EXISTS throughout: a database created before migrations were
-- tracked (v0.22.0) already has all of it, and is adopted as is.

-- follow.SQLCheckpoints, under its default table name.
CREATE TABLE IF NOT EXISTS checkpoints (origin TEXT NOT NULL, ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (origin, ns));
CREATE TABLE IF NOT EXISTS checkpoints_bootstrap (origin TEXT NOT NULL, ns TEXT NOT NULL, at_id TEXT NOT NULL, after_name TEXT NOT NULL, PRIMARY KEY (origin, ns));
CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS seen_by_id ON seen (ns_id);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (href TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind INTEGER NOT NULL,
	item TEXT, item_head TEXT, title TEXT, state INTEGER NOT NULL DEFAULT 0,
	self INTEGER NOT NULL DEFAULT 0, head TEXT, parents TEXT, access TEXT,
	dangling TEXT, cyclic INTEGER NOT NULL DEFAULT 0, deep INTEGER NOT NULL DEFAULT 0, depth INTEGER NOT NULL DEFAULT -1,
	item_state INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS edges (child TEXT NOT NULL, pos INTEGER NOT NULL, parent TEXT NOT NULL, ord TEXT,
	state INTEGER NOT NULL, PRIMARY KEY (child, pos));
CREATE INDEX IF NOT EXISTS edges_by_parent ON edges (parent, ord, child);
CREATE TABLE IF NOT EXISTS items (ns TEXT NOT NULL, name TEXT NOT NULL, state INTEGER NOT NULL, head TEXT, title TEXT,
	created TEXT, file TEXT, PRIMARY KEY (ns, name)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS self_parents (ns TEXT NOT NULL, name TEXT NOT NULL, parents TEXT NOT NULL,
	PRIMARY KEY (ns, name)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS edge_subjects (gs TEXT PRIMARY KEY, subjects TEXT NOT NULL, exp INTEGER NOT NULL);
