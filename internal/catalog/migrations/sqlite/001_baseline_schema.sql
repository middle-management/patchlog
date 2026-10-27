-- Migration: baseline schema
-- Created: 2026-10-27T08:00:27Z
-- Checksum: d0b62a664a21823e8167b92f8c893b80052e6e4ce740bb610125c44a0d170428
-- Chain: fb02a9f8a2cc40c72018fad321adc41471cb6c008623edfe9eb450e7bbe28e44
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The tables of §B.11.7, in the tree service's database (Service.Init).
-- The spec's nodes(node, inherit) is access_nodes here (the tree service has
-- its own nodes table), and effective is kept for every node (folders too,
-- for listing visibility), keyed by the node's href. Rows with tombstoned =
-- 1 are a deleted item's, frozen as they were when its tombstone was seen.
-- IF NOT EXISTS throughout: a database created before migrations were
-- tracked (v0.22.0) already has all of it, and is adopted as is.

CREATE TABLE IF NOT EXISTS access_nodes (node TEXT PRIMARY KEY, inherit INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS acl (node TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY (node, subject, role)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS effective (node TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL,
	tombstoned INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (node, subject, role)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS effective_by_subject ON effective (subject, node);
