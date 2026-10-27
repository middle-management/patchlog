-- Migration: baseline schema
-- Created: 2026-10-27T08:00:27Z
-- Checksum: 06810b7d20942c09e8a7608d167e081d4cd373df25f2a594f5c7470cdf7a8773
-- Chain: a30c26f1cb9d5d4cf1d9dfd789bc12710b18e7581b7535d7c83ac22e4e4bb630
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Sealed views of a sealed/e2e catalog or index (Cache), in a service's
-- database.
-- IF NOT EXISTS throughout: a database created before migrations were
-- tracked (v0.22.0) already has all of it, and is adopted as is.

CREATE TABLE IF NOT EXISTS sealed_views (view TEXT PRIMARY KEY, scope TEXT NOT NULL, at TEXT NOT NULL,
	body BLOB NOT NULL, json INTEGER NOT NULL, tags TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sealed_views_scope ON sealed_views (scope, at);
CREATE TABLE IF NOT EXISTS sealed_view_tags (tag TEXT NOT NULL, view TEXT NOT NULL, PRIMARY KEY (tag, view)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS sealed_view_tags_view ON sealed_view_tags (view);
