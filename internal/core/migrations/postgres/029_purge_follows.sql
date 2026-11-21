-- Migration: purge follows
-- Created: 2026-11-20T16:55:47Z
-- Checksum: 119d2bee7b6be13e421ee72109888d8f489878bc123cd42f6a5021aefa920f81
-- Chain: 2b23b9671e3c7c2e45f0c3cbc09c7d06826f1dbd513053d5683db3e7c17fda68
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- current.sql: Development-only migration file
-- 
-- This file is automatically applied in development environments.
-- When ready for production, commit this as a numbered migration file (NNN_name.sql)
-- and clear this file.
--
-- Example usage:
-- ALTER TABLE users ADD COLUMN new_feature_flag BOOLEAN DEFAULT false;-- current.sql: Development-only migration file
-- 
-- This file is automatically applied in development environments.
-- When ready for production, commit this as a numbered migration file (NNN_name.sql)
-- and clear this file.
--
-- Example usage:
-- ALTER TABLE users ADD COLUMN new_feature_flag BOOLEAN DEFAULT false;-- Purges followed from the origins of imports (§G.1 Purges follow imports,
-- purgefollow.go): one follow per namespace imported into, origin and
-- source namespace there, started by the first import batch whose source
-- names a bundle and that origin. upto is the origin's ns_id up to which
-- every purge is applied.
CREATE TABLE IF NOT EXISTS purge_follows (
  ns      bigint NOT NULL REFERENCES namespaces,
  origin  TEXT    NOT NULL,
  src_ns  TEXT    NOT NULL,
  upto    TEXT    NOT NULL,
  PRIMARY KEY (ns, origin, src_ns)
);
-- The names a follow's import batches wrote, each with the source.at that
-- brought it first; pending until the origin's log has been read from
-- there (a name imported after the follow started).
CREATE TABLE IF NOT EXISTS purge_follow_names (
  ns      bigint NOT NULL REFERENCES namespaces,
  origin  TEXT    NOT NULL,
  src_ns  TEXT    NOT NULL,
  name    TEXT    NOT NULL,
  from_at TEXT    NOT NULL,
  pending INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ns, origin, src_ns, name)
);
-- Followed purges §6.1 refuses as in_use, waiting for an operator: the
-- origin's entry, the refusal's body (JSON) and since when (unix ms).
CREATE TABLE IF NOT EXISTS purge_follow_waiting (
  ns      bigint NOT NULL REFERENCES namespaces,
  origin  TEXT    NOT NULL,
  src_ns  TEXT    NOT NULL,
  name    TEXT    NOT NULL,
  entry   TEXT    NOT NULL,
  refusal TEXT    NOT NULL,
  since   bigint NOT NULL,
  PRIMARY KEY (ns, origin, src_ns, name)
);
