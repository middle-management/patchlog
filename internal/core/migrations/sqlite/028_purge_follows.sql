-- Migration: purge follows
-- Created: 2026-11-20T16:55:47Z
-- Checksum: 1525de6ba27bf3b9c56cf756ba1c63dfacbfbed5bcbec7f3716f3b7c62d8cde9
-- Chain: a178aa2e5ed065286273ae621db7615efa7107f3b95cd23a278c6102101426ea
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
  ns      INTEGER NOT NULL REFERENCES namespaces,
  origin  TEXT    NOT NULL,
  src_ns  TEXT    NOT NULL,
  upto    TEXT    NOT NULL,
  PRIMARY KEY (ns, origin, src_ns)
);
-- The names a follow's import batches wrote, each with the source.at that
-- brought it first; pending until the origin's log has been read from
-- there (a name imported after the follow started).
CREATE TABLE IF NOT EXISTS purge_follow_names (
  ns      INTEGER NOT NULL REFERENCES namespaces,
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
  ns      INTEGER NOT NULL REFERENCES namespaces,
  origin  TEXT    NOT NULL,
  src_ns  TEXT    NOT NULL,
  name    TEXT    NOT NULL,
  entry   TEXT    NOT NULL,
  refusal TEXT    NOT NULL,
  since   INTEGER NOT NULL,
  PRIMARY KEY (ns, origin, src_ns, name)
);
