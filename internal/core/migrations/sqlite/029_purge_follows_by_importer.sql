-- Migration: purge follows by importer
-- Created: 2026-11-21T07:02:52Z
-- Checksum: 8c075bb14c88f7752120cc82d7909efa2e6d7c078d1405ae1d41ea9f9d836a0f
-- Chain: ce43db82115f746203156730b75d9b80106aa0be4e2fa779a8dc2a7c18d6ca17
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
-- ALTER TABLE users ADD COLUMN new_feature_flag BOOLEAN DEFAULT false;-- Purges follow only import batches by a principal the operator names as
-- the origin's importer, under a grant that may purge the names the batch
-- writes (§G.1, v0.88): each name is kept with the principal that
-- imported it, and only names an importer of the origin wrote are
-- followed. The names kept before carry no principal: they follow nothing.
DROP TABLE IF EXISTS purge_follow_names;
CREATE TABLE IF NOT EXISTS purge_follow_names (
  ns       INTEGER NOT NULL REFERENCES namespaces,
  origin   TEXT    NOT NULL,
  src_ns   TEXT    NOT NULL,
  name     TEXT    NOT NULL,
  importer TEXT    NOT NULL,
  from_at  TEXT    NOT NULL,
  pending  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ns, origin, src_ns, name, importer)
);
