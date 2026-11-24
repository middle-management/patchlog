-- Migration: purge follows by importer
-- Created: 2026-11-24T20:24:29Z
-- Checksum: 3581497b2f4159958a06c5f173e8ee3ec7c694dc1ac2767c9285bf143a9b1a14
-- Chain: 08f33eaed9a14cefa75f07b41c8db9cedcef8573441bd4acf0b1afd44c647a1c
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
  ns       bigint  NOT NULL REFERENCES namespaces,
  origin   TEXT    NOT NULL,
  src_ns   TEXT    NOT NULL,
  name     TEXT    NOT NULL,
  importer TEXT    NOT NULL,
  from_at  TEXT    NOT NULL,
  pending  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ns, origin, src_ns, name, importer)
);
