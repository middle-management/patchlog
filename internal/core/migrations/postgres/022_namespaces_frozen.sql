-- Migration: namespaces frozen
-- Created: 2026-11-19T12:36:03Z
-- Checksum: a86262e25929f5b363f6510d7c8acb13e85bb649875005981a0041dca8d0b95c
-- Chain: a9ea2a283f8a712550330c6c89f0734e56d5fad03f49e6bb45b148e8cd7d299d
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
-- ALTER TABLE users ADD COLUMN new_feature_flag BOOLEAN DEFAULT false;
-- namespaces.frozen mirrors the namespace document's frozen member: a
-- config write sets it, but a local branch created frozen kept 0 until its
-- next config write. Counting a base's live branches reads the column
-- (nsconfig.go, liveBranches), so the rows created that way are set here.
UPDATE namespaces SET frozen = 1 WHERE frozen = 0 AND config_seq IN
  (SELECT c.seq FROM ns_config c WHERE c.ns = namespaces.ns AND (c.doc::jsonb -> 'frozen') = 'true'::jsonb);
