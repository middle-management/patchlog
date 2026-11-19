-- Migration: namespaces frozen
-- Created: 2026-11-19T12:36:03Z
-- Checksum: 0faf61af567cafadffe3324dc201c6065d6edb1de4a8b7638667b58313c2361d
-- Chain: 35f9ee85caa56e079abff5b2d43c6bca176c74d566ac63bbb73132ad4879d0a3
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
  (SELECT c.seq FROM ns_config c WHERE c.ns = namespaces.ns AND json_type(c.doc, '$.frozen') = 'true');
