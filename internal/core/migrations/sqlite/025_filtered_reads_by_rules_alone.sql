-- Migration: filtered reads by rules alone
-- Created: 2026-11-20T14:31:47Z
-- Checksum: 197f94fa894691f812374c7506632ae6eb96f4d11d6a1abdae72dbf3fff7416d
-- Chain: caa1c92b0899cc87e7c1ba00124b017b5ffa9375d3c98cedab1ce0c60f5ee2cc
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
-- Filtered reads judge visibility by the grant's read rules alone (v0.87:
-- no catalogs): a checkpoint is an ns_id of {ns}, so combined checkpoints
-- aren't recorded, and no subject set holds "partial".
DROP INDEX IF EXISTS filtered_ats_created;
DROP TABLE IF EXISTS filtered_ats;
ALTER TABLE filtered_gs DROP COLUMN partial;
