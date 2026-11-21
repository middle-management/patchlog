-- Migration: filtered reads by rules alone
-- Created: 2026-11-20T14:31:47Z
-- Checksum: 3d803506b1e87e02a09cff49813230b584c5dcde75ed723df98a03a55d1b7595
-- Chain: 357bb6fbc66981f669d74c8e40d4f6ef05d3f3f50b107503947c9e585f53cf16
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
-- no catalogs), so the index follows no namespace for visibility and
-- keeps no catalog.trust.
DROP TABLE IF EXISTS member_checkpoints;
DROP TABLE IF EXISTS member_conf;
DROP TABLE IF EXISTS catalog_trust;
