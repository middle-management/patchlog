-- Migration: drop remote branch tables
-- Created: 2026-11-20T15:23:20Z
-- Checksum: 17a31576c4885c135359a2c47fe47e76220e9be6dc94dd765e0c0d6bc2441309
-- Chain: 59d5b6c139ea860d890e5f6f516018b06ca3533db439dff40664d7e4a8683a36
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
-- v0.87 removed remote branches (the former §G.3 and §G.5.2): their
-- registrations, bases, follow state and notices go.
DROP TABLE IF EXISTS remote_branches;
DROP TABLE IF EXISTS remote_bases;
DROP TABLE IF EXISTS remote_catchup;
DROP TABLE IF EXISTS remote_chain_read;
DROP TABLE IF EXISTS remote_levels;
DROP TABLE IF EXISTS remote_notices;
