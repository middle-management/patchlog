-- Migration: edge records per view
-- Created: 2026-11-20T16:40:35Z
-- Checksum: 733eb611427bbb5ee217a448d67970d16ab0b6a0f926a7ed7ccc1dae7df96f25
-- Chain: 335c6f8b329fdac89a39b6cdb854f7d6d18b5135a73e1083d8076c0e262a0b02
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
-- v0.87: what a reader's cookies are judged by is kept per view (§A.4).
ALTER TABLE edge_gs RENAME TO edge_views;
ALTER TABLE edge_gs_keys RENAME TO edge_view_keys;
