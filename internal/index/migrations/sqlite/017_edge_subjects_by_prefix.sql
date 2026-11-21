-- Migration: edge subjects by prefix
-- Created: 2026-11-20T16:41:37Z
-- Checksum: 8b429e65b7a9d98b171e66d8c9c34ce3c344de6b8b2f84bd8183c47b580cb817
-- Chain: 008ed4a07e084dfae573636b9273d3d519994590aeee4dcb8b86edc0bbdabf27
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
-- The markers behind each of the service's cookies are kept by its prefix.
ALTER TABLE edge_subjects RENAME COLUMN gs TO prefix;
