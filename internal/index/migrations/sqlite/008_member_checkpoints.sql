-- Migration: member checkpoints
-- Created: 2026-11-09T11:33:22Z
-- Checksum: dcd28763146bb485669cee7eebc421aee80525c67d1248bf0f553b23ebdee5c5
-- Chain: 87e480873a5ba2c0366ca0bfa3fe69fbb132fd12b516f5660f2a3b02ca90ad57
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
-- ALTER TABLE users ADD COLUMN new_feature_flag BOOLEAN DEFAULT false;-- member_checkpoints: follow.SQLCheckpoints under another table name, the
-- checkpoint of each namespace visibility reads that the index follows
-- without serving it (§A.4 Private namespaces: a covered namespace's
-- trusted catalogs, their catalog.trust members and a covered branch's
-- bases; members.go), committed with the purges it applies (§A.1), so a
-- restart resumes there and purges made meanwhile still reach the cache.
-- member_conf: as ns_conf, the read mode and level such a namespace's
-- follower last applied, against which a config entry is found to make it
-- private or raise it to sealed or e2e (§9, Index.narrowed).
CREATE TABLE IF NOT EXISTS member_checkpoints (origin TEXT NOT NULL, ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (origin, ns));
CREATE TABLE IF NOT EXISTS member_conf (ns TEXT PRIMARY KEY, public INTEGER NOT NULL, level TEXT NOT NULL);
