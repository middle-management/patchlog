-- Migration: edge store tables of the index's own edge grants
-- Created: 2026-11-20T15:09:03Z
-- Checksum: 2989aaa69962451753f85203ada27e346de0cbf23faf476dddf34d61e87b2ade
-- Chain: 192e6632de8fc0749970477ba901e3b55676877133de031b1a669b55168258e9
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
-- The state of the index's own edge grants (edgeStore), which package
-- svcedge kept under a migration namespace of its own before it was
-- folded into the index with the tree service's removal (v0.87):
-- edge_subjects, the subjects behind each subject set the index minted an
-- edge grant for, until the last of them expires; edge_buckets, the
-- exchangeRate buckets of its exchange, one per principal. A database that
-- has them already keeps them.
CREATE TABLE IF NOT EXISTS edge_subjects (gs TEXT PRIMARY KEY, subjects TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS edge_buckets (k TEXT PRIMARY KEY, tokens REAL NOT NULL, last INTEGER NOT NULL) WITHOUT ROWID;
