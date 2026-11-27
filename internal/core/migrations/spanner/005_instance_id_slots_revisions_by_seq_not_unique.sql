-- Migration: instance id slots, revisions by seq not unique
-- Created: 2026-11-27T14:25:28Z
-- Checksum: c7359f930782ca982daf2f3f2e467776990ab172255878ad362b6b8074919780
-- Chain: 6ae555e2c9e3ec7eb55ef96229b63c2b27652e38317879f0d36ffe5dd156286c
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
-- Each instance's slot in the ids it takes (spslots.go), so no two take
-- the same: revisions' index by seq alone, which a revision read without
-- its resource goes through, then needs no uniqueness checked at each
-- commit (docs/SPANNER.md, the twelfth run).
CREATE TABLE IF NOT EXISTS id_slots (
  slot    bigint NOT NULL PRIMARY KEY,
  holder  text   NOT NULL,
  expires bigint NOT NULL
);
DROP INDEX IF EXISTS revisions_seq_key;
CREATE INDEX IF NOT EXISTS revisions_by_seq ON revisions (seq);
