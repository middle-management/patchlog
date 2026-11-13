-- Migration: write producers
-- Created: 2026-11-13T07:42:12Z
-- Checksum: 2ab94f7de462b4b5f657de79173f6f058b3f670e79dc6dc6dec2199a63c5a0bc
-- Chain: 6f3b1cabee2fbee78061b78f163b63d7dc2926e7f0e587665ed38c7372070e59
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

-- EXPERIMENTAL (internal/core/producer.go; docs/SPEC-FEEDBACK.md, v0.82 Open
-- 91): the retry key of single resource writes. Per resource, author and
-- producer id, the last epoch and seq written and the revision that write
-- made, stored in the write's transaction. Only written where the core
-- runs with -experimental-rebase.
CREATE TABLE IF NOT EXISTS write_producers (
  res      BIGINT NOT NULL,
  author   BIGINT NOT NULL,
  producer TEXT NOT NULL,
  epoch    BIGINT NOT NULL,
  seq      BIGINT NOT NULL,
  last_seq BIGINT NOT NULL,
  PRIMARY KEY (res, author, producer)
);
