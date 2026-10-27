-- Migration: revisions rules
-- Created: 2026-10-27T13:41:22Z
-- Checksum: f9caff3251507267e0dc9688caa2717ee257537dc93297af56ebf45a0de8c494
-- Chain: 8ed538a22c0f76ab88bcb62834ff1e82285f4ba80f3ba05f3f06a979d9ebfff8
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- revisions.rules: the schema rules marker of a revision (schema.Rules,
-- schemaload.go): 1 for V073, 0 for Legacy; NULL, read as Legacy, in rows
-- from before it and in rows a remote branch mirrors from a base that
-- serves no marker (§6.1, F-S1).
ALTER TABLE revisions ADD COLUMN IF NOT EXISTS rules smallint;
