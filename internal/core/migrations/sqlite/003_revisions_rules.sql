-- Migration: revisions rules
-- Created: 2026-10-27T13:41:22Z
-- Checksum: fcc39414b8f6f60c7bf37877b16f5f3b4cdc33e64bb03af0246c8e64001e6cc5
-- Chain: 52f5fc9a89bfe13a90a0d04ccdb49fb18de1dba17cca98fd4097f6679e237684
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- revisions.rules: the schema rules marker of a revision (schema.Rules,
-- schemaload.go): 1 for V073, 0 for Legacy; NULL, read as Legacy, in rows
-- from before it and in rows a remote branch mirrors from a base that
-- serves no marker (§6.1, F-S1).
ALTER TABLE revisions ADD COLUMN rules INTEGER;
