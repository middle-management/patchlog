-- Migration: explicit gone
-- Created: 2026-10-27T13:46:20Z
-- Checksum: 85a3b7d1ae2fd2a32a8c8519aec2651b775cd1916f6bae1ca376a99359316985
-- Chain: 4292d9362f25a1ffff979dab548c375b2922804806fa6efccd6092f179e8d07a
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Placements whose explicit placement was deleted or purged, which still
-- win over $parents (§B.9); meta "gone" marks them filled in for a
-- database from before they were kept (backfillNodes).
CREATE TABLE IF NOT EXISTS explicit_gone (name TEXT PRIMARY KEY) WITHOUT ROWID;
