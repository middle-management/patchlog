-- Migration: ns_log via
-- Created: 2026-10-27T13:40:57Z
-- Checksum: 9687a67996ad279a453858b5eafe45e8abf901019b9e16b68b96793eeff57e27
-- Chain: e76c6fe208b1018168ac27833714c15ba5b13190a4a01a240d772e30ef937a92
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- ns_log.via: the canonical JSON array of the delegatees of the grant a
-- namespace entry was written under (appendNS, grantVia), served unhashed
-- (§5, §7.4); NULL for none, for the server's own entries, and in rows
-- from before it, which can't be recovered from the stored grants (one
-- row per root id).
ALTER TABLE ns_log ADD COLUMN IF NOT EXISTS via text;
