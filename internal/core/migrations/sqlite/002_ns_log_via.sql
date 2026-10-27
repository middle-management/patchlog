-- Migration: ns_log via
-- Created: 2026-10-27T13:40:57Z
-- Checksum: aaf9d6f282c9ebe7348a0e089af18aa9521f211709b08819ea568305c141f683
-- Chain: f036798ffe85ecb97ebec378fe2d285fdff4bd6a437fc1068ca36fde6f7c8517
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
ALTER TABLE ns_log ADD COLUMN via TEXT;
