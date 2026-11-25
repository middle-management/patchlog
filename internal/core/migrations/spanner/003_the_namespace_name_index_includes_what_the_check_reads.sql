-- Migration: the namespace name index includes what the check reads
-- Created: 2026-11-25T14:10:43Z
-- Checksum: e2d68d2b62b53c38af30ae7f50deedbec27449430c9937a59840295303948da8
-- Chain: 5765b24891c66278a8eed1fcd13475e76228704aedd9e0aaf59dd7133e382fb2
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The write's check reads its namespace by name (lookupResource): with the
-- columns it reads in the name's index, Spanner reads no base row for them
-- (docs/SPANNER.md, the fifth bench run, where the check was half of its
-- CPU). They change once a group commit, as the head moves. The index is
-- made again to include them: Spanner can't add included columns to a
-- unique index in place.
DROP INDEX IF EXISTS namespaces_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS namespaces_name_key ON namespaces (name)
  INCLUDE (base, base_at, base_config_seq, frozen, purged, head_seq, config_seq);
