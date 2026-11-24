-- Migration: hotspots: sharded commit-timestamp index, no id_blocks
-- Created: 2026-11-24T18:24:32Z
-- Checksum: 3f55a802dc7494a61927877707df508a9bb6d1bf8926fbe05ebad6cfb97cd23d
-- Chain: a175ee55f04917c76a5666a944d4815ddd8c51ce01b3b913427a4ab17a089a99
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Spanner's hotspots (docs/SPANNER.md, spanner.go).
--
-- The tailer's index on ns_log's commit timestamps, sharded: every append
-- wrote at its tail, one point of the index for the whole deployment; now
-- at the tail of its namespace's shard (spShard, the top bits of ns), one
-- of 32, which the tailer reads each of.
ALTER TABLE ns_log ADD COLUMN IF NOT EXISTS shard bigint NOT NULL DEFAULT (0);
DROP INDEX IF EXISTS ns_log_committed;
CREATE INDEX IF NOT EXISTS ns_log_committed_by_shard ON ns_log (shard, committed);
-- The chain-ordered ids are no longer taken in blocks from a counter, whose
-- inserts all landed at the end of each table's keys, but made of a bucket
-- of the chain's key and the time (seqGen).
DROP TABLE IF EXISTS id_blocks;
