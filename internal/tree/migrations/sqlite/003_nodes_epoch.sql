-- Migration: nodes epoch
-- Created: 2026-10-27T13:46:20Z
-- Checksum: a44a87442b0517aabc5a767b1f56b8bf2925aad00d8e4f7189f9a8d7996d6b7b
-- Chain: eb2c96fd0b7a480fe10729f1a03771ff902949e1da5b46865b235cf91f3f6d6f
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- nodes.epoch, the epoch a node's head is served under in a sealed or e2e
-- catalog (§E.2.6). Rows written before it, and the epochs of items' file
-- metadata, are read in by backfillEpochs, which meta "epochs" marks
-- pending; a database without rows has nothing to read in.
ALTER TABLE nodes ADD COLUMN epoch INTEGER;
INSERT INTO meta (k, v) SELECT 'epochs', 'pending'
WHERE EXISTS (SELECT 1 FROM nodes) OR EXISTS (SELECT 1 FROM items)
ON CONFLICT (k) DO NOTHING;
