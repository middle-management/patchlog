-- Migration: nodes born epoch
-- Created: 2026-10-28T06:24:04Z
-- Checksum: 88555c4cfc4b987ad375f11e5939409ec73c4569b8afd77f1ec4080054e1081f
-- Chain: 23b9a8f3a9216cf3ca22dc1ad0fc3a04c546a52a788a65aa460ae59ee795d3db
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- nodes.born_epoch, the epoch the first revision of a node's document is
-- served under in a sealed or e2e catalog (§E.2.6): a listing seals born
-- apart from the node's other values where it differs from the head's
-- epoch. Rows written before it are read in by backfillEpochs, which
-- meta "epochs" marks pending again; a database without a born has
-- nothing to read in.
ALTER TABLE nodes ADD COLUMN born_epoch INTEGER;
INSERT INTO meta (k, v) SELECT 'epochs', 'pending'
WHERE EXISTS (SELECT 1 FROM nodes WHERE born IS NOT NULL AND born <> '')
ON CONFLICT (k) DO NOTHING;
