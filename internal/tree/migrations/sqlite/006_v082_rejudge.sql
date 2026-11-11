-- Migration: v082 rejudge
-- Created: 2026-11-11T07:39:59Z
-- Checksum: 603594e21d9480b46f233c220822fd4d481ba59b722e7dd9b073661f3fd01008
-- Chain: 1621ec6e6db06265e5cf976fd5f064f722316afa69960638ce65df396b344371
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- v0.82 (SERVICES §E.2.6 Per-entry sealing): a service seals nothing
-- derived from a revision until it has judged its epoch. A born_epoch
-- stored by an earlier release may have been judged as it was applied,
-- not read from the first revision: every one is reset, and read in again
-- by backfillEpochs, which meta "epochs" marks pending again (its row is
-- deleted once a fill is done). Until then such a born is left out of
-- sealed and e2e listings.
UPDATE nodes SET born_epoch = NULL WHERE born IS NOT NULL AND born <> '';
INSERT INTO meta (k, v) SELECT 'epochs', 'pending'
WHERE EXISTS (SELECT 1 FROM nodes WHERE born IS NOT NULL AND born <> '')
ON CONFLICT (k) DO NOTHING;
