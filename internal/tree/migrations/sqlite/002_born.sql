-- Migration: born
-- Created: 2026-10-27T13:46:20Z
-- Checksum: 2adf99e3becbf4038ae5573f2e2274d14709cd1c8b788d6756b96090ceb97dee
-- Chain: ab9738f7ee47d9e00e41bd28aca237c309b4a645636e96a59397903349ff74fc
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- born, the created of the first revision of a node's document (§B.5),
-- of explicit and implicit nodes and of content documents' $parents: ''
-- where it can't be known, NULL where it isn't read yet (bornVal), as in
-- every row from before it, which backfillNodes fills in.
ALTER TABLE nodes ADD COLUMN born TEXT;
ALTER TABLE self_parents ADD COLUMN born TEXT;
