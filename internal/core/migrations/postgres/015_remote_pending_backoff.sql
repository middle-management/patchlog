-- Migration: remote pending backoff
-- Created: 2026-11-10T07:54:47Z
-- Checksum: b50548f384e2c9e04da78260e545ef2c881ab949edd410d715d4539dd159ad1d
-- Chain: af848c841864ae90c2078f5f55a0048b0b329cce6cb50441ce8d631e9c608120
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Backoff of pending pre-raise sealings (§G.5.2 E3 sources; core
-- preraise_pending.go, v0.26.1). tries is how many syncs have asked the
-- source for the sealing again and failed since it was recorded, and due
-- when a sync may next ask, in Unix milliseconds (pendingBackoff: at the
-- next two syncs, then after a minute, doubling up to four hours); rows
-- from before are due at once. A purge of a remote branch's resource or
-- namespace now deletes its rows; those an earlier purge left, of a purged
-- shadow or resource, are deleted here.
ALTER TABLE remote_pending_sealings ADD COLUMN IF NOT EXISTS tries bigint NOT NULL DEFAULT 0;
ALTER TABLE remote_pending_sealings ADD COLUMN IF NOT EXISTS due bigint NOT NULL DEFAULT 0;
DELETE FROM remote_pending_sealings
  WHERE shadow IN (SELECT ns FROM namespaces WHERE purged = 1)
  OR EXISTS (SELECT 1 FROM resources r WHERE r.ns = remote_pending_sealings.shadow AND r.name = remote_pending_sealings.name AND r.state = 2);
