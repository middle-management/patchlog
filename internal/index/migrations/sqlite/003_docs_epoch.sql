-- Migration: docs epoch
-- Created: 2026-10-27T13:47:32Z
-- Checksum: a66399684c65aaf5e1ec1b1e5760a9e07c6fd28d7cd029498d814b470920a9dd
-- Chain: 3c1b5af82077955d6f16d13659ea16e3bf72e4e3c3d1f1f4e85f1691741e9ed1
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- docs.epoch: in a sealed or e2e namespace, the epoch a document's head is
-- served under (derived.EpochOf), which its hits are sealed under
-- (§E.2.6); NULL or 0 where not known. A database whose rows predate it is
-- rebuilt if it follows a sealed or e2e namespace (initSchema).
ALTER TABLE docs ADD COLUMN epoch INTEGER;
