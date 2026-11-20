-- Migration: purge by name live branches
-- Created: 2026-11-20T12:29:33Z
-- Checksum: dc2a712c4680c05f91883e712a5ffe5fdf559fc59adbcda339b672b196eb8746
-- Chain: a0b6261d3e268810d29ce27a911fda1e660785fade623ebd51651edb69003fa6
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- current.sql: Development-only migration file
-- 
-- This file is automatically applied in development environments.
-- When ready for production, commit this as a numbered migration file (NNN_name.sql)
-- and clear this file.
--
-- Example usage:
-- ALTER TABLE users ADD COLUMN new_feature_flag BOOLEAN DEFAULT false;
-- A purge finds the namespaces it has something to do in from the name
-- (nspurge.go, purgeHolders): the ones that hold a resources row, sealed
-- copies or blob sealings for it, by these three indexes, where it read
-- every branch below the purged namespace and asked each by (ns, name).
CREATE INDEX IF NOT EXISTS resources_name ON resources (name, ns);
CREATE INDEX IF NOT EXISTS sealed_by_name ON sealed (name, ns) WHERE name IS NOT NULL;
CREATE INDEX IF NOT EXISTS blob_epochs_name ON blob_epochs (name, ns);
-- And the branches of a namespace made at or after a position of its log,
-- the ones that may read a name through that the namespace has had since
-- then: a purge reads those and not the branches made before.
CREATE INDEX IF NOT EXISTS namespaces_base_at ON namespaces (base, base_at);
-- A namespace's live branches (nsconfig.go, liveBranches), counted at
-- every branch creation and unfreeze without reading the frozen and purged
-- ones.
CREATE INDEX IF NOT EXISTS namespaces_live ON namespaces (base, ns) WHERE frozen = 0 AND purged = 0;
