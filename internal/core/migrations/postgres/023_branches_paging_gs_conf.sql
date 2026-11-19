-- Migration: branches paging gs conf
-- Created: 2026-11-19T15:19:05Z
-- Checksum: 4ab4a482db0addd06334c1e9fa11609e67853239a765745b74fc740e64073bd4
-- Chain: a0449f848a4dfc1d6d0e93598b4255a4f73b9d092e500baf8014e26ce99f6d33
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
-- A page of GET /ns/{ns}/branches (§7.4) and of a namespace purge's
-- dependents (§8.5) is in byte order of key (nsconfig.go, branchesAfter;
-- remote_source.go, registrationsAfter). namespaces_base orders a base's
-- branches by the database's collation, so neither a page's bound nor its
-- order could use it: as namespaces_name_c for the pages of GET /ns. A
-- remote branch's key is {origin}/{ns}, which (origin, name) doesn't
-- order ("https://a/x" is after "https://a.b/x").
CREATE INDEX IF NOT EXISTS namespaces_base_c ON namespaces (base, name COLLATE "C");
CREATE INDEX IF NOT EXISTS remote_branches_key ON remote_branches (ns, ((origin || '/' || name) COLLATE "C"));

-- Filtered namespace reads (§B.11.9 gs, filtered_admit.go; v0.86): "Once
-- an entry after its exchange changes one of them, the cookie is 403 from
-- that entry on, even where a later entry undoes the change." conf is the
-- ns_config row of {ns} under which the exchange recorded the row's entry
-- digest: a cookie is judged at every namespace document between it and
-- the one at the answer's checkpoint, not at the checkpoint's alone. 0, a
-- row from before it was kept, never holds.
ALTER TABLE filtered_gs ADD COLUMN conf bigint NOT NULL DEFAULT 0;
