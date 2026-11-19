-- Migration: branches paging gs conf
-- Created: 2026-11-19T15:19:05Z
-- Checksum: e37e1de5d6e0169dcce67efbaf2881cfb13ceee8ea9be0a4e9326badb4933d64
-- Chain: aa1d5762e5cc450d182f685c365efd6c34b6b7294d8c14014188f4f64763317f
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
-- A page of GET /ns/{ns}/branches (§7.4) is in byte order of key
-- (remote_source.go, registrationsAfter). A remote branch's key is
-- {origin}/{ns}, which the primary key's (origin, name) doesn't order
-- ("https://a/x" is after "https://a.b/x"). (A base's branches are in
-- byte order in namespaces_base already: SQLite's index is BINARY.)
CREATE INDEX IF NOT EXISTS remote_branches_key ON remote_branches (ns, (origin || '/' || name));

-- Filtered namespace reads (§B.11.9 gs, filtered_admit.go; v0.86): "Once
-- an entry after its exchange changes one of them, the cookie is 403 from
-- that entry on, even where a later entry undoes the change." conf is the
-- ns_config row of {ns} under which the exchange recorded the row's entry
-- digest: a cookie is judged at every namespace document between it and
-- the one at the answer's checkpoint, not at the checkpoint's alone. 0, a
-- row from before it was kept, never holds.
ALTER TABLE filtered_gs ADD COLUMN conf BIGINT NOT NULL DEFAULT 0;
