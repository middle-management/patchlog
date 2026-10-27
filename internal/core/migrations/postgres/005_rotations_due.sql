-- Migration: rotations due
-- Created: 2026-10-27T13:41:22Z
-- Checksum: 11ea17ec42ec7aa1c632146119770a9c84d244291dd586737727cfdcb3ac1382
-- Chain: a952100485c8a02986d8baf71b6009638005839000f34d8179714b0b85821282
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Sealed namespaces whose rotation after a revocation is due, recorded
-- with the revocation and cleared by the next new epoch; retried until
-- then (Options.RotateOnRevoke, sealed.go).
CREATE TABLE IF NOT EXISTS rotations_due (
  ns    bigint PRIMARY KEY REFERENCES namespaces,
  since bigint NOT NULL
);
