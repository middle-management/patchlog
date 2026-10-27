-- Migration: rotations due
-- Created: 2026-10-27T13:41:22Z
-- Checksum: e1226dbf9f6865282cf0da364600e4a8642c01a56ff68413e679f84ca1a4dd6d
-- Chain: fd8393fdcab995280a373af66fd445b316a396556c723fcd2626ad39014e4b77
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Sealed namespaces whose rotation after a revocation is due, recorded
-- with the revocation and cleared by the next new epoch; retried until
-- then (Options.RotateOnRevoke, sealed.go).
CREATE TABLE IF NOT EXISTS rotations_due (
  ns    INTEGER PRIMARY KEY REFERENCES namespaces,
  since INTEGER NOT NULL
);
