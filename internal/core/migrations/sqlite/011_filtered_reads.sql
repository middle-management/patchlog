-- Migration: filtered reads
-- Created: 2026-11-09T05:24:45Z
-- Checksum: e9feca356bcab83d8c37efe648e6e673b77085f1f3f18a6742ad71ac2c8bf1a1
-- Chain: c48fd865d47abf72b2f775b4ff9252305d5652ae00e53e32368bfd8151d64c1e
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
-- Filtered namespace reads (§B.11.9, filtered_state.go). filtered_gs keeps,
-- for each namespace and subject set an edge grant was issued for, what a
-- cookie for it is judged by: its subjects, and the rules and /principal
-- values its scope digest covers (kid, read roles, block rules, readScope,
-- principal, digest, the encoded grantcheck.ReadFilter), until exp, the
-- latest of its cookies' expiries. A gs names no namespace, so one grant
-- (or two callers alike) can have the same gs in two: rows are per (ns,
-- gs). filtered_ats records each combined checkpoint a filtered URL was
-- minted at, ns → ns_id as JSON, swept after 7 days.
CREATE TABLE IF NOT EXISTS filtered_gs (
  ns          TEXT    NOT NULL,
  gs          TEXT    NOT NULL,
  subjects    TEXT    NOT NULL,
  partial     INTEGER NOT NULL,
  kid         TEXT    NOT NULL,
  roles       TEXT    NOT NULL,
  block_rules TEXT    NOT NULL,
  read_scope  INTEGER NOT NULL,
  principal   TEXT    NOT NULL,
  digest      TEXT    NOT NULL,
  filter      TEXT    NOT NULL,
  exp         INTEGER NOT NULL,
  PRIMARY KEY (ns, gs)
);
CREATE INDEX IF NOT EXISTS filtered_gs_exp ON filtered_gs (exp);
CREATE TABLE IF NOT EXISTS filtered_ats (
  at          TEXT    PRIMARY KEY,
  cps         TEXT    NOT NULL,
  created     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS filtered_ats_created ON filtered_ats (created);
