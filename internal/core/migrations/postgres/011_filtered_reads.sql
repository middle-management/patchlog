-- Migration: filtered reads
-- Created: 2026-11-09T05:24:45Z
-- Checksum: cb4a899f63bc17c97ecb22fa75e90ebab0086d8840297af6175efa2351e2eaf8
-- Chain: 6726f64fa99ee060bf6e8b79341548c180054f41429b82458ebc76f2c8c08003
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
  ns          text    NOT NULL,
  gs          text    NOT NULL,
  subjects    text    NOT NULL,
  partial     bigint  NOT NULL,
  kid         text    NOT NULL,
  roles       text    NOT NULL,
  block_rules text    NOT NULL,
  read_scope  bigint  NOT NULL,
  principal   text    NOT NULL,
  digest      text    NOT NULL,
  filter      text    NOT NULL,
  exp         bigint  NOT NULL,
  PRIMARY KEY (ns, gs)
);
CREATE INDEX IF NOT EXISTS filtered_gs_exp ON filtered_gs (exp);
CREATE TABLE IF NOT EXISTS filtered_ats (
  at          text    PRIMARY KEY,
  cps         text    NOT NULL,
  created     bigint  NOT NULL
);
CREATE INDEX IF NOT EXISTS filtered_ats_created ON filtered_ats (created);
