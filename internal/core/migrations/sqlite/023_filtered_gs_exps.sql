-- Migration: filtered gs exps
-- Created: 2026-11-19T16:07:49Z
-- Checksum: cc1b4ac21ff08945376c9bf33f95b53b65c86fe6b64508a7bc315628d841ea19
-- Chain: b6740df7ef5cf301f2bd4fc2789327461c0d306bfd9665e0012f5aa43bae2eab
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
-- Filtered namespace reads (§B.11.9 gs, §C.5.2, filtered_state.go; v0.86):
-- a cookie carries its prefix and exp alone, so the cookies of one gs that
-- expire at the same second are one cookie. filtered_gs_exps keeps, per
-- such cookie, the entry digest its exchanges recorded and the ns_config
-- row of {ns} they read (conf): a read under the cookie is judged from
-- its own row, and an exchange whose cookie must be told apart from the
-- one a second holds takes an earlier second. It replaces
-- filtered_gs.entry_after and the judging by filtered_gs.conf, which told
-- cookies apart by "expires no later" and so could give a reader whose
-- grant ends within the quarter of an hour no cookie that reads.
CREATE TABLE IF NOT EXISTS filtered_gs_exps (
  ns    TEXT NOT NULL,
  gs    TEXT NOT NULL,
  exp   BIGINT NOT NULL,
  entry TEXT NOT NULL,
  conf  BIGINT NOT NULL,
  PRIMARY KEY (ns, gs, exp)
);
CREATE INDEX IF NOT EXISTS filtered_gs_exps_exp ON filtered_gs_exps (exp);
