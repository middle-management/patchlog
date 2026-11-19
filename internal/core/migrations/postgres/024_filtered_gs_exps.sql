-- Migration: filtered gs exps
-- Created: 2026-11-19T16:07:49Z
-- Checksum: 369f3a37db28863c9e897bbabeb02ab90e10f76662f459a2463aaa8b16f77696
-- Chain: 8eee454e069fd688264d872b2e92fb63bcbde06ee423fd7a608cc092116628ce
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
  exp   bigint NOT NULL,
  entry TEXT NOT NULL,
  conf  bigint NOT NULL,
  PRIMARY KEY (ns, gs, exp)
);
CREATE INDEX IF NOT EXISTS filtered_gs_exps_exp ON filtered_gs_exps (exp);
