-- Migration: filtered reads by view, reads judged per revision
-- Created: 2026-11-20T16:14:52Z
-- Checksum: f10337520d4731a289ef14e90ed0f93878cd58e656bb206bdba18ad2191b1cf6
-- Chain: 446fce873c94f00094503547bf721068cb23a106db57e071517fb8f6f7afcf27
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
-- Filtered reads at /ns/{ns}/view/{view} (v0.87, §7.9): a partial
-- reader's subject set is its view. filtered_views keeps, per namespace
-- and view an edge grant was issued for, what a cookie for it is judged
-- by (the rules and /principal values its digest covers), and
-- filtered_view_exps, per cookie (its second of expiry), the entry digest
-- its exchanges recorded and the namespace document they read. Cookies
-- minted under the old tables are left to expire unread.
DROP INDEX IF EXISTS filtered_gs_exp;
DROP TABLE IF EXISTS filtered_gs;
DROP INDEX IF EXISTS filtered_gs_exps_exp;
DROP TABLE IF EXISTS filtered_gs_exps;
CREATE TABLE IF NOT EXISTS filtered_views (
  ns          TEXT    NOT NULL,
  view        TEXT    NOT NULL,
  subjects    TEXT    NOT NULL,
  kid         TEXT    NOT NULL,
  pub         TEXT    NOT NULL,
  roles       TEXT    NOT NULL,
  block_rules TEXT    NOT NULL,
  read_scope  BIGINT  NOT NULL,
  principal   TEXT    NOT NULL,
  digest      TEXT    NOT NULL,
  entry       TEXT    NOT NULL,
  conf        BIGINT  NOT NULL,
  filter      TEXT    NOT NULL,
  exp         BIGINT  NOT NULL,
  PRIMARY KEY (ns, view)
);
CREATE INDEX IF NOT EXISTS filtered_views_exp ON filtered_views (exp);
CREATE TABLE IF NOT EXISTS filtered_view_exps (
  ns    TEXT   NOT NULL,
  view  TEXT   NOT NULL,
  exp   BIGINT NOT NULL,
  entry TEXT   NOT NULL,
  conf  BIGINT NOT NULL,
  PRIMARY KEY (ns, view, exp)
);
CREATE INDEX IF NOT EXISTS filtered_view_exps_exp ON filtered_view_exps (exp);
-- Reads are judged per revision (§C.2 item 5, §7.9 Cost): read_judged
-- keeps, per digest of the rules and /principal values a read is judged
-- by (judge), whether they allow reading the revision or tombstone id of
-- resource name. An id determines its document everywhere (§3.3), so the
-- answer holds in every namespace and is kept once pruning drops the
-- document (§8.6). A purged resource is judged without it (doc null).
CREATE TABLE IF NOT EXISTS read_judged (
  judge   TEXT   NOT NULL,
  name    TEXT   NOT NULL,
  id      BLOB  NOT NULL,
  visible BIGINT NOT NULL,
  PRIMARY KEY (judge, name, id)
);
