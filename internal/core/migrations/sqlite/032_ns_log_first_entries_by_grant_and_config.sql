-- Migration: ns_log first entries by grant and config
-- Created: 2026-11-27T09:08:21Z
-- Checksum: fc023ef38630ec1c6fac4a148c2cd40373f7d41bbacd9038e700af7250369226
-- Chain: 53971947cd027b8971ba1975f81ee4a9837ee513a926f8c02e474ba43c53bb4c
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Two per-write indexes of ns_log that served rare lookups, replaced by
-- rows written once (docs/capacity/storage, CHANGELOG):
--
-- ns_grants: the first entry of each namespace recording each grant, by
-- the grant's number (grants.ref), for GET /ns/{ns}/grants/{gid}, archive
-- candidates and sealing a grant (§C.3.1, grants.go, archive.go), in place
-- of ns_log_by_grant and ns_log_by_grant_ref. A trigger adds the row as the
-- entry is inserted; an entry's seq is above every earlier one's, so the
-- first row stays the first.
--
-- ns_config.first_seq: the first entry of the namespace under each
-- configuration, for idempotent retries of config writes and batches
-- (nsconfig.go, write.go), in place of ns_log_ns_config. A trigger sets it
-- as the first such entry is inserted.
--
-- Both are filled from the entries there are (one pass over ns_log), then
-- the indexes are dropped.
CREATE TABLE IF NOT EXISTS ns_grants (
  grant_ref  INTEGER NOT NULL,
  ns         INTEGER NOT NULL,
  first_seq  INTEGER NOT NULL,
  PRIMARY KEY (grant_ref, ns)
) WITHOUT ROWID;
INSERT OR IGNORE INTO ns_grants (grant_ref, ns, first_seq)
  SELECT ref, ns, MIN(seq) FROM (
    SELECT COALESCE(l.grant_ref, g.ref) AS ref, l.ns, l.seq FROM ns_log l LEFT JOIN grants g ON g.id = l.grant_id
    WHERE l.grant_id IS NOT NULL OR l.grant_ref IS NOT NULL) x
  WHERE ref IS NOT NULL GROUP BY ref, ns;
CREATE TRIGGER IF NOT EXISTS ns_log_first_grant AFTER INSERT ON ns_log WHEN NEW.grant_ref IS NOT NULL
BEGIN
  INSERT OR IGNORE INTO ns_grants (grant_ref, ns, first_seq) VALUES (NEW.grant_ref, NEW.ns, NEW.seq);
END;

ALTER TABLE ns_config ADD COLUMN first_seq INTEGER;
UPDATE ns_config SET first_seq = (SELECT MIN(l.seq) FROM ns_log l WHERE l.ns = ns_config.ns AND l.config_seq = ns_config.seq);
CREATE TRIGGER IF NOT EXISTS ns_log_first_config AFTER INSERT ON ns_log
BEGIN
  UPDATE ns_config SET first_seq = NEW.seq WHERE seq = NEW.config_seq AND ns = NEW.ns AND first_seq IS NULL;
END;

DROP INDEX IF EXISTS ns_log_by_grant;
DROP INDEX IF EXISTS ns_log_by_grant_ref;
DROP INDEX IF EXISTS ns_log_ns_config;
