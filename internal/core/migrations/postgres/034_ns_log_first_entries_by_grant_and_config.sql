-- Migration: ns_log first entries by grant and config
-- Created: 2026-11-27T09:08:21Z
-- Checksum: 0e9718043faa3f75add2ea25fd08f0ad1fbb934b5098fcdf53c440a71733eec5
-- Chain: 56f6b7d976379d176338b6e426672278af96d6b12d2ada90c801861cfcca64ed
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
-- of ns_log_by_grant and ns_log_by_grant_ref. The trigger adds the row as
-- the entry is inserted; entries of a namespace are appended under its log
-- lock in seq order (pglock.go), so the first row stays the first.
--
-- ns_config.first_seq: the first entry of the namespace under each
-- configuration, for idempotent retries of config writes and batches
-- (nsconfig.go, write.go), in place of ns_log_ns_config. The trigger sets
-- it as the first such entry is inserted.
--
-- Both are filled from the entries there are (one pass over ns_log, and
-- an update of every ns_config row, under the migration's lock), then the
-- indexes are dropped.
CREATE TABLE IF NOT EXISTS ns_grants (
  grant_ref  bigint NOT NULL,
  ns         bigint NOT NULL,
  first_seq  bigint NOT NULL,
  PRIMARY KEY (grant_ref, ns)
);
INSERT INTO ns_grants (grant_ref, ns, first_seq)
  SELECT ref, ns, MIN(seq) FROM (
    SELECT COALESCE(l.grant_ref, g.ref) AS ref, l.ns, l.seq FROM ns_log l LEFT JOIN grants g ON g.id = l.grant_id
    WHERE l.grant_id IS NOT NULL OR l.grant_ref IS NOT NULL) x
  WHERE ref IS NOT NULL GROUP BY ref, ns
  ON CONFLICT DO NOTHING;
ALTER TABLE ns_config ADD COLUMN IF NOT EXISTS first_seq bigint;
UPDATE ns_config SET first_seq = (SELECT MIN(l.seq) FROM ns_log l WHERE l.ns = ns_config.ns AND l.config_seq = ns_config.seq);

CREATE OR REPLACE FUNCTION ns_log_firsts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.grant_ref IS NOT NULL THEN
    INSERT INTO ns_grants (grant_ref, ns, first_seq) VALUES (NEW.grant_ref, NEW.ns, NEW.seq) ON CONFLICT DO NOTHING;
  END IF;
  UPDATE ns_config SET first_seq = NEW.seq WHERE seq = NEW.config_seq AND ns = NEW.ns AND first_seq IS NULL;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS ns_log_firsts ON ns_log;
CREATE TRIGGER ns_log_firsts AFTER INSERT ON ns_log FOR EACH ROW EXECUTE FUNCTION ns_log_firsts();

DROP INDEX IF EXISTS ns_log_by_grant;
DROP INDEX IF EXISTS ns_log_by_grant_ref;
DROP INDEX IF EXISTS ns_log_ns_config;
