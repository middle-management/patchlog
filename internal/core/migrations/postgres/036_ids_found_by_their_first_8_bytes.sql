-- Migration: ids found by their first 8 bytes
-- Created: 2026-11-28T05:54:15Z
-- Checksum: ae07f856ed578a58bd3374b805fc170e6e9ea5b676ea34fb5c10a5ee3a37b97b
-- Chain: 79df356b39f0a1698a20fb3d479eecafb13efddd16b39fac295e1b8289c5475d
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Ids found by their first 8 bytes (dialect.go idKeySQL, docs/capacity/
-- storage/README.md "The memory cliff"): ns_log (ns, id) and revisions
-- (res, id), unique constraints on the whole 20-byte id, become indexes
-- on (ns, key) and (res, key), the key the id's first 8 bytes as a bigint
-- (an expression: no column, nothing for an insert to set). An entry
-- takes 24 bytes where it took 40, so the two indexes a write inserts into
-- at a random place are 40% smaller. Lookups compare the whole id on the
-- rows the key finds. The whole id stays unique in its namespace and in
-- its resource: a trigger of each table looks it up through the new index
-- before a row goes in (the probe the unique index made) and raises the
-- unique violation the constraint did, on the same table and constraint
-- name, so a write that loses a race (isConflict) is told as before. Two
-- concurrent inserts of one id can't see each other's row; the second
-- still fails on its chain's unique constraint (ns, prev_seq) or (res,
-- parent_seq), an id being the hash of its parent's (§3.3, §3.5).
--
-- Building the indexes reads each table once, under a lock that holds
-- writes back for as long.
CREATE INDEX IF NOT EXISTS ns_log_ns_id8 ON ns_log (ns, (('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint));
CREATE INDEX IF NOT EXISTS revisions_res_id8 ON revisions (res, (('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint));

CREATE OR REPLACE FUNCTION ns_log_id_unique() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM ns_log WHERE ns = NEW.ns
      AND ('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint = ('x' || encode(substr(NEW.id, 1, 8), 'hex'))::bit(64)::bigint
      AND id = NEW.id AND seq <> NEW.seq) THEN
    RAISE EXCEPTION 'duplicate key value violates unique constraint "ns_log_ns_id_key"'
      USING ERRCODE = 'unique_violation', TABLE = 'ns_log', CONSTRAINT = 'ns_log_ns_id_key',
        DETAIL = format('Key (ns, id)=(%s, %s) already exists.', NEW.ns, NEW.id);
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS ns_log_id_unique ON ns_log;
CREATE TRIGGER ns_log_id_unique BEFORE INSERT OR UPDATE OF ns, id ON ns_log FOR EACH ROW EXECUTE FUNCTION ns_log_id_unique();

CREATE OR REPLACE FUNCTION revisions_id_unique() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM revisions WHERE res = NEW.res
      AND ('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint = ('x' || encode(substr(NEW.id, 1, 8), 'hex'))::bit(64)::bigint
      AND id = NEW.id AND seq <> NEW.seq) THEN
    RAISE EXCEPTION 'duplicate key value violates unique constraint "revisions_res_id_key"'
      USING ERRCODE = 'unique_violation', TABLE = 'revisions', CONSTRAINT = 'revisions_res_id_key',
        DETAIL = format('Key (res, id)=(%s, %s) already exists.', NEW.res, NEW.id);
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS revisions_id_unique ON revisions;
CREATE TRIGGER revisions_id_unique BEFORE INSERT OR UPDATE OF res, id ON revisions FOR EACH ROW EXECUTE FUNCTION revisions_id_unique();

ALTER TABLE ns_log DROP CONSTRAINT IF EXISTS ns_log_ns_id_key;
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_res_id_key;
