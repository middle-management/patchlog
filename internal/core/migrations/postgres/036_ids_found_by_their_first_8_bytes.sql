-- Migration: ids found by their first 8 bytes
-- Created: 2026-11-28T09:02:17Z
-- Checksum: d91f874b7f9764ca792ce94e7a98c550142e739c161ca6443c9329ccf769eef0
-- Chain: 61a7703a1310b613897fa43d3e63ec86eee8c636d3660c71ca0add2a6297e528
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Ids found by their first 8 bytes (dialect.go idKeySQL, docs/capacity/
-- storage/README.md "The memory cliff"): ns_log (ns, id) and revisions
-- (res, id), unique constraints on the whole 20-byte id, become indexes on
-- (ns, key) and (res, key), the key the id's first 8 bytes as a bigint (an
-- expression: no column, nothing for an insert to set). An entry takes 24
-- bytes where it took 40, so the two indexes a write inserts into at a
-- random place are 40% smaller. Lookups compare the whole id on the rows
-- the key finds. The whole id stays unique in its namespace and in its
-- resource: a trigger of each table looks up the rows each insert
-- statement wrote through the new index (the probe the unique index made)
-- and raises the unique violation the constraint did, on the same table
-- and constraint name, so a write that loses a race (isConflict) is told
-- as before. Two concurrent inserts of one id can't see each other's row;
-- the second still fails on its chain's unique constraint (ns, prev_seq)
-- or (res, parent_seq), an id being the hash of its parent's (§3.3, §3.5).
--
-- Building the indexes reads each table once, under a lock that holds
-- writes back for as long.
CREATE INDEX IF NOT EXISTS ns_log_ns_id8 ON ns_log (ns, (('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint));
CREATE INDEX IF NOT EXISTS revisions_res_id8 ON revisions (res, (('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint));

-- Per statement, over the rows it inserted (a bulk insert's thousand
-- rows in one pass): each row probes the key index, a LATERAL subquery
-- with a LIMIT, which the planner can't turn into a join the other way
-- round. The query is planned afresh for each statement (EXECUTE), from
-- the table's size then: a plan cached by the function would keep what
-- it chose while the table was small, a scan of a whole index with the
-- key as a filter, as the table grew. Nothing but an index is allowed.
CREATE OR REPLACE FUNCTION ns_log_id_unique() RETURNS trigger LANGUAGE plpgsql
  SET enable_seqscan = off SET enable_hashjoin = off SET enable_mergejoin = off AS $$
DECLARE d record; found_rows bigint;
BEGIN
  EXECUTE 'SELECT n.ns, n.id FROM ns_log_new n, LATERAL (SELECT 1 FROM ns_log x WHERE x.ns = n.ns
    AND (''x'' || encode(substr(x.id, 1, 8), ''hex''))::bit(64)::bigint = (''x'' || encode(substr(n.id, 1, 8), ''hex''))::bit(64)::bigint
    AND x.id = n.id AND x.seq <> n.seq LIMIT 1) y LIMIT 1' INTO d;
  GET DIAGNOSTICS found_rows = ROW_COUNT;
  IF found_rows > 0 THEN
    RAISE EXCEPTION 'duplicate key value violates unique constraint "ns_log_ns_id_key"'
      USING ERRCODE = 'unique_violation', TABLE = 'ns_log', CONSTRAINT = 'ns_log_ns_id_key',
        DETAIL = format('Key (ns, id)=(%s, %s) already exists.', d.ns, d.id);
  END IF;
  RETURN NULL;
END
$$;
DROP TRIGGER IF EXISTS ns_log_id_unique ON ns_log;
CREATE TRIGGER ns_log_id_unique AFTER INSERT ON ns_log REFERENCING NEW TABLE AS ns_log_new FOR EACH STATEMENT EXECUTE FUNCTION ns_log_id_unique();
-- Nothing changes an id or its ns once stored; should anything, the
-- row is checked as it changes.
CREATE OR REPLACE FUNCTION ns_log_id_unique_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM ns_log WHERE ns = NEW.ns AND ('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint = ('x' || encode(substr(NEW.id, 1, 8), 'hex'))::bit(64)::bigint AND id = NEW.id AND seq <> NEW.seq) THEN
    RAISE EXCEPTION 'duplicate key value violates unique constraint "ns_log_ns_id_key"'
      USING ERRCODE = 'unique_violation', TABLE = 'ns_log', CONSTRAINT = 'ns_log_ns_id_key',
        DETAIL = format('Key (ns, id)=(%s, %s) already exists.', NEW.ns, NEW.id);
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS ns_log_id_unique_update ON ns_log;
CREATE TRIGGER ns_log_id_unique_update BEFORE UPDATE OF ns, id ON ns_log FOR EACH ROW EXECUTE FUNCTION ns_log_id_unique_update();

-- Per statement, over the rows it inserted (a bulk insert's thousand
-- rows in one pass): each row probes the key index, a LATERAL subquery
-- with a LIMIT, which the planner can't turn into a join the other way
-- round. The query is planned afresh for each statement (EXECUTE), from
-- the table's size then: a plan cached by the function would keep what
-- it chose while the table was small, a scan of a whole index with the
-- key as a filter, as the table grew. Nothing but an index is allowed.
CREATE OR REPLACE FUNCTION revisions_id_unique() RETURNS trigger LANGUAGE plpgsql
  SET enable_seqscan = off SET enable_hashjoin = off SET enable_mergejoin = off AS $$
DECLARE d record; found_rows bigint;
BEGIN
  EXECUTE 'SELECT n.res, n.id FROM revisions_new n, LATERAL (SELECT 1 FROM revisions x WHERE x.res = n.res
    AND (''x'' || encode(substr(x.id, 1, 8), ''hex''))::bit(64)::bigint = (''x'' || encode(substr(n.id, 1, 8), ''hex''))::bit(64)::bigint
    AND x.id = n.id AND x.seq <> n.seq LIMIT 1) y LIMIT 1' INTO d;
  GET DIAGNOSTICS found_rows = ROW_COUNT;
  IF found_rows > 0 THEN
    RAISE EXCEPTION 'duplicate key value violates unique constraint "revisions_res_id_key"'
      USING ERRCODE = 'unique_violation', TABLE = 'revisions', CONSTRAINT = 'revisions_res_id_key',
        DETAIL = format('Key (res, id)=(%s, %s) already exists.', d.res, d.id);
  END IF;
  RETURN NULL;
END
$$;
DROP TRIGGER IF EXISTS revisions_id_unique ON revisions;
CREATE TRIGGER revisions_id_unique AFTER INSERT ON revisions REFERENCING NEW TABLE AS revisions_new FOR EACH STATEMENT EXECUTE FUNCTION revisions_id_unique();
-- Nothing changes an id or its res once stored; should anything, the
-- row is checked as it changes.
CREATE OR REPLACE FUNCTION revisions_id_unique_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM revisions WHERE res = NEW.res AND ('x' || encode(substr(id, 1, 8), 'hex'))::bit(64)::bigint = ('x' || encode(substr(NEW.id, 1, 8), 'hex'))::bit(64)::bigint AND id = NEW.id AND seq <> NEW.seq) THEN
    RAISE EXCEPTION 'duplicate key value violates unique constraint "revisions_res_id_key"'
      USING ERRCODE = 'unique_violation', TABLE = 'revisions', CONSTRAINT = 'revisions_res_id_key',
        DETAIL = format('Key (res, id)=(%s, %s) already exists.', NEW.res, NEW.id);
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS revisions_id_unique_update ON revisions;
CREATE TRIGGER revisions_id_unique_update BEFORE UPDATE OF res, id ON revisions FOR EACH ROW EXECUTE FUNCTION revisions_id_unique_update();

ALTER TABLE ns_log DROP CONSTRAINT IF EXISTS ns_log_ns_id_key;
ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_res_id_key;
