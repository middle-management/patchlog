-- Migration: ids found by their first 8 bytes
-- Created: 2026-11-28T05:54:16Z
-- Checksum: 7538daa2a711f6a2380e35ddc4b708bd4a6f5fd29bed3dc7b92f5c2768b5b982
-- Chain: 400bee8bb1e3ec0b49c8d028e8bbd7b8e7f0b9f025ae249cb7e9c7ba80949cc1
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Ids found by their first 8 bytes (dialect.go idKeySQL, docs/capacity/
-- storage/README.md "The memory cliff"): ns_log UNIQUE (ns, id) and
-- revisions UNIQUE (res, id), on the whole 20-byte id, become indexes on
-- (ns, substr(id, 1, 8)) and (res, substr(id, 1, 8)), an expression (no
-- column, nothing for an insert to set). Lookups compare the whole id on
-- the rows the key finds. The whole id stays unique in its namespace and
-- in its resource: a trigger of each table looks it up through the new
-- index before a row goes in and fails as the constraint did (isConflict);
-- it compares +id, which no index answers, so the probe takes the key
-- index, whose page the insert then writes, not revisions_by_id.
--
-- A table constraint's index can't be dropped, so both tables are rebuilt:
-- copied aside, dropped, created again without it, copied back, with
-- their indexes and triggers, every seq kept. The foreign keys to them
-- (head_history, blobs, snapshots, e2e_snapshots) are deferred to the
-- commit, by which time the rows are back; their columns are indexed for
-- as long, so the drop and the copy back check them by index. This rewrites
-- the two largest tables, once.
PRAGMA defer_foreign_keys = ON;
CREATE INDEX tmp_head_history_ns_seq ON head_history (ns_seq);
CREATE INDEX tmp_head_history_target_seq ON head_history (target_seq);
CREATE INDEX tmp_blobs_ref_seq ON blobs (ref_seq);

CREATE TABLE tmp_revisions AS SELECT * FROM revisions;
DROP TABLE revisions;
CREATE TABLE revisions (
  seq        INTEGER PRIMARY KEY,
  res        INTEGER NOT NULL REFERENCES resources,
  id         BLOB    NOT NULL,
  parent_seq INTEGER,                        -- NULL for genesis; a row of another resource for a foreign parent
  first      INTEGER NOT NULL DEFAULT 0,
  kind       INTEGER NOT NULL,               -- 0 rev · 1 tombstone
  patches    TEXT,                           -- canonical JSON; NULL for tombstones, after purge, and below a horizon; a BLOB when encrypted at rest (crypt.go)
  author     INTEGER NOT NULL REFERENCES authors,
  via        TEXT,
  grant_id   BLOB,
  signature  TEXT,                           -- addition: optional author signature (§C.3)
  schema_ref TEXT,                           -- addition: $schema of the resulting document, if typed (§6.1 index)
  created    INTEGER NOT NULL,
  gesture    TEXT,                           -- §7.2, metadata, not hashed
  undoes     TEXT,
  size       INTEGER,                        -- addition: for a revision a write left as a head, its canonical document's length and sha-256 (headMeta, /heads); NULL otherwise, and in rows from before
  digest     BLOB,
  rules      INTEGER,
  grant_ref  INTEGER,
  UNIQUE (res, parent_seq)
);
INSERT INTO revisions (seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules, grant_ref)
  SELECT seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules, grant_ref FROM tmp_revisions;
DROP TABLE tmp_revisions;
CREATE UNIQUE INDEX one_first ON revisions (res) WHERE first = 1;
CREATE INDEX revisions_by_id ON revisions (id);  -- also finds draft schema revisions in branches (§6.1, D.2)
CREATE INDEX revisions_res_seq ON revisions (res, seq);
CREATE INDEX revisions_by_gesture ON revisions (gesture) WHERE gesture IS NOT NULL;
CREATE INDEX revisions_by_undoes ON revisions (undoes) WHERE undoes IS NOT NULL;
CREATE INDEX revisions_schema_ref ON revisions (schema_ref) WHERE schema_ref IS NOT NULL;
CREATE INDEX revisions_res_id8 ON revisions (res, substr(id, 1, 8));
CREATE TRIGGER revisions_id_unique BEFORE INSERT ON revisions
  WHEN EXISTS (SELECT 1 FROM revisions WHERE res = NEW.res AND substr(id, 1, 8) = substr(NEW.id, 1, 8) AND +id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'UNIQUE constraint failed: revisions.res, revisions.id');
END;
CREATE TRIGGER revisions_id_unique_update BEFORE UPDATE OF res, id ON revisions
  WHEN EXISTS (SELECT 1 FROM revisions WHERE res = NEW.res AND substr(id, 1, 8) = substr(NEW.id, 1, 8) AND +id = NEW.id AND seq <> NEW.seq)
BEGIN
  SELECT RAISE(ABORT, 'UNIQUE constraint failed: revisions.res, revisions.id');
END;

CREATE TABLE tmp_ns_log AS SELECT * FROM ns_log;
DROP TABLE ns_log;
CREATE TABLE ns_log (
  seq        INTEGER PRIMARY KEY,
  ns         INTEGER NOT NULL REFERENCES namespaces,
  id         BLOB    NOT NULL,
  prev_seq   INTEGER,
  kind       INTEGER NOT NULL,               -- 0 head · 1 tombstone · 2 purge · 3 config · 4 batch · 5 purge-ns · 6 branch · 7 prune
  res        INTEGER,                        -- addition: the resource of a single-resource entry
  target_seq INTEGER,
  body       TEXT    NOT NULL,               -- addition: canonical(entry) exactly as hashed (§3.5); '' when derived (entrybody.go)
  config_seq INTEGER NOT NULL,               -- addition: ns_config row in force after this entry
  author     INTEGER NOT NULL REFERENCES authors,
  created    INTEGER NOT NULL,
  grant_id   BLOB,                           -- §C.3; the root sub and kid are read from the stored grant (§7.4); NULL for entries the server writes itself and without authentication
  no_auth    INTEGER,                        -- 1: written on a request while authentication was disabled, served as "grant": null (§1, §7.4); NULL otherwise, and in rows from before v0.38
  gestures   TEXT,                           -- addition: canonical JSON of the entry's unhashed gesture members (§7.4): { gesture?, undoes? } of a single write, { gestures } of a batch; NULL for none
  via        TEXT,
  grant_ref  INTEGER,
  UNIQUE (ns, prev_seq)
);
INSERT INTO ns_log (seq, ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id, no_auth, gestures, via, grant_ref)
  SELECT seq, ns, id, prev_seq, kind, res, target_seq, body, config_seq, author, created, grant_id, no_auth, gestures, via, grant_ref FROM tmp_ns_log;
DROP TABLE tmp_ns_log;
CREATE UNIQUE INDEX one_ns_first ON ns_log (ns) WHERE prev_seq IS NULL;
CREATE INDEX ns_log_ns_seq ON ns_log (ns, seq);
CREATE INDEX ns_log_ns_id8 ON ns_log (ns, substr(id, 1, 8));
CREATE TRIGGER ns_log_first_grant AFTER INSERT ON ns_log WHEN NEW.grant_ref IS NOT NULL
BEGIN
  INSERT OR IGNORE INTO ns_grants (grant_ref, ns, first_seq) VALUES (NEW.grant_ref, NEW.ns, NEW.seq);
END;
CREATE TRIGGER ns_log_first_config AFTER INSERT ON ns_log
BEGIN
  UPDATE ns_config SET first_seq = NEW.seq WHERE seq = NEW.config_seq AND ns = NEW.ns AND first_seq IS NULL;
END;
CREATE TRIGGER ns_log_id_unique BEFORE INSERT ON ns_log
  WHEN EXISTS (SELECT 1 FROM ns_log WHERE ns = NEW.ns AND substr(id, 1, 8) = substr(NEW.id, 1, 8) AND +id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'UNIQUE constraint failed: ns_log.ns, ns_log.id');
END;
CREATE TRIGGER ns_log_id_unique_update BEFORE UPDATE OF ns, id ON ns_log
  WHEN EXISTS (SELECT 1 FROM ns_log WHERE ns = NEW.ns AND substr(id, 1, 8) = substr(NEW.id, 1, 8) AND +id = NEW.id AND seq <> NEW.seq)
BEGIN
  SELECT RAISE(ABORT, 'UNIQUE constraint failed: ns_log.ns, ns_log.id');
END;

DROP INDEX tmp_head_history_ns_seq;
DROP INDEX tmp_head_history_target_seq;
DROP INDEX tmp_blobs_ref_seq;
