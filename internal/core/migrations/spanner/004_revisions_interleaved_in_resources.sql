-- Migration: revisions interleaved in resources
-- Created: 2026-11-27T11:25:12Z
-- Checksum: 0ce39c2c148fd6e13c1bc2b0bc07818123434ea1fd3118540f6a6536911119b2
-- Chain: 18b37fda528961d13093cd1f705cab1f89f5032b067b6a9696fc046b39df4de3
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
-- Revisions interleaved in their resource's row, keyed (res, seq): a
-- write's check reads a resource, its head and the revision with an id
-- (revisions_res_id_key, interleaved too) together, and Spanner keeps a
-- row's interleaved children in its split, so the three are one server's
-- (docs/SPANNER.md, the eleventh run). A revision by its seq alone is
-- revisions_seq_key's. Spanner can't change a table's key: the table is
-- made anew and its rows copied, in one transaction (a database of more
-- than Spanner's mutations a commit needs it done by hand, in parts).
-- Resources rows are never deleted, so no revision loses its parent.
CREATE TABLE IF NOT EXISTS revisions_by_res (
  seq        bigint NOT NULL,
  res        bigint NOT NULL,
  id         bytea  NOT NULL CHECK (length(id) = 20),
  parent_seq bigint,
  first      bigint NOT NULL DEFAULT 0,
  kind       bigint NOT NULL,
  patches    bytea,
  author     bigint NOT NULL,
  via        text,
  grant_id   bytea,
  signature  text,
  schema_ref text,
  created    bigint NOT NULL,
  gesture    text,
  undoes     text,
  size       bigint,
  digest     bytea,
  rules      bigint,
  first_res  bigint GENERATED ALWAYS AS (CASE WHEN first = 1 THEN res END) STORED,
  PRIMARY KEY (res, seq)
) INTERLEAVE IN PARENT resources;

INSERT INTO revisions_by_res (seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules)
SELECT seq, res, id, parent_seq, first, kind, patches, author, via, grant_id, signature, schema_ref, created, gesture, undoes, size, digest, rules FROM revisions;

DROP INDEX IF EXISTS revisions_res_id_key;
DROP INDEX IF EXISTS revisions_res_parent_seq_key;
DROP INDEX IF EXISTS one_first;
DROP INDEX IF EXISTS revisions_by_id;
DROP INDEX IF EXISTS revisions_res_seq;
DROP INDEX IF EXISTS revisions_by_gesture;
DROP INDEX IF EXISTS revisions_by_undoes;
DROP INDEX IF EXISTS revisions_schema_ref;
DROP TABLE IF EXISTS revisions;
ALTER TABLE revisions_by_res RENAME TO revisions;
CREATE UNIQUE INDEX IF NOT EXISTS revisions_seq_key ON revisions (seq);
CREATE UNIQUE INDEX IF NOT EXISTS revisions_res_id_key ON revisions (res, id) INTERLEAVE IN resources;
CREATE UNIQUE INDEX IF NOT EXISTS revisions_res_parent_seq_key ON revisions (res, parent_seq) INTERLEAVE IN resources WHERE parent_seq IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS one_first ON revisions (first_res) WHERE first_res IS NOT NULL;
CREATE INDEX IF NOT EXISTS revisions_by_id ON revisions (id);
CREATE INDEX IF NOT EXISTS revisions_by_gesture ON revisions (gesture) WHERE gesture IS NOT NULL;
CREATE INDEX IF NOT EXISTS revisions_by_undoes ON revisions (undoes) WHERE undoes IS NOT NULL;
CREATE INDEX IF NOT EXISTS revisions_schema_ref ON revisions (schema_ref) WHERE schema_ref IS NOT NULL;
