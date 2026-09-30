package core

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// schemaSQL is the storage layout of Addendum D.2, with a few additions noted
// inline. Every hash is a 20-byte BLOB; rows reference each other by integer.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS namespaces (
  ns         INTEGER PRIMARY KEY,
  name       TEXT    NOT NULL UNIQUE,
  base       INTEGER REFERENCES namespaces,  -- NULL unless a branch
  base_at    INTEGER,                        -- ns_log.seq of ` + "`at`" + ` in the base
  base_config_seq INTEGER,                   -- addition: base's ns_config row copied at creation (§C.4)
  frozen     INTEGER NOT NULL DEFAULT 0,
  purged     INTEGER NOT NULL DEFAULT 0,
  head_seq   INTEGER,                        -- addition: current ns_log head
  config_seq INTEGER                         -- addition: current ns_config head
);
CREATE TABLE IF NOT EXISTS authors (author INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);

CREATE TABLE IF NOT EXISTS resources (
  res         INTEGER PRIMARY KEY,
  ns          INTEGER NOT NULL REFERENCES namespaces,
  name        TEXT    NOT NULL,
  head_seq    INTEGER,                       -- current head entry (revision or tombstone)
  state       INTEGER NOT NULL DEFAULT 0,    -- 0 live · 1 tombstoned · 2 purged
  horizon_seq INTEGER,                       -- §8.6; NULL if never pruned
  keep        TEXT,                          -- addition: canonical JSON array of kept ids (§8.6)
  UNIQUE (ns, name)
);

CREATE TABLE IF NOT EXISTS revisions (
  seq        INTEGER PRIMARY KEY,
  res        INTEGER NOT NULL REFERENCES resources,
  id         BLOB    NOT NULL,
  parent_seq INTEGER,                        -- NULL for genesis; a row of another resource for a foreign parent
  first      INTEGER NOT NULL DEFAULT 0,
  kind       INTEGER NOT NULL,               -- 0 rev · 1 tombstone
  patches    TEXT,                           -- canonical JSON; NULL for tombstones, after purge, and below a horizon
  author     INTEGER NOT NULL REFERENCES authors,
  via        TEXT,
  grant_id   BLOB,
  signature  TEXT,                           -- addition: optional author signature (§C.3)
  schema_ref TEXT,                           -- addition: $schema of the resulting document, if typed (§6.1 index)
  created    INTEGER NOT NULL,
  UNIQUE (res, id),
  UNIQUE (res, parent_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_first ON revisions (res) WHERE first = 1;
CREATE INDEX IF NOT EXISTS revisions_id ON revisions (id);
CREATE INDEX IF NOT EXISTS revisions_res_seq ON revisions (res, seq);

CREATE TABLE IF NOT EXISTS grants (id BLOB PRIMARY KEY, blocks TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS heads (res INTEGER PRIMARY KEY REFERENCES resources, seq INTEGER NOT NULL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS heads_seq ON heads (seq);
-- Intermediate snapshots (D.4) and documents kept below a horizon (§8.6).
CREATE TABLE IF NOT EXISTS snapshots (seq INTEGER PRIMARY KEY REFERENCES revisions, res INTEGER NOT NULL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS snapshots_res ON snapshots (res, seq);

-- Addition: pruning archives (§8.6). from_seq and to_seq are the first and
-- last archived revisions of res; key is the archive's name (Archiver).
CREATE TABLE IF NOT EXISTS archives (
  seq        INTEGER PRIMARY KEY,
  res        INTEGER NOT NULL REFERENCES resources,
  from_seq   INTEGER NOT NULL,
  to_seq     INTEGER NOT NULL,
  key        TEXT    NOT NULL,
  url        TEXT    NOT NULL,
  created    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS archives_res ON archives (res, from_seq);

CREATE TABLE IF NOT EXISTS ns_log (
  seq        INTEGER PRIMARY KEY,
  ns         INTEGER NOT NULL REFERENCES namespaces,
  id         BLOB    NOT NULL,
  prev_seq   INTEGER,
  kind       INTEGER NOT NULL,               -- 0 head · 1 tombstone · 2 purge · 3 config · 4 batch · 5 purge-ns · 6 branch · 7 prune
  res        INTEGER,                        -- addition: the resource of a single-resource entry
  target_seq INTEGER,
  body       TEXT    NOT NULL,               -- addition: canonical(entry) exactly as hashed (§3.5)
  config_seq INTEGER NOT NULL,               -- addition: ns_config row in force after this entry
  author     INTEGER NOT NULL REFERENCES authors,
  created    INTEGER NOT NULL,
  UNIQUE (ns, id),
  UNIQUE (ns, prev_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_ns_first ON ns_log (ns) WHERE prev_seq IS NULL;

CREATE TABLE IF NOT EXISTS head_history (
  res        INTEGER NOT NULL REFERENCES resources,
  ns_seq     INTEGER NOT NULL REFERENCES ns_log,
  target_seq INTEGER NOT NULL REFERENCES revisions,
  PRIMARY KEY (res, ns_seq)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ns_config (
  seq        INTEGER PRIMARY KEY,
  ns         INTEGER NOT NULL REFERENCES namespaces,
  id         BLOB    NOT NULL,
  parent_seq INTEGER,
  patches    TEXT    NOT NULL,
  doc        TEXT    NOT NULL,               -- addition: the resulting namespace document
  author     INTEGER NOT NULL REFERENCES authors,
  created    INTEGER NOT NULL,
  UNIQUE (ns, id),
  UNIQUE (ns, parent_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_config_genesis ON ns_config (ns) WHERE parent_seq IS NULL;
`

func openDB(path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(ON)&_txlock=immediate"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		// One connection keeps the in-memory database alive and shared.
		db.SetMaxOpenConns(1)
	}
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return db, nil
}

// Entry kinds, as stored.
const (
	kindRev       = 0
	kindTombstone = 1
)

const (
	stateLive       = 0
	stateTombstoned = 1
	statePurged     = 2
)

var nsKindNames = []string{"head", "tombstone", "purge", "config", "batch", "purge-ns", "branch", "prune"}

func nsKindCode(k string) int {
	for i, n := range nsKindNames {
		if n == k {
			return i
		}
	}
	panic("unknown ns kind " + k)
}
