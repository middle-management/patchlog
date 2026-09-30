package core

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"

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
  patches    TEXT,                           -- canonical JSON; NULL for tombstones, after purge, and below a horizon; a BLOB when encrypted at rest (crypt.go)
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

-- Addition: data keys of encryption at rest (Addendum E.1), wrapped by the
-- key store named in keystore. res is a resources row, or 0 for the
-- deployment key of grants. Purge deletes a resource's key (crypt.go).
CREATE TABLE IF NOT EXISTS deks (
  res        INTEGER PRIMARY KEY,
  wrapped    BLOB    NOT NULL,
  keystore   TEXT    NOT NULL,
  created    INTEGER NOT NULL
);

-- Addition: epoch keys of sealed namespaces (Addendum E.2, sealed.go), 32
-- random bytes per (namespace, epoch), wrapped by the key store. created is
-- the epoch's start: the created time of the config write that began it.
CREATE TABLE IF NOT EXISTS epoch_keys (
  ns         INTEGER NOT NULL REFERENCES namespaces,
  epoch      INTEGER NOT NULL,
  wrapped    BLOB    NOT NULL,
  keystore   TEXT    NOT NULL,
  created    INTEGER NOT NULL,
  PRIMARY KEY (ns, epoch)
) WITHOUT ROWID;
-- Addition: the epoch in force when a revision or tombstone of a sealed
-- namespace was written (§E.2.1), keyed by revisions.seq.
CREATE TABLE IF NOT EXISTS rev_epochs (seq INTEGER PRIMARY KEY, epoch INTEGER NOT NULL);
-- Addition: sealed bytes, stored once and served forever (§E.2.2). ns is
-- the serving namespace (a branch seals read-through content under its own
-- keys); kind is doc, entry, config or range; key is name/id for doc and
-- entry, the ns_id for config and "since:id" for range. name and rev_seq
-- let purges and prunes find a resource's rows.
CREATE TABLE IF NOT EXISTS sealed (
  ns         INTEGER NOT NULL,
  kind       TEXT    NOT NULL,
  key        TEXT    NOT NULL,
  name       TEXT,
  rev_seq    INTEGER,
  jwe        TEXT    NOT NULL,
  created    INTEGER NOT NULL,
  PRIMARY KEY (ns, kind, key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS sealed_name ON sealed (ns, name);
CREATE INDEX IF NOT EXISTS sealed_rev ON sealed (rev_seq);

-- Addition: epochs of e2e namespaces (Addendum E.3, e2e.go). The server
-- holds no key for them: a row records only that epoch e of ns began with
-- the config write at created (the epoch range of POST /keys, and the kids
-- a sealed patch set may name).
CREATE TABLE IF NOT EXISTS e2e_epochs (
  ns         INTEGER NOT NULL REFERENCES namespaces,
  epoch      INTEGER NOT NULL,
  created    INTEGER NOT NULL,
  PRIMARY KEY (ns, epoch)
) WITHOUT ROWID;
-- Addition: client-supplied sealed snapshots of e2e resources (§8.6): the
-- horizon's document as a JWE, opaque to the server. seq is the horizon
-- revision.
CREATE TABLE IF NOT EXISTS e2e_snapshots (seq INTEGER PRIMARY KEY REFERENCES revisions, res INTEGER NOT NULL, jwe TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS e2e_snapshots_res ON e2e_snapshots (res, seq);

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
  kid        TEXT,                           -- addition: the key that signed the writer's root block (§F.3 merge.authors); NULL without a grant
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

-- Addition: remote branches registered with this deployment (§G.3, source
-- side). One row per (base namespace, remote); ns_seq is the latest remote
-- branch entry, prev_seq the one before it (idempotent retries).
CREATE TABLE IF NOT EXISTS remote_branches (
  ns         INTEGER NOT NULL REFERENCES namespaces,
  origin     TEXT    NOT NULL,
  name       TEXT    NOT NULL,
  at_seq     INTEGER NOT NULL,               -- ns_log.seq of at in ns
  ns_seq     INTEGER NOT NULL,               -- latest registration entry
  prev_seq   INTEGER,                        -- the registration entry before it
  expires    INTEGER NOT NULL,               -- unix ms
  PRIMARY KEY (ns, origin, name)
) WITHOUT ROWID;

-- Addition: remote branches of this deployment (§G.3, branch side). Each has
-- a hidden shadow namespace (named "~" + the branch's name, outside the
-- §3.6 grammar) holding the base's verified log and revisions up to at.
CREATE TABLE IF NOT EXISTS remote_bases (
  shadow      INTEGER PRIMARY KEY REFERENCES namespaces,
  branch      INTEGER NOT NULL UNIQUE REFERENCES namespaces,
  origin      TEXT    NOT NULL,
  ns          TEXT    NOT NULL,
  at          TEXT    NOT NULL,
  checkpoint  TEXT    NOT NULL,               -- last verified entry of the base's log followed
  reg_ns_id   TEXT,                           -- latest registration entry at the base, if registered
  reg_expires INTEGER                         -- its expiry (unix ms)
);

-- Addition: purges seen in a remote base's log (§G.3), applied or not.
CREATE TABLE IF NOT EXISTS remote_notices (
  seq       INTEGER PRIMARY KEY,
  branch    INTEGER NOT NULL REFERENCES namespaces,
  id        TEXT    NOT NULL,                 -- the base's ns_id of the entry
  kind      TEXT    NOT NULL,                 -- purge or purge-ns
  resource  TEXT,
  applied   INTEGER NOT NULL,
  created   INTEGER NOT NULL,
  UNIQUE (branch, id)
);
`

// openDB opens the database. secure_delete zeroes deleted and overwritten
// content, so a purge (and turning encryption at rest on, which rewrites
// rows) leaves no plaintext in free pages once the WAL is checkpointed.
func openDB(path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)&_txlock=immediate"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(ON)&_pragma=secure_delete(ON)&_txlock=immediate"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		// One connection keeps the in-memory database alive and shared.
		db.SetMaxOpenConns(1)
	} else {
		// Keep connections open: a new SQLite connection parses the whole
		// schema and loses its prepared statements, and database/sql keeps
		// only two idle ones by default, so under concurrent reads most of
		// the time went to reopening connections.
		n := 4 * runtime.GOMAXPROCS(0)
		db.SetMaxOpenConns(n)
		db.SetMaxIdleConns(n)
	}
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	return db, nil
}

// migrate adds columns that databases created by earlier versions lack.
func migrate(db *sql.DB) error {
	ctx := context.Background()
	var has bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pragma_table_info('ns_log') WHERE name = 'kid')`).Scan(&has); err != nil {
		return err
	}
	if !has {
		if _, err := db.ExecContext(ctx, `ALTER TABLE ns_log ADD COLUMN kid TEXT`); err != nil {
			return err
		}
	}
	return nil
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
