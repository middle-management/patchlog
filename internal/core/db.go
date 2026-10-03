package core

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"

	"github.com/middle-management/patchlog/internal/grant"
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
  config_seq INTEGER,                        -- addition: current ns_config head
  head_id    BLOB                            -- addition: the id of head_seq (NULL: look it up, e.g. a shadow's)
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
  snap_revs   INTEGER,                       -- addition: revisions since the last intermediate snapshot (D.4); NULL: count them
  snap_bytes  INTEGER,                       -- addition: their stored patch sets' bytes
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
  gesture    TEXT,                           -- §7.2, metadata, not hashed; its partial index is created after migrate (gestureIndexes)
  undoes     TEXT,
  UNIQUE (res, id),
  UNIQUE (res, parent_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_first ON revisions (res) WHERE first = 1;
CREATE INDEX IF NOT EXISTS revisions_by_id ON revisions (id);  -- also finds draft schema revisions in branches (§6.1, D.2)
DROP INDEX IF EXISTS revisions_id;
CREATE INDEX IF NOT EXISTS revisions_res_seq ON revisions (res, seq);

-- root_sub and root_kid: the root block's sub and kid, in plaintext even
-- when blocks is encrypted (crypt.go), for the grant references namespace
-- entries serve (§7.4, grantref.go). Neither is secret: the log serves both.
CREATE TABLE IF NOT EXISTS grants (id BLOB PRIMARY KEY, blocks TEXT NOT NULL, root_sub TEXT, root_kid TEXT);

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
  grant_id   BLOB,                           -- §C.3; the root sub and kid are read from the stored grant (§7.4); NULL for entries the server writes itself and without authentication
  no_auth    INTEGER,                        -- 1: written on a request while authentication was disabled, served as "grant": null (§1, §7.4); NULL otherwise, and in rows from before v0.38
  gestures   TEXT,                           -- addition: canonical JSON of the entry's unhashed gesture members (§7.4): { gesture?, undoes? } of a single write, { gestures } of a batch; NULL for none
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

-- Blobs (§7.8, D.2). Attachments: one row per resource and blob, pruned
-- once pruning ended it (410). owner is an addition: the blob_bytes row
-- holding the bytes (0 for plaintext shared by every resource, else the
-- resource whose data key encrypts them, blobs.go).
CREATE TABLE IF NOT EXISTS blobs (
  res      INTEGER NOT NULL REFERENCES resources,
  bid      BLOB    NOT NULL,
  type     TEXT    NOT NULL,
  nonce    TEXT,
  size     INTEGER NOT NULL,
  hash     BLOB    NOT NULL,                -- sha256 of the bytes
  owner    INTEGER NOT NULL,
  created  INTEGER NOT NULL,
  ref_seq  INTEGER NOT NULL REFERENCES revisions,  -- first revision here that references it
  pruned   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (res, bid)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blobs_bytes ON blobs (owner, hash);
-- One row per resource, blob and uploader (root sub and kid, §7.8).
CREATE TABLE IF NOT EXISTS blob_pending (
  res      INTEGER NOT NULL REFERENCES resources,
  bid      BLOB    NOT NULL,
  uploader TEXT    NOT NULL,
  type     TEXT    NOT NULL,
  nonce    TEXT,
  size     INTEGER NOT NULL,
  hash     BLOB    NOT NULL,
  owner    INTEGER NOT NULL,
  created  INTEGER NOT NULL,
  PRIMARY KEY (res, bid, uploader)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_pending_bytes ON blob_pending (owner, hash);
CREATE INDEX IF NOT EXISTS blob_pending_created ON blob_pending (created);
-- Addition: which revisions reference which blob (§5), as intervals of the
-- resource's chain: the documents at revisions from_seq up to (excluding)
-- to_seq reference bid; to_seq is NULL while the head's document does.
CREATE TABLE IF NOT EXISTS blob_refs (
  res      INTEGER NOT NULL REFERENCES resources,
  bid      BLOB    NOT NULL,
  from_seq INTEGER NOT NULL,
  to_seq   INTEGER,
  PRIMARY KEY (res, bid, from_seq)
) WITHOUT ROWID;
-- Addition: blob bytes, by owner and sha256. Encrypted under the owner's
-- data key when owner is a resource. The bytes are in the file under the
-- blob directory that file names (D.2 keeps them outside the database), data
-- then empty, or with no file in data (blobstore.go).
CREATE TABLE IF NOT EXISTS blob_bytes (
  owner    INTEGER NOT NULL,
  hash     BLOB    NOT NULL,
  data     BLOB    NOT NULL,
  file     TEXT,
  UNIQUE (owner, hash)
);
-- The sealed form of a blob per epoch it is served under (§E.2.2, D.2's
-- blob_epochs), stored once and served forever. Keyed like sealed: ns is
-- the serving namespace (a branch seals read-through blobs under its own
-- keys) and name the resource. The sealing is in data, or in the file file
-- names (blobstore.go); both are NULL once pruning removed every revision of
-- the epoch that references the blob (410).
CREATE TABLE IF NOT EXISTS blob_epochs (
  ns       INTEGER NOT NULL,
  name     TEXT    NOT NULL,
  bid      BLOB    NOT NULL,
  epoch    INTEGER NOT NULL,
  data     BLOB,
  file     TEXT,
  created  INTEGER NOT NULL,
  PRIMARY KEY (ns, name, bid, epoch)
) WITHOUT ROWID;

-- Addition: second CDN purges (D.8, repurge.go). Each CDN tag purge is
-- queued in the transaction that commits it, keyed on its namespace entry
-- (ns_seq; NULL for a restore from an archive, which has none), and sent
-- again by the leader once due. The row is the job's durable progress: it
-- is deleted once sent.
CREATE TABLE IF NOT EXISTS cdn_repurge (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ns_seq   INTEGER UNIQUE,
  tags     TEXT    NOT NULL,                -- JSON array of tags
  due      INTEGER NOT NULL                 -- unix ms
);
CREATE INDEX IF NOT EXISTS cdn_repurge_due ON cdn_repurge (due);

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

// openDB opens the database: a Postgres URL (pgschema.go), or a SQLite
// file or ":memory:".
//
// In SQLite, secure_delete zeroes deleted and overwritten content, so a
// purge (and turning encryption at rest on, which rewrites rows) leaves no
// plaintext in free pages once the WAL is checkpointed. Postgres has no
// equivalent: deleted and overwritten tuples stay in the table's files
// until VACUUM reclaims them (and in WAL and backups until those expire).
func openDB(path string) (db *sql.DB, pg bool, err error) {
	if isPostgresURL(path) {
		db, err := openPG(path)
		return db, true, err
	}
	db, err = openSQLite(path)
	return db, false, err
}

func openSQLite(path string) (*sql.DB, error) {
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

// migrate adds columns that databases created by earlier versions lack,
// running a column's then statement (or function) once, right after adding
// it, in the same transaction: a migration stopped half-way leaves neither.
func migrate(db *sql.DB) error {
	ctx := context.Background()
	for _, c := range []struct {
		table, col, typ, then string
		thenGo                func(context.Context, *sql.Tx) error
	}{
		{"ns_log", "grant_id", "BLOB", backfillNSGrants, nil}, {"ns_log", "no_auth", "INTEGER", "", nil}, {"grants", "root_sub", "TEXT", "", nil},
		{"grants", "root_kid", "TEXT", "", backfillGrantRoots(func(int) string { return "?" })},
		{"blob_bytes", "file", "TEXT", "", nil}, {"blob_epochs", "file", "TEXT", "", nil},
		{"namespaces", "head_id", "BLOB", "", nil}, {"resources", "snap_revs", "INTEGER", "", nil}, {"resources", "snap_bytes", "INTEGER", "", nil},
		{"revisions", "gesture", "TEXT", "", nil}, {"revisions", "undoes", "TEXT", "", nil}, {"ns_log", "gestures", "TEXT", "", nil}} {
		var has bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pragma_table_info(?) WHERE name = ?)`, c.table, c.col).Scan(&has); err != nil {
			return err
		}
		if has {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+c.table+` ADD COLUMN `+c.col+` `+c.typ); err != nil {
			tx.Rollback()
			return err
		}
		if c.then != "" {
			if _, err := tx.ExecContext(ctx, c.then); err != nil {
				tx.Rollback()
				return err
			}
		}
		if c.thenGo != nil {
			if err := c.thenGo(ctx, tx); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	// After the columns exist, in databases from before them too.
	_, err := db.ExecContext(ctx, gestureIndexes)
	return err
}

// gestureIndexes find the revisions of a gesture, and those undoing it
// (§7.4, D.2): partial, since most revisions have neither.
const gestureIndexes = `
CREATE INDEX IF NOT EXISTS revisions_by_gesture ON revisions (gesture) WHERE gesture IS NOT NULL;
CREATE INDEX IF NOT EXISTS revisions_by_undoes ON revisions (undoes) WHERE undoes IS NOT NULL;
`

// backfillGrantRoots fills grants.root_sub and root_kid of a database from
// before them, for the grants stored in plaintext. Those stored encrypted
// keep NULL, and grantRef reads them by decrypting, as before (§7.4, E.1).
// ph is the dialect's placeholder for the n-th argument.
func backfillGrantRoots(ph func(n int) string) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, blocks FROM grants WHERE root_sub IS NULL`)
		if err != nil {
			return err
		}
		type root struct {
			id       []byte
			sub, kid string
		}
		var roots []root
		for rows.Next() {
			var id, blocks []byte
			if err := rows.Scan(&id, &blocks); err != nil {
				rows.Close()
				return err
			}
			if isSealed(string(blocks)) {
				continue
			}
			if g, err := grant.ParseStored(blocks); err == nil && len(g.Blocks) > 0 {
				roots = append(roots, root{id, g.Blocks[0].Sub, g.Blocks[0].Kid})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range roots {
			if _, err := tx.ExecContext(ctx, `UPDATE grants SET root_sub = `+ph(1)+`, root_kid = `+ph(2)+` WHERE id = `+ph(3), r.sub, r.kid, r.id); err != nil {
				return err
			}
		}
		return nil
	}
}

// backfillNSGrants gives the namespace entries of a database from before
// grant references (§5, §7.4) the grant they were written under, where the
// revisions they record still say it: a head, tombstone or batch entry
// written on a request moved heads to revisions that all store the
// request's grant (§C.3), and those the server wrote itself (mirrored
// schemas, §G.3) moved them to revisions without one. Earlier versions
// recorded only the root kid, in a column ns_log.kid that such databases
// keep but nothing reads: other entries (config, branch, purge, purge-ns,
// prune) serve no grant.
const backfillNSGrants = `UPDATE ns_log SET grant_id = g.grant_id
FROM (SELECT h.ns_seq AS seq, MAX(r.grant_id) AS grant_id FROM head_history h JOIN revisions r ON r.seq = h.target_seq
      WHERE r.grant_id IS NOT NULL GROUP BY h.ns_seq) AS g
WHERE g.seq = ns_log.seq AND ns_log.kind IN (0, 1, 4)`

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
