package core

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The storage dialect: SQLite (the default, Addendum D.2) or Postgres
// (Addendum D.8). Queries are written once, in the subset both accept,
// with ? placeholders; on Postgres the tx wrapper (stmts.go) rewrites them
// to $1..$n. What differs:
//
//   - the schema (migrations/sqlite and migrations/postgres). The tables,
//     columns and constraints are the same, so every query runs on both;
//     the types differ. On Postgres integer keys are bigint identities,
//     flags and small codes smallint (not boolean: queries compare them
//     with 0 and 1 on both dialects); hashes are bytea, checked to be 20
//     bytes; canonical JSON is text, never jsonb, which would reorder keys
//     and normalise numbers: ids are served and re-hashed from exactly the
//     stored bytes (§3.1). The columns that hold an encrypted row when
//     encryption at rest is on (crypt.go: revisions.patches, heads.doc,
//     snapshots.doc, grants.blocks) are bytea, which keeps the plaintext's
//     bytes just as exactly. Timestamps stay integer Unix milliseconds, as
//     in SQLite. Patch sets stay in revisions rather than in a table of
//     their own (D.8 "content apart from the skeleton"): purge and pruning
//     set them to NULL, and vacuum reclaims the space;
//   - placeholders, and bool arguments, which Postgres won't coerce into
//     the smallint flag columns the two schemas share;
//   - values that are canonical JSON or, encrypted at rest, binary
//     (revisions.patches, heads.doc, snapshots.doc, grants.blocks): TEXT
//     or BLOB in SQLite's dynamic typing, bytea on Postgres (blobArg). A
//     compressed patch set (SQLite only, compress.go) is a BLOB;
//   - array arguments, which SQLite reads as JSON (inArray);
//   - constraint violations (isConflict);
//   - transactions and write serialisation (engine.go).

// isPostgresURL reports whether a database path names a Postgres database.
func isPostgresURL(path string) bool {
	return strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://")
}

// IsPostgres reports whether the engine stores in Postgres.
func (e *Engine) IsPostgres() bool { return e.pg }

// rebinds caches rewritten query texts: queries are constant strings,
// except a few built with a variable number of placeholders.
var rebinds sync.Map // string -> string

// rebind rewrites ? placeholders outside quoted literals to $1..$n.
func rebind(q string) string {
	if v, ok := rebinds.Load(q); ok {
		return v.(string)
	}
	var b strings.Builder
	b.Grow(len(q) + 16)
	n := 0
	var quote byte
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	s := b.String()
	rebinds.Store(q, s)
	return s
}

// Entry and revision ids are found by their first 8 bytes (docs/capacity/
// storage/README.md, "The memory cliff"): ns_log and revisions are indexed
// on (ns, idKey(id)) and (res, idKey(id)), not on the whole 20-byte id,
// and a lookup compares the whole id on the rows the index finds, so ids
// sharing a prefix in one namespace or resource are told apart. A trigger
// of each table (migration 036 on Postgres, 034 on SQLite) keeps the whole
// id unique in its namespace or resource, through the same index, as the
// unique constraints it replaced did. The key is an expression index, so
// it costs no column and no insert sets it: on Postgres a bigint (the
// bytes big-endian, two's complement), 24 bytes an index entry where (ns,
// id) took 40; in SQLite the 8 bytes as a BLOB.

// idKeySQL is the indexed key of the id column col.
func idKeySQL(pg bool, col string) string {
	if pg {
		return `('x' || encode(substr(` + col + `, 1, 8), 'hex'))::bit(64)::bigint`
	}
	return `substr(` + col + `, 1, 8)`
}

// idKeyArg is idKeySQL's value for id: nil for a nil id.
func idKeyArg(pg bool, id []byte) any {
	if id == nil {
		return nil
	}
	if pg {
		return int64(binary.BigEndian.Uint64(id[:8]))
	}
	return id[:8]
}

// idIs is the condition that the id column col is the argument, by its
// key and then whole: it takes the arguments idArgs returns, in order.
func (e *Engine) idIs(col string) string { return idIsSQL(e.pg, col) }

// In SQLite the whole id is compared as +col, which no index answers: with
// statistics the planner would rather take revisions_by_id (id), as
// selective but over every resource's revisions, so a write's retry lookup
// would read a page of it where the key index's page is the one the write
// then inserts into.
func idIsSQL(pg bool, col string) string {
	if pg {
		return idKeySQL(pg, col) + ` = ? AND ` + col + ` = ?`
	}
	return idKeySQL(pg, col) + ` = ? AND +` + col + ` = ?`
}

// idArgs are idIs's arguments for id.
func (e *Engine) idArgs(id []byte) (any, any) { return idKeyArg(e.pg, id), nilBytes(id) }

// nilBytes is b, or an untyped nil for a nil b (a NULL argument).
func nilBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// pgArgs converts arguments Postgres won't take as they are: bools go into
// smallint columns as 0 or 1.
func pgArgs(args []any) []any {
	copied := false
	for i, a := range args {
		if v, ok := a.(bool); ok {
			if !copied { // the caller's slice stays as it was
				args, copied = append([]any(nil), args...), true
			}
			if v {
				args[i] = int64(1)
			} else {
				args[i] = int64(0)
			}
		}
	}
	return args
}

// blobArg is the argument for a column holding canonical JSON or an
// encrypted row: the text itself in SQLite (stored as TEXT, as before),
// bytes on Postgres, whose bytea would parse a string as escaped input.
func (e *Engine) blobArg(b []byte) any {
	if e.pg {
		return b
	}
	return string(b)
}

// inArray is the condition that col is an element of an array argument
// (arrayArg) of the Postgres type typ. SQLite has no arrays: there the
// argument is a JSON array, whose elements json_each reads, so one query
// text (stmtCache) takes any number of them, unbounded by SQLite's limit
// on variables.
func (e *Engine) inArray(col, typ string) string {
	if e.pg {
		return col + ` = ANY(?::` + typ + `[])`
	}
	return col + ` IN (SELECT value FROM json_each(?))`
}

// arrayArg is the argument for inArray: the slice itself on Postgres, its
// JSON text in SQLite. Integers and resource names (ValidResourceName)
// come back out of JSON as they went in.
func (e *Engine) arrayArg(v any) any {
	if e.pg {
		return v
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // slices of ints or strings
	}
	return string(b)
}

// conflictTables are the tables whose UNIQUE violations mean a concurrent
// writer won the race of a resource chain or a namespace chain (D.3).
var conflictTables = []string{"revisions", "resources", "ns_log", "head_history", "heads"}

// errChainRace rolls back a write that found its resource's head moved
// since its precondition was checked (insertItem): on Postgres, writers of
// one namespace insert concurrently, and a resource chain's race is caught
// by its unique constraints or by this check (pglock.go).
var errChainRace = errors.New("a concurrent write moved the resource's head")

// isConflict reports a UNIQUE violation of a resource chain or a namespace
// chain, or errChainRace: a concurrent writer won the race (D.3). On SQLite
// the re-check under the write lock makes it unreachable, and it remains
// the final safety net; on Postgres it is how two writers of one resource
// that checked concurrently learn which one won (pglock.go).
func isConflict(err error) bool {
	if errors.Is(err, errChainRace) {
		return true
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		if pe.Code != "23505" { // unique_violation
			return false
		}
		for _, t := range conflictTables {
			if pe.TableName == t {
				return true
			}
		}
		return false
	}
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	// SQLITE_CONSTRAINT_TRIGGER: the triggers keeping ids unique in a
	// namespace and a resource (idKeySQL) raise the message the unique
	// constraints they replaced did.
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY, sqlite3.SQLITE_CONSTRAINT_TRIGGER:
	default:
		return false
	}
	msg := se.Error()
	for _, c := range []string{"revisions.res", "resources.ns", "ns_log.ns", "head_history.res", "heads.res"} {
		if strings.Contains(msg, c) {
			return true
		}
	}
	return false
}
