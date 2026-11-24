package core

import (
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
//
// Spanner's PostgreSQL interface, through PGAdapter (docs/SPANNER.md), is
// a third: the Postgres dialect (e.pg) with e.spanner set, for the
// statements Spanner refuses or runs otherwise, each branched where it is
// written (spanner.go has the shared helpers), and a schema of its own
// (migrations/spanner).

// spannerScheme prefixes a URL of a Spanner database's PostgreSQL
// interface (PGAdapter): it speaks the Postgres protocol, so nothing in
// the connection tells the two apart.
const spannerScheme = "spanner+postgres://"

// isPostgresURL reports whether a database path names a Postgres database,
// or a Spanner database through PGAdapter (isSpannerURL).
func isPostgresURL(path string) bool {
	return strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://") || isSpannerURL(path)
}

// isSpannerURL reports whether a database path names a Spanner database
// through PGAdapter: spanner+postgres://user@host:port/database.
func isSpannerURL(path string) bool { return strings.HasPrefix(path, spannerScheme) }

// pgxURL is a database URL as pgx takes it: a Spanner URL's scheme is
// postgres://.
func pgxURL(path string) string {
	if isSpannerURL(path) {
		return "postgres://" + strings.TrimPrefix(path, spannerScheme)
	}
	return path
}

// IsPostgres reports whether the engine stores in Postgres, or in Spanner
// through its PostgreSQL interface.
func (e *Engine) IsPostgres() bool { return e.pg }

// IsSpanner reports whether the engine stores in Spanner (docs/SPANNER.md).
func (e *Engine) IsSpanner() bool { return e.spanner }

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

// octetLength is the length in bytes of col: Spanner has no octet_length,
// and its length of a bytea counts bytes.
func (e *Engine) octetLength(col string) string {
	if e.spanner {
		return `length(` + col + `)`
	}
	return `octet_length(` + col + `)`
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
		if pe.Code == "23505" && pe.TableName == "" {
			// Spanner's, which names the index or the table in its
			// message alone (spanner.go); Postgres's name the table.
			return spannerConflict(pe)
		}
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
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
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
