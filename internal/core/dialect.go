package core

import (
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
//   - the schema (db.go schemaSQL and pgschema.go schemaPG);
//   - placeholders, and bool arguments, which Postgres won't coerce into
//     the smallint flag columns the two schemas share;
//   - values that are canonical JSON or, encrypted at rest, binary
//     (revisions.patches, heads.doc, snapshots.doc, grants.blocks): TEXT
//     or BLOB in SQLite's dynamic typing, bytea on Postgres (blobArg);
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

// conflictTables are the tables whose UNIQUE violations mean a concurrent
// writer won the race of a resource chain or a namespace chain (D.3).
var conflictTables = []string{"revisions", "resources", "ns_log", "head_history", "heads"}

// isConflict reports a UNIQUE violation of a resource chain or a namespace
// chain: a concurrent writer won the race (D.3). Within one deployment the
// re-check under the write lock makes it unreachable; it remains the final
// safety net.
func isConflict(err error) bool {
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
