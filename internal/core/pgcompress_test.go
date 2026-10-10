package core

import (
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// On Postgres the large columns are compressed with lz4 where the server
// has it, not pglz, its default (pgschema.go): set when a database is
// created, and on one created before, when it is opened again.
func TestPGColumnCompression(t *testing.T) {
	if !pgtest.Enabled() {
		t.Skip("Postgres only")
	}
	t.Parallel()
	path := pgtest.FreshDB(t)
	open := func() *Engine {
		e, err := Open(Options{Path: path, BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
			Purger: discardPurger{}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := open()
	var lz4 bool
	if err := e.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_settings WHERE name = 'default_toast_compression' AND 'lz4' = ANY (enumvals))`).Scan(&lz4); err != nil {
		t.Fatal(err)
	}
	if !lz4 {
		e.Close()
		t.Skip("the server has no lz4")
	}
	compression := func(e *Engine) map[string]string {
		t.Helper()
		rows, err := e.db.Query(`SELECT attrelid::regclass::text || '.' || attname, attcompression::text FROM pg_attribute
			WHERE (attrelid::regclass::text, attname::text) IN (('revisions', 'patches'), ('heads', 'doc'), ('snapshots', 'doc'), ('ns_log', 'body'), ('blob_bytes', 'data'))`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var col, c string
			if err := rows.Scan(&col, &c); err != nil {
				t.Fatal(err)
			}
			out[col] = c
		}
		return out
	}
	want := func(e *Engine, c string) {
		t.Helper()
		got := compression(e)
		if len(got) != 5 {
			t.Fatalf("columns %v", got)
		}
		for col, have := range got {
			if have != c {
				t.Fatalf("%s compression %q, want %q (%v)", col, have, c, got)
			}
		}
	}
	want(e, "l")
	// A database from before: its columns on the default, set when opened.
	if _, err := e.db.Exec(`ALTER TABLE revisions ALTER COLUMN patches SET COMPRESSION default;
		ALTER TABLE heads ALTER COLUMN doc SET COMPRESSION default`); err != nil {
		t.Fatal(err)
	}
	e.Close()
	e = open()
	defer e.Close()
	want(e, "l")
}
