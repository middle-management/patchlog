package derived

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/middle-management/patchlog/internal/dbmigrate"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// KEYS-8 (SERVICES §E.2.6 View keys; v0.81): views a v0.26.1 service
// stored were sealed under K_e or K_r, not under view keys, so derived
// migration 002 deletes them and they are sealed again on demand. A cache
// database migrated as v0.26.1 left it (001 only) and holding a view is
// opened by Init: Get misses, and a view stored since is kept.
func TestV081CacheDropsStoredViews(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(filepath.Join(t.TempDir(), "c.db"), ""))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := fstest.MapFS{}
	ents, err := fs.ReadDir(migrations, "migrations/sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "001_") {
			b, err := fs.ReadFile(migrations, "migrations/sqlite/"+e.Name())
			if err != nil {
				t.Fatal(err)
			}
			old["migrations/sqlite/"+e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	if len(old) != 1 {
		t.Fatalf("migration 001 not found: %v", old)
	}
	if err := dbmigrate.Migrate(ctx, db, old, "derived"); err != nil {
		t.Fatal(err)
	}
	const view = "/cat/at/1abc/children"
	if _, err := db.ExecContext(ctx, `INSERT INTO sealed_views (view, scope, at, body, json, tags) VALUES (?, 'cat', '1abc', ?, 0, 'ns:cat')`, view, []byte("eyJ…K_e-sealed")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sealed_view_tags (tag, view) VALUES ('ns:cat', ?)`, view); err != nil {
		t.Fatal(err)
	}

	c := NewCache(4, db)
	if err := c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if st, ok := c.Get(ctx, view); ok {
		t.Fatalf("a view stored by v0.26.1 served after the upgrade: %q", st.Body)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_view_tags`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d tag rows left (%v)", n, err)
	}
	if _, err := c.Put(ctx, view, "cat", "1abc", Stored{Body: []byte("new"), Tags: "ns:cat"}); err != nil {
		t.Fatal(err)
	}
	// A restart runs no migration again: the new view stays.
	c2 := NewCache(4, db)
	if err := c2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if st, ok := c2.Get(ctx, view); !ok || string(st.Body) != "new" {
		t.Fatalf("a view stored since the upgrade: %q %v", st.Body, ok)
	}
}
