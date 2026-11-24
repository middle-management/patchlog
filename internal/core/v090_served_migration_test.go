package core

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// TestV090FilteredServedBackfill: a namespace that existed before
// filtered_served counts as one a view of which has been served, so a
// purge there still clears ns:{ns}, which cached filtered ranges carry
// (§8.3 CDN, v0.90). Which views were served before can't be told: the
// view records are swept, and bearer reads never wrote them.
func TestV090FilteredServedBackfill(t *testing.T) {
	path := pgtest.FreshDB(t)
	before := 31 // Postgres: 032_filtered_served
	if !pgtest.Enabled() {
		path = filepath.Join(t.TempDir(), "old.db")
		before = 29 // SQLite: 030_filtered_served
	}
	blobs := t.TempDir()
	opts := func() Options {
		return Options{Path: path, BlobDir: blobs, AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1, Purger: discardPurger{}}
	}
	o := opts()
	o.migrations = migrationsUpTo(t, before)
	old, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	mkNS(t, old, "early", map[string]any{})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := Open(opts())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mkNS(t, e, "late", map[string]any{})
	for ns, want := range map[string]bool{"early": true, "late": false} {
		q := `SELECT EXISTS (SELECT 1 FROM filtered_served WHERE ns = ?)`
		if e.pg {
			q = rebind(q)
		}
		var got bool
		if err := e.db.QueryRowContext(context.Background(), q, ns).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s in filtered_served: %v, want %v", ns, got, want)
		}
	}
}
