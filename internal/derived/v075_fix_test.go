package derived

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// openWAL opens a cache over a database in WAL mode, as the services'
// are: a read on another connection sees the rows an open transaction
// deletes until it commits.
func openWAL(t *testing.T) (*sql.DB, *Cache) {
	t.Helper()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(filepath.Join(t.TempDir(), "c.db"), "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := NewCache(0, db)
	if err := c.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db, c
}

// A view read from the database while a purge's transaction is open is
// the row as before the purge: it may be served then, but not remembered
// past the commit (Purged). Before, the in-memory front kept it, and a
// service whose at a backfill doesn't move (tree's backfillEpochs) served
// the purged listing from then on (TestV073P37EpochsBackfilled).
func TestV075CacheGetDuringPurge(t *testing.T) {
	ctx := context.Background()
	db, c := openWAL(t)
	const view = "/cat/g/all/at/1/children?of=old"
	if _, err := c.Put(ctx, view, "cat", "1", Stored{Body: []byte("old"), Tags: "ns:cat"}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := c.Purge(ctx, tx, []string{"ns:cat"}); err != nil {
		t.Fatal(err)
	}
	// Not committed yet: the database still has the row.
	if st, ok := c.Get(ctx, view); !ok || string(st.Body) != "old" {
		t.Fatalf("before the purge commits: %q %v", st.Body, ok)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	c.Purged([]string{"ns:cat"})
	if st, ok := c.Get(ctx, view); ok {
		t.Fatalf("a purged view is still served: %q", st.Body)
	}
	// It is stored again once computed after the purge.
	if _, err := c.PutSince(ctx, view, "cat", "1", c.Generation(), Stored{Body: []byte("new"), Tags: "ns:cat"}); err != nil {
		t.Fatal(err)
	}
	if st, ok := c.Get(ctx, view); !ok || string(st.Body) != "new" {
		t.Fatalf("after the purge: %q %v", st.Body, ok)
	}
}

// A view computed from what was read before a purge that carried one of
// its tags isn't stored after it, in memory or in the database, where the
// purge can't change the at (a backfill): it would be served unchanged.
// One whose tags the purges since didn't carry is stored.
func TestV075CachePutAfterPurge(t *testing.T) {
	ctx := context.Background()
	db, c := openWAL(t)
	gen := c.Generation()
	if err := c.Purge(ctx, db, []string{"ns:cat"}); err != nil {
		t.Fatal(err)
	}
	st, err := c.PutSince(ctx, "/cat/g/all/at/1", "cat", "1", gen, Stored{Body: []byte("stale"), Tags: "ns:cat,r:cat/old"})
	if err != nil || string(st.Body) != "stale" {
		t.Fatalf("served: %q %v", st.Body, err)
	}
	if st, ok := c.Get(ctx, "/cat/g/all/at/1"); ok {
		t.Fatalf("stored though read before a purge of its tags: %q", st.Body)
	}
	if _, err := c.PutSince(ctx, "/other/at/1", "other", "1", gen, Stored{Body: []byte("O"), Tags: "ns:other"}); err != nil {
		t.Fatal(err)
	}
	// A restart: only the database.
	c2 := NewCache(0, db)
	if st, ok := c2.Get(ctx, "/cat/g/all/at/1"); ok {
		t.Fatalf("persisted though read before a purge of its tags: %q", st.Body)
	}
	if st, ok := c2.Get(ctx, "/other/at/1"); !ok || string(st.Body) != "O" {
		t.Fatalf("a view the purge didn't touch: %q %v", st.Body, ok)
	}
	// More purges since than are recalled: taken to have touched it.
	gen = c.Generation()
	for range maxPurges + 1 {
		c.Purged([]string{"ns:x"})
	}
	if _, err := c.PutSince(ctx, "/n/at/1", "n", "1", gen, Stored{Body: []byte("N"), Tags: "ns:n"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(ctx, "/n/at/1"); ok {
		t.Fatal("stored though read before more purges than are recalled")
	}
}
