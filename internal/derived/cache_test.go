package derived

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// Stored views survive a new Cache on the same database (a restart), and
// go by tag (Purge) or when their scope's at moves on (Retire).
func TestCachePersists(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := NewCache(2, db)
	if err := c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	put := func(c *Cache, view, scope, at, tags, body string) Stored {
		st, err := c.Put(ctx, view, scope, at, Stored{Body: []byte(body), Tags: tags})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	put(c, "/n/at/1?q=a", "n", "1", "idx:n,r:n/a", "A")
	put(c, "/n/at/1?q=b", "n", "1", "idx:n,r:n/b", "B")
	put(c, "/m/at/1", "m", "1", "idx:m", "M")
	// First writer wins.
	if st := put(c, "/n/at/1?q=a", "n", "1", "idx:n", "other"); string(st.Body) != "A" {
		t.Fatalf("second put %q", st.Body)
	}

	// A restart: a new cache over the same database, beyond the memory
	// front (max 2).
	c2 := NewCache(2, db)
	if err := c2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for view, want := range map[string]string{"/n/at/1?q=a": "A", "/n/at/1?q=b": "B", "/m/at/1": "M"} {
		if st, ok := c2.Get(ctx, view); !ok || string(st.Body) != want || st.JSON {
			t.Fatalf("%s: %q %v", view, st.Body, ok)
		}
	}
	if st, _ := c2.Get(ctx, "/n/at/1?q=a"); st.Tags != "idx:n,r:n/a" {
		t.Fatalf("tags %q", st.Tags)
	}

	// Purge by tag, in memory and in the database.
	if err := c2.Purge(ctx, db, []string{"r:n/a"}); err != nil {
		t.Fatal(err)
	}
	for _, cc := range []*Cache{c2, NewCache(2, db)} {
		if _, ok := cc.Get(ctx, "/n/at/1?q=a"); ok {
			t.Fatal("purged view served")
		}
		if _, ok := cc.Get(ctx, "/n/at/1?q=b"); !ok {
			t.Fatal("other view purged")
		}
	}
	// Retire: n moved to at 2; m is untouched.
	if err := c2.Retire(ctx, db, "n", "2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := NewCache(2, db).Get(ctx, "/n/at/1?q=b"); ok {
		t.Fatal("retired view served")
	}
	if _, ok := NewCache(2, db).Get(ctx, "/m/at/1"); !ok {
		t.Fatal("view of another scope retired")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sealed_view_tags`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tag rows %d %v", n, err)
	}
}
