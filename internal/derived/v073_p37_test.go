package derived

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// TestCacheDropV073P37 (wave-3 carry-over): Drop removes the stored views
// a predicate on view, scope and form picks, from memory and from the
// database with their tags, so a restart doesn't serve them again, and
// keeps the rest.
func TestCacheDropV073P37(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(filepath.Join(t.TempDir(), "c.db"), ""))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := NewCache(8, db)
	if err := c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		view string
		json bool
	}{{"/n/at/1", false}, {"/n/g/x/at/1", false}, {"/n/at/1?q=a", true}} {
		if _, err := c.Put(ctx, v.view, "n", "1", Stored{Body: []byte(v.view), JSON: v.json, Tags: "idx:n"}); err != nil {
			t.Fatal(err)
		}
	}
	whole := func(view, scope string, json bool) bool { return !json && strings.HasPrefix(view, "/"+scope+"/at/") }
	if err := c.Drop(ctx, whole); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Cache{c, NewCache(8, db)} {
		if _, ok := c.Get(ctx, "/n/at/1"); ok {
			t.Error("a dropped view is still stored")
		}
		for _, v := range []string{"/n/g/x/at/1", "/n/at/1?q=a"} {
			if _, ok := c.Get(ctx, v); !ok {
				t.Errorf("%s was dropped", v)
			}
		}
	}
	var tags int
	if err := db.QueryRow(`SELECT count(*) FROM sealed_view_tags WHERE view = '/n/at/1'`).Scan(&tags); err != nil || tags != 0 {
		t.Errorf("tags of a dropped view: %d %v", tags, err)
	}
}
