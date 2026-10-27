package index

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestV073P37EpochColumnUpgrade (ENC-32, IX-25): a database whose docs rows
// predate docs.epoch (migration 003_docs_epoch) is rebuilt if it follows a sealed or e2e namespace,
// whose hits are sealed under their heads' epochs (§E.2.6), and otherwise
// keeps its rows, the column added.
func TestV073P37EpochColumnUpgrade(t *testing.T) {
	for _, c := range []struct {
		level string
		kept  int
	}{{"sealed", 0}, {"e2e", 0}, {"at-rest", 1}, {"", 1}} {
		path := filepath.Join(t.TempDir(), "i.db")
		ix := openBare(t, path)
		for _, q := range []string{
			`ALTER TABLE docs DROP COLUMN epoch`,
			`DELETE FROM mmmigrate_applied WHERE namespace = 'index' AND name = 'docs_epoch'`,
			`INSERT INTO docs (ns, resource, head, schema) VALUES ('n', 'a', 'h', NULL)`,
			`INSERT INTO ns_conf (ns, public, level) VALUES ('n', 0, '` + c.level + `')`,
		} {
			if _, err := ix.db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		ix.db.Close()
		ix = openBare(t, path)
		var docs, col int
		if err := ix.db.QueryRow(`SELECT (SELECT count(*) FROM docs), (SELECT count(*) FROM pragma_table_info('docs') WHERE name = 'epoch')`).Scan(&docs, &col); err != nil {
			t.Fatal(err)
		}
		if docs != c.kept || col != 1 {
			t.Errorf("level %q: %d rows kept, epoch column %d (want %d rows, the column)", c.level, docs, col, c.kept)
		}
	}
}

// TestV073P37FiltersForgotten (IX-18): the read filters held in memory for
// scope markers are dropped once their last edge grant expires, as their
// edge_filters rows are, when filters are next recorded; one still in use
// is kept, and its expiry is the latest recorded.
func TestV073P37FiltersForgotten(t *testing.T) {
	ctx := context.Background()
	ix := openBare(t, filepath.Join(t.TempDir(), "i.db"))
	ix.filters = map[string]keptFilter{}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f := func() *readFilter { return &readFilter{principal: map[string]any{}} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(ix.recordFilters(ctx, map[string]*readFilter{"reads:a:scope:1": f(), "reads:a:scope:2": f()}, t0.Add(15*time.Minute), t0))
	must(ix.recordFilters(ctx, map[string]*readFilter{"reads:a:scope:2": f()}, t0.Add(25*time.Minute), t0.Add(10*time.Minute)))
	must(ix.recordFilters(ctx, map[string]*readFilter{"reads:a:scope:3": f()}, t0.Add(35*time.Minute), t0.Add(20*time.Minute)))
	if _, ok := ix.filters["reads:a:scope:1"]; ok || len(ix.filters) != 2 {
		t.Errorf("filters held after the first expired: %v", ix.filters)
	}
	if k := ix.filters["reads:a:scope:2"]; k.exp != t0.Add(25*time.Minute).Unix() {
		t.Errorf("scope 2 expires at %d, want the later edge grant's", k.exp)
	}
	var rows int
	must(ix.db.QueryRow(`SELECT count(*) FROM edge_filters`).Scan(&rows))
	if rows != 2 {
		t.Errorf("%d edge_filters rows, want 2", rows)
	}
}
