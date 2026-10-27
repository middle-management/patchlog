package index

import (
	"path/filepath"
	"testing"
)

// TestV073P37EpochColumnUpgrade (ENC-32, IX-25): a database whose docs rows
// predate docs.epoch is rebuilt if it follows a sealed or e2e namespace,
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
