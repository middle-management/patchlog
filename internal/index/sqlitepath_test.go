package index_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The index opens its database at exactly Options.DB, '#' and '?' in it
// and all, with the DSN's pragmas: "file:" + path cut the path at the '#'
// (t.TempDir of an unnamed subtest holds "#00"), so another file held the
// index.
func TestDBPathOpensThatFile(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "i#00?x.db")
	s := startSvc(t, w.c, svcOpts{db: path, ns: []string{"matches"}, untyped: true})
	head := s.caughtUp("matches")
	for q, want := range map[string]string{"journal_mode": "wal", "busy_timeout": "10000"} {
		if got := s.ix.Pragma(q); got != want {
			t.Errorf("PRAGMA %s = %q, want %q", q, got, want)
		}
	}
	s.stop()

	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
	for _, ent := range must(os.ReadDir(dir)) {
		if !strings.HasPrefix(ent.Name(), "i#00?x.db") {
			t.Errorf("stray file %q", ent.Name())
		}
	}
	s = startSvc(t, w.c, svcOpts{db: path, ns: []string{"matches"}, untyped: true, noRun: true})
	if got := s.ix.Checkpoint("matches"); got != head {
		t.Errorf("reopened: checkpoint %q, want %q", got, head)
	}
	if s.ix.CountRows("matches") == 0 {
		t.Error("reopened: no rows")
	}
}
