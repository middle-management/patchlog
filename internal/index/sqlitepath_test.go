package index_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/index"
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

// An index that an earlier release kept at the path cut at its '?' (or
// '#', or with its %XX decoded) is refused, not replayed into a new
// database at the full path.
func TestDBLegacyPathRefused(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	dir := t.TempDir()
	path, old := filepath.Join(dir, "i.db?x"), filepath.Join(dir, "i.db")
	s := startSvc(t, w.c, svcOpts{db: old, ns: []string{"matches"}, untyped: true})
	s.caughtUp("matches")
	s.stop()

	ix, err := index.Open(context.Background(), index.Options{Client: w.c, DB: path, Namespaces: []string{"matches"}, Logf: t.Logf})
	if err == nil {
		ix.Close()
		t.Fatal("opened a new database beside the legacy one")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), old) {
		t.Errorf("error %q names not both %s and %s", err, path, old)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s: %v", path, err)
	}
}
