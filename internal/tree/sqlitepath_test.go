package tree_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/tree"
)

// The service opens its database at exactly Options.DB, '#' and '?' in it
// and all, with the DSN's pragmas: "file:" + path cut the path at the '#'
// (t.TempDir of an unnamed subtest holds "#00"), so another file held the
// graph.
func TestDBPathOpensThatFile(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "t#00?x.db")
	s := startSvc(t, w.c, svcOpts{db: path})
	s.caughtUp("cat", "matches")
	cat, matches := s.s.Checkpoint("cat"), s.s.Checkpoint("matches")
	for q, want := range map[string]string{"journal_mode": "wal", "busy_timeout": "10000"} {
		var got string
		if err := s.s.DB().QueryRow(`PRAGMA ` + q).Scan(&got); err != nil || got != want {
			t.Errorf("PRAGMA %s = %q, %v; want %q", q, got, err, want)
		}
	}
	s.stop()

	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
	for _, ent := range must(os.ReadDir(dir)) {
		if !strings.HasPrefix(ent.Name(), "t#00?x.db") {
			t.Errorf("stray file %q", ent.Name())
		}
	}
	// Reopened without running: the checkpoints come from the file.
	r := must(tree.Open(context.Background(), tree.Options{Client: w.c, Catalog: "cat", DB: path, Logf: t.Logf}))
	defer r.Close()
	if got := r.Checkpoint("cat"); got != cat {
		t.Errorf("reopened: cat checkpoint %q, want %q", got, cat)
	}
	if got := r.Checkpoint("matches"); got != matches {
		t.Errorf("reopened: matches checkpoint %q, want %q", got, matches)
	}
}

// A graph that an earlier release kept at the path cut at its '#' (or
// '?', or with its %XX decoded) is refused, not replayed into a new
// database at the full path, which would lose edge_subjects too.
func TestDBLegacyPathRefused(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	dir := t.TempDir()
	path, old := filepath.Join(dir, "t.db#x"), filepath.Join(dir, "t.db")
	s := startSvc(t, w.c, svcOpts{db: old})
	s.caughtUp("cat", "matches")
	s.stop()

	r, err := tree.Open(context.Background(), tree.Options{Client: w.c, Catalog: "cat", DB: path, Logf: t.Logf})
	if err == nil {
		r.Close()
		t.Fatal("opened a new database beside the legacy one")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), old) {
		t.Errorf("error %q names not both %s and %s", err, path, old)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s: %v", path, err)
	}
}
