package dbmigrate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/middle-management/mmmigrate/source"
)

// Every package's committed migrations are unchanged since they were
// committed (their checksums and chain hold), and, in CI, current.sql holds
// nothing left to commit: a migration tests apply but deployments wouldn't.
func TestMigrations(t *testing.T) {
	dirs, err := filepath.Glob("../*/migrations/current.sql")
	if err != nil {
		t.Fatal(err)
	}
	more, err := filepath.Glob("../*/migrations/*/current.sql")
	if err != nil {
		t.Fatal(err)
	}
	dirs = append(dirs, more...)
	if len(dirs) == 0 {
		t.Fatal("no migrations found")
	}
	for _, f := range dirs {
		dir := filepath.Dir(f)
		if err := source.ValidateChain(dir); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
		if os.Getenv("CI") != "" {
			if err := source.CheckDirtyCurrent(dir); err != nil {
				t.Errorf("%s: %v (make migration)", dir, err)
			}
		}
	}
}
