package core

import (
	"os"
	"testing"

	"github.com/middle-management/mmmigrate/source"
)

// The committed migrations are unchanged since they were committed (their
// checksums and chain hold), and, in CI, current.sql holds nothing left to
// commit: a migration tests apply but deployments wouldn't.
func TestMigrations(t *testing.T) {
	for _, dir := range []string{"migrations/sqlite", "migrations/postgres"} {
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
