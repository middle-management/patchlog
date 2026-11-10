package main

import (
	"strings"
	"testing"
)

// The usage text lists the e2e subcommand v0.81 has, seal-status, as
// runE2E's own usage does, and not migrate-keyring, which v0.81 removed
// (runE2E answers it with migrateKeyringRemoved).
func TestV081XrevUsageE2E(t *testing.T) {
	t.Parallel()
	want := strings.TrimSpace(strings.TrimPrefix(e2eUsage, "usage:"))
	if !strings.Contains(usageText, want) {
		t.Errorf("usage text lacks %q", want)
	}
	if strings.Contains(usageText, "migrate-keyring") {
		t.Error("usage text still lists e2e migrate-keyring")
	}
}
