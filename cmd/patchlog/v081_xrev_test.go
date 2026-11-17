package main

import (
	"bytes"
	"strings"
	"testing"
)

// The e2e help lists the subcommand v0.81 has, seal-status, and not
// migrate-keyring, which v0.81 removed (run answers it with
// migrateKeyringRemoved).
func TestV081XrevUsageE2E(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if code := run([]string{"e2e", "--help"}, &out, &out); code != 0 {
		t.Fatalf("e2e --help: %d", code)
	}
	if !strings.Contains(out.String(), "seal-status") {
		t.Errorf("e2e help lacks seal-status: %s", out.String())
	}
	if strings.Contains(out.String(), "migrate-keyring") {
		t.Error("e2e help still lists migrate-keyring")
	}
}
