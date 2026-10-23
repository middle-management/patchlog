package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// CIS-36: -remote-ignore-purges is gone: a deployment that sees a remote
// base's purge applies it (§4, §G.3); -remote-follow-interval 0 stops
// following altogether.
func TestV073RemoteIgnorePurgesFlagGone(t *testing.T) {
	if os.Getenv("P32_SERVE") == "1" {
		serve(strings.Fields(os.Getenv("P32_ARGS")))
		return
	}
	// A database path that can't be opened: serve exits right after its
	// flags were taken, without listening.
	db := filepath.Join(t.TempDir(), "missing", "dir", "p.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestV073RemoteIgnorePurgesFlagGone$")
	cmd.Env = append(os.Environ(), "P32_SERVE=1", "P32_ARGS=-remote-ignore-purges -addr 127.0.0.1:0 -db "+db)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "flag provided but not defined: -remote-ignore-purges") {
		t.Fatalf("serve -remote-ignore-purges: %v\n%s", err, out)
	}
}
