package main

// Addendum G.4 tools: export, import and bundle verification. They are
// clients of the public API; the logic is in internal/bundle.
//
//	patchlog export -api URL -ns NS[,NS] [-resource a,b] [-mode history|snapshot] [-o file.jsonl] [-bearer T]
//	                [-recipient key.jwk]... [-plaintext] [-identity id.jwk]
//	patchlog import -api URL -ns TARGET -i file.jsonl [-dry-run] (-atomic | -pace 0.5) [-bearer T]
//	                [-only NS[,NS]] [-identity id.jwk] [-allow-less-protected]
//	patchlog bundle verify -i file.jsonl [-identity id.jwk]
//	patchlog bundle keygen -o id.jwk
//
// Encryption (§G.5): -recipient writes a sealed bundle (§G.5.1.1), which
// export requires for private and sealed sources unless -plaintext is
// given; -identity opens sealed bundles and unwraps the keys of sealed
// namespaces; import refuses targets less protected than their source
// unless -allow-less-protected.

import (
	"context"
	"os"
	"os/signal"

	"github.com/middle-management/patchlog/internal/bundle"
)

func bundleCmd(cmd string, args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := bundle.CLI(ctx, cmd, args, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
