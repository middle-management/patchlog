package main

// Addendum G.4 tools: export, import and bundle verification. They are
// clients of the public API; the logic is in internal/bundle.
//
//	patchlog export -api URL -ns NS[,NS] [-resource a,b] [-mode history|snapshot] [-o file.jsonl] [-bearer T]
//	patchlog import -api URL -ns TARGET -i file.jsonl [-dry-run] (-atomic | -pace 0.5) [-bearer T]
//	patchlog bundle verify -i file.jsonl

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
