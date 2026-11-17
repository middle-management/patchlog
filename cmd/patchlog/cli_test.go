package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	arg "github.com/alexflint/go-arg"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/lifecycle"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

// parseArgs parses args into dest, a flag group or command struct as the
// root, defaults and environment applied; t fails on a parse error.
func parseArgs(t *testing.T, dest any, args ...string) {
	t.Helper()
	p, err := arg.NewParser(arg.Config{Program: "patchlog"}, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Parse(args); err != nil {
		t.Fatalf("parse %q: %v", args, err)
	}
}

// command parses a patchlog command line and returns its (innermost)
// command; t fails on a parse error.
func command(t *testing.T, args ...string) any {
	t.Helper()
	var c cli
	p, err := newParser(&c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Parse(args); err != nil {
		t.Fatalf("parse %q: %v", args, err)
	}
	return p.Subcommand()
}

// runStatus runs a patchlog command line that fails before its command
// runs, or is removed, returning its exit status and stderr.
func runStatus(args ...string) (int, string) {
	var out, errw bytes.Buffer
	code := run(args, &out, &errw)
	return code, errw.String()
}

// TestCLIParses checks the struct tags: every command builds a parser,
// and single- and double-dash spellings of a flag both parse.
func TestCLIParses(t *testing.T) {
	t.Parallel()
	for _, dash := range []string{"-", "--"} {
		c := command(t, "merge", "status", dash+"api", "http://x", dash+"branch", "b", dash+"resolve", "a=1.json", dash+"resolve", "b=2.json", dash+"json").(*mergeBranchCmd)
		if c.API != "http://x" || c.Branch != "b" || len(c.Resolve) != 2 || !c.JSON {
			t.Errorf("%s: %+v", dash, c)
		}
	}
	s := command(t, "serve", "--playground=false", "--max-batch-size", "64 MiB").(*serveCmd)
	if s.Playground || s.MaxBatchSize == nil || *s.MaxBatchSize != 64<<20 || s.DocumentSize != nil {
		t.Errorf("serve: %+v", s)
	}
}

// TestCLIRequired checks a missing required flag is named in the error,
// not by its placeholder, and exits 2.
func TestCLIRequired(t *testing.T) {
	t.Parallel()
	code, msg := runStatus("rebase", "--branch", "b")
	if code != 2 || !strings.Contains(msg, "--new is required") {
		t.Errorf("%d %q", code, msg)
	}
	if code, msg := runStatus("merge"); code != 2 || !strings.Contains(msg, "release") {
		t.Errorf("merge without a subcommand: %d %q", code, msg)
	}
}

// TestCLIDefaults checks the defaults written into tags against the
// constants they copy.
func TestCLIDefaults(t *testing.T) {
	t.Parallel()
	var s serveCmd
	parseArgs(t, &s)
	if s.ShutdownTimeout != lifecycle.DefaultTimeout || s.EdgeHeader != edge.DefaultHeader || s.EdgePrefixHeader != edge.DefaultPrefixHeader ||
		s.EdgeGrantKid != edge.DefaultKid || s.MaxValidationSteps != core.DefaultMaxValidationSteps || s.CORSMaxAge != 10*time.Minute {
		t.Errorf("serve defaults: %+v", s)
	}
	var si schemaImportCmd
	parseArgs(t, &si, "--ns", "x", "f.json")
	if si.MaxDocs != schemaimport.DefaultMaxDocs || si.MaxBytes != schemaimport.DefaultMaxBytes || si.Timeout != schemaimport.DefaultTimeout {
		t.Errorf("schema import defaults: %+v", si)
	}
}
