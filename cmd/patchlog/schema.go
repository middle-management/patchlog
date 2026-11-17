package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

// schemaCmd is patchlog schema import.
type schemaCmd struct {
	Import *schemaImportCmd `arg:"subcommand:import" help:"import external JSON Schemas into a namespace as schema resources"`
}

// schemaImportCmd imports external JSON Schemas into a namespace as schema
// resources, references pinned to revision paths (§6.1).
type schemaImportCmd struct {
	API           string        `arg:"--api,env:PATCHLOG_API" placeholder:"URL" help:"base URL of the deployment (optional with --dry-run: then every resource is planned as a create)"`
	NS            string        `arg:"--ns,required" help:"target namespace (not a branch)"`
	Bearer        string        `arg:"--bearer,env:PATCHLOG_BEARER" placeholder:"GRANT" help:"grant (Authorization: Bearer)"`
	Author        string        `arg:"--author,env:PATCHLOG_AUTHOR" placeholder:"NAME" help:"X-Author (development mode)"`
	Name          string        `arg:"--name" help:"resource name of the root schema (default: from its URL)"`
	DryRun        bool          `arg:"--dry-run" help:"fetch, convert, compile and print the plan; write nothing"`
	JSON          bool          `arg:"--json" help:"print the result as JSON"`
	MaxDocs       int           `arg:"--max-docs" default:"100" placeholder:"N" help:"most documents to fetch"`
	MaxBytes      int64         `arg:"--max-bytes" default:"33554432" placeholder:"N" help:"most bytes to fetch, in total"`
	Timeout       time.Duration `arg:"--timeout" default:"30s" placeholder:"DURATION" help:"timeout of each fetch"`
	DeclareSchema bool          `arg:"--declare-schema" help:"add a $schema property to schemas that are closed at the document root, for servers before spec v0.36 (patchlog before v0.7.0), which validated it"`
	Sources       []string      `arg:"positional,required" placeholder:"URL|FILE" help:"the schemas to import"`
}

func (a *schemaImportCmd) run(string) {
	if code := a.importSchemas(context.Background(), os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

func (a *schemaImportCmd) importSchemas(ctx context.Context, stdout, stderr io.Writer) int {
	if a.API == "" && !a.DryRun {
		fmt.Fprintln(stderr, "schema import: --api is required without --dry-run")
		return 2
	}
	var c *client.Client
	if a.API != "" {
		var opts []client.Option
		if a.Bearer != "" {
			opts = append(opts, client.WithBearer(a.Bearer))
		}
		if a.Author != "" {
			opts = append(opts, client.WithAuthor(a.Author))
		}
		var err error
		if c, err = client.New(a.API, opts...); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, err := schemaimport.Plan(ctx, c, a.Sources, schemaimport.Options{
		NS: a.NS, Name: a.Name, MaxDocs: a.MaxDocs, MaxBytes: a.MaxBytes, Timeout: a.Timeout, DeclareSchema: a.DeclareSchema,
	})
	if err != nil {
		fmt.Fprintln(stderr, "schema import:", err)
		return 1
	}
	written := false
	if !a.DryRun && res.Changed() {
		if err := res.Write(ctx, c); err != nil {
			fmt.Fprintln(stderr, "schema import:", err)
			return 1
		}
		written = true
	}
	if a.JSON {
		out := map[string]any{"ns": res.NS, "dryRun": a.DryRun, "written": written, "entries": res.Entries}
		if len(res.Bundled) > 0 {
			out["bundled"] = res.Bundled
		}
		if len(res.Warnings) > 0 {
			out["warnings"] = res.Warnings
		}
		if len(res.NSIDs) > 0 {
			out["ns_ids"] = res.NSIDs
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(out)
		return 0
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	for _, b := range res.Bundled {
		fmt.Fprintf(stderr, "note: these documents reference each other in a cycle and were merged into one resource (the others under $defs): %v\n", b)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tRESOURCE\tACTION\tPATH")
	for _, e := range res.Entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Source, e.Resource, e.Action, e.Path)
	}
	tw.Flush()
	switch {
	case a.DryRun:
		fmt.Fprintln(stderr, "dry run: nothing written")
	case !written:
		fmt.Fprintln(stderr, "nothing to write: every schema is unchanged")
	}
	return 0
}
