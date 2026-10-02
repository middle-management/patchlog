package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schemaimport"
)

const schemaUsage = "usage: patchlog schema import -api URL -ns NS [-bearer GRANT] [-author A] [-name NAME] [-dry-run] [-json] [-no-declare-schema] [-max-docs N] [-max-bytes N] [-timeout D] URL|FILE..."

// schemaCmd is `patchlog schema import`: external JSON Schemas into a
// namespace as schema resources, references pinned to revision paths (§6.1).
func schemaCmd(args []string) {
	if len(args) < 1 || args[0] != "import" {
		fmt.Fprintln(os.Stderr, schemaUsage)
		os.Exit(2)
	}
	os.Exit(schemaImport(context.Background(), args[1:], os.Stdout, os.Stderr))
}

func schemaImport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("schema import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", "", "base URL of the deployment (optional with -dry-run: then every resource is planned as a create)")
	ns := fs.String("ns", "", "target namespace (not a branch)")
	bearer := fs.String("bearer", "", "grant (Authorization: Bearer)")
	author := fs.String("author", "", "X-Author (development mode)")
	name := fs.String("name", "", "resource name of the root schema (default: from its URL)")
	dry := fs.Bool("dry-run", false, "fetch, convert, compile and print the plan; write nothing")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	maxDocs := fs.Int("max-docs", schemaimport.DefaultMaxDocs, "most documents to fetch")
	maxBytes := fs.Int64("max-bytes", schemaimport.DefaultMaxBytes, "most bytes to fetch, in total")
	timeout := fs.Duration("timeout", schemaimport.DefaultTimeout, "timeout of each fetch")
	noDeclare := fs.Bool("no-declare-schema", false, "don't add a $schema property to schemas that are closed at the document root (§6.1)")
	fs.Usage = func() { fmt.Fprintln(stderr, schemaUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *ns == "" || fs.NArg() == 0 || (*api == "" && !*dry) {
		fs.Usage()
		return 2
	}
	var c *client.Client
	if *api != "" {
		var opts []client.Option
		if *bearer != "" {
			opts = append(opts, client.WithBearer(*bearer))
		}
		if *author != "" {
			opts = append(opts, client.WithAuthor(*author))
		}
		var err error
		if c, err = client.New(*api, opts...); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, err := schemaimport.Plan(ctx, c, fs.Args(), schemaimport.Options{
		NS: *ns, Name: *name, MaxDocs: *maxDocs, MaxBytes: *maxBytes, Timeout: *timeout, NoDeclareSchema: *noDeclare,
	})
	if err != nil {
		fmt.Fprintln(stderr, "schema import:", err)
		return 1
	}
	written := false
	if !*dry && res.Changed() {
		if err := res.Write(ctx, c); err != nil {
			fmt.Fprintln(stderr, "schema import:", err)
			return 1
		}
		written = true
	}
	if *asJSON {
		out := map[string]any{"ns": res.NS, "dryRun": *dry, "written": written, "entries": res.Entries}
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
	case *dry:
		fmt.Fprintln(stderr, "dry run: nothing written")
	case !written:
		fmt.Fprintln(stderr, "nothing to write: every schema is unchanged")
	}
	return 0
}
