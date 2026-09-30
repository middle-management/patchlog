package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/core"
)

// archiveCmd is `patchlog archive restore`: the offline restore of pruned
// history from its archives (§8.6, §D.4).
func archiveCmd(args []string) {
	if len(args) < 1 || args[0] != "restore" {
		fmt.Fprintln(os.Stderr, "usage: patchlog archive restore -db patchlog.db [-from file:///path] [-ns NS] [-resource NAME]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("archive restore", flag.ExitOnError)
	db := fs.String("db", "patchlog.db", "SQLite database path (no server may have it open)")
	from := fs.String("from", "", "file:// directory the archives are in now (default: the URLs recorded when they were written)")
	ns := fs.String("ns", "", "restore only this namespace")
	res := fs.String("resource", "", "restore only this resource (with -ns)")
	fs.Parse(args[1:])
	if *res != "" && *ns == "" {
		log.Fatal("-resource needs -ns")
	}
	if _, err := os.Stat(*db); err != nil {
		log.Fatalf("-db: %v", err)
	}
	e, err := core.Open(core.Options{Path: *db, RetentionInterval: -1})
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	reps, err := archive.Restore(context.Background(), e, archive.RestoreOptions{
		From: *from, NS: *ns, Name: *res,
		Log: func(format string, args ...any) { log.Printf(format, args...) },
	})
	if err != nil {
		log.Fatal(err)
	}
	var restored, cleared, failed int
	for _, r := range reps {
		restored += r.Restored
		if r.Cleared {
			cleared++
		}
		failed += len(r.Failed)
	}
	fmt.Printf("%d resources, %d patch sets restored, %d horizons cleared, %d archives failed\n", len(reps), restored, cleared, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// archiver builds the serve archiver from -archive and -archive-root.
func archiver(def string, roots []string) (core.Archiver, error) {
	if def == "" && len(roots) == 0 {
		return nil, nil
	}
	return archive.NewDir(def, roots...)
}
