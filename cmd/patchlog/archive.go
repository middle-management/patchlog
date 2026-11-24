package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/keystore"
)

// archiveCmd is patchlog archive restore.
type archiveCmd struct {
	Restore *archiveRestoreCmd `arg:"subcommand:restore" help:"restore pruned history from its archives, offline (§8.6, §D.4)"`
}

// archiveRestoreCmd is the offline restore of pruned history from its
// archives (§8.6, §D.4).
type archiveRestoreCmd struct {
	DB        string `arg:"--db" default:"patchlog.db" placeholder:"PATH|URL" help:"SQLite database path (no server may have it open), or a Postgres URL"`
	BlobDir   string `arg:"--blob-dir,env:PATCHLOG_BLOB_DIR" placeholder:"DIR" help:"the server's blob directory (default <db>.blobs next to a SQLite file)"`
	From      string `arg:"--from" placeholder:"file:///DIR" help:"file:// directory the archives are in now (default: the URLs recorded when they were written)"`
	NS        string `arg:"--ns" help:"restore only this namespace"`
	Resource  string `arg:"--resource" placeholder:"NAME" help:"restore only this resource (with --ns)"`
	MasterKey string `arg:"--master-key" placeholder:"FILE" help:"master key file, needed to restore archives of encrypted namespaces (Addendum E.1)"`
}

func (a *archiveRestoreCmd) run(string) {
	if a.Resource != "" && a.NS == "" {
		log.Fatal("--resource needs --ns")
	}
	if _, err := os.Stat(a.DB); err != nil && !strings.HasPrefix(a.DB, "postgres") && !strings.HasPrefix(a.DB, "spanner://") {
		log.Fatalf("--db: %v", err)
	}
	opt := core.Options{Path: a.DB, BlobDir: a.BlobDir, RetentionInterval: -1}
	if a.MasterKey != "" {
		ks, err := keystore.LoadFile(a.MasterKey, false)
		if err != nil {
			log.Fatalf("--master-key: %v", err)
		}
		opt.KeyStore = ks
	}
	e, err := core.Open(opt)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	reps, err := archive.Restore(context.Background(), e, archive.RestoreOptions{
		From: a.From, NS: a.NS, Name: a.Resource,
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

// archiver builds the serve archiver from --archive and --archive-root.
func archiver(def string, roots []string) (core.Archiver, error) {
	if def == "" && len(roots) == 0 {
		return nil, nil
	}
	return archive.NewDir(def, roots...)
}
