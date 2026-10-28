package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/middle-management/patchlog/internal/blobstores"
	"github.com/middle-management/patchlog/internal/core"
)

// blobFlags are -blob-store and its shorthand -blob-dir (§7.8: where blob
// bytes are stored).
type blobFlags struct{ store, dir *string }

func addBlobFlags(fs *flag.FlagSet) blobFlags {
	return blobFlags{
		store: fs.String("blob-store", envOr("PATCHLOG_BLOB_STORE", ""), "where blob bytes are stored: file:///<directory>, or s3://<bucket>/<prefix>?region=…[&endpoint=…] (credentials from the AWS chain); default $PATCHLOG_BLOB_STORE. Instances sharing a database must share it"),
		dir:   fs.String("blob-dir", envOr("PATCHLOG_BLOB_DIR", ""), "directory blob bytes are stored in, short for -blob-store file:///<dir>; default $PATCHLOG_BLOB_DIR. With neither: <db>.blobs next to a SQLite file, else the database itself (on DynamoDB, which then caps blobSize at 350 KiB)"),
	}
}

// apply sets the engine's blob store, opt.Path being set
// (blobstores.ForDB).
func (f blobFlags) apply(opt *core.Options) error {
	if *f.store != "" && *f.dir != "" {
		return fmt.Errorf("give -blob-store or -blob-dir ($PATCHLOG_BLOB_STORE or $PATCHLOG_BLOB_DIR), not both")
	}
	s, err := blobstores.ForDB(context.Background(), *f.store, *f.dir, opt.Path)
	if err != nil {
		return fmt.Errorf("-blob-store/-blob-dir: %w", err)
	}
	opt.BlobStore = s
	return nil
}
