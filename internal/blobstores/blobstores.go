// Package blobstores opens a blob store (core.BlobStore, §7.8) from the
// URL of -blob-store:
//
//	file:///var/lib/patchlog/blobs                  a directory (internal/fsblobs, as -blob-dir)
//	s3://bucket/prefix?region=…&endpoint=…          an S3 bucket (internal/s3blobs)
//
// and picks a deployment's store (ForDB): -blob-store, -blob-dir, or by
// default a directory next to a SQLite file. It is the one place that
// knows every kind, so the engine imports none of them, nor their
// dependencies (the AWS SDK for S3).
package blobstores

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/fsblobs"
	"github.com/middle-management/patchlog/internal/s3blobs"
)

// ForDB picks a deployment's store from -blob-store (url) and -blob-dir
// (dir), at most one given: the store the URL names, else the directory,
// else "<db>.blobs" next to a SQLite file database. For ":memory:",
// Postgres and DynamoDB without either it is nil: the bytes stay in the
// database.
func ForDB(ctx context.Context, url, dir, db string) (core.BlobStore, error) {
	switch {
	case url != "" && dir != "":
		return nil, fmt.Errorf("blob store: give a URL or a directory, not both")
	case url != "":
		return Open(ctx, url)
	case dir == "" && core.IsSQLiteFile(db):
		dir = db + ".blobs"
	case dir == "":
		return nil, nil
	}
	s, err := fsblobs.Open(dir)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Open opens the store a URL names.
func Open(ctx context.Context, rawurl string) (core.BlobStore, error) {
	switch {
	case s3blobs.IsURL(rawurl):
		s, err := s3blobs.Open(ctx, rawurl)
		if err != nil {
			return nil, err
		}
		return s, nil
	case strings.HasPrefix(rawurl, "file:"):
		u, err := url.Parse(rawurl)
		if err != nil || (u.Host != "" && u.Host != "localhost") || u.Path == "" || u.RawQuery != "" {
			return nil, fmt.Errorf("blob store: a file URL is file:///<directory>, got %q", rawurl)
		}
		s, err := fsblobs.Open(u.Path)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	return nil, fmt.Errorf("blob store: %q: want a file:// or s3:// URL", rawurl)
}
