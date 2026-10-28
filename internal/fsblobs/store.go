// Package fsblobs keeps blob bytes in files under a directory
// (core.BlobStore, §7.8): the default next to a SQLite file, and -blob-dir
// or file:// URLs (internal/blobstores). Several instances share it only
// on a shared volume; S3 (internal/s3blobs) needs none.
//
// Each name is a file at that relative path. A write goes to a temporary
// file in its directory, is synced, renamed into place and the directory
// synced: a crash leaves the whole file or none (and at worst a temporary
// file, which SweepLeftovers deletes once the engine's orphan sweep calls
// it).
//
// Like s3blobs, it satisfies core.BlobStore through standard library
// types, without importing the engine.
package fsblobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store keeps bytes in files under Dir.
type Store struct{ Dir string }

// Open returns the store of the directory dir, creating it if need be.
func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("blob directory: %w", err)
	}
	return &Store{Dir: abs}, nil
}

func (s *Store) String() string { return s.Dir }

func (s *Store) path(name string) string { return filepath.Join(s.Dir, filepath.FromSlash(name)) }

// Put writes a temporary file in the name's directory, syncs it, renames
// it into place and syncs the directory: a crash leaves the whole file or
// none (and at worst a temporary file, for the sweep).
func (s *Store) Put(_ context.Context, name string, data []byte) error {
	full := s.path(name)
	dir := filepath.Dir(full)
	created, err := s.mkdirs(dir)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), full)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	// The new entry, and those of directories just created, survive a crash.
	for _, d := range append([]string{dir}, created...) {
		if err := syncDir(d); err != nil {
			return err
		}
	}
	return nil
}

// tmpPrefix starts the names of temporary files.
const tmpPrefix = ".tmp-"

// mkdirs creates dir and its missing parents under s.Dir, and returns the
// parents whose entries changed (to sync).
func (s *Store) mkdirs(dir string) ([]string, error) {
	if _, err := os.Stat(dir); err == nil {
		return nil, nil
	}
	var missing []string
	for d := dir; d != s.Dir && d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		missing = append(missing, d)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var parents []string
	for _, d := range missing {
		parents = append(parents, filepath.Dir(d))
	}
	return parents, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) Open(_ context.Context, name string) (io.ReadSeekCloser, error) {
	return os.Open(s.path(name))
}

func (s *Store) Remove(_ context.Context, name string) error {
	err := os.Remove(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// List lists the stored names; temporary files aren't stored names
// (SweepLeftovers deletes them).
func (s *Store) List(ctx context.Context, fn func(name string, size int64, modified time.Time) error) error {
	return s.walk(ctx, func(name string, temp bool, info fs.FileInfo) error {
		if temp {
			return nil
		}
		return fn(name, info.Size(), info.ModTime())
	})
}

// SweepLeftovers deletes the temporary files of writes a crash interrupted
// that were last modified before before; the engine's orphan sweep calls
// it with its grace, which outlasts any write.
func (s *Store) SweepLeftovers(ctx context.Context, before time.Time) (int, error) {
	n := 0
	err := s.walk(ctx, func(name string, temp bool, info fs.FileInfo) error {
		if !temp || !info.ModTime().Before(before) {
			return nil
		}
		if err := os.Remove(s.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		n++
		return nil
	})
	return n, err
}

// walk calls fn for every regular file under the directory, by name,
// telling temporary files apart.
func (s *Store) walk(ctx context.Context, fn func(name string, temp bool, info fs.FileInfo) error) error {
	return filepath.WalkDir(s.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return ctx.Err()
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(s.Dir, p)
		if err != nil {
			return nil
		}
		return fn(filepath.ToSlash(rel), strings.HasPrefix(d.Name(), tmpPrefix), info)
	})
}
