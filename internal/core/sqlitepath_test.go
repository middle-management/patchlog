package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The engine opens its SQLite database at exactly Options.Path, '#' and
// '?' in it and all, with the DSN's pragmas: "file:" + path cut the path
// at the '#' (t.TempDir of an unnamed subtest holds "#00"), so another
// file held the data.
func TestSQLitePathOpensThatFile(t *testing.T) {
	skipOnPostgres(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a#00?b.db")
	open := func() *Engine {
		t.Helper()
		e, err := Open(Options{Path: path, BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	ctx := context.Background()
	r := Request{NS: "n", Cred: Credentials{Author: "a"}}
	e := open()
	if _, err := e.WriteConfig(ctx, r, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteResource(ctx, r, Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"t": 1}}}}}}); err != nil {
		t.Fatal(err)
	}
	h, err := e.ResourceHead(ctx, "n", "d", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]string{"journal_mode": "wal", "busy_timeout": "10000", "foreign_keys": "1"} {
		var got string
		if err := e.db.QueryRow(`PRAGMA ` + q).Scan(&got); err != nil || got != want {
			t.Errorf("PRAGMA %s = %q, %v; want %q", q, got, err, want)
		}
	}
	e.Close()

	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		if !strings.HasPrefix(ent.Name(), "a#00?b.db") {
			t.Errorf("stray file %q", ent.Name())
		}
	}
	e = open()
	defer e.Close()
	if got, err := e.ResourceHead(ctx, "n", "d", Credentials{}); err != nil || got.Head != h.Head {
		t.Errorf("reopened: head %+v, %v; want %s", got, err, h.Head)
	}
}

// A database that an earlier release kept at the path cut at its '#' (or
// '?', or with its %XX decoded) is refused, not replaced by an empty one
// at the full path: the blob directory was already at the full path, so
// the empty database's blob sweep would delete every blob file in it.
// Moved to the full path, it opens with its blobs.
func TestSQLiteLegacyPathRefused(t *testing.T) {
	skipOnPostgres(t)
	dir := t.TempDir()
	path, old := filepath.Join(dir, "x.db#prod"), filepath.Join(dir, "x.db")
	blobDir := path + ".blobs"
	opts := Options{Path: old, BlobDir: blobDir, AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}}
	// The layout "-db x.db#prod" gave before.
	e, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("blob bytes")
	h := sha256.Sum256(data)
	if err := e.update(context.Background(), func(t *tx) error { t.putBytes(0, h[:], data); return nil }); err != nil {
		t.Fatal(err)
	}
	e.Close()
	past := time.Now().Add(-2 * time.Hour)
	filepath.WalkDir(blobDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			err = os.Chtimes(p, past, past)
		}
		return err
	})

	opts.Path, opts.BlobDir = path, ""
	if e, err := Open(opts); err == nil {
		e.Close()
		t.Fatal("opened an empty database beside the legacy one")
	} else if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), old) {
		t.Errorf("error %q names not both %s and %s", err, path, old)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s: %v", path, err)
	}
	if n := countFiles(t, blobDir); n != 1 {
		t.Errorf("%d blob files, want 1", n)
	}

	for _, sfx := range []string{"", "-wal", "-shm"} {
		if err := os.Rename(old+sfx, path+sfx); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	e, err = Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if n, err := e.SweepBlobFiles(context.Background()); err != nil || n != 0 {
		t.Errorf("swept %d, %v", n, err)
	}
	if n, r := countFiles(t, blobDir), bytesRows(t, e); n != 1 || r != 1 {
		t.Errorf("moved: %d blob files, %d rows; want 1, 1", n, r)
	}
	checkFilesNamed(t, e)
}
