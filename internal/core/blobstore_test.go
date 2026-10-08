package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// Blob files (blobstore.go): what a transaction stores and deletes, on
// SQLite and, with PATCHLOG_TEST_PG, on Postgres.

func openBlobEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1,
		BlobSweepInterval: -1, Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// countFiles counts the files under dir.
func countFiles(t *testing.T, dir string) int {
	t.Helper()
	n, err := fileCount(dir)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func fileCount(dir string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return err
	})
	return n, err
}

// checkFilesNamed fails unless every file a row names exists.
func checkFilesNamed(t *testing.T, e *Engine) {
	t.Helper()
	var files []string
	err := e.read(context.Background(), func(t *tx) error {
		for _, table := range []string{"blob_bytes", "blob_epochs"} {
			rows, err := t.Query(`SELECT file FROM ` + table + ` WHERE file IS NOT NULL`)
			t.must(err)
			for rows.Next() {
				var f string
				t.must(rows.Scan(&f))
				files = append(files, f)
			}
			rows.Close()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(e.blobs.root(), f)); err != nil {
			t.Fatalf("a row names %s: %v", f, err)
		}
	}
}

func bytesRows(t *testing.T, e *Engine) int {
	t.Helper()
	var n int
	if err := e.read(context.Background(), func(t *tx) error {
		return t.QueryRow(`SELECT COUNT(*) FROM blob_bytes`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// A transaction that rolls back, by error or panic, leaves no file; one
// that commits leaves its file, and a collection's file goes only once
// the collecting transaction commits.
func TestBlobFilesTransactions(t *testing.T) {
	t.Parallel()
	e := openBlobEngine(t)
	dir := e.blobs.root()
	ctx := context.Background()
	data := []byte("transactional bytes")
	h := sha256.Sum256(data)
	abort := errors.New("abort")

	if err := e.update(ctx, func(t *tx) error {
		t.putBytes(0, h[:], data)
		return abort
	}); err != abort {
		t.Fatalf("update: %v", err)
	}
	if err := e.update(ctx, func(t *tx) error {
		t.putBytes(0, h[:], data)
		panic("boom")
	}); err == nil {
		t.Fatal("a panic commits nothing")
	}
	if n, r := countFiles(t, dir), bytesRows(t, e); n != 0 || r != 0 {
		t.Fatalf("after rollbacks: %d files, %d rows", n, r)
	}

	if err := e.update(ctx, func(t *tx) error {
		t.putBytes(0, h[:], data)
		t.putBytes(0, h[:], data) // stored once
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, dir); n != 1 {
		t.Fatalf("%d files after a commit", n)
	}
	checkFilesNamed(t, e)
	if err := e.read(ctx, func(t *tx) error {
		if got := t.readBytes(0, h[:]); !bytes.Equal(got, data) {
			return errors.New("read back different bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Nothing names the bytes: a collection that rolls back keeps the file.
	if err := e.update(ctx, func(t *tx) error {
		t.gcBytes(0, h[:])
		return abort
	}); err != abort {
		t.Fatalf("update: %v", err)
	}
	if n, r := countFiles(t, dir), bytesRows(t, e); n != 1 || r != 1 {
		t.Fatalf("after a rolled-back collection: %d files, %d rows", n, r)
	}
	checkFilesNamed(t, e)
	if err := e.update(ctx, func(t *tx) error {
		t.gcBytes(0, h[:])
		if n, _ := fileCount(dir); n != 1 {
			return errors.New("the file went before the commit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, r := countFiles(t, dir), bytesRows(t, e); n != 0 || r != 0 {
		t.Fatalf("after the collection: %d files, %d rows", n, r)
	}
}

// A reader whose snapshot predates a collection finds the file gone and
// reads again, seeing the collection.
func TestBlobFilesReadAgain(t *testing.T) {
	t.Parallel()
	e := openBlobEngine(t)
	ctx := context.Background()
	mkNS(t, e, "r", map[string]any{"read": "public"})
	data := []byte("read again")
	bid := uploadAndAttach(t, e, "r", "a", data)
	b, err := e.ReadBlob(ctx, "r", "a", bid, Credentials{})
	if err != nil || b.Status != 200 || !bytes.Equal(b.Data, data) {
		t.Fatalf("read %+v %v", b, err)
	}
	calls := 0
	b, err = readAgain(func() (*Blob, error) {
		calls++
		if calls == 1 {
			return nil, panicErr(errBytesGone)
		}
		return e.ReadBlob(ctx, "r", "a", bid, Credentials{})
	})
	if err != nil || calls != 2 || !bytes.Equal(b.Data, data) {
		t.Fatalf("read again: %d calls, %v", calls, err)
	}
	// A file gone for good fails both reads, as an internal error.
	removeAll(t, e.blobs.root())
	if _, err := e.ReadBlob(ctx, "r", "a", bid, Credentials{}); !errors.Is(err, errBytesGone) {
		t.Fatalf("read of a missing file: %v", err)
	}
}

// removeAll deletes every file under dir.
func removeAll(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			err = os.Remove(p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// uploadAndAttach uploads data to ns/name and writes a document that
// references it, and returns the blob id.
func uploadAndAttach(t *testing.T, e *Engine, ns, name string, data []byte) string {
	t.Helper()
	bid := uploadBlob(t, e, ns, name, data)
	r := who
	r.NS = ns
	doc := map[string]any{"b": map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}}
	it := Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}}}
	if _, err := e.WriteResource(context.Background(), r, it); err != nil {
		t.Fatal(err)
	}
	return bid
}

func uploadBlob(t *testing.T, e *Engine, ns, name string, data []byte) string {
	t.Helper()
	bid, err := tryUpload(e, ns, name, data)
	if err != nil {
		t.Fatal(err)
	}
	return bid
}

func tryUpload(e *Engine, ns, name string, data []byte) (string, error) {
	bid := ids.Blob("text/plain", "", data).String()
	r := who
	r.NS = ns
	up := BlobUpload{Type: "text/plain", Body: bytes.NewReader(data), Length: int64(len(data))}
	return bid, e.UploadBlob(context.Background(), r, name, bid, up)
}

func headOf(t *testing.T, e *Engine, ns, name string) string {
	t.Helper()
	var id string
	if err := e.read(context.Background(), func(t *tx) error {
		n := t.nsByName(ns)
		r := t.resource(n.id, name)
		id = t.rev(r.headSeq.Int64).id.String()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func purge(t *testing.T, e *Engine, ns, name string) {
	t.Helper()
	if err := tryPurge(e, ns, name, headOf(t, e, ns, name)); err != nil {
		t.Fatal(err)
	}
}

func tryPurge(e *Engine, ns, name, head string) error {
	r := who
	r.NS = ns
	if _, err := e.Purge(context.Background(), r, name, head, true); err != nil {
		return fmt.Errorf("purge %s/%s: %w", ns, name, err)
	}
	return nil
}

// Two instances share one blob directory (Addendum D.8): each serves what
// the other stored, shared plaintext is one file until the last resource
// naming it is purged, and uploads racing purges of the same bytes never
// leave a row naming a deleted file.
func TestPGBlobFilesShared(t *testing.T) {
	t.Parallel()
	a, b := twoInstances(t)
	ctx := context.Background()
	dir := a.blobs.root()
	if dir != b.blobs.root() {
		t.Fatal("the instances don't share the directory")
	}
	mkNS(t, a, "n1", map[string]any{"read": "public"})
	mkNS(t, a, "n2", map[string]any{"read": "public"})
	data := []byte("shared between instances")
	bid := uploadAndAttach(t, a, "n1", "x", data)
	if uploadAndAttach(t, b, "n2", "y", data) != bid {
		t.Fatal("same bytes, same id")
	}
	if n := countFiles(t, dir); n != 1 {
		t.Fatalf("%d files for one byte string", n)
	}
	got, err := b.ReadBlob(ctx, "n1", "x", bid, Credentials{})
	if err != nil || got.Status != 200 || !bytes.Equal(got.Data, data) {
		t.Fatalf("b reads a's blob: %+v %v", got, err)
	}
	purge(t, a, "n2", "y")
	if n := countFiles(t, dir); n != 1 {
		t.Fatalf("%d files while n1/x still names the bytes", n)
	}
	purge(t, b, "n1", "x")
	if n := countFiles(t, dir); n != 0 {
		t.Fatalf("%d files after the last purge", n)
	}
	if got, err := a.ReadBlob(ctx, "n1", "x", bid, Credentials{}); err != nil || got.Status != 410 {
		t.Fatalf("after purge: %+v %v", got, err)
	}

	// Uploads on one instance racing purges on the other.
	race := []byte("racing bytes")
	for i := range 15 {
		name := "k" + string(rune('a'+i))
		uploadAndAttach(t, b, "n2", name, race)
		head := headOf(t, b, "n2", name)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); _, errs[0] = tryUpload(a, "n1", "pending", race) }()
		go func() { defer wg.Done(); errs[1] = tryPurge(b, "n2", name, head) }()
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Fatal(err)
		}
		checkFilesNamed(t, a)
	}
	rbid := uploadAndAttach(t, a, "n1", "z", race)
	if got, err := b.ReadBlob(ctx, "n1", "z", rbid, Credentials{}); err != nil || got.Status != 200 || !bytes.Equal(got.Data, race) {
		t.Fatalf("read after the races: %+v %v", got, err)
	}
	if n := countFiles(t, dir); n != 1 {
		t.Fatalf("%d files for one byte string", n)
	}
}
