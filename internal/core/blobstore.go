package core

// Where blob bytes live (§7.8, D.2).
//
// The rows of blob_bytes (blobs.go) and blob_epochs (sealedblobs.go) stay
// the arbiters of which bytes exist: who stores first, who collects, and
// the Postgres row locks between them are as before. What a blob store
// changes is where a row's bytes are:
//
//   - no store (Engine.blobs nil): in the row (data). The default for
//     ":memory:" and for Postgres (DynamoDB: inline in the BYTES# item).
//   - a BlobStore: in a file of the store, named by the row (file); data is
//     empty (blob_bytes) or NULL (blob_epochs). internal/fsblobs keeps files under
//     a directory, the default for a SQLite file at "<db path>.blobs";
//     internal/s3blobs keeps them as objects of an S3 bucket
//     (Options.BlobStore, opened from -blob-store by internal/blobstores).
//
// Rows whose file is NULL keep their bytes in data whichever store the
// engine has, so a database written before files (or by an instance
// without a store) keeps working: nothing is migrated, and such rows go
// the usual way when collected.
//
// Layout. Bytes go to {owner}/{hh}/{sha256 hex}.{random} (owner 0 for the
// shared plaintext, else the resource whose data key encrypts them, hh the
// hash's first two hex digits), stored sealings to
// e/{ns}/{hh}/{bid hex}.{epoch}.{random}. The random suffix makes every
// stored copy its own file, so deleting the file of a collected row can
// never remove one a later row names: on Postgres a collector deletes its
// row and, once committed, its file, while a concurrent upload of the same
// bytes inserts a new row naming a new file.
//
// Writes. A file is stored durably (BlobStore.Put: for fsblobs a
// temporary file in its directory, synced, renamed into place and its
// directory synced; for S3 one PutObject) before the row naming it is
// inserted; a transaction that rolls back deletes the files it wrote (an
// ambiguous commit failure leaves them to the sweep). So a committed row
// always names a complete file, and a crash leaves at most orphan files.
//
// Deletes. A transaction that deletes a row naming a file (gcBytes,
// purges, prunes) deletes the file after it commits (updateOnce). A crash
// in between leaves an orphan. Readers whose snapshot predates that commit
// may find the file gone: they read again (errBytesGone). An open file
// stays readable once deleted; an S3 object being served streams from the
// GET that opened it, but a range read after its deletion fails. Deleting is not
// erasing: a purge's plaintext stays in free blocks (unlike SQLite's
// secure_delete pages); encryption at rest makes it unreadable instead.
//
// The sweep. On the leader, SweepBlobFiles lists the store and deletes
// files older than orphanGrace that no row names (and temporary files that
// old), which only
// a crash, an ambiguous commit or a lost race leaves. No transaction lasts
// that long, so a file whose row is yet to commit is never swept.
//
// Several instances share one store (a bucket, or a directory on a shared
// volume), and a store belongs to one database: the sweep deletes whatever
// that database doesn't name.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/fsblobs"
)

// orphanGrace is how old an unnamed stored object must be before the sweep
// deletes it (Options.BlobOrphanGrace).
const orphanGrace = time.Hour

// errBytesGone reports that a row's file was deleted after the reading
// transaction's snapshot: a later read sees the row gone too.
var errBytesGone = errors.New("blob file deleted since the read began")

// BlobStore keeps the bytes of blob_bytes and blob_epochs rows outside the
// database (Options.BlobStore): a directory (internal/fsblobs, file://
// URLs, -blob-dir), or an object store such as S3 (internal/s3blobs). Its
// methods use only the standard library's types, so a store needn't import
// this package. Names are slash-separated paths chosen by the engine, each
// stored once and never rewritten.
type BlobStore interface {
	// Put stores data durably under name: once it returns, Open finds it.
	Put(ctx context.Context, name string, data []byte) error
	// Open opens a stored name for reading; a missing one is an error
	// matching fs.ErrNotExist. Bytes stored under a name never change, so
	// a reader may read them lazily (ranges read only what they need).
	Open(ctx context.Context, name string) (io.ReadSeekCloser, error)
	// Remove deletes a stored name; a missing one is no error.
	Remove(ctx context.Context, name string) error
	// List calls fn for every name stored, with its size and when it was
	// stored, in no particular order: the orphan sweep and BlobStats.
	List(ctx context.Context, fn func(name string, size int64, modified time.Time) error) error
	// String describes the store, for logs and BlobStats: a directory or a
	// URL.
	String() string
}

// openBlobStore picks the engine's blob store: Options.BlobStore, else a
// directory (Options.BlobDir, by default "<db path>.blobs" next to a
// SQLite file), else nil, the bytes then kept in their rows (":memory:",
// and Postgres without either).
func openBlobStore(opt Options, pg bool) (BlobStore, error) {
	switch {
	case opt.BlobStore != nil && opt.BlobDir != "":
		return nil, errors.New("core: give BlobStore or BlobDir, not both")
	case opt.BlobStore != nil:
		return opt.BlobStore, nil
	}
	dir := opt.BlobDir
	if dir == "" {
		switch {
		case pg:
			log.Print("blob bytes are stored in the database: give -blob-store (an s3:// bucket, or a file:// directory every instance shares) to store them outside it")
			return nil, nil
		case opt.Path == ":memory:":
			return nil, nil
		}
		dir = opt.Path + ".blobs"
	}
	s, err := fsblobs.Open(dir)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// BlobStore is the engine's blob store; nil when blob bytes are kept in
// the database.
func (e *Engine) BlobStore() BlobStore { return e.blobs }

// --- in transactions -----------------------------------------------------------

// storeFile stores data for a row about to be inserted and returns the
// file name it records, or "" if the row keeps data (no blob store). The
// file is deleted again if the transaction rolls back.
func (t *tx) storeFile(prefix string, data []byte) string {
	name, err := t.e.putBlob(t.context(), prefix, data)
	if err != nil {
		panic(fmt.Errorf("storing blob bytes: %w", err))
	}
	if name != "" {
		t.newFiles = append(t.newFiles, name)
	}
	return name
}

// putBlob stores data under a new name starting with prefix and returns
// the name, or "" without a blob store. The random suffix makes every
// stored copy its own file (see the top of the file).
func (e *Engine) putBlob(ctx context.Context, prefix string, data []byte) (string, error) {
	if e.blobs == nil {
		return "", nil
	}
	var suffix [8]byte
	rand.Read(suffix[:])
	name := prefix + "." + hex.EncodeToString(suffix[:])
	if err := e.blobs.Put(ctx, name, data); err != nil {
		return "", err
	}
	return name, nil
}

// dropFile deletes a file once the transaction that deleted the row naming
// it has committed.
func (t *tx) dropFile(name string) {
	if name != "" {
		t.dropFiles = append(t.dropFiles, name)
	}
}

// discardFile deletes a file this transaction stored but no row names
// (another transaction's row won).
func (t *tx) discardFile(name string) {
	for i, n := range t.newFiles {
		if n == name {
			t.newFiles = append(t.newFiles[:i], t.newFiles[i+1:]...)
			break
		}
	}
	t.e.removeFiles([]string{name})
}

// readFile returns a file's whole content.
func (t *tx) readFile(name string) []byte {
	f := t.openFile(name)
	defer f.Close()
	data, err := io.ReadAll(f)
	t.must(err)
	return data
}

// openFile opens a file a row names, or panics with errBytesGone if it is
// gone (deleted after this transaction's snapshot).
func (t *tx) openFile(name string) io.ReadSeekCloser {
	f, err := t.e.openStored(t.context(), name)
	t.must(err)
	return f
}

// openStored opens a file a row names; errBytesGone if it is gone.
func (e *Engine) openStored(ctx context.Context, name string) (io.ReadSeekCloser, error) {
	if e.blobs == nil {
		return nil, fmt.Errorf("blob file %s: the bytes are stored outside the database, and no blob store is configured", name)
	}
	f, err := e.blobs.Open(ctx, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", errBytesGone, name)
	}
	return f, err
}

// removeTimeout bounds deleting one file of the blob store: deletes run
// after the transaction that dropped the row committed, whatever became of
// its request (the sweep retries what fails).
const removeTimeout = time.Minute

// removeFiles deletes files, logging failures (the sweep retries them).
func (e *Engine) removeFiles(names []string) {
	if e.blobs == nil {
		return
	}
	for _, n := range names {
		ctx, cancel := context.WithTimeout(context.Background(), removeTimeout)
		if err := e.blobs.Remove(ctx, n); err != nil {
			log.Printf("blob store: %v", err)
		}
		cancel()
	}
}

// bytesFile is the prefix of the file of blob bytes (owner, hash).
func bytesFile(owner int64, hash []byte) string {
	h := hex.EncodeToString(hash)
	return strconv.FormatInt(owner, 10) + "/" + h[:2] + "/" + h
}

// epochFile is the prefix of the file of a blob's sealing in namespace ns
// under epoch e.
func epochFile(ns int64, bid []byte, e int) string {
	h := hex.EncodeToString(bid)
	return "e/" + strconv.FormatInt(ns, 10) + "/" + h[:2] + "/" + h + "." + strconv.Itoa(e)
}

// --- the orphan sweep ------------------------------------------------------------

// SweepBlobFiles deletes the files of the blob store that no row names
// and that are older than the grace (an hour), and temporary files that
// old: what a crash, an ambiguous commit or a lost race leaves
// (blobstore.go). It returns how many it deleted.
func (e *Engine) SweepBlobFiles(ctx context.Context) (int, error) {
	if e.blobs == nil {
		return 0, nil
	}
	grace := e.opt.BlobOrphanGrace
	if grace <= 0 {
		grace = orphanGrace
	}
	cutoff := time.Now().Add(-grace)
	// The candidates, listed before the rows are read: a file older than
	// the grace whose row isn't visible yet would need a transaction that
	// old.
	type group struct {
		table string // blob_bytes or blob_epochs
		key   int64  // owner or ns
	}
	cands := map[group][]string{}
	var temps []string
	err := e.blobs.List(ctx, func(name string, _ int64, modified time.Time) error {
		if !modified.Before(cutoff) {
			return nil
		}
		parts := strings.Split(name, "/")
		if strings.HasPrefix(parts[len(parts)-1], fsblobs.TempPrefix) {
			temps = append(temps, name)
			return nil
		}
		var g group
		var err error
		switch {
		case len(parts) == 3:
			g.table = "blob_bytes"
			g.key, err = strconv.ParseInt(parts[0], 10, 64)
		case len(parts) == 4 && parts[0] == "e":
			g.table = "blob_epochs"
			g.key, err = strconv.ParseInt(parts[1], 10, 64)
		default:
			return nil // not ours
		}
		if err == nil {
			cands[g] = append(cands[g], name)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	var orphans []string
	if e.ddb != nil {
		// The BYTES items name the files (ddbPutBytes).
		_, _, bytes, err := e.ddb.store.ScanBlobs(ctx)
		if err != nil {
			return 0, ddbAsErr(err)
		}
		named := map[string]bool{}
		for _, b := range bytes {
			named[b.File] = true
		}
		for _, files := range cands {
			for _, f := range files {
				if !named[f] {
					orphans = append(orphans, f)
				}
			}
		}
	} else if err := e.read(ctx, func(t *tx) error {
		for g, files := range cands {
			col := "owner"
			if g.table == "blob_epochs" {
				col = "ns"
			}
			named := map[string]bool{}
			rows, err := t.Query(`SELECT file FROM `+g.table+` WHERE `+col+` = ? AND file IS NOT NULL`, g.key)
			t.must(err)
			for rows.Next() {
				var f string
				t.must(rows.Scan(&f))
				named[f] = true
			}
			rows.Close()
			for _, f := range files {
				if !named[f] {
					orphans = append(orphans, f)
				}
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	orphans = append(orphans, temps...)
	n := 0
	if err := e.jobStep(ctx); err != nil {
		return 0, err
	}
	for _, f := range orphans {
		if err := e.blobs.Remove(ctx, f); err != nil {
			log.Printf("blob sweep: %v", err)
			continue
		}
		n++
	}
	return n, nil
}
