package core

// Where blob bytes live (§7.8, D.2).
//
// The rows of blob_bytes (blobs.go) and blob_epochs (sealedblobs.go) stay
// the arbiters of which bytes exist: who stores first, who collects, and
// the Postgres row locks between them are as before. What a blob store
// changes is where a row's bytes are:
//
//   - tableStore: in the row (data). The default for ":memory:" and for
//     Postgres without Options.BlobDir.
//   - fileStore: in a file under a directory, named by the row (file); data
//     is empty (blob_bytes) or NULL (blob_epochs). The default for a SQLite
//     file, at "<db path>.blobs".
//
// Rows whose file is NULL keep their bytes in data whichever store the
// engine has, so a database written before files (or by an instance
// without a directory) keeps working: nothing is migrated, and such rows
// go the usual way when collected.
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
// Writes. A file is written to a temporary file in its directory, synced,
// renamed into place and its directory synced, before the row naming it is
// inserted; a transaction that rolls back deletes the files it wrote (an
// ambiguous commit failure leaves them to the sweep). So a committed row
// always names a complete file, and a crash leaves at most orphan files.
//
// Deletes. A transaction that deletes a row naming a file (gcBytes,
// purges, prunes) deletes the file after it commits (updateOnce). A crash
// in between leaves an orphan. Readers whose snapshot predates that commit
// may find the file gone: they read again (errBytesGone). Deleting is not
// erasing: a purge's plaintext stays in free blocks (unlike SQLite's
// secure_delete pages); encryption at rest makes it unreadable instead.
//
// The sweep. On the leader, SweepBlobFiles deletes files older than
// orphanGrace that no row names (and temporary files that old), which only
// a crash, an ambiguous commit or a lost race leaves. No transaction lasts
// that long, so a file whose row is yet to commit is never swept.
//
// Several instances on Postgres share one directory (a shared volume),
// and a directory belongs to one database: the sweep deletes whatever that
// database doesn't name.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// orphanGrace is how old an unnamed file must be before the sweep deletes it.
const orphanGrace = time.Hour

// errBytesGone reports that a row's file was deleted after the reading
// transaction's snapshot: a later read sees the row gone too.
var errBytesGone = errors.New("blob file deleted since the read began")

// blobStore keeps the bytes of blob_bytes and blob_epochs rows.
type blobStore interface {
	// put stores data durably under a new name starting with prefix and
	// returns the name for the row, or "" if the row keeps data itself.
	put(prefix string, data []byte) (string, error)
	// open opens a stored name.
	open(name string) (*os.File, error)
	// remove deletes a stored name; a missing one is no error.
	remove(name string) error
	// root is the directory of a file store, or "".
	root() string
}

// tableStore keeps bytes in their rows.
type tableStore struct{}

func (tableStore) put(string, []byte) (string, error) { return "", nil }
func (tableStore) remove(string) error                { return nil }
func (tableStore) root() string                       { return "" }
func (tableStore) open(name string) (*os.File, error) {
	return nil, fmt.Errorf("blob file %s: the bytes are stored in files, and no blob directory is configured", name)
}

// fileStore keeps bytes in files under dir.
type fileStore struct{ dir string }

func (s *fileStore) root() string { return s.dir }

func (s *fileStore) path(name string) string { return filepath.Join(s.dir, filepath.FromSlash(name)) }

func (s *fileStore) put(prefix string, data []byte) (string, error) {
	var suffix [8]byte
	rand.Read(suffix[:])
	name := prefix + "." + hex.EncodeToString(suffix[:])
	full := s.path(name)
	dir := filepath.Dir(full)
	created, err := s.mkdirs(dir)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
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
		return "", err
	}
	// The new entry, and those of directories just created, survive a crash.
	for _, d := range append([]string{dir}, created...) {
		if err := syncDir(d); err != nil {
			return "", err
		}
	}
	return name, nil
}

// mkdirs creates dir and its missing parents under s.dir, and returns the
// parents whose entries changed (to sync).
func (s *fileStore) mkdirs(dir string) ([]string, error) {
	if _, err := os.Stat(dir); err == nil {
		return nil, nil
	}
	var missing []string
	for d := dir; d != s.dir && d != filepath.Dir(d); d = filepath.Dir(d) {
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

func (s *fileStore) open(name string) (*os.File, error) { return os.Open(s.path(name)) }

func (s *fileStore) remove(name string) error {
	err := os.Remove(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// openBlobStore picks the engine's blob store (Options.BlobDir).
func openBlobStore(dir, path string, pg bool) (blobStore, error) {
	if dir == "" {
		switch {
		case pg:
			log.Print("blob bytes are stored in the database: give -blob-dir (a directory every instance shares) to store them in files")
			return tableStore{}, nil
		case path == ":memory:":
			return tableStore{}, nil
		}
		dir = path + ".blobs"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("blob directory: %w", err)
	}
	return &fileStore{dir: abs}, nil
}

// --- in transactions -----------------------------------------------------------

// storeFile stores data for a row about to be inserted and returns the
// file name it records, or "" if the row keeps data (tableStore). The file
// is deleted again if the transaction rolls back.
func (t *tx) storeFile(prefix string, data []byte) string {
	name, err := t.e.blobs.put(prefix, data)
	if err != nil {
		panic(fmt.Errorf("storing blob bytes: %w", err))
	}
	if name != "" {
		t.newFiles = append(t.newFiles, name)
	}
	return name
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
func (t *tx) openFile(name string) *os.File {
	f, err := t.e.blobs.open(name)
	if errors.Is(err, fs.ErrNotExist) {
		panic(fmt.Errorf("%w: %s", errBytesGone, name))
	}
	t.must(err)
	return f
}

// removeFiles deletes files, logging failures (the sweep retries them).
func (e *Engine) removeFiles(names []string) {
	for _, n := range names {
		if err := e.blobs.remove(n); err != nil {
			log.Printf("blob store: %v", err)
		}
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

// SweepBlobFiles deletes the files in the blob directory that no row names
// and that are older than an hour, and temporary files that old: what a
// crash, an ambiguous commit or a lost race leaves (blobstore.go). It
// returns how many it deleted.
func (e *Engine) SweepBlobFiles(ctx context.Context) (int, error) {
	dir := e.blobs.root()
	if dir == "" {
		return 0, nil
	}
	cutoff := time.Now().Add(-orphanGrace)
	// The candidates, listed before the rows are read: a file older than
	// the grace whose row isn't visible yet would need a transaction that
	// old.
	type group struct {
		table string // blob_bytes or blob_epochs
		key   int64  // owner or ns
	}
	cands := map[group][]string{}
	var temps []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
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
		if err != nil || !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(d.Name(), ".tmp-") {
			temps = append(temps, rel)
			return nil
		}
		parts := strings.Split(rel, "/")
		var g group
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
			cands[g] = append(cands[g], rel)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	var orphans []string
	err = e.read(ctx, func(t *tx) error {
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
	})
	if err != nil {
		return 0, err
	}
	orphans = append(orphans, temps...)
	n := 0
	for _, f := range orphans {
		if err := e.blobs.remove(f); err != nil {
			log.Printf("blob sweep: %v", err)
			continue
		}
		n++
	}
	return n, nil
}
