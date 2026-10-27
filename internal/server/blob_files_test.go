package server

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// Blob bytes in files (core/blobstore.go). Like every server test, these
// run on SQLite and, with PATCHLOG_TEST_PG, on Postgres, with blob files in
// a temporary directory, or with PATCHLOG_TEST_BLOBS in S3.

// blobFiles lists the files of the engine's blob store under prefix.
func (e *tenv) blobFiles(prefix string) []string {
	e.t.Helper()
	s := e.e.BlobStore()
	if s == nil {
		e.t.Fatal("no blob store")
	}
	var out []string
	err := s.List(context.Background(), func(name string, _ int64, _ time.Time) error {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// readBlobFile reads a file of the engine's blob store.
func (e *tenv) readBlobFile(name string) ([]byte, error) {
	f, err := e.e.BlobStore().Open(context.Background(), name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (e *tenv) expectFiles(prefix string, n int, what string) []string {
	e.t.Helper()
	files := e.blobFiles(prefix)
	if len(files) != n {
		e.t.Fatalf("%s: %d files under %q, want %d: %v", what, len(files), prefix, n, files)
	}
	return files
}

// Shared plaintext is one file, served with ranges; files of collected
// bytes go once the collecting transaction commits: the grace sweep, and
// a purge.
func TestBlobFilesLifecycle(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning)
	e.mkNS("f", map[string]any{"read": "public", "limits": map[string]any{"blobGrace": "PT1H"}})
	data := []byte("0123456789 file-backed blob")
	bid := e.upload("f", "a", "text/plain", data)
	files := e.expectFiles("", 1, "pending upload")
	if !strings.HasPrefix(files[0], "0/") {
		t.Fatalf("plaintext bytes in %s, want owner 0", files[0])
	}
	if b, err := e.readBlobFile(files[0]); err != nil || !bytes.Equal(b, data) {
		t.Fatalf("file content %q %v", b, err)
	}
	head := e.create("f", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	if e.upload("f", "b", "text/plain", data) != bid { // the same bytes, pending elsewhere
		t.Fatal("same bytes, same id")
	}
	e.upload("f", "c", "text/plain", []byte("only pending"))
	e.expectFiles("", 2, "shared bytes once, plus another blob")
	if s := e.blobStats(); s.Bytes != 2 || s.Files != 2 || s.Size != int64(len(data)+len("only pending")) {
		t.Fatalf("stats %+v", s)
	}

	r := e.do(req{method: "GET", path: blobPath("f", "a", bid), hdr: map[string]string{"Range": "bytes=2-5"}})
	if r.Code != 206 || string(r.Body) != "2345" || r.H.Get("Content-Range") != "bytes 2-5/27" {
		t.Fatalf("range %d %q %v", r.Code, r.Body, r.H)
	}
	if r := e.get(blobPath("f", "a", bid)); string(r.Body) != string(data) {
		t.Fatalf("read %q", r.Body)
	}

	// The sweep ends both pending entries: the attached bytes stay.
	e.clock.Advance(61 * time.Minute)
	if n, err := e.e.SweepBlobs(context.Background()); err != nil || n != 2 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if got := e.expectFiles("", 1, "after the sweep"); got[0] != files[0] {
		t.Fatalf("kept %v, want %s", got, files[0])
	}

	tomb := e.del("f", "a", head)
	expect(t, e.do(req{method: "POST", path: "/r/f/a/purge", ifMatch: tomb, author: "admin"}), 204)
	e.expectFiles("", 0, "after the purge")
	expect(t, e.get(blobPath("f", "a", bid)), 410)
}

// §E.1: bytes encrypted at rest are a file per resource, without the
// plaintext; a purge deletes them along with the data key.
func TestBlobFilesAtRest(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	e.mkNS("enc", atRest(map[string]any{"read": "public"}))
	data := []byte("at rest " + encMarker)
	bid := e.upload("enc", "a", "text/plain", data)
	head := e.create("enc", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	e.upload("enc", "b", "text/plain", data)
	files := e.expectFiles("", 2, "one copy per resource")
	for _, f := range files {
		if strings.HasPrefix(f, "0/") {
			t.Fatalf("encrypted bytes in %s", f)
		}
		b, err := e.readBlobFile(f)
		if err != nil || bytes.Contains(b, []byte(encMarker)) {
			t.Fatalf("%s holds plaintext (%v)", f, err)
		}
	}
	if r := e.get(blobPath("enc", "a", bid)); string(r.Body) != string(data) {
		t.Fatalf("read %q", r.Body)
	}
	tomb := e.del("enc", "a", head)
	expect(t, e.do(req{method: "POST", path: "/r/enc/a/purge", ifMatch: tomb, author: "admin"}), 204)
	e.expectFiles("", 1, "after purging one resource")
}

// §E.2.2: an epoch's sealing is a file too, the first stored winning among
// concurrent first readers; purges delete it.
func TestBlobFilesSealed(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t, withoutBlobSweep)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	data := []byte("sealed " + encMarker)
	nonce := seal.NewNonce()
	r, bid := e.putBlob("s", "a", "text/plain", nonce, data)
	expect(t, r, 201)
	p1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), nonce)})))
	loc := blobPath("s", "a", bid) + "/e/1"
	var wg sync.WaitGroup
	bodies := make([]string, 6)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bodies[i] = string(e.get(loc).Body)
		}(i)
	}
	wg.Wait()
	for _, b := range bodies[1:] {
		if b != bodies[0] || b == "" {
			t.Fatal("concurrent first readers got different sealings")
		}
	}
	sealed := e.expectFiles("e/", 1, "one stored sealing")
	if b, err := e.readBlobFile(sealed[0]); err != nil || string(b) != bodies[0] {
		t.Fatalf("sealing file differs (%v)", err)
	}
	rr := e.do(req{method: "GET", path: loc, hdr: map[string]string{"Range": "bytes=0-3"}})
	if rr.Code != 206 || string(rr.Body) != "PLB1" {
		t.Fatalf("range %d %q", rr.Code, rr.Body)
	}
	expect(t, e.do(req{method: "POST", path: "/r/s/a/purge", ifMatch: p1, author: "admin"}), 204)
	e.expectFiles("", 0, "after the purge")
	expect(t, e.get(loc), 410)
}

// The orphan sweep deletes old files no row names, and nothing else (a
// store's own leftovers, as fsblobs' temporary files, are its package's to
// test). "Old" is past BlobOrphanGrace, shortened here: the files are
// stored, then those meant to look fresh once it has passed.
func TestBlobFilesOrphanSweep(t *testing.T) {
	t.Parallel()
	const grace = 2 * time.Second
	e := newEnv(t, withBlobTuning, func(o *core.Options) { o.BlobOrphanGrace = grace })
	e.mkNS("o", map[string]any{"read": "public"})
	data := []byte("named")
	bid := e.upload("o", "a", "text/plain", data)
	e.create("o", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	named := e.expectFiles("", 1, "the attached blob")[0]
	store := e.e.BlobStore()
	h := strings.Repeat("ab", 32)
	write := func(names ...string) {
		for _, name := range names {
			if err := store.Put(context.Background(), name, []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("0/ab/"+h+".0011223344556677", // orphan bytes
		"7/ab/"+h+".0011223344556677",              // orphan bytes of a resource
		"e/1/ab/"+strings.Repeat("ab", 20)+".1.00", // orphan sealing
		"notes.txt", "0/README") // not the store's
	time.Sleep(grace + time.Second)          // object stores keep whole seconds
	write("0/ab/" + h + ".8899aabbccddeeff") // a write yet to commit
	n, err := e.e.SweepBlobFiles(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("swept %d %v", n, err)
	}
	got := e.blobFiles("")
	want := []string{"0/README", "0/ab/" + h + ".8899aabbccddeeff", named, "notes.txt"}
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("left %v, want %v", got, want)
	}
	expect(t, e.get(blobPath("o", "a", bid)), 200)
}

// Rows written before blob files keep their bytes in the table: they are
// served, copied and collected as before.
func TestBlobFilesLegacyRows(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy.db")
	e := newEnv(t, withBlobTuning, withPath(path))
	e.mkNS("l", map[string]any{"read": "public"})
	data := []byte("bytes from before files")
	bid := e.upload("l", "a", "text/plain", data)
	head := e.create("l", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	file := e.expectFiles("", 1, "the upload")[0]
	if e.blobStats().Store != path+".blobs" {
		t.Fatalf("blob directory %s, want next to the database", e.blobStats().Store)
	}
	// As an earlier version stored it.
	db, err := sql.Open("sqlite", sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE blob_bytes SET data = ?, file = NULL`, data); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(path+".blobs", file)); err != nil {
		t.Fatal(err)
	}
	if r := e.get(blobPath("l", "a", bid)); r.Code != 200 || string(r.Body) != string(data) {
		t.Fatalf("legacy read %d %q", r.Code, r.Body)
	}
	if s := e.blobStats(); s.Bytes != 1 || s.Files != 0 || s.Size != int64(len(data)) {
		t.Fatalf("stats %+v", s)
	}
	tomb := e.del("l", "a", head)
	expect(t, e.do(req{method: "POST", path: "/r/l/a/purge", ifMatch: tomb, author: "admin"}), 204)
	if s := e.blobStats(); s.Bytes != 0 {
		t.Fatalf("stats after purge %+v", s)
	}
}

// Without a blob directory (":memory:", Postgres without -blob-dir) the
// bytes stay in the database.
func TestBlobTableStore(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBlobTuning, withTableBlobs)
	e.mkNS("t", map[string]any{"read": "public"})
	data := []byte("in the table")
	bid := e.upload("t", "a", "text/plain", data)
	head := e.create("t", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")})
	if s := e.blobStats(); s.Store != "" || s.Bytes != 1 || s.Files != 0 || s.Size != int64(len(data)) {
		t.Fatalf("stats %+v", s)
	}
	r := e.do(req{method: "GET", path: blobPath("t", "a", bid), hdr: map[string]string{"Range": "bytes=3-5"}})
	if r.Code != 206 || string(r.Body) != "the" {
		t.Fatalf("range %d %q", r.Code, r.Body)
	}
	if n, err := e.e.SweepBlobFiles(context.Background()); err != nil || n != 0 {
		t.Fatalf("file sweep %d %v", n, err)
	}
	tomb := e.del("t", "a", head)
	expect(t, e.do(req{method: "POST", path: "/r/t/a/purge", ifMatch: tomb, author: "admin"}), 204)
	if s := e.blobStats(); s.Bytes != 0 {
		t.Fatalf("stats after purge %+v", s)
	}
}
