package dav

import (
	"fmt"
	"testing"
	"time"
)

// A raw file's type (§H.1): the name's extension, else the upload's
// Content-Type unless it says nothing of the bytes, else the existing
// file's, else application/octet-stream; a text/ type only for a UTF-8
// body, a leading BOM allowed (GW-4, GW-5).
func TestV073FileTypeOrder(t *testing.T) {
	t.Parallel()
	bad := []byte("\xff\xfe\x00abc")
	for _, c := range []struct {
		name, ctype, had string
		body             []byte
		want             string
	}{
		{"x.md", "image/png", "image/gif", []byte("# x"), "text/markdown"},
		{"x", "image/x-foo", "image/gif", []byte("x"), "image/x-foo"},
		{"x", "", "image/gif", []byte("x"), "image/gif"},
		{"x", "application/octet-stream", "image/gif", []byte("x"), "image/gif"},
		{"x", "binary/octet-stream", "image/gif", []byte("x"), "image/gif"},
		{"x", "application/x-www-form-urlencoded", "image/gif", []byte("x"), "image/gif"},
		{"x", "multipart/form-data; boundary=b", "image/gif", []byte("x"), "image/gif"},
		{"x", "", "", []byte("x"), "application/octet-stream"},
		{"x.txt", "", "", bad, "application/octet-stream"},
		{"x.txt", "", "", []byte("\xef\xbb\xbfhé"), "text/plain"},
		{"x.txt", "", "", []byte("\xef\xbb\xbf\xff"), "application/octet-stream"},
		{"x", "text/x-foo", "", bad, "application/octet-stream"},
		{"x", "", "text/plain", bad, "application/octet-stream"},
		{"x", "", "text/plain", []byte("ok"), "text/plain"},
		{"x.png", "", "", bad, "image/png"},
	} {
		if got := fileType(c.name, c.ctype, c.had, c.body); got != c.want {
			t.Errorf("fileType(%q, %q, %q, %q) = %q, want %q", c.name, c.ctype, c.had, c.body, got, c.want)
		}
	}
}

// The records of an idle user are retired past the sweep (GW-24): each
// document they had records of stays a lost mark, and its path records
// stay, at most maxRetiredMarks of each, for at most maxRetired users,
// the least recently used going first.
func TestV073RetiredRecordsBounded(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := &Server{opt: Options{Now: func() time.Time { return now }, RecordIdle: time.Hour, RecordBytes: 1 << 20}, recRoots: map[string]*recStore{}}
	for i := 0; i < maxRetired+3; i++ {
		p := s.newPrincipal(fmt.Sprintf("u%d", i))
		for j := 0; j < 2; j++ {
			s.remember(p, "docs", fmt.Sprintf("d%d", j), record{rev: "r"}, false)
		}
		s.notePath(p, "/docs/d0.json", "docs", "d0")
		now = now.Add(time.Second)
	}
	big := s.newPrincipal("big")
	for j := 0; j < maxRetiredMarks+10; j++ {
		s.remember(big, "docs", fmt.Sprintf("d%d", j), record{rev: "r"}, false)
		s.notePath(big, fmt.Sprintf("/docs/d%d.json", j), "docs", fmt.Sprintf("d%d", j))
	}
	now = now.Add(2 * time.Hour)
	s.recMu.Lock()
	s.sweepRecordsLocked(now)
	n := len(s.recRoots)
	_, oldest := s.recRoots["u0"]
	rs := s.recRoots["big"]
	s.recMu.Unlock()
	if n != maxRetired || oldest {
		t.Fatalf("%d users' records kept (u0 among them: %v), want %d", n, oldest, maxRetired)
	}
	if rs == nil || rs.docs.Len() != 0 || rs.forgotten.Len() != maxRetiredMarks || rs.paths.Len() != maxRetiredMarks || s.recBytes != 0 {
		t.Fatalf("retired: %d docs, %d marks, %d paths, %d bytes", rs.docs.Len(), rs.forgotten.Len(), rs.paths.Len(), s.recBytes)
	}
	last := fmt.Sprintf("d%d", maxRetiredMarks+9)
	if d := s.recordsOf(big, "docs", last); !d.lost || len(d.rs) != 0 {
		t.Fatalf("%s after the sweep: %+v", last, d)
	}
	if ns, name, ok := s.pathOf(big, "/docs/"+last+".json"); !ok || ns != "docs" || name != last {
		t.Fatalf("path record after the sweep: %q %q %v", ns, name, ok)
	}
}

// Retired, a user's records keep, of the entries the user wrote, the one
// used last of each document kept as a lost mark (GW-24, §H.4
// "Records"): where the head is the user's own DELETE that is it,
// however many entries of other documents the user wrote after it; the
// rest go, and so do those of documents with no mark.
func TestV073RetiredKeepsOwnDelete(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := &Server{opt: Options{Now: func() time.Time { return now }, RecordIdle: time.Hour, RecordBytes: 1 << 20}, recRoots: map[string]*recStore{}}
	p := s.newPrincipal("u")
	s.remember(p, "docs", "x", record{rev: "x1", wrote: true}, false)
	s.markOwn(p, "docs", "x", "x1")
	s.markOwn(p, "docs", "x", "xt") // the user's DELETE
	for i := 0; i < maxRetiredMarks+10; i++ {
		rev := fmt.Sprintf("y%d", i)
		s.remember(p, "docs", "y", record{rev: rev, wrote: true}, false)
		s.markOwn(p, "docs", "y", rev)
	}
	s.markOwn(p, "docs", "unmarked", "u1")
	now = now.Add(2 * time.Hour)
	s.recMu.Lock()
	s.sweepRecordsLocked(now)
	n := s.recRoots["u"].own.Len()
	s.recMu.Unlock()
	last := fmt.Sprintf("y%d", maxRetiredMarks+9)
	for _, c := range []struct {
		name, id string
		want     bool
	}{{"x", "xt", true}, {"x", "x1", false}, {"y", last, true}, {"y", "y0", false}, {"unmarked", "u1", false}} {
		if got := s.ownEntry(p, "docs", c.name, c.id); got != c.want {
			t.Errorf("own entry %s@%s after the sweep: %v, want %v", c.name, c.id, got, c.want)
		}
	}
	if n != 2 {
		t.Errorf("%d own entries kept, want 2", n)
	}
	if d := s.recordsOf(p, "docs", "x"); !d.lost {
		t.Errorf("x after the sweep: %+v", d)
	}
}
