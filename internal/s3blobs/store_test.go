package s3blobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// The store against an S3-compatible service: PATCHLOG_TEST_BLOBS names a
// bucket (internal/testenv), else these skip.
func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("PATCHLOG_TEST_BLOBS")
	if !IsURL(url) {
		t.Skip("PATCHLOG_TEST_BLOBS names no s3:// bucket")
	}
	ctx := context.Background()
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBucket(ctx); err != nil {
		t.Fatal(err)
	}
	s = s.Sub(fmt.Sprintf("s3blobs-test-%d", time.Now().UnixNano()))
	t.Cleanup(func() {
		s.List(ctx, func(name string, _ int64, _ time.Time) error { return s.Remove(ctx, name) })
	})
	return s
}

func TestOpenURL(t *testing.T) {
	for _, bad := range []string{"s3://", "s3:///x", "file:///x", "s3://b?bogus=1", "s3://b?path-style=maybe"} {
		if _, err := Open(context.Background(), bad); err == nil {
			t.Errorf("%q opened", bad)
		}
	}
	s, err := Open(context.Background(), "s3://bucket/a/b/?region=eu-west-1&endpoint=http://localhost:9000")
	if err != nil {
		t.Fatal(err)
	}
	if s.Bucket != "bucket" || s.Prefix != "a/b/" || s.String() != "s3://bucket/a/b/" || s.Sub("/c/").Prefix != "a/b/c/" {
		t.Fatalf("%+v", s)
	}
	if s, _ := Open(context.Background(), "s3://bucket?region=eu-west-1"); s.Prefix != "" {
		t.Fatalf("prefix %q", s.Prefix)
	}
}

// Put, Open, ranges by seeking, List, Remove; a missing name is
// fs.ErrNotExist.
func TestStore(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()
	data := []byte("0123456789abcdefghij")
	before := time.Now().Add(-time.Minute)
	for _, n := range []string{"0/ab/x.1", "e/1/ab/y.1.2", "notes"} {
		if err := s.Put(ctx, n, data); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	if err := s.List(ctx, func(name string, size int64, mod time.Time) error {
		if size != int64(len(data)) || mod.Before(before) {
			t.Errorf("%s: size %d, modified %v", name, size, mod)
		}
		names = append(names, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	if strings.Join(names, " ") != "0/ab/x.1 e/1/ab/y.1.2 notes" {
		t.Fatalf("listed %v", names)
	}

	f, err := s.Open(ctx, "0/ab/x.1")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil || string(head) != "0123" {
		t.Fatalf("head %q %v", head, err)
	}
	if n, err := f.Seek(0, io.SeekEnd); err != nil || n != int64(len(data)) {
		t.Fatalf("size %d %v", n, err)
	}
	if _, err := f.Seek(10, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	part := make([]byte, 5)
	if _, err := io.ReadFull(f, part); err != nil || string(part) != "abcde" {
		t.Fatalf("range %q %v", part, err)
	}
	if _, err := f.Seek(-2, io.SeekEnd); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(f); err != nil || string(rest) != "ij" {
		t.Fatalf("tail %q %v", rest, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if all, err := io.ReadAll(f); err != nil || !bytes.Equal(all, data) {
		t.Fatalf("all %q %v", all, err)
	}

	if err := s.Remove(ctx, "0/ab/x.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, "0/ab/x.1"); err != nil {
		t.Fatalf("removing a missing name: %v", err)
	}
	if _, err := s.Open(ctx, "0/ab/x.1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open after remove: %v", err)
	}
	// An object deleted while open: a re-read from elsewhere finds it gone.
	g, err := s.Open(ctx, "notes")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := s.Remove(ctx, "notes"); err != nil {
		t.Fatal(err)
	}
	g.Seek(5, io.SeekStart)
	if _, err := io.ReadAll(g); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read after remove: %v", err)
	}
}
