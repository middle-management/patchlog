package fsblobs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Put, Open with seeks, List (temporary files included), Remove; a
// missing name is fs.ErrNotExist.
func TestStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("0123456789abcdefghij")
	for _, n := range []string{"0/ab/x.1", "e/1/ab/y.1.2"} {
		if err := s.Put(ctx, n, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "0", "ab", TempPrefix+"1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := s.List(ctx, func(name string, size int64, mod time.Time) error {
		if time.Since(mod) > time.Minute {
			t.Errorf("%s: modified %v", name, mod)
		}
		names = append(names, name)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	if strings.Join(names, " ") != "0/ab/.tmp-1 0/ab/x.1 e/1/ab/y.1.2" {
		t.Fatalf("listed %v", names)
	}
	f, err := s.Open(ctx, "0/ab/x.1")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Seek(10, io.SeekStart)
	if rest, err := io.ReadAll(f); err != nil || string(rest) != "abcdefghij" {
		t.Fatalf("range %q %v", rest, err)
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
}
