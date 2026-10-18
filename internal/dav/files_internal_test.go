package dav

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// §H.1's table takes extensions in any letter case; types are lowercased,
// without parameters.
func TestFileTypeTable(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, ctype, want string }{
		{"Notes.MD", "", "text/markdown"},
		{"a.Markdown", "text/plain", "text/markdown"},
		{"PHOTO.JPG", "image/png", "image/jpeg"},
		{"x.JpEg", "", "image/jpeg"},
		{"Sheet.XLSX", "", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		{"icon.SVG", "", "image/svg+xml"},
		{"app.MJS", "", "text/javascript"},
		{"x.JSON", "", "application/json"},
		{"archive.tar.gz", "Application/GZIP; q=1", "application/gzip"},
		{"README", "TEXT/PLAIN; charset=utf-8", "text/plain"},
		{"x.", "text/csv", "text/csv"},
		{"x", "text", "application/octet-stream"},
		{"x", "multipart/mixed", "application/octet-stream"},
	} {
		if got := fileType(c.name, c.ctype); got != c.want {
			t.Errorf("fileType(%q, %q) = %q, want %q", c.name, c.ctype, got, c.want)
		}
	}
}

// A file shows a document without a top-level $nonce of the fresh form
// and a $successor of §8.1's, and with any other value of those names,
// which is content; names deeper down are content too.
func TestBare(t *testing.T) {
	t.Parallel()
	nonce := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range []struct{ doc, want string }{
		{`{"$nonce": "` + nonce + `", "$successor": "x", "a": 1}`, `{"a": 1}`},
		{`{"$successor": "/r/other/x", "a": 1}`, `{"a": 1}`},
		{`{"$nonce": 5, "$successor": "Not A Name", "a": 1}`, `{"$nonce": 5, "$successor": "Not A Name", "a": 1}`},
		{`{"$nonce": "short", "a": {"$nonce": "` + nonce + `"}}`, `{"$nonce": "short", "a": {"$nonce": "` + nonce + `"}}`},
		{`[{"$nonce": "` + nonce + `"}]`, `[{"$nonce": "` + nonce + `"}]`},
		{`{"$schema": "/r/s/x/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "$nonce": "` + nonce + `"}`, `{"$schema": "/r/s/x/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`},
	} {
		got := bare(must(jsonv.Parse([]byte(c.doc))))
		if want := must(jsonv.Parse([]byte(c.want))); !jsonv.Equal(got, want) {
			t.Errorf("bare(%s) = %s, want %s", c.doc, jsonv.Canonical(got), c.want)
		}
	}
}

// Duplicates' names (§H.2 "Siblings"): the number before the extension,
// skipping taken ones, and back.
func TestDupNames(t *testing.T) {
	t.Parallel()
	taken := map[string]bool{"x (2).json": true}
	if got := dupName("x.json", func(n string) bool { return taken[n] }); got != "x (3).json" {
		t.Fatalf("dupName %q", got)
	}
	if got := dupName("notes", func(string) bool { return false }); got != "notes (2)" {
		t.Fatalf("dupName %q", got)
	}
	for in, want := range map[string]string{"x (2).json": "x.json", "a.b (12).md": "a.b.md", "x (2)": "x"} {
		if got, _, ok := dupOf(in); !ok || got != want {
			t.Fatalf("dupOf(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"x (1).json", "x.json", "x(2).json", "x (a).json"} {
		if _, _, ok := dupOf(in); ok {
			t.Fatalf("dupOf(%q)", in)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
