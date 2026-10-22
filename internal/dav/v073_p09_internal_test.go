package dav

import "testing"

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
