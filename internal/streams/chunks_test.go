package streams

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"
)

func split(t *testing.T, r io.Reader, max int) ([]string, error) {
	t.Helper()
	sp := newSplitter(r, max)
	var out []string
	for {
		cs, err := sp.next()
		out = append(out, cs...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func TestSplitter(t *testing.T) {
	body := "data: a\n\ndata: bb\n\n" + strings.Repeat("ÿ☃𝄞", 40) + "\nlast line without an end"
	for _, max := range []int{4, 5, 7, 16, 64, 1 << 10} {
		for name, r := range map[string]io.Reader{
			"whole":    strings.NewReader(body),
			"one byte": iotest.OneByteReader(strings.NewReader(body)),
			"halves":   iotest.HalfReader(strings.NewReader(body)),
		} {
			cs, err := split(t, r, max)
			if err != nil {
				t.Fatalf("max %d, %s: %v", max, name, err)
			}
			if strings.Join(cs, "") != body {
				t.Fatalf("max %d, %s: chunks don't join to the body", max, name)
			}
			for i, c := range cs {
				if len(c) == 0 || len(c) > max || !utf8.ValidString(c) {
					t.Fatalf("max %d, %s: chunk %d %q", max, name, i, c)
				}
				// A chunk ends at a line end unless its line is longer
				// than max, or the body ends.
				if !strings.HasSuffix(c, "\n") && i != len(cs)-1 && len(c) < max-utf8.UTFMax+1 {
					t.Fatalf("max %d, %s: chunk %d %q ends mid-line", max, name, i, c)
				}
			}
		}
	}
	// With room, the lines of one read are one chunk.
	if cs, _ := split(t, strings.NewReader("a\nb\nc"), 64); len(cs) != 2 || cs[0] != "a\nb\n" || cs[1] != "c" {
		t.Fatalf("chunks %q", cs)
	}
	for _, bad := range []string{"ok\n\xff\n", "\xe2\x98", "abc\xe2\x98", strings.Repeat("\x80", 20)} {
		for _, max := range []int{4, 64} {
			if cs, err := split(t, iotest.OneByteReader(strings.NewReader(bad)), max); err != errNotUTF8 {
				t.Fatalf("%q, max %d: %q %v", bad, max, cs, err)
			}
		}
	}
	if cs, err := split(t, strings.NewReader(""), 8); err != nil || len(cs) != 0 {
		t.Fatalf("empty body: %q %v", cs, err)
	}
}

func TestTextType(t *testing.T) {
	for ct, want := range map[string]bool{
		"text/event-stream": true, "text/plain; charset=utf-8": true, "application/json": true, "application/x-ndjson": true,
		"application/problem+json": true, "": true, "application/xml": true,
		"image/png": false, "application/octet-stream": false, "audio/mpeg": false, "application/pdf": false, ";;": false,
	} {
		if textType(ct) != want {
			t.Fatalf("textType(%q) = %v", ct, !want)
		}
	}
}

func TestKeyedID(t *testing.T) {
	a := keyedID(caller{sub: "user:ann", key: "k1"}, "turn-1")
	if len(a) != 32 || a != keyedID(caller{sub: "user:ann", key: "k1"}, "turn-1") {
		t.Fatalf("id %q", a)
	}
	for _, other := range []string{
		keyedID(caller{sub: "user:ann", key: "k2"}, "turn-1"),
		keyedID(caller{sub: "user:bo", key: "k1"}, "turn-1"),
		keyedID(caller{sub: "user:ann", key: "k1"}, "turn-2"),
		keyedID(caller{sub: "user:an", key: "k1"}, "nturn-1"),
		keyedID(caller{sub: "user:ann,6:turn-1", key: "k1"}, ""),
	} {
		if other == a {
			t.Fatal("two callers or keys share an id")
		}
	}
}
