package streams

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func split(t *testing.T, r io.Reader, max int) ([]string, error) {
	t.Helper()
	sp := newSplitter(r, max, 6*max)
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
	a := keyedID("streams", caller{sub: "user:ann", key: "k1"}, "turn-1")
	if len(a) != 32 || a != keyedID("streams", caller{sub: "user:ann", key: "k1"}, "turn-1") {
		t.Fatalf("id %q", a)
	}
	for _, other := range []string{
		keyedID("streams", caller{sub: "user:ann", key: "k2"}, "turn-1"),
		keyedID("streams", caller{sub: "user:bo", key: "k1"}, "turn-1"),
		keyedID("streams", caller{sub: "user:ann", key: "k1"}, "turn-2"),
		keyedID("streams", caller{sub: "user:an", key: "k1"}, "nturn-1"),
		keyedID("streams", caller{sub: "user:ann,6:turn-1", key: "k1"}, ""),
		keyedID("other", caller{sub: "user:ann", key: "k1"}, "turn-1"),
	} {
		if other == a {
			t.Fatal("two callers or keys share an id")
		}
	}
}

// cutReader gives data and then fails, as a response cut short does.
type cutReader struct {
	r   io.Reader
	err error
}

func (c *cutReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == io.EOF {
		err = c.err
	}
	return n, err
}

func TestSplitterCutShort(t *testing.T) {
	for body, want := range map[string]string{
		"a\nb\npartial":       "a\nb\npartial",
		"a\npartial \xe2\x98": "a\npartial ", // half a character at the cut is dropped
		"no line end":         "no line end",
		"":                    "",
	} {
		for _, r := range []io.Reader{strings.NewReader(body), iotest.OneByteReader(strings.NewReader(body))} {
			sp := newSplitter(&cutReader{r, io.ErrUnexpectedEOF}, 64, 384)
			var got []string
			var err error
			for err == nil {
				var cs []string
				cs, err = sp.next()
				got = append(got, cs...)
			}
			if err != io.ErrUnexpectedEOF || strings.Join(got, "") != want {
				t.Fatalf("%q: %q %v", body, got, err)
			}
		}
	}
	// Bad bytes before the cut are still not text.
	sp := newSplitter(&cutReader{strings.NewReader("ok\n\xff\xfe more"), io.ErrUnexpectedEOF}, 64, 384)
	var got []string
	var err error
	for err == nil {
		var cs []string
		cs, err = sp.next()
		got = append(got, cs...)
	}
	if err != errNotUTF8 || strings.Join(got, "") != "ok\n" {
		t.Fatalf("bad bytes before the cut: %q %v", got, err)
	}
}

// A chunk is cut by its length as a JSON string too.
func TestSplitterEncoded(t *testing.T) {
	body := strings.Repeat("\x1b", 100) + "\n" + strings.Repeat("é\"", 40) + "\nplain text\n" + strings.Repeat("\x00☃", 30)
	for _, enc := range []int{6, 7, 16, 60, 1000} {
		sp := newSplitter(iotest.HalfReader(strings.NewReader(body)), 64, enc)
		var got []string
		for {
			cs, err := sp.next()
			got = append(got, cs...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("enc %d: %v", enc, err)
			}
		}
		if strings.Join(got, "") != body {
			t.Fatalf("enc %d: chunks don't join to the body", enc)
		}
		for _, c := range got {
			if n := len(jsonv.Canonical(c)) - 2; n > enc || len(c) > 64 || len(c) == 0 || !utf8.ValidString(c) {
				t.Fatalf("enc %d: chunk %q is %d bytes as JSON", enc, c, n)
			}
			if encFit([]byte(c), 1<<30) != len(c) {
				t.Fatal("encFit")
			}
		}
	}
}
