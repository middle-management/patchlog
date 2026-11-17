package streams

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"strings"
	"unicode/utf8"
)

var errNotUTF8 = errors.New("the upstream body is not UTF-8 text")

// textType reports whether a Content-Type names text a stream can keep
// (J.1): text/*, JSON and its line-delimited forms, XML, and the +json and
// +xml suffixes. No Content-Type at all is taken as text; the bytes still
// have to be UTF-8.
func textType(ct string) bool {
	if strings.TrimSpace(ct) == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/json", "application/x-ndjson", "application/ndjson", "application/jsonl", "application/x-jsonlines",
		"application/json-seq", "application/xml", "application/x-www-form-urlencoded":
		return true
	}
	return false
}

// splitter cuts an upstream body into chunks (J.1): UTF-8 text ending at a
// line end, at most max bytes each and at most enc bytes as a canonical
// JSON string without its quotes, which is how the core measures a value
// (§6.6 valueSize: a control character is six bytes there). A line longer
// than that is cut between two characters. What it has read of a line
// that hasn't ended is held back until the line ends, the bound is reached
// or the body does.
type splitter struct {
	r     io.Reader
	max   int
	enc   int
	buf   []byte
	carry []byte
}

func newSplitter(r io.Reader, max, enc int) *splitter {
	return &splitter{r: r, max: max, enc: enc, buf: make([]byte, 32<<10)}
}

// encFit is the length of the longest prefix of b that is at most limit
// bytes as the inside of a canonical JSON string (jsonv.Canonical).
func encFit(b []byte, limit int) int {
	n := 0
	for i, c := range b {
		switch {
		case c == '"', c == '\\', c == '\b', c == '\f', c == '\n', c == '\r', c == '\t':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
		if n > limit {
			return i
		}
	}
	return len(b)
}

// next returns the chunks of the next read, perhaps none, and the read's
// error with the last ones: io.EOF at the end of the body, or what cut it
// short, after what had arrived of its last line. errNotUTF8 is a body
// that isn't UTF-8.
func (s *splitter) next() ([]string, error) {
	n, err := s.r.Read(s.buf)
	s.carry = append(s.carry, s.buf[:n]...)
	var out []string
	for {
		cut := s.cut(err != nil)
		if cut == 0 {
			break
		}
		if !utf8.Valid(s.carry[:cut]) {
			good := 0
			for good < cut {
				r, size := utf8.DecodeRune(s.carry[good:cut])
				if r == utf8.RuneError && size <= 1 {
					break
				}
				good += size
			}
			if err != nil && err != io.EOF && cut == len(s.carry) && !utf8.FullRune(s.carry[good:]) {
				// A body cut short in the middle of a character: what
				// came before it is kept, and the cut is the error.
				if good > 0 {
					out = append(out, string(s.carry[:good]))
				}
				s.carry = nil
				return out, err
			}
			// The whole lines before the bad bytes are still the stream's.
			if i := bytes.LastIndexByte(s.carry[:good], '\n'); i >= 0 {
				out = append(out, string(s.carry[:i+1]))
			}
			return out, errNotUTF8
		}
		out = append(out, string(s.carry[:cut]))
		s.carry = s.carry[cut:]
	}
	if len(s.carry) == 0 {
		s.carry = nil
	}
	return out, err
}

// cut is the length of the next chunk in carry, 0 for none yet. At the
// end of the body nothing is held back.
func (s *splitter) cut(end bool) int {
	c := s.carry
	if len(c) == 0 {
		return 0
	}
	// The bound in bytes: max, or less where the text needs escaping.
	lim := s.max
	if f := encFit(c[:min(len(c), s.max)], s.enc); f < min(len(c), s.max) {
		lim = f
	}
	window := c
	if len(window) > lim {
		window = window[:lim]
	}
	if i := bytes.LastIndexByte(window, '\n'); i >= 0 {
		return i + 1
	}
	if len(c) < lim && !end {
		return 0
	}
	if len(c) <= lim && end {
		return len(c)
	}
	// No line end within the bound: cut before the character that
	// crosses it.
	k := len(window)
	if len(c) > k {
		for back := 0; back < utf8.UTFMax && k > 0 && !utf8.RuneStart(c[k]); back++ {
			k--
		}
	} else {
		// Exactly at the bound, the body not at its end: the last
		// character may be incomplete.
		for back := 1; back <= utf8.UTFMax && back <= k; back++ {
			if utf8.RuneStart(c[k-back]) {
				if !utf8.FullRune(c[k-back:]) {
					k -= back
				}
				break
			}
		}
	}
	if k == 0 {
		// Not text: let the caller's validation say so.
		return max(len(window), 1)
	}
	return k
}
