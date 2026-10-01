package jsonv

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf16"
)

// refWriteString is the byte-by-byte writer the bulk one replaced.
func refWriteString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xF])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// Canonical strings and parsing agree with the byte-by-byte forms on
// random strings mixing ASCII runs, escapes, control characters and
// multi-byte runes, and every canonical string parses back to itself.
func TestStringFastPaths(t *testing.T) {
	pieces := []string{"a", "plain ascii run ", `"`, `\`, "\n", "\t", "\x01", "\x1f", "é", "日本", "😀", "/", " ", " "}
	r := rand.New(rand.NewSource(1))
	for n := 0; n < 5000; n++ {
		var sb strings.Builder
		for k := r.Intn(12); k > 0; k-- {
			sb.WriteString(pieces[r.Intn(len(pieces))])
		}
		s := sb.String()
		var got, want bytes.Buffer
		writeString(&got, s)
		refWriteString(&want, s)
		if got.String() != want.String() {
			t.Fatalf("%q: wrote %s, want %s", s, got.String(), want.String())
		}
		back, err := Parse(got.Bytes())
		if err != nil || back != s {
			t.Fatalf("%q: parsed back %q, %v", s, back, err)
		}
	}
	// Escapes that the writer never produces still parse.
	for in, want := range map[string]string{`"a\/b"`: "a/b", `"éx"`: "éx", `"ab😀"`: "ab😀", `"xA"`: "xA"} {
		if got, err := Parse([]byte(in)); err != nil || got != want {
			t.Errorf("%s: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"\"ab\x01\"", `"abc`, "\"ab\xff\"", `"\ud83d"`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// The ASCII fast path of lessUTF16 orders as encoding both names does, on
// random names mixing ASCII, BMP runes above the surrogates, supplementary
// runes and invalid bytes.
func TestLessUTF16(t *testing.T) {
	ref := func(a, b string) bool {
		ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
		for i := 0; i < len(ua) && i < len(ub); i++ {
			if ua[i] != ub[i] {
				return ua[i] < ub[i]
			}
		}
		return len(ua) < len(ub)
	}
	pieces := []string{"a", "b", "A", "z", "~", "é", "", "￿", "😀", "\xc3", "\xff"}
	r := rand.New(rand.NewSource(2))
	gen := func() string {
		var sb strings.Builder
		for k := r.Intn(5); k > 0; k-- {
			sb.WriteString(pieces[r.Intn(len(pieces))])
		}
		return sb.String()
	}
	for n := 0; n < 20000; n++ {
		a, b := gen(), gen()
		if got, want := lessUTF16(a, b), ref(a, b); got != want {
			t.Fatalf("lessUTF16(%q, %q) = %v, want %v", a, b, got, want)
		}
	}
}
