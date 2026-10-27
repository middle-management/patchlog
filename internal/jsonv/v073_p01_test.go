package jsonv

import (
	"fmt"
	"testing"
	"unicode/utf16"
)

// nonchars are the 66 Unicode noncharacters (§3.1).
func nonchars() []rune {
	var out []rune
	for r := rune(0xFDD0); r <= 0xFDEF; r++ {
		out = append(out, r)
	}
	for plane := rune(0); plane <= 0x10; plane++ {
		out = append(out, plane<<16|0xFFFE, plane<<16|0xFFFF)
	}
	return out
}

// escaped writes r as a JSON \u escape, a surrogate pair above the BMP.
func escaped(r rune) string {
	if r < 0x10000 {
		return fmt.Sprintf(`\u%04x`, r)
	}
	hi, lo := utf16.EncodeRune(r)
	return fmt.Sprintf(`\u%04X\u%04X`, hi, lo)
}

// §3.1: request bodies refuse noncharacters, raw or escaped, in values and
// keys; stored data still parses with Parse.
func TestParseInputNoncharacters(t *testing.T) {
	nc := nonchars()
	if len(nc) != 66 {
		t.Fatalf("%d noncharacters, want 66", len(nc))
	}
	for _, r := range nc {
		if !Noncharacter(r) {
			t.Errorf("Noncharacter(U+%04X) = false", r)
		}
		for _, body := range []string{
			`"` + string(r) + `"`,
			`"` + escaped(r) + `"`,
			`{"a":["x` + escaped(r) + `y"]}`,
			`{"` + string(r) + `":1}`,
		} {
			if _, err := ParseInput([]byte(body)); err == nil {
				t.Errorf("ParseInput(%q) accepted U+%04X", body, r)
			}
			if _, err := Parse([]byte(body)); err != nil {
				t.Errorf("Parse(%q): %v", body, err)
			}
		}
	}
	// The surrogate-pair escape of U+1FFFE, written as JSON text.
	if _, err := ParseInput([]byte(`"\ud83f\udffe"`)); err == nil {
		t.Error(`ParseInput accepted "\ud83f\udffe" (U+1FFFE)`)
	}
	// Their neighbours are characters.
	for _, r := range []rune{0xFDCF, 0xFDF0, 0xFFFD, 0x1FFFD, 0x10FFFD, 0x10000, 'a'} {
		if Noncharacter(r) {
			t.Errorf("Noncharacter(U+%04X) = true", r)
		}
		for _, body := range []string{`"` + string(r) + `"`, `"` + escaped(r) + `"`} {
			if _, err := ParseInput([]byte(body)); err != nil {
				t.Errorf("ParseInput(%q): %v", body, err)
			}
		}
	}
	if Noncharacter(-1) || Noncharacter(0x110000|0xFFFE) {
		t.Error("Noncharacter outside the code space")
	}
	// Everything Parse refuses, ParseInput refuses too.
	for _, s := range []string{`{"a":1,"a":2}`, `"\ud800"`, "\"\xff\"", `1e400`, `9007199254740992`, ``} {
		if _, err := ParseInput([]byte(s)); err == nil {
			t.Errorf("ParseInput(%q) accepted", s)
		}
	}
}

// §7.2 (GB-21): media types compare ignoring case, with a charset naming
// UTF-8 the only parameter.
func TestMediaType(t *testing.T) {
	for _, ct := range []string{"application/json", "Application/JSON", "application/json; charset=utf-8", "application/json;charset=UTF-8",
		`application/json; charset="utf-8"`, "application/json ; Charset = Utf-8", "application/json;"} {
		if !MediaType(ct, "application/json") {
			t.Errorf("MediaType(%q) = false", ct)
		}
	}
	for _, ct := range []string{"", " ", "text/plain", "application/json-patch+json", "application/jsonx", "application/json; charset=latin1",
		"application/json; charset=utf8", "application/json; foo=bar", "application/json; charset=utf-8; foo=bar", "application/json, text/plain",
		"application/json; charset=utf-8; charset=latin1"} {
		if MediaType(ct, "application/json") {
			t.Errorf("MediaType(%q) = true", ct)
		}
	}
}
