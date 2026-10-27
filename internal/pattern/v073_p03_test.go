package pattern

import (
	"regexp"
	"testing"
)

// §6.6: \uXXXX reads as \x{XXXX}, inside classes too, a surrogate pair as
// one code point, and never after an escaped backslash or inside \Q…\E.
func TestTranslate(t *testing.T) {
	for _, c := range []struct{ in, out string }{
		{`abc`, `abc`},
		{`^\u00e9$`, `^\x{00E9}$`},
		{`[\u00e0-\u00ff]+`, `[\x{00E0}-\x{00FF}]+`},
		{`[^\u005D]`, `[^\x{005D}]`},
		{`\uD83D\uDE00`, `\x{1F600}`},
		{`\ud83d\ude00x`, `\x{1F600}x`},
		{`\\u0041`, `\\u0041`},
		{`\\\u0041`, `\\\x{0041}`},
		{`\Q\u0041\E\u0041`, `\Q\u0041\E\x{0041}`},
		{`\Q\u0041`, `\Q\u0041`},
		{`\u{41}`, `\u{41}`},
		{`\u004`, `\u004`},
		{`\x{41}\d\.`, `\x{41}\d\.`},
		{`\x{FFFF}\x{10000}`, `\x{FFFF}\x{10000}`},
		{`a\`, `a\`},
	} {
		got, err := Translate(c.in)
		if err != nil || got != c.out {
			t.Errorf("Translate(%q) = %q, %v; want %q", c.in, got, err, c.out)
		}
	}
	for _, in := range []string{
		`\uD800`, `\uDC00`, `x\uDBFFy`, `\uD83D\u0041`, `\uD83D\uD83D`, `[\uDE00]`,
		`\x{D800}`, `\x{dfff}`, `[a\x{DC00}]`,
	} {
		if got, err := Translate(in); err == nil {
			t.Errorf("Translate(%q) = %q, want a lone-surrogate error", in, got)
		}
	}
}

func TestCompile(t *testing.T) {
	for _, c := range []struct {
		re, s string
		match bool
	}{
		{`^\u00e9$`, "é", true},
		{`^\u00e9$`, "e", false},
		{`^[\u00e0-\u00ff]+$`, "àéÿ", true},
		{`^[^\u005D]$`, "]", false},
		{`^\uD83D\uDE00$`, "😀", true},
		{`^\\u0041$`, `\u0041`, true},
		{`^\\u0041$`, "A", false},
		{`^\Q\u0041\E$`, `\u0041`, true},
	} {
		re, err := Compile(c.re)
		if err != nil {
			t.Errorf("Compile(%q): %v", c.re, err)
			continue
		}
		if re.MatchString(c.s) != c.match {
			t.Errorf("%q matching %q: got %v", c.re, c.s, !c.match)
		}
	}
	// What RE2 refuses stays refused: backreferences, lookaround, other \u.
	for _, re := range []string{`(a)\1`, `(?=a)`, `\u{41}`, `\u12`, `\uDE00`} {
		if _, err := Compile(re); err == nil {
			t.Errorf("Compile(%q) accepted", re)
		}
	}
	// Without \u or \x escapes, Translate is the identity.
	for _, re := range []string{`^[a-z]+$`, `(?i)x|y`, `\p{L}\d{2}\.\\`} {
		got, err := Translate(re)
		if err != nil || got != re {
			t.Errorf("Translate(%q) = %q, %v", re, got, err)
		}
		if _, err := regexp.Compile(got); err != nil {
			t.Errorf("%q: %v", re, err)
		}
	}
}
