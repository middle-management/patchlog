package dav

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// Titles (§H.2): Unicode, 1 to 255 bytes of UTF-8, not . or .., without
// /, \, NUL, Cc, Cf, Zl and Zp, and here without a trailing space or dot.
func TestTitleRules(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"Report.json", "Match report 2026.md", "日本語", ".hidden", "a", "x copy.md", "untitled folder", strings.Repeat("é", 127)} {
		if why := titleWhy(ok); why != "" {
			t.Errorf("titleWhy(%q) = %q", ok, why)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", "a\x00b", "tab\there", "zero​width", "line ", "para ", "end.", "end ",
		strings.Repeat("x", 256), "\xff.md"} {
		if titleWhy(bad) == "" {
			t.Errorf("titleWhy(%q) takes it", bad)
		}
	}
	if got, err := newTitle("Résumé.txt"); err != nil || got != "Résumé.txt" {
		t.Errorf("newTitle of NFD = %q, %v", got, err)
	}
}

// A title another tool wrote that breaks the rules is shown escaped, a
// valid name, within 255 bytes.
func TestShownTitles(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Report.json": "Report.json", "a/b\\c": "a%2Fb%5Cc", ".": "%2E", "..": "%2E%2E", "x.": "x%2E", "x ": "x%20", "tab\there": "tab%09here",
		"Résumé": "Résumé", "\xffx": "%FFx", "": "", strings.Repeat("a", 300): strings.Repeat("a", 255),
		strings.Repeat("a", 254) + ".b": strings.Repeat("a", 254),
	} {
		got := shown(in)
		if got != want {
			t.Errorf("shown(%q) = %q, want %q", in, got, want)
		}
		if got != "" && titleWhy(got) != "" {
			t.Errorf("shown(%q) = %q, which breaks the rules: %s", in, got, titleWhy(got))
		}
	}
}

// Siblings' names compare after NFC and, unless case-sensitive, case
// folding.
func TestNameKeys(t *testing.T) {
	t.Parallel()
	folding, exact := &Server{}, &Server{opt: Options{CaseSensitive: true}}
	for _, p := range [][2]string{{"Notes.MD", "notes.md"}, {"Résumé", "résumé"}, {"STRASSE", "straße"}} {
		if folding.nameKey(p[0]) != folding.nameKey(p[1]) {
			t.Errorf("%q and %q differ, folded", p[0], p[1])
		}
	}
	if exact.nameKey("Notes.md") == exact.nameKey("notes.md") {
		t.Error("case-sensitive names compare equal under another case")
	}
	if exact.nameKey("Résumé") != exact.nameKey("Résumé") {
		t.Error("NFD and NFC differ, case-sensitive")
	}
	if n := newName(); len(n) != 13 || strings.Trim(n, "abcdefghijklmnopqrstuvwxyz234567") != "" || !folderName(n) {
		t.Errorf("newName %q", n)
	}
}

// An order key after k sorts after it (§B.2), of the digits catalogs'
// rules allow, as short as k unless k ends in z.
func TestKeyAfter(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"": "a0", "a0": "a1", "a9": "aA", "az": "b0", "a0z": "a10", "zz": "zzV", "a1V": "a1W",
		"a~": "b", "a-": "a0", "a_x": "aa", "z~": ""} {
		if got := keyAfter(in); got != want {
			t.Errorf("keyAfter(%q) = %q, want %q", in, got, want)
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		b := make([]byte, 1+r.IntN(6))
		for i := range b {
			b[i] = byte(0x21 + r.IntN(0x5e))
		}
		k := string(b)
		got := keyAfter(k)
		if got == "" {
			continue
		}
		if got <= k || strings.Trim(got, orderDigits) != "" {
			t.Fatalf("keyAfter(%q) = %q", k, got)
		}
	}
}
