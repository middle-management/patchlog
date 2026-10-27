package dav

import (
	"strings"
	"testing"
)

// Spec v0.73, Addendum H (gateways): names.

// Scratch names (§H.6) include LibreOffice's lock files (.~lock.*#), vim's
// other swap files (*.swo, *.swx) and sed -i's temporary file (sed and six
// letters or digits), besides those before v0.56 (GW-13).
func TestV073ScratchNamesAdded(t *testing.T) {
	t.Parallel()
	for _, n := range []string{".~lock.report.odt#", ".~lock.#", "a.swo", ".notes.md.swx", ".swo", "sedAb12cd", "sed000000", "sedZZZZZZ",
		".DS_Store", "x.swp", "4913", "x~", "#x#", "Icon\r"} {
		if !scratchName(n) {
			t.Errorf("scratchName(%q) = false", n)
		}
	}
	for _, n := range []string{".~lock.x", ".~lock.", "~lock.x#", "a.swo.txt", "a.swox", "sed12345", "sedabcdefg", "sed-abcde", "sedé12345",
		"Sedabcdef", "xsedabcdef", "sed", "notes.md"} {
		if scratchName(n) {
			t.Errorf("scratchName(%q) = true", n)
		}
	}
}

// Titles exclude Cc, Zl, Zp and, of Cf, only the bidirectional controls
// U+202A–U+202E and U+2066–U+2069: joiners, soft hyphens, LRM and RLM and
// other format characters are allowed, and a title holding them is shown
// as it is, not escaped (§H.2 "Titles", GW-15).
func TestV073TitleFormatCharacters(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"a\u200db.txt", "a\u200cb", "co\u00adop.md", "a\u200eb", "a\u200fb", "\ufeffbom", "x\u2060y", "\U000e0001tag"} {
		if why := titleWhy(ok); why != "" {
			t.Errorf("titleWhy(%q) = %q", ok, why)
		}
		if got := shown(ok); got != ok {
			t.Errorf("shown(%q) = %q", ok, got)
		}
		if got, err := newTitle(ok); err != nil || got != ok {
			t.Errorf("newTitle(%q) = %q, %v", ok, got, err)
		}
	}
	for r := rune(0x202a); r <= 0x2069; r++ {
		if r == 0x202f {
			r = 0x2066
		}
		title := "a" + string(r) + "b"
		if titleWhy(title) == "" {
			t.Errorf("titleWhy(%q) takes U+%04X", title, r)
		}
		if got := shown(title); got != "a"+pct(string(r))+"b" {
			t.Errorf("shown(%q) = %q", title, got)
		}
		if _, err := newTitle(title); err == nil || !strings.Contains(err.Error(), "bidirectional") {
			t.Errorf("newTitle(%q) = %v", title, err)
		}
	}
	// The rest of Cf's neighbours stay allowed: U+202F (a space, Zs) and
	// U+2065 (unassigned) aren't controls.
	for _, ok := range []string{"a\u202fb", "a\u2065b"} {
		if why := titleWhy(ok); why != "" {
			t.Errorf("titleWhy(%q) = %q", ok, why)
		}
	}
}
