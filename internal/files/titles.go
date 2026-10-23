package files

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Titles in a file tree (§H.2): a file's or folder's name is its node's
// title, compared with its siblings' after NFC and, unless a tool is set
// to be case-sensitive, after Unicode simple case folding, as NTFS
// compares names (not full folding). The tree service's lookup (§B.5)
// and gateways (internal/dav's nameKey) compare titles alike.

// TitleKey is what titles are compared by (§H.2 "Siblings"): NFC, then,
// unless caseSensitive, Unicode simple case folding, a character for a
// character (FoldRune). Full folding would make "Maße" and "Masse", or
// "ﬁle" and "file", one name, which case-insensitive file systems keep
// apart.
func TitleKey(title string, caseSensitive bool) string {
	n := norm.NFC.String(title)
	if caseSensitive {
		return n
	}
	return norm.NFC.String(strings.Map(FoldRune, n))
}

// FoldRune is r's simple case folding, as a key: the least character of
// its orbit (unicode.SimpleFold), so k, K and the Kelvin sign are one.
func FoldRune(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	return least
}
