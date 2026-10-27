// Package pattern reads the regular expressions of rules, grants, key
// scopes and schemas as §6.6 says: RE2 syntax and semantics, with
// \uXXXX read as \x{XXXX}, a surrogate pair of such escapes as the one
// code point it encodes, and a lone surrogate as a pattern RE2 doesn't
// accept.
package pattern

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Translate rewrites re for Go's regexp package (RE2): every \uXXXX
// escape, inside character classes too, becomes \x{XXXX}, and a high
// surrogate escape followed by a low one becomes the code point they
// encode. An escaped backslash is copied as it is, so \\u0041 stays a
// backslash followed by "u0041", and so is \Q…\E literal text. A lone
// surrogate, written as \uXXXX or as \x{XXXX}, is an error (§6.6). Any
// other \u is left for RE2 to refuse, ECMAScript's \u{…} included.
func Translate(re string) (string, error) {
	if !strings.Contains(re, `\`) {
		return re, nil
	}
	var b strings.Builder
	b.Grow(len(re) + 8)
	for i := 0; i < len(re); {
		if re[i] != '\\' || i+1 == len(re) {
			b.WriteByte(re[i])
			i++
			continue
		}
		switch re[i+1] {
		case 'u':
			r, ok := hex4(re, i+2)
			if !ok {
				b.WriteString(`\u`)
				i += 2
				continue
			}
			j := i + 6
			if utf16.IsSurrogate(r) {
				lo, ok := rune(0), false
				if r < 0xDC00 && strings.HasPrefix(re[j:], `\u`) {
					lo, ok = hex4(re, j+2)
					ok = ok && lo >= 0xDC00 && lo <= 0xDFFF
				}
				if !ok {
					return "", fmt.Errorf("lone surrogate %s in regular expression", re[i:j])
				}
				r = utf16.DecodeRune(r, lo)
				j += 6
			}
			fmt.Fprintf(&b, `\x{%04X}`, r)
			i = j
		case 'x':
			if v, n, ok := braced(re, i+2); ok && v >= 0xD800 && v <= 0xDFFF {
				return "", fmt.Errorf("lone surrogate %s in regular expression", re[i:n])
			}
			b.WriteString(re[i : i+2])
			i += 2
		case 'Q':
			// Literal text up to \E, or to the end (RE2).
			n := len(re)
			if k := strings.Index(re[i+2:], `\E`); k >= 0 {
				n = i + 2 + k + 2
			}
			b.WriteString(re[i:n])
			i = n
		default:
			b.WriteString(re[i : i+2])
			i += 2
		}
	}
	return b.String(), nil
}

// Compile is regexp.Compile of re as Translate rewrites it.
func Compile(re string) (*regexp.Regexp, error) {
	t, err := Translate(re)
	if err != nil {
		return nil, err
	}
	return regexp.Compile(t)
}

// hex4 reads the four hex digits at re[i:].
func hex4(re string, i int) (rune, bool) {
	if i+4 > len(re) {
		return 0, false
	}
	v, err := strconv.ParseUint(re[i:i+4], 16, 32)
	return rune(v), err == nil
}

// braced reads the value of the {hex} at re[i:], as \x{…} takes it, and
// the index just past its "}".
func braced(re string, i int) (v uint64, end int, ok bool) {
	if i >= len(re) || re[i] != '{' {
		return 0, 0, false
	}
	k := strings.IndexByte(re[i:], '}')
	if k < 2 {
		return 0, 0, false
	}
	v, err := strconv.ParseUint(re[i+1:i+k], 16, 32)
	return v, i + k + 1, err == nil
}
