package dav

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Names in a file tree (§H.2): a file's or folder's name is its node's
// title, Unicode a person gave it, compared with its siblings' after NFC
// and, unless the server is case-sensitive (Options.CaseSensitive), after
// case folding, as the file systems of Finder's and Explorer's users do.

// maxTitle bounds a title's UTF-8 (§H.2 "Titles").
const maxTitle = 255

// titleWhy says why name can't be given to a file or folder in a tree
// (§H.2 "Titles"), "" if it can: it must be UTF-8 (NFC is the caller's,
// which normalises), 1 to 255 bytes of it, not . or .., without /, \,
// NUL, or characters of Cc, Cf, Zl and Zp; and, since Windows drops them,
// without a trailing space or dot.
func titleWhy(name string) string {
	switch {
	case !utf8.ValidString(name):
		return "it isn't UTF-8"
	case name == "":
		return "it is empty"
	case len(name) > maxTitle:
		return fmt.Sprintf("it is %d bytes of UTF-8, over %d", len(name), maxTitle)
	case name == "." || name == "..":
		return "it is . or .."
	case strings.HasSuffix(name, " ") || strings.HasSuffix(name, "."):
		return "it ends in a space or a dot, which Windows drops"
	}
	for _, r := range name {
		if badTitleRune(r) {
			return fmt.Sprintf("it holds %U, and titles hold no /, \\, NUL, control or format characters, nor line or paragraph separators", r)
		}
	}
	return ""
}

func badTitleRune(r rune) bool {
	return r == '/' || r == '\\' || r == 0 || unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}

// newTitle is the title a file or folder named name is given: name in NFC,
// refused (403) if it breaks the rules (titleWhy).
func newTitle(name string) (string, error) {
	t := norm.NFC.String(name)
	if why := titleWhy(t); why != "" {
		return "", fail(http.StatusForbidden, "%q can't name a file or folder here: %s; a name in a file tree is 1 to 255 bytes of UTF-8, not . or .., without /, \\, NUL or control characters, and doesn't end in a space or a dot (§H.2)", name, why)
	}
	return t, nil
}

// shown is a title as a file name (§H.2 "Titles"): as it is if it keeps
// the rules, else escaped, so a title another tool wrote never corrupts a
// listing. Escaped, it is in NFC, its invalid bytes and the characters
// titles can't hold are %XX of their UTF-8, as are a lone . or .. and a
// trailing space or dot, within 255 bytes. "" for "": the caller shows
// the node by another name.
func shown(title string) string {
	if title == "" || titleWhy(title) == "" && norm.NFC.IsNormalString(title) {
		return title
	}
	var valid strings.Builder
	for i := 0; i < len(title); {
		r, n := utf8.DecodeRuneInString(title[i:])
		if r == utf8.RuneError && n == 1 {
			fmt.Fprintf(&valid, "%%%02X", title[i])
		} else {
			valid.WriteString(title[i : i+n])
		}
		i += n
	}
	var toks []string
	for _, r := range norm.NFC.String(valid.String()) {
		if badTitleRune(r) {
			toks = append(toks, pct(string(r)))
		} else {
			toks = append(toks, string(r))
		}
	}
	for n := len(toks); ; {
		out, taken := "", 0
		for _, t := range toks[:n] {
			if len(out)+len(t) > maxTitle {
				break
			}
			out += t
			taken++
		}
		switch {
		case out == "." || out == "..":
			return pct(out)
		case strings.HasSuffix(out, " ") || strings.HasSuffix(out, "."):
			esc := out[:len(out)-1] + pct(out[len(out)-1:])
			if len(esc) <= maxTitle {
				return esc
			}
			// The escape doesn't fit: one character fewer.
			n = taken - 1
			continue
		}
		return out
	}
}

// pct is s as %XX of its bytes.
func pct(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// nameKey is what sibling names are compared by (§H.2 "Siblings"): NFC,
// then, unless names are case-sensitive here, Unicode case folding.
func (s *Server) nameKey(name string) string {
	n := norm.NFC.String(name)
	if s.opt.CaseSensitive {
		return n
	}
	return norm.NFC.String(cases.Fold().String(n))
}

// newName is an opaque resource name for a new item or folder node
// (§H.2): 13 random base32 characters, lowercase, without a dot.
func newName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("dav: random: " + err.Error())
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// orderDigits are the characters order keys are made of, ascending by
// code unit (§B.2 "order"; §B.6's rule allows them).
const orderDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// keyAfter is an order key (§B.2) after k, of orderDigits, no longer than
// k but where k ends in z ("" for none: "a0"); "" where none fits in 64
// characters, the node then listed after the ordered ones.
func keyAfter(k string) string {
	if k == "" {
		return "a0"
	}
	next := func(c byte) byte { return orderDigits[strings.IndexByte(orderDigits, c)+1] }
	// bump returns p with its last digit below z one higher, the rest
	// dropped; "" if p is all z.
	bump := func(p string) string {
		for j := len(p) - 1; j >= 0; j-- {
			if p[j] != 'z' {
				return p[:j] + string(next(p[j]))
			}
		}
		return ""
	}
	i := 0
	for i < len(k) && strings.IndexByte(orderDigits, k[i]) >= 0 {
		i++
	}
	var out string
	switch {
	case i == len(k):
		// All digits: one higher, as a number of k's length, else longer.
		if b := bump(k); b != "" {
			out = b + strings.Repeat("0", len(k)-len(b))
		} else {
			out = k + "V"
		}
	default:
		// A character no digit is: the smallest digit above it, else a
		// digit above one before it.
		c := k[i]
		if j := strings.IndexFunc(orderDigits, func(r rune) bool { return byte(r) > c }); j >= 0 {
			out = k[:i] + orderDigits[j:j+1]
		} else {
			out = bump(k[:i])
		}
	}
	if len(out) > 64 {
		return ""
	}
	return out
}
