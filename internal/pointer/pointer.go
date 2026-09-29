// Package pointer implements JSON Pointer (RFC 6901).
package pointer

import (
	"errors"
	"strconv"
	"strings"
)

// Pointer is a parsed, unescaped JSON Pointer. The root is an empty slice.
type Pointer []string

// ErrSyntax reports a malformed pointer.
var ErrSyntax = errors.New("malformed JSON pointer")

// Parse parses and unescapes s.
func Parse(s string) (Pointer, error) {
	if s == "" {
		return Pointer{}, nil
	}
	if s[0] != '/' {
		return nil, ErrSyntax
	}
	parts := strings.Split(s[1:], "/")
	for i, p := range parts {
		if strings.Contains(p, "~") {
			var b strings.Builder
			for j := 0; j < len(p); j++ {
				if p[j] != '~' {
					b.WriteByte(p[j])
					continue
				}
				if j+1 >= len(p) {
					return nil, ErrSyntax
				}
				switch p[j+1] {
				case '0':
					b.WriteByte('~')
				case '1':
					b.WriteByte('/')
				default:
					return nil, ErrSyntax
				}
				j++
			}
			parts[i] = b.String()
		}
	}
	return Pointer(parts), nil
}

// MustParse parses a pointer known to be valid.
func MustParse(s string) Pointer {
	p, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return p
}

// String escapes and formats the pointer.
func (p Pointer) String() string {
	var b strings.Builder
	for _, s := range p {
		b.WriteByte('/')
		s = strings.ReplaceAll(s, "~", "~0")
		s = strings.ReplaceAll(s, "/", "~1")
		b.WriteString(s)
	}
	return b.String()
}

// HasPrefix reports whether q is at or above p (q is a prefix of p),
// comparing unescaped segments.
func (p Pointer) HasPrefix(q Pointer) bool {
	if len(q) > len(p) {
		return false
	}
	for i := range q {
		if p[i] != q[i] {
			return false
		}
	}
	return true
}

// Overlaps reports whether p and q are at, above or below each other.
func (p Pointer) Overlaps(q Pointer) bool { return p.HasPrefix(q) || q.HasPrefix(p) }

// ArrayIndex parses an RFC 6901 array index token (no leading zeros).
func ArrayIndex(tok string) (int, bool) {
	if tok == "" || (len(tok) > 1 && tok[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(tok)
	return n, err == nil
}

// Get resolves p in doc.
func Get(doc any, p Pointer) (any, bool) {
	cur := doc
	for _, tok := range p {
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, ok := ArrayIndex(tok)
			if !ok || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}
