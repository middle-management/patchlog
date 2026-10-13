package derived

import (
	"net/url"
	"slices"
	"sort"
	"strings"
)

// CanonicalQuery is a query in the one form an index or tree service
// redirects to and answers 200 at (§A.5 "Canonical URLs"): "?" and the
// parameters of v but drop, sorted by name, then value, comparing their
// decoded UTF-8 bytes, each name and value with every byte other than
// ALPHA, DIGIT, "-", ".", "_" and "~" percent-encoded in uppercase hex (a
// space is %20, never +); "" if none is left. The order of a parameter's
// values is lost, so a repeatable parameter must not depend on it.
func CanonicalQuery(v url.Values, drop ...string) string {
	type param struct{ k, v string }
	var ps []param
	for k, vals := range v {
		if slices.Contains(drop, k) {
			continue
		}
		for _, x := range vals {
			ps = append(ps, param{k, x})
		}
	}
	if len(ps) == 0 {
		return ""
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].k != ps[j].k {
			return ps[i].k < ps[j].k
		}
		return ps[i].v < ps[j].v
	})
	var b strings.Builder
	for i, p := range ps {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		escapeTo(&b, p.k)
		b.WriteByte('=')
		escapeTo(&b, p.v)
	}
	return b.String()
}

// escapeTo writes s with every byte but the unreserved ones of RFC 3986
// percent-encoded in uppercase hex.
func escapeTo(b *strings.Builder, s string) {
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
}
