// Package jsonv is the JSON value model shared by the whole server: strict
// I-JSON parsing (RFC 7493, §3.1), JCS canonical serialisation (RFC 8785) and
// RFC 6902 value equality.
//
// Values are plain Go values: nil, bool, float64, string, []any and
// map[string]any. Numbers are IEEE doubles, which is what JCS serialises.
// The bundle importer also holds values as their canonical bytes (Raw,
// whose contract says which functions take one).
package jsonv

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger is 2^53-1, the I-JSON integer bound.
const MaxSafeInteger = 1<<53 - 1

// maxParseDepth guards the recursive parser. Document nesting limits (§6.6)
// are enforced separately and are much lower.
const maxParseDepth = 1000

// SyntaxError reports input that is not I-JSON.
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("invalid JSON at byte %d: %s", e.Offset, e.Msg)
}

// Parse parses exactly one I-JSON value. It rejects duplicate object keys,
// lone surrogates, invalid UTF-8, non-finite numbers and integer literals
// outside ±(2^53−1).
func Parse(data []byte) (any, error) {
	p := &parser{b: data}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, p.err("trailing data")
	}
	return v, nil
}

type parser struct {
	b []byte
	i int
}

func (p *parser) err(msg string) error { return &SyntaxError{Offset: p.i, Msg: msg} }

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxParseDepth {
		return nil, p.err("nesting too deep")
	}
	if p.i >= len(p.b) {
		return nil, p.err("unexpected end of input")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return true, p.lit("true")
	case c == 'f':
		return false, p.lit("false")
	case c == 'n':
		return nil, p.lit("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.err(fmt.Sprintf("unexpected character %q", c))
	}
}

func (p *parser) lit(s string) error {
	if !bytes.HasPrefix(p.b[p.i:], []byte(s)) {
		return p.err("invalid literal")
	}
	p.i += len(s)
	return nil
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // {
	m := map[string]any{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, p.err("expected object key")
		}
		at := p.i
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, &SyntaxError{Offset: at, Msg: fmt.Sprintf("duplicate key %q", k)}
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, p.err("expected ':'")
		}
		p.i++
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		m[k] = v
		p.ws()
		if p.i >= len(p.b) {
			return nil, p.err("unexpected end of input")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return m, nil
		default:
			return nil, p.err("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.i++ // [
	a := []any{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return a, nil
	}
	for {
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.ws()
		if p.i >= len(p.b) {
			return nil, p.err("unexpected end of input")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return a, nil
		default:
			return nil, p.err("expected ',' or ']'")
		}
	}
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.b) {
		return 0, p.err("short \\u escape")
	}
	var r rune
	for k := 0; k < 4; k++ {
		h, ok := hexVal(p.b[p.i+k])
		if !ok {
			return 0, p.err("invalid \\u escape")
		}
		r = r<<4 | h
	}
	p.i += 4
	return r, nil
}

func (p *parser) str() (string, error) {
	p.i++ // "
	// Fast path: plain ASCII up to the closing quote is the string itself.
	start := p.i
	for p.i < len(p.b) {
		c := p.b[p.i]
		if c == '"' {
			s := string(p.b[start:p.i])
			p.i++
			return s, nil
		}
		if c == '\\' || c < 0x20 || c >= utf8.RuneSelf {
			break
		}
		p.i++
	}
	sb := append([]byte(nil), p.b[start:p.i]...)
	for {
		if p.i >= len(p.b) {
			return "", p.err("unterminated string")
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(sb), nil
		case c == '\\':
			p.i++
			if p.i >= len(p.b) {
				return "", p.err("unterminated escape")
			}
			e := p.b[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				sb = append(sb, e)
			case 'b':
				sb = append(sb, '\b')
			case 'f':
				sb = append(sb, '\f')
			case 'n':
				sb = append(sb, '\n')
			case 'r':
				sb = append(sb, '\r')
			case 't':
				sb = append(sb, '\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 || p.i+6 > len(p.b) || p.b[p.i] != '\\' || p.b[p.i+1] != 'u' {
						return "", p.err("lone surrogate")
					}
					p.i += 2
					r2, err := p.hex4()
					if err != nil {
						return "", err
					}
					if r2 < 0xDC00 || r2 > 0xDFFF {
						return "", p.err("lone surrogate")
					}
					r = utf16.DecodeRune(r, r2)
				}
				sb = utf8.AppendRune(sb, r)
			default:
				return "", p.err("invalid escape")
			}
		case c < 0x20:
			return "", p.err("control character in string")
		case c < utf8.RuneSelf:
			sb = append(sb, c)
			p.i++
		default:
			r, size := utf8.DecodeRune(p.b[p.i:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.err("invalid UTF-8")
			}
			sb = append(sb, p.b[p.i:p.i+size]...)
			p.i += size
		}
	}
}

func (p *parser) number() (any, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.b) && p.b[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		return nil, p.err("invalid number")
	}
	if p.i < len(p.b) && p.b[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return nil, p.err("invalid number")
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, p.err("invalid number")
		}
	}
	lit := string(p.b[start:p.i])
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, &SyntaxError{Offset: start, Msg: "number out of range"}
	}
	if UnsafeInteger(f) {
		return nil, &SyntaxError{Offset: start, Msg: "integer outside ±(2^53−1)"}
	}
	return f, nil
}

// UnsafeInteger reports whether f's canonical form (JCS) is an integer
// literal outside ±(2^53−1): an integral value with 2^53 ≤ |f| < 10^21,
// however it was written (§3.1). Larger values serialise with an exponent
// and are accepted, so a stored patch set is always accepted again.
func UnsafeInteger(f float64) bool {
	a := math.Abs(f)
	return a > MaxSafeInteger && a < 1e21 && a == math.Trunc(a)
}

// Canonical returns the RFC 8785 (JCS) serialisation of v, UTF-8 encoded.
// v must be a value of the model; ints are accepted for convenience.
func Canonical(v any) []byte {
	// A pooled buffer keeps its capacity, so a large document is written
	// without growing (reallocating and copying) the buffer again and
	// again; the result is one exact-size copy.
	b := canonBufs.Get().(*bytes.Buffer)
	b.Reset()
	writeCanonical(b, v)
	out := bytes.Clone(b.Bytes())
	if b.Cap() <= maxPooledCanon {
		canonBufs.Put(b)
	}
	return out
}

// CanonicalOf is Canonical of a value IsValue accepts, checked as it is
// written in one pass; ok is false, and nothing returned, for any other.
func CanonicalOf(v any) (canon []byte, ok bool) {
	b := canonBufs.Get().(*bytes.Buffer)
	b.Reset()
	if ok = writeChecked(b, v, 0); ok {
		canon = bytes.Clone(b.Bytes())
	}
	if b.Cap() <= maxPooledCanon {
		canonBufs.Put(b)
	}
	return canon, ok
}

func writeChecked(b *bytes.Buffer, v any, depth int) bool {
	switch x := v.(type) {
	case nil, bool:
		writeCanonical(b, x)
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) || UnsafeInteger(x) {
			return false
		}
		b.WriteString(FormatNumber(x))
	case string:
		if !utf8.ValidString(x) {
			return false
		}
		writeString(b, x)
	case []any:
		if depth >= maxParseDepth {
			return false
		}
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if !writeChecked(b, e, depth+1) {
				return false
			}
		}
		b.WriteByte(']')
	case map[string]any:
		if depth >= maxParseDepth {
			return false
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return false
			}
			keys = append(keys, k)
		}
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if !writeChecked(b, x[k], depth+1) {
				return false
			}
		}
		b.WriteByte('}')
	case Raw:
		if x == nil {
			return false
		}
		b.Write(x) // canonical already, by its contract
	default:
		return false
	}
	return true
}

// maxPooledCanon bounds the buffers kept for reuse (documents are at most a
// few MiB, §6.6).
const maxPooledCanon = 8 << 20

var canonBufs = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func writeCanonical(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case float64:
		b.WriteString(FormatNumber(x))
	case int:
		b.WriteString(FormatNumber(float64(x)))
	case int64:
		b.WriteString(FormatNumber(float64(x)))
	case string:
		writeString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, e)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			writeCanonical(b, x[k])
		}
		b.WriteByte('}')
	case Raw:
		if x == nil {
			panic("jsonv: nil Raw")
		}
		b.Write(x) // canonical already, by its contract
	default:
		panic(fmt.Sprintf("jsonv: unsupported type %T", v))
	}
}

// sortUTF16 sorts strings by their UTF-16 code units, as JCS requires.
func sortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
}

func lessUTF16(a, b string) bool {
	// Most member names differ first at an ASCII byte, after a common
	// prefix that decodes the same in both (an ASCII byte ends any
	// sequence before it): their order is that byte's. Encoding both names
	// at every comparison was most of the cost of canonicalising.
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	switch {
	case i < len(a) && i < len(b):
		if a[i] < utf8.RuneSelf && b[i] < utf8.RuneSelf {
			return a[i] < b[i]
		}
	case i == len(a) && i == len(b):
		return false
	case i == len(a):
		if b[i] < utf8.RuneSelf {
			return true
		}
	default:
		if a[i] < utf8.RuneSelf {
			return false
		}
	}
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		// Copy the run of bytes that need no escaping in one go: byte by
		// byte, canonicalising a large document was most of a write's cost.
		j := i
		for j < len(s) && s[j] >= 0x20 && s[j] != '"' && s[j] != '\\' {
			j++
		}
		if j > i {
			b.WriteString(s[i:j])
			if i = j; i == len(s) {
				break
			}
		}
		c := s[i]
		switch {
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

// FormatNumber serialises a double as ECMAScript Number.prototype.toString
// does, which is what RFC 8785 prescribes.
func FormatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		panic("jsonv: non-finite number")
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip digits in scientific form: d.ddde±x
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := cutByte(s, 'e')
	exp, _ := strconv.Atoi(expStr)
	digits := make([]byte, 0, len(mant))
	for i := 0; i < len(mant); i++ {
		if mant[i] != '.' {
			digits = append(digits, mant[i])
		}
	}
	k := len(digits)
	n := exp + 1
	var out []byte
	switch {
	case k <= n && n <= 21:
		out = append(digits, bytes.Repeat([]byte{'0'}, n-k)...)
	case 0 < n && n <= 21:
		out = append(append(append([]byte{}, digits[:n]...), '.'), digits[n:]...)
	case -6 < n && n <= 0:
		out = append(append([]byte("0."), bytes.Repeat([]byte{'0'}, -n)...), digits...)
	default:
		e := n - 1
		es := "+"
		if e < 0 {
			es = "-"
			e = -e
		}
		out = append(out, digits[0])
		if k > 1 {
			out = append(out, '.')
			out = append(out, digits[1:]...)
		}
		out = append(out, 'e')
		out = append(out, es...)
		out = strconv.AppendInt(out, int64(e), 10)
	}
	return sign + string(out)
}

func cutByte(s string, c byte) (string, string, bool) {
	if i := bytes.IndexByte([]byte(s), c); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// Equal is RFC 6902 value equality: numbers by value, objects unordered. A
// Raw is compared as the value it holds.
func Equal(a, b any) bool {
	if r, ok := a.(Raw); ok {
		a = r.parsed()
	}
	if r, ok := b.(Raw); ok {
		b = r.parsed()
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !Equal(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// IsValue reports whether v is already a value of the model, one Parse
// could have returned: nil, bool, finite float64 (no integer outside
// ±(2^53−1)), valid UTF-8 strings, and []any and map[string]any of
// values, nested at most as deep as Parse allows; or a non-nil Raw, which
// holds one in canonical form, taken on its contract (it isn't parsed, and
// its own nesting isn't counted). A value a client builds from parsed
// values needs no round trip through JSON text.
func IsValue(v any) bool { return isValue(v, 0) }

func isValue(v any, depth int) bool {
	switch x := v.(type) {
	case nil, bool:
		return true
	case Raw:
		return x != nil
	case float64:
		return !math.IsInf(x, 0) && !math.IsNaN(x) && !UnsafeInteger(x)
	case string:
		return utf8.ValidString(x)
	case []any:
		if depth >= maxParseDepth {
			return false
		}
		for _, e := range x {
			if !isValue(e, depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		if depth >= maxParseDepth {
			return false
		}
		for k, e := range x {
			if !utf8.ValidString(k) || !isValue(e, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// Clone deep-copies a value. A Raw is shared: it is never modified.
func Clone(v any) any {
	switch x := v.(type) {
	case []any:
		c := make([]any, len(x))
		for i, e := range x {
			c[i] = Clone(e)
		}
		return c
	case map[string]any:
		c := make(map[string]any, len(x))
		for k, e := range x {
			c[k] = Clone(e)
		}
		return c
	}
	return v
}

// Depth is the nesting depth of v: 0 for scalars, 1 for an empty or flat
// container, and so on; a Raw's is that of the value it holds.
func Depth(v any) int {
	d := 0
	switch x := v.(type) {
	case Raw:
		return Depth(x.parsed())
	case []any:
		for _, e := range x {
			if c := Depth(e); c > d {
				d = c
			}
		}
		return d + 1
	case map[string]any:
		for _, e := range x {
			if c := Depth(e); c > d {
				d = c
			}
		}
		return d + 1
	}
	return 0
}

// MustParse parses canonical bytes the server wrote itself.
func MustParse(data []byte) any {
	v, err := Parse(data)
	if err != nil {
		panic(err)
	}
	return v
}

// FromGo converts a value built from Go literals (ints, []string,
// map[string]string, …) into the model by a canonical round trip. A Raw
// becomes the value it holds.
func FromGo(v any) any {
	return normalize(v)
}

func normalize(v any) any {
	switch x := v.(type) {
	case nil, bool, float64, string:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case []any:
		c := make([]any, len(x))
		for i, e := range x {
			c[i] = normalize(e)
		}
		return c
	case []string:
		c := make([]any, len(x))
		for i, e := range x {
			c[i] = e
		}
		return c
	case map[string]any:
		c := make(map[string]any, len(x))
		for k, e := range x {
			c[k] = normalize(e)
		}
		return c
	case map[string]string:
		c := make(map[string]any, len(x))
		for k, e := range x {
			c[k] = e
		}
		return c
	case Raw:
		return x.parsed()
	}
	panic(fmt.Sprintf("jsonv: cannot normalise %T", v))
}
