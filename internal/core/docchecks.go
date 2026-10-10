package core

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// fromScratch reports whether a step's patch set may be as large as
// documentSize: a create, or a restore whose first operation is a root
// replace (§6.6). At E3 the patch set is sealed and its shape unknown, so
// every create and restore counts.
func fromScratch(s *stepState) bool {
	switch s.action {
	case "create":
		return true
	case "restore":
		if s.sealed {
			return true
		}
		ops, _ := s.raw.([]any)
		if len(ops) == 0 {
			return false
		}
		op, _ := ops[0].(map[string]any)
		return op["op"] == "replace" && op["path"] == ""
	}
	return false
}

// docShape is what step 4 measures of a resulting document (§6.6), read
// from its canonical form in one pass (shapeOf) rather than by walking the
// document once for each: its nesting depth (jsonv.Depth), the first
// string, member name or pointer over valueSize or pathSize, and whether
// any object has a $blob member (hasBlobMember).
type docShape struct {
	depth int
	bad   *Error
	blobs bool
}

// shapeOf measures a document from its canonical form (§3.1), which step 4
// computes for documentSize anyway. valueSize and pathSize measure strings
// and pointers as canonical JSON: a string's length there is the length of
// its token, quotes included, and the "~" and "/" of a member name, which
// a pointer escapes as two characters, appear in its token as themselves.
//
// It reports what a depth-first walk of the document finds visiting
// members in canonical order: the first value whose pointer or string is
// too long, below which the walk goes no further, unless a later member
// name of an object the walk is in is too long, which is reported instead.
func shapeOf(l Limits, canon []byte) docShape {
	s := shapeScan{l: l, b: canon}
	if len(canon) > 0 {
		s.value(0, 0)
	}
	return s.docShape
}

// shapeScan is shapeOf's state: the canonical form and the offset reached.
type shapeScan struct {
	docShape
	l Limits
	b []byte
	i int
}

// value scans the value at s.i, nested in depth containers, whose pointer
// is path bytes long as canonical JSON without its quotes. The walk of
// shapeOf reaches it only if nothing was found too long before it.
func (s *shapeScan) value(path, depth int) {
	walked := s.bad == nil
	if walked && path+2 > s.l.PathSize {
		s.bad = limitErr(413, fmt.Sprintf("a path is longer than %d bytes", s.l.PathSize))
		walked = false
	}
	switch s.b[s.i] {
	case '"':
		if n := s.str(); walked && n > s.l.ValueSize {
			s.bad = limitErr(413, fmt.Sprintf("a string is longer than %d bytes", s.l.ValueSize))
		}
	case '[':
		s.depth = max(s.depth, depth+1)
		s.i++
		if s.b[s.i] == ']' {
			s.i++
			return
		}
		for k := 0; ; k++ {
			s.value(path+1+decimalLen(k), depth+1)
			s.i++ // ',' or ']'
			if s.b[s.i-1] == ']' {
				return
			}
		}
	case '{':
		s.depth = max(s.depth, depth+1)
		s.i++
		if s.b[s.i] == '}' {
			s.i++
			return
		}
		// The walk measures the names of an object it reaches until one is
		// too long, whatever its members' values hold.
		names := walked
		for {
			start := s.i
			n := s.str()
			name := s.b[start:s.i]
			if names && n > s.l.ValueSize {
				s.bad = limitErr(413, fmt.Sprintf("a member name is longer than %d bytes", s.l.ValueSize))
				names = false
			}
			if string(name) == `"$blob"` {
				s.blobs = true
			}
			s.i++ // ':'
			s.value(path+1+n-2+bytes.Count(name, []byte("~"))+bytes.Count(name, []byte("/")), depth+1)
			s.i++ // ',' or '}'
			if s.b[s.i-1] == '}' {
				return
			}
		}
	default:
		// A number or a literal: canonical JSON has no space after it.
		for s.i < len(s.b) && s.b[s.i] != ',' && s.b[s.i] != ']' && s.b[s.i] != '}' {
			s.i++
		}
	}
}

// str skips the string token at s.i and returns its length. Canonical JSON
// escapes a quote inside a string with a backslash, and a backslash with
// another.
func (s *shapeScan) str() int {
	start := s.i
	j := start + 1
	for {
		j += bytes.IndexByte(s.b[j:], '"')
		k := j
		for s.b[k-1] == '\\' {
			k--
		}
		if (j-k)%2 == 0 {
			break
		}
		j++
	}
	s.i = j + 1
	return s.i - start
}

// decimalLen is the number of digits of k >= 0.
func decimalLen(k int) int {
	n := 1
	for k >= 10 {
		k /= 10
		n++
	}
	return n
}

var blobTypeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)

func blobErr(pointer, msg string) *Error {
	return apiErr(422, "blob", "message", msg, "pointer", pointer)
}

// checkBlobRefs finds the blob references of a document (§6.5, §7.8): the
// objects whose $blob member is a string, at any depth. Each must be
// well-formed, and there may be at most blobsPerDocument distinct blobs.
// Schema documents are not searched.
func checkBlobRefs(l Limits, doc any) *Error {
	if m, ok := doc.(map[string]any); ok {
		if s, ok := m["$schema"].(string); ok && schema.IsDialect(s) {
			return nil
		}
	}
	if !hasBlobMember(doc) {
		return nil
	}
	distinct := map[string]bool{}
	var bad *Error
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		if bad != nil {
			return
		}
		switch x := v.(type) {
		case []any:
			for i, e := range x {
				walk(e, ptr+"/"+strconv.Itoa(i))
			}
		case map[string]any:
			if id, ok := x["$blob"].(string); ok {
				if bad = checkBlobRef(x, id, ptr); bad == nil {
					distinct[id] = true
				}
				return
			}
			for k, e := range x {
				walk(e, ptr+"/"+ptrEscaper.Replace(k))
			}
		}
	}
	walk(doc, "")
	if bad != nil {
		return bad
	}
	if len(distinct) > l.BlobsPerDocument {
		return limitErr(422, fmt.Sprintf("more than %d blobs referenced", l.BlobsPerDocument))
	}
	return nil
}

// ptrEscaper escapes a member name as a JSON Pointer token.
var ptrEscaper = strings.NewReplacer("~", "~0", "/", "~1")

// hasBlobMember reports whether any object of a document has a $blob
// member: most documents have none, and are then not walked again with
// the pointers of their members (checkBlobRefs, blobRefsOf).
func hasBlobMember(v any) bool {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if hasBlobMember(e) {
				return true
			}
		}
	case map[string]any:
		if _, ok := x["$blob"]; ok {
			return true
		}
		for _, e := range x {
			if hasBlobMember(e) {
				return true
			}
		}
	}
	return false
}

func checkBlobRef(m map[string]any, id, ptr string) *Error {
	if _, err := ids.Parse(id); err != nil {
		return blobErr(ptr, "$blob must be a blob id")
	}
	for k := range m {
		switch k {
		case "$blob", "type", "size", "nonce":
		default:
			return blobErr(ptr, fmt.Sprintf("a blob reference has no member %q", k))
		}
	}
	if t, ok := m["type"].(string); !ok || !blobTypeRe.MatchString(t) {
		return blobErr(ptr, "a blob reference needs a lowercase type/subtype without parameters")
	}
	if n, ok := m["size"].(float64); !ok || n < 0 || n != math.Trunc(n) || n > 1<<53 {
		return blobErr(ptr, "a blob reference needs a size, a non-negative integer")
	}
	if x, has := m["nonce"]; has {
		if n, ok := x.(string); !ok || !seal.ValidNonce(n) {
			return blobErr(ptr, "a blob reference's nonce must be 26 base32 characters")
		}
	}
	// Availability (§7.8), also at step 4, needs the store: checkBlobs
	// (blobs.go) runs right after the limits.
	return nil
}
