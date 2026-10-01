package core

import (
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

// canonStringLen is the length of s as canonical JSON, quotes included.
func canonStringLen(s string) int {
	n := 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"', c == '\\', c == '\b', c == '\f', c == '\n', c == '\r', c == '\t':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
	}
	return n
}

// checkValuesAndPaths enforces valueSize and pathSize on a document (§6.6):
// the largest string, member names included, and the longest JSON Pointer to
// any value, both measured as canonical JSON.
func checkValuesAndPaths(l Limits, doc any) *Error {
	var bad *Error
	var walk func(v any, path int)
	// path is the canonical JSON length of the pointer to v, without quotes.
	walk = func(v any, path int) {
		if bad != nil {
			return
		}
		if path+2 > l.PathSize {
			bad = limitErr(413, fmt.Sprintf("a path is longer than %d bytes", l.PathSize))
			return
		}
		switch x := v.(type) {
		case string:
			if canonStringLen(x) > l.ValueSize {
				bad = limitErr(413, fmt.Sprintf("a string is longer than %d bytes", l.ValueSize))
			}
		case []any:
			for i, e := range x {
				walk(e, path+1+len(strconv.Itoa(i)))
			}
		case map[string]any:
			for k, e := range x {
				n := canonStringLen(k)
				if n > l.ValueSize {
					bad = limitErr(413, fmt.Sprintf("a member name is longer than %d bytes", l.ValueSize))
					return
				}
				// "~" and "/" are escaped as two characters in a pointer.
				walk(e, path+1+n-2+strings.Count(k, "~")+strings.Count(k, "/"))
			}
		}
	}
	walk(doc, 0)
	return bad
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
				walk(e, ptr+"/"+strings.NewReplacer("~", "~0", "/", "~1").Replace(k))
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
	// TODO(blobs): availability (§7.8) is checked here, at step 4: the blob
	// must be attached to this resource, pending for this uploader, or
	// readable through a base or a batch source, and match its type, size
	// and nonce (422, code "blob"). Until blobs exist, a well-formed
	// reference to an unknown blob is accepted.
	return nil
}
