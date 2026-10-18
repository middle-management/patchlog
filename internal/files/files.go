// Package files holds what tools that show namespaces as files share
// (Addendum H): the rendering of a JSON file (§H.1), and the metadata a
// listing gives a file (§H.3). The tree service and gateways compute them
// alike, so every tool shows a document as the same bytes.
package files

import (
	"bytes"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
)

// JSONType is the type of a JSON file (§H.1).
const JSONType = "application/json"

// Rendering is what a JSON file reads as (§H.1): the canonical JSON text
// (§3.1) of doc without a top-level $nonce of the fresh form (§6.4.1) or
// $successor of the form of §8.1, laid out by Layout. $schema stays. doc
// is a parsed document (jsonv values) and is not modified.
func Rendering(doc any) []byte {
	if m, ok := doc.(map[string]any); ok {
		drop := 0
		for _, k := range [...]string{"$nonce", "$successor"} {
			if v, has := m[k]; has && schema.LeftOut(k, v) {
				drop++
			}
		}
		if drop > 0 {
			out := make(map[string]any, len(m)-drop)
			for k, v := range m {
				if (k == "$nonce" || k == "$successor") && schema.LeftOut(k, v) {
					continue
				}
				out[k] = v
			}
			doc = out
		}
	}
	return Layout(jsonv.Canonical(doc))
}

// Layout lays out canonical JSON text as ECMAScript's
// JSON.stringify(value, null, 2) does (§H.1): every member and element on
// its own line, indented two spaces per level, ": " after member names,
// "," at line ends, empty objects and arrays as {} and [], LF line ends
// and one final LF. Tokens are copied as they are, member order included:
// the text is laid out, never parsed and written again, which in
// ECMAScript would move keys that look like array indices first. canon
// must be canonical (§3.1), with no whitespace outside strings.
func Layout(canon []byte) []byte {
	var b bytes.Buffer
	b.Grow(len(canon) + len(canon)/2 + 1)
	depth := 0
	newline := func() {
		b.WriteByte('\n')
		for i := 0; i < depth; i++ {
			b.WriteString("  ")
		}
	}
	for i := 0; i < len(canon); i++ {
		switch c := canon[i]; c {
		case '"':
			j := i + 1
			for j < len(canon) && canon[j] != '"' {
				if canon[j] == '\\' {
					j++
				}
				j++
			}
			b.Write(canon[i : j+1])
			i = j
		case '{', '[':
			if i+1 < len(canon) && (canon[i+1] == '}' || canon[i+1] == ']') {
				b.WriteByte(c)
				b.WriteByte(canon[i+1])
				i++
				continue
			}
			b.WriteByte(c)
			depth++
			newline()
		case '}', ']':
			depth--
			newline()
			b.WriteByte(c)
		case ',':
			b.WriteByte(',')
			newline()
		case ':':
			b.WriteString(": ")
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\n')
	return b.Bytes()
}

// Meta is the file metadata of a document as a file-tree listing gives it
// (§H.3), without its modified time: for a raw file (§H.1), the blob
// reference's size and type; for a JSON file, the length of its rendering
// and application/json.
type Meta struct {
	Size int64
	Type string
}

// MetaOf is doc's Meta (§H.3).
func MetaOf(doc any) Meta {
	if client.RawBlobOf(doc) != "" {
		m := doc.(map[string]any)
		size, _ := m["size"].(float64)
		typ, _ := m["type"].(string)
		return Meta{Size: int64(size), Type: typ}
	}
	return Meta{Size: int64(len(Rendering(doc))), Type: JSONType}
}
