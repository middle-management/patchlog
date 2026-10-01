package schemaimport

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
)

// Drafts, by the year or number in their meta-schema URL. 0 is unknown
// (no or a custom $schema), treated like 2020-12 with lenient conversions.
const (
	draftUnknown = 0
	draft3       = 3
	draft4       = 4
	draft6       = 6
	draft7       = 7
	draft2019    = 2019
	draft2020    = 2020
)

// metaKey strips scheme and trailing "#" from a meta-schema URL.
func metaKey(s string) string {
	s = strings.TrimSuffix(s, "#")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

// draftOf returns the draft a $schema URL names, or draftUnknown.
func draftOf(s string) int {
	switch metaKey(s) {
	case "json-schema.org/draft-03/schema":
		return draft3
	case "json-schema.org/draft-04/schema":
		return draft4
	case "json-schema.org/draft-06/schema":
		return draft6
	case "json-schema.org/draft-07/schema":
		return draft7
	case "json-schema.org/draft/2019-09/schema":
		return draft2019
	case "json-schema.org/draft/2020-12/schema":
		return draft2020
	}
	return draftUnknown
}

// isMeta reports whether an absolute URL (no fragment) is a JSON Schema
// meta-schema or vocabulary meta-schema of any draft. These are never fetched.
func isMeta(u string) bool {
	k := metaKey(u)
	return strings.HasPrefix(k, "json-schema.org/draft-0") || strings.HasPrefix(k, "json-schema.org/draft/")
}

// Keyword classes, by what the keyword's value holds.
type class int

const (
	cLeaf   class = iota // not a subschema (copied verbatim)
	cSchema              // one subschema
	cMap                 // object of subschemas
	cArray               // array of subschemas
	cDeps                // draft ≤ 2019 "dependencies": per member, a subschema or a string array
	cDrop                // removed from the output
)

var (
	single = map[string]bool{"additionalProperties": true, "not": true, "if": true, "then": true, "else": true,
		"propertyNames": true, "contains": true, "unevaluatedItems": true, "unevaluatedProperties": true, "contentSchema": true}
	maps   = map[string]bool{"properties": true, "patternProperties": true, "$defs": true, "dependentSchemas": true}
	arrays = map[string]bool{"allOf": true, "anyOf": true, "oneOf": true, "prefixItems": true}
)

func isSchemaValue(v any) bool {
	switch v.(type) {
	case map[string]any, bool:
		return true
	}
	return false
}

// classify says what keyword k of schema object obj becomes in draft 2020-12:
// its new name and its class. An unknown keyword becomes an x-* annotation
// (renamed is true), which validates exactly as before: unknown keywords have
// no assertion semantics. A keyword dropped for a collision has class cDrop.
func classify(obj map[string]any, k string, draft int) (nk string, c class, renamed bool) {
	switch {
	case single[k]:
		return k, cSchema, false
	case maps[k]:
		return k, cMap, false
	case arrays[k]:
		return k, cArray, false
	}
	switch k {
	case "definitions":
		return "$defs", cMap, false
	case "items":
		if _, ok := obj["items"].([]any); ok {
			return "prefixItems", cArray, false
		}
		return "items", cSchema, false
	case "additionalItems":
		if _, ok := obj["items"].([]any); ok {
			return "items", cSchema, false
		}
	case "dependencies":
		if _, ok := obj[k].(map[string]any); ok {
			return "", cDeps, false
		}
	case "$id", "$anchor", "$schema":
		// Identifiers are resolved to revision paths and JSON Pointers; the
		// server forbids $id other than a schema's own revision path (§6.1).
		return "", cDrop, false
	case "id":
		if draft == draft4 || draft == draft3 {
			return "", cDrop, false
		}
	}
	if schema.IsKeyword(k) || strings.HasPrefix(k, "x-") {
		return k, cLeaf, false
	}
	if _, taken := obj["x-"+k]; taken {
		return "", cDrop, true
	}
	return "x-" + k, cLeaf, true
}

// draftAt updates the draft for a schema object carrying a known $schema.
func draftAt(obj map[string]any, draft int) int {
	if s, ok := obj["$schema"].(string); ok {
		if d := draftOf(s); d != draftUnknown {
			return d
		}
	}
	return draft
}

// child is a subschema of a schema object, at tokens relative to it, in the
// source (pre-conversion) form.
type child struct {
	toks []string
	node any
}

// children lists the subschemas of a source schema object.
func children(obj map[string]any, draft int) []child {
	var out []child
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		_, c, _ := classify(obj, k, draft)
		switch c {
		case cSchema:
			out = append(out, child{[]string{k}, v})
		case cMap:
			if m, ok := v.(map[string]any); ok {
				for _, n := range sortedKeys(m) {
					out = append(out, child{[]string{k, n}, m[n]})
				}
			}
		case cArray:
			if a, ok := v.([]any); ok {
				for i, e := range a {
					out = append(out, child{[]string{k, strconv.Itoa(i)}, e})
				}
			}
		case cDeps:
			m := v.(map[string]any)
			for _, n := range sortedKeys(m) {
				if isSchemaValue(m[n]) {
					out = append(out, child{[]string{k, n}, m[n]})
				}
			}
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// translate maps a JSON Pointer into a source document to the same location
// in its converted form. It fails if the location doesn't exist or doesn't
// survive the conversion.
func translate(doc any, draft int, p pointer.Pointer) (pointer.Pointer, error) {
	const (
		mSchema = iota
		mMap
		mArray
		mData
	)
	out := pointer.Pointer{}
	node, mode := doc, mSchema
	notFound := func() (pointer.Pointer, error) {
		return nil, fmt.Errorf("%s does not exist", p.String())
	}
	for i := 0; i < len(p); i++ {
		tok := p[i]
		switch mode {
		case mSchema:
			obj, ok := node.(map[string]any)
			if !ok {
				return notFound()
			}
			draft = draftAt(obj, draft)
			v, ok := obj[tok]
			if !ok {
				return notFound()
			}
			nk, c, _ := classify(obj, tok, draft)
			switch c {
			case cDrop:
				return nil, fmt.Errorf("%s points into %q, which is not imported", p.String(), tok)
			case cDeps:
				if i+1 >= len(p) {
					return nil, fmt.Errorf("%s points at \"dependencies\", which is split into dependentSchemas and dependentRequired", p.String())
				}
				i++
				m := v.(map[string]any)
				v2, ok := m[p[i]]
				if !ok {
					return notFound()
				}
				if isSchemaValue(v2) {
					out = append(out, "dependentSchemas", p[i])
					mode = mSchema
				} else {
					out = append(out, "dependentRequired", p[i])
					mode = mData
				}
				node = v2
				continue
			case cSchema:
				mode = mSchema
			case cMap:
				mode = mMap
			case cArray:
				mode = mArray
			default:
				mode = mData
			}
			out = append(out, nk)
			node = v
		case mMap:
			m, ok := node.(map[string]any)
			if !ok {
				return notFound()
			}
			if node, ok = m[tok]; !ok {
				return notFound()
			}
			out = append(out, tok)
			mode = mSchema
		case mArray, mData:
			v, ok := pointer.Get(node, pointer.Pointer{tok})
			if !ok {
				return notFound()
			}
			out = append(out, tok)
			node = v
			if mode == mArray {
				mode = mSchema
			}
		}
	}
	return out, nil
}

// refRewriter returns the new $ref for the schema object at a source pointer,
// or meta set for a reference to a JSON Schema meta-schema.
type refRewriter func(at pointer.Pointer) (ref string, meta string, err error)

// converter turns a source schema into draft 2020-12 as the server accepts it
// (§6.1, §6.5): identifiers dropped, references rewritten, older-draft
// keywords translated and unknown keywords renamed to x-*.
type converter struct {
	rewrite refRewriter
	warn    func(kind, detail string)
	where   string // document URL, for messages
}

func (cv *converter) schema(node any, at pointer.Pointer, draft int) (any, error) {
	obj, ok := node.(map[string]any)
	if !ok {
		return node, nil
	}
	draft = draftAt(obj, draft)
	out := map[string]any{}
	put := func(k string, v any) error {
		if _, dup := out[k]; dup {
			return fmt.Errorf("%s#%s: %q would be written twice", cv.where, at.String(), k)
		}
		out[k] = v
		return nil
	}
	merge := func(k string, m map[string]any) error {
		cur, ok := out[k].(map[string]any)
		if !ok {
			return put(k, m)
		}
		for n, v := range m {
			if _, dup := cur[n]; dup {
				return fmt.Errorf("%s#%s: %s/%s is defined twice (e.g. by both \"definitions\" and \"$defs\")", cv.where, at.String(), k, n)
			}
			cur[n] = v
		}
		return nil
	}
	sub := func(v any, toks ...string) (any, error) {
		return cv.schema(v, append(append(pointer.Pointer{}, at...), toks...), draft)
	}
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		nk, c, renamed := classify(obj, k, draft)
		if renamed {
			if c == cDrop {
				cv.warn("dropped unknown keyword "+strconv.Quote(k)+" (x-"+k+" already present)", cv.where+"#"+at.String())
			} else {
				cv.warn("renamed unknown keyword "+strconv.Quote(k)+" to "+strconv.Quote(nk), cv.where+"#"+at.String())
			}
		}
		if k == "$recursiveRef" || k == "$recursiveAnchor" {
			cv.warn("2019-09 "+k+" is not supported and has no effect", cv.where+"#"+at.String())
		}
		switch c {
		case cDrop:
		case cLeaf:
			if err := put(nk, v); err != nil {
				return nil, err
			}
		case cSchema:
			s, err := sub(v, k)
			if err != nil {
				return nil, err
			}
			if err := put(nk, s); err != nil {
				return nil, err
			}
		case cMap:
			m, ok := v.(map[string]any)
			if !ok {
				if err := put(nk, v); err != nil {
					return nil, err
				}
				continue
			}
			nm := map[string]any{}
			for _, n := range sortedKeys(m) {
				s, err := sub(m[n], k, n)
				if err != nil {
					return nil, err
				}
				nm[n] = s
			}
			if err := merge(nk, nm); err != nil {
				return nil, err
			}
		case cArray:
			a, ok := v.([]any)
			if !ok {
				if err := put(nk, v); err != nil {
					return nil, err
				}
				continue
			}
			na := make([]any, len(a))
			for i, e := range a {
				s, err := sub(e, k, strconv.Itoa(i))
				if err != nil {
					return nil, err
				}
				na[i] = s
			}
			if err := put(nk, na); err != nil {
				return nil, err
			}
		case cDeps:
			m := v.(map[string]any)
			ds, dr := map[string]any{}, map[string]any{}
			for _, n := range sortedKeys(m) {
				if isSchemaValue(m[n]) {
					s, err := sub(m[n], k, n)
					if err != nil {
						return nil, err
					}
					ds[n] = s
				} else {
					dr[n] = m[n]
				}
			}
			if len(ds) > 0 {
				if err := merge("dependentSchemas", ds); err != nil {
					return nil, err
				}
			}
			if len(dr) > 0 {
				if err := merge("dependentRequired", dr); err != nil {
					return nil, err
				}
			}
		}
	}
	// Draft-04 boolean exclusiveMaximum / exclusiveMinimum.
	for _, b := range [][2]string{{"exclusiveMaximum", "maximum"}, {"exclusiveMinimum", "minimum"}} {
		ex, ok := obj[b[0]].(bool)
		if !ok {
			continue
		}
		delete(out, b[0])
		if n, isNum := obj[b[1]].(float64); ex && isNum {
			delete(out, b[1])
			out[b[0]] = n
		}
	}
	if _, ok := obj["$ref"].(string); ok {
		ref, meta, err := cv.rewrite(at)
		if err != nil {
			return nil, err
		}
		if meta != "" {
			delete(out, "$ref")
			if _, taken := out["x-meta-ref"]; !taken {
				out["x-meta-ref"] = meta
			}
			cv.warn("dropped $ref to the meta-schema "+meta+" (§6.1 accepts no absolute URLs in $ref); that subschema now accepts any schema", cv.where+"#"+at.String())
		} else {
			out["$ref"] = ref
		}
	}
	if d, ok := obj["$dynamicRef"].(string); ok && !strings.HasPrefix(d, "#") {
		return nil, fmt.Errorf("%s#%s: $dynamicRef %q is not a fragment; the server resolves only same-document $dynamicRef (§6.1)", cv.where, at.String(), d)
	}
	return out, nil
}

// fragment encodes a JSON Pointer as a URI fragment (RFC 6901 §6), without
// the leading "#".
func fragment(p pointer.Pointer) string {
	s := p.String()
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("-._~!$&'()*+,;=:@/?", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
