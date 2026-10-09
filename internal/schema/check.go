package schema

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/pointer"
)

// keywords is every draft 2020-12 keyword across all vocabularies.
var keywords = map[string]bool{}

func init() {
	for _, k := range []string{
		// core
		"$schema", "$id", "$ref", "$anchor", "$dynamicRef", "$dynamicAnchor", "$vocabulary", "$comment", "$defs",
		// applicator
		"prefixItems", "items", "contains", "additionalProperties", "properties", "patternProperties",
		"dependentSchemas", "propertyNames", "if", "then", "else", "allOf", "anyOf", "oneOf", "not",
		// unevaluated
		"unevaluatedItems", "unevaluatedProperties",
		// validation
		"type", "const", "enum", "multipleOf", "maximum", "exclusiveMaximum", "minimum", "exclusiveMinimum",
		"maxLength", "minLength", "pattern", "maxItems", "minItems", "uniqueItems", "maxContains", "minContains",
		"maxProperties", "minProperties", "required", "dependentRequired",
		// meta-data
		"title", "description", "default", "deprecated", "readOnly", "writeOnly", "examples",
		// format-annotation
		"format",
		// content
		"contentEncoding", "contentMediaType", "contentSchema",
	} {
		keywords[k] = true
	}
}

// IsKeyword reports whether k is a draft 2020-12 keyword (§6.5: any other
// keyword not starting with "x-" makes a schema invalid).
func IsKeyword(k string) bool { return keywords[k] }

var (
	schemaKeywords    = []string{"items", "contains", "additionalProperties", "not", "if", "then", "else", "propertyNames", "unevaluatedItems", "unevaluatedProperties", "contentSchema"}
	schemaMapKeywords = []string{"properties", "patternProperties", "$defs", "dependentSchemas"}
	schemaArrKeywords = []string{"allOf", "anyOf", "oneOf", "prefixItems"}
)

// CheckSchemaDocument validates the constraints of §6.1, §6.5 and §6.6 for a
// document that is a schema: $id, $ref/$dynamicRef forms, unknown keywords and
// RE2-compatible regular expressions. selfPath is the revision path the schema
// is stored at, or "" if not yet known (then $id is forbidden). A top-level
// $nonce of the fresh-nonce form is mechanics, not a keyword, as for
// validation (Instance), so namespaces that require nonces can hold schemas
// (§6.2, §C.7).
func CheckSchemaDocument(doc any, selfPath string) error {
	if m, ok := doc.(map[string]any); ok {
		if n, _ := m["$nonce"].(string); freshNonce.MatchString(n) {
			doc = without(m, "$nonce")
		}
	}
	return checkSchema(doc, pointer.Pointer{}, selfPath)
}

// without returns a copy of m without key k.
func without(m map[string]any, k string) map[string]any {
	out := make(map[string]any, len(m))
	for x, v := range m {
		if x != k {
			out[x] = v
		}
	}
	return out
}

func checkSchema(s any, at pointer.Pointer, selfPath string) error {
	switch obj := s.(type) {
	case bool:
		return nil
	case map[string]any:
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !keywords[k] && !strings.HasPrefix(k, "x-") {
				return &SchemaError{Msg: fmt.Sprintf("unknown keyword %q at %s", k, loc(at))}
			}
		}
		if err := checkCore(obj, at, selfPath); err != nil {
			return err
		}
		if p, ok := obj["pattern"]; ok {
			ps, ok := p.(string)
			if !ok {
				return &SchemaError{Msg: fmt.Sprintf("pattern at %s must be a string", loc(at))}
			}
			if err := checkRegexp(ps, child(at, "pattern")); err != nil {
				return err
			}
		}
		for _, k := range schemaKeywords {
			if sub, ok := obj[k]; ok {
				if err := checkSchema(sub, child(at, k), selfPath); err != nil {
					return err
				}
			}
		}
		for _, k := range schemaMapKeywords {
			sub, ok := obj[k]
			if !ok {
				continue
			}
			m, ok := sub.(map[string]any)
			if !ok {
				return &SchemaError{Msg: fmt.Sprintf("%s at %s must be an object", k, loc(at))}
			}
			names := make([]string, 0, len(m))
			for n := range m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				p := child(at, k, n)
				if k == "patternProperties" {
					if err := checkRegexp(n, p); err != nil {
						return err
					}
				}
				if err := checkSchema(m[n], p, selfPath); err != nil {
					return err
				}
			}
		}
		for _, k := range schemaArrKeywords {
			sub, ok := obj[k]
			if !ok {
				continue
			}
			arr, ok := sub.([]any)
			if !ok {
				return &SchemaError{Msg: fmt.Sprintf("%s at %s must be an array", k, loc(at))}
			}
			for i, e := range arr {
				if err := checkSchema(e, child(at, k, fmt.Sprint(i)), selfPath); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return &SchemaError{Msg: fmt.Sprintf("schema at %s must be an object or boolean", loc(at))}
	}
}

func checkCore(obj map[string]any, at pointer.Pointer, selfPath string) error {
	if v, ok := obj["$schema"]; ok {
		s, ok := v.(string)
		if !ok || !IsDialect(s) {
			return &RefError{Msg: fmt.Sprintf("$schema at %s must be a supported dialect URL", loc(at))}
		}
	}
	if v, ok := obj["$id"]; ok {
		s, _ := v.(string)
		if len(at) != 0 || selfPath == "" || s != selfPath {
			return &RefError{Msg: fmt.Sprintf("$id at %s is not allowed", loc(at))}
		}
	}
	if v, ok := obj["$ref"]; ok {
		s, ok := v.(string)
		if !ok {
			return &RefError{Msg: fmt.Sprintf("$ref at %s must be a string", loc(at))}
		}
		if !strings.HasPrefix(s, "#") {
			if _, _, err := SplitRef(s); err != nil {
				return &RefError{Msg: fmt.Sprintf("at %s: %s", loc(at), strings.TrimPrefix(err.Error(), "schema_ref: "))}
			}
		}
	}
	if v, ok := obj["$dynamicRef"]; ok {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(s, "#") {
			return &RefError{Msg: fmt.Sprintf("$dynamicRef at %s must be a fragment", loc(at))}
		}
	}
	return nil
}

func checkRegexp(re string, at pointer.Pointer) error {
	if _, err := regexp.Compile(re); err != nil {
		return &SchemaError{Msg: fmt.Sprintf("regular expression at %s is not RE2-compatible: %v", loc(at), err)}
	}
	return nil
}

func child(at pointer.Pointer, toks ...string) pointer.Pointer {
	p := make(pointer.Pointer, 0, len(at)+len(toks))
	return append(append(p, at...), toks...)
}

func loc(p pointer.Pointer) string {
	if len(p) == 0 {
		return "the root"
	}
	return p.String()
}

// Refs returns the revision paths directly referenced by a schema document via
// $ref (fragments dropped), deduplicated and sorted, for the referenced-schema index (§6.1).
func Refs(schemaDoc any) []Ref {
	seen := map[string]bool{}
	var out []Ref
	var walk func(s any)
	walk = func(s any) {
		obj, ok := s.(map[string]any)
		if !ok {
			return
		}
		if r, ok := obj["$ref"].(string); ok {
			if ref, _, err := SplitRef(r); err == nil && !seen[ref.Path()] {
				seen[ref.Path()] = true
				out = append(out, ref)
			}
		}
		for _, k := range schemaKeywords {
			walk(obj[k])
		}
		for _, k := range schemaMapKeywords {
			if m, ok := obj[k].(map[string]any); ok {
				for _, sub := range m {
					walk(sub)
				}
			}
		}
		for _, k := range schemaArrKeywords {
			if arr, ok := obj[k].([]any); ok {
				for _, sub := range arr {
					walk(sub)
				}
			}
		}
	}
	walk(schemaDoc)
	sort.Slice(out, func(i, j int) bool { return out[i].Path() < out[j].Path() })
	return out
}

// RefAt is one $ref of a schema document that names a schema revision, with
// where it sits.
type RefAt struct {
	Pointer pointer.Pointer // the $ref string's location in the document
	Raw     string          // the string as written, fragment included
	Ref     Ref             // the revision, fragment dropped
}

// RefLocations returns every $ref at a schema position of a schema document
// (§6.1) that names a schema revision path (same-document fragments don't
// count), in document order with members sorted. $ref strings in const,
// enum, default, examples or any other non-schema position are not found.
func RefLocations(schemaDoc any) []RefAt {
	var out []RefAt
	var walk func(s any, at pointer.Pointer)
	walk = func(s any, at pointer.Pointer) {
		obj, ok := s.(map[string]any)
		if !ok {
			return
		}
		if r, ok := obj["$ref"].(string); ok && !strings.HasPrefix(r, "#") {
			if ref, _, err := SplitRef(r); err == nil {
				out = append(out, RefAt{Pointer: child(at, "$ref"), Raw: r, Ref: ref})
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch {
			case inList(schemaKeywords, k):
				walk(obj[k], child(at, k))
			case inList(schemaMapKeywords, k):
				if m, ok := obj[k].(map[string]any); ok {
					names := make([]string, 0, len(m))
					for n := range m {
						names = append(names, n)
					}
					sort.Strings(names)
					for _, n := range names {
						walk(m[n], child(at, k, n))
					}
				}
			case inList(schemaArrKeywords, k):
				if arr, ok := obj[k].([]any); ok {
					for i, e := range arr {
						walk(e, child(at, k, fmt.Sprint(i)))
					}
				}
			}
		}
	}
	walk(schemaDoc, pointer.Pointer{})
	return out
}

func inList(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
