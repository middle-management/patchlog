package schema

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/pointer"
)

// keywords is every draft 2020-12 keyword across all vocabularies.
var keywords = map[string]bool{}

func init() {
	for _, k := range []string{
		// core; definitions holds subschemas, as $defs does (§6.5)
		"$schema", "$id", "$ref", "$anchor", "$dynamicRef", "$dynamicAnchor", "$vocabulary", "$comment", "$defs", "definitions",
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
// keyword not starting with "x-" makes a schema invalid, dependencies,
// $recursiveAnchor and $recursiveRef included).
func IsKeyword(k string) bool { return keywords[k] }

var (
	schemaKeywords    = []string{"items", "contains", "additionalProperties", "not", "if", "then", "else", "propertyNames", "unevaluatedItems", "unevaluatedProperties", "contentSchema"}
	schemaMapKeywords = []string{"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
	schemaArrKeywords = []string{"allOf", "anyOf", "oneOf", "prefixItems"}
)

// mode is the rules a check holds a schema to.
type mode uint8

const (
	// write: a schema document written now (§6.1, §6.2 step 5, §6.5, §6.6).
	write mode = iota
	// stored: a schema document stored under an earlier version, held to
	// the rules it was written under (§6.1): v0.55's, which allowed a
	// nested dialect $schema, a root $id equal to its own revision path
	// and any format, together with all that writes accept now. Its
	// revision path is selfPath; without one (re-validating its content,
	// ValidateRules) any $id is refused, as v0.55 refused it at write.
	stored
	// fragment: a rule's schema fragment (§6.4.2): write's rules, with no
	// $schema in any subschema and same-document references only.
	fragment
)

type checker struct {
	mode     mode
	selfPath string // stored: the revision path the schema is stored at
}

// rules is the marker a check compiles patterns under.
func (ck checker) rules() Rules {
	if ck.mode == stored {
		return Legacy
	}
	return V073
}

// CheckSchemaDocument validates the constraints of §6.1, §6.5 and §6.6 for a
// document that is a schema: $schema, $id, $ref/$dynamicRef forms, unknown
// keywords, formats and RE2-compatible regular expressions.
//
// selfPath "" checks a schema being written (write mode): $id is invalid
// anywhere, $schema anywhere but the root, and so is a format draft
// 2020-12 doesn't define. Otherwise selfPath is the revision path the
// schema is stored at (stored mode), and the schema is held to the rules
// it was stored under (§6.1), which accepted a root $id equal to
// selfPath, a dialect $schema in any subschema and any format.
//
// In either mode a top-level $nonce of the fresh-nonce form and a
// $successor of the form of §8.1 are mechanics, not keywords, as for
// validation (Instance), so namespaces that require nonces can hold
// schemas (§6.2, §C.7) and schema resources can move (§8.1, §6.5).
func CheckSchemaDocument(doc any, selfPath string) error {
	ck := checker{mode: write}
	if selfPath != "" {
		ck = checker{mode: stored, selfPath: selfPath}
	}
	return ck.check(leaveOut(doc), pointer.Pointer{})
}

// CheckFragment checks a rule's schema fragment (§6.4.2): it is held to
// §6.1's $id ban, §6.5 and §6.6 as a schema document written now is, may
// have no $schema keyword in any subschema, and its $ref and $dynamicRef
// are same-document fragments only. Every refusal is a *SchemaError: the
// namespace document is invalid (422), or the grant (401).
func CheckFragment(frag any) error {
	err := checker{mode: fragment}.check(frag, pointer.Pointer{})
	var re *RefError
	if errors.As(err, &re) {
		return &SchemaError{Msg: re.Msg}
	}
	return err
}

// leaveOut returns doc without the top-level $nonce and $successor that
// step 5 of §6.2 leaves out (LeftOut): in a schema document they aren't
// keywords, and are left out before it is checked against its dialect,
// checked and compiled (§6.5). doc itself is never modified.
func leaveOut(doc any) any {
	m, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	drop := func(k string) bool {
		v, ok := m[k]
		return ok && (k == "$nonce" || k == "$successor") && LeftOut(k, v)
	}
	if !drop("$nonce") && !drop("$successor") {
		return doc
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if !drop(k) {
			out[k] = v
		}
	}
	return out
}

func (ck checker) check(s any, at pointer.Pointer) error {
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
		if err := ck.checkCore(obj, at); err != nil {
			return err
		}
		if p, ok := obj["pattern"]; ok {
			ps, ok := p.(string)
			if !ok {
				return &SchemaError{Msg: fmt.Sprintf("pattern at %s must be a string", loc(at))}
			}
			if err := ck.checkRegexp(ps, child(at, "pattern")); err != nil {
				return err
			}
		}
		for _, k := range schemaKeywords {
			if sub, ok := obj[k]; ok {
				if err := ck.check(sub, child(at, k)); err != nil {
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
					if err := ck.checkRegexp(n, p); err != nil {
						return err
					}
				}
				if err := ck.check(m[n], p); err != nil {
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
				if err := ck.check(e, child(at, k, fmt.Sprint(i))); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return &SchemaError{Msg: fmt.Sprintf("schema at %s must be an object or boolean", loc(at))}
	}
}

func (ck checker) checkCore(obj map[string]any, at pointer.Pointer) error {
	if v, ok := obj["$schema"]; ok {
		switch {
		case ck.mode == fragment:
			return &SchemaError{Msg: fmt.Sprintf("$schema at %s is not allowed in a rule's schema", loc(at))}
		case ck.mode == write && len(at) != 0:
			return &SchemaError{Msg: fmt.Sprintf("$schema at %s is not allowed: only a schema's root has one", loc(at))}
		}
		s, ok := v.(string)
		if !ok || !IsDialect(s) {
			return &RefError{Msg: fmt.Sprintf("$schema at %s must be a supported dialect URL", loc(at))}
		}
	}
	if v, ok := obj["$id"]; ok {
		if ck.mode != stored {
			return &SchemaError{Msg: fmt.Sprintf("$id at %s is not allowed", loc(at))}
		}
		s, _ := v.(string)
		if len(at) != 0 || ck.selfPath == "" || s != ck.selfPath {
			return &RefError{Msg: fmt.Sprintf("$id at %s is not allowed", loc(at))}
		}
	}
	if v, ok := obj["$ref"]; ok {
		s, ok := v.(string)
		if !ok {
			return &RefError{Msg: fmt.Sprintf("$ref at %s must be a string", loc(at))}
		}
		if !strings.HasPrefix(s, "#") {
			if ck.mode == fragment {
				return &SchemaError{Msg: fmt.Sprintf("$ref at %s must be a same-document fragment in a rule's schema", loc(at))}
			}
			if _, err := ParseRefTarget(s); err != nil {
				var se *SchemaError
				if errors.As(err, &se) {
					return &SchemaError{Msg: fmt.Sprintf("at %s: %s", loc(at), se.Msg)}
				}
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
	if v, ok := obj["format"]; ok && ck.mode != stored {
		f, ok := v.(string)
		if !ok {
			return &SchemaError{Msg: fmt.Sprintf("format at %s must be a string", loc(at))}
		}
		if !formats2020[f] {
			return &SchemaError{Msg: fmt.Sprintf("format %q at %s is not one draft 2020-12 defines", f, loc(at))}
		}
	}
	return nil
}

func (ck checker) checkRegexp(re string, at pointer.Pointer) error {
	if _, err := ck.rules().CompileRegexp(re); err != nil {
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

// refRevision returns the schema revision a $ref string names, whatever
// its fragment says: a fragment a check would refuse never hides the
// revision from reference counting (in_use, the index, bundle renames),
// which fails closed.
func refRevision(s string) (Ref, bool) {
	docPart, _, _ := strings.Cut(s, "#")
	return ParseRef(docPart)
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
			if ref, ok := refRevision(r); ok && !seen[ref.Path()] {
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
// (§6.1) that names a schema revision path, whatever its fragment
// (same-document fragments don't count), in document order with members
// sorted. $ref strings in const, enum, default, examples or any other
// non-schema position are not found.
func RefLocations(schemaDoc any) []RefAt {
	var out []RefAt
	var walk func(s any, at pointer.Pointer)
	walk = func(s any, at pointer.Pointer) {
		obj, ok := s.(map[string]any)
		if !ok {
			return
		}
		if r, ok := obj["$ref"].(string); ok {
			if ref, ok := refRevision(r); ok {
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
