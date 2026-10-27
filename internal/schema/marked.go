package schema

import (
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Each revision of a closure under its own marker (§6.1: "A schema stored
// under an earlier version is compiled as that version did", wherever it
// is reached from: named by a document's $schema, or through the $ref of a
// schema written since).
//
// The library compiles a schema's whole $ref closure with one compiler,
// whose formats and regexp engine serve every revision in it. Legacy and
// V073 read a pattern alike whenever V073 accepts it (CompileRegexp), and
// a V073 revision's patterns were all accepted under V073 when it was
// written; so a closure compiles with Legacy's engine, which reads every
// revision's patterns as its marker does. The markers differ in five
// format names: semver and period, which Legacy asserts and V073 doesn't;
// idn-email and idn-hostname, the reverse; and regex, which each asserts
// as it reads patterns. Each revision has those renamed to the names its
// own marker registers (markFormats, markedFormats). The library's other
// formats assert alike under both markers, and a name neither knows is
// ignored by both.

// ValidateMarked is ValidateRules for a caller that knows each schema
// revision's marker (§6.1): a schema document is checked under rules, the
// marker it is written under, as ValidateRules checks it; a document typed
// by a revision path validates against that revision, which compiles with
// each revision of its $ref closure, its own included, under the marker
// rulesOf gives it.
func (v *Validator) ValidateMarked(doc any, load Loader, rules Rules, rulesOf func(Ref) Rules) error {
	return v.validate(doc, load, rules, rulesOf)
}

// markedSchema is a compiled schema and the marker it compiled each
// revision of its closure under.
type markedSchema struct {
	sch     *jsonschema.Schema
	closure []Ref
	marks   []Rules
}

// holds reports whether rulesOf still gives each revision of m's closure
// the marker it compiled under.
func (m markedSchema) holds(rulesOf func(Ref) Rules) bool {
	for i, r := range m.closure {
		if rulesOf(r) != m.marks[i] {
			return false
		}
	}
	return true
}

// compileMarked compiles the revision at ref with each revision of its
// $ref closure under its own marker, which rulesOf gives. The result is
// kept by path with those markers, and serves while rulesOf gives each
// revision the same: a marker is the revision row's, so a path compiles
// one way unless the row it resolves to changes (a namespace purged and
// made again).
func (v *Validator) compileMarked(ref Ref, load Loader, rulesOf func(Ref) Rules) (*jsonschema.Schema, error) {
	path := ref.Path()
	v.mu.Lock()
	m, ok := v.marked.Get(path)
	v.mu.Unlock()
	if ok && m.holds(rulesOf) {
		return m.sch, nil
	}
	var loadErr error
	docs := v.urlLoader(load, &loadErr)
	m = markedSchema{}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseRegexpEngine(Legacy.regexpEngine)
	for _, f := range markedFormats() {
		c.RegisterFormat(f)
	}
	c.UseLoader(urlLoaderFunc(func(url string) (any, error) {
		doc, err := docs(url)
		if err != nil {
			return nil, err
		}
		r, _ := ParseRef(strings.TrimPrefix(url, syntheticBase)) // docs served it
		rules := rulesOf(r)
		m.closure, m.marks = append(m.closure, r), append(m.marks, rules)
		return markFormats(doc, rules), nil
	}))
	sch, err := c.Compile(syntheticBase + path)
	if err != nil {
		if loadErr != nil {
			return nil, loadErr
		}
		return nil, &SchemaError{Msg: err.Error()}
	}
	m.sch = sch
	v.mu.Lock()
	v.marked.Put(path, m, 1)
	v.mu.Unlock()
	return sch, nil
}

// markerFormats are the format names Legacy and V073 read differently.
var markerFormats = map[string]bool{"semver": true, "period": true, "idn-email": true, "idn-hostname": true, "regex": true}

// markedPrefix starts the name format f has in a revision under marker r
// (markedFormatName). No document can hold it: JSON texts decode to UTF-8
// (jsonv), and the byte 0xff is never part of UTF-8, so a renamed format
// is apart from every name a schema can write.
const markedPrefix = "\xff"

// markedFormatName is the name format f, one of markerFormats, has in a
// revision under marker r once markFormats renamed it.
func markedFormatName(r Rules, f string) string {
	return markedPrefix + r.String() + markedPrefix + f
}

// writtenFormat is the format name a revision wrote, for one markFormats
// renamed (markedFormatName): validation messages name what the schema
// says. Any other name is returned as is.
func writtenFormat(name string) string {
	rest, ok := strings.CutPrefix(name, markedPrefix)
	if !ok {
		return name
	}
	if _, f, ok := strings.Cut(rest, markedPrefix); ok {
		return f
	}
	return name
}

// markedFormats are the formats a compile of revisions under their own
// markers registers (compileMarked): under Legacy, semver and period as
// the library asserts them and regex as Legacy reads patterns, idn-email
// and idn-hostname not at all, as v0.55 asserted them; under V073,
// idn-email and idn-hostname with UTS 46 processing and regex as §6.6
// reads patterns, semver and period not at all (Configure).
var markedFormats = sync.OnceValue(func() []*jsonschema.Format {
	return []*jsonschema.Format{
		{Name: markedFormatName(Legacy, "semver"), Validate: libraryFormat("semver")},
		{Name: markedFormatName(Legacy, "period"), Validate: libraryFormat("period")},
		{Name: markedFormatName(Legacy, "regex"), Validate: Legacy.validateRegexp},
		{Name: markedFormatName(V073, "idn-email"), Validate: validateIDNEmail},
		{Name: markedFormatName(V073, "idn-hostname"), Validate: validateIDNHostname},
		{Name: markedFormatName(V073, "regex"), Validate: V073.validateRegexp},
	}
})

// libraryFormat is the library's own assertion of format name, as a
// compiler that asserts formats finds it.
func libraryFormat(name string) func(any) error {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	const url = syntheticBase + "/library-format"
	if err := c.AddResource(url, map[string]any{"format": name}); err != nil {
		panic("schema: library format " + name + ": " + err.Error())
	}
	sch, err := c.Compile(url)
	if err != nil || sch.Format == nil {
		panic("schema: the library has no format " + name)
	}
	return sch.Format.Validate
}

// validateRegexp asserts the regex format as r reads patterns, as the
// library asserts it with r's engine.
func (r Rules) validateRegexp(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	_, err := r.regexpEngine(s)
	return err
}

// markFormats returns doc, a schema revision under marker r, with each
// format named in markerFormats renamed to r's (markedFormatName), in every
// subschema: the members of properties, patternProperties, $defs,
// definitions and dependentSchemas, and any other member's object or
// array but the data of const, enum, default and examples, so that a
// subschema a JSON Pointer reaches outside a keyword is renamed too. doc
// itself is never modified: the parts renamed are copies.
func markFormats(doc any, r Rules) any {
	out, _ := markSchema(doc, r)
	return out
}

func isString(v any) bool { _, ok := v.(string); return ok }

// dataKeywords hold instance data, never a subschema.
var dataKeywords = map[string]bool{"const": true, "enum": true, "default": true, "examples": true}

func markSchema(s any, r Rules) (any, bool) {
	switch x := s.(type) {
	case map[string]any:
		var out map[string]any
		set := func(k string, v any) {
			if out == nil {
				out = maps.Clone(x)
			}
			out[k] = v
		}
		for k, v := range x {
			switch {
			case k == "format" && isString(v):
				if f := v.(string); markerFormats[f] {
					set(k, markedFormatName(r, f))
				}
			case dataKeywords[k]:
			case slices.Contains(schemaMapKeywords, k):
				// Member names are property names, $defs names and the
				// like, never keywords: each member is a subschema.
				m, ok := v.(map[string]any)
				if !ok {
					continue
				}
				var mm map[string]any
				for name, sub := range m {
					if ns, changed := markSchema(sub, r); changed {
						if mm == nil {
							mm = maps.Clone(m)
						}
						mm[name] = ns
					}
				}
				if mm != nil {
					set(k, mm)
				}
			default:
				if nv, changed := markSchema(v, r); changed {
					set(k, nv)
				}
			}
		}
		if out == nil {
			return s, false
		}
		return out, true
	case []any:
		var out []any
		for i, e := range x {
			if ne, changed := markSchema(e, r); changed {
				if out == nil {
					out = slices.Clone(x)
				}
				out[i] = ne
			}
		}
		if out == nil {
			return s, false
		}
		return out, true
	}
	return s, false
}
