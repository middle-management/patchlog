package jsv

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The differential tests hold jsv to the verdicts of the library the
// server uses today, configured as internal/schema configures it: draft
// 2020-12, formats asserted, patterns read by internal/pattern.

type libLoader func(string) (any, error)

func (f libLoader) Load(url string) (any, error) { return f(url) }

func libCompile(doc any, load func(string) (any, error)) (sch *jsonschema.Schema, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	c := jsonschema.NewCompiler()
	schema.V073.Configure(c)
	if load == nil {
		load = func(url string) (any, error) { return nil, fmt.Errorf("refusing to load %q", url) }
	}
	c.UseLoader(libLoader(load))
	if err := c.AddResource(defaultBase, doc); err != nil {
		return nil, err
	}
	return c.Compile(defaultBase)
}

// repoOptions are the Options that correspond to the library as the
// repository configures it. idn-email and idn-hostname, which
// internal/schema adds to the library, are not exported by it and stay
// unchecked here.
func repoOptions(load func(string) (any, error)) Options {
	return Options{
		Load:         load,
		AssertFormat: true,
		Regexp: func(p string) (Matcher, error) {
			re, err := schema.V073.CompileRegexp(p)
			if err != nil {
				return nil, err
			}
			return re, nil
		},
	}
}

// TestDifferentialSuite runs every schema and instance of the suite,
// optional tests included, through both validators.
func TestDifferentialSuite(t *testing.T) {
	dir := suiteDir(t)
	load := suiteLoader(dir)
	compared, bothRefuse := 0, 0
	for _, sub := range []string{"", "optional", "optional/format"} {
		for _, path := range suiteFiles(t, dir, sub) {
			name := filepath.Base(path)
			if strings.HasPrefix(name, "idn-") {
				continue // formats internal/schema adds and does not export
			}
			for _, c := range readSuiteFile(t, path) {
				if m, ok := c.Schema.(map[string]any); ok {
					if f, _ := m["format"].(string); strings.HasPrefix(f, "idn-") {
						continue
					}
				}
				lib, lerr := libCompile(c.Schema, load)
				sch, jerr := Compile(c.Schema, "", repoOptions(load))
				if (lerr == nil) != (jerr == nil) {
					key := name + ": " + c.Description
					if why, ok := knownCompileDifferences[key]; ok {
						t.Logf("known difference: %s: %s", key, why)
						continue
					}
					t.Errorf("%s: %s: compile disagrees:\n  library: %v\n  jsv:     %v", name, c.Description, lerr, jerr)
					continue
				}
				if lerr != nil {
					bothRefuse++
					continue
				}
				for _, tc := range c.Tests {
					le, je := lib.Validate(tc.Data), sch.Validate(tc.Data, ValidateOptions{})
					compared++
					if (le == nil) != (je == nil) {
						key := name + ": " + c.Description + " / " + tc.Description
						if why, ok := knownVerdictDifferences[key]; ok {
							t.Logf("known difference: %s: %s", key, why)
							continue
						}
						t.Errorf("%s: %s / %s (suite says valid=%v):\n  library: %v\n  jsv:     %v", name, c.Description, tc.Description, tc.Valid, le, je)
					}
				}
			}
		}
	}
	t.Logf("%d instances compared; %d schemas refused by both", compared, bothRefuse)
}

// Where the two are known to differ, and why.
var (
	knownCompileDifferences = map[string]string{
		"cross-draft.json: refs to historic drafts are processed as historic drafts": "jsv implements draft 2020-12 only and refuses a schema of another draft with an *UnsupportedError",
	}
	knownVerdictDifferences = map[string]string{}
)

// TestDifferentialRandom validates generated documents, most of them
// nearly valid, against hand-written schemas with both validators.
func TestDifferentialRandom(t *testing.T) {
	const perSchema = 3000
	for _, ts := range testSchemas {
		t.Run(ts.name, func(t *testing.T) {
			raw := mustJSON(ts.schema)
			lib, err := libCompile(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			sch, err := Compile(raw, "", repoOptions(nil))
			if err != nil {
				t.Fatal(err)
			}
			r := rand.New(rand.NewSource(1))
			valid := 0
			for i := 0; i < perSchema; i++ {
				g := &generator{r: r, root: raw, noise: []float64{0, 0.02, 0.1}[i%3]}
				doc := g.gen(raw, 0)
				le, je := lib.Validate(doc), sch.Validate(doc, ValidateOptions{})
				if (le == nil) != (je == nil) {
					t.Fatalf("disagree on %s:\n  library: %v\n  jsv:     %v", jsonText(doc), le, je)
				}
				if je == nil {
					valid++
				}
			}
			t.Logf("%d documents, %d valid, %d invalid", perSchema, valid, perSchema-valid)
			if valid < perSchema/10 || valid > perSchema*9/10 {
				t.Errorf("the documents do not exercise both verdicts: %d of %d valid", valid, perSchema)
			}
		})
	}
}

// TestDifferentialSchemas: the two agree on which schemas compile, and on
// the verdicts of those that do, for schemas that are malformed, refer to
// nothing, or apply themselves to the same instance.
func TestDifferentialSchemas(t *testing.T) {
	docs := []string{`null`, `{}`, `5`, `"s"`, `[1]`, `{"a": 1}`, `{"a": {"a": "s"}}`, `{"loop": 1}`}
	for _, s := range []string{
		// Only what is referred to is compiled, so loaded.
		`{"$defs": {"unused": {"$ref": "https://elsewhere.test/x"}}}`,
		`{"$defs": {"unused": {"$ref": "#/nowhere"}}}`,
		`{"$defs": {"unused": {"type": "nope"}}}`,
		`{"$defs": {"unused": {"pattern": "("}}}`,
		`{"$ref": "#/nowhere"}`,
		`{"$ref": "#nowhere"}`,
		`{"$ref": "https://elsewhere.test/x"}`,
		`{"unknown": {"$ref": "#/nowhere"}}`,
		`{"properties": {"a": {"$ref": "#/unknown/x"}}, "unknown": {"x": {"type": "string"}}}`,
		// Reference cycles: the schema that comes back to itself fails.
		`{"$ref": "#"}`,
		`{"allOf": [{"$ref": "#"}]}`,
		`{"anyOf": [{"type": "null"}, {"$ref": "#"}]}`,
		`{"oneOf": [{"type": "null"}, {"$ref": "#"}]}`,
		`{"if": {"type": "object"}, "then": {"$ref": "#"}}`,
		`{"not": {"$ref": "#"}}`,
		`{"not": {"not": {"$ref": "#"}}}`,
		`{"properties": {"a": {"$ref": "#"}}, "dependentSchemas": {"loop": {"$ref": "#"}}}`,
		`{"$ref": "#/$defs/a", "$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"anyOf": [{"type": "integer"}, {"$ref": "#/$defs/a"}]}}}`,
		`{"$dynamicAnchor": "x", "anyOf": [{"type": "integer"}, {"$dynamicRef": "#x"}]}`,
		`{"properties": {"a": {"$ref": "#"}}, "unevaluatedProperties": {"$ref": "#"}}`,
		// Malformed keywords.
		`{"$id": "http://x.test/a#frag"}`,
		`{"$anchor": "a", "$defs": {"x": {"$anchor": "a"}}}`,
		`{"type": []}`,
		`{"type": "nope"}`,
		`{"type": ["string", "string"]}`,
		`{"allOf": []}`,
		`{"enum": []}`,
		`{"enum": [1, 1]}`,
		`{"required": ["a", "a"]}`,
		`{"minLength": 1.5}`,
		`{"minLength": 2.0}`,
		`{"minLength": -1}`,
		`{"multipleOf": 0}`,
		`{"format": 5}`,
		`{"then": 5}`,
		`{"title": 5}`,
		`{"properties": {"a": 5}}`,
		`{"properties": []}`,
		`{"patternProperties": {"(": true}}`,
		`{"dependentRequired": {"a": "b"}}`,
		`{"dependentRequired": {"a": ["b"]}}`,
		`{"minContains": 2}`,
		`{"contains": {"type": "integer"}, "minContains": 0, "maxContains": 0}`,
		`{"prefixItems": []}`,
		`{"items": [{"type": "integer"}]}`,
		`{"$schema": "https://json-schema.org/draft/2020-12/schema#", "type": "object"}`,
		`{"$defs": {"x": 5}}`,
		`{"then": {"type": "integer"}, "else": false}`,
		`{"uniqueItems": "yes"}`,
		`{"const": {"$ref": "#/nowhere"}}`,
		`true`,
		`false`,
		`5`,
	} {
		raw := mustJSON(s)
		lib, lerr := libCompile(raw, nil)
		sch, jerr := Compile(raw, "", repoOptions(nil))
		if (lerr == nil) != (jerr == nil) {
			t.Errorf("%s: compile disagrees:\n  library: %v\n  jsv:     %v", s, lerr, jerr)
			continue
		}
		if lerr != nil {
			continue
		}
		for _, d := range docs {
			doc := mustJSON(d)
			le, je := lib.Validate(doc), sch.Validate(doc, ValidateOptions{})
			if (le == nil) != (je == nil) {
				t.Errorf("%s on %s:\n  library: %v\n  jsv:     %v", s, d, le, je)
			}
			// ValidateChange with a change somewhere, or everywhere, agrees.
			for _, changed := range [][]string{{""}, {"/a"}, {"/a/a"}, {"/loop"}} {
				if ce := sch.ValidateChange(doc, changed, ValidateOptions{}); je == nil && ce != nil {
					t.Errorf("%s on %s: ValidateChange(%q) = %v, Validate = nil", s, d, changed, ce)
				}
			}
		}
	}
}

// signedField finds a number written with a sign where a format has
// digits: the library reads those fields with strconv.Atoi, which takes a
// sign, so it passes "+2:00:00Z" as a time and "+1.2.3.4" as an ipv4.
// jsv does not: RFC 3339 and RFC 2673 have digits only there.
var signedField = regexp.MustCompile(`(^|[.:Tt\[+-])[+-][0-9]`)

// TestDifferentialFormats: on strings near valid ones, the two validators
// read every format alike, signed fields aside.
func TestDifferentialFormats(t *testing.T) {
	seeds := map[string][]string{
		"date-time":             {"2026-10-15T12:00:00Z", "2026-02-28T23:59:60+01:00", "1990-12-31T15:59:60-08:00", "2026-10-15t12:00:00.123z"},
		"date":                  {"2026-10-15", "2024-02-29", "0000-01-01"},
		"time":                  {"12:00:00Z", "23:59:60Z", "08:30:06.283185+00:20", "01:02:03-23:59"},
		"duration":              {"P1Y2M3DT4H5M6S", "PT1H", "P3W", "P1M", "PT0S"},
		"email":                 {"joe.bloggs@example.com", "\"joe bloggs\"@example.com", "a@[127.0.0.1]", "a@[IPv6:::1]", "te~st@example.com"},
		"hostname":              {"www.example.com", "xn--4gbwdl.xn--wgbh1c", "a-b.c", "example."},
		"ipv4":                  {"192.168.0.1", "0.0.0.0", "255.255.255.255"},
		"ipv6":                  {"::1", "1:2:3:4:5:6:7:8", "::ffff:192.168.0.1", "fe80::1"},
		"uri":                   {"http://foo.bar/?baz=qux#quux", "urn:oasis:names:x", "http://[::1]:80/a", "mailto:a@b.c", "http://a.b/%41"},
		"uri-reference":         {"/abc", "#frag", "a/b?c", "//x.y/z", "http://a.b/c"},
		"iri":                   {"http://ƒøø.ßår/?∂éœ=πîx#πîüx", "http://a.b/c"},
		"iri-reference":         {"/âππ", "#ƒrägmênt"},
		"uri-template":          {"http://example.com/dictionary/{term:1}/{term}", "a/{b}/c"},
		"uuid":                  {"2eb8aa08-aa98-11ea-b4aa-73b441d16380", "2EB8AA08-AA98-11EA-B4AA-73B441D16380"},
		"json-pointer":          {"/foo/bar~0/baz~1/%a", "", "/a~1b"},
		"relative-json-pointer": {"1", "0/foo/bar", "2/0/baz/1/zip", "0#"},
		"regex":                 {"^a[0-9]+$", "(a|b)*", "\\u0041{2}"},
	}
	names := make([]string, 0, len(seeds))
	for name := range seeds {
		names = append(names, name)
	}
	sort.Strings(names)
	alphabet := []byte("0123456789+-.:TZtz/@[]{}~%#? aP_\"\\x")
	r := rand.New(rand.NewSource(7))
	for _, name := range names {
		raw := map[string]any{"format": name}
		lib, err := libCompile(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		sch, err := Compile(raw, "", repoOptions(nil))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		valid, signed := 0, 0
		for i := 0; i < 20000; i++ {
			b := []byte(seeds[name][r.Intn(len(seeds[name]))])
			for m := r.Intn(3); m > 0; m-- {
				switch r.Intn(4) {
				case 0:
					if len(b) > 0 {
						j := r.Intn(len(b))
						b = append(b[:j], b[j+1:]...)
					}
				case 1:
					j := r.Intn(len(b) + 1)
					b = append(b[:j], append([]byte{alphabet[r.Intn(len(alphabet))]}, b[j:]...)...)
				case 2:
					if len(b) > 0 {
						b[r.Intn(len(b))] = alphabet[r.Intn(len(alphabet))]
					}
				case 3:
					if len(b) > 1 {
						j := r.Intn(len(b) - 1)
						b[j], b[j+1] = b[j+1], b[j]
					}
				}
			}
			s := string(b)
			if seen[s] {
				continue
			}
			seen[s] = true
			le, je := lib.Validate(s), sch.Validate(s, ValidateOptions{})
			if je == nil {
				valid++
			}
			if (le == nil) == (je == nil) {
				continue
			}
			if le == nil && signedField.MatchString(s) {
				signed++
				continue
			}
			t.Errorf("%s %q: library valid=%v, jsv valid=%v", name, s, le == nil, je == nil)
		}
		t.Logf("%s: %d strings, %d valid; %d with a signed field that only the library accepts", name, len(seen), valid, signed)
		if valid == 0 || valid == len(seen) {
			t.Errorf("%s: the strings do not exercise both verdicts", name)
		}
	}
}
