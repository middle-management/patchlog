package jsv

import (
	"math/rand"
	"regexp"
	"testing"

	"github.com/middle-management/patchlog/internal/pattern"
)

// These tests fix behaviour that was first established by running jsv
// against the JSON Schema library the server used before: which schemas
// compile, what a reference cycle does,
// how each format reads strings near valid ones. The two agreed on all of
// it, but for what the comments below name.

// repoOptions are the Options the server compiles schemas with, less the
// idn formats of internal/schema: formats asserted, patterns read by
// internal/pattern.
func repoOptions(load func(string) (any, error)) Options {
	return Options{
		Load:         load,
		AssertFormat: true,
		Regexp: func(p string) (Matcher, error) {
			re, err := pattern.Compile(p)
			if err != nil {
				return nil, err
			}
			return re, nil
		},
	}
}

// TestGeneratedDocuments validates generated documents, most of them
// nearly valid, against the hand-written schemas: Collect reports
// failures exactly when Validate fails, and both verdicts occur.
func TestGeneratedDocuments(t *testing.T) {
	const perSchema = 3000
	for _, ts := range testSchemas {
		t.Run(ts.name, func(t *testing.T) {
			raw := mustJSON(ts.schema)
			sch, err := Compile(raw, "", repoOptions(nil))
			if err != nil {
				t.Fatal(err)
			}
			r := rand.New(rand.NewSource(1))
			valid := 0
			for i := 0; i < perSchema; i++ {
				g := &generator{r: r, root: raw, noise: []float64{0, 0.02, 0.1}[i%3]}
				doc := g.gen(raw, 0)
				err := sch.Validate(doc, ValidateOptions{})
				checkCollect(t, sch, doc, err)
				if err == nil {
					valid++
				}
			}
			if valid != ts.valid {
				t.Errorf("%d of %d documents are valid, want %d", valid, perSchema, ts.valid)
			}
		})
	}
}

// TestSchemas: which schemas compile, and the verdicts of those that do
// on a few documents ("v" valid, "-" invalid, in the order of docs; ""
// for a schema that does not compile).
func TestSchemas(t *testing.T) {
	docs := []string{`null`, `{}`, `5`, `"s"`, `[1]`, `{"a": 1}`, `{"a": {"a": "s"}}`, `{"loop": 1}`}
	for _, tc := range []struct{ schema, want string }{
		// Only what is referred to is compiled, so loaded.
		{`{"$defs": {"unused": {"$ref": "https://elsewhere.test/x"}}}`, "vvvvvvvv"},
		{`{"$defs": {"unused": {"$ref": "#/nowhere"}}}`, "vvvvvvvv"},
		{`{"$defs": {"unused": {"type": "nope"}}}`, ""},
		{`{"$defs": {"unused": {"pattern": "("}}}`, ""},
		{`{"$ref": "#/nowhere"}`, ""},
		{`{"$ref": "#nowhere"}`, ""},
		{`{"$ref": "https://elsewhere.test/x"}`, ""},
		{`{"unknown": {"$ref": "#/nowhere"}}`, "vvvvvvvv"},
		{`{"properties": {"a": {"$ref": "#/unknown/x"}}, "unknown": {"x": {"type": "string"}}}`, "vvvvv--v"},
		// Reference cycles: the schema that comes back to itself fails.
		{`{"$ref": "#"}`, "--------"},
		{`{"allOf": [{"$ref": "#"}]}`, "--------"},
		{`{"anyOf": [{"type": "null"}, {"$ref": "#"}]}`, "v-------"},
		{`{"oneOf": [{"type": "null"}, {"$ref": "#"}]}`, "v-------"},
		{`{"if": {"type": "object"}, "then": {"$ref": "#"}}`, "v-vvv---"},
		{`{"not": {"$ref": "#"}}`, "vvvvvvvv"},
		{`{"not": {"not": {"$ref": "#"}}}`, "--------"},
		{`{"properties": {"a": {"$ref": "#"}}, "dependentSchemas": {"loop": {"$ref": "#"}}}`, "vvvvvvv-"},
		{`{"$ref": "#/$defs/a", "$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"anyOf": [{"type": "integer"}, {"$ref": "#/$defs/a"}]}}}`, "--v-----"},
		{`{"$dynamicAnchor": "x", "anyOf": [{"type": "integer"}, {"$dynamicRef": "#x"}]}`, "--v-----"},
		{`{"properties": {"a": {"$ref": "#"}}, "unevaluatedProperties": {"$ref": "#"}}`, "vvvvvvvv"},
		// Malformed keywords.
		{`{"$id": "http://x.test/a#frag"}`, ""},
		{`{"$anchor": "a", "$defs": {"x": {"$anchor": "a"}}}`, ""},
		{`{"type": []}`, ""},
		{`{"type": "nope"}`, ""},
		{`{"type": ["string", "string"]}`, ""},
		{`{"allOf": []}`, ""},
		{`{"enum": []}`, "--------"},
		{`{"enum": [1, 1]}`, "--------"},
		{`{"required": ["a", "a"]}`, ""},
		{`{"minLength": 1.5}`, ""},
		{`{"minLength": 2.0}`, "vvv-vvvv"},
		{`{"minLength": -1}`, ""},
		{`{"multipleOf": 0}`, ""},
		{`{"format": 5}`, ""},
		{`{"then": 5}`, ""},
		{`{"title": 5}`, ""},
		{`{"properties": {"a": 5}}`, ""},
		{`{"properties": []}`, ""},
		{`{"patternProperties": {"(": true}}`, ""},
		{`{"dependentRequired": {"a": "b"}}`, ""},
		{`{"dependentRequired": {"a": ["b"]}}`, "vvvvv--v"},
		{`{"minContains": 2}`, "vvvvvvvv"},
		{`{"contains": {"type": "integer"}, "minContains": 0, "maxContains": 0}`, "vvvv-vvv"},
		{`{"prefixItems": []}`, ""},
		{`{"items": [{"type": "integer"}]}`, ""},
		{`{"$schema": "https://json-schema.org/draft/2020-12/schema#", "type": "object"}`, "-v---vvv"},
		{`{"$defs": {"x": 5}}`, ""},
		{`{"then": {"type": "integer"}, "else": false}`, "vvvvvvvv"},
		{`{"uniqueItems": "yes"}`, ""},
		{`{"const": {"$ref": "#/nowhere"}}`, "--------"},
		{`true`, "vvvvvvvv"},
		{`false`, "--------"},
		{`5`, ""},
		// Keywords of earlier drafts are refused, not ignored (the library
		// applied both).
		{`{"dependencies": {"a": ["b"]}}`, ""},
		{`{"$recursiveRef": "#"}`, ""},
		{`{"$schema": "http://json-schema.org/draft-07/schema#"}`, ""},
	} {
		sch, err := Compile(mustJSON(tc.schema), "", repoOptions(nil))
		if err != nil {
			if tc.want != "" {
				t.Errorf("%s: %v", tc.schema, err)
			}
			continue
		}
		got := ""
		for _, d := range docs {
			doc := mustJSON(d)
			err := sch.Validate(doc, ValidateOptions{})
			checkCollect(t, sch, doc, err)
			if err == nil {
				got += "v"
			} else {
				got += "-"
			}
			// ValidateChange with a change somewhere, or everywhere, agrees.
			for _, changed := range [][]string{{""}, {"/a"}, {"/a/a"}, {"/loop"}} {
				if ce := sch.ValidateChange(doc, changed, ValidateOptions{}); err == nil && ce != nil {
					t.Errorf("%s on %s: ValidateChange(%q) = %v, Validate = nil", tc.schema, d, changed, ce)
				}
			}
		}
		if got != tc.want {
			t.Errorf("%s: verdicts %q, want %q", tc.schema, got, tc.want)
		}
	}
}

// TestCycleFailure: a reference cycle is reported as one, with the schema
// it is in.
func TestCycleFailure(t *testing.T) {
	sch, err := Compile(mustJSON(`{"properties": {"a": {"$ref": "#/$defs/loop"}}, "$defs": {"loop": {"allOf": [{"$ref": "#/$defs/loop"}]}}}`), "https://example.test/s", Options{})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sch.Collect(mustJSON(`{"a": 1}`), ValidateOptions{})
	if err != nil || len(fs) != 1 || fs[0].InstancePath != "/a" || fs[0].Cycle != "https://example.test/s#/$defs/loop" {
		t.Errorf("Collect = %+v, %v", fs, err)
	}
}

// signedField finds a number written with a sign where a format has
// digits. The library read those fields with strconv.Atoi, which takes a
// sign, and so passed "+2:00:00Z" as a time and "+1.2.3.4" as an ipv4;
// jsv does not: RFC 3339 and RFC 2673 have digits only there.
var signedField = regexp.MustCompile(`(^|[.:Tt\[+-])[+-][0-9]`)

// TestFormats: each format on strings that are valid, and on ones near
// them that are not.
func TestFormats(t *testing.T) {
	for name, tc := range map[string]struct{ valid, invalid []string }{
		"date-time": {
			[]string{"2026-10-15T12:00:00Z", "2026-02-28T00:59:60+01:00", "1990-12-31T15:59:60-08:00", "2026-10-15t12:00:00.123z"},
			[]string{"2026-10-15", "2026-10-15 12:00:00Z", "2026-10-15T12:00:00", "2026-02-30T12:00:00Z", "2026-10-15T24:00:00Z",
				"2026-10-15T12:00:60Z", "2026-10-15T12:00:00.Z", "2026-10-15T+2:00:00Z", "2026-10-15T12:-0:00Z", "2026-10-15T12:00:00+1:00"},
		},
		"date": {
			[]string{"2026-10-15", "2024-02-29", "0000-01-01"},
			[]string{"2026-02-29", "2026-13-01", "2026-00-10", "2026-1-01", "26-10-15", "2026/10/15", "2026-10-32", "+026-10-15"},
		},
		"time": {
			[]string{"12:00:00Z", "23:59:60Z", "08:30:06.283185+00:20", "01:02:03-23:59", "12:00:00z"},
			[]string{"12:00:00", "24:00:00Z", "12:60:00Z", "12:00:61Z", "12:00:60Z", "1:00:00Z", "12:00:00+24:00", "12:00:00+0100",
				"+2:00:00Z", "12:-0:00Z", "12:00:+0Z", "01:02:03-+3:59", "12:00:00.Z"},
		},
		"duration": {
			[]string{"P1Y2M3DT4H5M6S", "PT1H", "P3W", "P1M", "PT0S"},
			[]string{"P", "PT", "1Y", "P1S", "P1YT", "P1D2M", "P1W2D", "PT1H2H", "P-1D", "P1.5D"},
		},
		"email": {
			[]string{"joe.bloggs@example.com", "\"joe bloggs\"@example.com", "a@[127.0.0.1]", "a@[IPv6:::1]", "te~st@example.com"},
			[]string{"joe", ".joe@example.com", "joe.@example.com", "jo..e@example.com", "joe bloggs@example.com",
				"joe@-example.com", "joe@[127.0.0.256]", "a@[+127.0.0.1]", "joe@example..com"},
		},
		"hostname": {
			[]string{"www.example.com", "xn--4gbwdl.xn--wgbh1c", "a-b.c", "example."},
			[]string{"", "-a.example", "a-.example", "a_b.example", "a..b", "exa mple.com", "exämple.com"},
		},
		"ipv4": {
			[]string{"192.168.0.1", "0.0.0.0", "255.255.255.255"},
			[]string{"256.0.0.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.", "+1.2.3.4", "192.168.-0.1", "1.2.3.a", "::1"},
		},
		"ipv6": {
			[]string{"::1", "1:2:3:4:5:6:7:8", "::ffff:192.168.0.1", "fe80::1"},
			[]string{"1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "::g", "fe80::1%eth0", "1.2.3.4", "12345::"},
		},
		"uri": {
			[]string{"http://foo.bar/?baz=qux#quux", "urn:oasis:names:x", "http://[::1]:80/a", "mailto:a@b.c", "http://a.b/%41"},
			[]string{"/abc", "//x.y/z", "http://a.b/%zz", "http://[::g]/", ":// missing scheme", "abc"},
		},
		"uri-reference": {
			[]string{"/abc", "#frag", "a/b?c", "//x.y/z", "http://a.b/c", ""},
			[]string{"\\\\WINDOWS\\fileshare", "http://a.b/%zz", "#frag\\ment"},
		},
		"uri-template": {
			[]string{"http://example.com/dictionary/{term:1}/{term}", "a/{b}/c"},
			[]string{"http://example.com/dictionary/{term:1}/{term", "a/{b{c}}", "a/}b{"},
		},
		"uuid": {
			[]string{"2eb8aa08-aa98-11ea-b4aa-73b441d16380", "2EB8AA08-AA98-11EA-B4AA-73B441D16380"},
			[]string{"2eb8aa08-aa98-11ea-b4aa-73b441d1638", "2eb8aa08aa9811eab4aa73b441d16380", "2eb8aa08-aa98-11ea-b4aa-73b441d1638g",
				"2eb8aa08-aa98-11ea-b4aa73b4-41d16380", "{2eb8aa08-aa98-11ea-b4aa-73b441d16380}"},
		},
		"json-pointer": {
			[]string{"/foo/bar~0/baz~1/%a", "", "/a~1b", "/"},
			[]string{"a", "/a~", "/a~2", "#/a"},
		},
		"relative-json-pointer": {
			[]string{"1", "0/foo/bar", "2/0/baz/1/zip", "0#"},
			[]string{"/foo", "-1/a", "01/a", "0##", "1a", ""},
		},
		"regex": {
			[]string{"^a[0-9]+$", "(a|b)*", "\\u0041{2}"},
			[]string{"(", "a{2,1}", "[z-a]", "\\uD800"},
		},
	} {
		sch, err := Compile(map[string]any{"format": name}, "", repoOptions(nil))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range tc.valid {
			if err := sch.Validate(s, ValidateOptions{}); err != nil {
				t.Errorf("%s %q: %v", name, s, err)
			}
		}
		for _, s := range tc.invalid {
			if err := sch.Validate(s, ValidateOptions{}); err == nil {
				t.Errorf("%s %q is valid", name, s)
			}
		}
	}
	// Signed fields, the one place the library read a format otherwise.
	for _, s := range []string{"+2:00:00Z", "12:-0:00Z", "+1.2.3.4", "a@[+127.0.0.1]"} {
		if !signedField.MatchString(s) {
			t.Errorf("signedField does not match %q", s)
		}
	}
}
