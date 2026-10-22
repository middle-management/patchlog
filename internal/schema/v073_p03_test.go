package schema

import (
	"errors"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const d073 = `"$schema":"https://json-schema.org/draft/2020-12/schema"`

// writeCheck validates a dialect document as its write does (§6.2 step 5),
// against newStore's revisions.
func writeCheck(doc string) error { return NewValidator().Validate(j(doc), newStore().load) }

// isInvalid reports whether err is a 422 invalid: a schema that isn't
// valid, or one its dialect's meta-schema refuses.
func isInvalid(err error) bool {
	var se *SchemaError
	var ve *ValidationError
	return errors.As(err, &se) || errors.As(err, &ve)
}

func isSchemaErr(err error) bool {
	var se *SchemaError
	var re *RefError
	return errors.As(err, &se) && !errors.As(err, &re)
}

// CIS-10: a schema written with $id in any subschema, root included, is
// invalid, not schema_ref (§6.1).
func TestV073WrittenID(t *testing.T) {
	for _, doc := range []string{
		`{` + d073 + `,"$id":"https://example.com/s"}`,
		`{` + d073 + `,"$id":"` + pathPerson + `"}`,
		`{` + d073 + `,"properties":{"a":{"$id":"x"}}}`,
		`{` + d073 + `,"$defs":{"a":{"$id":"` + pathAddress + `"}}}`,
	} {
		if err := writeCheck(doc); !isSchemaErr(err) {
			t.Errorf("%s: got %T %v, want SchemaError", doc, err, err)
		}
		if err := CheckSchemaDocument(j(doc), ""); !isSchemaErr(err) {
			t.Errorf("check %s: got %T %v, want SchemaError", doc, err, err)
		}
	}
}

// CIS-11: $schema in any subschema but the root, dialect or not, is
// invalid when written (§6.1).
func TestV073WrittenNestedSchema(t *testing.T) {
	for _, doc := range []string{
		`{` + d073 + `,"properties":{"a":{` + d073 + `}}}`,
		`{` + d073 + `,"items":{"$schema":"` + pathAddress + `"}}`,
		`{` + d073 + `,"allOf":[{"$schema":"http://json-schema.org/draft-07/schema#"}]}`,
		`{` + d073 + `,"$defs":{"a":{"$schema":3}}}`,
	} {
		// The meta-schema refuses a $schema that isn't a URI first.
		if err := writeCheck(doc); !isInvalid(err) {
			t.Errorf("%s: got %T %v, want invalid", doc, err, err)
		}
		if err := CheckSchemaDocument(j(doc), ""); !isSchemaErr(err) {
			t.Errorf("check %s: got %T %v, want SchemaError", doc, err, err)
		}
	}
	// The root's own $schema is the dialect's; anything else stays schema_ref.
	var re *RefError
	if err := CheckSchemaDocument(j(`{"$schema":"`+pathAddress+`"}`), ""); !errors.As(err, &re) {
		t.Errorf("root $schema: got %v, want RefError", err)
	}
}

var (
	pathLib  = "/r/schemas/lib/rev/" + rev('h')
	pathUser = "/r/schemas/user/rev/" + rev('i')
)

func anchorStore() *store {
	s := newStore()
	s.docs[pathLib] = j(`{` + d073 + `,"$anchor":"top","type":"object",
		"$defs":{"num":{"$anchor":"num","type":"number"},"node":{"$dynamicAnchor":"node","type":"string"}},
		"definitions":{"flag":{"$anchor":"flag.v-1_x","type":"boolean"}}}`)
	s.docs[pathUser] = j(`{` + d073 + `,"type":"object","properties":{
		"n":{"$ref":"` + pathLib + `#num"},"s":{"$ref":"` + pathLib + `#node"},
		"t":{"$ref":"` + pathLib + `#top"},"f":{"$ref":"` + pathLib + `#flag.v-1_x"}}}`)
	return s
}

// CIS-13: a revision path's plain-name fragment is resolved by an $anchor
// or $dynamicAnchor of the revision; one that names nothing makes the
// schema invalid (§6.1).
func TestV073RevisionAnchors(t *testing.T) {
	v := NewValidator()
	s := anchorStore()
	if err := v.Validate(s.docs[pathUser], s.load); err != nil {
		t.Fatalf("writing the schema: %v", err)
	}
	if err := v.Validate(j(`{"$schema":"`+pathUser+`","n":1,"s":"x","t":{},"f":true}`), s.load); err != nil {
		t.Fatalf("valid: %v", err)
	}
	var ve *ValidationError
	if err := v.Validate(j(`{"$schema":"`+pathUser+`","n":"1","s":1,"t":2,"f":0}`), s.load); !errors.As(err, &ve) {
		t.Fatalf("got %v, want ValidationError", err)
	}
	got := map[string]bool{}
	for _, d := range ve.Errors {
		got[d.Pointer] = true
	}
	for _, p := range []string{"/n", "/s", "/t", "/f"} {
		if !got[p] {
			t.Errorf("no error at %s: %+v", p, ve.Errors)
		}
	}
	for _, frag := range []string{"#nope", "#Num", "#1num", "#num%41", "#$defs/num"} {
		doc := `{` + d073 + `,"$ref":"` + pathLib + frag + `"}`
		if err := v.Validate(j(doc), s.load); !isSchemaErr(err) {
			t.Errorf("%s: got %T %v, want SchemaError", frag, err, err)
		}
	}
	// Names are parsed, and found, with the revision they name.
	tg, err := ParseRefTarget(pathLib + "#num")
	if err != nil || tg.Ref.Path() != pathLib || tg.Anchor != "num" || tg.Pointer != nil {
		t.Fatalf("ParseRefTarget = %+v, %v", tg, err)
	}
	if r, p, err := SplitRef(pathLib + "#num"); err != nil || r.Path() != pathLib || p != nil {
		t.Fatalf("SplitRef = %v, %v, %v", r, p, err)
	}
	if refs := Refs(s.docs[pathUser]); len(refs) != 1 || refs[0].Path() != pathLib {
		t.Fatalf("Refs = %+v", refs)
	}
	if locs := RefLocations(s.docs[pathUser]); len(locs) != 4 || locs[0].Ref.Path() != pathLib || locs[0].Raw != pathLib+"#flag.v-1_x" {
		t.Fatalf("RefLocations = %+v", locs)
	}
	// Not a URI fragment: schema_ref, as before.
	var re *RefError
	if _, err := ParseRefTarget(pathLib + "#a b"); !errors.As(err, &re) {
		t.Errorf("unencoded space: got %v", err)
	}
}

// CIS-15: a format draft 2020-12 doesn't define makes a written schema
// invalid; V073 asserts exactly that set, idn-email and idn-hostname with
// UTS 46, and Legacy keeps the library's behaviour (§6.2 step 5).
func TestV073Formats(t *testing.T) {
	for f := range formats2020 {
		doc := `{` + d073 + `,"format":"` + f + `"}`
		if err := writeCheck(doc); err != nil {
			t.Errorf("format %s: %v", f, err)
		}
	}
	if len(formats2020) != 19 {
		t.Errorf("%d formats", len(formats2020))
	}
	for _, f := range []string{"semver", "period", "foo", "Email", ""} {
		doc := `{` + d073 + `,"properties":{"a":{"format":"` + f + `"}}}`
		if err := writeCheck(doc); !isSchemaErr(err) {
			t.Errorf("format %q: got %T %v, want SchemaError", f, err, err)
		}
	}

	p := "/r/schemas/formats/rev/" + rev('j')
	s := newStore()
	s.docs[p] = j(`{` + d073 + `,"properties":{
		"e":{"format":"idn-email"},"h":{"format":"idn-hostname"},
		"v":{"format":"semver"},"p":{"format":"period"},"x":{"format":"x-unknown"}}}`)
	v := NewValidator()
	check := func(rules Rules, member, value string, ok bool) {
		t.Helper()
		err := v.ValidateRules(map[string]any{"$schema": p, member: value}, s.load, rules)
		var ve *ValidationError
		if ok && err != nil || !ok && !errors.As(err, &ve) {
			t.Errorf("%v: %s %q: got %v, want ok %v", rules, member, value, err, ok)
		}
	}
	for _, c := range []struct {
		member, value string
		ok            bool
	}{
		{"e", "user@example.com", true},
		{"e", "用户@例子.广告", true},
		{"e", "ñandú@ñandú.example", true},
		{"e", `"quoted name"@example.com`, true},
		{"e", "x@[192.0.2.1]", true},
		{"e", "x@[IPv6:2001:db8::1]", true},
		{"e", "not an email", false},
		{"e", "@example.com", false},
		{"e", "a..b@example.com", false},
		{"e", "x@[IPv6:192.0.2.1]", false},
		{"e", "x@-bad-.example", false},
		{"h", "example.com", true},
		{"h", "EXAMPLE.com", true},
		{"h", "실례.테스트", true},
		{"h", "xn--ihqwcrb4cv8a8dqg056pqjye", true},
		{"h", "ex ample.com", false},
		{"h", "a..b", false},
		{"h", "-a.example", false},
		{"h", "xn--X", false},
		{"h", "", false},
		{"h", strings.Repeat("a", 64) + ".example", false},
		{"v", "not semver", true},
		{"p", "not a period", true},
		{"x", "anything", true},
	} {
		check(V073, c.member, c.value, c.ok)
	}
	// Legacy, as every stored revision loads for now: semver and period
	// asserted, idn-* not.
	check(Legacy, "e", "not an email", true)
	check(Legacy, "h", "ex ample.com", true)
	check(Legacy, "v", "not semver", false)
	check(Legacy, "p", "not a period", false)
	check(Legacy, "x", "anything", true)
	if err := v.Validate(map[string]any{"$schema": p, "v": "not semver"}, s.load); err == nil {
		t.Error("Validate compiles stored revisions under V073")
	}
}

// CIS-16: patterns in schemas read \\uXXXX as \x{XXXX}, a surrogate pair as
// one code point, and refuse a lone surrogate (§6.6): pattern,
// patternProperties, the regex format and the meta-schema's check of
// patterns, written or stored.
func TestV073Patterns(t *testing.T) {
	p := "/r/schemas/pat/rev/" + rev('k')
	doc := `{` + d073 + `,"type":"object","properties":{
		"a":{"pattern":"^\\u00e9+$"},"b":{"pattern":"^[\\u00e0-\\u00ff]$"},"e":{"pattern":"^\\uD83D\\uDE00$"},"r":{"format":"regex"}},
		"patternProperties":{"^\\u00f1":{"type":"integer"}}}`
	if err := writeCheck(doc); err != nil {
		t.Fatalf("writing: %v", err)
	}
	s := newStore()
	s.docs[p] = j(doc)
	v := NewValidator()
	for _, rules := range []Rules{Legacy, V073} {
		if err := v.ValidateRules(j(`{"$schema":"`+p+`","a":"éé","b":"ÿ","e":"😀","r":"^\\u00e9$","ña":1}`), s.load, rules); err != nil {
			t.Errorf("%v: valid: %v", rules, err)
		}
		var ve *ValidationError
		err := v.ValidateRules(j(`{"$schema":"`+p+`","a":"e","b":"a","e":"x","r":"(?=a)","ño":"1"}`), s.load, rules)
		if !errors.As(err, &ve) || len(ve.Errors) != 5 {
			t.Errorf("%v: invalid: %v", rules, err)
		}
	}
	for _, re := range []string{`\\uD800`, `[\\uDC00]`, `\\uD83D\\u0041`, `\\x{DFFF}`, `(a)\\1`, `\\u{41}`} {
		for _, doc := range []string{
			`{` + d073 + `,"pattern":"` + re + `"}`,
			`{` + d073 + `,"patternProperties":{"` + re + `":{}}}`,
		} {
			if err := writeCheck(doc); !isInvalid(err) {
				t.Errorf("%s: got %v, want invalid", doc, err)
			}
			if err := CheckSchemaDocument(j(doc), ""); !isSchemaErr(err) {
				t.Errorf("check %s: got %v, want SchemaError", doc, err)
			}
		}
	}
	// After an escaped backslash, RE2 reads "u0041" as written.
	if err := writeCheck(`{` + d073 + `,"pattern":"^\\\\u0041$"}`); err != nil {
		t.Errorf("escaped backslash: %v", err)
	}
	// A pattern RE2 took as written compiles as it did, though the
	// translation refuses it.
	s.docs[p] = j(`{` + d073 + `,"properties":{"a":{"pattern":"^a\\x{D800}?$"}}}`)
	if err := CheckSchemaDocument(s.docs[p], p); err != nil {
		t.Errorf("stored: %v", err)
	}
	if err := NewValidator().Validate(j(`{"$schema":"`+p+`","a":"a"}`), s.load); err != nil {
		t.Errorf("stored: %v", err)
	}
}

// CIS-17: stored revisions are checked in stored mode, by v0.55's rules,
// and compile under their marker, cached by path and marker (§6.1).
func TestV073StoredModeAndMarker(t *testing.T) {
	p := "/r/schemas/old/rev/" + rev('l')
	doc := j(`{` + d073 + `,"$id":"` + p + `","properties":{
		"n":{` + d073 + `,"type":"string"},"v":{"format":"semver"},"x":{"format":"x-mine"}}}`)
	if err := CheckSchemaDocument(doc, p); err != nil {
		t.Fatalf("stored mode: %v", err)
	}
	if err := checkStoredSchema(doc, p); err != nil {
		t.Fatalf("checkStoredSchema: %v", err)
	}
	if err := CheckSchemaDocument(doc, ""); !isSchemaErr(err) {
		t.Fatalf("write mode: %v", err)
	}
	s := newStore()
	s.docs[p] = doc
	v := NewValidator()
	bad := map[string]any{"$schema": p, "v": "x"}
	if err := v.ValidateRules(bad, s.load, Legacy); err == nil {
		t.Error("Legacy: semver not asserted")
	}
	if err := v.ValidateRules(bad, s.load, V073); err != nil {
		t.Errorf("V073: %v", err)
	}
	for _, r := range []Rules{Legacy, V073} {
		if _, ok := v.compiled.Get(compiledKey{p, r}); !ok {
			t.Errorf("%v not cached", r)
		}
	}
	if s.calls[p] != 1 {
		t.Errorf("loaded %d times", s.calls[p])
	}
}

// Invariant 3: a schema stored before the upgrade, with a format semver, a
// nested $schema and a root $id equal to its own path, validates its
// documents exactly as before.
func TestV073StoredBeforeUpgrade(t *testing.T) {
	p := "/r/schemas/before/rev/" + rev('m')
	s := newStore()
	s.docs[p] = j(`{` + d073 + `,"$id":"` + p + `","type":"object","properties":{
		"v":{"format":"semver"},"n":{` + d073 + `,"type":"string"}},"required":["v"]}`)
	v := NewValidator()
	if err := v.Validate(j(`{"$schema":"`+p+`","v":"1.2.3","n":"x"}`), s.load); err != nil {
		t.Fatalf("valid: %v", err)
	}
	var ve *ValidationError
	if err := v.Validate(j(`{"$schema":"`+p+`","v":"1.2","n":1}`), s.load); !errors.As(err, &ve) || len(ve.Errors) != 2 {
		t.Fatalf("got %v, want errors at /n and /v", err)
	}
	if ve.Errors[0].Pointer != "/n" || ve.Errors[1].Pointer != "/v" {
		t.Errorf("errors %+v", ve.Errors)
	}
}

// CIS-18: definitions holds subschemas, as $defs does; dependencies,
// $recursiveAnchor and $recursiveRef make a schema invalid (§6.5).
func TestV073Definitions(t *testing.T) {
	p := "/r/schemas/defs7/rev/" + rev('n')
	doc := `{` + d073 + `,"$ref":"#/definitions/a","definitions":{"a":{"type":"string","pattern":"^x"},
		"b":{"$anchor":"b","properties":{"r":{"$ref":"` + pathAddress + `"}}}}}`
	if err := writeCheck(doc); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := writeCheck(`{` + d073 + `,"$ref":"#b","definitions":{"b":{"$anchor":"b","type":"string"}}}`); err != nil {
		t.Errorf("anchor in definitions: %v", err)
	}
	if err := writeCheck(`{` + d073 + `,"definitions":{"a":{"foo":1}}}`); !isSchemaErr(err) {
		t.Errorf("unknown keyword in definitions: %v", err)
	}
	s := newStore()
	s.docs[p] = j(doc)
	v := NewValidator()
	if err := v.Validate(map[string]any{"$schema": p}, s.load); err == nil {
		t.Error("an object validated against a string schema")
	}
	if refs := Refs(s.docs[p]); len(refs) != 1 || refs[0].Path() != pathAddress {
		t.Errorf("Refs = %+v", refs)
	}
	if locs := RefLocations(s.docs[p]); len(locs) != 1 || locs[0].Pointer.String() != "/definitions/b/properties/r/$ref" {
		t.Errorf("RefLocations = %+v", locs)
	}
	if !IsKeyword("definitions") {
		t.Error("definitions is no keyword")
	}
	for _, doc := range []string{
		`{` + d073 + `,"dependencies":{"a":["b"]}}`,
		`{` + d073 + `,"dependencies":{"a":{}}}`,
		`{` + d073 + `,"$recursiveAnchor":true}`,
		`{` + d073 + `,"$recursiveAnchor":"a"}`,
		`{` + d073 + `,"$recursiveRef":"#"}`,
		`{` + d073 + `,"definitions":{"a":{"$recursiveRef":"#"}}}`,
	} {
		if err := writeCheck(doc); !isInvalid(err) {
			t.Errorf("%s: got %v, want invalid", doc, err)
		}
		if err := CheckSchemaDocument(j(doc), ""); !isSchemaErr(err) {
			t.Errorf("check %s: got %v, want SchemaError", doc, err)
		}
	}
}

// CIS-19: a well-formed top-level $successor, like a fresh $nonce, is no
// keyword of a schema document, written or stored (§6.5); any other is.
func TestV073SchemaSuccessor(t *testing.T) {
	for _, succ := range []string{"other-schema", "/r/schemas2/next.v2"} {
		doc := `{` + d073 + `,"$successor":"` + succ + `","$nonce":"abcdefghijklmnopqrstuvwxyz","type":"object","additionalProperties":false}`
		if err := writeCheck(doc); err != nil {
			t.Errorf("%s: %v", succ, err)
		}
		p := "/r/schemas/moved/rev/" + rev('o')
		s := newStore()
		s.docs[p] = j(doc)
		if err := CheckSchemaDocument(s.docs[p], p); err != nil {
			t.Errorf("stored %s: %v", succ, err)
		}
		if err := NewValidator().Validate(j(`{"$schema":"`+p+`"}`), s.load); err != nil {
			t.Errorf("validating against it: %v", err)
		}
		var ve *ValidationError
		if err := NewValidator().Validate(j(`{"$schema":"`+p+`","a":1}`), s.load); !errors.As(err, &ve) {
			t.Errorf("closed: got %v", err)
		}
	}
	for _, doc := range []string{
		`{` + d073 + `,"$successor":"Bad Name"}`,
		`{` + d073 + `,"$successor":"/r/ns/a/b"}`,
		`{` + d073 + `,"$successor":1}`,
		`{` + d073 + `,"properties":{"a":{"$successor":"x"}}}`,
	} {
		if err := writeCheck(doc); !isSchemaErr(err) {
			t.Errorf("%s: got %v, want SchemaError", doc, err)
		}
	}
}

// CheckFragment holds a rule's schema to §6.4.2; Configure compiles it
// (P20).
func TestV073CheckFragment(t *testing.T) {
	for _, f := range []string{
		`true`,
		`{"type":"string","pattern":"^\\u00e9$","format":"idn-email"}`,
		`{"$ref":"#/definitions/a","definitions":{"a":{"x-index":true}}}`,
		`{"$dynamicRef":"#n","$defs":{"n":{"$dynamicAnchor":"n"}}}`,
	} {
		if err := CheckFragment(j(f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, f := range []string{
		`{` + d073 + `}`,
		`{"items":{` + d073 + `}}`,
		`{"$id":"x"}`,
		`{"$ref":"` + pathAddress + `"}`,
		`{"$ref":"` + pathAddress + `#/$defs/zip"}`,
		`{"$dynamicRef":"` + pathAddress + `"}`,
		`{"foo":1}`,
		`{"dependencies":{}}`,
		`{"format":"semver"}`,
		`{"pattern":"(?=a)"}`,
		`{"pattern":"\\uDE00"}`,
		`{"$nonce":"abcdefghijklmnopqrstuvwxyz"}`,
		`{"$successor":"x"}`,
		`3`,
	} {
		if err := CheckFragment(j(f)); !isSchemaErr(err) {
			t.Errorf("%s: got %T %v, want SchemaError", f, err, err)
		}
	}
	c := jsonschema.NewCompiler()
	V073.Configure(c)
	if err := c.AddResource("urn:rule", j(`{"properties":{"a":{"pattern":"^\\u00e9$"},"e":{"format":"idn-email"}}}`)); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("urn:rule")
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(map[string]any{"a": "é", "e": "ü@example.com"}); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := sch.Validate(map[string]any{"e": "nope"}); err == nil {
		t.Error("idn-email not asserted")
	}
}
