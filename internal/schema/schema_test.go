package schema

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func rev(c byte) string { return "1" + strings.Repeat(string(c), 32) }

var (
	pathPerson  = "/r/schemas/person/rev/" + rev('a')
	pathAddress = "/r/schemas/address/rev/" + rev('b')
	pathMissing = "/r/schemas/missing/rev/" + rev('c')
	pathBranch  = "/r/feature-x/thing/rev/" + rev('d')
)

func j(s string) any { return jsonv.MustParse([]byte(s)) }

type store struct {
	mu    sync.Mutex
	docs  map[string]any
	calls map[string]int
}

func newStore() *store {
	return &store{
		docs: map[string]any{
			pathPerson: j(`{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"type": "object",
				"required": ["name", "age"],
				"properties": {
					"$schema": {"type": "string"},
					"name": {"type": "string", "minLength": 1},
					"age": {"type": "integer", "minimum": 0},
					"email": {"type": "string", "format": "email"},
					"born": {"type": "string", "format": "date-time"},
					"a/b": {"type": "string"},
					"address": {"$ref": "` + pathAddress + `"}
				},
				"additionalProperties": false
			}`),
			pathAddress: j(`{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"type": "object",
				"required": ["city"],
				"properties": {"city": {"type": "string"}, "zip": {"$ref": "#/$defs/zip"}},
				"$defs": {"zip": {"type": "string", "pattern": "^[0-9]{5}$"}}
			}`),
		},
		calls: map[string]int{},
	}
}

func (s *store) load(r Ref) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := r.Path()
	s.calls[p]++
	if r.NS == "feature-x" {
		return nil, ErrBranch
	}
	if d, ok := s.docs[p]; ok {
		return d, nil
	}
	return nil, ErrUnavailable
}

func TestParseRef(t *testing.T) {
	r, ok := ParseRef(pathPerson)
	if !ok || r.NS != "schemas" || r.Name != "person" || r.Rev != rev('a') || r.Path() != pathPerson {
		t.Fatalf("ParseRef = %+v, %v", r, ok)
	}
	for _, bad := range []string{
		"/r/a/b",
		"https://host/r/a/b/rev/" + rev('a'),
		pathPerson + "?x=1",
		"/r/a/b%41/rev/" + rev('a'),
		"/r/a/../b/rev/" + rev('a'),
		"/r/a/./b/rev/" + rev('a'),
		"/r/A/b/rev/" + rev('a'),
		pathPerson + "#",
		"/r/a/b/rev/1" + strings.Repeat("a", 31),
		"/r/a/b/rev/1" + strings.Repeat("1", 32),
		" " + pathPerson,
	} {
		if _, ok := ParseRef(bad); ok {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}
}

func TestUntyped(t *testing.T) {
	v := NewValidator()
	for _, d := range []any{nil, 1.0, "x", []any{}, j(`{"a":1}`), j(`{"$schemas":"x"}`)} {
		if err := v.Validate(d, nil); err != nil {
			t.Errorf("Validate(%v) = %v", d, err)
		}
	}
}

func TestMalformedSchema(t *testing.T) {
	v := NewValidator()
	s := newStore()
	for _, sv := range []any{
		1.0, nil, true,
		"/r/a/b",
		"https://host/r/a/b/rev/" + rev('a'),
		"https://patchlog.invalid" + pathPerson,
		pathPerson + "?q=1",
		strings.Replace(pathPerson, "person", "pers%6Fn", 1),
		"/r/schemas/x/../person/rev/" + rev('a'),
		"/r/schemas/./person/rev/" + rev('a'),
		"http://json-schema.org/draft-07/schema#",
		"https://json-schema.org/draft/2020-12/schema#",
		"",
	} {
		err := v.Validate(map[string]any{"$schema": sv}, s.load)
		var re *RefError
		if !errors.As(err, &re) {
			t.Errorf("$schema %v: got %v, want RefError", sv, err)
		}
	}
	if len(s.calls) != 0 {
		t.Errorf("loader called: %v", s.calls)
	}
}

func TestTypedValid(t *testing.T) {
	v := NewValidator()
	s := newStore()
	doc := j(`{"$schema":"` + pathPerson + `","name":"Ada","age":36,"email":"ada@example.com",
		"born":"1815-12-10T00:00:00Z","address":{"city":"London","zip":"12345"}}`)
	if err := v.Validate(doc, s.load); err != nil {
		t.Fatal(err)
	}
	// float64 integer-valued numbers satisfy "integer".
	doc = map[string]any{"$schema": pathPerson, "name": "Ada", "age": 3.0}
	if err := v.Validate(doc, s.load); err != nil {
		t.Fatal(err)
	}
}

func TestTypedInvalid(t *testing.T) {
	v := NewValidator()
	s := newStore()
	doc := j(`{"$schema":"` + pathPerson + `","name":"","age":3.5,"extra":true,"a/b":1,
		"address":{"zip":"abc"}}`)
	err := v.Validate(doc, s.load)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("got %v, want ValidationError", err)
	}
	got := map[string]bool{}
	for _, d := range ve.Errors {
		got[d.Pointer] = true
		if d.Message == "" {
			t.Errorf("empty message for %s", d.Pointer)
		}
	}
	for _, p := range []string{"", "/name", "/age", "/a~1b", "/address", "/address/zip"} {
		if !got[p] {
			t.Errorf("missing error at %q; got %+v", p, ve.Errors)
		}
	}
	// stable order
	err2 := v.Validate(doc, s.load)
	if err.Error() != err2.Error() {
		t.Errorf("unstable:\n%v\n%v", err, err2)
	}
}

func TestFormatAssertion(t *testing.T) {
	v := NewValidator()
	s := newStore()
	for _, extra := range []string{`"email":"not an email"`, `"born":"yesterday"`} {
		doc := j(`{"$schema":"` + pathPerson + `","name":"Ada","age":1,` + extra + `}`)
		var ve *ValidationError
		if err := v.Validate(doc, s.load); !errors.As(err, &ve) {
			t.Errorf("%s: got %v, want ValidationError", extra, err)
		}
	}
}

func TestRefChainAndCaching(t *testing.T) {
	v := NewValidator()
	s := newStore()
	ok := j(`{"$schema":"` + pathPerson + `","name":"a","age":1,"address":{"city":"x"}}`)
	bad := j(`{"$schema":"` + pathPerson + `","name":"a","age":1,"address":{"city":1}}`)
	if err := v.Validate(ok, s.load); err != nil {
		t.Fatal(err)
	}
	var ve *ValidationError
	if err := v.Validate(bad, s.load); !errors.As(err, &ve) || ve.Errors[0].Pointer != "/address/city" {
		t.Fatalf("got %v", err)
	}
	if s.calls[pathPerson] != 1 || s.calls[pathAddress] != 1 {
		t.Errorf("loader calls = %v, want one per path", s.calls)
	}
	// A different validator entry point sharing a cached dependency.
	s.docs[pathMissing] = j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"` + pathAddress + `"}`)
	if err := v.Validate(map[string]any{"$schema": pathMissing, "city": "x"}, s.load); err != nil {
		t.Fatal(err)
	}
	if s.calls[pathAddress] != 1 {
		t.Errorf("address loaded again: %v", s.calls)
	}
}

func TestUnavailableAndBranch(t *testing.T) {
	v := NewValidator()
	s := newStore()
	var ue *UnavailableError
	err := v.Validate(map[string]any{"$schema": pathMissing}, s.load)
	if !errors.As(err, &ue) || ue.Ref != pathMissing {
		t.Fatalf("got %v, want UnavailableError", err)
	}
	// unavailable through $ref
	p := "/r/schemas/refs-missing/rev/" + rev('e')
	s.docs[p] = j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"` + pathMissing + `"}`)
	err = v.Validate(map[string]any{"$schema": p}, s.load)
	if !errors.As(err, &ue) || ue.Ref != pathMissing {
		t.Fatalf("got %v, want UnavailableError for %s", err, pathMissing)
	}
	var re *RefError
	if err := v.Validate(map[string]any{"$schema": pathBranch}, s.load); !errors.As(err, &re) {
		t.Fatalf("branch: got %v, want RefError", err)
	}
	// forbidden
	deny := func(Ref) (any, error) { return nil, ErrForbidden }
	if err := NewValidator().Validate(map[string]any{"$schema": pathPerson}, deny); !errors.Is(err, ErrForbidden) {
		t.Fatalf("forbidden: got %v", err)
	}
	// a failed load is not cached
	delete(s.calls, pathMissing)
	s.docs[pathMissing] = j(`{"$schema":"https://json-schema.org/draft/2020-12/schema"}`)
	if err := v.Validate(map[string]any{"$schema": pathMissing}, s.load); err != nil {
		t.Fatal(err)
	}
}

func TestStoredSchemaInvalid(t *testing.T) {
	v := NewValidator()
	s := newStore()
	cases := map[string]string{
		"/r/s/unknown/rev/" + rev('f'):   `{"$schema":"https://json-schema.org/draft/2020-12/schema","foo":1}`,
		"/r/s/notschema/rev/" + rev('f'): `{"a":1}`,
		"/r/s/badref/rev/" + rev('f'):    `{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"http://x"}`,
		"/r/s/meta/rev/" + rev('f'):      `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":7}`,
	}
	for p, d := range cases {
		s.docs[p] = j(d)
		var se *SchemaError
		if err := v.Validate(map[string]any{"$schema": p}, s.load); !errors.As(err, &se) {
			t.Errorf("%s: got %v, want SchemaError", p, err)
		}
	}
	// own $id is allowed
	p := "/r/s/withid/rev/" + rev('g')
	s.docs[p] = j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"` + p + `","type":"object"}`)
	if err := v.Validate(map[string]any{"$schema": p}, s.load); err != nil {
		t.Fatal(err)
	}
}

func TestDialectDocuments(t *testing.T) {
	v := NewValidator()
	s := newStore()
	const d = `"$schema":"https://json-schema.org/draft/2020-12/schema"`
	valid := []string{
		`{` + d + `,"type":"object","properties":{"a":{"type":"string","x-index":{"sort":true}}}}`,
		`{` + d + `,"x-index":true,"$defs":{"n":{"type":"number"}},"items":{"$ref":"#/$defs/n"}}`,
		`{` + d + `,"properties":{"addr":{"$ref":"` + pathAddress + `"}}}`,
		`{` + d + `,"x-ref":{"pinned":true},"enum":[{"foo":1}],"const":{"$ref":"http://x"},"default":{"bar":1},"examples":[{"baz":1}]}`,
		`{` + d + `,"$dynamicAnchor":"n","$dynamicRef":"#n","patternProperties":{"^\\p{L}+$":{}}}`,
	}
	for _, doc := range valid {
		if err := v.Validate(j(doc), s.load); err != nil {
			t.Errorf("%s: %v", doc, err)
		}
	}
	type want int
	const (
		wantRef want = iota
		wantSchema
		wantInvalid
		wantUnavailable
		wantBad // ValidationError or SchemaError: both 422 invalid
	)
	invalid := map[string]want{
		`{` + d + `,"foo":1}`:                                              wantSchema,
		`{` + d + `,"properties":{"a":{"foo":1}}}`:                         wantSchema,
		`{` + d + `,"allOf":[{"definitions":{}}]}`:                         wantSchema,
		`{` + d + `,"$ref":"http://x"}`:                                    wantRef,
		`{` + d + `,"items":{"$ref":"/r/a/b"}}`:                            wantRef,
		`{` + d + `,"$ref":"https://patchlog.invalid` + pathAddress + `"}`: wantRef,
		`{` + d + `,"$dynamicRef":"` + pathAddress + `"}`:                  wantRef,
		`{` + d + `,"$id":"` + pathAddress + `"}`:                          wantRef,
		`{` + d + `,"$defs":{"x":{"$id":"x"}}}`:                            wantRef,
		`{` + d + `,"pattern":"^(?=a)"}`:                                   wantBad,
		`{` + d + `,"patternProperties":{"(a)\\1":{}}}`:                    wantBad,
		`{` + d + `,"type":"nope"}`:                                        wantInvalid,
		`{` + d + `,"$ref":"#/$defs/missing"}`:                             wantSchema,
		`{` + d + `,"$ref":"` + pathMissing + `"}`:                         wantUnavailable,
		`{` + d + `,"$ref":"` + pathBranch + `"}`:                          wantRef,
	}
	for doc, w := range invalid {
		err := v.Validate(j(doc), s.load)
		var (
			re *RefError
			se *SchemaError
			ve *ValidationError
			ue *UnavailableError
		)
		ok := false
		switch w {
		case wantRef:
			ok = errors.As(err, &re)
		case wantSchema:
			ok = errors.As(err, &se)
		case wantInvalid:
			ok = errors.As(err, &ve) && len(ve.Errors) > 0 && ve.Errors[0].Pointer == "/type"
		case wantUnavailable:
			ok = errors.As(err, &ue)
		case wantBad:
			ok = errors.As(err, &ve) || errors.As(err, &se)
		}
		if !ok {
			t.Errorf("%s: got %T %v, want kind %d", doc, err, err, w)
		}
	}
}

func TestCheckSchemaDocumentSelfID(t *testing.T) {
	doc := j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"` + pathPerson + `"}`)
	if err := CheckSchemaDocument(doc, pathPerson); err != nil {
		t.Fatal(err)
	}
	var re *RefError
	if err := CheckSchemaDocument(doc, pathAddress); !errors.As(err, &re) {
		t.Fatalf("got %v", err)
	}
	if err := CheckSchemaDocument(doc, ""); !errors.As(err, &re) {
		t.Fatalf("got %v", err)
	}
}

// A top-level $nonce of the fresh form is no keyword (§6.2, §C.7); any
// other $nonce is.
func TestCheckSchemaDocumentNonce(t *testing.T) {
	if err := CheckSchemaDocument(j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$nonce":"abcdefghijklmnopqrstuvwxyz"}`), ""); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{
		`{"$nonce":"short"}`,
		`{"properties":{"a":{"$nonce":"abcdefghijklmnopqrstuvwxyz"}}}`,
	} {
		var se *SchemaError
		if err := CheckSchemaDocument(j(d), ""); !errors.As(err, &se) {
			t.Errorf("%s: got %v, want SchemaError", d, err)
		}
	}
}

func TestRefs(t *testing.T) {
	doc := j(`{"$schema":"https://json-schema.org/draft/2020-12/schema",
		"$ref":"` + pathPerson + `",
		"properties":{"a":{"$ref":"` + pathAddress + `"},"b":{"$ref":"#/$defs/x"}},
		"$defs":{"x":{"items":{"$ref":"` + pathPerson + `"}}},
		"const":{"$ref":"` + pathMissing + `"}}`)
	got := Refs(doc)
	if len(got) != 2 || got[0].Path() != pathAddress || got[1].Path() != pathPerson {
		t.Fatalf("Refs = %+v", got)
	}
}

func TestConcurrent(t *testing.T) {
	v := NewValidator()
	s := newStore()
	doc := j(`{"$schema":"` + pathPerson + `","name":"a","age":1,"address":{"city":"x"}}`)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := v.Validate(doc, s.load); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestCheckSchemaDocumentRegexp(t *testing.T) {
	for _, d := range []string{
		`{"pattern":"^(?=a)"}`,
		`{"properties":{"a":{"pattern":"(?<!x)y"}}}`,
		`{"patternProperties":{"(a)\\1":{}}}`,
	} {
		var se *SchemaError
		if err := CheckSchemaDocument(j(d), ""); !errors.As(err, &se) {
			t.Errorf("%s: got %v, want SchemaError", d, err)
		}
	}
}

var pathFrag = "/r/schemas/frag/rev/" + rev('e')

func fragStore() *store {
	s := newStore()
	s.docs[pathAddress].(map[string]any)["$defs"].(map[string]any)["a b"] = j(`{"type":"integer"}`)
	s.docs[pathAddress].(map[string]any)["$defs"].(map[string]any)["x/y~z"] = j(`{"type":"boolean"}`)
	s.docs[pathFrag] = j(`{"$schema":"https://json-schema.org/draft/2020-12/schema",
		"type":"object","properties":{
			"home":{"$ref":"` + pathAddress + `#/$defs/zip"},
			"root":{"$ref":"` + pathAddress + `#"},
			"sp":{"$ref":"` + pathAddress + `#/$defs/a%20b"},
			"esc":{"$ref":"` + pathAddress + `#/$defs/x~1y~0z"},
			"esc2":{"$ref":"` + pathAddress + `#/$defs/x%7E1y%7E0z"}
		}}`)
	return s
}

func TestRefThroughFragment(t *testing.T) {
	v := NewValidator()
	s := fragStore()
	ok := j(`{"$schema":"` + pathFrag + `","home":"12345","root":{"city":"x"},"sp":3,"esc":true,"esc2":false}`)
	if err := v.Validate(ok, s.load); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if s.calls[pathAddress] != 1 {
		t.Errorf("address loaded %d times", s.calls[pathAddress])
	}
	bad := j(`{"$schema":"` + pathFrag + `","home":"abc","root":{},"sp":"s","esc":1}`)
	err := v.Validate(bad, s.load)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("got %v, want ValidationError", err)
	}
	got := map[string]bool{}
	for _, d := range ve.Errors {
		got[d.Pointer] = true
	}
	for _, p := range []string{"/home", "/root", "/sp", "/esc"} {
		if !got[p] {
			t.Errorf("missing error at %q: %+v", p, ve.Errors)
		}
	}
	if len(got) != 4 {
		t.Errorf("extra errors: %+v", ve.Errors)
	}
}

func TestRefsDropFragment(t *testing.T) {
	doc := j(`{"$schema":"https://json-schema.org/draft/2020-12/schema",
		"properties":{"a":{"$ref":"` + pathAddress + `#/$defs/zip"},"b":{"$ref":"` + pathAddress + `"},
		"c":{"$ref":"` + pathPerson + `#"},"d":{"$ref":"` + pathMissing + `#nope"},"e":{"$ref":"#/$defs/x"}}}`)
	got := Refs(doc)
	if len(got) != 2 || got[0].Path() != pathAddress || got[1].Path() != pathPerson {
		t.Fatalf("Refs = %+v", got)
	}
}

func TestBadRefFragments(t *testing.T) {
	v := NewValidator()
	s := fragStore()
	for _, frag := range []string{
		"#foo",              // anchor on a foreign revision
		"#$defs/zip",        // not a pointer
		"#/$defs/zip#x",     // second '#'
		"#/$defs/%zz",       // bad percent-encoding
		"#/$defs/%",         // truncated percent-encoding
		"#/$defs/%ff",       // invalid UTF-8
		"#/$defs/a b",       // unencoded space
		"#/$defs/x~2",       // bad pointer escape
		"#/$defs/x~",        // dangling tilde
		"#/$defs/\"q\"",     // unencoded quote
		"#/$defs/é",         // unencoded non-ASCII
		"?q=1#/$defs/zip",   // query
		"/extra#/$defs/zip", // path suffix
	} {
		ref := pathAddress + frag
		ref = strings.ReplaceAll(ref, `"`, `\"`)
		err := CheckSchemaDocument(j(`{"$ref":"`+ref+`"}`), "")
		var re *RefError
		if !errors.As(err, &re) {
			t.Errorf("check %q: got %v, want RefError", ref, err)
		}
		doc := j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"` + ref + `"}`)
		// Malformed percent-encodings are not valid uri-references, which the
		// dialect meta-schema reports first (422 invalid).
		var ve *ValidationError
		if err := v.Validate(doc, s.load); !errors.As(err, &re) && !(strings.Contains(frag, "%") && errors.As(err, &ve)) {
			t.Errorf("validate %q: got %v, want RefError", ref, err)
		}
	}
	// Missing target: rejected at compile time as an invalid schema.
	for _, ref := range []string{pathAddress + "#/nope", pathAddress + "#/$defs/zip/nope/deeper", pathAddress + "#/$defs/a%2520b"} {
		doc := j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"` + ref + `"}`)
		err := v.Validate(doc, s.load)
		var se *SchemaError
		if !errors.As(err, &se) {
			t.Errorf("%q: got %v, want SchemaError", ref, err)
		}
	}
	// A stored schema with a missing target fails when a document uses it.
	s.docs[pathFrag] = j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"` + pathAddress + `#/nope"}`)
	err := v.Validate(j(`{"$schema":"`+pathFrag+`"}`), s.load)
	var se *SchemaError
	if !errors.As(err, &se) {
		t.Errorf("stored missing target: got %v", err)
	}
	// Unavailable revision behind a fragment.
	doc := j(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"` + pathMissing + `#/$defs/x"}`)
	var ue *UnavailableError
	if err := v.Validate(doc, s.load); !errors.As(err, &ue) {
		t.Errorf("unavailable: got %v", err)
	}
	// $schema itself stays strict.
	err = v.Validate(map[string]any{"$schema": pathAddress + "#/$defs/zip"}, s.load)
	var re *RefError
	if !errors.As(err, &re) {
		t.Errorf("$schema with fragment: got %v", err)
	}
	if _, ok := ParseRef(pathAddress + "#"); ok {
		t.Error("ParseRef accepted a fragment")
	}
}
