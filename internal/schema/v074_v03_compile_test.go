package schema

import (
	"errors"
	"testing"
)

// CORE-3 (§6.1, §6.2 step 5, §6.6): every schema compiles under this
// version. A revision whose row carries the Legacy marker, named directly
// or reached through a $ref, asserts idn-hostname; one with a pattern only
// raw RE2 took (\x{D800}), or naming semver, is an invalid schema; and
// ValidateMarked never consults the markers.
func TestV074V03EveryRevisionCompilesCurrent(t *testing.T) {
	t.Parallel()
	st := newStore()
	host := "/r/schemas/host/rev/" + rev('h')
	root := "/r/schemas/root/rev/" + rev('r')
	pat := "/r/schemas/pat/rev/" + rev('p')
	ver := "/r/schemas/ver/rev/" + rev('v')
	st.docs[host] = j(`{` + d073 + `,"type":"object","properties":{"h":{"format":"idn-hostname"}}}`)
	st.docs[root] = j(`{` + d073 + `,"type":"object","properties":{"in":{"$ref":"` + host + `"}}}`)
	st.docs[pat] = j(`{` + d073 + `,"type":"object","properties":{"a":{"pattern":"[\\x{D800}]"}}}`)
	st.docs[ver] = j(`{` + d073 + `,"type":"object","properties":{"v":{"format":"semver"}}}`)
	legacy := func(Ref) Rules { return Legacy }
	v := NewValidator()

	var ve *ValidationError
	err := v.ValidateMarked(map[string]any{"$schema": host, "h": "-bad-"}, st.load, V073, legacy)
	if !errors.As(err, &ve) || ve.Errors[0].Pointer != "/h" {
		t.Errorf("a Legacy revision: %v, want a refusal at /h", err)
	}
	err = v.ValidateMarked(map[string]any{"$schema": root, "in": map[string]any{"h": "-bad-"}}, st.load, V073, legacy)
	if !errors.As(err, &ve) || ve.Errors[0].Pointer != "/in/h" {
		t.Errorf("a Legacy revision through a $ref: %v, want a refusal at /in/h", err)
	}
	if err := v.ValidateMarked(map[string]any{"$schema": host, "h": "example.com"}, st.load, V073, legacy); err != nil {
		t.Errorf("a valid host: %v", err)
	}
	for _, p := range []string{pat, ver} {
		var se *SchemaError
		if err := v.ValidateMarked(map[string]any{"$schema": p}, st.load, Legacy, legacy); !errors.As(err, &se) {
			t.Errorf("%s under Legacy: %v, want SchemaError", p, err)
		}
	}
	// A Legacy schema document written again (a copy) is held to today's
	// rules too.
	if err := v.ValidateRules(st.docs[ver], st.load, Legacy); !isInvalid(err) {
		t.Errorf("a copy of a Legacy schema naming semver: %v, want invalid", err)
	}
}
