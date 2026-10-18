package schema

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// §6.2 step 5: the instance validated leaves out $schema, a fresh-form
// $nonce and a $successor of the form of §8.1, at the top level only.
func TestInstance(t *testing.T) {
	nonce := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range []struct{ in, want any }{
		{map[string]any{"$schema": "/r/s/x/rev/1a", "a": 1.0}, map[string]any{"a": 1.0}},
		{map[string]any{"$nonce": nonce, "a": 1.0}, map[string]any{"a": 1.0}},
		{map[string]any{"$nonce": "short"}, map[string]any{"$nonce": "short"}},
		{map[string]any{"$nonce": 1.0}, map[string]any{"$nonce": 1.0}},
		{map[string]any{"b": map[string]any{"$schema": "x", "$nonce": nonce}}, map[string]any{"b": map[string]any{"$schema": "x", "$nonce": nonce}}},
		{[]any{1.0}, []any{1.0}},
		{map[string]any{"$successor": "new-name.v2", "a": 1.0}, map[string]any{"a": 1.0}},
		{map[string]any{"$successor": "/r/other_ns/x", "$nonce": nonce, "$schema": "s"}, map[string]any{}},
		{map[string]any{"$successor": "Upper"}, map[string]any{"$successor": "Upper"}},
		{map[string]any{"$successor": "/r/ns/a/b"}, map[string]any{"$successor": "/r/ns/a/b"}},
		{map[string]any{"$successor": "/r/n.s/a"}, map[string]any{"$successor": "/r/n.s/a"}},
		{map[string]any{"$successor": 1.0}, map[string]any{"$successor": 1.0}},
		{map[string]any{"b": map[string]any{"$successor": "x"}}, map[string]any{"b": map[string]any{"$successor": "x"}}},
	} {
		if got := Instance(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Instance(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	doc := map[string]any{"$schema": "x"}
	Instance(doc)
	if _, ok := doc["$schema"]; !ok {
		t.Fatal("Instance modified its argument")
	}
}

// The §8.1 form: a bare resource name, or /r/{ns}/{name}, names valid
// under §3.6.
func TestSuccessor(t *testing.T) {
	for _, ok := range []string{"a", "a.b_c-d", "0", strings.Repeat("a", 128), "/r/ns/a", "/r/n_s-2/x.y", "/r/" + strings.Repeat("n", 64) + "/a"} {
		if !Successor(ok) {
			t.Errorf("Successor(%q) = false", ok)
		}
	}
	for _, bad := range []any{"", "A", ".a", "-a", strings.Repeat("a", 129), "/r/ns", "/r/ns/", "/r//a", "/r/n.s/a", "/r/ns/a/b", "/r/ns/a?x", "r/ns/a", "/ns/a", "/r/" + strings.Repeat("n", 65) + "/a", "/r/ns/a/rev/1a", 1.0, nil, true, map[string]any{}} {
		if Successor(bad) {
			t.Errorf("Successor(%v) = true", bad)
		}
	}
}

// A closed schema accepts a well-formed $successor, of either form, which
// it needn't declare (§6.2 step 5, §8.1), and validates any other as data.
func TestValidateSuccessor(t *testing.T) {
	v := NewValidator()
	s := newStore()
	for _, succ := range []string{"bob", "/r/people/bob"} {
		d := j(`{"$schema":"` + pathAddress + `","city":"x","$successor":"` + succ + `"}`)
		if err := v.Validate(d, s.load); err != nil {
			t.Errorf("$successor %q: %v", succ, err)
		}
	}
	closed := j(`{"$schema":"` + pathPerson + `","name":"a","age":1,"$successor":"/r/people/bob"}`)
	if err := v.Validate(closed, s.load); err != nil {
		t.Errorf("closed schema, well-formed $successor: %v", err)
	}
	for _, succ := range []string{"Bob", "/r/people/bob/x", "../bob"} {
		d := j(`{"$schema":"` + pathPerson + `","name":"a","age":1,"$successor":"` + succ + `"}`)
		var ve *ValidationError
		if err := v.Validate(d, s.load); !errors.As(err, &ve) {
			t.Errorf("closed schema, $successor %q: %v", succ, err)
		}
	}
}
