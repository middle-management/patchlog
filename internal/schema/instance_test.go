package schema

import (
	"reflect"
	"testing"
)

// §6.2 step 5: the instance validated leaves out $schema and a fresh-form
// $nonce, at the top level only.
func TestInstance(t *testing.T) {
	nonce := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range []struct{ in, want any }{
		{map[string]any{"$schema": "/r/s/x/rev/1a", "a": 1.0}, map[string]any{"a": 1.0}},
		{map[string]any{"$nonce": nonce, "a": 1.0}, map[string]any{"a": 1.0}},
		{map[string]any{"$nonce": "short"}, map[string]any{"$nonce": "short"}},
		{map[string]any{"$nonce": 1.0}, map[string]any{"$nonce": 1.0}},
		{map[string]any{"b": map[string]any{"$schema": "x", "$nonce": nonce}}, map[string]any{"b": map[string]any{"$schema": "x", "$nonce": nonce}}},
		{[]any{1.0}, []any{1.0}},
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
