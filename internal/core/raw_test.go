package core

import "testing"

// §7.8 Files: a raw document's root is a blob reference with no other
// members than those validation leaves out (§6.2 step 5).
func TestRawBlob(t *testing.T) {
	bid := "1" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nonce := "abcdefghijklmnopqrstuvwxyz"
	ref := func(extra map[string]any) map[string]any {
		m := map[string]any{"$blob": bid, "type": "text/plain", "size": 3.0}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for _, d := range []map[string]any{
		ref(nil),
		ref(map[string]any{"nonce": nonce}),
		ref(map[string]any{"$schema": "/r/s/x/rev/" + bid, "$nonce": nonce, "$successor": "/r/n/x"}),
		ref(map[string]any{"$successor": "x"}),
	} {
		if RawBlob(d) != bid {
			t.Errorf("not raw: %v", d)
		}
	}
	for _, d := range []any{
		ref(map[string]any{"title": "x"}),
		ref(map[string]any{"$nonce": "short"}),
		ref(map[string]any{"$successor": "Bad"}),
		ref(map[string]any{"nonce": 1.0}),
		ref(map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema"}),
		map[string]any{"$blob": bid, "type": "text/plain"},
		map[string]any{"$blob": bid, "size": 3.0},
		map[string]any{"$blob": "nope", "type": "text/plain", "size": 3.0},
		map[string]any{"f": ref(nil)},
		[]any{ref(nil)},
		"x",
		nil,
	} {
		if RawBlob(d) != "" {
			t.Errorf("raw: %v", d)
		}
	}
}
