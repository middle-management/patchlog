package core

import "testing"

// §6.6: at E3 every create and restore may be as large as documentSize.
func TestCheckLimitsFromScratch(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	l.PatchSetSize, l.DocumentSize = 100, 1000
	big := make([]byte, 500)
	root := []any{map[string]any{"op": "replace", "path": "", "value": 1.0}}
	add := []any{map[string]any{"op": "add", "path": "/a", "value": 1.0}}
	for _, c := range []struct {
		name string
		s    stepState
		ok   bool
	}{
		{"create", stepState{action: "create"}, true},
		{"e2e create", stepState{action: "create", sealed: true}, true},
		{"e2e restore", stepState{action: "restore", sealed: true}, true},
		{"e2e append", stepState{action: "append", sealed: true}, false},
		{"restore from scratch", stepState{action: "restore", raw: root}, true},
		{"restore with add", stepState{action: "restore", raw: add}, false},
		{"empty restore", stepState{action: "restore", raw: []any{}}, false},
		{"append", stepState{action: "append", raw: root}, false},
	} {
		c.s.canon = big
		err := checkLimits(l, &itemState{steps: []*stepState{&c.s}})
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestCanonStringLen(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]int{"": 2, "abc": 5, `a"b`: 6, "\n\x01": 2 + 2 + 6, "é": 4} {
		if got := canonStringLen(s); got != want {
			t.Errorf("%q: %d, want %d", s, got, want)
		}
	}
}
