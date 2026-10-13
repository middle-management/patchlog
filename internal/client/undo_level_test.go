package client

import "testing"

// §11.2 Finding a gesture, Addendum E: a grant that can't read the
// namespace document learns the level from the entries it opened. A patch
// set of one sealed op is e2e even when delivered sealed, since E3
// includes E2's delivery format; a log of tombstones and [] restores, or
// none, tells nothing.
func TestOpenedLevel(t *testing.T) {
	sealedOp := []any{map[string]any{"op": "sealed", "value": "eyJ..."}}
	plain := []any{map[string]any{"op": "replace", "path": "/n", "value": 1.0}}
	rev := func(p []any) LogEntry { return LogEntry{Kind: "rev", Patches: p, HasPatches: p != nil} }
	tomb := LogEntry{Kind: "tombstone"}
	for _, tc := range []struct {
		name      string
		log       []LogEntry
		e2e, told bool
	}{
		{"empty", nil, false, false},
		{"tombstones and [] restores", []LogEntry{tomb, rev([]any{}), tomb}, false, false},
		{"pruned patch sets", []LogEntry{rev(nil)}, false, false},
		{"plain", []LogEntry{rev(plain)}, false, true},
		{"e2e", []LogEntry{rev(sealedOp)}, true, true},
		{"e2e after a restore", []LogEntry{tomb, rev([]any{}), rev(sealedOp)}, true, true},
		{"a sealed op among others", []LogEntry{rev(append(append([]any{}, plain...), sealedOp...))}, false, true},
	} {
		if e2e, told := openedLevel(tc.log); e2e != tc.e2e || told != tc.told {
			t.Errorf("%s: e2e %v told %v, want %v %v", tc.name, e2e, told, tc.e2e, tc.told)
		}
	}
}
