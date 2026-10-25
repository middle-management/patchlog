package core

import (
	"database/sql"
	"testing"
)

// v0.73 §8.6 Request (BBD-46): a prune that sends keep changes the keep set
// only if it differs as a set from the stored one, an absent set being
// empty; order and repeats don't count, so such a prune writes no entry.
func TestV073P26KeepChanged(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		stored  string // "" = no stored set
		keep    []string
		changed bool
	}{
		{"", nil, false},
		{"", []string{}, false},
		{`[]`, []string{}, false},
		{`["a","b"]`, []string{"b", "a"}, false},
		{`["a","b"]`, []string{"a", "b", "a"}, false},
		{`["a"]`, []string{}, true},
		{"", []string{"a"}, true},
		{`["a","b"]`, []string{"a", "c"}, true},
		{`["a","b"]`, []string{"a"}, true},
	} {
		own := &resRow{}
		if c.stored != "" {
			own.keep = sql.NullString{String: c.stored, Valid: true}
		}
		if got := keepChanged(own, c.keep); got != c.changed {
			t.Errorf("stored %q, keep %q: changed %v, want %v", c.stored, c.keep, got, c.changed)
		}
	}
}
