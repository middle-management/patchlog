package core

import (
	"context"
	"slices"
	"testing"
)

// v0.88 §7.9 URLs ("Ranges are immutable but for purges and archive
// restores since"): a write that may change a cached filtered range, a
// purge or a restore that brings documents back, purges ns:{ns}, the tag
// those ranges carry, once a view has been recorded in the namespace, and
// only then (tagFilteredRanges, called by purgeApply and RestoreResource).
func TestV088RestoreTagsFilteredRanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := &p35Purger{}
	e := p35Engine(t, p)
	mkNS(t, e, "m", map[string]any{"read": "grant"})
	tags := func() []string {
		var out []string
		if err := e.update(ctx, func(t *tx) error {
			t.tags = nil
			t.tagFilteredRanges(t.nsByName("m"))
			out = slices.Clone(t.tags)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := tags(); len(got) != 0 {
		t.Fatalf("no view recorded: %v", got)
	}
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`INSERT INTO filtered_views (ns, view, subjects, kid, pub, roles, block_rules, read_scope, principal, digest, entry, conf, filter, exp)
			VALUES ('m', 'v', '[]', 'k', '', '[]', '[]', 0, '{}', 'd', '', 0, '{}', 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := tags(); !slices.Equal(got, []string{"ns:m"}) {
		t.Fatalf("a view recorded: %v, want [ns:m]", got)
	}
}
