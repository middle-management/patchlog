package core

import (
	"context"
	"slices"
	"testing"
)

// v0.90 §8.3 CDN ("ns:{ns} once a view of the namespace has been served",
// CONFORMANCE Filtered reads 89): a purge clears ns:{ns}, the tag of
// filtered ranges, once a view of the namespace has been served, a
// bearer's read at a view URL included, which records no filtered_views
// row, and still after filtered_views rows are swept. Before any view is
// served it doesn't. Until v0.90 the tag was cleared only while a
// filtered_views row was kept.
func TestV090BPurgeClearsNSOnceAViewIsServed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV76fWorld(t, false)
	tags := func() []string {
		var out []string
		if err := w.e.update(ctx, func(t *tx) error {
			t.tags = nil
			t.tagFilteredRanges(t.nsByName("matches"))
			out = slices.Clone(t.tags)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := tags(); len(got) != 0 {
		t.Fatalf("no view served yet: %v", got)
	}
	red, st := v76fRedirect(t, w.v75World, "matches", "", w.li())
	if st != 0 {
		t.Fatalf("li's redirect to her view: %d", st)
	}
	if got := tags(); len(got) != 0 {
		t.Fatalf("a redirect serves no view: %v", got)
	}
	if _, _, err := w.e.FilteredLog(ctx, "matches", red.View, red.At, "", 10, w.li()); err != nil {
		t.Fatal(err)
	}
	var rows int
	w.inTx(func(t *tx) { t.must(t.QueryRow(`SELECT COUNT(*) FROM filtered_views`).Scan(&rows)) })
	if rows != 0 {
		t.Fatalf("a bearer's read recorded %d filtered_views rows: the test shows nothing", rows)
	}
	if got := tags(); !slices.Equal(got, []string{"ns:matches"}) {
		t.Fatalf("a view served: %v, want [ns:matches]", got)
	}
	// And a purge carries it.
	p := &p35Purger{}
	w.e.opt.Purger = p
	h, err := w.e.ResourceHead(ctx, "matches", "derby", w.admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.Purge(ctx, Request{NS: "matches", Cred: w.admin}, "derby", h.Head, false); err != nil {
		t.Fatal(err)
	}
	if got := p.take(); !slices.Contains(got, "ns:matches") {
		t.Fatalf("the purge of derby cleared %v, not ns:matches", got)
	}
}

// v0.90 §E.2.2 Filtered answers ("keys holds ... a view's keys for each
// revision of the namespace it names that is visible, tombstones and
// revisions of purged resources excepted"), §8.3 Effect (the view keys
// stored for its revisions are removed; CONFORMANCE Filtered reads 89):
// once derby is purged, li's filtered answers, which still name its
// revisions in the namespace log, carry no keys for them, and none is
// stored again.
func TestV090BFilteredAnswersNoKeysOfPurged(t *testing.T) {
	w := newV89SealedWorld(t)
	ctx := context.Background()
	li := w.li() // by /resource alone: a purged name stays visible to it
	kv, view := v89Key(t, w, li)
	v1 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v1"})
	o1 := v89Put(w, "shared", map[string]any{"team": "a", "title": "o1"})
	got := advCollect(t, w, li, kv, view, "derby")
	if _, ok := got[v1]; !ok {
		t.Fatalf("control: no keys for visible %s before the purge", v1)
	}
	h, err := w.e.ResourceHead(ctx, "matches", "derby", w.admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.Purge(ctx, Request{NS: "matches", Cred: w.admin}, "derby", h.Head, false); err != nil {
		t.Fatal(err)
	}
	got = advCollect(t, w, li, kv, view, "shared")
	if _, ok := got[v1]; ok {
		t.Errorf("keys of purged derby's %s in li's answers", v1)
	}
	if _, ok := got[o1]; !ok {
		t.Errorf("control: no keys for shared's %s after derby's purge", o1)
	}
	var stored int
	w.inTx(func(t *tx) {
		t.must(t.QueryRow(`SELECT COUNT(*) FROM sealed WHERE kind = ? AND name = ?`, sealKeys, "derby").Scan(&stored))
	})
	if stored != 0 {
		t.Errorf("%d view keys of purged derby stored", stored)
	}
}
