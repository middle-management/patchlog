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

// v0.90 §E.2.2 Epochs ("Served epochs are those of the revisions here
// whose documents are still stored, that reference the blob and that the
// request may read"; CONFORMANCE ENC-29, Filtered reads 92): li is sent
// to the epoch of v1, which she may read, never to that of hidden v3; v3's
// epoch at the unprefixed URL is 404 with no-store for her grant, as any
// epoch not served, where it was a read-rule failure before v0.90. An
// unrestricted reader is sent to v3's.
func TestV090BBlobEpochsOfReadableRevisions(t *testing.T) {
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}})
	data := []byte("shared blob")
	bid, nonce := advUpload(t, w, "derby", data)
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v1", "b": advRef(bid, nonce, data)})
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "sealed", "epoch": 2.0}})
	v89Put(w, "derby", map[string]any{"team": "b", "secret": "S", "b": advRef(bid, nonce, data)})
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, w.admin); err != nil || b.Status != 302 || b.Epoch != 2 {
		t.Fatalf("admin: %+v %v, want 302 to epoch 2", b, err)
	}
	li := advDocReader(w)
	// Her grant at the blob's own URL is sent to its form under her view
	// (contentRedirect), which sends her to v1's epoch.
	_, view := v89Key(t, w, li)
	vc, err := w.e.ViewCredentials(ctx, "matches", view, li)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, vc); err != nil || b.Status != 302 || b.Epoch != 1 {
		t.Fatalf("li: %+v %v, want 302 to epoch 1", b, err)
	}
	b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "2", li)
	if err != nil || b == nil || b.Status != 404 || !b.NoStore {
		t.Fatalf("li at hidden v3's epoch 2: %+v %v, want 404 with no-store", b, err)
	}
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", li); err != nil || b.Status != 200 {
		t.Fatalf("li at v1's epoch 1: %+v %v", b, err)
	} else {
		b.Close()
	}
}

// v0.90 §8.5 ("The full read check of the first row is ... a partial
// reader passing at /heads (§7.9)"): once matches is purged, li, a partial
// reader who lacks unrestricted read, passes the read check of its
// /heads and gets 410, as at her view's URLs; a grant that may not read
// matches still gets 403.
func TestV090BPartialReaderPurgedHeads(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	head := w.head("matches")
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/frozen", "value": true})
	op := w.cred(w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"matches"}, "can": []any{"purge-ns"}})
	if _, err := w.e.PurgeNamespace(ctx, Request{NS: "matches", Cred: op}, w.head("matches"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.NamespaceHeads(ctx, "matches", head, "", w.li()); v75Status(err) != 410 {
		t.Fatalf("li at the purged namespace's /heads: %v, want 410", err)
	}
	writer := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"matches"}, "can": []any{"create"}})
	if _, err := w.e.NamespaceHeads(ctx, "matches", head, "", writer); v75Status(err) != 403 {
		t.Fatalf("a grant without read at the purged namespace's /heads: %v, want 403", err)
	}
}
