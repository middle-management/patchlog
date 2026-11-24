package core

import (
	"context"
	"testing"
	"time"
)

// v0.90 §E.2.2 Epochs ("An epoch whose referencing revisions were all
// pruned answers 410 ... where the server recorded it when pruning and
// the request may read one of them, one judged without its document
// being hidden unless a kept answer shows it (§7.9 Cost), and 404
// otherwise"): v1, the only revision referencing the blob in epoch 1, is
// visible to li, who read it before the prune; once pruned and recorded,
// li's /e/1 is 410, as an unrestricted reader's is, by the kept answer. A
// reader whose view never judged v1 judges it without its document: 404.
func TestV090DPrunedVisibleEpochIs410(t *testing.T) {
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}})
	data := []byte("shared blob")
	bid, nonce := advUpload(t, w, "derby", data)
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v1", "b": advRef(bid, nonce, data)})
	li := advDocReader(w)
	// li reads the blob under epoch 1, which judges v1 (and keeps it).
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", li); err != nil || b == nil || b.Status != 200 {
		t.Fatalf("li at epoch 1 before the prune: %+v %v, want 200", b, err)
	} else {
		b.Close()
	}
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "sealed", "epoch": 2.0}})
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v2", "b": advRef(bid, nonce, data)})
	v3 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v3", "b": advRef(bid, nonce, data)})
	w.clock.Add(int64(10 * time.Minute / time.Millisecond))
	pruner := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"matches"}, "can": []any{"read", "prune"}})
	if _, err := w.e.Prune(ctx, Request{NS: "matches", Cred: pruner}, "derby", PruneRequest{Horizon: v3}); err != nil {
		t.Fatal(err)
	}
	// The same grant again, li's of before having expired: the same view.
	li = advDocReader(w)
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", w.admin); err != nil || b.Status != 410 {
		t.Fatalf("admin at pruned epoch 1: %+v %v, want 410", b, err)
	}
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", li); err != nil || b == nil || b.Status != 410 {
		t.Fatalf("li at pruned epoch 1, v1 judged visible before the prune: %+v %v, want 410", b, err)
	}
	// The kept answer survives the engine's memory: read_judged.
	w.e.judgedMu.Lock()
	w.e.judgedMem.Flush()
	w.e.judgedMu.Unlock()
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", li); err != nil || b == nil || b.Status != 410 {
		t.Fatalf("li at pruned epoch 1, its answer kept in read_judged alone: %+v %v, want 410", b, err)
	}
	fresh := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "schema": map[string]any{"const": "a"}}}})
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", fresh); err != nil || b == nil || b.Status != 404 {
		t.Fatalf("a reader that never judged v1 at pruned epoch 1: %+v %v, want 404", b, err)
	}
}

// As TestV090DPrunedVisibleEpochIs410, for v1 written before matches was
// sealed: it has no epoch of its own, and its first stored sealing fixed
// epoch 1 (§E.2.2). Pruning deletes that sealing; the epoch it fixed
// stays v1's, so li, whose kept answer shows v1, gets the recorded 410
// as the unrestricted reader does, not 404.
func TestV090DPrunedEpochFixedBySealingIs410(t *testing.T) {
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	data := []byte("shared blob")
	bid, nonce := advUpload(t, w, "derby", data)
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v1", "b": advRef(bid, nonce, data)})
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}})
	li := advDocReader(w)
	// li reads the blob under epoch 1: v1's sealing is stored, fixing
	// its epoch, and li's answer for v1 kept.
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, w.admin); err != nil || b.Status != 302 || b.Epoch != 1 {
		t.Fatalf("admin: %+v %v, want 302 to epoch 1", b, err)
	}
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", li); err != nil || b == nil || b.Status != 200 {
		t.Fatalf("li at epoch 1 before the prune: %+v %v, want 200", b, err)
	} else {
		b.Close()
	}
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		v := t2.resolve(n, "derby", nil)
		if _, fixed := t2.revEpochFixed(n, v.head); !fixed {
			t.Fatal("v1's epoch isn't fixed by a stored sealing: the test doesn't test what it says")
		}
	})
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "sealed", "epoch": 2.0}})
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v2", "b": advRef(bid, nonce, data)})
	v3 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v3", "b": advRef(bid, nonce, data)})
	w.clock.Add(int64(10 * time.Minute / time.Millisecond))
	pruner := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"matches"}, "can": []any{"read", "prune"}})
	if _, err := w.e.Prune(ctx, Request{NS: "matches", Cred: pruner}, "derby", PruneRequest{Horizon: v3}); err != nil {
		t.Fatal(err)
	}
	li = advDocReader(w)
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", w.admin); err != nil || b.Status != 410 {
		t.Fatalf("admin at pruned epoch 1: %+v %v, want 410", b, err)
	}
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", li); err != nil || b == nil || b.Status != 410 {
		t.Fatalf("li at pruned epoch 1, v1 judged visible before the prune: %+v %v, want 410", b, err)
	}
	// Epoch 2, which v2 and v3 have, is still served, and nothing else.
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "2", li); err != nil || b == nil || b.Status != 200 {
		t.Fatalf("li at epoch 2: %+v %v, want 200", b, err)
	} else {
		b.Close()
	}
	fresh := w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "schema": map[string]any{"const": "a"}}}})
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", fresh); err != nil || b == nil || b.Status != 404 {
		t.Fatalf("a reader that never judged v1 at pruned epoch 1: %+v %v, want 404", b, err)
	}
}
