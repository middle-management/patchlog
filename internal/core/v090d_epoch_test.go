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
