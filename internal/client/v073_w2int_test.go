package client_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §11.2 The guard, §7.2, §8.1: a resource deleted between an undo's plan
// and its batch fails the batch with 410 gone naming the tombstone as
// head, as cores answer an append on a tombstoned resource from v0.73
// (412 before). The undo is planned again, as after a 412, and the new
// plan finds the delete since the gesture: a conflict, not the batch's
// 410.
func TestV073W2UndoReplansOnGone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var other atomic.Pointer[client.Client]
	var fired atomic.Bool
	s := clienttest.New(t, clienttest.Options{Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && r.URL.Path == "/ns/u/batch" && fired.CompareAndSwap(false, true) {
				bob := other.Load()
				hd := must(bob.Head(r.Context(), "u", "a"))
				must(bob.Delete(r.Context(), "u", "a", hd.ID))
			}
			h.ServeHTTP(w, r)
		})
	}})
	alice := s.Client(t, client.WithAuthor("alice"))
	other.Store(s.Client(t, client.WithAuthor("bob")))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	w := must(alice.CreateDoc(ctx, "u", "a", map[string]any{"n": 0}))
	g := client.NewGesture()
	must(alice.Append(ctx, "u", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))
	_, err := alice.Undo(ctx, "u", g)
	var ce *client.ConflictError
	if !fired.Load() || !errors.As(err, &ce) {
		t.Fatalf("undo after a delete meanwhile: %v", err)
	}
}
