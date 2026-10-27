package playground

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// W2X: P15 x playground undo. From v0.73 an append on a resource
// tombstoned meanwhile is 410 gone naming the tombstone as head, where it
// was 412 (§7.2 table). Like client.Undo, the playground's undoRun plans
// again on that 410, as §11.2's guard says for a 412, so a resource
// deleted between the undo's plan and its batch is reported as a
// conflict, not thrown as the batch's raw 410.
const w2xUndoGoneHarness = undoPrelude + `
(async () => {
  let out;
  try {
    const u = await undoRun('u', input.g, {});
    out = { ok: !!u.ok, conflicts: (u.conflicts || []).length, impossible: u.impossible || '' };
  } catch (e) {
    out = { thrown: e.message };
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
`

func TestW2XPlaygroundUndoReplansOnGone(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	ctx := context.Background()
	var bob atomic.Pointer[client.Client]
	var fired atomic.Bool
	s := clienttest.New(t, clienttest.Options{Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && r.URL.Path == "/ns/u/batch" && fired.CompareAndSwap(false, true) {
				b := bob.Load()
				hd, err := b.Head(r.Context(), "u", "a")
				if err == nil {
					_, err = b.Delete(r.Context(), "u", "a", hd.ID)
				}
				if err != nil {
					t.Errorf("bob's delete: %v", err)
				}
			}
			h.ServeHTTP(w, r)
		})
	}})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob.Store(s.Client(t, client.WithAuthor("bob")))
	if _, err := alice.CreateNamespace(ctx, "u", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	w, err := alice.CreateDoc(ctx, "u", "a", map[string]any{"n": 0})
	if err != nil {
		t.Fatal(err)
	}
	g := client.NewGesture()
	if _, err := alice.Append(ctx, "u", "a", w.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 1}}, client.WithGesture(g)); err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	b := runUndoHarness(t, node, w2xUndoGoneHarness, map[string]any{"base": s.URL, "author": "alice", "key": key, "g": g})
	var out struct {
		OK         bool   `json:"ok"`
		Conflicts  int    `json:"conflicts"`
		Impossible string `json:"impossible"`
		Thrown     string `json:"thrown"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	if !fired.Load() {
		t.Fatal("the batch was never sent")
	}
	if out.Thrown != "" || out.Conflicts == 0 {
		t.Fatalf("undo after a delete between plan and batch: want the delete as a conflict (plan again, as client.Undo does), got %s", b)
	}
}
