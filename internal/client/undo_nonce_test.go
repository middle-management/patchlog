package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// §11.2, §C.7: where nonces are required, every patch-set step of an
// inverse adds a fresh $nonce, the one before a "delete" included, and a
// tombstone's inverse is a restore with just a fresh $nonce, even for
// history written before the namespace required them.
func TestUndoRequiredNonces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "rn", map[string]any{}))

	w := must(c.CreateDoc(ctx, "rn", "del", map[string]any{"n": 1}))
	gDel := client.NewGesture()
	must(c.Delete(ctx, "rn", "del", w.ID, client.WithGesture(gDel)))

	w = must(c.CreateDoc(ctx, "rn", "app", map[string]any{"n": 1}))
	gApp := client.NewGesture()
	must(c.Append(ctx, "rn", "app", w.ID, ops(op("replace", "/n", 2)), client.WithGesture(gApp)))

	w = must(c.CreateDoc(ctx, "rn", "res", map[string]any{"n": 1}))
	del := must(c.Delete(ctx, "rn", "res", w.ID))
	gRes := client.NewGesture()
	must(c.Restore(ctx, "rn", "res", del.ID, ops(op("replace", "/n", 2)), client.WithGesture(gRes)))

	h := must(c.NSHead(ctx, "rn"))
	must(c.PatchConfig(ctx, "rn", h.Config, ops(op("add", "/nonce", "required"))))

	nonced := func(st client.Step) bool {
		return strings.Contains(string(jsonv.Canonical(jsonv.FromGo(st.Patches))), `"path":"/$nonce"`)
	}
	// A tombstone: a restore with just a fresh nonce.
	plan := must(c.PlanUndo(ctx, "rn", gDel))
	if st := plan.Resources[0].Steps; len(st) != 1 || st[0].Delete || !nonced(st[0]) || len(st[0].Patches.([]any)) != 1 {
		t.Fatalf("tombstone inverse %+v", st)
	}
	must(c.Undo(ctx, "rn", gDel))
	if doc, st := docOf(t, c, "rn", "del"); st != client.Live {
		t.Fatalf("undo of a delete: %v", st)
	} else {
		sameDoc(t, "restored", doc, map[string]any{"n": 1})
	}

	// A revision.
	must(c.Undo(ctx, "rn", gApp))
	doc, _ := docOf(t, c, "rn", "app")
	sameDoc(t, "undone append", doc, map[string]any{"n": 1})

	// A restore: its inverse, then "delete"; the step before it has one.
	plan = must(c.PlanUndo(ctx, "rn", gRes))
	if st := plan.Resources[0].Steps; len(st) != 2 || st[0].Delete || !nonced(st[0]) || !st[1].Delete {
		t.Fatalf("restore inverse %+v", st)
	}
	must(c.Undo(ctx, "rn", gRes))
	if doc, st := docOf(t, c, "rn", "res"); st != client.Tombstoned {
		t.Fatalf("undo of a restore: %v", st)
	} else {
		sameDoc(t, "last live document", doc, map[string]any{"n": 1})
	}
}
