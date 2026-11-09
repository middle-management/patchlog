package client_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// OTHER-1 (§11.2 The inverse and The guard, "with writes widened as in
// §F.3"): a write whose last segment indexes an array counts as one to the
// whole outermost array holding it. Alice's insertion into /a/0/b writes
// /a, so Bob's later change to /a/0/c, inside the same outermost array, is
// a conflict for a person and nothing is written.
func TestV077UndoWidensToOutermostArray(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	must(alice.CreateDoc(ctx, "u", "a", map[string]any{"a": []any{map[string]any{"b": []any{1}, "c": 0}}}))
	g := client.NewGesture()
	must(alice.Append(ctx, "u", "a", head(t, alice, "u", "a"), ops(op("add", "/a/0/b/1", 2)), client.WithGesture(g)))
	must(bob.Append(ctx, "u", "a", head(t, bob, "u", "a"), ops(op("replace", "/a/0/c", 5))))
	before := head(t, alice, "u", "a")

	plan := must(alice.PlanUndo(ctx, "u", g))
	if len(plan.Resources) != 1 || !reflect.DeepEqual(plan.Resources[0].Writes, []string{"/a"}) {
		t.Fatalf("plan resources %+v", plan.Resources)
	}
	if plan.Err() == nil || len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != "overlap" {
		t.Fatalf("plan conflicts %+v", plan.Conflicts)
	}
	if _, err := alice.Undo(ctx, "u", g); !client.IsUndoConflict(err) {
		t.Fatalf("undo: %v", err)
	}
	if h := head(t, alice, "u", "a"); h != before {
		t.Fatalf("head moved: %s, want %s", h, before)
	}
	doc, _ := docOf(t, alice, "u", "a")
	sameDoc(t, "kept", doc, map[string]any{"a": []any{map[string]any{"b": []any{1, 2}, "c": 5}}})
}

// OTHER-1 (§11.2, §F.3): a last "-" that names an object member indexes no
// array and stays as written, so Bob's change to a sibling member doesn't
// conflict with undoing Alice's write to /o/-.
func TestV077UndoDashMemberNotWidened(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	alice := s.Client(t, client.WithAuthor("alice"))
	bob := s.Client(t, client.WithAuthor("bob"))
	must(alice.CreateNamespace(ctx, "u", map[string]any{}))
	must(alice.CreateDoc(ctx, "u", "o", map[string]any{"o": map[string]any{"-": 1, "x": 2}}))
	g := client.NewGesture()
	must(alice.Append(ctx, "u", "o", head(t, alice, "u", "o"), ops(op("replace", "/o/-", 9)), client.WithGesture(g)))
	must(bob.Append(ctx, "u", "o", head(t, bob, "u", "o"), ops(op("replace", "/o/x", 3))))

	plan := must(alice.PlanUndo(ctx, "u", g))
	if len(plan.Resources) != 1 || !reflect.DeepEqual(plan.Resources[0].Writes, []string{"/o/-"}) || plan.Err() != nil {
		t.Fatalf("plan %+v", plan)
	}
	must(alice.Undo(ctx, "u", g))
	doc, _ := docOf(t, alice, "u", "o")
	sameDoc(t, "undone", doc, map[string]any{"o": map[string]any{"-": 1, "x": 3}})
}
