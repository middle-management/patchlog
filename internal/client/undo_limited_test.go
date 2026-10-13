package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// §11.2 Finding a gesture, §C.5: a writer limited to some resources reads
// neither the namespace log nor its document. Where no listing answers it
// (sealed namespaces, or UndoScanLog), it scans the logs of the documents
// it knows the action touched (UndoResources), and learns the level from
// what it reads: a sealed resource log is a list of JWEs, and every step
// of the inverse then adds a fresh $nonce. Without them it gets
// ErrNeedResources, not a raw 403. Redo and the stack work the same way.
func TestUndoLimitedWriter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	for _, tc := range []struct {
		name, level string
		// listed: the gestures listing answers li, so finding the gesture
		// from resource logs needs UndoScanLog.
		listed bool
	}{
		{"plain", "", true},
		{"sealed", "sealed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns := "lim-" + tc.name
			doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
			if tc.level != "" {
				doc["encryption"] = map[string]any{"level": tc.level}
			}
			opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
			must(opc.CreateNamespace(ctx, ns, doc))
			rights := []string{"read", "create", "append"}
			only := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}}}
			li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{ns}, rights, only)), client.WithKeys(client.NewKeys(nil)))
			bob := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:bob", []string{ns}, rights)), client.WithKeys(client.NewKeys(nil)))
			if _, err := li.NSHead(ctx, ns); err == nil {
				t.Fatal("li reads the namespace")
			}

			wa := must(li.Create(ctx, ns, "a", nonced(client.GenesisPatches(map[string]any{"n": 1, "o": 1}))))
			wb := must(li.Create(ctx, ns, "b", nonced(client.GenesisPatches(map[string]any{"n": 1}))))
			g := client.NewGesture()
			wa = must(li.Append(ctx, ns, "a", wa.ID, nonced(ops(op("replace", "/n", 2))), client.WithGesture(g)))
			must(bob.Append(ctx, ns, "a", wa.ID, nonced(ops(op("replace", "/o", 2)))))
			must(li.Append(ctx, ns, "b", wb.ID, nonced(ops(op("replace", "/n", 2))), client.WithGesture(g)))
			gb := client.NewGesture()
			must(li.Append(ctx, ns, "b", head(t, li, ns, "b"), nonced(ops(op("add", "/x", 1))), client.WithGesture(gb)))

			var scan []client.UndoOption
			if tc.listed {
				plan := must(li.PlanUndo(ctx, ns, g))
				if plan.Source != "gestures" || len(plan.Resources) != 2 {
					t.Fatalf("listed plan %+v", plan)
				}
				scan = []client.UndoOption{client.UndoScanLog()}
			}
			with := func(opts ...client.UndoOption) []client.UndoOption {
				return append(append([]client.UndoOption{}, scan...), opts...)
			}
			res := client.UndoResources("a", "b")

			_, err := li.PlanUndo(ctx, ns, g, with()...)
			if !errors.Is(err, client.ErrNeedResources) || !(client.IsAuth(err) || client.IsNotFound(err)) {
				t.Fatalf("without resources: %v", err)
			}
			if _, err := li.UndoStack(ctx, ns, "user:li"); !errors.Is(err, client.ErrNeedResources) {
				t.Fatalf("stack without resources: %v", err)
			}
			if _, err := li.PlanUndo(ctx, ns, gb, with(client.UndoResources("a"))...); !errors.Is(err, client.ErrGestureNotFound) {
				t.Fatalf("a gesture only in a resource not named: %v", err)
			}

			plan := must(li.PlanUndo(ctx, ns, g, with(res)...))
			if plan.Source != "resources" || plan.Level != tc.level || plan.Author != "user:li" || len(plan.Batch.Items) != 2 || plan.Err() != nil {
				t.Fatalf("plan %+v", plan)
			}
			for _, it := range plan.Batch.Items {
				for _, st := range it.Steps {
					if !strings.Contains(string(jsonv.Canonical(jsonv.FromGo(st.Patches))), `"path":"/$nonce"`) {
						t.Fatalf("a step without a fresh nonce: %v", st.Patches)
					}
				}
			}
			u := must(li.Undo(ctx, ns, g, with(res)...))
			a, _ := docOf(t, li, ns, "a")
			sameDoc(t, "a", a, map[string]any{"n": 1, "o": 2})
			b, _ := docOf(t, li, ns, "b")
			sameDoc(t, "b", b, map[string]any{"n": 1, "x": 1})
			if n, _ := a["$nonce"].(string); !seal.ValidNonce(n) {
				t.Fatalf("a: no fresh nonce %v", a)
			}

			st := must(li.UndoStack(ctx, ns, "user:li", res))
			if len(st.Undone) != 1 || st.Undone[0].Gesture != g || st.Undone[0].Target != u.Gesture || len(st.Undone[0].Resources) != 2 ||
				len(st.Done) != 1 || st.Done[0].Gesture != gb {
				t.Fatalf("stack %+v", st)
			}

			must(li.Redo(ctx, ns, g, with(res)...))
			a, _ = docOf(t, li, ns, "a")
			sameDoc(t, "redone a", a, map[string]any{"n": 2, "o": 2})
			st = must(li.UndoStack(ctx, ns, "user:li", res))
			if len(st.Undone) != 0 || len(st.Done) != 2 || st.Done[1].Gesture != g || len(st.Done[1].Chain) != 2 {
				t.Fatalf("stack after the redo %+v", st)
			}

			// Another writer's later edit of the gesture's path stops it.
			must(bob.Append(ctx, ns, "b", head(t, bob, ns, "b"), nonced(ops(op("replace", "/x", 2)))))
			if _, err := li.Undo(ctx, ns, gb, with(res)...); !client.IsUndoConflict(err) {
				t.Fatalf("undo after an overlapping edit: %v", err)
			}
		})
	}
}

// §11.2, §C.5, §E.3: sealing an e2e inverse needs the current epoch and
// pad, which only the namespace document gives, so a writer limited to
// some resources is refused once it learns the level from the resource
// log, with or without an E2E view.
func TestUndoLimitedWriterE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	admin := clienttest.NewKey("admin")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "le")))
	must(opc.CreateNamespace(ctx, "le", map[string]any{"read": "grant", "keys": []any{admin.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}))
	jwk, priv, _ := seal.GenerateRecipient()
	ac := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:admin", []string{"le"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": jwk})))
	x := ac.E2E(priv)
	must(x.InitKeyring(ctx, "le"))
	w := must(x.CreateDocSealed(ctx, "le", "a", map[string]any{"n": 0}))
	g := client.NewGesture()
	must(x.AppendSealed(ctx, "le", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))

	only := map[string]any{"enc": jwk, "rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}
	li := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:li", []string{"le"}, []string{"read", "append"}, only)))
	if _, err := li.PlanUndo(ctx, "le", g); !errors.Is(err, client.ErrNeedResources) {
		t.Fatalf("without resources: %v", err)
	}
	for _, opts := range [][]client.UndoOption{
		{client.UndoResources("a")},
		{client.UndoResources("a"), client.UndoE2E(li.E2E(priv))},
	} {
		if _, err := li.Undo(ctx, "le", g, opts...); !errors.Is(err, client.ErrUndoE2ELimited) {
			t.Fatalf("limited e2e undo: %v", err)
		}
	}
	if h := must(li.Head(ctx, "le", "a")); h.ID != head(t, ac, "le", "a") {
		t.Fatal("the refused undo wrote")
	}
}
