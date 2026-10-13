package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
			before := must(bob.NSHead(ctx, ns)).ID
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
				// UndoSince needs /heads, which li can't read: it is dropped,
				// and the listing still answers.
				plan = must(li.PlanUndo(ctx, ns, g, client.UndoSince(before)))
				if plan.Source != "gestures" || len(plan.Resources) != 2 {
					t.Fatalf("listed plan with a since %+v", plan)
				}
				// The listing answered: an author with no entries there is
				// not found, not a call for resources.
				if _, err := li.PlanUndo(ctx, ns, g, client.UndoAuthor("user:bob")); !errors.Is(err, client.ErrGestureNotFound) {
					t.Fatalf("listed, another author: %v", err)
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
			for what, f := range map[string]func(...client.UndoOption) error{
				"plan": func(o ...client.UndoOption) error { _, err := li.PlanUndo(ctx, ns, g, o...); return err },
				"redo": func(o ...client.UndoOption) error { _, err := li.Redo(ctx, ns, g, o...); return err },
			} {
				if err := f(with(client.UndoSince(before))...); !errors.Is(err, client.ErrNeedResources) {
					t.Fatalf("%s with a since, without resources: %v", what, err)
				}
			}
			// A 401 is a grant that can't be used at all, not one limited
			// to some resources (§12).
			expired := s.Client(t, client.WithBearer(k.Grant(t, s.Now().Add(-2*time.Hour), "user:li", []string{ns}, rights, only)), client.WithKeys(client.NewKeys(nil)))
			for _, err := range []error{
				func() error { _, err := expired.PlanUndo(ctx, ns, g, with(res)...); return err }(),
				func() error { _, err := expired.UndoStack(ctx, ns, "user:li", res); return err }(),
			} {
				if ae, ok := client.AsAPIError(err); !ok || ae.Status != 401 || errors.Is(err, client.ErrNeedResources) {
					t.Fatalf("an expired grant: %v", err)
				}
			}
			if _, err := li.PlanUndo(ctx, ns, gb, with(client.UndoResources("a"))...); !errors.Is(err, client.ErrGestureNotFound) {
				t.Fatalf("a gesture only in a resource not named: %v", err)
			}

			if plan := must(li.PlanUndo(ctx, ns, g, with(res, client.UndoSince(before))...)); plan.Source != "resources" || len(plan.Batch.Items) != 2 {
				t.Fatalf("plan with a since %+v", plan)
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

// §11.2 When undo is impossible, §8.6: resource logs carry no markers, so
// a limited writer can't see a gesture's revisions below a pruning horizon.
// One whose first revision read directly follows the horizon may continue
// below it, and is refused as impossible rather than undone in part; one
// after other entries is undone as usual.
func TestUndoLimitedPruned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	for _, tc := range []struct {
		name, level string
		scan        []client.UndoOption
	}{
		{"plain", "", []client.UndoOption{client.UndoScanLog()}},
		{"sealed", "sealed", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns := "lp-" + tc.name
			doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
			if tc.level != "" {
				doc["encryption"] = map[string]any{"level": tc.level}
			}
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
			only := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}
			li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{ns}, []string{"read", "create", "append"}, only)), client.WithKeys(client.NewKeys(nil)))
			w := must(li.Create(ctx, ns, "a", nonced(client.GenesisPatches(map[string]any{"n": 0, "p": 0, "q": 0, "r": 0}))))
			g := client.NewGesture()
			w = must(li.Append(ctx, ns, "a", w.ID, nonced(ops(op("replace", "/n", 1))), client.WithGesture(g)))
			w = must(li.Append(ctx, ns, "a", w.ID, nonced(ops(op("replace", "/p", 1))), client.WithGesture(g)))
			horizon := w.ID
			w = must(li.Append(ctx, ns, "a", w.ID, nonced(ops(op("replace", "/q", 1))), client.WithGesture(g)))
			w = must(li.Append(ctx, ns, "a", w.ID, nonced(ops(op("replace", "/r", 1)))))
			g2 := client.NewGesture()
			must(li.Append(ctx, ns, "a", w.ID, nonced(ops(op("replace", "/r", 2))), client.WithGesture(g2)))
			s.Clock.Advance(10 * time.Minute)
			pg := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:op", []string{ns}, []string{"read", "prune"})), client.WithKeys(client.NewKeys(nil)))
			must(pg.Prune(ctx, ns, "a", client.PruneRequest{Horizon: horizon}))
			with := func(opts ...client.UndoOption) []client.UndoOption {
				return append(append([]client.UndoOption{}, tc.scan...), opts...)
			}

			_, err := li.Undo(ctx, ns, g, with(client.UndoResources("a"))...)
			var ie *client.ImpossibleError
			if !errors.As(err, &ie) || ie.Reason != "pruned" || ie.Resource != "a" {
				t.Fatalf("a gesture straddling the horizon: %v", err)
			}
			got, _ := docOf(t, li, ns, "a")
			sameDoc(t, "after the refusal", got, map[string]any{"n": 1, "p": 1, "q": 1, "r": 2})

			must(li.Undo(ctx, ns, g2, with(client.UndoResources("a"))...))
			got, _ = docOf(t, li, ns, "a")
			sameDoc(t, "after the horizon", got, map[string]any{"n": 1, "p": 1, "q": 1, "r": 1})
		})
	}
}

// §11.2, §7.4: for a grant that reads the namespace, a since not in the
// namespace chain is the server's 404, never a call for resources, and
// UndoResources doesn't make it be dropped.
func TestUndoBadSince(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "bs"))).CreateNamespace(ctx, "bs", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	bob := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:bob", []string{"bs"}, []string{"read", "create", "append"})))
	w := must(bob.Create(ctx, "bs", "a", client.GenesisPatches(map[string]any{"n": 1})))
	g := client.NewGesture()
	must(bob.Append(ctx, "bs", "a", w.ID, ops(op("replace", "/n", 2)), client.WithGesture(g)))
	must(bob.Undo(ctx, "bs", g))
	bad := w.ID // a resource revision, not in the namespace chain
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"plan, scanning the log", func() error {
			_, err := bob.PlanUndo(ctx, "bs", g, client.UndoScanLog(), client.UndoSince(bad))
			return err
		}},
		{"plan, with resources", func() error {
			_, err := bob.PlanUndo(ctx, "bs", g, client.UndoSince(bad), client.UndoResources("a"))
			return err
		}},
		{"redo", func() error {
			_, err := bob.Redo(ctx, "bs", g, client.UndoScanLog(), client.UndoSince(bad), client.UndoResources("a"))
			return err
		}},
		{"stack", func() error {
			_, err := bob.UndoStack(ctx, "bs", "user:bob", client.UndoSince(bad), client.UndoResources("a"))
			return err
		}},
	} {
		if err := tc.call(); !client.IsNotFound(err) || errors.Is(err, client.ErrNeedResources) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
